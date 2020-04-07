// Copyright 2017, 2018 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Generic trait for trie node encoding/decoding. Takes a `hash_db::Hasher`
//! to parametrize the hashes used in the codec.

use crate::MaybeDebug;
use crate::node::{Node, NodePlan};
use crate::ChildReference;
use ordered_trie::BinaryHasher;

use crate::rstd::{borrow::Borrow, Error, hash, vec::Vec, EmptyIter, ops::Range, marker::PhantomData};

/// Representation of a nible slice (right aligned).
/// It contains a right aligned padded first byte (first pair element is the number of nibbles
/// (0 to max nb nibble - 1), second pair element is the padded nibble), and a slice over
/// the remaining bytes.
pub type Partial<'a> = ((u8, u8), &'a[u8]);

/// Trait for trie node encoding/decoding.
pub trait NodeCodec: Sized {
	/// Codec error type.
	type Error: Error;

	/// Output type of encoded node hasher.
	type HashOut: AsRef<[u8]> + AsMut<[u8]> + Default + MaybeDebug + PartialEq + Eq
		+ hash::Hash + Send + Sync + Clone + Copy;

	/// Get the hashed null node.
	fn hashed_null_node() -> Self::HashOut;

	/// Decode bytes to a `NodePlan`. Returns `Self::E` on failure.
	fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error>;

	/// Decode bytes to a `Node`. Returns `Self::E` on failure.
	fn decode(data: &[u8]) -> Result<Node, Self::Error> {
		// TODO ensure real use codec have their own implementation
		// as this can be slower
		Ok(Self::decode_plan(data)?.build(data))
	}

	/// Check if the provided bytes correspond to the codecs "empty" node.
	fn is_empty_node(data: &[u8]) -> bool;

	/// Returns an encoded empty node.
	fn empty_node() -> &'static [u8];

	/// Returns an encoded leaf node
	fn leaf_node(partial: Partial, value: &[u8]) -> Vec<u8>;

	/// Returns an encoded extension node
	/// Note that number_nibble is the number of element of the iterator
	/// it can possibly be obtain by `Iterator` `size_hint`, but
	/// for simplicity it is used directly as a parameter.
	fn extension_node(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		child_ref: ChildReference<Self::HashOut>,
	) -> Vec<u8>;

	/// Returns an encoded branch node.
	/// Takes an iterator yielding `ChildReference<Self::HashOut>` and an optional value.
	fn branch_node(
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<&[u8]>,
	) -> Vec<u8>;

	/// Returns an encoded branch node with a possible partial path.
	/// `number_nibble` is the partial path length as in `extension_node`.
	fn branch_node_nibbled(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<&[u8]>
	) -> Vec<u8>;
}

/// Trait for handling complex proof.
/// This adds methods to basic node codec in order to support:
/// - storage encoding with existing `NodeCodec` methods
/// - encode a proof specific representation. (usually the common representation and
/// the merkle proof of the children stored encoded hash).
/// - Intermediate optional common representation shared between storage
pub trait NodeCodecComplex: NodeCodec {
	/// Sequence of hashes needed for the children proof verification.
	type AdditionalHashesPlan: Iterator<Item = Range<usize>>;

	/// TODO EMCH this is technical function for common implementation.
	/// TODO document this damn bitmap!!!
	/// The parameter bitmap indicates children that are directly encoded
	/// in the proof or encoded as inline. That is the difference between
	/// the set of children and the set of children that are part of the
	/// additional hash of the proof. TODO remove it (not needed if we
	/// remove it from encode input, then doc that at codec level).
	fn decode_plan_proof(data: &[u8]) -> Result<(
		NodePlan,
		Option<(Bitmap, Self::AdditionalHashesPlan)>,
	), Self::Error>;

	/// Decode but child are not include (instead we put empty inline
	/// nodes).
	fn decode_proof(data: &[u8]) -> Result<(
		Node,
		Option<(Bitmap, HashesIter<Self::AdditionalHashesPlan, Self::HashOut>)>,
	), Self::Error> {
		let (plan, hashes) = Self::decode_plan_proof(data)?;
		let hashes = hashes.map(|(bitmap, hashes)| (bitmap, HashesIter::new(data, hashes)));
		Ok((plan.build(data), hashes))
	}

	/// Returns branch node encoded for storage, and additional information for hash calculation.
	/// 
	/// Takes an iterator yielding `ChildReference<Self::HashOut>` and an optional value
	/// as input, the third input is an output container needed for hash calculation.
	fn branch_node_common(
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<&[u8]>,
		register_children: &mut [Option<Range<usize>>],
	) -> (Vec<u8>, EncodedCommon);

	/// Variant of `branch_node_common` but with a nibble.
	///
	/// `number_nibble` is the partial path length, it replaces the one
	/// use by `extension_node`.
	fn branch_node_nibbled_common(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<&[u8]>,
		register_children: &mut [Option<Range<usize>>],
	) -> (Vec<u8>, EncodedCommon);

	/// Returns branch node encoded information for hash.
	/// Result is the same as `branch_node_common().1.encoded_common(branch_node_common().0`.
	fn branch_node_for_hash(
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<&[u8]>,
	) -> Vec<u8>;

	/// Variant of `branch_node_for_hash` but with a nibble.
	fn branch_node_nibbled_for_hash(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<&[u8]>,
	) -> Vec<u8>;

	/// Build compact proof encoding from branch info.
	///
	/// - `hash_proof_header`: the part common with the header info from hash.
	/// It can be calculated from `branch_node_common` through
	/// `EncodedCommon` call, or directly by `branch_node_for_hash`.
	/// TODO EMCH rename this common `HashProofHeader`.
	/// - `children`: contains all children reference, not that children reference
	/// that are compacted are set as inline children of length 0.
	/// TODO consider using bitmap directly
	fn encode_compact_proof<H: BinaryHasher>(
		hash_proof_header: Vec<u8>,
		children: &[Option<ChildReference<H::Out>>],
		hash_buf: &mut H::Buffer,
	) -> Vec<u8>;
}

/// Information to fetch bytes that needs to be include when calculating a node hash.
/// The node hash is the hash of these information and the merkle root of its children.
/// TODO EMCH rename to BranchHashInfo
#[derive(Clone)]
pub enum EncodedCommon {
	/// No need for complex hash. TODO EMCH see if still used.
	Unused,
	/// Range over the branch encoded for storage.
	Range(Range<usize>),
	/// Allocated in case we cannot use a range.
	Allocated(Vec<u8>),
}

impl EncodedCommon {
	pub fn encoded_common<'a>(&'a self, encoded: &'a [u8]) -> &'a [u8] {
		match self {
			EncodedCommon::Unused => encoded,
			EncodedCommon::Range(range) => &encoded[range.clone()],
			EncodedCommon::Allocated(buff) => &buff[..],
		}
	}
	// TODO this is bad we should produce a branch that does
	// not include it in the first place (new encode fn with
	// default impl using trim no child).
	// TODO consider removal
	pub fn trim_common(self, encoded: &mut Vec<u8>) {
		match self {
			EncodedCommon::Unused => (),
			EncodedCommon::Range(range) => {
				encoded.truncate(range.end);
				if range.start != 0 {
					*encoded = encoded.split_off(range.start);
				}
			},
			EncodedCommon::Allocated(buf) => {
				*encoded = buf;
			},
		}
	}

}

use ordered_trie::{HashDBComplex, HasherComplex};
use hash_db::{HashDB, Prefix, HashDBRef, Hasher};

pub trait HashDBComplexDyn<H: Hasher, T>: Send + Sync + HashDB<H, T> {
	/// Insert a datum item into the DB and return the datum's hash for a later lookup. Insertions
	/// are counted and the equivalent number of `remove()`s must be performed before the data
	/// is considered dead.
	///
	/// TODO warn semantic of children differs from HashDBComplex (in HashDBComplex it is the
	/// children of the binary hasher, here it is the children of the patricia merkle trie).
	fn insert_complex(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		children: &[Option<Range<usize>>],
		common: EncodedCommon,
	) -> H::Out;
}

impl<H: HasherComplex, T, C: HashDBComplex<H, T>> HashDBComplexDyn<H, T> for C {
	fn insert_complex(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		children: &[Option<Range<usize>>],
		common: EncodedCommon,
	) -> H::Out {

		// TODO factor this with iter_build (just use the trait)
		let nb_children = children.iter().filter(|v| v.is_some()).count();
		let children = ComplexLayoutIterValues::new(
			children.iter().filter_map(|v| v.as_ref()),
			value,
		);

		<C as HashDBComplex<H, T>>::insert_complex(
			self,
			prefix,
			value,
			common.encoded_common(value),
			nb_children,
			children,
			EmptyIter::default(),
			false,
		)
	}
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a dyn HashDBComplexDyn<H, T> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> {
		self.as_hash_db().get(key, prefix)
	}

	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		self.as_hash_db().contains(key, prefix)
	}
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a mut dyn HashDBComplexDyn<H, T> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> {
		self.as_hash_db().get(key, prefix)
	}

	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		self.as_hash_db().contains(key, prefix)
	}
}

// TODO this using a buffer is bad (we should switch
// binary hasher to use slice as input (or be able to))
pub struct ComplexLayoutIterValues<'a, HO, I> {
	children: I, 
	node: &'a [u8],
	_ph: PhantomData<HO>,
}
/*
code snippet for children iter:
ComplexLayoutIterValues::new(nb_children, children, value)
				.map(|(is_defined, v)| {
					debug_assert!(is_defined);
					v
				});
code snippet for proof
			let iter = ComplexLayoutIterValues::new(nb_children, children, value)
				.zip(iter_key)
				.filter_map(|((is_defined, hash), key)| if is_defined {
					Some((key, hash))
				} else {
					None
				});
*/	

impl<'a, HO: Default, I> ComplexLayoutIterValues<'a, HO, I> {
	pub fn new(children: I, node: &'a[u8]) -> Self {
		ComplexLayoutIterValues {
			children,
			node,
			_ph: PhantomData,
		}
	}
}

impl<'a, HO: AsMut<[u8]> + Default, I: Iterator<Item = &'a Range<usize>>> Iterator for ComplexLayoutIterValues<'a, HO, I> {
	type Item = Option<HO>;

	fn next(&mut self) -> Option<Self::Item> {
		if let Some(range) = self.children.next() {
			let range_len = range.len();
			if range_len == 0 {
				// this is for undefined proof hash
				return None;
			}
			let mut dest = HO::default();
			dest.as_mut()[..range_len].copy_from_slice(&self.node[range.clone()]);
			/* inherent to default?? TODO consider doing it, but if refacto
			 * this will be part of hasher (when run with slice as input)
			 * for i in range_len..dest.len() {
				dest[i] = 0;
			}*/
			// TODO the input iterator is HO but could really be &HO, would need some
			// change on trie_root to.
			Some(Some(dest))
		} else {
			None
		}
	}
}

/// Children bitmap codec for radix 16 trie.
pub struct Bitmap(u16);

/// Length of a 16 element bitmap.
pub const BITMAP_LENGTH: usize = 2;

impl Bitmap {

	pub fn decode(data: &[u8]) -> Self {
		let map = data[0] as u16 + data[1] as u16 * 256;
		Bitmap(map)
	}

	pub fn value_at(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}

	pub fn encode<I: Iterator<Item = bool>>(has_children: I , output: &mut [u8]) {
		let mut bitmap: u16 = 0;
		let mut cursor: u16 = 1;
		for v in has_children {
			if v { bitmap |= cursor }
			cursor <<= 1;
		}
		output[0] = (bitmap % 256) as u8;
		output[1] = (bitmap / 256) as u8;
	}
}


/// Simple implementation of a additional hash iterator based
/// upon a sequential encoding of known length.
pub struct HashesPlan {
	hash_len: usize,
	/// we use two size counter to implement `size_hint`.
	end: usize,
	offset: usize,
}

impl HashesPlan {
	pub fn new(nb_child: usize, offset: usize, hash_len: usize) -> Self {
		HashesPlan {
			end: offset + (hash_len * nb_child),
			hash_len,
			offset,
		}
	}
}

/// Iterator over additional hashes
/// upon a sequential encoding of known length.
pub struct HashesIter<'a, I, HO> {
	data: &'a [u8],
	ranges: I,
	buffer: HO,
}

impl<'a, I, HO: Default> HashesIter<'a, I, HO> {
	pub fn new(data: &'a [u8], ranges: I) -> Self {
		HashesIter {
			ranges,
			data,
			buffer: HO::default(),
		}
	}
}

impl<'a, I, HO> Iterator for HashesIter<'a, I, HO>
	where
		I: Iterator<Item = Range<usize>>,
		HO: AsMut<[u8]> + Clone, 
{
	type Item = HO;

	fn next(&mut self) -> Option<Self::Item> {
		if let Some(range) = self.ranges.next() {
			self.buffer.as_mut().copy_from_slice(&self.data[range]);
			Some(self.buffer.clone())
		} else {
			None
		}
	}
}

impl Iterator for HashesPlan {
	type Item = Range<usize>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.offset < self.end {
			self.offset += self.hash_len;
			Some(Range {
				start: self.offset - self.hash_len,
				end: self.offset
			})
		} else {
			None
		}
	}

	fn size_hint(&self) -> (usize, Option<usize>) {
		let size = self.end / self.hash_len;
		(size, Some(size))
	}
}

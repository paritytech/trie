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
use hash_db::{HasherHybrid, BinaryHasher};

use crate::rstd::{borrow::Borrow, Error, hash, vec::Vec, ops::Range};

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

/// Trait for handling hybrid proof.
/// This adds methods to basic node codec in order to support:
/// - storage encoding with existing `NodeCodec` methods
/// - encode a proof specific representation. (usually the common representation and
/// the merkle proof of the children stored encoded hash).
/// - Intermediate optional common representation shared between storage
pub trait NodeCodecHybrid: NodeCodec {
	/// Sequence of hashes needed for the children proof verification.
	type AdditionalHashesPlan: Iterator<Item = Range<usize>>;

	/// Technical function to implement `decode_compact_proof`.
	fn decode_plan_compact_proof(data: &[u8]) -> Result<(
		NodePlan,
		Option<(Bitmap, Self::AdditionalHashesPlan)>,
	), Self::Error>;

	/// Decode a `Node` from a proof. The node can miss some branch that
	/// are not use by the proof, in this case they are stored as an inline
	/// zero length child.
	///
	/// With resulting node is attached a bitmap of children included in
	/// the proof calculation and a sequence of additianal node for proof
	/// verification.
	/// In practice this contains inline node that are in the proof and
	/// and ommitted children hash (compacted hash).
	fn decode_compact_proof(data: &[u8]) -> Result<(
		Node,
		Option<(Bitmap, HashesIter<Self::AdditionalHashesPlan, Self::HashOut>)>,
	), Self::Error> {
		let (plan, hashes) = Self::decode_plan_compact_proof(data)?;
		let hashes = hashes.map(|(bitmap, hashes)| (bitmap, HashesIter::new(data, hashes)));
		Ok((plan.build(data), hashes))
	}

	/// Build compact proof encoding from branch info.
	///
	/// - `hash_proof_header`: the part common with the header info from hash.
	/// It can be calculated from `branch_node_common` through
	/// `ChildProofHeader` call, or directly by `branch_node_for_hash`.
	/// - `children`: contains all children, with compact (ommited children) defined as
	/// a null length inline node.
	/// - `hash_buff`: technical buffer for the hasher of the second level proof.
	/// - `in_proof`: position of nodes that are included in proof, this includes
	/// hash nodes (can be deducted from unsized children) and inline nodes.
	/// The children to be include in the proof are therefore the compacted one and the
	/// inline nodes only.
	/// The other children value are needed because they can be included into the additional
	/// hash, and are required for intermediate hash calculation.
	fn encode_compact_proof<H: BinaryHasher>(
		hash_proof_header: Vec<u8>,
		children: &[Option<ChildReference<H::Out>>],
		in_proof: &[bool],
		hash_buf: &mut H::Buffer,
	) -> Vec<u8>;

	/// Does the encoded content need a hybrid proof.
	/// With current hybrid proof capability this is strictly
	/// the same as checking if the node is a branch.
	/// It return the proof header and the NodePlan if hybrid proof is needed.
	fn need_hybrid_proof(data: &[u8]) -> crate::rstd::result::Result<Option<(NodePlan, ChildProofHeader)>, ()>;

	/// Returns branch node encoded for storage, and additional information for hash calculation.
	///
	/// Takes an iterator yielding `ChildReference<Self::HashOut>` and an optional value
	/// as input, the third input is an output container needed for hash calculation.
	fn branch_node_common(
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<&[u8]>,
		register_children: Option<&mut [Option<Range<usize>>]>,
	) -> (Vec<u8>, ChildProofHeader);

	/// Variant of `branch_node_common` but with a nibble.
	///
	/// `number_nibble` is the partial path length, it replaces the one
	/// use by `extension_node`.
	fn branch_node_nibbled_common(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		value: Option<&[u8]>,
		register_children: Option<&mut [Option<Range<usize>>]>,
	) -> (Vec<u8>, ChildProofHeader);

	/// Returns branch node encoded information for hash.
	/// Result is the same as `branch_node_common().1.header(branch_node_common().0`.
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

	/// Return a error from a static description.
	/// Depending on implementation it is fine drop the description
	/// and act as a default error semantic.
	fn codec_error(desc: &'static str) -> Self::Error;
}

/// Information to fetch bytes that needs to be include when calculating a node hash.
/// The node hash is the hash of these information and the merkle root of its children.
#[derive(Clone)]
pub enum ChildProofHeader {
	/// No need for hybrid hash.
	Unused,
	/// Range over the branch encoded for storage.
	Range(Range<usize>),
	/// Allocated in case we cannot use a range.
	Allocated(Vec<u8>),
}

impl ChildProofHeader {
	pub fn header<'a>(&'a self, encoded: &'a [u8]) -> &'a [u8] {
		match self {
			ChildProofHeader::Unused => encoded,
			ChildProofHeader::Range(range) => &encoded[range.clone()],
			ChildProofHeader::Allocated(buff) => &buff[..],
		}
	}
}

use hash_db::{HashDB, Prefix, HashDBRef, Hasher, HashDBHybrid};

pub trait HashDBHybridDyn<H: HasherHybrid, T>: Send + Sync + HashDB<H, T> {
	/// Insert a datum item into the DB and return the datum's hash for a later lookup. Insertions
	/// are counted and the equivalent number of `remove()`s must be performed before the data
	/// is considered dead.
	fn insert_branch_hybrid(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		children: &[Option<Range<usize>>],
		common: ChildProofHeader,
		buffer: &mut <H::InnerHasher as BinaryHasher>::Buffer,
	) -> H::Out;
}

impl<H: HasherHybrid, T, C: HashDBHybrid<H, T>> HashDBHybridDyn<H, T> for C {
	fn insert_branch_hybrid(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		children: &[Option<Range<usize>>],
		common: ChildProofHeader,
		buffer: &mut <H::InnerHasher as BinaryHasher>::Buffer,
	) -> H::Out {
		let nb_children = children.iter().filter(|v| v.is_some()).count();
		let children = children.iter().map(|o_range| o_range.as_ref().map(|range| {
			let mut dest = H::Out::default();
			dest.as_mut()[..range.len()].copy_from_slice(&value[range.clone()]);
			dest
		}));

		<C as HashDBHybrid<H, T>>::insert_branch_hybrid(
			self,
			prefix,
			value,
			common.header(value),
			nb_children,
			children,
			buffer,
		)
	}
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a dyn HashDBHybridDyn<H, T> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> {
		self.as_hash_db().get(key, prefix)
	}

	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		self.as_hash_db().contains(key, prefix)
	}
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a mut dyn HashDBHybridDyn<H, T> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> {
		self.as_hash_db().get(key, prefix)
	}

	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		self.as_hash_db().contains(key, prefix)
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

/// Adapter standard implementation to use with `HashDBInsertComplex` function.
/// This can be use as a callback to insert encoded node into a hashdb when
/// using `insert_hybrid` method.
pub fn hybrid_hash_node_adapter<Codec: NodeCodecHybrid<HashOut = Hasher::Out>, Hasher: HasherHybrid>(
	encoded_node: &[u8]
) -> crate::rstd::result::Result<Option<Hasher::Out>, ()> {
	Codec::need_hybrid_proof(encoded_node).map(|hybrid|
		if let Some((node, common)) = hybrid {
			match node {
				NodePlan::Branch { children, .. } | NodePlan::NibbledBranch { children, .. } => {
					let nb_children = children.iter().filter(|v| v.is_some()).count();
					let children = children.iter().map(|o_range| o_range.as_ref().map(|range| {
						range.as_hash(encoded_node)
					}));
					let mut buf = <Hasher as HasherHybrid>::InnerHasher::init_buffer();
					Some(Hasher::hash_hybrid(
						common.header(encoded_node),
						nb_children,
						children,
						&mut buf,
					))
				},
				_ => unreachable!("hybrid only touch branch node"),
			}
		} else {
			None
		}
	)
}

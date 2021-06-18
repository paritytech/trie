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

//! Reference implementation of a streamer.

use std::fmt;
use std::iter::once;
use std::marker::PhantomData;
use std::ops::Range;
use parity_scale_codec::{Decode, Input, Output, Encode, Compact, Error as CodecError};
use trie_root::{Hasher, MetaHasher};

use trie_db::{
	node::{NibbleSlicePlan, NodePlan, Value, ValuePlan, NodeHandlePlan},
	triedbmut::ChildReference,
	DBValue,
	trie_visit,
	TrieBuilder,
	TrieRoot,
	Partial,
	Meta,
	ChildrenDecoded,
	GlobalMeta,
};
use std::borrow::Borrow;

use trie_db::{
	nibble_ops, NodeCodec,
	Trie, TrieConfiguration, TrieDB, TrieDBMut,
	TrieLayout, TrieMut,
};
pub use trie_root::TrieStream;
pub mod node {
	pub use trie_db::node::Node;
}

/// Reference hasher is a keccak hasher.
pub type RefHasher = keccak_hasher::KeccakHasher;

/// Apply a test method on every test layouts.
#[macro_export]
macro_rules! test_layouts {
	($test:ident, $test_internal:ident) => {
		#[test]
		fn $test() {
			$test_internal::<reference_trie::CheckMetaHasherNoExt>();
			$test_internal::<reference_trie::NoExtensionLayout>();
			$test_internal::<reference_trie::ExtensionLayout>();
		}
	};
}

/// Apply a test method on every test layouts.
#[macro_export]
macro_rules! test_layouts_no_meta {
	($test:ident, $test_internal:ident) => {
		#[test]
		fn $test() {
			$test_internal::<reference_trie::NoExtensionLayout>();
			$test_internal::<reference_trie::ExtensionLayout>();
		}
	};
}


/// Trie layout using extension nodes.
#[derive(Default, Clone)]
pub struct ExtensionLayout;

impl TrieLayout for ExtensionLayout {
	const USE_EXTENSION: bool = true;
	const ALLOW_EMPTY: bool = false;
	type Hash = RefHasher;
	type Codec = ReferenceNodeCodec<RefHasher>;
	type MetaHasher = hash_db::NoMeta;
	type Meta = ();

	fn global_meta(&self) -> <Self::Meta as Meta>::GlobalMeta {
		()
	}
}

impl TrieConfiguration for ExtensionLayout { }

/// Trie layout without extension nodes, allowing
/// generic hasher.
pub struct GenericNoExtensionLayout<H>(PhantomData<H>);

impl<H> Default for GenericNoExtensionLayout<H> {
	fn default() -> Self {
		GenericNoExtensionLayout(PhantomData)
	}
}

impl<H> Clone for GenericNoExtensionLayout<H> {
	fn clone(&self) -> Self {
		GenericNoExtensionLayout(PhantomData)
	}
}

impl<H: Hasher> TrieLayout for GenericNoExtensionLayout<H> {
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = false;
	type Hash = H;
	type Codec = ReferenceNodeCodecNoExt<H>;
	type MetaHasher = hash_db::NoMeta;
	type Meta = ();

	fn global_meta(&self) -> <Self::Meta as Meta>::GlobalMeta {
		()
	}
}

/// Trie that allows empty values.
#[derive(Default, Clone)]
pub struct AllowEmptyLayout;

impl TrieLayout for AllowEmptyLayout {
	const USE_EXTENSION: bool = true;
	const ALLOW_EMPTY: bool = true;
	type Hash = RefHasher;
	type Codec = ReferenceNodeCodec<RefHasher>;
	type MetaHasher = hash_db::NoMeta;
	type Meta = ();

	fn global_meta(&self) -> <Self::Meta as Meta>::GlobalMeta {
		()
	}
}

/// Contains threshold for applying alt_hashing.
#[derive(Default, Clone, Debug)]
pub struct CheckMetaHasherNoExt(pub Option<u32>);

impl TrieLayout for CheckMetaHasherNoExt {
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = false;
	const USE_META: bool = true;

	type Hash = RefHasher;
	type Codec = ReferenceNodeCodecNoExtMeta<RefHasher>;
	type MetaHasher = TestMetaHasher;
	type Meta = TrieMeta;

	fn global_meta(&self) -> <Self::Meta as Meta>::GlobalMeta {
		self.0
	}
}

/// Test alt hashing.
/// Also allow indicating that value is a hash of value.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct TestMetaHasher;

impl<H: Hasher> hash_db::MetaHasher<H, DBValue> for TestMetaHasher {
	type Meta = TrieMeta;
	type GlobalMeta = Option<u32>;

	fn hash(value: &[u8], meta: &Self::Meta) -> H::Out {
		match &meta {
			TrieMeta { range: Some(range), contain_hash: false, apply_inner_hashing: true, .. } => {
				let value = inner_hashed_value::<H>(value, Some((range.start, range.end)));
				H::hash(value.as_slice())
			},
			TrieMeta { range: Some(_range), contain_hash: true, .. } => {
				// value contains a hash of data (already inner_hashed_value).
				H::hash(value)
			},
			_ => {
				H::hash(value)
			},
		}
	}

	fn stored_value(value: &[u8], mut meta: Self::Meta) -> DBValue {
		let mut stored = Vec::with_capacity(value.len() + 1);
		if meta.contain_hash {
			// already contain hash, just flag it.
			stored.push(trie_constants::DEAD_HEADER_META_HASHED_VALUE);
			stored.extend_from_slice(value);
			return stored;
		}
		if meta.unused_value && meta.apply_inner_hashing {
			if meta.range.is_some() {
				// Warning this assumes that encoded value cannot start by this,
				// so it is tightly coupled with the header type of the codec.
				stored.push(trie_constants::DEAD_HEADER_META_HASHED_VALUE);
				let range = meta.range.as_ref().expect("Tested in condition");
				meta.contain_hash = true; // useless but could be with meta as &mut
				// store hash instead of value.
				let value = inner_hashed_value::<H>(value, Some((range.start, range.end)));
				stored.extend_from_slice(value.as_slice());
				return stored;
			}
		}
		stored.extend_from_slice(value);
		stored
	}

	fn stored_value_owned(value: DBValue, meta: Self::Meta) -> DBValue {
		<Self as MetaHasher<H, DBValue>>::stored_value(value.as_slice(), meta)
	}

	fn extract_value(mut stored: &[u8], global_meta: Self::GlobalMeta) -> (&[u8], Self::Meta) {
		let input = &mut stored;
		let mut contain_hash = false;
		if input.get(0) == Some(&trie_constants::DEAD_HEADER_META_HASHED_VALUE) {
			contain_hash = true;
			*input = &input[1..];
		}
		let mut meta = TrieMeta {
			range: None,
			unused_value: contain_hash,
			contain_hash,
			apply_inner_hashing: false,
			try_inner_hashing: None,
		};
		meta.set_global_meta(global_meta);
		(stored, meta)
	}

	fn extract_value_owned(mut stored: DBValue, global: Self::GlobalMeta) -> (DBValue, Self::Meta) {
		let len = stored.len();
		let (v, meta) = <Self as MetaHasher<H, DBValue>>::extract_value(stored.as_slice(), global);
		let removed = len - v.len();
		(stored.split_off(removed), meta)
	}
}

/// Meta use by trie state.
#[derive(Default, Clone, Debug)]
pub struct TrieMeta {
	/// Range of encoded value or hashed value.
	/// When encoded value, it includes the length of the value.
	pub range: Option<core::ops::Range<usize>>,
	/// Defined in the trie layout, when used with
	/// `TrieDbMut` it switch nodes to alternative hashing
	/// method by defining the threshold to use with alternative
	/// hashing.
	/// Trie codec or other proof manipulation will always use
	/// `None` in order to prevent state change on reencoding.
	pub try_inner_hashing: Option<u32>,
	/// Flag indicating alternative value hash is currently use
	/// or will be use.
	pub apply_inner_hashing: bool,
	/// Does current encoded contains a hash instead of
	/// a value (information stored in meta for proofs).
	pub contain_hash: bool,
	/// Record if a value was accessed, this is
	/// set as accessed by defalult, but can be
	/// change on access explicitely: `HashDB::get_with_meta`.
	/// and reset on access explicitely: `HashDB::access_from`.
	/// Not strictly needed in this struct, but does not add memory usage here.
	pub unused_value: bool,
}

impl Meta for TrieMeta {
	/// When true apply inner hashing of value.
	type GlobalMeta = Option<u32>;

	/// When true apply inner hashing of value.
	type StateMeta = bool;

	fn set_state_meta(&mut self, state_meta: Self::StateMeta) {
		self.apply_inner_hashing = state_meta;
	}

	fn read_state_meta(&self) -> Self::StateMeta {
		self.apply_inner_hashing
	}

	fn read_global_meta(&self) -> Self::GlobalMeta {
		self.try_inner_hashing
	}

	fn set_global_meta(&mut self, global_meta: Self::GlobalMeta) {
		self.try_inner_hashing = global_meta;
	}

	fn meta_for_new(
		global: Self::GlobalMeta,
	) -> Self {
		let mut result = Self::default();
		result.set_global_meta(global);
		result
	}

	fn meta_for_existing_inline_node(
		global: Self::GlobalMeta,
	) -> Self {
		Self::meta_for_new(global)
	}

	fn meta_for_empty(
		global: Self::GlobalMeta,
	) -> Self {
		Self::meta_for_new(global)
	}

	fn encoded_value_callback(
		&mut self,
		value_plan: ValuePlan,
	) {
		let (contain_hash, range) = match value_plan {
			ValuePlan::Value(range, with_len) => (false, with_len..range.end),
			ValuePlan::HashedValue(range, _size) => (true, range),
			ValuePlan::NoValue => return,
		};

		if let Some(threshold) = self.try_inner_hashing.clone() {
			self.apply_inner_hashing = range.end - range.start >= threshold as usize;
		}

		self.range = Some(range);
		self.contain_hash = contain_hash;
	}

	fn decoded_callback(
		&mut self,
		node_plan: &NodePlan,
	) {
		let (contain_hash, range) = match node_plan.value_plan() {
			Some(ValuePlan::Value(range, with_len)) => (false, *with_len..range.end),
			Some(ValuePlan::HashedValue(range, _size)) => (true, range.clone()),
			Some(ValuePlan::NoValue) => return,
			None => return,
		};

		self.range = Some(range);
		self.contain_hash = contain_hash;
	}

	fn contains_hash_of_value(&self) -> bool {
		self.contain_hash
	}
}

impl TrieMeta {
	/// Was value accessed.
	pub fn accessed_value(&mut self) -> bool {
		!self.unused_value
	}

	/// For proof, this allow setting node as unaccessed until
	/// a call to `access_from`.
	pub fn set_accessed_value(&mut self, accessed: bool) {
		self.unused_value = !accessed;
	}
}

/// Treshold for using hash of value instead of value
/// in encoded trie node.
pub const INNER_HASH_TRESHOLD: usize = 1;

/// Representation with inner hash.
pub fn inner_hashed_value<H: Hasher>(x: &[u8], range: Option<(usize, usize)>) -> Vec<u8> {
	if let Some((start, end)) = range {
		let len = x.len();
		if start < len && end == len {
			// terminal inner hash
			let hash_end = H::hash(&x[start..]);
			let mut buff = vec![0; x.len() + hash_end.as_ref().len() - (end - start)];
			buff[..start].copy_from_slice(&x[..start]);
			buff[start..].copy_from_slice(hash_end.as_ref());
			return buff;
		}
		if start == 0 && end < len {
			// start inner hash
			let hash_start = H::hash(&x[..start]);
			let hash_len = hash_start.as_ref().len();
			let mut buff = vec![0; x.len() + hash_len - (end - start)];
			buff[..hash_len].copy_from_slice(hash_start.as_ref());
			buff[hash_len..].copy_from_slice(&x[end..]);
			return buff;
		}
		if start < len && end < len {
			// middle inner hash
			let hash_middle = H::hash(&x[start..end]);
			let hash_len = hash_middle.as_ref().len();
			let mut buff = vec![0; x.len() + hash_len - (end - start)];
			buff[..start].copy_from_slice(&x[..start]);
			buff[start..start + hash_len].copy_from_slice(hash_middle.as_ref());
			buff[start + hash_len..].copy_from_slice(&x[end..]);
			return buff;
		}
	}
	// if anything wrong default to hash
	x.to_vec()
}

mod codec_alt_hashing {
	use super::*;
	use super::TestMetaHasher as StateHasher;
	use super::CodecError as Error;
	use super::NodeCodec as NodeCodecT;

	/// Constants specific to encoding with alt hashing.
	pub mod trie_constants {
		const FIRST_PREFIX: u8 = 0b_00 << 6;
		/// In proof this header is used when only hashed value is stored.
		pub const DEAD_HEADER_META_HASHED_VALUE: u8 = EMPTY_TRIE | 0b_00_01;
		pub const NIBBLE_SIZE_BOUND: usize = u16::max_value() as usize;
		pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
		pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
		pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
		pub const EMPTY_TRIE: u8 = FIRST_PREFIX | (0b_00 << 4);
		pub const ALT_HASHING_LEAF_PREFIX_MASK: u8 = FIRST_PREFIX | (0b_1 << 5);
		pub const ALT_HASHING_BRANCH_WITH_MASK: u8 = FIRST_PREFIX | (0b_01 << 4);
	}

	#[derive(Default, Clone)]
	pub struct NodeCodec<H>(PhantomData<H>);

	impl<H: Hasher> NodeCodec<H> {
		fn decode_plan_inner_hashed<M: Meta<StateMeta = bool>>(
			data: &[u8],
			meta: &mut M,
		) -> Result<NodePlan, Error> {
			let mut input = ByteSliceInput::new(data);

			let contains_hash = meta.contains_hash_of_value();
			let header = NodeHeader::decode(&mut input)?;
			let alt_hashing = header.alt_hashing();
			meta.set_state_meta(alt_hashing);

			let branch_has_value = if let NodeHeader::Branch(has_value, _) = &header {
				*has_value
			} else {
				// alt_hash_branch
				true
			};

			match header {
				NodeHeader::Null => Ok(NodePlan::Empty),
				NodeHeader::AltHashBranch(nibble_count)
				| NodeHeader::Branch(_, nibble_count) => {
					let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
					// check that the padding is valid (if any)
					if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
						return Err(CodecError::from("Bad format"));
					}
					let partial = input.take(
						(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE,
					)?;
					let partial_padding = nibble_ops::number_padding(nibble_count);
					let bitmap_range = input.take(BITMAP_LENGTH)?;
					let bitmap = Bitmap::decode(&data[bitmap_range])?;
					let value = if branch_has_value {
						if alt_hashing && contains_hash {
							ValuePlan::HashedValue(input.take(H::LENGTH)?, 0)
						} else {
							let with_len = input.offset;
							let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
							ValuePlan::Value(input.take(count)?, with_len)
						}
					} else {
						ValuePlan::NoValue
					};
					let mut children = [
						None, None, None, None, None, None, None, None,
						None, None, None, None, None, None, None, None,
					];
					for i in 0..nibble_ops::NIBBLE_LENGTH {
						if bitmap.value_at(i) {
							let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
							let range = input.take(count)?;
							children[i] = Some(if count == H::LENGTH {
								NodeHandlePlan::Hash(range)
							} else {
								NodeHandlePlan::Inline(range)
							});
						}
					}
					Ok(NodePlan::NibbledBranch {
						partial: NibbleSlicePlan::new(partial, partial_padding),
						value,
						children,
					})
				},
				NodeHeader::AltHashLeaf(nibble_count)
				| NodeHeader::Leaf(nibble_count) => {
					let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
					// check that the padding is valid (if any)
					if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
						return Err(CodecError::from("Bad format"));
					}
					let partial = input.take(
						(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE,
					)?;
					let partial_padding = nibble_ops::number_padding(nibble_count);
					let value = if alt_hashing && contains_hash {
						ValuePlan::HashedValue(input.take(H::LENGTH)?, 0)
					} else {
						let with_len = input.offset;
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						ValuePlan::Value(input.take(count)?, with_len)
					};

					Ok(NodePlan::Leaf {
						partial: NibbleSlicePlan::new(partial, partial_padding),
						value,
					})
				}
			}
		}
	}

	impl<H, M> NodeCodecT<M> for NodeCodec<H>
		where
			H: Hasher,
			M: Meta<StateMeta = bool, GlobalMeta = Option<u32>>,
	{
		type Error = Error;
		type HashOut = H::Out;

		fn hashed_null_node() -> <H as Hasher>::Out {
			H::hash(<Self as NodeCodecT<M>>::empty_node_no_meta())
		}

		fn decode_plan(data: &[u8], meta: &mut M) -> Result<NodePlan, Self::Error> {
			Self::decode_plan_inner_hashed(data, meta).map(|plan| {
				meta.decoded_callback(&plan);
				plan
			})
		}

		fn decode_plan_inner(_data: &[u8]) -> Result<NodePlan, Self::Error> {
			unreachable!("decode_plan is implemented")
		}

		fn is_empty_node(data: &[u8]) -> bool {
			data == <Self as NodeCodecT<M>>::empty_node_no_meta()
		}

		fn empty_node(_meta: &mut M) -> Vec<u8> {
			vec![trie_constants::EMPTY_TRIE]
		}

		fn empty_node_no_meta() -> &'static [u8] {
			&[trie_constants::EMPTY_TRIE]
		}

		fn leaf_node(partial: Partial, value: Value, meta: &mut M) -> Vec<u8> {
			// Note that we use AltHash type only if inner hashing will occur,
			// this way we allow changing hash threshold.
			// With fix inner hashing alt hash can be use with all node, but
			// that is not better (encoding can use an additional nibble byte
			// sometime).
			let mut output = if meta.read_global_meta().as_ref().map(|threshold|
				value_do_hash(&value, threshold)
			).unwrap_or(meta.read_state_meta()) {
				partial_encode(partial, NodeKind::AltHashLeaf)
			} else {
				partial_encode(partial, NodeKind::Leaf)
			};
			match value {
				Value::Value(value) => {
					let with_len = output.len();
					Compact(value.len() as u32).encode_to(&mut output);
					let start = output.len();
					output.extend_from_slice(value);
					let end = output.len();
					meta.encoded_value_callback(ValuePlan::Value(start..end, with_len));
				},
				Value::HashedValue(hash, _size) => {
					debug_assert!(hash.len() == H::LENGTH);
					let start = output.len();
					output.extend_from_slice(hash);
					let end = output.len();
					meta.encoded_value_callback(ValuePlan::HashedValue(start..end, 0));
				},
				Value::NoValue => unimplemented!("No support for incomplete nodes"),
			}
			output
		}

		fn extension_node(
			_partial: impl Iterator<Item = u8>,
			_nbnibble: usize,
			_child: ChildReference<<H as Hasher>::Out>,
			_meta: &mut M,
		) -> Vec<u8> {
			unreachable!()
		}

		fn branch_node(
			_children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
			_maybe_value: Value,
			_meta: &mut M,
		) -> Vec<u8> {
			unreachable!()
		}

		fn branch_node_nibbled(
			partial: impl Iterator<Item = u8>,
			number_nibble: usize,
			children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
			value: Value,
			meta: &mut M,
		) -> Vec<u8> {
			let mut output = match (&value,  meta.read_global_meta().as_ref().map(|threshold|
				value_do_hash(&value, threshold)
			).unwrap_or(meta.read_state_meta())) {
				(&Value::NoValue, _) => {
					partial_from_iterator_encode(partial, number_nibble, NodeKind::BranchNoValue)
				},
				(_, false) => {
					partial_from_iterator_encode(partial, number_nibble, NodeKind::BranchWithValue)
				},
				(_, true) => {
					partial_from_iterator_encode(partial, number_nibble, NodeKind::AltHashBranchWithValue)
				},
			};

			let bitmap_index = output.len();
			let mut bitmap: [u8; BITMAP_LENGTH] = [0; BITMAP_LENGTH];
			(0..BITMAP_LENGTH).for_each(|_|output.push(0));
			match value {
				Value::Value(value) => {
					let with_len = output.len();
					Compact(value.len() as u32).encode_to(&mut output);
					let start = output.len();
					output.extend_from_slice(value);
					let end = output.len();
					meta.encoded_value_callback(ValuePlan::Value(start..end, with_len));
				},
				Value::HashedValue(hash, _size) => {
					debug_assert!(hash.len() == H::LENGTH);
					let start = output.len();
					output.extend_from_slice(hash);
					let end = output.len();
					meta.encoded_value_callback(ValuePlan::HashedValue(start..end, 0));
				},
				Value::NoValue => (),
			}
			Bitmap::encode(children.map(|maybe_child| match maybe_child.borrow() {
				Some(ChildReference::Hash(h)) => {
					h.as_ref().encode_to(&mut output);
					true
				}
				&Some(ChildReference::Inline(inline_data, len)) => {
					inline_data.as_ref()[..len].encode_to(&mut output);
					true
				}
				None => false,
			}), bitmap.as_mut());
			output[bitmap_index..bitmap_index + BITMAP_LENGTH]
				.copy_from_slice(&bitmap[..BITMAP_LENGTH]);
			output
		}
	}

	// utils

	fn value_do_hash(val: &Value, threshold: &u32) -> bool {
		match val {
			Value::Value(val) => {
				val.encoded_size() >= *threshold as usize
			},
			Value::HashedValue(..) => true, // can only keep hashed
			Value::NoValue => {
				false
			},
		}
	}

	/// Encode and allocate node type header (type and size), and partial value.
	/// It uses an iterator over encoded partial bytes as input.
	fn partial_from_iterator_encode<I: Iterator<Item = u8>>(
		partial: I,
		nibble_count: usize,
		node_kind: NodeKind,
	) -> Vec<u8> {
		let nibble_count = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, nibble_count);

		let mut output = Vec::with_capacity(3 + (nibble_count / nibble_ops::NIBBLE_PER_BYTE));
		match node_kind {
			NodeKind::Leaf => NodeHeader::Leaf(nibble_count).encode_to(&mut output),
			NodeKind::BranchWithValue => NodeHeader::Branch(true, nibble_count).encode_to(&mut output),
			NodeKind::BranchNoValue => NodeHeader::Branch(false, nibble_count).encode_to(&mut output),
			NodeKind::AltHashLeaf => NodeHeader::AltHashLeaf(nibble_count).encode_to(&mut output),
			NodeKind::AltHashBranchWithValue => NodeHeader::AltHashBranch(nibble_count)
				.encode_to(&mut output),
		};
		output.extend(partial);
		output
	}

	/// Encode and allocate node type header (type and size), and partial value.
	/// Same as `partial_from_iterator_encode` but uses non encoded `Partial` as input.
	fn partial_encode(partial: Partial, node_kind: NodeKind) -> Vec<u8> {
		let number_nibble_encoded = (partial.0).0 as usize;
		let nibble_count = partial.1.len() * nibble_ops::NIBBLE_PER_BYTE + number_nibble_encoded;

		let nibble_count = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, nibble_count);

		let mut output = Vec::with_capacity(3 + partial.1.len());
		match node_kind {
			NodeKind::Leaf => NodeHeader::Leaf(nibble_count).encode_to(&mut output),
			NodeKind::BranchWithValue => NodeHeader::Branch(true, nibble_count).encode_to(&mut output),
			NodeKind::BranchNoValue => NodeHeader::Branch(false, nibble_count).encode_to(&mut output),
			NodeKind::AltHashLeaf => NodeHeader::AltHashLeaf(nibble_count).encode_to(&mut output),
			NodeKind::AltHashBranchWithValue => NodeHeader::AltHashBranch(nibble_count)
				.encode_to(&mut output),
		};
		if number_nibble_encoded > 0 {
			output.push(nibble_ops::pad_right((partial.0).1));
		}
		output.extend_from_slice(&partial.1[..]);
		output
	}

	/// A node header
	#[derive(Copy, Clone, PartialEq, Eq, Debug)]
	pub(crate) enum NodeHeader {
		Null,
		Branch(bool, usize),
		Leaf(usize),
		AltHashBranch(usize),
		AltHashLeaf(usize),
	}

	/// NodeHeader without content
	pub(crate) enum NodeKind {
		Leaf,
		BranchNoValue,
		BranchWithValue,
		AltHashLeaf,
		AltHashBranchWithValue,
	}

	impl Encode for NodeHeader {
		fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
			match self {
				NodeHeader::Null => output.push_byte(trie_constants::EMPTY_TRIE),
				NodeHeader::Branch(true, nibble_count)	=>
					encode_size_and_prefix(*nibble_count, trie_constants::BRANCH_WITH_MASK, 2, output),
				NodeHeader::Branch(false, nibble_count) =>
					encode_size_and_prefix(*nibble_count, trie_constants::BRANCH_WITHOUT_MASK, 2, output),
				NodeHeader::Leaf(nibble_count) =>
					encode_size_and_prefix(*nibble_count, trie_constants::LEAF_PREFIX_MASK, 2, output),
				NodeHeader::AltHashBranch(nibble_count)	=>
					encode_size_and_prefix(*nibble_count, trie_constants::ALT_HASHING_BRANCH_WITH_MASK, 4, output),
				NodeHeader::AltHashLeaf(nibble_count)	=>
					encode_size_and_prefix(*nibble_count, trie_constants::ALT_HASHING_LEAF_PREFIX_MASK, 3, output),
			}
		}
	}

	impl NodeHeader {
		/// Is this header using alternate hashing scheme.
		pub(crate) fn alt_hashing(&self) -> bool {
			match self {
				NodeHeader::Null
				| NodeHeader::Leaf(..)
				| NodeHeader::Branch(..) => false,
				NodeHeader::AltHashBranch(..)
				| NodeHeader::AltHashLeaf(..) => true,
			}
		}
	}

	impl parity_scale_codec::EncodeLike for NodeHeader {}

	impl Decode for NodeHeader {
		fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
			let i = input.read_byte()?;
			if i == trie_constants::EMPTY_TRIE {
				return Ok(NodeHeader::Null);
			}
			match i & (0b11 << 6) {
				trie_constants::LEAF_PREFIX_MASK => Ok(NodeHeader::Leaf(decode_size(i, input, 2)?)),
				trie_constants::BRANCH_WITH_MASK => Ok(NodeHeader::Branch(true, decode_size(i, input, 2)?)),
				trie_constants::BRANCH_WITHOUT_MASK => Ok(NodeHeader::Branch(false, decode_size(i, input, 2)?)),
				trie_constants::EMPTY_TRIE => {
					if i & (0b111 << 5) == trie_constants::ALT_HASHING_LEAF_PREFIX_MASK {
						Ok(NodeHeader::AltHashLeaf(decode_size(i, input, 3)?))
					} else if i & (0b1111 << 4) == trie_constants::ALT_HASHING_BRANCH_WITH_MASK {
						Ok(NodeHeader::AltHashBranch(decode_size(i, input, 4)?))
					} else {
						// do not allow any special encoding
						Err("Unallowed encoding".into())
					}
				},
				_ => unreachable!(),
			}
		}
	}

	/// Returns an iterator over encoded bytes for node header and size.
	/// Size encoding allows unlimited, length inefficient, representation, but
	/// is bounded to 16 bit maximum value to avoid possible DOS.
	pub(crate) fn size_and_prefix_iterator(
		size: usize,
		prefix: u8,
		prefix_mask: usize,
	) -> impl Iterator<Item = u8> {
		let size = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, size);

		let max_value = 255u8 >> prefix_mask;
		let l1 = std::cmp::min(max_value as usize - 1, size);
		let (first_byte, mut rem) = if size == l1 {
			(once(prefix + l1 as u8), 0)
		} else {
			(once(prefix + max_value as u8), size - l1)
		};
		let next_bytes = move || {
			if rem > 0 {
				if rem < 256 {
					let result = rem - 1;
					rem = 0;
					Some(result as u8)
				} else {
					rem = rem.saturating_sub(255);
					Some(255)
				}
			} else {
				None
			}
		};
		first_byte.chain(std::iter::from_fn(next_bytes))
	}

	/// Encodes size and prefix to a stream output (prefix on 2 first bit only).
	fn encode_size_and_prefix<W>(size: usize, prefix: u8, prefix_mask: usize, out: &mut W)
		where W: Output + ?Sized,
	{
		for b in size_and_prefix_iterator(size, prefix, prefix_mask) {
			out.push_byte(b)
		}
	}

	/// Decode size only from stream input and header byte.
	fn decode_size(
		first: u8,
		input: &mut impl Input,
		prefix_mask: usize,
	) -> Result<usize, Error> {
		let max_value = 255u8 >> prefix_mask;
		let mut result = (first & max_value) as usize;
		if result < max_value as usize {
			return Ok(result);
		}
		result -= 1;
		while result <= trie_constants::NIBBLE_SIZE_BOUND {
			let n = input.read_byte()? as usize;
			if n < 255 {
				return Ok(result + n + 1);
			}
			result += 255;
		}
		Ok(trie_constants::NIBBLE_SIZE_BOUND)
	}

	/// Reference implementation of a `TrieStream` without extension.
	#[derive(Default, Clone)]
	pub struct ReferenceTrieStreamNoExt {
		/// Current node buffer.
		buffer: Vec<u8>,
		/// Global trie alt hashing activation.
		inner_value_hashing: Option<u32>,
		/// For current node, do we use alt hashing.
		apply_inner_hashing: bool,
		/// Keep trace of position of encoded value.
		current_value_range: Option<Range<usize>>,
	}

	/// Create a leaf/branch node, encoding a number of nibbles.
	fn fuse_nibbles_node<'a>(nibbles: &'a [u8], kind: NodeKind) -> impl Iterator<Item = u8> + 'a {
		let size = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, nibbles.len());

		let iter_start = match kind {
			NodeKind::Leaf => size_and_prefix_iterator(size, trie_constants::LEAF_PREFIX_MASK, 2),
			NodeKind::BranchNoValue => size_and_prefix_iterator(size, trie_constants::BRANCH_WITHOUT_MASK, 2),
			NodeKind::BranchWithValue => size_and_prefix_iterator(size, trie_constants::BRANCH_WITH_MASK, 2),
			NodeKind::AltHashLeaf =>
				size_and_prefix_iterator(size, trie_constants::ALT_HASHING_LEAF_PREFIX_MASK, 3),
			NodeKind::AltHashBranchWithValue =>
				size_and_prefix_iterator(size, trie_constants::ALT_HASHING_BRANCH_WITH_MASK, 4),
		};
		iter_start
			.chain(if nibbles.len() % 2 == 1 { Some(nibbles[0]) } else { None })
			.chain(nibbles[nibbles.len() % 2..].chunks(2).map(|ch| ch[0] << 4 | ch[1]))
	}
	fn value_do_hash_stream(val: &[u8], threshold: &u32) -> bool {
		val.encoded_size() >= *threshold as usize
	}
	impl TrieStream for ReferenceTrieStreamNoExt {
		type GlobalMeta = Option<u32>;

		fn new(meta: Option<u32>) -> Self {
			Self {
				buffer: Vec::new(),
				inner_value_hashing: meta,
				apply_inner_hashing: false,
				current_value_range: None,
			}
		}

		fn append_empty_data(&mut self) {
			self.buffer.push(trie_constants::EMPTY_TRIE);
		}

		fn append_leaf(&mut self, key: &[u8], value: &[u8]) {
			self.apply_inner_hashing = self.inner_value_hashing.as_ref().map(|threshold|
				value_do_hash_stream(value, threshold)
			).unwrap_or(false);
			let kind = if self.apply_inner_hashing {
				NodeKind::AltHashLeaf
			} else {
				NodeKind::Leaf
			};
			self.buffer.extend(fuse_nibbles_node(key, kind));
			let start = self.buffer.len();
			Compact(value.len() as u32).encode_to(&mut self.buffer);
			self.buffer.extend_from_slice(value);
			self.current_value_range = Some(start..self.buffer.len());
		}

		fn begin_branch(
			&mut self,
			maybe_partial: Option<&[u8]>,
			maybe_value: Option<&[u8]>,
			has_children: impl Iterator<Item = bool>,
		) {
			if let Some(partial) = maybe_partial {
				if let Some(value) = maybe_value {
					self.apply_inner_hashing = self.inner_value_hashing.as_ref().map(|threshold|
						value_do_hash_stream(value, threshold)
					).unwrap_or(false);
					let kind = if self.apply_inner_hashing {
						NodeKind::AltHashBranchWithValue
					} else {
						NodeKind::BranchWithValue
					};
					self.buffer.extend(fuse_nibbles_node(partial, kind));
				} else {
					self.buffer.extend(fuse_nibbles_node(partial, NodeKind::BranchNoValue));
				}
				let bm = branch_node_bit_mask(has_children);
				self.buffer.extend([bm.0,bm.1].iter());
			} else {
				debug_assert!(false, "trie stream codec only for no extension trie");
				self.buffer.extend(&branch_node(maybe_value.is_some(), has_children));
			}
			if let Some(value) = maybe_value {
				let start = self.buffer.len();
				Compact(value.len() as u32).encode_to(&mut self.buffer);
				self.buffer.extend_from_slice(value);
				self.current_value_range = Some(start..self.buffer.len());
			}
		}

		fn append_extension(&mut self, _key: &[u8]) {
			debug_assert!(false, "trie stream codec only for no extension trie");
		}

		fn append_substream<H: Hasher>(&mut self, other: Self) {
			let apply_inner_hashing = other.apply_inner_hashing;
			let range = other.current_value_range.clone();
			let data = other.out();
			match data.len() {
				0..=31 => data.encode_to(&mut self.buffer),
				_ => {
					if apply_inner_hashing {
						let meta = TrieMeta {
							range: range,
							unused_value: false,
							contain_hash: false,
							// Using `inner_value_hashing` instead to check this.
							// And unused in hasher.
							try_inner_hashing: None,
							apply_inner_hashing: true,
						};
						<StateHasher as MetaHasher<H, Vec<u8>>>::hash(&data, &meta).as_ref()
							.encode_to(&mut self.buffer);
					} else {
						H::hash(&data).as_ref().encode_to(&mut self.buffer);
					}
				},
			}
		}

		fn hash_root<H: Hasher>(self) -> H::Out {
			let apply_inner_hashing = self.apply_inner_hashing;
			let range = self.current_value_range;
			let data = self.buffer;
			let meta = TrieMeta {
				range: range,
				unused_value: false,
				contain_hash: false,
				try_inner_hashing: None,
				apply_inner_hashing: true,
			};

			if apply_inner_hashing {
				<StateHasher as MetaHasher<H, Vec<u8>>>::hash(&data, &meta)
			} else {
				H::hash(&data)
			}
		}

		fn out(self) -> Vec<u8> { self.buffer }
	}
}

pub use codec_alt_hashing::NodeCodec as ReferenceNodeCodecNoExtMeta;
pub use codec_alt_hashing::ReferenceTrieStreamNoExt;
pub use codec_alt_hashing::trie_constants;

#[derive(Clone, Copy, Debug)]
pub enum Version {
	Old,
	New,
}

impl Default for Version {
	fn default() -> Self {
		// freshly created nodes are New.
		Version::New
	}
}

/// previous layout in updatable scenario.
#[derive(Default, Clone)]
pub struct Old;

impl TrieLayout for Old {
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = false;
	type Hash = RefHasher;
	type Codec = ReferenceNodeCodecNoExt<RefHasher>;
	type MetaHasher = hash_db::NoMeta;
	type Meta = ();

	fn global_meta(&self) -> <Self::Meta as Meta>::GlobalMeta {
		()
	}
}

/// Test Meta input.
#[derive(Default, Clone, Debug)]
pub struct VersionedValueMeta {
	range: Option<core::ops::Range<usize>>,
	old_remaining_children: Option<Vec<u8>>,
	version: Version,
}

impl Meta for VersionedValueMeta {
	type GlobalMeta = Version;

	type StateMeta = ();

	fn set_state_meta(&mut self, _state_meta: Self::StateMeta) {
	}

	fn read_state_meta(&self) -> Self::StateMeta {
		()
	}

	fn set_global_meta(&mut self, _global_meta: Self::GlobalMeta) {
	}

	fn read_global_meta(&self) -> Self::GlobalMeta {
		self.version.clone()
	}

	fn meta_for_new(
		input: Self::GlobalMeta,
	) -> Self {
		let old_remaining_children = if matches!(input, Version::Old) {
			Some(Vec::new())
		} else {
			None
		};
		VersionedValueMeta { range: None, version: input, old_remaining_children }
	}

	fn meta_for_existing_inline_node(
		input: Self::GlobalMeta,
	) -> Self {
		let old_remaining_children = if matches!(input, Version::Old) {
			Some(Vec::new())
		} else {
			None
		};
		VersionedValueMeta { range: None, version: input, old_remaining_children }
	}

	fn meta_for_empty(
		input: Self::GlobalMeta,
	) -> Self {
		// empty is same for new and old, using new
		VersionedValueMeta { range: None, version: input, old_remaining_children: None }
	}

	fn encoded_value_callback(
		&mut self,
		value_plan: ValuePlan,
	) {
		if matches!(self.version, Version::New) {
			let range = match value_plan {
				ValuePlan::Value(range, _) => range,
				ValuePlan::HashedValue(_range, _size) => unimplemented!(),
				ValuePlan::NoValue => return,
			};

			if range.end - range.start >= INNER_HASH_TRESHOLD {
				self.range = Some(range);
			}
		}
	}

	fn decoded_callback(
		&mut self,
		node_plan: &trie_db::node::NodePlan,
	) {
		if matches!(self.version, Version::Old) {
			if self.old_remaining_children.is_none() {
				let mut non_inline_children = Vec::new();
				for (index, child) in node_plan.inline_children().enumerate() {
					if matches!(child, ChildrenDecoded::Hash) {
						// overflow for radix > 256, ok with current hex trie only implementation.
						non_inline_children.push(index as u8);
					}
				}
				self.old_remaining_children = Some(non_inline_children);
			}
		}
	}

	fn contains_hash_of_value(&self) -> bool {
		false
	}
}

/// Test value function: prepend optional encoded size of value
pub struct TestUpdatableMetaHasher<H>(PhantomData<H>);

impl<H: Hasher> hash_db::MetaHasher<H, DBValue> for TestUpdatableMetaHasher<H> {
	type Meta = VersionedValueMeta;
	type GlobalMeta = Version;

	fn hash(value: &[u8], meta: &Self::Meta) -> H::Out {
		if matches!(meta.version, Version::New) {
			if let Some(range) = meta.range.as_ref() {
				assert!(matches!(meta.version,Version::New));
				let value = inner_hashed_value::<H>(value, Some((range.start, range.end)));
				return H::hash(value.as_slice());
			}
		}
		H::hash(value)
	}

	fn stored_value(value: &[u8], meta: Self::Meta) -> DBValue {
		if let Version::Old = meta.version {
			// non empty empty trie byte for old node
			let mut stored = Vec::with_capacity(value.len() + 20);
			stored.push(EMPTY_TRIE); // 1 byte
			stored.extend_from_slice(meta.old_remaining_children.encode().as_slice()); // max 18 byt
			stored.extend_from_slice(value);
			stored
		} else {
			value.to_vec()
		}
	}

	fn stored_value_owned(value: DBValue, meta: Self::Meta) -> DBValue {
		Self::stored_value(value.as_slice(), meta)
	}

	fn extract_value(mut stored: &[u8], _meta: Self::GlobalMeta) -> (&[u8], Self::Meta) {
		let len = stored.len();
		let input = &mut stored;
		// if len == 1 it is new empty trie.
		let (version, old_remaining_children) = if input[0] == EMPTY_TRIE && input.len() > 1 {
			*input = &input[1..];
			(Version::Old, Decode::decode(input).ok().flatten())
		} else {
			(Version::New, None)
		};
		let read_bytes = len - input.len();
		let stored = &stored[read_bytes..];
		(stored, VersionedValueMeta {
			old_remaining_children,
			range: None,
			version,
		})
	}

	fn extract_value_owned(mut stored: DBValue, _meta: Self::GlobalMeta) -> (DBValue, Self::Meta) {
		// TODO factor with extract_value
		let len = stored.len();
		let input = &mut stored.as_slice();
		// if len == 1 it is new empty trie.
		let (version, old_remaining_children) = if input[0] == EMPTY_TRIE && input.len() > 1 {
			*input = &input[1..];
			(Version::Old, Decode::decode(input).ok().flatten())
		} else {
			(Version::New, None)
		};
		let read_bytes = len - input.len();
		let stored = stored.split_off(read_bytes);
		(stored, VersionedValueMeta {
			old_remaining_children,
			range: None,
			version,
		})
	}
}

impl<H: Hasher> TrieConfiguration for GenericNoExtensionLayout<H> { }

/// Trie layout without extension nodes.
pub type NoExtensionLayout = GenericNoExtensionLayout<RefHasher>;

/// Children bitmap codec for radix 16 trie.
pub struct Bitmap(u16);

const BITMAP_LENGTH: usize = 2;

impl Bitmap {

	fn decode(data: &[u8]) -> Result<Self, CodecError> {
		Ok(u16::decode(&mut &data[..])
			.map(|v| Bitmap(v))?)
	}

	fn value_at(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}

	fn encode<I: Iterator<Item = bool>>(has_children: I , output: &mut [u8]) {
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

pub type RefTrieDB<'a> = trie_db::TrieDB<'a, ExtensionLayout>;
pub type RefTrieDBMut<'a> = trie_db::TrieDBMut<'a, ExtensionLayout>;
pub type RefTrieDBMutNoExt<'a> = trie_db::TrieDBMut<'a, NoExtensionLayout>;
pub type RefTrieDBMutAllowEmpty<'a> = trie_db::TrieDBMut<'a, AllowEmptyLayout>;
pub type RefFatDB<'a> = trie_db::FatDB<'a, ExtensionLayout>;
pub type RefFatDBMut<'a> = trie_db::FatDBMut<'a, ExtensionLayout>;
pub type RefSecTrieDB<'a> = trie_db::SecTrieDB<'a, ExtensionLayout>;
pub type RefSecTrieDBMut<'a> = trie_db::SecTrieDBMut<'a, ExtensionLayout>;
pub type RefLookup<'a, Q> = trie_db::Lookup<'a, ExtensionLayout, Q>;
pub type RefLookupNoExt<'a, Q> = trie_db::Lookup<'a, NoExtensionLayout, Q>;

pub fn reference_trie_root<T: TrieLayout, I, A, B>(input: I) -> <T::Hash as Hasher>::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	if T::USE_EXTENSION {
		trie_root::trie_root::<T::Hash, T::MetaHasher, ReferenceTrieStream, _, _, _>(input, Default::default())
	} else {
		trie_root::trie_root_no_extension::<T::Hash, T::MetaHasher, ReferenceTrieStreamNoExt, _, _, _>(input, Default::default())
	}
}

fn data_sorted_unique<I, A: Ord, B>(input: I) -> Vec<(A, B)>
	where
		I: IntoIterator<Item = (A, B)>,
{
	let mut m = std::collections::BTreeMap::new();
	for (k,v) in input {
		let _ = m.insert(k,v); // latest value for uniqueness
	}
	m.into_iter().collect()
}

pub fn reference_trie_root_iter_build<T, I, A, B>(input: I) -> <T::Hash as Hasher>::Out where
	T: TrieLayout,
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = trie_db::TrieRoot::<T>::default();
	trie_visit(data_sorted_unique(input), &mut cb, &T::default());
	cb.root.unwrap_or_default()
}

fn reference_trie_root_unhashed<I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::unhashed_trie::<RefHasher, hash_db::NoMeta, ReferenceTrieStream, _, _, _>(input, Default::default())
}

fn reference_trie_root_unhashed_no_extension<I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::unhashed_trie_no_extension::<RefHasher, TestMetaHasher, ReferenceTrieStreamNoExt, _, _, _>(input, Default::default())
}

const EMPTY_TRIE: u8 = 0;
const LEAF_NODE_OFFSET: u8 = 1;
const EXTENSION_NODE_OFFSET: u8 = 128;
const BRANCH_NODE_NO_VALUE: u8 = 254;
const BRANCH_NODE_WITH_VALUE: u8 = 255;
const LEAF_NODE_OVER: u8 = EXTENSION_NODE_OFFSET - LEAF_NODE_OFFSET;
const EXTENSION_NODE_OVER: u8 = BRANCH_NODE_NO_VALUE - EXTENSION_NODE_OFFSET;
const LEAF_NODE_LAST: u8 = EXTENSION_NODE_OFFSET - 1;
const EXTENSION_NODE_LAST: u8 = BRANCH_NODE_NO_VALUE - 1;

// Constant use with no extensino trie codec.
const NIBBLE_SIZE_BOUND_NO_EXT: usize = u16::max_value() as usize;
const FIRST_PREFIX: u8 = 0b_00 << 6;
const LEAF_PREFIX_MASK_NO_EXT: u8 = 0b_01 << 6;
const BRANCH_WITHOUT_MASK_NO_EXT: u8 = 0b_10 << 6;
const BRANCH_WITH_MASK_NO_EXT: u8 = 0b_11 << 6;
const EMPTY_TRIE_NO_EXT: u8 = FIRST_PREFIX | 0b_00;

/// Create a leaf/extension node, encoding a number of nibbles. Note that this
/// cannot handle a number of nibbles that is zero or greater than 125 and if
/// you attempt to do so *IT WILL PANIC*.
fn fuse_nibbles_node<'a>(nibbles: &'a [u8], leaf: bool) -> impl Iterator<Item = u8> + 'a {
	debug_assert!(
		nibbles.len() < LEAF_NODE_OVER.min(EXTENSION_NODE_OVER) as usize,
		"nibbles length too long. what kind of size of key are you trying to include in the trie!?!"
	);
	let first_byte = if leaf {
		LEAF_NODE_OFFSET
	} else {
		EXTENSION_NODE_OFFSET
	} + nibbles.len() as u8;

	once(first_byte)
		.chain(if nibbles.len() % 2 == 1 { Some(nibbles[0]) } else { None })
		.chain(nibbles[nibbles.len() % 2..].chunks(2).map(|ch| ch[0] << 4 | ch[1]))
}

enum NodeKindNoExt {
	Leaf,
	BranchNoValue,
	BranchWithValue,
}

/// Encoding of branch header and children bitmap (for trie stream radix 16).
/// For stream variant with extension.
fn branch_node(has_value: bool, has_children: impl Iterator<Item = bool>) -> [u8; 3] {
	let mut result = [0, 0, 0];
	branch_node_buffered(has_value, has_children, &mut result[..]);
	result
}

/// Encoding of branch header and children bitmap for any radix.
/// For codec/stream variant with extension.
fn branch_node_buffered<I: Iterator<Item = bool>>(
	has_value: bool,
	has_children: I,
	output: &mut[u8],
) {
	let first = if has_value {
		BRANCH_NODE_WITH_VALUE
	} else {
		BRANCH_NODE_NO_VALUE
	};
	output[0] = first;
	Bitmap::encode(has_children, &mut output[1..]);
}

/// Encoding of children bitmap (for trie stream radix 16).
/// For stream variant without extension.
fn branch_node_bit_mask(has_children: impl Iterator<Item = bool>) -> (u8, u8) {
	let mut bitmap: u16 = 0;
	let mut cursor: u16 = 1;
	for v in has_children {
		if v { bitmap |= cursor }
		cursor <<= 1;
	}
	((bitmap % 256 ) as u8, (bitmap / 256 ) as u8)
}

/// Reference implementation of a `TrieStream` with extension nodes.
#[derive(Default, Clone)]
pub struct ReferenceTrieStream {
	buffer: Vec<u8>
}

impl TrieStream for ReferenceTrieStream {
	type GlobalMeta = ();

	fn new(_meta: ()) -> Self {
		ReferenceTrieStream {
			buffer: Vec::new()
		}
	}

	fn append_empty_data(&mut self) {
		self.buffer.push(EMPTY_TRIE);
	}

	fn append_leaf(&mut self, key: &[u8], value: &[u8]) {
		self.buffer.extend(fuse_nibbles_node(key, true));
		value.encode_to(&mut self.buffer);
	}

	fn begin_branch(
		&mut self,
		maybe_key: Option<&[u8]>,
		maybe_value: Option<&[u8]>,
		has_children: impl Iterator<Item = bool>,
	) {
		self.buffer.extend(&branch_node(maybe_value.is_some(), has_children));
		if let Some(partial) = maybe_key {
			// should not happen
			self.buffer.extend(fuse_nibbles_node(partial, false));
		}
		if let Some(value) = maybe_value {
			value.encode_to(&mut self.buffer);
		}
	}

	fn append_extension(&mut self, key: &[u8]) {
		self.buffer.extend(fuse_nibbles_node(key, false));
	}

	fn append_substream<H: Hasher>(&mut self, other: Self) {
		let data = other.out();
		match data.len() {
			0..=31 => data.encode_to(&mut self.buffer),
			_ => H::hash(&data).as_ref().encode_to(&mut self.buffer),
		}
	}

	fn out(self) -> Vec<u8> { self.buffer }

	fn hash_root<H: Hasher>(self) -> H::Out {
		H::hash(&self.buffer)
	}
}

/// A node header.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum NodeHeader {
	Null,
	Branch(bool),
	Extension(usize),
	Leaf(usize),
}

/// A node header no extension.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum NodeHeaderNoExt {
	Null,
	Branch(bool, usize),
	Leaf(usize),
}

impl Encode for NodeHeader {
	fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
		match self {
			NodeHeader::Null => output.push_byte(EMPTY_TRIE),
			NodeHeader::Branch(true) => output.push_byte(BRANCH_NODE_WITH_VALUE),
			NodeHeader::Branch(false) => output.push_byte(BRANCH_NODE_NO_VALUE),
			NodeHeader::Leaf(nibble_count) =>
				output.push_byte(LEAF_NODE_OFFSET + *nibble_count as u8),
			NodeHeader::Extension(nibble_count) =>
				output.push_byte(EXTENSION_NODE_OFFSET + *nibble_count as u8),
		}
	}
}

/// Encode and allocate node type header (type and size), and partial value.
/// It uses an iterator over encoded partial bytes as input.
fn size_and_prefix_iterator(size: usize, prefix: u8) -> impl Iterator<Item = u8> {
	let size = ::std::cmp::min(NIBBLE_SIZE_BOUND_NO_EXT, size);

	let l1 = std::cmp::min(62, size);
	let (first_byte, mut rem) = if size == l1 {
		(once(prefix + l1 as u8), 0)
	} else {
		(once(prefix + 63), size - l1)
	};
	let next_bytes = move || {
		if rem > 0 {
			if rem < 256 {
				let result = rem - 1;
				rem = 0;
				Some(result as u8)
			} else {
				rem = rem.saturating_sub(255);
				Some(255)
			}
		} else {
			None
		}
	};
	first_byte.chain(::std::iter::from_fn(next_bytes))
}

fn encode_size_and_prefix(size: usize, prefix: u8, out: &mut (impl Output + ?Sized)) {
	for b in size_and_prefix_iterator(size, prefix) {
		out.push_byte(b)
	}
}

fn decode_size<I: Input>(first: u8, input: &mut I) -> Result<usize, CodecError> {
	let mut result = (first & 255u8 >> 2) as usize;
	if result < 63 {
		return Ok(result);
	}
	result -= 1;
	while result <= NIBBLE_SIZE_BOUND_NO_EXT {
		let n = input.read_byte()? as usize;
		if n < 255 {
			return Ok(result + n + 1);
		}
		result += 255;
	}
	Err("Size limit reached for a nibble slice".into())
}

impl Encode for NodeHeaderNoExt {
	fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
		match self {
			NodeHeaderNoExt::Null => output.push_byte(EMPTY_TRIE_NO_EXT),
			NodeHeaderNoExt::Branch(true, nibble_count)	=>
				encode_size_and_prefix(*nibble_count, BRANCH_WITH_MASK_NO_EXT, output),
			NodeHeaderNoExt::Branch(false, nibble_count) =>
				encode_size_and_prefix(*nibble_count, BRANCH_WITHOUT_MASK_NO_EXT, output),
			NodeHeaderNoExt::Leaf(nibble_count) =>
				encode_size_and_prefix(*nibble_count, LEAF_PREFIX_MASK_NO_EXT, output),
		}
	}
}

impl Decode for NodeHeader {
	fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
		Ok(match input.read_byte()? {
			EMPTY_TRIE => NodeHeader::Null,
			BRANCH_NODE_NO_VALUE => NodeHeader::Branch(false),
			BRANCH_NODE_WITH_VALUE => NodeHeader::Branch(true),
			i @ LEAF_NODE_OFFSET ..= LEAF_NODE_LAST =>
				NodeHeader::Leaf((i - LEAF_NODE_OFFSET) as usize),
			i @ EXTENSION_NODE_OFFSET ..= EXTENSION_NODE_LAST =>
				NodeHeader::Extension((i - EXTENSION_NODE_OFFSET) as usize),
		})
	}
}

impl Decode for NodeHeaderNoExt {
	fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
		let i = input.read_byte()?;
		if i == EMPTY_TRIE_NO_EXT {
			return Ok(NodeHeaderNoExt::Null);
		}
		match i & (0b11 << 6) {
			LEAF_PREFIX_MASK_NO_EXT =>
				Ok(NodeHeaderNoExt::Leaf(decode_size(i, input)?)),
			BRANCH_WITHOUT_MASK_NO_EXT =>
				Ok(NodeHeaderNoExt::Branch(false, decode_size(i, input)?)),
			BRANCH_WITH_MASK_NO_EXT =>
				Ok(NodeHeaderNoExt::Branch(true, decode_size(i, input)?)),
			// do not allow any special encoding
			_ => Err("Unknown type of node".into()),
		}
	}
}

/// Simple reference implementation of a `NodeCodec`.
#[derive(Default, Clone)]
pub struct ReferenceNodeCodec<H>(PhantomData<H>);

/// Simple reference implementation of a `NodeCodec`.
/// Even if implementation follows initial specification of
/// https://github.com/w3f/polkadot-re-spec/issues/8, this may
/// not follow it in the future, it is mainly the testing codec without extension node.
#[derive(Default, Clone)]
pub struct ReferenceNodeCodecNoExt<H>(PhantomData<H>);

fn partial_to_key(partial: Partial, offset: u8, over: u8) -> Vec<u8> {
	let number_nibble_encoded = (partial.0).0 as usize;
	let nibble_count = partial.1.len() * nibble_ops::NIBBLE_PER_BYTE + number_nibble_encoded;
	assert!(nibble_count < over as usize);
	let mut output = vec![offset + nibble_count as u8];
	if number_nibble_encoded > 0 {
		output.push(nibble_ops::pad_right((partial.0).1));
	}
	output.extend_from_slice(&partial.1[..]);
	output
}

fn partial_from_iterator_to_key<I: Iterator<Item = u8>>(
	partial: I,
	nibble_count: usize,
	offset: u8,
	over: u8,
) -> Vec<u8> {
	assert!(nibble_count < over as usize);
	let mut output = Vec::with_capacity(1 + (nibble_count / nibble_ops::NIBBLE_PER_BYTE));
	output.push(offset + nibble_count as u8);
	output.extend(partial);
	output
}

fn partial_from_iterator_encode<I: Iterator<Item = u8>>(
	partial: I,
	nibble_count: usize,
	node_kind: NodeKindNoExt,
) -> Vec<u8> {
	let nibble_count = ::std::cmp::min(NIBBLE_SIZE_BOUND_NO_EXT, nibble_count);

	let mut output = Vec::with_capacity(3 + (nibble_count / nibble_ops::NIBBLE_PER_BYTE));
	match node_kind {
		NodeKindNoExt::Leaf =>
			NodeHeaderNoExt::Leaf(nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchWithValue =>
			NodeHeaderNoExt::Branch(true, nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchNoValue =>
			NodeHeaderNoExt::Branch(false, nibble_count).encode_to(&mut output),
	};
	output.extend(partial);
	output
}

fn partial_encode(partial: Partial, node_kind: NodeKindNoExt) -> Vec<u8> {
	let number_nibble_encoded = (partial.0).0 as usize;
	let nibble_count = partial.1.len() * nibble_ops::NIBBLE_PER_BYTE + number_nibble_encoded;

	let nibble_count = ::std::cmp::min(NIBBLE_SIZE_BOUND_NO_EXT, nibble_count);

	let mut output = Vec::with_capacity(3 + partial.1.len());
	match node_kind {
		NodeKindNoExt::Leaf =>
			NodeHeaderNoExt::Leaf(nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchWithValue =>
			NodeHeaderNoExt::Branch(true, nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchNoValue =>
			NodeHeaderNoExt::Branch(false, nibble_count).encode_to(&mut output),
	};
	if number_nibble_encoded > 0 {
		output.push(nibble_ops::pad_right((partial.0).1));
	}
	output.extend_from_slice(&partial.1[..]);
	output
}

struct ByteSliceInput<'a> {
	data: &'a [u8],
	offset: usize,
}

impl<'a> ByteSliceInput<'a> {
	fn new(data: &'a [u8]) -> Self {
		ByteSliceInput {
			data,
			offset: 0,
		}
	}

	fn take(&mut self, count: usize) -> Result<Range<usize>, CodecError> {
		if self.offset + count > self.data.len() {
			return Err("out of data".into());
		}

		let range = self.offset..(self.offset + count);
		self.offset += count;
		Ok(range)
	}
}

impl<'a> Input for ByteSliceInput<'a> {
	fn remaining_len(&mut self) -> Result<Option<usize>, CodecError> {
		let remaining = if self.offset <= self.data.len() {
			Some(self.data.len() - self.offset)
		} else {
			None
		};
		Ok(remaining)
	}

	fn read(&mut self, into: &mut [u8]) -> Result<(), CodecError> {
		let range = self.take(into.len())?;
		into.copy_from_slice(&self.data[range]);
		Ok(())
	}

	fn read_byte(&mut self) -> Result<u8, CodecError> {
		if self.offset + 1 > self.data.len() {
			return Err("out of data".into());
		}

		let byte = self.data[self.offset];
		self.offset += 1;
		Ok(byte)
	}
}

// NOTE: what we'd really like here is:
// `impl<H: Hasher> NodeCodec<H> for RlpNodeCodec<H> where <KeccakHasher as Hasher>::Out: Decodable`
// but due to the current limitations of Rust const evaluation we can't do
// `const HASHED_NULL_NODE: <KeccakHasher as Hasher>::Out = <KeccakHasher as Hasher>::Out( … … )`.
// Perhaps one day soon?
impl<H: Hasher, M: Meta> NodeCodec<M> for ReferenceNodeCodec<H> {
	type Error = CodecError;
	type HashOut = H::Out;

	fn hashed_null_node() -> <H as Hasher>::Out {
		H::hash(<Self as NodeCodec<M>>::empty_node_no_meta())
	}

	fn decode_plan_inner(data: &[u8]) -> ::std::result::Result<NodePlan, Self::Error> {
		let mut input = ByteSliceInput::new(data);
		match NodeHeader::decode(&mut input)? {
			NodeHeader::Null => Ok(NodePlan::Empty),
			NodeHeader::Branch(has_value) => {
				let bitmap_range = input.take(BITMAP_LENGTH)?;
				let bitmap = Bitmap::decode(&data[bitmap_range])?;

				let value = if has_value {
					let start = input.offset;
					let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
					ValuePlan::Value(input.take(count)?, start)
				} else {
					ValuePlan::NoValue
				};
				let mut children = [
					None, None, None, None, None, None, None, None,
					None, None, None, None, None, None, None, None,
				];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if bitmap.value_at(i) {
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						let range = input.take(count)?;
						children[i] = Some(if count == H::LENGTH {
							NodeHandlePlan::Hash(range)
						} else {
							NodeHandlePlan::Inline(range)
						});
					}
				}
				Ok(NodePlan::Branch { value, children })
			}
			NodeHeader::Extension(nibble_count) => {
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
				let range = input.take(count)?;
				let child = if count == H::LENGTH {
					NodeHandlePlan::Hash(range)
				} else {
					NodeHandlePlan::Inline(range)
				};
				Ok(NodePlan::Extension {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					child
				})
			}
			NodeHeader::Leaf(nibble_count) => {
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let start = input.offset;
				let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
				let value = input.take(count)?;
				Ok(NodePlan::Leaf {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value: ValuePlan::Value(value, start),
				})
			}
		}
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodec<M>>::empty_node_no_meta()
	}

	fn empty_node(_meta: &mut M) -> Vec<u8> {
		vec![EMPTY_TRIE]
	}

	fn empty_node_no_meta() -> &'static[u8] {
		&[EMPTY_TRIE]
	}

	fn leaf_node(partial: Partial, value: Value, meta: &mut M) -> Vec<u8> {
		let mut output = partial_to_key(partial, LEAF_NODE_OFFSET, LEAF_NODE_OVER);
		match value {
			Value::Value(value) => {
				let start_len = output.len();
				Compact(value.len() as u32).encode_to(&mut output);
				let start = output.len();
				output.extend_from_slice(value);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::Value(start..end, start_len));
			},
			_ => unimplemented!("unsupported"),
		}
		output
	}

	fn extension_node(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		child: ChildReference<Self::HashOut>,
		_meta: &mut M,
	) -> Vec<u8> {
		let mut output = partial_from_iterator_to_key(
			partial,
			number_nibble,
			EXTENSION_NODE_OFFSET,
			EXTENSION_NODE_OVER,
		);
		match child {
			ChildReference::Hash(h) => h.as_ref().encode_to(&mut output),
			ChildReference::Inline(inline_data, len) =>
				(&AsRef::<[u8]>::as_ref(&inline_data)[..len]).encode_to(&mut output),
		};
		output
	}

	fn branch_node(
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		maybe_value: Value,
		meta: &mut M,
	) -> Vec<u8> {
		let mut output = vec![0; BITMAP_LENGTH + 1];
		let mut prefix: [u8; 3] = [0; 3];
		let have_value = match maybe_value {
			Value::Value(value) => {
				let start_len = output.len();
				Compact(value.len() as u32).encode_to(&mut output);
				let start = output.len();
				output.extend_from_slice(value);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::Value(start..end, start_len));
				true
			},
			Value::NoValue => {
				meta.encoded_value_callback(ValuePlan::NoValue);
				false
			},
			_ => unimplemented!("unsupported"),
		};
		let has_children = children.map(|maybe_child| match maybe_child.borrow() {
			Some(ChildReference::Hash(h)) => {
				h.as_ref().encode_to(&mut output);
				true
			}
			&Some(ChildReference::Inline(inline_data, len)) => {
				inline_data.as_ref()[..len].encode_to(&mut output);
				true
			}
			None => false,
		});
		branch_node_buffered(have_value, has_children, prefix.as_mut());
		output[0..BITMAP_LENGTH + 1].copy_from_slice(prefix.as_ref());
		output
	}

	fn branch_node_nibbled(
		_partial:	impl Iterator<Item = u8>,
		_number_nibble: usize,
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		_maybe_value: Value,
		_meta: &mut M,
	) -> Vec<u8> {
		unreachable!()
	}
}

impl<H: Hasher> ReferenceNodeCodecNoExt<H> {
	fn decode_plan_inner2<M: Meta>(
		data: &[u8],
		contains_hash: bool,
		meta: Option<&mut M>,
	) -> std::result::Result<NodePlan, CodecError> {
		if data.len() < 1 {
			return Err(CodecError::from("Empty encoded node."));
		}
		let offset = if let Some(meta) = meta {
			meta.decode_state_meta(data)?
		} else {
			0
		};
		let mut input = ByteSliceInput::new(data);
		let _ = input.take(offset)?;

		Ok(match NodeHeaderNoExt::decode(&mut input)? {
			NodeHeaderNoExt::Null => NodePlan::Empty,
			NodeHeaderNoExt::Branch(has_value, nibble_count) => {
				let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
				// check that the padding is valid (if any)
				if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
					return Err(CodecError::from("Bad format"));
				}
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let bitmap_range = input.take(BITMAP_LENGTH)?;
				let bitmap = Bitmap::decode(&data[bitmap_range])?;
				let value = if has_value {
					let start_len = input.offset;
					let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
					if contains_hash {
						ValuePlan::HashedValue(input.take(H::LENGTH)?, count)
					} else {
						ValuePlan::Value(input.take(count)?, start_len)
					}
				} else {
					ValuePlan::NoValue
				};
				let mut children = [
					None, None, None, None, None, None, None, None,
					None, None, None, None, None, None, None, None,
				];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if bitmap.value_at(i) {
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						let range = input.take(count)?;
						children[i] = Some(if count == H::LENGTH {
							NodeHandlePlan::Hash(range)
						} else {
							NodeHandlePlan::Inline(range)
						});
					}
				}
				NodePlan::NibbledBranch {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value,
					children,
				}
			}
			NodeHeaderNoExt::Leaf(nibble_count) => {
				let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
				// check that the padding is valid (if any)
				if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
					return Err(CodecError::from("Bad format"));
				}
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let start = input.offset;
				let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
				let value = if contains_hash {
					ValuePlan::HashedValue(input.take(H::LENGTH)?, count)
				} else {
					ValuePlan::Value(input.take(count)?, start)
				};

				NodePlan::Leaf {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value,
				}
			}
		})
	}
}


impl<H: Hasher, M: Meta> NodeCodec<M> for ReferenceNodeCodecNoExt<H> {
	type Error = CodecError;
	type HashOut = <H as Hasher>::Out;

	fn hashed_null_node() -> <H as Hasher>::Out {
		H::hash(<Self as NodeCodec<M>>::empty_node_no_meta())
	}

	fn decode_plan(data: &[u8], meta: &mut M) -> Result<NodePlan, Self::Error> {
		let contains_hash = meta.contains_hash_of_value();
		Self::decode_plan_inner2(data, contains_hash, Some(meta)).map(|plan| {
			meta.decoded_callback(&plan);
			plan
		})
	}

	fn decode_plan_inner(data: &[u8]) -> std::result::Result<NodePlan, Self::Error> {
		let meta: Option<&mut M> = None;
		Self::decode_plan_inner2(data, false, meta)
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodec<M>>::empty_node_no_meta()
	}

	fn empty_node(meta: &mut M) -> Vec<u8> {
		let mut output = meta.encode_state_meta();
		output.extend_from_slice(&[EMPTY_TRIE_NO_EXT]);
		output
	}

	fn empty_node_no_meta() -> &'static [u8] {
		&[EMPTY_TRIE_NO_EXT]
	}

	fn leaf_node(partial: Partial, value: Value, meta: &mut M) -> Vec<u8> {
		let mut output = meta.encode_state_meta();
		output.append(&mut partial_encode(partial, NodeKindNoExt::Leaf));
		match value {
			Value::Value(value) => {
				let start_len = output.len();
				Compact(value.len() as u32).encode_to(&mut output);
				let start = output.len();
				output.extend_from_slice(value);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::Value(start..end, start_len));
			},
			Value::HashedValue(hash, size) => {
				debug_assert!(hash.len() == H::LENGTH);
				Compact(size as u32).encode_to(&mut output);
				let start = output.len();
				output.extend_from_slice(hash);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::HashedValue(start..end, size));
			},
			Value::NoValue => unreachable!(),
		}
		output
	}

	fn extension_node(
		_partial: impl Iterator<Item = u8>,
		_nbnibble: usize,
		_child: ChildReference<<H as Hasher>::Out>,
		_met: &mut M,
	) -> Vec<u8> {
		unreachable!()
	}

	fn branch_node(
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
		_maybe_value: Value,
		_meta: &mut M,
	) -> Vec<u8> {
		unreachable!()
	}

	fn branch_node_nibbled(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		maybe_value: Value,
		meta: &mut M,
	) -> Vec<u8> {
		let mut output = meta.encode_state_meta();
		output.append(&mut if let Value::NoValue = &maybe_value {
			partial_from_iterator_encode(
				partial,
				number_nibble,
				NodeKindNoExt::BranchNoValue,
			)
		} else {
			partial_from_iterator_encode(
				partial,
				number_nibble,
				NodeKindNoExt::BranchWithValue,
			)
		});
		let bitmap_index = output.len();
		let mut bitmap: [u8; BITMAP_LENGTH] = [0; BITMAP_LENGTH];
		(0..BITMAP_LENGTH).for_each(|_| output.push(0));
		match maybe_value {
			Value::Value(value) => {
				let start_len = output.len();
				Compact(value.len() as u32).encode_to(&mut output);
				let start = output.len();
				output.extend_from_slice(value);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::Value(start..end, start_len));
			},
			Value::HashedValue(hash, size) => {
				debug_assert!(hash.len() == H::LENGTH);
				Compact(size as u32).encode_to(&mut output);
				let start = output.len();
				output.extend_from_slice(hash);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::HashedValue(start..end, size));
			},
			Value::NoValue => (),
		}

		Bitmap::encode(children.map(|maybe_child| match maybe_child.borrow() {
			Some(ChildReference::Hash(h)) => {
				h.as_ref().encode_to(&mut output);
				true
			}
			&Some(ChildReference::Inline(inline_data, len)) => {
				inline_data.as_ref()[..len].encode_to(&mut output);
				true
			}
			None => false,
		}), bitmap.as_mut());
		output[bitmap_index..bitmap_index + BITMAP_LENGTH]
			.copy_from_slice(&bitmap.as_ref()[..BITMAP_LENGTH]);
		output
	}
}

/// Compare trie builder and in memory trie.
pub fn compare_implementations<T, DB> (
	data: Vec<(Vec<u8>, Vec<u8>)>,
	mut memdb: DB,
	mut hashdb: DB,
)
	where
		T: TrieLayout,
		DB : hash_db::HashDB<T::Hash, DBValue, T::Meta, GlobalMeta<T>> + Eq,
{
	let root_new = calc_root_build::<T, _, _, _, _>(data.clone(), &mut hashdb);
	let root = {
		let mut root = Default::default();
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
		}
		t.commit();
		*t.root()
	};
	if root_new != root {
		{
			let db : &dyn hash_db::HashDB<_, _, _, _> = &hashdb;
			let t = TrieDB::<T>::new(&db, &root_new).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:x?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_, _, _, _> = &memdb;
			let t = TrieDB::<T>::new(&db, &root).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:x?}", a);
			}
		}
	}

	assert_eq!(root, root_new);
	// compare db content for key fuzzing
	assert!(memdb == hashdb);
}

/// Compare trie builder and trie root implementations.
pub fn compare_root<T: TrieLayout, DB: hash_db::HashDB<T::Hash, DBValue, T::Meta, GlobalMeta<T>>>(
	data: Vec<(Vec<u8>, Vec<u8>)>,
	mut memdb: DB,
) {
	let root_new = reference_trie_root_iter_build::<T, _, _, _>(data.clone());
	let root = {
		let mut root = Default::default();
		let mut t = trie_db::TrieDBMut::<T>::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
		}
		*t.root()
	};

	assert_eq!(root, root_new);
}

/// Compare trie builder and trie root unhashed implementations.
pub fn compare_unhashed(
	data: Vec<(Vec<u8>, Vec<u8>)>,
) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashed::<ExtensionLayout>::default();
		trie_visit(data.clone().into_iter(), &mut cb, &ExtensionLayout);
		cb.root.unwrap_or(Default::default())
	};
	let root = reference_trie_root_unhashed(data);

	assert_eq!(root, root_new);
}

/// Compare trie builder and trie root unhashed implementations.
/// This uses the variant without extension nodes.
pub fn compare_unhashed_no_extension(
	data: Vec<(Vec<u8>, Vec<u8>)>,
) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashed::<NoExtensionLayout>::default();
		trie_visit(data.clone().into_iter(), &mut cb, &NoExtensionLayout::default());
		cb.root.unwrap_or(Default::default())
	};
	let root = reference_trie_root_unhashed_no_extension(data);

	assert_eq!(root, root_new);
}

/// Trie builder root calculation utility.
pub fn calc_root<T, I, A, B>(
	data: I,
) -> <T::Hash as Hasher>::Out
	where
		T: TrieLayout,
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord + fmt::Debug,
		B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = TrieRoot::<T>::default();
	trie_visit(data.into_iter(), &mut cb, &T::default());
	cb.root.unwrap_or_default()
}

/// Trie builder trie building utility.
pub fn calc_root_build<T, I, A, B, DB>(
	data: I,
	hashdb: &mut DB
) -> <T::Hash as Hasher>::Out
	where
		T: TrieLayout,
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord + fmt::Debug,
		B: AsRef<[u8]> + fmt::Debug,
		DB: hash_db::HashDB<T::Hash, DBValue, T::Meta, GlobalMeta<T>>,
{
	let mut cb = TrieBuilder::<T, DB>::new(hashdb);
	trie_visit(data.into_iter(), &mut cb, &T::default());
	cb.root.unwrap_or_default()
}

/// `compare_implementations_no_extension` for unordered input (trie_root does
/// ordering before running when trie_build expect correct ordering).
pub fn compare_implementations_unordered<T, DB> (
	data: Vec<(Vec<u8>, Vec<u8>)>,
	mut memdb: DB,
	mut hashdb: DB,
)
	where
		T: TrieLayout,
		DB : hash_db::HashDB<T::Hash, DBValue, T::Meta, GlobalMeta<T>> + Eq,
{
	let mut b_map = std::collections::btree_map::BTreeMap::new();
	let root = {
		let mut root = Default::default();
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
			b_map.insert(data[i].0.clone(), data[i].1.clone());
		}
		*t.root()
	};
	let root_new = {
		let mut cb = TrieBuilder::<T, DB>::new(&mut hashdb);
		trie_visit(b_map.into_iter(), &mut cb, &T::default());
		cb.root.unwrap_or_default()
	};

	if root != root_new {
		{
			let db : &dyn hash_db::HashDB<_, _, _, _> = &memdb;
			let t = TrieDB::<T>::new(&db, &root).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_, _, _, _> = &hashdb;
			let t = TrieDB::<T>::new(&db, &root_new).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
	}

	assert_eq!(root, root_new);
}

/// Testing utility that uses some periodic removal over
/// its input test data.
pub fn compare_insert_remove<T, DB: hash_db::HashDB<T::Hash, DBValue, T::Meta, GlobalMeta<T>>>(
	data: Vec<(bool, Vec<u8>, Vec<u8>)>,
	mut memdb: DB,
)
	where
		T: TrieLayout,
		DB : hash_db::HashDB<T::Hash, DBValue, T::Meta, GlobalMeta<T>> + Eq,
{

	let mut data2 = std::collections::BTreeMap::new();
	let mut root = Default::default();
	let mut a = 0;
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		t.commit();
	}
	while a < data.len() {
		// new triemut every 3 element
		root = {
			let mut t = TrieDBMut::<T>::from_existing(&mut memdb, &mut root).unwrap();
			for _ in 0..3 {
				if data[a].0 {
					// remove
					t.remove(&data[a].1[..]).unwrap();
					data2.remove(&data[a].1[..]);
				} else {
					// add
					t.insert(&data[a].1[..], &data[a].2[..]).unwrap();
					data2.insert(&data[a].1[..], &data[a].2[..]);
				}

				a += 1;
				if a == data.len() {
					break;
				}
			}
			t.commit();
			*t.root()
		};
	}
	let mut t = TrieDBMut::<T>::from_existing(&mut memdb, &mut root).unwrap();
	// we are testing the RefTrie code here so we do not sort or check uniqueness
	// before.
	assert_eq!(*t.root(), calc_root::<T, _, _, _>(data2));
}

#[cfg(test)]
mod tests {
	use super::*;
	use trie_db::node::Node;

	#[test]
	fn test_encoding_simple_trie() {
		for prefix in [
			LEAF_PREFIX_MASK_NO_EXT,
			BRANCH_WITHOUT_MASK_NO_EXT,
			BRANCH_WITH_MASK_NO_EXT,
		].iter() {
			for i in (0..1000).chain(NIBBLE_SIZE_BOUND_NO_EXT - 2..NIBBLE_SIZE_BOUND_NO_EXT + 2) {
				let mut output = Vec::new();
				encode_size_and_prefix(i, *prefix, &mut output);
				let input = &mut &output[..];
				let first = input.read_byte().unwrap();
				assert_eq!(first & (0b11 << 6), *prefix);
				let v = decode_size(first, input);
				assert_eq!(Ok(std::cmp::min(i, NIBBLE_SIZE_BOUND_NO_EXT)), v);
			}
		}
	}

	#[test]
	fn too_big_nibble_length() {
		// + 1 for 0 added byte of nibble encode
		let input = vec![0u8; (NIBBLE_SIZE_BOUND_NO_EXT as usize + 1) / 2 + 1];
		let enc = <ReferenceNodeCodecNoExt<RefHasher> as NodeCodec<_>>
		::leaf_node(((0, 0), &input), Value::Value(&[1]), &mut ());
		let dec = <ReferenceNodeCodecNoExt<RefHasher> as NodeCodec<_>>
		::decode(&enc, &mut ()).unwrap();
		let o_sl = if let Node::Leaf(sl, _) = dec {
			Some(sl)
		} else { None };
		assert!(o_sl.is_some());
	}

	#[test]
	fn size_encode_limit_values() {
		let sizes = [0, 1, 62, 63, 64, 317, 318, 319, 572, 573, 574];
		let encs = [
			vec![0],
			vec![1],
			vec![0x3e],
			vec![0x3f, 0],
			vec![0x3f, 1],
			vec![0x3f, 0xfe],
			vec![0x3f, 0xff, 0],
			vec![0x3f, 0xff, 1],
			vec![0x3f, 0xff, 0xfe],
			vec![0x3f, 0xff, 0xff, 0],
			vec![0x3f, 0xff, 0xff, 1],
		];
		for i in 0..sizes.len() {
			let mut enc = Vec::new();
			encode_size_and_prefix(sizes[i], 0, &mut enc);
			assert_eq!(enc, encs[i]);
			let s_dec = decode_size(encs[i][0], &mut &encs[i][1..]);
			assert_eq!(s_dec, Ok(sizes[i]));
		}
	}
}

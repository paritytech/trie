// Copyright 2017, 2021 Parity Technologies
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

use hashbrown::{hash_map::Entry, HashMap};
use parity_scale_codec::{Compact, Decode, Encode, Error as CodecError, Input, Output};
use std::{borrow::Borrow, fmt, iter::once, marker::PhantomData, ops::Range};
use trie_db::{
	memory_db::{KeyFunction, MemoryDB, PrefixedKey},
	nibble_ops,
	node::{NibbleSlicePlan, NodeHandlePlan, NodeOwned, NodePlan, Value, ValuePlan},
	node_db,
	node_db::Hasher,
	trie_root::{self, TrieStream, Value as TrieStreamValue},
	trie_visit,
	triedbmut::ChildReference,
	DBValue, Location, NodeCodec, Trie, TrieBuilder, TrieConfiguration, TrieDBBuilder,
	TrieDBMutBuilder, TrieHash, TrieLayout, TrieRoot,
};

mod substrate;
mod substrate_like;
pub mod node {
	pub use trie_db::node::Node;
}

pub use substrate_like::{
	trie_constants, HashedValueNoExt, HashedValueNoExtThreshold,
	NodeCodec as ReferenceNodeCodecNoExtMeta, ReferenceTrieStreamNoExt,
};

pub use paste::paste;
pub use substrate::{LayoutV0 as SubstrateV0, LayoutV1 as SubstrateV1};
pub use trie_db::mem_tree_db::{Location as MemLocation, MemTreeDB};

/// Reference hasher is a keccak hasher.
pub type RefHasher = trie_db::keccak_hasher::KeccakHasher;

pub type PrefixedMemoryDB<T> =
	MemoryDB<<T as TrieLayout>::Hash, PrefixedKey<<T as TrieLayout>::Hash>, DBValue>;

/// Apply a test method on every test layouts.
#[macro_export]
macro_rules! test_layouts {
	($test:ident, $test_internal:ident) => {
		#[test]
		fn $test() {
			eprintln!("Running with layout `HashedValueNoExtThreshold` and MemTreeDB");
			$test_internal::<
				$crate::HashedValueNoExtThreshold<1, $crate::MemLocation>,
				$crate::MemTreeDB<$crate::RefHasher>,
			>();
			eprintln!("Running with layout `HashedValueNoExt` and MemTreeDB");
			$test_internal::<$crate::HashedValueNoExt, $crate::MemTreeDB<$crate::RefHasher>>();
			eprintln!("Running with layout `NoExtensionLayout` and MemTreeDB");
			$test_internal::<
				$crate::GenericNoExtensionLayout<$crate::RefHasher, $crate::MemLocation>,
				$crate::MemTreeDB<$crate::RefHasher>,
			>();

			eprintln!("Running with layout `HashedValueNoExtThreshold` and MemoryDB");
			$test_internal::<
				$crate::HashedValueNoExtThreshold<1, ()>,
				$crate::PrefixedMemoryDB<$crate::HashedValueNoExtThreshold<1, ()>>,
			>();
			eprintln!("Running with layout `HashedValueNoExt` and MemoryDB");
			$test_internal::<
				$crate::HashedValueNoExt,
				$crate::PrefixedMemoryDB<$crate::HashedValueNoExt>,
			>();
			eprintln!("Running with layout `NoExtensionLayout` and MemoryDB");
			$test_internal::<
				$crate::NoExtensionLayout,
				$crate::PrefixedMemoryDB<$crate::NoExtensionLayout>,
			>();
			eprintln!("Running with layout `ExtensionLayout` and MemoryDB");
			$test_internal::<
				$crate::ExtensionLayout,
				$crate::PrefixedMemoryDB<$crate::ExtensionLayout>,
			>();
		}
	};
}

#[macro_export]
macro_rules! test_layouts_substrate {
	($test:ident) => {
		$crate::paste! {
			#[test]
			fn [<$test _substrate_v0>]() {
				$test::<$crate::SubstrateV0<$crate::RefHasher>>();
			}
			#[test]
			fn [<$test _substrate_v1>]() {
				$test::<$crate::SubstrateV1<$crate::RefHasher>>();
			}
		}
	};
}

/// Apply a test method on every test layouts.
#[macro_export]
macro_rules! test_layouts_no_meta {
	($test:ident, $test_internal:ident) => {
		#[test]
		fn $test() {
			$test_internal::<$crate::NoExtensionLayout>();
			$test_internal::<$crate::ExtensionLayout>();
		}
	};
}

/// Trie layout using extension nodes.
#[derive(Default, Clone)]
pub struct ExtensionLayout;

impl TrieLayout for ExtensionLayout {
	const USE_EXTENSION: bool = true;
	const ALLOW_EMPTY: bool = false;
	const MAX_INLINE_VALUE: Option<u32> = None;
	type Hash = RefHasher;
	type Codec = ReferenceNodeCodec<RefHasher>;
	type Location = ();
}

impl TrieConfiguration for ExtensionLayout {}

/// Trie layout without extension nodes, allowing
/// generic hasher.
pub struct GenericNoExtensionLayout<H, L>(PhantomData<(H, L)>);

impl<H, L> Default for GenericNoExtensionLayout<H, L> {
	fn default() -> Self {
		GenericNoExtensionLayout(PhantomData)
	}
}

impl<H, L> Clone for GenericNoExtensionLayout<H, L> {
	fn clone(&self) -> Self {
		GenericNoExtensionLayout(PhantomData)
	}
}

impl<H: Hasher, L: Location> TrieLayout for GenericNoExtensionLayout<H, L> {
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = false;
	const MAX_INLINE_VALUE: Option<u32> = None;
	type Hash = H;
	type Codec = ReferenceNodeCodecNoExt<H>;
	type Location = L;
}

/// Trie that allows empty values.
#[derive(Default, Clone)]
pub struct AllowEmptyLayout;

impl TrieLayout for AllowEmptyLayout {
	const USE_EXTENSION: bool = true;
	const ALLOW_EMPTY: bool = true;
	const MAX_INLINE_VALUE: Option<u32> = None;
	type Hash = RefHasher;
	type Codec = ReferenceNodeCodec<RefHasher>;
	type Location = ();
}

impl<H: Hasher, L: Location> TrieConfiguration for GenericNoExtensionLayout<H, L> {}

/// Trie layout without extension nodes.
pub type NoExtensionLayout = GenericNoExtensionLayout<RefHasher, ()>;

/// Children bitmap codec for radix 16 trie.
pub struct Bitmap(u16);

const BITMAP_LENGTH: usize = 2;

impl Bitmap {
	fn decode(data: &[u8]) -> Result<Self, CodecError> {
		Ok(u16::decode(&mut &data[..]).map(|v| Bitmap(v))?)
	}

	fn value_at(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}

	fn encode<I: Iterator<Item = bool>>(has_children: I, output: &mut [u8]) {
		let mut bitmap: u16 = 0;
		let mut cursor: u16 = 1;
		for v in has_children {
			if v {
				bitmap |= cursor
			}
			cursor <<= 1;
		}
		output[0] = (bitmap % 256) as u8;
		output[1] = (bitmap / 256) as u8;
	}
}

pub type RefTrieDB<'a, 'cache> = trie_db::TrieDB<'a, 'cache, ExtensionLayout>;
pub type RefTrieDBBuilder<'a, 'cache> = trie_db::TrieDBBuilder<'a, 'cache, ExtensionLayout>;
pub type RefTrieDBMut<'a> = trie_db::TrieDBMut<'a, ExtensionLayout>;
pub type RefTrieDBMutBuilder<'a> = trie_db::TrieDBMutBuilder<'a, ExtensionLayout>;
pub type RefTrieDBMutNoExt<'a> = trie_db::TrieDBMut<'a, NoExtensionLayout>;
pub type RefTrieDBMutNoExtBuilder<'a> = trie_db::TrieDBMutBuilder<'a, NoExtensionLayout>;
pub type RefTrieDBMutAllowEmpty<'a> = trie_db::TrieDBMut<'a, AllowEmptyLayout>;
pub type RefTrieDBMutAllowEmptyBuilder<'a> = trie_db::TrieDBMutBuilder<'a, AllowEmptyLayout>;
pub type RefTestTrieDBCache = TestTrieCache<ExtensionLayout>;
pub type RefTestTrieDBCacheNoExt = TestTrieCache<NoExtensionLayout>;
pub type RefLookup<'a, 'cache, Q> = trie_db::Lookup<'a, 'cache, ExtensionLayout, Q>;
pub type RefLookupNoExt<'a, 'cache, Q> = trie_db::Lookup<'a, 'cache, NoExtensionLayout, Q>;

pub fn reference_trie_root<T: TrieLayout, I, A, B>(input: I) -> <T::Hash as Hasher>::Out
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	if T::USE_EXTENSION {
		trie_root::trie_root::<T::Hash, ReferenceTrieStream, _, _, _>(input, T::MAX_INLINE_VALUE)
	} else {
		trie_root::trie_root_no_extension::<T::Hash, ReferenceTrieStreamNoExt, _, _, _>(
			input,
			T::MAX_INLINE_VALUE,
		)
	}
}

fn data_sorted_unique<I, A: Ord, B>(input: I) -> Vec<(A, B)>
where
	I: IntoIterator<Item = (A, B)>,
{
	let mut m = std::collections::BTreeMap::new();
	for (k, v) in input {
		let _ = m.insert(k, v); // latest value for uniqueness
	}
	m.into_iter().collect()
}

pub fn reference_trie_root_iter_build<T, I, A, B>(input: I) -> <T::Hash as Hasher>::Out
where
	T: TrieLayout,
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = trie_db::TrieRoot::<T>::default();
	trie_visit::<T, _, _, _, _>(data_sorted_unique(input), &mut cb);
	cb.root.unwrap_or_default()
}

fn reference_trie_root_unhashed<I, A, B>(input: I) -> Vec<u8>
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::unhashed_trie::<RefHasher, ReferenceTrieStream, _, _, _>(input, Default::default())
}

fn reference_trie_root_unhashed_no_extension<I, A, B>(input: I) -> Vec<u8>
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::unhashed_trie_no_extension::<RefHasher, ReferenceTrieStreamNoExt, _, _, _>(
		input,
		Default::default(),
	)
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
	let first_byte =
		if leaf { LEAF_NODE_OFFSET } else { EXTENSION_NODE_OFFSET } + nibbles.len() as u8;

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
	output: &mut [u8],
) {
	let first = if has_value { BRANCH_NODE_WITH_VALUE } else { BRANCH_NODE_NO_VALUE };
	output[0] = first;
	Bitmap::encode(has_children, &mut output[1..]);
}

/// Encoding of children bitmap (for trie stream radix 16).
/// For stream variant without extension.
fn branch_node_bit_mask(has_children: impl Iterator<Item = bool>) -> (u8, u8) {
	let mut bitmap: u16 = 0;
	let mut cursor: u16 = 1;
	for v in has_children {
		if v {
			bitmap |= cursor
		}
		cursor <<= 1;
	}
	((bitmap % 256) as u8, (bitmap / 256) as u8)
}

/// Reference implementation of a `TrieStream` with extension nodes.
#[derive(Default, Clone)]
pub struct ReferenceTrieStream {
	buffer: Vec<u8>,
}

impl TrieStream for ReferenceTrieStream {
	fn new() -> Self {
		ReferenceTrieStream { buffer: Vec::new() }
	}

	fn append_empty_data(&mut self) {
		self.buffer.push(EMPTY_TRIE);
	}

	fn append_leaf(&mut self, key: &[u8], value: TrieStreamValue) {
		if let TrieStreamValue::Inline(value) = value {
			self.buffer.extend(fuse_nibbles_node(key, true));
			value.encode_to(&mut self.buffer);
		} else {
			unreachable!("This stream do not allow external value node")
		}
	}

	fn begin_branch(
		&mut self,
		maybe_key: Option<&[u8]>,
		maybe_value: Option<TrieStreamValue>,
		has_children: impl Iterator<Item = bool>,
	) {
		self.buffer.extend(&branch_node(!matches!(maybe_value, None), has_children));
		if let Some(partial) = maybe_key {
			// should not happen
			self.buffer.extend(fuse_nibbles_node(partial, false));
		}
		if let Some(TrieStreamValue::Inline(value)) = maybe_value {
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

	fn out(self) -> Vec<u8> {
		self.buffer
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
	let (first_byte, mut rem) =
		if size == l1 { (once(prefix + l1 as u8), 0) } else { (once(prefix + 63), size - l1) };
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
		return Ok(result)
	}
	result -= 1;
	while result <= NIBBLE_SIZE_BOUND_NO_EXT {
		let n = input.read_byte()? as usize;
		if n < 255 {
			return Ok(result + n + 1)
		}
		result += 255;
	}
	Err("Size limit reached for a nibble slice".into())
}

impl Encode for NodeHeaderNoExt {
	fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
		match self {
			NodeHeaderNoExt::Null => output.push_byte(EMPTY_TRIE_NO_EXT),
			NodeHeaderNoExt::Branch(true, nibble_count) =>
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
			i @ LEAF_NODE_OFFSET..=LEAF_NODE_LAST =>
				NodeHeader::Leaf((i - LEAF_NODE_OFFSET) as usize),
			i @ EXTENSION_NODE_OFFSET..=EXTENSION_NODE_LAST =>
				NodeHeader::Extension((i - EXTENSION_NODE_OFFSET) as usize),
		})
	}
}

impl Decode for NodeHeaderNoExt {
	fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
		let i = input.read_byte()?;
		if i == EMPTY_TRIE_NO_EXT {
			return Ok(NodeHeaderNoExt::Null)
		}
		match i & (0b11 << 6) {
			LEAF_PREFIX_MASK_NO_EXT => Ok(NodeHeaderNoExt::Leaf(decode_size(i, input)?)),
			BRANCH_WITHOUT_MASK_NO_EXT =>
				Ok(NodeHeaderNoExt::Branch(false, decode_size(i, input)?)),
			BRANCH_WITH_MASK_NO_EXT => Ok(NodeHeaderNoExt::Branch(true, decode_size(i, input)?)),
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
		NodeKindNoExt::Leaf => NodeHeaderNoExt::Leaf(nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchWithValue =>
			NodeHeaderNoExt::Branch(true, nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchNoValue =>
			NodeHeaderNoExt::Branch(false, nibble_count).encode_to(&mut output),
	};
	output.extend(partial);
	output
}

struct ByteSliceInput<'a> {
	data: &'a [u8],
	offset: usize,
}

impl<'a> ByteSliceInput<'a> {
	fn new(data: &'a [u8]) -> Self {
		ByteSliceInput { data, offset: 0 }
	}

	fn take(&mut self, count: usize) -> Result<Range<usize>, CodecError> {
		if self.offset + count > self.data.len() {
			return Err("out of data".into())
		}

		let range = self.offset..(self.offset + count);
		self.offset += count;
		Ok(range)
	}
}

impl<'a> Input for ByteSliceInput<'a> {
	fn remaining_len(&mut self) -> Result<Option<usize>, CodecError> {
		let remaining =
			if self.offset <= self.data.len() { Some(self.data.len() - self.offset) } else { None };
		Ok(remaining)
	}

	fn read(&mut self, into: &mut [u8]) -> Result<(), CodecError> {
		let range = self.take(into.len())?;
		into.copy_from_slice(&self.data[range]);
		Ok(())
	}

	fn read_byte(&mut self) -> Result<u8, CodecError> {
		if self.offset + 1 > self.data.len() {
			return Err("out of data".into())
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
impl<H: Hasher> NodeCodec for ReferenceNodeCodec<H> {
	type Error = CodecError;
	type HashOut = H::Out;

	fn hashed_null_node() -> <H as Hasher>::Out {
		H::hash(<Self as NodeCodec>::empty_node())
	}

	fn decode_plan(data: &[u8]) -> ::std::result::Result<NodePlan, Self::Error> {
		let mut input = ByteSliceInput::new(data);
		match NodeHeader::decode(&mut input)? {
			NodeHeader::Null => Ok(NodePlan::Empty),
			NodeHeader::Branch(has_value) => {
				let bitmap_range = input.take(BITMAP_LENGTH)?;
				let bitmap = Bitmap::decode(&data[bitmap_range])?;

				let value = if has_value {
					let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
					Some(ValuePlan::Inline(input.take(count)?))
				} else {
					None
				};
				let mut children = [
					None, None, None, None, None, None, None, None, None, None, None, None, None,
					None, None, None,
				];
				let mut i_hash = 0;
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if bitmap.value_at(i) {
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						let range = input.take(count)?;
						children[i] = Some(if count == H::LENGTH {
							i_hash += 1;
							NodeHandlePlan::Hash(range, i_hash - 1)
						} else {
							NodeHandlePlan::Inline(range)
						});
					}
				}
				Ok(NodePlan::Branch { value, children })
			},
			NodeHeader::Extension(nibble_count) => {
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) /
						nibble_ops::NIBBLE_PER_BYTE,
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
				let range = input.take(count)?;
				let child = if count == H::LENGTH {
					NodeHandlePlan::Hash(range, 0)
				} else {
					NodeHandlePlan::Inline(range)
				};
				Ok(NodePlan::Extension {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					child,
				})
			},
			NodeHeader::Leaf(nibble_count) => {
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) /
						nibble_ops::NIBBLE_PER_BYTE,
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
				let value = input.take(count)?;
				Ok(NodePlan::Leaf {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value: ValuePlan::Inline(value),
				})
			},
		}
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodec>::empty_node()
	}

	fn empty_node() -> &'static [u8] {
		&[EMPTY_TRIE]
	}

	fn leaf_node<L>(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		value: Value<L>,
	) -> Vec<u8> {
		let mut output =
			partial_from_iterator_to_key(partial, number_nibble, LEAF_NODE_OFFSET, LEAF_NODE_OVER);
		match value {
			Value::Inline(value) => {
				Compact(value.len() as u32).encode_to(&mut output);
				output.extend_from_slice(value);
			},
			_ => unimplemented!("unsupported"),
		}
		output
	}

	fn extension_node<L>(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		child: ChildReference<Self::HashOut, L>,
	) -> Vec<u8> {
		let mut output = partial_from_iterator_to_key(
			partial,
			number_nibble,
			EXTENSION_NODE_OFFSET,
			EXTENSION_NODE_OVER,
		);
		match child {
			ChildReference::Hash(h, _) => h.as_ref().encode_to(&mut output),
			ChildReference::Inline(inline_data, len) =>
				(&AsRef::<[u8]>::as_ref(&inline_data)[..len]).encode_to(&mut output),
		};
		output
	}

	fn branch_node<L>(
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut, L>>>>,
		maybe_value: Option<Value<L>>,
	) -> Vec<u8> {
		let mut output = vec![0; BITMAP_LENGTH + 1];
		let mut prefix: [u8; 3] = [0; 3];
		let have_value = match maybe_value {
			Some(Value::Inline(value)) => {
				Compact(value.len() as u32).encode_to(&mut output);
				output.extend_from_slice(value);
				true
			},
			None => false,
			_ => unimplemented!("unsupported"),
		};
		let has_children = children.map(|maybe_child| match maybe_child.borrow() {
			Some(ChildReference::Hash(h, _)) => {
				h.as_ref().encode_to(&mut output);
				true
			},
			&Some(ChildReference::Inline(inline_data, len)) => {
				inline_data.as_ref()[..len].encode_to(&mut output);
				true
			},
			None => false,
		});
		branch_node_buffered(have_value, has_children, prefix.as_mut());
		output[0..BITMAP_LENGTH + 1].copy_from_slice(prefix.as_ref());
		output
	}

	fn branch_node_nibbled<L>(
		_partial: impl Iterator<Item = u8>,
		_number_nibble: usize,
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut, L>>>>,
		_maybe_value: Option<Value<L>>,
	) -> Vec<u8> {
		unreachable!("codec with extension branch")
	}
}

impl<H: Hasher> NodeCodec for ReferenceNodeCodecNoExt<H> {
	type Error = CodecError;
	type HashOut = <H as Hasher>::Out;

	fn hashed_null_node() -> <H as Hasher>::Out {
		H::hash(<Self as NodeCodec>::empty_node())
	}

	fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
		if data.len() < 1 {
			return Err(CodecError::from("Empty encoded node."))
		}
		let mut input = ByteSliceInput::new(data);

		Ok(match NodeHeaderNoExt::decode(&mut input)? {
			NodeHeaderNoExt::Null => NodePlan::Empty,
			NodeHeaderNoExt::Branch(has_value, nibble_count) => {
				let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
				// check that the padding is valid (if any)
				if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
					return Err(CodecError::from("Bad format"))
				}
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) /
						nibble_ops::NIBBLE_PER_BYTE,
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let bitmap_range = input.take(BITMAP_LENGTH)?;
				let bitmap = Bitmap::decode(&data[bitmap_range])?;
				let value = if has_value {
					let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
					Some(ValuePlan::Inline(input.take(count)?))
				} else {
					None
				};
				let mut children = [
					None, None, None, None, None, None, None, None, None, None, None, None, None,
					None, None, None,
				];
				let mut i_hash = 0;
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if bitmap.value_at(i) {
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						let range = input.take(count)?;
						children[i] = Some(if count == H::LENGTH {
							i_hash += 1;
							NodeHandlePlan::Hash(range, i_hash - 1)
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
			},
			NodeHeaderNoExt::Leaf(nibble_count) => {
				let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
				// check that the padding is valid (if any)
				if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
					return Err(CodecError::from("Bad format"))
				}
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) /
						nibble_ops::NIBBLE_PER_BYTE,
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
				let value = ValuePlan::Inline(input.take(count)?);

				NodePlan::Leaf { partial: NibbleSlicePlan::new(partial, partial_padding), value }
			},
		})
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodec>::empty_node()
	}

	fn empty_node() -> &'static [u8] {
		&[EMPTY_TRIE_NO_EXT]
	}

	fn leaf_node<L>(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		value: Value<L>,
	) -> Vec<u8> {
		let mut output = partial_from_iterator_encode(partial, number_nibble, NodeKindNoExt::Leaf);
		match value {
			Value::Inline(value) => {
				Compact(value.len() as u32).encode_to(&mut output);
				output.extend_from_slice(value);
			},
			Value::Node(..) => unimplemented!("No support for inner hashed value"),
		}
		output
	}

	fn extension_node<L>(
		_partial: impl Iterator<Item = u8>,
		_nbnibble: usize,
		_child: ChildReference<<H as Hasher>::Out, L>,
	) -> Vec<u8> {
		unreachable!("no extension codec")
	}

	fn branch_node<L>(
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out, L>>>>,
		_maybe_value: Option<Value<L>>,
	) -> Vec<u8> {
		unreachable!("no extension codec")
	}

	fn branch_node_nibbled<L>(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut, L>>>>,
		maybe_value: Option<Value<L>>,
	) -> Vec<u8> {
		let mut output = if maybe_value.is_none() {
			partial_from_iterator_encode(partial, number_nibble, NodeKindNoExt::BranchNoValue)
		} else {
			partial_from_iterator_encode(partial, number_nibble, NodeKindNoExt::BranchWithValue)
		};
		let bitmap_index = output.len();
		let mut bitmap: [u8; BITMAP_LENGTH] = [0; BITMAP_LENGTH];
		(0..BITMAP_LENGTH).for_each(|_| output.push(0));
		match maybe_value {
			Some(Value::Inline(value)) => {
				Compact(value.len() as u32).encode_to(&mut output);
				output.extend_from_slice(value);
			},
			Some(Value::Node(..)) => unimplemented!("No support for inner hashed value"),
			None => (),
		}

		Bitmap::encode(
			children.map(|maybe_child| match maybe_child.borrow() {
				Some(ChildReference::Hash(h, _)) => {
					h.as_ref().encode_to(&mut output);
					true
				},
				&Some(ChildReference::Inline(inline_data, len)) => {
					inline_data.as_ref()[..len].encode_to(&mut output);
					true
				},
				None => false,
			}),
			bitmap.as_mut(),
		);
		output[bitmap_index..bitmap_index + BITMAP_LENGTH]
			.copy_from_slice(&bitmap.as_ref()[..BITMAP_LENGTH]);
		output
	}
}

/// Compare trie builder and in memory trie.
pub fn compare_implementations<T, K>(data: Vec<(Vec<u8>, Vec<u8>)>)
where
	T: TrieLayout,
	T::Location: std::fmt::Debug,
	K: KeyFunction<T::Hash> + Send + Sync,
{
	let (mut mem_db1, _) = MemoryDB::<T::Hash, K, _>::default_with_root();
	let (mut mem_db2, _) = MemoryDB::<T::Hash, K, _>::default_with_root();
	let root_new = calc_root_build::<T, _, _, _, _>(data.clone(), &mut mem_db1);
	let root = {
		let mut t = TrieDBMutBuilder::<T>::new(&mut mem_db2).build();
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
		}
		t.commit().apply_to(&mut mem_db2)
	};
	if root_new != root {
		{
			let db: &dyn node_db::NodeDB<_, _, _> = &mem_db1;
			let t = TrieDBBuilder::<T>::new(db, &root_new).build();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:x?}", a);
			}
		}
		{
			let db: &dyn node_db::NodeDB<_, _, _> = &mem_db2;
			let t = TrieDBBuilder::<T>::new(db, &root).build();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:x?}", a);
			}
		}
	}

	assert_eq!(root, root_new);
	// compare db content for key fuzzing
	assert!(mem_db1 == mem_db2);
}

/// Compare trie builder and trie root implementations.
pub fn compare_root<T: TrieLayout, DB: node_db::NodeDB<T::Hash, DBValue, T::Location>>(
	data: Vec<(Vec<u8>, Vec<u8>)>,
	memdb: DB,
) {
	let root_new = reference_trie_root_iter_build::<T, _, _, _>(data.clone());
	let root = {
		let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
		}
		*t.commit().hash()
	};

	assert_eq!(root, root_new);
}

/// Compare trie builder and trie root unhashed implementations.
pub fn compare_unhashed(data: Vec<(Vec<u8>, Vec<u8>)>) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashed::<ExtensionLayout>::default();
		trie_visit::<ExtensionLayout, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = reference_trie_root_unhashed(data);

	assert_eq!(root, root_new);
}

/// Compare trie builder and trie root unhashed implementations.
/// This uses the variant without extension nodes.
pub fn compare_unhashed_no_extension(data: Vec<(Vec<u8>, Vec<u8>)>) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashed::<NoExtensionLayout>::default();
		trie_visit::<NoExtensionLayout, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = reference_trie_root_unhashed_no_extension(data);

	assert_eq!(root, root_new);
}

/// Trie builder root calculation utility.
pub fn calc_root<T, I, A, B>(data: I) -> <T::Hash as Hasher>::Out
where
	T: TrieLayout,
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = TrieRoot::<T>::default();
	trie_visit::<T, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or_default()
}

/// Trie builder trie building utility.
pub fn calc_root_build<T, I, A, B, K>(
	data: I,
	memdb: &mut MemoryDB<T::Hash, K, DBValue>,
) -> TrieHash<T>
where
	T: TrieLayout,
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
	K: KeyFunction<T::Hash> + Send + Sync,
{
	let mut cb = TrieBuilder::<T, K>::new(memdb);
	trie_visit::<T, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or_default()
}

/// `compare_implementations_no_extension` for unordered input (trie_root does
/// ordering before running when trie_build expect correct ordering).

pub fn compare_implementations_unordered<T, K>(data: Vec<(Vec<u8>, Vec<u8>)>)
where
	T: TrieLayout,
	T::Location: std::fmt::Debug,
	K: KeyFunction<T::Hash> + Send + Sync,
{
	let mut mem_db1 = MemoryDB::<T::Hash, K, _>::default();
	let mut mem_db2 = MemoryDB::<T::Hash, K, _>::default();
	let mut b_map = std::collections::btree_map::BTreeMap::new();
	let root = {
		let mut t = TrieDBMutBuilder::<T>::new(&mut mem_db1).build();
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
			b_map.insert(data[i].0.clone(), data[i].1.clone());
		}
		*t.commit().hash()
	};
	let root_new = {
		let mut cb = TrieBuilder::<T, K>::new(&mut mem_db2);
		trie_visit::<T, _, _, _, _>(b_map.into_iter(), &mut cb);
		cb.root.unwrap_or_default()
	};

	if root != root_new {
		{
			let db: &dyn node_db::NodeDB<_, _, _> = &mem_db1;
			let t = TrieDBBuilder::<T>::new(db, &root).build();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
		{
			let db: &dyn node_db::NodeDB<_, _, _> = &mem_db2;
			let t = TrieDBBuilder::<T>::new(db, &root_new).build();
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
pub fn compare_insert_remove<T, K>(data: Vec<(bool, Vec<u8>, Vec<u8>)>)
where
	T: TrieLayout,
	K: KeyFunction<T::Hash> + Send + Sync,
{
	let mut data2 = std::collections::BTreeMap::new();
	let mut a = 0;
	let mut memdb = MemoryDB::<T::Hash, K, _>::default();
	let mut root = {
		let t = TrieDBMutBuilder::<T>::new(&memdb).build();
		*t.commit().hash()
	};
	while a < data.len() {
		// new triemut every 3 element
		root = {
			let mut t = TrieDBMutBuilder::<T>::from_existing(&memdb, root).build();
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
					break
				}
			}
			t.commit().apply_to(&mut memdb)
		};
	}
	// we are testing the RefTrie code here so we do not sort or check uniqueness
	// before.
	assert_eq!(root, calc_root::<T, _, _, _>(data2));
}

/// Example trie cache implementation.
///
/// Should not be used for anything in production.
pub struct TestTrieCache<L: TrieLayout> {
	/// In a real implementation we need to make sure that this is unique per trie root.
	value_cache: HashMap<Vec<u8>, trie_db::CachedValue<TrieHash<L>, L::Location>>,
	node_cache: HashMap<TrieHash<L>, NodeOwned<TrieHash<L>, L::Location>>,
}

impl<L: TrieLayout> TestTrieCache<L> {
	/// Clear the value cache.
	pub fn clear_value_cache(&mut self) {
		self.value_cache.clear();
	}

	/// Clear the node cache.
	pub fn clear_node_cache(&mut self) {
		self.node_cache.clear();
	}
}

impl<L: TrieLayout> Default for TestTrieCache<L> {
	fn default() -> Self {
		Self { value_cache: Default::default(), node_cache: Default::default() }
	}
}

impl<L: TrieLayout> trie_db::TrieCache<L::Codec, L::Location> for TestTrieCache<L> {
	fn lookup_value_for_key(
		&mut self,
		key: &[u8],
	) -> Option<&trie_db::CachedValue<TrieHash<L>, L::Location>> {
		self.value_cache.get(key)
	}

	fn cache_value_for_key(
		&mut self,
		key: &[u8],
		value: trie_db::CachedValue<TrieHash<L>, L::Location>,
	) {
		self.value_cache.insert(key.to_vec(), value);
	}

	fn get_or_insert_node(
		&mut self,
		hash: TrieHash<L>,
		_location: L::Location,
		fetch_node: &mut dyn FnMut() -> trie_db::Result<
			NodeOwned<TrieHash<L>, L::Location>,
			TrieHash<L>,
			trie_db::CError<L>,
		>,
	) -> trie_db::Result<&NodeOwned<TrieHash<L>, L::Location>, TrieHash<L>, trie_db::CError<L>> {
		match self.node_cache.entry(hash) {
			Entry::Occupied(e) => Ok(e.into_mut()),
			Entry::Vacant(e) => {
				let node = (*fetch_node)()?;
				Ok(e.insert(node))
			},
		}
	}

	fn get_node(
		&mut self,
		hash: &TrieHash<L>,
		_location: L::Location,
	) -> Option<&NodeOwned<TrieHash<L>, L::Location>> {
		self.node_cache.get(hash)
	}

	fn insert_new_node(&mut self, _hash: &TrieHash<L>) {}
}

#[cfg(test)]
mod tests {
	use super::*;
	use trie_db::{nibble_ops::NIBBLE_PER_BYTE, node::Node};

	const _: fn() -> () = || {
		struct AssertTrieDBRawIteratorIsSendAndSync
		where
			trie_db::TrieDBRawIterator<NoExtensionLayout>: Send + Sync;
	};

	#[test]
	fn test_encoding_simple_trie() {
		for prefix in
			[LEAF_PREFIX_MASK_NO_EXT, BRANCH_WITHOUT_MASK_NO_EXT, BRANCH_WITH_MASK_NO_EXT].iter()
		{
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
		let enc = <ReferenceNodeCodecNoExt<RefHasher> as NodeCodec>::leaf_node(
			input.iter().cloned(),
			input.len() * NIBBLE_PER_BYTE,
			Value::<()>::Inline(&[1]),
		);
		let dec =
			<ReferenceNodeCodecNoExt<RefHasher> as NodeCodec>::decode(&enc, &[] as &[()]).unwrap();
		let o_sl = if let Node::Leaf(sl, _) = dec { Some(sl) } else { None };
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

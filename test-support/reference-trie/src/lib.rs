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
use trie_root::Hasher;

use trie_db::{
	node::{NibbleSlicePlan, NodePlan, NodeHandlePlan},
	triedbmut::ChildReference,
	DBValue,
	trie_visit,
	TrieBuilderComplex,
	TrieRootComplex,
	TrieRootUnhashedComplex,
	Partial,
	BinaryHasher,
	EncodedNoChild,
};
use std::borrow::Borrow;
use keccak_hasher::KeccakHasher;

pub use trie_db::{
	decode_compact, encode_compact, HashDBComplexDyn,
	nibble_ops, NibbleSlice, NibbleVec, NodeCodec, proof, Record, Recorder,
	Trie, TrieConfiguration, TrieDB, TrieDBIterator, TrieDBMut, TrieDBNodeIterator, TrieError,
	TrieIterator, TrieLayout, TrieMut, Bitmap, BITMAP_LENGTH,
};
pub use trie_root::TrieStream;
pub mod node {
	pub use trie_db::node::Node;
}

/// Trie layout using extension nodes.
pub struct ExtensionLayout;

impl TrieLayout for ExtensionLayout {
	const USE_EXTENSION: bool = true;
	const COMPLEX_HASH: bool = true;
	type Hash = KeccakHasher;
	type Codec = ReferenceNodeCodec<KeccakHasher>;
}

impl TrieConfiguration for ExtensionLayout { }

/// Trie layout without extension nodes, allowing
/// generic hasher.
pub struct GenericNoExtensionLayout<H>(PhantomData<H>);

impl<H: BinaryHasher> TrieLayout for GenericNoExtensionLayout<H> {
	const USE_EXTENSION: bool = false;
	const COMPLEX_HASH: bool = true;
	type Hash = H;
	type Codec = ReferenceNodeCodecNoExt<H>;
}

impl<H: BinaryHasher> TrieConfiguration for GenericNoExtensionLayout<H> { }

/// Trie layout without extension nodes.
pub type NoExtensionLayout = GenericNoExtensionLayout<keccak_hasher::KeccakHasher>;

pub type RefTrieDB<'a> = trie_db::TrieDB<'a, ExtensionLayout>;
pub type RefTrieDBNoExt<'a> = trie_db::TrieDB<'a, NoExtensionLayout>;
pub type RefTrieDBMut<'a> = trie_db::TrieDBMut<'a, ExtensionLayout>;
pub type RefTrieDBMutNoExt<'a> = trie_db::TrieDBMut<'a, NoExtensionLayout>;
pub type RefFatDB<'a> = trie_db::FatDB<'a, ExtensionLayout>;
pub type RefFatDBMut<'a> = trie_db::FatDBMut<'a, ExtensionLayout>;
pub type RefSecTrieDB<'a> = trie_db::SecTrieDB<'a, ExtensionLayout>;
pub type RefSecTrieDBMut<'a> = trie_db::SecTrieDBMut<'a, ExtensionLayout>;
pub type RefLookup<'a, Q> = trie_db::Lookup<'a, ExtensionLayout, Q>;
pub type RefLookupNoExt<'a, Q> = trie_db::Lookup<'a, NoExtensionLayout, Q>;

pub fn reference_trie_root<I, A, B>(input: I) -> <KeccakHasher as Hasher>::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::trie_root::<KeccakHasher, ReferenceTrieStream, _, _, _>(input)
}

/*fn reference_trie_root_unhashed<I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::unhashed_trie::<KeccakHasher, ReferenceTrieStream, _, _, _>(input)
}*/

pub fn reference_trie_root_no_extension<I, A, B>(input: I) -> <KeccakHasher as Hasher>::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::trie_root_no_extension::<KeccakHasher, ReferenceTrieStreamNoExt, _, _, _>(input)
}

/*fn reference_trie_root_unhashed_no_extension<I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::unhashed_trie_no_extension::<KeccakHasher, ReferenceTrieStreamNoExt, _, _, _>(input)
}*/

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

pub fn reference_trie_root_iter_build<I, A, B>(input: I) -> <KeccakHasher as Hasher>::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = trie_db::TrieRootComplex::<KeccakHasher, _>::default();
	trie_visit::<ExtensionLayout, _, _, _, _>(data_sorted_unique(input), &mut cb);
	cb.root.unwrap_or(Default::default())
}

pub fn reference_trie_root_no_extension_iter_build<I, A, B>(input: I) -> <KeccakHasher as Hasher>::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = trie_db::TrieRootComplex::<KeccakHasher, _>::default();
	trie_visit::<NoExtensionLayout, _, _, _, _>(data_sorted_unique(input), &mut cb);
	cb.root.unwrap_or(Default::default())
}

fn reference_trie_root_unhashed_iter_build<I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = trie_db::TrieRootUnhashedComplex::<KeccakHasher>::default();
	trie_visit::<ExtensionLayout, _, _, _, _>(data_sorted_unique(input), &mut cb);
	cb.root.unwrap_or(Default::default())
}

fn reference_trie_root_unhashed_no_extension_iter_build<I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = trie_db::TrieRootUnhashedComplex::<KeccakHasher>::default();
	trie_visit::<NoExtensionLayout, _, _, _, _>(data_sorted_unique(input), &mut cb);
	cb.root.unwrap_or(Default::default())
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
const EMPTY_TRIE_NO_EXT: u8 = 0;
const NIBBLE_SIZE_BOUND_NO_EXT: usize = u16::max_value() as usize;
const LEAF_PREFIX_MASK_NO_EXT: u8 = 0b_01 << 6;
const BRANCH_WITHOUT_MASK_NO_EXT: u8 = 0b_10 << 6;
const BRANCH_WITH_MASK_NO_EXT: u8 = 0b_11 << 6;

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

/// Create a leaf or branch node header followed by its encoded partial nibbles.
fn fuse_nibbles_node_no_extension<'a>(
	nibbles: &'a [u8],
	kind: NodeKindNoExt,
) -> impl Iterator<Item = u8> + 'a {
	let size = ::std::cmp::min(NIBBLE_SIZE_BOUND_NO_EXT, nibbles.len());

	let iter_start = match kind {
		NodeKindNoExt::Leaf => size_and_prefix_iterator(size, LEAF_PREFIX_MASK_NO_EXT),
		NodeKindNoExt::BranchNoValue => size_and_prefix_iterator(size, BRANCH_WITHOUT_MASK_NO_EXT),
		NodeKindNoExt::BranchWithValue => size_and_prefix_iterator(size, BRANCH_WITH_MASK_NO_EXT),
	};
	iter_start
		.chain(if nibbles.len() % 2 == 1 { Some(nibbles[0]) } else { None })
		.chain(nibbles[nibbles.len() % 2..].chunks(2).map(|ch| ch[0] << 4 | ch[1]))
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
	fn new() -> Self {
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
}

/// Reference implementation of a `TrieStream` without extension.
#[derive(Default, Clone)]
pub struct ReferenceTrieStreamNoExt {
	buffer: Vec<u8>
}

impl TrieStream for ReferenceTrieStreamNoExt {
	fn new() -> Self {
		ReferenceTrieStreamNoExt {
			buffer: Vec::new()
		}
	}

	fn append_empty_data(&mut self) {
		self.buffer.push(EMPTY_TRIE_NO_EXT);
	}

	fn append_leaf(&mut self, key: &[u8], value: &[u8]) {
		self.buffer.extend(fuse_nibbles_node_no_extension(key, NodeKindNoExt::Leaf));
		value.encode_to(&mut self.buffer);
	}

	fn begin_branch(
		&mut self,
		maybe_key: Option<&[u8]>,
		maybe_value: Option<&[u8]>,
		has_children: impl Iterator<Item = bool>
	) {
		if let Some(partial) = maybe_key {
			if maybe_value.is_some() {
				self.buffer.extend(
					fuse_nibbles_node_no_extension(partial, NodeKindNoExt::BranchWithValue)
				);
			} else {
				self.buffer.extend(
					fuse_nibbles_node_no_extension(partial, NodeKindNoExt::BranchNoValue)
				);
			}
			let bitmap = branch_node_bit_mask(has_children);
			self.buffer.extend([bitmap.0, bitmap.1].iter());
		} else {
			// should not happen
			self.buffer.extend(&branch_node(maybe_value.is_some(), has_children));
		}
		if let Some(value) = maybe_value {
			value.encode_to(&mut self.buffer);
		}
	}

	fn append_extension(&mut self, _key: &[u8]) {
		// should not happen
	}

	fn append_substream<H: Hasher>(&mut self, other: Self) {
		let data = other.out();
		match data.len() {
			0..=31 => data.encode_to(&mut self.buffer),
			_ => H::hash(&data).as_ref().encode_to(&mut self.buffer),
		}
	}

	fn out(self) -> Vec<u8> { self.buffer }
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
	fn encode_to<T: Output>(&self, output: &mut T) {
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

fn encode_size_and_prefix(size: usize, prefix: u8, out: &mut impl Output) {
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
	fn encode_to<T: Output>(&self, output: &mut T) {
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

impl<H: Hasher> ReferenceNodeCodec<H> {
	fn decode_plan_internal(
		data: &[u8],
		is_complex: bool,
	) -> ::std::result::Result<(NodePlan, usize), <Self as NodeCodec>::Error> {
		let mut input = ByteSliceInput::new(data);
		let node = match NodeHeader::decode(&mut input)? {
			NodeHeader::Null => NodePlan::Empty,
			NodeHeader::Branch(has_value) => {
				let bitmap_range = input.take(BITMAP_LENGTH)?;
				let bitmap = Bitmap::decode(&data[bitmap_range]);

				let value = if has_value {
					let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
					Some(input.take(count)?)
				} else {
					None
				};
				let mut children = [
					None, None, None, None, None, None, None, None,
					None, None, None, None, None, None, None, None,
				];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if bitmap.value_at(i) {
						if is_complex {
							children[i] = Some(NodeHandlePlan::Inline(Range { start: 0, end: 0 }));
						} else {
							let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
							let range = input.take(count)?;
							children[i] = Some(if count == H::LENGTH {
								NodeHandlePlan::Hash(range)
							} else {
								NodeHandlePlan::Inline(range)
							});
						}
					}
				}
				NodePlan::Branch { value, children }
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
				NodePlan::Extension {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					child
				}
			}
			NodeHeader::Leaf(nibble_count) => {
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
				let value = input.take(count)?;
				NodePlan::Leaf {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value,
				}
			}
		};
		Ok((node, input.offset))
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
		Ok(Self::decode_plan_internal(data, false)?.0)
	}

	fn decode_plan_no_child(data: &[u8]) -> ::std::result::Result<(NodePlan, usize), Self::Error> {
		Self::decode_plan_internal(data, true)
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodec>::empty_node()
	}

	fn empty_node() -> &'static[u8] {
		&[EMPTY_TRIE]
	}

	fn leaf_node(partial: Partial, value: &[u8]) -> Vec<u8> {
		let mut output = partial_to_key(partial, LEAF_NODE_OFFSET, LEAF_NODE_OVER);
		value.encode_to(&mut output);
		output
	}

	fn extension_node(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		child: ChildReference<Self::HashOut>,
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
		maybe_value: Option<&[u8]>,
		mut register_children: Option<&mut [Option<Range<usize>>]>,
	) -> (Vec<u8>, EncodedNoChild) {
		let mut output = vec![0; BITMAP_LENGTH + 1];
		let mut prefix: [u8; 3] = [0; 3];
		let have_value = if let Some(value) = maybe_value {
			value.encode_to(&mut output);
			true
		} else {
			false
		};
		let mut ix = 0;
		let ix = &mut ix;
		let mut register_children = register_children.as_mut();
		let register_children = &mut register_children;
		let no_child = if register_children.is_some() {
			EncodedNoChild::Range(Range {
				start: 0,
				end: output.len(),
			})
		} else {
			EncodedNoChild::Unused
		};
		let has_children = children.map(|maybe_child| match maybe_child.borrow() {
			Some(ChildReference::Hash(h)) => {
				if let Some(ranges) = register_children {
					// this assume scale codec put len on one byte, which is the
					// case for reasonable hash length.
					let encode_size_offset = 1;
					ranges[*ix] = Some(Range {
						start: output.len() + encode_size_offset,
						end: output.len() + encode_size_offset + h.as_ref().len(),
					});
					*ix += 1;
				}
				h.as_ref().encode_to(&mut output);
				true
			}
			&Some(ChildReference::Inline(inline_data, len)) => {
				if let Some(ranges) = register_children {
					let encode_size_offset = 1;
					ranges[*ix] = Some(Range {
						start: output.len() + encode_size_offset,
						end: output.len() + encode_size_offset + len,
					});
					*ix += 1;
				}
				inline_data.as_ref()[..len].encode_to(&mut output);
				true
			}
			None => {
				if register_children.is_some() {
					*ix += 1;
				}
				false
			},
		});
		branch_node_buffered(have_value, has_children, prefix.as_mut());
		output[0..BITMAP_LENGTH + 1].copy_from_slice(prefix.as_ref());
		(output, no_child)
	}

	fn branch_node_nibbled(
		_partial:	impl Iterator<Item = u8>,
		_number_nibble: usize,
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		_maybe_value: Option<&[u8]>,
		_register_children: Option<&mut [Option<Range<usize>>]>,
	) -> (Vec<u8>, EncodedNoChild) {
		unreachable!()
	}

}

impl<H: Hasher> ReferenceNodeCodecNoExt<H> {
	fn decode_plan_internal(
		data: &[u8],
		is_complex: bool,
	) -> ::std::result::Result<(NodePlan, usize), <Self as NodeCodec>::Error> {
		let mut input = ByteSliceInput::new(data);
		let node = match NodeHeaderNoExt::decode(&mut input)? {
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
				let bitmap = Bitmap::decode(&data[bitmap_range]);
				let value = if has_value {
					let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
					Some(input.take(count)?)
				} else {
					None
				};
				let mut children = [
					None, None, None, None, None, None, None, None,
					None, None, None, None, None, None, None, None,
				];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if bitmap.value_at(i) {
						if is_complex {
							children[i] = Some(NodeHandlePlan::Inline(Range { start: 0, end: 0 }));
						} else {
							let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
							let range = input.take(count)?;
							children[i] = Some(if count == H::LENGTH {
								NodeHandlePlan::Hash(range)
							} else {
								NodeHandlePlan::Inline(range)
							});
						}
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
				let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
				let value = input.take(count)?;
				NodePlan::Leaf {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value,
				}
			}
		};
		Ok((node, input.offset))
	}
}

impl<H: Hasher> NodeCodec for ReferenceNodeCodecNoExt<H> {
	type Error = CodecError;
	type HashOut = <H as Hasher>::Out;

	fn decode_plan(data: &[u8]) -> ::std::result::Result<NodePlan, Self::Error> {
		Ok(Self::decode_plan_internal(data, false)?.0)
	}

	fn decode_plan_no_child(data: &[u8]) -> ::std::result::Result<(NodePlan, usize), Self::Error> {
		Self::decode_plan_internal(data, true)
	}

	fn hashed_null_node() -> <H as Hasher>::Out {
		H::hash(<Self as NodeCodec>::empty_node())
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodec>::empty_node()
	}

	fn empty_node() -> &'static [u8] {
		&[EMPTY_TRIE_NO_EXT]
	}

	fn leaf_node(partial: Partial, value: &[u8]) -> Vec<u8> {
		let mut output = partial_encode(partial, NodeKindNoExt::Leaf);
		value.encode_to(&mut output);
		output
	}

	fn extension_node(
		_partial: impl Iterator<Item = u8>,
		_nbnibble: usize,
		_child: ChildReference<<H as Hasher>::Out>,
	) -> Vec<u8> {
		unreachable!()
	}

	fn branch_node(
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
		_maybe_value: Option<&[u8]>,
		_register_children: Option<&mut [Option<Range<usize>>]>,
	) -> (Vec<u8>, EncodedNoChild) {
		unreachable!()
	}

	fn branch_node_nibbled(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<Self::HashOut>>>>,
		maybe_value: Option<&[u8]>,
		mut register_children: Option<&mut [Option<Range<usize>>]>,
	) -> (Vec<u8>, EncodedNoChild) {
		let mut output = if maybe_value.is_some() {
			partial_from_iterator_encode(
				partial,
				number_nibble,
				NodeKindNoExt::BranchWithValue,
			)
		} else {
			partial_from_iterator_encode(
				partial,
				number_nibble,
				NodeKindNoExt::BranchNoValue,
			)
		};
		let bitmap_index = output.len();
		let mut bitmap: [u8; BITMAP_LENGTH] = [0; BITMAP_LENGTH];
		(0..BITMAP_LENGTH).for_each(|_| output.push(0));
		if let Some(value) = maybe_value {
			value.encode_to(&mut output);
		};
		let mut ix = 0;
		let ix = &mut ix;
		let mut register_children = register_children.as_mut();
		let register_children = &mut register_children;
		let no_child = if register_children.is_some() {
			EncodedNoChild::Range(Range {
				start: 0,
				end: output.len(),
			})
		} else {
			EncodedNoChild::Unused
		};
		Bitmap::encode(children.map(|maybe_child| match maybe_child.borrow() {
			Some(ChildReference::Hash(h)) => {
				if let Some(ranges) = register_children {
					// this assume scale codec put len on one byte, which is the
					// case for reasonable hash length.
					let encode_size_offset = 1;
					ranges[*ix] = Some(Range {
						start: output.len() + encode_size_offset,
						end: output.len() + encode_size_offset + h.as_ref().len(),
					});
					*ix += 1;
				}
				h.as_ref().encode_to(&mut output);
				true
			}
			&Some(ChildReference::Inline(inline_data, len)) => {
				if let Some(ranges) = register_children {
					let encode_size_offset = 1;
					ranges[*ix] = Some(Range {
						start: output.len() + encode_size_offset,
						end: output.len() + encode_size_offset + len,
					});
					*ix += 1;
				}
				inline_data.as_ref()[..len].encode_to(&mut output);
				true
			}
			None => {
				if register_children.is_some() {
					*ix += 1;
				}
				false
			},
		}), bitmap.as_mut());
		output[bitmap_index..bitmap_index + BITMAP_LENGTH]
			.copy_from_slice(&bitmap.as_ref()[..BITMAP_LENGTH]);
		(output, no_child)
	}

}

/// Compare trie builder and in memory trie.
pub fn compare_implementations<X : hash_db::HashDB<KeccakHasher, DBValue> + ordered_trie::HashDBComplex<KeccakHasher, DBValue> + Eq> (
	data: Vec<(Vec<u8>, Vec<u8>)>,
	mut memdb: X,
	mut hashdb: X,
) {
	let root_new = {
		let mut cb = TrieBuilderComplex::new(&mut hashdb);
		trie_visit::<ExtensionLayout, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
		}
		t.commit();
		t.root().clone()
	};
	if root_new != root {
		{
			let db : &dyn hash_db::HashDB<_, _> = &hashdb;
			let t = RefTrieDB::new(&db, &root_new).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:x?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_, _> = &memdb;
			let t = RefTrieDB::new(&db, &root).unwrap();
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
pub fn compare_root(
	data: Vec<(Vec<u8>, Vec<u8>)>,
	mut memdb: impl ordered_trie::HashDBComplex<KeccakHasher, DBValue>,
) {
	let root_new = {
		let mut cb = TrieRootComplex::<KeccakHasher, _>::default();
		trie_visit::<ExtensionLayout, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
		}
		t.root().clone()
	};

	assert_eq!(root, root_new);
}

/// Compare trie builder and trie root unhashed implementations.
pub fn compare_unhashed(
	data: Vec<(Vec<u8>, Vec<u8>)>,
) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashedComplex::<KeccakHasher>::default();
		trie_visit::<ExtensionLayout, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = reference_trie_root_unhashed_iter_build(data);

	assert_eq!(root, root_new);
}

/// Compare trie builder and trie root unhashed implementations.
/// This uses the variant without extension nodes.
pub fn compare_unhashed_no_extension(
	data: Vec<(Vec<u8>, Vec<u8>)>,
) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashedComplex::<KeccakHasher>::default();
		trie_visit::<NoExtensionLayout, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = reference_trie_root_unhashed_no_extension_iter_build(data);

	assert_eq!(root, root_new);
}

/// Trie builder root calculation utility.
pub fn calc_root<I, A, B>(
	data: I,
) -> <KeccakHasher as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord + fmt::Debug,
		B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = TrieRootComplex::<KeccakHasher, _>::default();
	trie_visit::<ExtensionLayout, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or(Default::default())
}

/// Trie builder root calculation utility.
/// This uses the variant without extension nodes.
pub fn calc_root_no_extension<I, A, B>(
	data: I,
) -> <KeccakHasher as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord + fmt::Debug,
		B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = TrieRootComplex::<KeccakHasher, _>::default();
	trie_db::trie_visit::<NoExtensionLayout, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or(Default::default())
}

/// Trie builder trie building utility.
pub fn calc_root_build<I, A, B, DB>(
	data: I,
	hashdb: &mut DB
) -> <KeccakHasher as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord + fmt::Debug,
		B: AsRef<[u8]> + fmt::Debug,
		DB: hash_db::HashDB<KeccakHasher, DBValue> + ordered_trie::HashDBComplex<KeccakHasher, DBValue>,
{
	let mut cb = TrieBuilderComplex::new(hashdb);
	trie_visit::<ExtensionLayout, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or(Default::default())
}

/// Trie builder trie building utility.
/// This uses the variant without extension nodes.
pub fn calc_root_build_no_extension<I, A, B, DB>(
	data: I,
	hashdb: &mut DB,
) -> <KeccakHasher as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord + fmt::Debug,
		B: AsRef<[u8]> + fmt::Debug,
		DB: hash_db::HashDB<KeccakHasher, DBValue> + ordered_trie::HashDBComplex<KeccakHasher, DBValue>,
{
	let mut cb = TrieBuilderComplex::new(hashdb);
	trie_db::trie_visit::<NoExtensionLayout, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or(Default::default())
}

/// Compare trie builder and in memory trie.
/// This uses the variant without extension nodes.
pub fn compare_implementations_no_extension(
	data: Vec<(Vec<u8>, Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher, DBValue> + ordered_trie::HashDBComplex<KeccakHasher, DBValue>,
	mut hashdb: impl hash_db::HashDB<KeccakHasher, DBValue> + ordered_trie::HashDBComplex<KeccakHasher, DBValue>,
) {
	let root_new = {
		let mut cb = TrieBuilderComplex::new(&mut hashdb);
		trie_visit::<NoExtensionLayout, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
		}
		t.root().clone()
	};
	
	if root != root_new {
		{
			let db : &dyn hash_db::HashDB<_, _> = &memdb;
			let t = RefTrieDBNoExt::new(&db, &root).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_, _> = &hashdb;
			let t = RefTrieDBNoExt::new(&db, &root_new).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
	}

	assert_eq!(root, root_new);
}

/// `compare_implementations_no_extension` for unordered input (trie_root does
/// ordering before running when trie_build expect correct ordering).
pub fn compare_implementations_no_extension_unordered(
	data: Vec<(Vec<u8>, Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher, DBValue> + ordered_trie::HashDBComplex<KeccakHasher, DBValue>,
	mut hashdb: impl hash_db::HashDB<KeccakHasher, DBValue> + ordered_trie::HashDBComplex<KeccakHasher, DBValue>,
) {
	let mut b_map = std::collections::btree_map::BTreeMap::new();
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..], &data[i].1[..]).unwrap();
			b_map.insert(data[i].0.clone(), data[i].1.clone());
		}
		t.root().clone()
	};
	let root_new = {
		let mut cb = TrieBuilderComplex::new(&mut hashdb);
		trie_visit::<NoExtensionLayout, _, _, _, _>(b_map.into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};

	if root != root_new {
		{
			let db : &dyn hash_db::HashDB<_, _> = &memdb;
			let t = RefTrieDBNoExt::new(&db, &root).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_, _> = &hashdb;
			let t = RefTrieDBNoExt::new(&db, &root_new).unwrap();
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
pub fn compare_no_extension_insert_remove(
	data: Vec<(bool, Vec<u8>, Vec<u8>)>,
	mut memdb: impl ordered_trie::HashDBComplex<KeccakHasher, DBValue>,
) {
	let mut data2 = std::collections::BTreeMap::new();
	let mut root = Default::default();
	let mut a = 0;
	{
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		t.commit();
	}
	while a < data.len() {
		// new triemut every 3 element
		root = {
			let mut t = RefTrieDBMutNoExt::from_existing(&mut memdb, &mut root).unwrap();
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
	let mut t = RefTrieDBMutNoExt::from_existing(&mut memdb, &mut root).unwrap();
	// we are testing the RefTrie code here so we do not sort or check uniqueness
	// before.
	assert_eq!(*t.root(), calc_root_no_extension(data2));
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
		let enc = <ReferenceNodeCodecNoExt<KeccakHasher> as NodeCodec>
		::leaf_node(((0, 0), &input), &[1]);
		let dec = <ReferenceNodeCodecNoExt<KeccakHasher> as NodeCodec>
		::decode(&enc).unwrap();
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

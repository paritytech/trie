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

extern crate hash_db;
extern crate trie_db;
extern crate parity_codec as codec;
extern crate trie_root;
extern crate keccak_hasher;

use std::fmt;
use std::error::Error as StdError;
use std::iter::once;
use codec::{Decode, Input, Output, Encode, Compact};
use trie_root::Hasher;
use trie_db::{
	node::Node,
	triedbmut::ChildReference,
	DBValue,
	trie_visit,
	trie_visit_no_ext,
	TrieBuilder,
	TrieRoot,
	Partial,
};
use std::borrow::Borrow;
use keccak_hasher::KeccakHasher;

pub use trie_db::{Trie, TrieMut, NibbleSlice, Recorder, NodeCodec};
pub use trie_db::{Record, TrieLayOut, NibbleHalf, NibbleOps};
pub use trie_root::TrieStream;

/// trie layout similar to parity-ethereum
pub struct LayoutOri;

impl TrieLayOut for LayoutOri {
	const USE_EXTENSION: bool = true;
	type H = keccak_hasher::KeccakHasher;
	type C = ReferenceNodeCodec;
	type N = NibbleHalf;
}

/// trie layout similar to substrate one
pub struct LayoutNew;

impl TrieLayOut for LayoutNew {
	const USE_EXTENSION: bool = false;
	type H = keccak_hasher::KeccakHasher;
	type C = ReferenceNodeCodecNoExt;
	type N = NibbleHalf;
}

pub type RefTrieDB<'a> = trie_db::TrieDB<'a, LayoutOri>;
pub type RefTrieDBNoExt<'a> = trie_db::TrieDB<'a, LayoutNew>;
pub type RefTrieDBMut<'a> = trie_db::TrieDBMut<'a, LayoutOri>;
pub type RefTrieDBMutNoExt<'a> = trie_db::TrieDBMut<'a, LayoutNew>;
pub type RefFatDB<'a> = trie_db::FatDB<'a, LayoutOri>;
pub type RefFatDBMut<'a> = trie_db::FatDBMut<'a, LayoutOri>;
pub type RefSecTrieDB<'a> = trie_db::SecTrieDB<'a, LayoutOri>;
pub type RefSecTrieDBMut<'a> = trie_db::SecTrieDBMut<'a, LayoutOri>;
pub type RefLookup<'a, Q> = trie_db::Lookup<'a, LayoutOri, Q>;
pub type RefLookupNoExt<'a, Q> = trie_db::Lookup<'a, LayoutNew, Q>;

pub fn ref_trie_root<I, A, B>(input: I) -> <KeccakHasher as Hasher>::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::trie_root::<KeccakHasher, ReferenceTrieStream, _, _, _>(input)
}

fn ref_trie_root_unhashed<I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::unhashed_trie::<KeccakHasher, ReferenceTrieStream, _, _, _>(input)
}

pub fn ref_trie_root_no_ext<I, A, B>(input: I) -> <KeccakHasher as Hasher>::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::trie_root_no_ext::<KeccakHasher, ReferenceTrieStreamNoExt, _, _, _>(input)
}

fn ref_trie_root_unhashed_no_ext<I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord + fmt::Debug,
	B: AsRef<[u8]> + fmt::Debug,
{
	trie_root::unhashed_trie_no_ext::<KeccakHasher, ReferenceTrieStreamNoExt, _, _, _>(input)
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

/*mod noext_cst {
	pub const EMPTY_TRIE: u8 = 0;
	pub const LEAF_NODE_OFFSET: u8 = 1;
	pub const LEAF_NODE_BIG: u8 = 85;
	pub const BRANCH_NODE_NO_VALUE: u8 = 86;
	pub const BRANCH_NODE_NO_VALUE_BIG: u8 = 170;
	pub const BRANCH_NODE_WITH_VALUE: u8 = 171;
	pub const BRANCH_NODE_WITH_VALUE_BIG: u8 = 255;
	pub const LEAF_NODE_OVER: u8 = LEAF_NODE_BIG - LEAF_NODE_OFFSET;
	pub const BRANCH_NODE_WITH_VALUE_OVER: u8 = BRANCH_NODE_WITH_VALUE_BIG - BRANCH_NODE_WITH_VALUE;
	pub const BRANCH_NODE_NO_VALUE_OVER: u8 = BRANCH_NODE_NO_VALUE_BIG - BRANCH_NODE_NO_VALUE;
	pub const LEAF_NODE_LAST: u8 = LEAF_NODE_BIG - 1;
	pub const BRANCH_NODE_WITH_VALUE_LAST: u8 = BRANCH_NODE_WITH_VALUE_BIG - 1;
	pub const BRANCH_NODE_NO_VALUE_LAST: u8 = BRANCH_NODE_NO_VALUE_BIG - 1;
}*/

/// constant use with trie simplification codec
mod s_cst {
	pub const EMPTY_TRIE: u8 = 0;
	pub const NIBBLE_SIZE_BOUND: usize = u16::max_value() as usize;
	pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
	pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
	pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
}


/// Create a leaf/extension node, encoding a number of nibbles. Note that this
/// cannot handle a number of nibbles that is zero or greater than 125 and if
/// you attempt to do so *IT WILL PANIC*.
fn fuse_nibbles_node<'a>(nibbles: &'a [u8], leaf: bool) -> impl Iterator<Item = u8> + 'a {
	debug_assert!(nibbles.len() < LEAF_NODE_OVER.min(EXTENSION_NODE_OVER) as usize, "nibbles length too long. what kind of size of key are you trying to include in the trie!?!");
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

/// Create a leaf/branch node, encoding a number of nibbles.
fn fuse_nibbles_node_noext<'a>(nibbles: &'a [u8], kind: NodeKindNoExt) -> impl Iterator<Item = u8> + 'a {
	let size = ::std::cmp::min(s_cst::NIBBLE_SIZE_BOUND, nibbles.len());

	let iter_start = match kind {
		NodeKindNoExt::Leaf => s_size_and_prefix_iter(size, s_cst::LEAF_PREFIX_MASK),
		NodeKindNoExt::BranchNoValue => s_size_and_prefix_iter(size, s_cst::BRANCH_WITHOUT_MASK),
		NodeKindNoExt::BranchWithValue => s_size_and_prefix_iter(size, s_cst::BRANCH_WITH_MASK),
	};
	iter_start
		.chain(if nibbles.len() % 2 == 1 { Some(nibbles[0]) } else { None })
		.chain(nibbles[nibbles.len() % 2..].chunks(2).map(|ch| ch[0] << 4 | ch[1]))
		//.chain(nibbles[..nibbles.len() - (nibbles.len() % 2)].chunks(2).map(|ch| ch[0] << 4 | ch[1]))
		//.chain(if nibbles.len() % 2 == 1 { Some(nibbles[nibbles.len() - 1] << 4) } else { None })
}

pub fn branch_node(has_value: bool, has_children: impl Iterator<Item = bool>) -> [u8; 3] {
	let first = if has_value {
		BRANCH_NODE_WITH_VALUE
	} else {
		BRANCH_NODE_NO_VALUE
	};
	let bm = branch_node_bit_mask(has_children);
	[first, bm.0, bm.1]
}

pub fn branch_node_bit_mask(has_children: impl Iterator<Item = bool>) -> (u8, u8) {
	let mut bitmap: u16 = 0;
	let mut cursor: u16 = 1;
	for v in has_children {
		if v { bitmap |= cursor }
		cursor <<= 1;
	}
	((bitmap % 256 ) as u8, (bitmap / 256 ) as u8)
}

/// Reference implementation of a `TrieStream`.
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

	fn begin_branch(&mut self, maybe_key: Option<&[u8]>, maybe_value: Option<&[u8]>, has_children: impl Iterator<Item = bool>) {
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
			0...31 => data.encode_to(&mut self.buffer),
			_ => H::hash(&data).as_ref().encode_to(&mut self.buffer),
		}
	}

	fn out(self) -> Vec<u8> { self.buffer }
}

/// Reference implementation of a `TrieStream`.
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
		self.buffer.push(s_cst::EMPTY_TRIE);
	}

	fn append_leaf(&mut self, key: &[u8], value: &[u8]) {
		self.buffer.extend(fuse_nibbles_node_noext(key, NodeKindNoExt::Leaf));
		value.encode_to(&mut self.buffer);
	}

	fn begin_branch(&mut self, maybe_key: Option<&[u8]>, maybe_value: Option<&[u8]>, has_children: impl Iterator<Item = bool>) {
		if let Some(partial) = maybe_key {
			if maybe_value.is_some() {
				self.buffer.extend(fuse_nibbles_node_noext(partial, NodeKindNoExt::BranchWithValue));
			} else {
				self.buffer.extend(fuse_nibbles_node_noext(partial, NodeKindNoExt::BranchNoValue));
			}
			let bm = branch_node_bit_mask(has_children);
			self.buffer.extend([bm.0,bm.1].iter());
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
			0...31 => data.encode_to(&mut self.buffer),
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
			NodeHeader::Leaf(nibble_count) => output.push_byte(LEAF_NODE_OFFSET + *nibble_count as u8),
			NodeHeader::Extension(nibble_count) => output.push_byte(EXTENSION_NODE_OFFSET + *nibble_count as u8),
		}
	}
}

fn s_size_and_prefix_iter(size: usize, prefix: u8) -> impl Iterator<Item = u8> {
	let size = ::std::cmp::min(s_cst::NIBBLE_SIZE_BOUND, size);

	let l1 = std::cmp::min(62, size);
	let (first_byte, mut rem) = if size == l1 {
		(once(prefix + l1 as u8), 0)
	} else {
		(once(prefix + 63), size - l1)
	};
	let next_bytes = move || {
		if rem > 0 {
			if rem < 256 {
				let res = rem - 1;
				rem = 0;
				Some(res as u8)
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

/// bounding size to storage in a u16 variable to avoid dos
fn s_encode_size_and_prefix(size: usize, prefix: u8, out: &mut impl Output) {
	for b in s_size_and_prefix_iter(size, prefix) {
		out.push_byte(b)
	}
}

fn s_decode_size<I: Input>(first: u8, input: &mut I) -> Option<usize> {
	let mut result = (first & 255u8 >> 2) as usize;
	if result < 63 {
		return Some(result);
	}
	result -= 1;
	while result <= s_cst::NIBBLE_SIZE_BOUND {
		let n = input.read_byte()? as usize;
		if n < 255 {
			return Some(result + n + 1);
		}
		result += 255;
	}
	Some(s_cst::NIBBLE_SIZE_BOUND)
}

#[test]
fn test_encoding_simple_trie() {
	for prefix in [
		s_cst::LEAF_PREFIX_MASK,
		s_cst::BRANCH_WITHOUT_MASK,
		s_cst::BRANCH_WITH_MASK,
	].iter() {
		for i in (0..1000)
			.chain(s_cst::NIBBLE_SIZE_BOUND - 2..s_cst::NIBBLE_SIZE_BOUND + 2) {
			let mut output = Vec::new();
			s_encode_size_and_prefix(i, *prefix, &mut output);
			let input	= &mut &output[..];
			let first = input.read_byte().unwrap();
			assert_eq!(first & (0b11 << 6), *prefix);
			let v = s_decode_size(first, input);
			assert_eq!(Some(std::cmp::min(i, s_cst::NIBBLE_SIZE_BOUND)), v);
		}

	}
}

/*
#[test]
fn test_mal() {
	let mut unique = std::collections::BTreeMap::new();
	// test over 32 bit only is still 4 byte & this bruteforce takes way to long...
	for i in (0..u32::max_value() / 4) {
		let enc = i.to_be_bytes();
		assert!(enc[0] >> 6 == 0);
		let input = &mut &enc[..];
		let first = input.read_byte().unwrap();
		if let Some(v) = s_decode_size(first, input) {
			let mut rem = 0;
			while let Some(_) = input.read_byte() { rem += 1 }
			if let Some((prev,prem)) = unique.insert(v, (enc.to_vec(),rem)) {
				assert_eq!(&enc[..4 - rem], &prev[..4 - prem],
					"duplicated key val {} {} {:x?} {:x?}", v, i, prev, enc);
			}
		}
	}
}
*/

impl Encode for NodeHeaderNoExt {
	fn encode_to<T: Output>(&self, output: &mut T) {
		match self {
			NodeHeaderNoExt::Null => output.push_byte(s_cst::EMPTY_TRIE),
			NodeHeaderNoExt::Branch(true, nibble_count)	=>
				s_encode_size_and_prefix(*nibble_count, s_cst::BRANCH_WITH_MASK, output),
			NodeHeaderNoExt::Branch(false, nibble_count) =>
				s_encode_size_and_prefix(*nibble_count, s_cst::BRANCH_WITHOUT_MASK, output),
			NodeHeaderNoExt::Leaf(nibble_count) =>
				s_encode_size_and_prefix(*nibble_count, s_cst::LEAF_PREFIX_MASK, output),
		}
	}
}

impl Decode for NodeHeader {
	fn decode<I: Input>(input: &mut I) -> Option<Self> {
		Some(match input.read_byte()? {
			EMPTY_TRIE => NodeHeader::Null,
			BRANCH_NODE_NO_VALUE => NodeHeader::Branch(false),
			BRANCH_NODE_WITH_VALUE => NodeHeader::Branch(true),
			i @ LEAF_NODE_OFFSET ... LEAF_NODE_LAST => NodeHeader::Leaf((i - LEAF_NODE_OFFSET) as usize),
			i @ EXTENSION_NODE_OFFSET ... EXTENSION_NODE_LAST => NodeHeader::Extension((i - EXTENSION_NODE_OFFSET) as usize),
		})
	}
}

impl Decode for NodeHeaderNoExt {
	fn decode<I: Input>(input: &mut I) -> Option<Self> {
		let i = input.read_byte()?;
		if i == s_cst::EMPTY_TRIE {
			return Some(NodeHeaderNoExt::Null);
		}
		match i & (0b11 << 6) {
			s_cst::LEAF_PREFIX_MASK => Some(NodeHeaderNoExt::Leaf(s_decode_size(i, input)?)),
			s_cst::BRANCH_WITHOUT_MASK => Some(NodeHeaderNoExt::Branch(false, s_decode_size(i, input)?)),
			s_cst::BRANCH_WITH_MASK => Some(NodeHeaderNoExt::Branch(true, s_decode_size(i, input)?)),
			// do not allow any special encoding
			_ => None,
		}
	}
}

/// Simple reference implementation of a `NodeCodec`.
/// This is similar to ethereum implementation.
#[derive(Default, Clone)]
pub struct ReferenceNodeCodec;

/// Simple reference implementation of a `NodeCodec`.
/// This is following https://github.com/w3f/polkadot-re-spec/issues/8
#[derive(Default, Clone)]
pub struct ReferenceNodeCodecNoExt;

#[derive(Debug, PartialEq, Eq, Clone)]
/// Error concerning the Parity-Codec based decoder.
pub enum ReferenceError {
	/// Bad format.
	BadFormat,
}

impl StdError for ReferenceError {
	fn description(&self) -> &str {
		"codec error"
	}
}

impl fmt::Display for ReferenceError {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		fmt::Debug::fmt(&self, f)
	}
}

fn take<'a>(input: &mut &'a[u8], count: usize) -> Option<&'a[u8]> {
	if input.len() < count {
		return None
	}
	let r = &(*input)[..count];
	*input = &(*input)[count..];
	Some(r)
}

fn partial_to_key<N: NibbleOps>(partial: Partial, offset: u8, over: u8) -> Vec<u8> {
	let nb_nibble_hpe = (partial.0).0 as usize;
	let nibble_count = partial.1.len() * N::NIBBLE_PER_BYTE + nb_nibble_hpe;
	assert!(nibble_count < over as usize);
	let mut output = vec![offset + nibble_count as u8];
	if nb_nibble_hpe > 0 {
		output.push(N::masked_right(nb_nibble_hpe as u8, (partial.0).1));
	}
	output.extend_from_slice(&partial.1[..]);
	output
}


fn partial_to_key_it<N: NibbleOps, I: Iterator<Item = u8>>(partial: I, nibble_count: usize, offset: u8, over: u8) -> Vec<u8> {
	assert!(nibble_count < over as usize);
	let mut output = Vec::with_capacity(1 + (nibble_count / N::NIBBLE_PER_BYTE));
	output.push(offset + nibble_count as u8);
	output.extend(partial);
	output
}

fn partial_enc_it<N: NibbleOps, I: Iterator<Item = u8>>(partial: I, nibble_count: usize, node_kind: NodeKindNoExt) -> Vec<u8> {
	let nibble_count = ::std::cmp::min(s_cst::NIBBLE_SIZE_BOUND, nibble_count);

	let mut output = Vec::with_capacity(3 + nibble_count);
	match node_kind {
		NodeKindNoExt::Leaf => NodeHeaderNoExt::Leaf(nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchWithValue => NodeHeaderNoExt::Branch(true, nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchNoValue => NodeHeaderNoExt::Branch(false, nibble_count).encode_to(&mut output),
	};
	output.extend(partial);
	output
}



fn partial_enc<N: NibbleOps>(partial: Partial, node_kind: NodeKindNoExt) -> Vec<u8> {
	let nb_nibble_hpe = (partial.0).0 as usize;
	let nibble_count = partial.1.len() * N::NIBBLE_PER_BYTE + nb_nibble_hpe;

	let nibble_count = ::std::cmp::min(s_cst::NIBBLE_SIZE_BOUND, nibble_count);

	let mut output = Vec::with_capacity(3 + partial.1.len());
	match node_kind {
		NodeKindNoExt::Leaf => NodeHeaderNoExt::Leaf(nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchWithValue => NodeHeaderNoExt::Branch(true, nibble_count).encode_to(&mut output),
		NodeKindNoExt::BranchNoValue => NodeHeaderNoExt::Branch(false, nibble_count).encode_to(&mut output),
	};
	if nb_nibble_hpe > 0 {
		output.push(N::masked_right(nb_nibble_hpe as u8, (partial.0).1));
	}
	output.extend_from_slice(&partial.1[..]);
	output
}

// NOTE: what we'd really like here is:
// `impl<H: Hasher> NodeCodec<H> for RlpNodeCodec<H> where <KeccakHasher as Hasher>::Out: Decodable`
// but due to the current limitations of Rust const evaluation we can't
// do `const HASHED_NULL_NODE: <KeccakHasher as Hasher>::Out = <KeccakHasher as Hasher>::Out( … … )`. Perhaps one day soon?
impl<N: NibbleOps> NodeCodec<KeccakHasher, N> for ReferenceNodeCodec {
	type Error = ReferenceError;

	fn hashed_null_node() -> <KeccakHasher as Hasher>::Out {
		KeccakHasher::hash(<Self as NodeCodec<_, N>>::empty_node())
	}

	fn decode(data: &[u8]) -> ::std::result::Result<Node<N>, Self::Error> {
		let input = &mut &*data;
		match NodeHeader::decode(input).ok_or(ReferenceError::BadFormat)? {
			NodeHeader::Null => Ok(Node::Empty),
			NodeHeader::Branch(has_value) => {
				// TODO EMCH var len bitmap up to 256 from 2 see NibbleOps variant 
				let bitmap = u16::decode(input).ok_or(ReferenceError::BadFormat)?;
				let value = if has_value {
					let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
					Some(take(input, count).ok_or(ReferenceError::BadFormat)?)
				} else {
					None
				};
				// TODO EMCH could not parameterized this on associated constant
				let mut children = [None; 16];
				let mut pot_cursor = 1;
				for i in 0..N::NIBBLE_LEN {
					if bitmap & pot_cursor != 0 {
						let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
						children[i] = Some(take(input, count).ok_or(ReferenceError::BadFormat)?);
					}
					pot_cursor <<= 1;
				}
				Ok(Node::Branch(children, value))
			}
			NodeHeader::Extension(nibble_count) => {
				let nibble_data = take(input, (nibble_count + (N::NIBBLE_PER_BYTE - 1)) / N::NIBBLE_PER_BYTE)
					.ok_or(ReferenceError::BadFormat)?;
				let nibble_slice = NibbleSlice::new_offset(nibble_data,
					N::nb_padding(nibble_count));
				let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
				Ok(Node::Extension(nibble_slice, take(input, count).ok_or(ReferenceError::BadFormat)?))
			}
			NodeHeader::Leaf(nibble_count) => {
				let nibble_data = take(input, (nibble_count + (N::NIBBLE_PER_BYTE - 1)) / N::NIBBLE_PER_BYTE)
					.ok_or(ReferenceError::BadFormat)?;
				let nibble_slice = NibbleSlice::new_offset(nibble_data,
					N::nb_padding(nibble_count));
				let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
				Ok(Node::Leaf(nibble_slice, take(input, count).ok_or(ReferenceError::BadFormat)?))
			}
		}
	}

	fn try_decode_hash(data: &[u8]) -> Option<<KeccakHasher as Hasher>::Out> {
		if data.len() == KeccakHasher::LENGTH {
			let mut r = <KeccakHasher as Hasher>::Out::default();
			r.as_mut().copy_from_slice(data);
			Some(r)
		} else {
			None
		}
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodec<_, N>>::empty_node()
	}

	fn empty_node() -> &'static[u8] {
		&[EMPTY_TRIE]
	}

	fn leaf_node(partial: Partial, value: &[u8]) -> Vec<u8> {
		let mut output = partial_to_key::<N>(partial, LEAF_NODE_OFFSET, LEAF_NODE_OVER);
		value.encode_to(&mut output);
		output
	}

	fn ext_node(partial: impl Iterator<Item = u8>, nb_nibble: usize, child: ChildReference<<KeccakHasher as Hasher>::Out>) -> Vec<u8> {
		let mut output = partial_to_key_it::<N,_>(partial, nb_nibble, EXTENSION_NODE_OFFSET, EXTENSION_NODE_OVER);
		match child {
			ChildReference::Hash(h) => h.as_ref().encode_to(&mut output),
			ChildReference::Inline(inline_data, len) => (&AsRef::<[u8]>::as_ref(&inline_data)[..len]).encode_to(&mut output),
		};
		output
	}

	fn branch_node(
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<<KeccakHasher as Hasher>::Out>>>>,
		maybe_value: Option<&[u8]>) -> Vec<u8> {
		let mut output = vec![0, 0, 0];
		let have_value = if let Some(value) = maybe_value {
			value.encode_to(&mut output);
			true
		} else {
			false
		};
		let prefix = branch_node(have_value, children.map(|maybe_child| match maybe_child.borrow() {
			Some(ChildReference::Hash(h)) => {
				h.as_ref().encode_to(&mut output);
				true
			}
			&Some(ChildReference::Inline(inline_data, len)) => {
				inline_data.as_ref()[..len].encode_to(&mut output);
				true
			}
			None => false,
		}));
		output[0..3].copy_from_slice(&prefix[..]);
		output
	}

	fn branch_node_nibbled(
		_partial:	impl Iterator<Item = u8>,
		_nb_nibble: usize,
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<<KeccakHasher as Hasher>::Out>>>>,
		_maybe_value: Option<&[u8]>) -> Vec<u8> {
		unreachable!()
	}

}

impl<N: NibbleOps> NodeCodec<KeccakHasher, N> for ReferenceNodeCodecNoExt {
	type Error = ReferenceError;

	fn hashed_null_node() -> <KeccakHasher as Hasher>::Out {
		KeccakHasher::hash(<Self as NodeCodec<_, N>>::empty_node())
	}

	fn decode(data: &[u8]) -> ::std::result::Result<Node<N>, Self::Error> {
		let input = &mut &*data;
		let head = NodeHeaderNoExt::decode(input).ok_or(ReferenceError::BadFormat)?;
		match head {
			NodeHeaderNoExt::Null => Ok(Node::Empty),
			NodeHeaderNoExt::Branch(has_value, nibble_count) => {
				let nb_nibble_hpe = nibble_count % N::NIBBLE_PER_BYTE;
				if nb_nibble_hpe > 0 && N::masked_left(nb_nibble_hpe as u8, input[0]) != 0 {
					return Err(ReferenceError::BadFormat);
				}
				let nibble_data = take(input, (nibble_count + (N::NIBBLE_PER_BYTE - 1)) / N::NIBBLE_PER_BYTE)
					.ok_or(ReferenceError::BadFormat)?;
				let nibble_slice = NibbleSlice::new_offset(nibble_data,
					N::nb_padding(nibble_count));
				let bitmap = u16::decode(input).ok_or(ReferenceError::BadFormat)?;
				let value = if has_value {
					let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
					Some(take(input, count).ok_or(ReferenceError::BadFormat)?)
				} else {
					None
				};
				let mut children = [None; 16];
				let mut pot_cursor = 1;
				for i in 0..N::NIBBLE_LEN {
					if bitmap & pot_cursor != 0 {
						let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
						children[i] = Some(take(input, count).ok_or(ReferenceError::BadFormat)?);
					}
					pot_cursor <<= 1;
				}
				Ok(Node::NibbledBranch(nibble_slice, children, value))
			}
			NodeHeaderNoExt::Leaf(nibble_count) => {
				let nb_nibble_hpe = nibble_count % N::NIBBLE_PER_BYTE;
				if nb_nibble_hpe > 0 && N::masked_left(nb_nibble_hpe as u8, input[0]) != 0 {
					return Err(ReferenceError::BadFormat);
				}
				let nibble_data = take(input, (nibble_count + (N::NIBBLE_PER_BYTE - 1)) / N::NIBBLE_PER_BYTE)
					.ok_or(ReferenceError::BadFormat)?;
				let nibble_slice = NibbleSlice::new_offset(nibble_data,
					N::nb_padding(nibble_count));
				let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
				Ok(Node::Leaf(nibble_slice, take(input, count).ok_or(ReferenceError::BadFormat)?))
			}
		}
	}

	fn try_decode_hash(data: &[u8]) -> Option<<KeccakHasher as Hasher>::Out> {
		<ReferenceNodeCodec as NodeCodec<_, N>>::try_decode_hash(data)
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodec<_, N>>::empty_node()
	}

	fn empty_node() -> &'static [u8] {
		&[s_cst::EMPTY_TRIE]
	}

	fn leaf_node(partial: Partial, value: &[u8]) -> Vec<u8> {
		let mut output = partial_enc::<N>(partial, NodeKindNoExt::Leaf);
		value.encode_to(&mut output);
		output
	}

	fn ext_node(_partial: impl Iterator<Item = u8>, _nbnibble: usize, _child: ChildReference<<KeccakHasher as Hasher>::Out>) -> Vec<u8> {
		unreachable!()
	}

	fn branch_node(
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<<KeccakHasher as Hasher>::Out>>>>,
		_maybe_value: Option<&[u8]>) -> Vec<u8> {
		unreachable!()
	}

	fn branch_node_nibbled(
		partial: impl Iterator<Item = u8>,
		nb_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<<KeccakHasher as Hasher>::Out>>>>,
		maybe_value: Option<&[u8]>) -> Vec<u8> {
		let mut output = if maybe_value.is_some() {
			partial_enc_it::<N,_>(partial, nb_nibble, NodeKindNoExt::BranchWithValue)
		} else {
			partial_enc_it::<N,_>(partial, nb_nibble, NodeKindNoExt::BranchNoValue)
		};
		let bm_ix = output.len();
		output.push(0);
		output.push(0);
		if let Some(value) = maybe_value {
			value.encode_to(&mut output);
		};
		let bm = branch_node_bit_mask(children.map(|maybe_child| match maybe_child.borrow() {
			Some(ChildReference::Hash(h)) => {
				h.as_ref().encode_to(&mut output);
				true
			}
			&Some(ChildReference::Inline(inline_data, len)) => {
				inline_data[..len].encode_to(&mut output);
				true
			}
			None => false,
		}));
		output[bm_ix] = bm.0;
		output[bm_ix + 1] = bm.1;
		output
	}

}

// TODO fuse with other layout
pub fn compare_impl<X : hash_db::HashDB<KeccakHasher,DBValue> + Eq> (
	data: Vec<(Vec<u8>,Vec<u8>)>,
	mut memdb: X,
	mut hashdb: X,
) {
	let root_new = {
		let mut cb = TrieBuilder::new(&mut hashdb);
		trie_visit::<KeccakHasher, ReferenceNodeCodec, NibbleHalf, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..],&data[i].1[..]).unwrap();
		}
		t.commit();
		t.root().clone()
	};
	if root_new != root {
		{
			let db : &dyn hash_db::HashDB<_,_> = &hashdb;
			let t = RefTrieDB::new(&db, &root_new).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:x?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_,_> = &memdb;
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

pub fn compare_root(
	data: Vec<(Vec<u8>,Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
) {
	let root_new = {
		let mut cb = TrieRoot::<KeccakHasher, _>::default();
		trie_visit::<KeccakHasher, ReferenceNodeCodec, NibbleHalf, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..],&data[i].1[..]).unwrap();
		}
		t.root().clone()
	};

	assert_eq!(root, root_new);
}

pub fn compare_unhashed(
	data: Vec<(Vec<u8>,Vec<u8>)>,
) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashed::<KeccakHasher>::default();
		trie_visit::<KeccakHasher, ReferenceNodeCodec, NibbleHalf, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = ref_trie_root_unhashed(data);

	assert_eq!(root, root_new);
}

pub fn compare_unhashed_no_ext(
	data: Vec<(Vec<u8>,Vec<u8>)>,
) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashed::<KeccakHasher>::default();
		trie_visit_no_ext::<KeccakHasher, ReferenceNodeCodecNoExt, NibbleHalf, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = ref_trie_root_unhashed_no_ext(data);

	assert_eq!(root, root_new);
}



pub fn calc_root<I,A,B>(
	data: I,
) -> <KeccakHasher as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord + fmt::Debug,
		B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = TrieRoot::<KeccakHasher, _>::default();
	trie_visit::<KeccakHasher, ReferenceNodeCodec, NibbleHalf, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or(Default::default())
}

pub fn calc_root_no_ext<I,A,B>(
	data: I,
) -> <KeccakHasher as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord + fmt::Debug,
		B: AsRef<[u8]> + fmt::Debug,
{
	let mut cb = TrieRoot::<KeccakHasher, _>::default();
	trie_db::trie_visit_no_ext::<KeccakHasher, ReferenceNodeCodecNoExt, NibbleHalf, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or(Default::default())
}

pub fn compare_impl_no_ext(
	data: Vec<(Vec<u8>,Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
	mut hashdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
) {
	let root_new = {
		let mut cb = TrieBuilder::new(&mut hashdb);
		trie_visit_no_ext::<KeccakHasher, ReferenceNodeCodecNoExt, NibbleHalf, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..],&data[i].1[..]).unwrap();
		}
		t.root().clone()
	};
/*	{
		let db : &dyn hash_db::HashDB<_,_> = &memdb;
			let t = RefTrieDBNoExt::new(&db, &root).unwrap();
			println!("{:?}", t);
	}*/
		
	if root != root_new {
		{
			let db : &dyn hash_db::HashDB<_,_> = &memdb;
			let t = RefTrieDBNoExt::new(&db, &root).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_,_> = &hashdb;
			let t = RefTrieDBNoExt::new(&db, &root_new).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
	}

	assert_eq!(root, root_new);
}

pub fn compare_impl_no_ext_unordered(
	data: Vec<(Vec<u8>,Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
	mut hashdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
) {
	let mut b_map = std::collections::btree_map::BTreeMap::new();
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for i in 0..data.len() {
			t.insert(&data[i].0[..],&data[i].1[..]).unwrap();
			b_map.insert(data[i].0.clone(),data[i].1.clone());
		}
		t.root().clone()
	};
	let root_new = {
		let mut cb = TrieBuilder::new(&mut hashdb);
		trie_visit_no_ext::<KeccakHasher, ReferenceNodeCodecNoExt, NibbleHalf, _, _, _, _>(b_map.into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};

	if root != root_new {
		{
			let db : &dyn hash_db::HashDB<_,_> = &memdb;
			let t = RefTrieDBNoExt::new(&db, &root).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_,_> = &hashdb;
			let t = RefTrieDBNoExt::new(&db, &root_new).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
	}

	assert_eq!(root, root_new);
}

pub fn compare_no_ext_insert_remove(
	data: Vec<(bool, Vec<u8>,Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
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
	/*{
		let db : &dyn hash_db::HashDB<_,_> = &memdb;
		let t = RefTrieDBNoExt::new(&db, &root).unwrap();
		println!("{:x?}",t);
	}*/
	let mut t = RefTrieDBMutNoExt::from_existing(&mut memdb, &mut root).unwrap();
	// we are testing the RefTrie code here so we do not sort or check uniqueness
	// before.
	assert_eq!(*t.root(), calc_root_no_ext(data2));
}

// TODO EMCH to big is currently truncate, keep it that way?? wait for final spec
#[test]
fn too_big_nibble_len () {
	// + 1 for 0 added byte of nibble encode
	let input = vec![0u8; (s_cst::NIBBLE_SIZE_BOUND as usize + 1) / 2 + 1];
	let enc = <ReferenceNodeCodecNoExt as NodeCodec<_, NibbleHalf>>::leaf_node(((0,0),&input), &[1]);
	let dec = <ReferenceNodeCodecNoExt as NodeCodec<_, NibbleHalf>>::decode(&enc).unwrap();
	let o_sl = if let Node::Leaf(sl,_) = dec {
		Some(sl)
	} else { None };
	assert!(o_sl.is_some());
}

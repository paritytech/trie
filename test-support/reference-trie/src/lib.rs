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
	ProcessEncodedNode,
	TrieBuilder,
	TrieRoot,
};
use std::borrow::Borrow;
use keccak_hasher::KeccakHasher;

pub use trie_db::{Trie, TrieMut, NibbleSlice, NodeCodec, Recorder, Record};
pub use trie_root::TrieStream;

pub type RefTrieDB<'a> = trie_db::TrieDB<'a, keccak_hasher::KeccakHasher, ReferenceNodeCodec>;
pub type RefTrieDBNoExt<'a> = trie_db::TrieDB<'a, keccak_hasher::KeccakHasher, ReferenceNodeCodecNoExt>;
pub type RefTrieDBMut<'a> = trie_db::TrieDBMut<'a, KeccakHasher, ReferenceNodeCodec>;
pub type RefTrieDBMutNoExt<'a> = trie_db::TrieDBMutNoExt<'a, KeccakHasher, ReferenceNodeCodecNoExt>;
pub type RefFatDB<'a> = trie_db::FatDB<'a, KeccakHasher, ReferenceNodeCodec>;
pub type RefFatDBMut<'a> = trie_db::FatDBMut<'a, KeccakHasher, ReferenceNodeCodec>;
pub type RefSecTrieDB<'a> = trie_db::SecTrieDB<'a, KeccakHasher, ReferenceNodeCodec>;
pub type RefSecTrieDBMut<'a> = trie_db::SecTrieDBMut<'a, KeccakHasher, ReferenceNodeCodec>;
pub type RefLookup<'a, Q> = trie_db::Lookup<'a, KeccakHasher, ReferenceNodeCodec, Q>;

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



const EMPTY_TRIE: u8 = 0;
const LEAF_NODE_OFFSET: u8 = 1;
const EXTENSION_NODE_OFFSET: u8 = 128;
const BRANCH_NODE_NO_VALUE: u8 = 254;
const BRANCH_NODE_WITH_VALUE: u8 = 255;
const LEAF_NODE_OVER: u8 = EXTENSION_NODE_OFFSET - LEAF_NODE_OFFSET;
const EXTENSION_NODE_OVER: u8 = BRANCH_NODE_NO_VALUE - EXTENSION_NODE_OFFSET;
const LEAF_NODE_LAST: u8 = EXTENSION_NODE_OFFSET - 1;
const EXTENSION_NODE_LAST: u8 = BRANCH_NODE_NO_VALUE - 1;

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

pub fn branch_node(has_value: bool, has_children: impl Iterator<Item = bool>) -> [u8; 3] {
	let first = if has_value {
		BRANCH_NODE_WITH_VALUE
	} else {
		BRANCH_NODE_NO_VALUE
	};
	let mut bitmap: u16 = 0;
	let mut cursor: u16 = 1;
	for v in has_children {
		if v { bitmap |= cursor }
		cursor <<= 1;
	}
	[first, (bitmap % 256 ) as u8, (bitmap / 256 ) as u8]
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

	fn begin_branch(&mut self, maybe_value: Option<&[u8]>, has_children: impl Iterator<Item = bool>) {
		self.buffer.extend(&branch_node(maybe_value.is_some(), has_children));
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

/// A node header.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum NodeHeader {
	Null,
	Branch(bool),
	Extension(usize),
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

impl Decode for NodeHeader {
	fn decode<I: Input>(input: &mut I) -> Option<Self> {
		Some(match input.read_byte()? {
			EMPTY_TRIE => NodeHeader::Null,
			BRANCH_NODE_NO_VALUE => NodeHeader::Branch(false),
			BRANCH_NODE_WITH_VALUE => NodeHeader::Branch(true),
			i @ LEAF_NODE_OFFSET ... LEAF_NODE_LAST => NodeHeader::Leaf((i - LEAF_NODE_OFFSET) as usize),
			i @ EXTENSION_NODE_OFFSET ... EXTENSION_NODE_LAST => NodeHeader::Extension((i - EXTENSION_NODE_OFFSET) as usize),
			_ => unreachable!(),
		})
	}
}

/// Simple reference implementation of a `NodeCodec`.
#[derive(Default, Clone)]
pub struct ReferenceNodeCodec;

/// Simple reference implementation of a `NodeCodec`.
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

fn partial_to_key(partial: &[u8], offset: u8, over: u8) -> Vec<u8> {
	let nibble_count = (partial.len() - 1) * 2 + if partial[0] & 16 == 16 { 1 } else { 0 };
	assert!(nibble_count < over as usize);
	let mut output = vec![offset + nibble_count as u8];
	if nibble_count % 2 == 1 {
		output.push(partial[0] & 0x0f);
	}
	output.extend_from_slice(&partial[1..]);
	output
}

// NOTE: what we'd really like here is:
// `impl<H: Hasher> NodeCodec<H> for RlpNodeCodec<H> where <KeccakHasher as Hasher>::Out: Decodable`
// but due to the current limitations of Rust const evaluation we can't
// do `const HASHED_NULL_NODE: <KeccakHasher as Hasher>::Out = <KeccakHasher as Hasher>::Out( … … )`. Perhaps one day soon?
impl NodeCodec<KeccakHasher> for ReferenceNodeCodec {
	type Error = ReferenceError;

	fn hashed_null_node() -> <KeccakHasher as Hasher>::Out {
		KeccakHasher::hash(&[0u8][..])
	}

	fn decode(data: &[u8]) -> ::std::result::Result<Node, Self::Error> {
		let input = &mut &*data;
		match NodeHeader::decode(input).ok_or(ReferenceError::BadFormat)? {
			NodeHeader::Null => Ok(Node::Empty),
			NodeHeader::Branch(has_value) => {
				let bitmap = u16::decode(input).ok_or(ReferenceError::BadFormat)?;
				let value = if has_value {
					let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
					Some(take(input, count).ok_or(ReferenceError::BadFormat)?)
				} else {
					None
				};
				let mut children = [None; 16];
				let mut pot_cursor = 1;
				for i in 0..16 {
					if bitmap & pot_cursor != 0 {
						let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
						children[i] = Some(take(input, count).ok_or(ReferenceError::BadFormat)?);
					}
					pot_cursor <<= 1;
				}
				Ok(Node::Branch(children, value))
			}
			NodeHeader::Extension(nibble_count) => {
				let nibble_data = take(input, (nibble_count + 1) / 2).ok_or(ReferenceError::BadFormat)?;
				let nibble_slice = NibbleSlice::new_offset(nibble_data, nibble_count % 2);
				let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
				Ok(Node::Extension(nibble_slice, take(input, count).ok_or(ReferenceError::BadFormat)?))
			}
			NodeHeader::Leaf(nibble_count) => {
				let nibble_data = take(input, (nibble_count + 1) / 2).ok_or(ReferenceError::BadFormat)?;
				let nibble_slice = NibbleSlice::new_offset(nibble_data, nibble_count % 2);
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
		data == &[EMPTY_TRIE][..]
	}

	fn empty_node() -> Vec<u8> {
		vec![EMPTY_TRIE]
	}

	fn leaf_node(partial: &[u8], value: &[u8]) -> Vec<u8> {
		let mut output = partial_to_key(partial, LEAF_NODE_OFFSET, LEAF_NODE_OVER);
		value.encode_to(&mut output);
		output
	}

	fn ext_node(partial: &[u8], child: ChildReference<<KeccakHasher as Hasher>::Out>) -> Vec<u8> {
		let mut output = partial_to_key(partial, EXTENSION_NODE_OFFSET, EXTENSION_NODE_OVER);
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
    _partial: &[u8],
    _children: impl Iterator<Item = impl Borrow<Option<ChildReference<<KeccakHasher as Hasher>::Out>>>>,
    _maybe_value: Option<&[u8]>) -> Vec<u8> {
    unreachable!()
	}

}

impl NodeCodec<KeccakHasher> for ReferenceNodeCodecNoExt {
	type Error = ReferenceError;

	fn hashed_null_node() -> <KeccakHasher as Hasher>::Out {
    ReferenceNodeCodec::hashed_null_node()
	}

	fn decode(data: &[u8]) -> ::std::result::Result<Node, Self::Error> {
		let input = &mut &*data;
		match NodeHeader::decode(input).ok_or(ReferenceError::BadFormat)? {
			NodeHeader::Null => Ok(Node::Empty),
			NodeHeader::Branch(has_value) => {
				let bitmap = u16::decode(input).ok_or(ReferenceError::BadFormat)?;
        let nibble_count = take(input, 1).ok_or(ReferenceError::BadFormat)?[0] as usize;
				let nibble_data = take(input, (nibble_count + 1) / 2).ok_or(ReferenceError::BadFormat)?;
				let nibble_slice = NibbleSlice::new_offset(nibble_data, nibble_count % 2);
				let value = if has_value {
					let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
					Some(take(input, count).ok_or(ReferenceError::BadFormat)?)
				} else {
					None
				};
				let mut children = [None; 16];
				let mut pot_cursor = 1;
				for i in 0..16 {
					if bitmap & pot_cursor != 0 {
						let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
						children[i] = Some(take(input, count).ok_or(ReferenceError::BadFormat)?);
					}
					pot_cursor <<= 1;
				}
				Ok(Node::NibbledBranch(nibble_slice, children, value))
			}
			NodeHeader::Extension(_) => unreachable!(),
			NodeHeader::Leaf(nibble_count) => {
				let nibble_data = take(input, (nibble_count + 1) / 2).ok_or(ReferenceError::BadFormat)?;
				let nibble_slice = NibbleSlice::new_offset(nibble_data, nibble_count % 2);
				let count = <Compact<u32>>::decode(input).ok_or(ReferenceError::BadFormat)?.0 as usize;
				Ok(Node::Leaf(nibble_slice, take(input, count).ok_or(ReferenceError::BadFormat)?))
			}
    }
  }

	fn try_decode_hash(data: &[u8]) -> Option<<KeccakHasher as Hasher>::Out> {
    ReferenceNodeCodec::try_decode_hash(data)
	}

	fn is_empty_node(data: &[u8]) -> bool {
    ReferenceNodeCodec::is_empty_node(data)
	}

	fn empty_node() -> Vec<u8> {
    ReferenceNodeCodec::empty_node()
	}

	fn leaf_node(partial: &[u8], value: &[u8]) -> Vec<u8> {
    ReferenceNodeCodec::leaf_node(partial, value)
	}

	fn ext_node(_partial: &[u8], _child: ChildReference<<KeccakHasher as Hasher>::Out>) -> Vec<u8> {
    unreachable!()
	}

	fn branch_node(
    _children: impl Iterator<Item = impl Borrow<Option<ChildReference<<KeccakHasher as Hasher>::Out>>>>,
    _maybe_value: Option<&[u8]>) -> Vec<u8> {
    unreachable!()
	}

	fn branch_node_nibbled(
    partial: &[u8],
    children: impl Iterator<Item = impl Borrow<Option<ChildReference<<KeccakHasher as Hasher>::Out>>>>,
    maybe_value: Option<&[u8]>) -> Vec<u8> {
		let mut output = Vec::with_capacity(partial.len() + 4); // TODO choose a good capacity estimation value (here it is only partial)
    for _ in 0..3 {
      output.push(0);
    }

    let nibble_count = (partial.len() - 1) * 2 + if partial[0] & 16 == 16 { 1 } else { 0 };
    output.push(nibble_count as u8);
    if nibble_count % 2 == 1 {
      output.push(partial[0] & 0x0f);
    }
    output.extend_from_slice(&partial[1..]);

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
				inline_data[..len].encode_to(&mut output);
				true
			}
			None => false,
		}));
		output[0..3].copy_from_slice(&prefix[..]);
		output
	}

}

pub fn compare_impl(
	data: Vec<(Vec<u8>,Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
	mut hashdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
) {
	let root_new = {
		let mut cb = TrieBuilder::new(&mut hashdb);
		trie_visit::<KeccakHasher, ReferenceNodeCodec, _, _, _, _>(data.clone().into_iter(), &mut cb);
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
	if root != root_new {
		{
			let db : &dyn hash_db::HashDB<_,_> = &memdb;
			let t = RefTrieDB::new(&db, &root).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
		{
			let db : &dyn hash_db::HashDB<_,_> = &hashdb;
			let t = RefTrieDB::new(&db, &root_new).unwrap();
			println!("{:?}", t);
			for a in t.iter().unwrap() {
				println!("a:{:?}", a);
			}
		}
	}

	assert_eq!(root, root_new);
}

pub fn compare_root(
	data: Vec<(Vec<u8>,Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
) {
	let root_new = {
		let mut cb = TrieRoot::<KeccakHasher, _>::default();
		trie_visit::<KeccakHasher, ReferenceNodeCodec, _, _, _, _>(data.clone().into_iter(), &mut cb);
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
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
) {
	let root_new = {
		let mut cb = trie_db::TrieRootUnhashed::<KeccakHasher>::default();
		trie_visit::<KeccakHasher, ReferenceNodeCodec, _, _, _, _>(data.clone().into_iter(), &mut cb);
		cb.root.unwrap_or(Default::default())
	};
	let root = ref_trie_root_unhashed(data);

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
	trie_visit::<KeccakHasher, ReferenceNodeCodec, _, _, _, _>(data.into_iter(), &mut cb);
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
	trie_db::trie_visit_no_ext::<KeccakHasher, ReferenceNodeCodecNoExt, _, _, _, _>(data.into_iter(), &mut cb);
	cb.root.unwrap_or(Default::default())
}

pub fn compare_impl_no_ext(
	data: Vec<(Vec<u8>,Vec<u8>)>,
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
	mut hashdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
) {
	let root_new = {
		let mut cb = TrieBuilder::new(&mut hashdb);
		trie_visit_no_ext::<KeccakHasher, ReferenceNodeCodecNoExt, _, _, _, _>(data.clone().into_iter(), &mut cb);
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
		trie_visit_no_ext::<KeccakHasher, ReferenceNodeCodecNoExt, _, _, _, _>(b_map.into_iter(), &mut cb);
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
/*
pub fn compare_impl_no_ext_unordered_rem(
	data: Vec<(Vec<u8>,Vec<u8>)>,
	rem: &[(usize, usize)],
	mut memdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
	mut hashdb: impl hash_db::HashDB<KeccakHasher,DBValue>,
) {
  let mut b_map = std::collections::btree_map::BTreeMap::new();
	let root = {
		let mut root = Default::default();
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
    let mut rem_ix = 0;
    let mut has_rem = true;
		for i in 0..data.len() {
			t.insert(&data[i].0[..],&data[i].1[..]).unwrap();
      b_map.insert(data[i].0.clone(),data[i].1.clone());
      if has_rem && i == rem[rem_ix].1 {
        t.remove(&data[rem[rem_ix].0].0[..]).unwrap();
        b_map.remove(&data[rem[rem_ix].0].0[..]);
        rem_ix += 1;
        if rem_ix == rem.len() { has_rem = false }
      }
		}
		t.root().clone()
	};
	let root_new = {
		let mut cb = TrieBuilder::new(&mut hashdb);
		trie_visit_no_ext::<KeccakHasher, ReferenceNodeCodecNoExt, _, _, _, _>(b_map.into_iter(), &mut cb);
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
}*/

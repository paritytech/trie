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

//! Generates trie root.
//!
//! This module should be used to generate trie root hash.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(core_intrinsics))]
#![cfg_attr(not(feature = "std"), feature(alloc))]

extern crate hash_db;

#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::cmp;

#[cfg(not(feature = "std"))]
extern crate alloc;
#[cfg(not(feature = "std"))]
use alloc::{collections::btree_map::BTreeMap, vec::Vec};
#[cfg(not(feature = "std"))]
use core::cmp;

#[cfg(test)]
extern crate keccak_hasher;

pub use hash_db::Hasher;

/// TODO: DOCUMENT!!!!
pub trait TrieStream {
	fn new() -> Self;
	fn append_empty_data(&mut self);
	fn begin_branch(&mut self, maybe_value: Option<&[u8]>, has_children: impl Iterator<Item = bool>);
	fn append_empty_child(&mut self) {}
	fn end_branch(&mut self, _value: Option<&[u8]>) {}
	fn append_leaf(&mut self, key: &[u8], value: &[u8]);
	fn append_extension(&mut self, key: &[u8]);
	fn append_substream<H: Hasher>(&mut self, other: Self);
	fn out(self) -> Vec<u8>;
}

fn shared_prefix_len<T: Eq>(first: &[T], second: &[T]) -> usize {
	first.iter()
		.zip(second.iter())
		.position(|(f, s)| f != s)
		.unwrap_or_else(|| cmp::min(first.len(), second.len()))
}

/// Generates a trie root hash for a vector of key-value tuples
///
/// ```rust
/// #[macro_use] extern crate hex_literal;
/// extern crate trie_root;
/// extern crate reference_trie;
/// extern crate keccak_hasher;
/// use trie_root::trie_root;
/// use reference_trie::ReferenceTrieStream;
/// use keccak_hasher::KeccakHasher;
///
/// fn main() {
/// 	let v = vec![
/// 		("doe", "reindeer"),
/// 		("dog", "puppy"),
/// 		("dogglesworth", "cat"),
/// 	];
///
/// 	let root = hex!["0807d5393ae7f349481063ebb5dbaf6bda58db282a385ca97f37dccba717cb79"];
/// 	assert_eq!(trie_root::<KeccakHasher, ReferenceTrieStream, _, _, _>(v), root);
/// }
/// ```
pub fn trie_root<H, S, I, A, B>(input: I) -> H::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	// first put elements into btree to sort them and to remove duplicates
	let input = input
		.into_iter()
		.collect::<BTreeMap<_, _>>();

	let mut nibbles = Vec::with_capacity(input.keys().map(|k| k.as_ref().len()).sum::<usize>() * 2);
	let mut lens = Vec::with_capacity(input.len() + 1);
	lens.push(0);
	for k in input.keys() {
		for &b in k.as_ref() {
			nibbles.push(b >> 4);
			nibbles.push(b & 0x0F);
		}
		lens.push(nibbles.len());
	}

	// then move them to a vector
	let input = input.into_iter().zip(lens.windows(2))
		.map(|((_, v), w)| (&nibbles[w[0]..w[1]], v))
		.collect::<Vec<_>>();

	let mut stream = S::new();
	build_trie::<H, S, _, _>(&input, 0, &mut stream);
	H::hash(&stream.out())
}

//#[cfg(test)]	// consider feature="std"
pub fn unhashed_trie<H, S, I, A, B>(input: I) -> Vec<u8> where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	// first put elements into btree to sort them and to remove duplicates
	let input = input
		.into_iter()
		.collect::<BTreeMap<_, _>>();

	let mut nibbles = Vec::with_capacity(input.keys().map(|k| k.as_ref().len()).sum::<usize>() * 2);
	let mut lens = Vec::with_capacity(input.len() + 1);
	lens.push(0);
	for k in input.keys() {
		for &b in k.as_ref() {
			nibbles.push(b >> 4);
			nibbles.push(b & 0x0F);
		}
		lens.push(nibbles.len());
	}

	// then move them to a vector
	let input = input.into_iter().zip(lens.windows(2))
		.map(|((_, v), w)| (&nibbles[w[0]..w[1]], v))
		.collect::<Vec<_>>();

	// println!("as nibbles: {:#x?}", input);
	let mut stream = S::new();
	build_trie::<H, S, _, _>(&input, 0, &mut stream);
	stream.out()
}

/// Generates a key-hashed (secure) trie root hash for a vector of key-value tuples.
///
/// ```rust
/// #[macro_use] extern crate hex_literal;
/// extern crate trie_root;
/// extern crate keccak_hasher;
/// extern crate reference_trie;
/// use trie_root::sec_trie_root;
/// use keccak_hasher::KeccakHasher;
/// use reference_trie::ReferenceTrieStream;
///
/// fn main() {
/// 	let v = vec![
/// 		("doe", "reindeer"),
/// 		("dog", "puppy"),
/// 		("dogglesworth", "cat"),
/// 	];
///
/// 	let root = hex!["d6e02b2bd48aa04fd2ad87cfac1144a29ca7f7dc60f4526c7b7040763abe3d43"];
/// 	assert_eq!(sec_trie_root::<KeccakHasher, ReferenceTrieStream, _, _, _>(v), root);
/// }
/// ```
pub fn sec_trie_root<H, S, I, A, B>(input: I) -> H::Out where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]>,
	B: AsRef<[u8]>,
	H: Hasher,
	H::Out: Ord,
	S: TrieStream,
{
	trie_root::<H, S, _, _, _>(input.into_iter().map(|(k, v)| (H::hash(k.as_ref()), v)))
}

/// Takes a slice of key/value tuples where the key is a slice of nibbles
/// and encodes it into the provided `Stream`.
// pub fn build_trie<H, S, A, B>(input: &[(A, B)], cursor: usize, stream: &mut S)
fn build_trie<H, S, A, B>(input: &[(A, B)], cursor: usize, stream: &mut S) where
	A: AsRef<[u8]>,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	match input.len() {
		// No input, just append empty data.
		0 => {
			// println!("[build_trie] no input; appending empty, cursor={}, stream={:?}", cursor, stream.as_raw());
			stream.append_empty_data()
		},
		// Leaf node; append the remainder of the key and the value. Done.
		1 => {
			// println!("[build_trie] appending leaf, cursor={}, stream={:?}, partial key={:?}", cursor, stream.as_raw(), &input[0].0.as_ref()[cursor..]);
			// stream.append_leaf::<H>(&input[0].0.as_ref()[cursor..], &input[0].1.as_ref() )
			stream.append_leaf(&input[0].0.as_ref()[cursor..], &input[0].1.as_ref() )
		},
		// We have multiple items in the input. We need to figure out if we
		// should add an extension node or a branch node.
		_ => {
			let (key, value) = (&input[0].0.as_ref(), input[0].1.as_ref());
			// Count the number of nibbles in the other elements that are
			// shared with the first key.
			// e.g. input = [ [1'7'3'10'12'13], [1'7'3'], [1'7'7'8'9'] ] => [1'7'] is common => 2
			let shared_nibble_count = input.iter().skip(1).fold(key.len(), |acc, &(ref k, _)| {
				cmp::min( shared_prefix_len(key, k.as_ref()), acc )
			});
			// Add an extension node if the number of shared nibbles is greater
			// than what we saw on the last call (`cursor`): append the new part
			// of the path then recursively append the remainder of all items
			// who had this partial key.
			if shared_nibble_count > cursor {
				// println!("[build_trie] appending ext and recursing, cursor={}, stream={:?}, partial key={:?}", cursor, stream.as_raw(), &key[cursor..shared_nibble_count]);
				stream.append_extension(&key[cursor..shared_nibble_count]);
				build_trie_trampoline::<H, _, _, _>(input, shared_nibble_count, stream);
				// println!("[build_trie] returning after recursing, cursor={}, stream={:?}, partial key={:?}", cursor, stream.as_raw(), &key[cursor..shared_nibble_count]);
				return;
			}

			// We'll be adding a branch node because the path is as long as it gets.
			// First we need to figure out what entries this branch node will have...

			// We have a a value for exactly this key. Branch node will have a value
			// attached to it.
			let value = if cursor == key.len() { Some(value) } else { None };

			// We need to know how many keys each of the children account for.
			let mut shared_nibble_counts = [0usize; 16];
			{
				// Children keys begin at either index 1 or 0, depending on whether we have a value.
				let mut begin = match value { None => 0, _ => 1 };
				for i in 0..16 {
					shared_nibble_counts[i] = input[begin..].iter()
						.take_while(|(k, _)| k.as_ref()[cursor] == i as u8)
						.count();
					begin += shared_nibble_counts[i];
				}
			}

			// Put out the node header:
			stream.begin_branch(value, shared_nibble_counts.iter().map(|&n| n > 0));

			// Fill in each slot in the branch node. We don't need to bother with empty slots since they
			// were registered in the header.
			let mut begin = match value { None => 0, _ => 1 };
			for &count in &shared_nibble_counts {
				if count > 0 {
					// println!("[build_trie] branch slot {}; recursing with cursor={}, begin={}, shared nibbles={}, input={:?}", i, cursor, begin, shared_nibble_count, &input[begin..(begin + shared_nibble_count)]);
					build_trie_trampoline::<H, S, _, _>(&input[begin..(begin + count)], cursor + 1, stream);
					begin += count;
				} else {
					stream.append_empty_child();
				}
			}

			// println!("[build_trie] branch slot 17; cursor={}, appending value {:?}", cursor, value);
			stream.end_branch(value);

			// println!("[build_trie] ending branch node, cursor={}, stream={:?}", cursor, stream.as_raw());
		}
	}
}

fn build_trie_trampoline<H, S, A, B>(input: &[(A, B)], cursor: usize, stream: &mut S) where
	A: AsRef<[u8]>,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	let mut substream = S::new();
	build_trie::<H, _, _, _>(input, cursor, &mut substream);
	stream.append_substream::<H>(substream);
}

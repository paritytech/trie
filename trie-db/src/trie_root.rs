// Copyright 2017, 2020 Parity Technologies
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

use crate::{
	node_db::Hasher,
	rstd::{cmp, vec::Vec, BTreeMap},
};

/// Different possible value to use for node encoding.
#[derive(Clone)]
pub enum Value<'a> {
	/// Contains a full value.
	Inline(&'a [u8]),
	/// Contains hash of a value.
	Node(Vec<u8>),
}

impl<'a> Value<'a> {
	fn new<H: Hasher>(value: &'a [u8], threshold: Option<u32>) -> Value<'a> {
		if let Some(threshold) = threshold {
			if value.len() >= threshold as usize {
				Value::Node(H::hash(value).as_ref().to_vec())
			} else {
				Value::Inline(value)
			}
		} else {
			Value::Inline(value)
		}
	}
}

/// Byte-stream oriented trait for constructing closed-form tries.
pub trait TrieStream {
	/// Construct a new `TrieStream`
	fn new() -> Self;
	/// Append an Empty node
	fn append_empty_data(&mut self);
	/// Start a new Branch node, possibly with a value; takes a list indicating
	/// which slots in the Branch node has further child nodes.
	fn begin_branch(
		&mut self,
		maybe_key: Option<&[u8]>,
		maybe_value: Option<Value>,
		has_children: impl Iterator<Item = bool>,
	);
	/// Append an empty child node. Optional.
	fn append_empty_child(&mut self) {}
	/// Wrap up a Branch node portion of a `TrieStream` and append the value
	/// stored on the Branch (if any).
	fn end_branch(&mut self, _value: Option<Value>) {}
	/// Append a Leaf node
	fn append_leaf(&mut self, key: &[u8], value: Value);
	/// Append an Extension node
	fn append_extension(&mut self, key: &[u8]);
	/// Append a Branch of Extension substream
	fn append_substream<H: Hasher>(&mut self, other: Self);
	/// Return the finished `TrieStream` as a vector of bytes.
	fn out(self) -> Vec<u8>;
}

fn shared_prefix_length<T: Eq>(first: &[T], second: &[T]) -> usize {
	first
		.iter()
		.zip(second.iter())
		.position(|(f, s)| f != s)
		.unwrap_or_else(|| cmp::min(first.len(), second.len()))
}

/// Generates a trie root hash for a vector of key-value tuples
///
/// ```ignore
/// use hex_literal::hex;
/// use trie_root::trie_root;
/// use reference_trie::ReferenceTrieStream;
/// use keccak_hasher::KeccakHasher;
///
/// let v = vec![
///     ("doe", "reindeer"),
///     ("dog", "puppy"),
///     ("dogglesworth", "cat"),
/// ];
///
/// let root = hex!["0807d5393ae7f349481063ebb5dbaf6bda58db282a385ca97f37dccba717cb79"];
/// assert_eq!(trie_root::<KeccakHasher, ReferenceTrieStream, _, _, _>(v), root);
/// ```
pub fn trie_root<H, S, I, A, B>(input: I, threshold: Option<u32>) -> H::Out
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	trie_root_inner::<H, S, I, A, B>(input, false, threshold)
}

fn trie_root_inner<H, S, I, A, B>(input: I, no_extension: bool, threshold: Option<u32>) -> H::Out
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	// first put elements into btree to sort them and to remove duplicates
	let input = input.into_iter().collect::<BTreeMap<_, _>>();

	// convert to nibbles
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
	let input = input
		.into_iter()
		.zip(lens.windows(2))
		.map(|((_, v), w)| (&nibbles[w[0]..w[1]], v))
		.collect::<Vec<_>>();

	let mut stream = S::new();
	build_trie::<H, S, _, _>(&input, 0, &mut stream, no_extension, threshold);
	H::hash(&stream.out())
}

/// Variant of `trie_root` for patricia trie without extension node.
/// See [`trie_root`].
pub fn trie_root_no_extension<H, S, I, A, B>(input: I, threshold: Option<u32>) -> H::Out
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	trie_root_inner::<H, S, I, A, B>(input, true, threshold)
}

//#[cfg(test)]	// consider feature="std"
/// Method similar to `trie_root` but returning the root encoded
/// node instead of its hash.
/// Mainly use for testing or debugging.
pub fn unhashed_trie<H, S, I, A, B>(input: I, threshold: Option<u32>) -> Vec<u8>
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	unhashed_trie_inner::<H, S, I, A, B>(input, false, threshold)
}

fn unhashed_trie_inner<H, S, I, A, B>(
	input: I,
	no_extension: bool,
	threshold: Option<u32>,
) -> Vec<u8>
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	// first put elements into btree to sort them and to remove duplicates
	let input = input.into_iter().collect::<BTreeMap<_, _>>();

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
	let input = input
		.into_iter()
		.zip(lens.windows(2))
		.map(|((_, v), w)| (&nibbles[w[0]..w[1]], v))
		.collect::<Vec<_>>();

	let mut stream = S::new();
	build_trie::<H, S, _, _>(&input, 0, &mut stream, no_extension, threshold);
	stream.out()
}

/// Variant of `unhashed_trie` for patricia trie without extension node.
/// See [`unhashed_trie`].
pub fn unhashed_trie_no_extension<H, S, I, A, B>(input: I, threshold: Option<u32>) -> Vec<u8>
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]> + Ord,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	unhashed_trie_inner::<H, S, I, A, B>(input, true, threshold)
}

/// Generates a key-hashed (secure) trie root hash for a vector of key-value tuples.
///
/// ```ignore
/// use hex_literal::hex;
/// use trie_root::sec_trie_root;
/// use keccak_hasher::KeccakHasher;
/// use reference_trie::ReferenceTrieStream;
///
/// let v = vec![
/// 	("doe", "reindeer"),
/// 	("dog", "puppy"),
/// 	("dogglesworth", "cat"),
/// ];
///
/// let root = hex!["d6e02b2bd48aa04fd2ad87cfac1144a29ca7f7dc60f4526c7b7040763abe3d43"];
/// assert_eq!(sec_trie_root::<KeccakHasher, ReferenceTrieStream, _, _, _>(v), root);
/// ```
pub fn sec_trie_root<H, S, I, A, B>(input: I, threshold: Option<u32>) -> H::Out
where
	I: IntoIterator<Item = (A, B)>,
	A: AsRef<[u8]>,
	B: AsRef<[u8]>,
	H: Hasher,
	H::Out: Ord,
	S: TrieStream,
{
	trie_root::<H, S, _, _, _>(input.into_iter().map(|(k, v)| (H::hash(k.as_ref()), v)), threshold)
}

/// Takes a slice of key/value tuples where the key is a slice of nibbles
/// and encodes it into the provided `Stream`.
fn build_trie<H, S, A, B>(
	input: &[(A, B)],
	cursor: usize,
	stream: &mut S,
	no_extension: bool,
	threshold: Option<u32>,
) where
	A: AsRef<[u8]>,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	match input.len() {
		// No input, just append empty data.
		0 => stream.append_empty_data(),
		// Leaf node; append the remainder of the key and the value. Done.
		1 => {
			let value = Value::new::<H>(input[0].1.as_ref(), threshold);
			stream.append_leaf(&input[0].0.as_ref()[cursor..], value)
		},
		// We have multiple items in the input. Figure out if we should add an
		// extension node or a branch node.
		_ => {
			let (key, value) = (&input[0].0.as_ref(), input[0].1.as_ref());
			// Count the number of nibbles in the other elements that are
			// shared with the first key.
			// e.g. input = [ [1'7'3'10'12'13], [1'7'3'], [1'7'7'8'9'] ] => [1'7'] is common => 2
			let shared_nibble_count = input.iter().skip(1).fold(key.len(), |acc, &(ref k, _)| {
				cmp::min(shared_prefix_length(key, k.as_ref()), acc)
			});
			// Add an extension node if the number of shared nibbles is greater
			// than what we saw on the last call (`cursor`): append the new part
			// of the path then recursively append the remainder of all items
			// who had this partial key.
			let (cursor, o_branch_slice) = if no_extension {
				if shared_nibble_count > cursor {
					(shared_nibble_count, Some(&key[cursor..shared_nibble_count]))
				} else {
					(cursor, Some(&key[0..0]))
				}
			} else if shared_nibble_count > cursor {
				stream.append_extension(&key[cursor..shared_nibble_count]);
				build_trie_trampoline::<H, _, _, _>(
					input,
					shared_nibble_count,
					stream,
					no_extension,
					threshold,
				);
				return
			} else {
				(cursor, None)
			};

			// We'll be adding a branch node because the path is as long as it gets.
			// First we need to figure out what entries this branch node will have...

			// We have a a value for exactly this key. Branch node will have a value
			// attached to it.
			let value = if cursor == key.len() { Some(value) } else { None };

			// We need to know how many key nibbles each of the children account for.
			let mut shared_nibble_counts = [0usize; 16];
			{
				// If the Branch node has a value then the first of the input keys
				// is exactly the key for that value and we don't care about it
				// when finding shared nibbles for our child nodes. (We know it's
				// the first of the input keys, because the input is sorted)
				let mut begin = match value {
					None => 0,
					_ => 1,
				};
				for i in 0..16 {
					shared_nibble_counts[i] = input[begin..]
						.iter()
						.take_while(|(k, _)| k.as_ref()[cursor] == i as u8)
						.count();
					begin += shared_nibble_counts[i];
				}
			}

			// Put out the node header:
			let value = value.map(|v| Value::new::<H>(v, threshold));
			stream.begin_branch(
				o_branch_slice,
				value.clone(),
				shared_nibble_counts.iter().map(|&n| n > 0),
			);

			// Fill in each slot in the branch node. We don't need to bother with empty slots
			// since they were registered in the header.
			let mut begin = match value {
				None => 0,
				_ => 1,
			};
			for &count in &shared_nibble_counts {
				if count > 0 {
					build_trie_trampoline::<H, S, _, _>(
						&input[begin..(begin + count)],
						cursor + 1,
						stream,
						no_extension,
						threshold.clone(),
					);
					begin += count;
				} else {
					stream.append_empty_child();
				}
			}

			stream.end_branch(value);
		},
	}
}

fn build_trie_trampoline<H, S, A, B>(
	input: &[(A, B)],
	cursor: usize,
	stream: &mut S,
	no_extension: bool,
	threshold: Option<u32>,
) where
	A: AsRef<[u8]>,
	B: AsRef<[u8]>,
	H: Hasher,
	S: TrieStream,
{
	let mut substream = S::new();
	build_trie::<H, _, _, _>(input, cursor, &mut substream, no_extension, threshold);
	stream.append_substream::<H>(substream);
}

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

use hash_db::Hasher;
use node::Node;
use nibble::NibbleOps;
use ChildReference;
#[cfg(feature = "std")]
use std::borrow::Borrow;

#[cfg(not(feature = "std"))]
use core::borrow::Borrow;

#[cfg(feature = "std")]
use std::error::Error;


#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(not(feature = "std"))]
pub trait Error {}

#[cfg(not(feature = "std"))]
impl<T> Error for T {}

/// Immutable representation of a nible slice (right aligned).
/// It contains a right aligned padded first byte (first pair element is the number of nibbles
/// (0 to max nb nibble - 1), second pair element is the padded nibble), and a slice over
/// the remaining bytes.
pub type Partial<'a> = ((u8,u8), &'a[u8]);

/// Trait for trie node encoding/decoding
/// TODO add const MAX_NODE_LEN and run all encoding over a mutable buffer, returning size. ->
/// avoid Vec by all means.
pub trait NodeCodec<H: Hasher, N: NibbleOps>: Sized {
	/// Codec error type
	type Error: Error;

	/// Get the hashed null node.
	fn hashed_null_node() -> H::Out;

	/// Decode bytes to a `Node`. Returns `Self::E` on failure.
	fn decode(data: &[u8]) -> Result<Node<N>, Self::Error>;

	/// Decode bytes to the `Hasher`s output type. Returns `None` on failure.
	fn try_decode_hash(data: &[u8]) -> Option<H::Out>;

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
	fn ext_node(
    partial: impl Iterator<Item = u8>,
    number_nibble: usize,
    child_ref: ChildReference<H::Out>,
  ) -> Vec<u8>;

	/// Returns an encoded branch node.
  /// Takes an iterator yielding `ChildReference<H::Out>` and an optional value.
	fn branch_node(
    children: impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>,
    value: Option<&[u8]>,
  ) -> Vec<u8>;

	/// Returns an encoded branch node with a possible partial path.
  /// `number_nibble` is the partial path lenghth as in `ext_node`.
	fn branch_node_nibbled(
    partial: impl Iterator<Item = u8>,
    number_nibble: usize,
    children: impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>,
    value: Option<&[u8]>
  ) -> Vec<u8>;
}

/// Bitmap encoder for the number of children nodes.
/// This would be useless with https://github.com/rust-lang/rust/issues/43408.
pub trait BitMap: Sized {
	/// length to encode the bitmap
	const ENCODED_LEN: usize;
	/// Codec error type.
	type Error: Error;

	/// Codec buffer to use.	
	type Buffer: AsRef<[u8]> + AsMut<[u8]> + Default;

	/// decode bitmap
	fn decode(data: &[u8]) -> Result<Self, Self::Error>;

	/// got values
	fn value_at(&self, i: usize) -> bool;

	/// encode to dest of right len
	fn encode<I: Iterator<Item = bool>>(has_children: I , dest: &mut [u8]);
}

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

//! Generic trait for trie node encoding/decoding. Takes a `hashdb::Hasher`
//! to parametrize the hashes used in the codec.

use hashdb::Hasher;
use node::Node;
use ChildReference;

use elastic_array::{ElasticArray128};

/// Trait for trie node encoding/decoding
pub trait NodeCodec<H: Hasher>: Sized {
	/// Codec error type
	type Error: ::std::error::Error;

	/// Get the hashed null node.
	fn hashed_null_node() -> H::Out;

	/// Decode bytes to a `Node`. Returns `Self::E` on failure.
	fn decode(data: &[u8]) -> Result<Node, Self::Error>;

	/// Decode bytes to the `Hasher`s output type.  Returns `None` on failure.
	fn try_decode_hash(data: &[u8]) -> Option<H::Out>;

	/// Check if the provided bytes correspond to the codecs "empty" node.
	fn is_empty_node(data: &[u8]) -> bool;

	/// Returns an empty node
	fn empty_node() -> Vec<u8>;

	/// Returns an encoded leaf node
	fn leaf_node(partial: &[u8], value: &[u8]) -> Vec<u8>;

	/// Returns an encoded extension node
	fn ext_node(partial: &[u8], child_ref: ChildReference<H::Out>) -> Vec<u8>;

	/// Returns an encoded branch node. Takes an iterator yielding `ChildReference<H::Out>` and an optional value
	fn branch_node<I>(children: I, value: Option<ElasticArray128<u8>>) -> Vec<u8>
	where I: IntoIterator<Item=Option<ChildReference<H::Out>>> + Iterator<Item=Option<ChildReference<H::Out>>>;
}

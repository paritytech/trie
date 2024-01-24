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

//! Database of byte-slices keyed to their hash.

use crate::rstd::{hash, vec::Vec};

#[cfg(feature = "std")]
use std::fmt::Debug;

#[cfg(feature = "std")]
pub trait MaybeDebug: Debug {}
#[cfg(feature = "std")]
impl<T: Debug> MaybeDebug for T {}
#[cfg(not(feature = "std"))]
pub trait MaybeDebug {}
#[cfg(not(feature = "std"))]
impl<T> MaybeDebug for T {}

/// A trie node prefix, it is the nibble path from the trie root
/// to the trie node.
/// For a node containing no partial key value it is the full key.
/// For a value node or node containing a partial key, it is the full key minus its node partial
/// nibbles (the node key can be split into prefix and node partial).
/// Therefore it is always the leftmost portion of the node key, so its internal representation
/// is a non expanded byte slice followed by a last padded byte representation.
/// The padded byte is an optional padded value.
pub type Prefix<'a> = (&'a [u8], Option<u8>);

/// An empty prefix constant.
/// Can be use when the prefix is not use internally
/// or for root nodes.
pub static EMPTY_PREFIX: Prefix<'static> = (&[], None);

/// Trait describing an object that can hash a slice of bytes. Used to abstract
/// other types over the hashing algorithm. Defines a single `hash` method and an
/// `Out` associated type with the necessary bounds.
pub trait Hasher: Sync + Send {
	/// The output type of the `Hasher`
	type Out: AsRef<[u8]>
		+ AsMut<[u8]>
		+ Default
		+ MaybeDebug
		+ core::cmp::Ord
		+ PartialEq
		+ Eq
		+ hash::Hash
		+ Send
		+ Sync
		+ Clone
		+ Copy;
	/// What to use to build `HashMap`s with this `Hasher`.
	type StdHasher: Sync + Send + Default + hash::Hasher;
	/// The length in bytes of the `Hasher` output.
	const LENGTH: usize;

	/// Compute the hash of the provided slice of bytes returning the `Out` type of the `Hasher`.
	fn hash(x: &[u8]) -> Self::Out;
}

/// Trait modelling datastore keyed by a hash defined by the `Hasher` and optional location tag.
pub trait NodeDB<H: Hasher, T, L>: Send + Sync {
	/// Look up a trie node by hash and location.
	/// Returns the node bytes and the list of children node locations if any.
	fn get(&self, key: &H::Out, prefix: Prefix, location: L) -> Option<(T, Vec<L>)>;

	/// Check for the existence of a hash-key at the location.
	fn contains(&self, key: &H::Out, prefix: Prefix, location: L) -> bool {
		self.get(key, prefix, location).is_some()
	}

	/// Compute value hash.
	fn hash(&self, value: &[u8]) -> H::Out {
		H::hash(value)
	}
}

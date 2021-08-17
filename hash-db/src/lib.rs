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

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
use std::fmt::Debug;
#[cfg(feature = "std")]
use std::hash;
#[cfg(not(feature = "std"))]
use core::hash;
#[cfg(not(feature = "std"))]
use alloc::{vec, vec::Vec};

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
pub type Prefix<'a> = (&'a[u8], Option<u8>);

/// An empty prefix constant.
/// Can be use when the prefix is not use internally
/// or for root nodes.
pub static EMPTY_PREFIX: Prefix<'static> = (&[], None);

/// Trait describing an object that can hash a slice of bytes. Used to abstract
/// other types over the hashing algorithm. Defines a single `hash` method and an
/// `Out` associated type with the necessary bounds.
pub trait Hasher: Sync + Send {
	/// The output type of the `Hasher`
	type Out: AsRef<[u8]> + AsMut<[u8]> + Default + MaybeDebug + PartialEq + Eq
		+ hash::Hash + Send + Sync + Clone + Copy;
	/// What to use to build `HashMap`s with this `Hasher`.
	type StdHasher: Sync + Send + Default + hash::Hasher;
	/// The length in bytes of the `Hasher` output.
	const LENGTH: usize;

	/// Compute the hash of the provided slice of bytes returning the `Out` type of the `Hasher`.
	fn hash(x: &[u8]) -> Self::Out;
}

/// Trait modelling a plain datastore whose key is a fixed type.
/// The caller should ensure that a key only corresponds to
/// one value.
pub trait PlainDB<K, V>: Send + Sync + AsPlainDB<K, V> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &K) -> Option<V>;

	/// Check for the existence of a hash-key.
	fn contains(&self, key: &K) -> bool;

	/// Insert a datum item into the DB. Insertions are counted and the equivalent
	/// number of `remove()`s must be performed before the data is considered dead.
	/// The caller should ensure that a key only corresponds to one value.
	fn emplace(&mut self, key: K, value: V);

	/// Remove a datum previously inserted. Insertions can be "owed" such that the
	/// same number of `insert()`s may happen without the data being eventually
	/// being inserted into the DB. It can be "owed" more than once.
	/// The caller should ensure that a key only corresponds to one value.
	fn remove(&mut self, key: &K);
}

/// Trait for immutable reference of PlainDB.
pub trait PlainDBRef<K, V> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &K) -> Option<V>;

	/// Check for the existance of a hash-key.
	fn contains(&self, key: &K) -> bool;
}

impl<'a, K, V> PlainDBRef<K, V> for &'a dyn PlainDB<K, V> {
	fn get(&self, key: &K) -> Option<V> { PlainDB::get(*self, key) }
	fn contains(&self, key: &K) -> bool { PlainDB::contains(*self, key) }
}

impl<'a, K, V> PlainDBRef<K, V> for &'a mut dyn PlainDB<K, V> {
	fn get(&self, key: &K) -> Option<V> { PlainDB::get(*self, key) }
	fn contains(&self, key: &K) -> bool { PlainDB::contains(*self, key) }
}

/// Trait modelling datastore keyed by a hash defined by the `Hasher`.
pub trait HashDB<H: Hasher, T>: Send + Sync + AsHashDB<H, T> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T>;

	/// Access additional content or indicates additional content being accessed.
	///
	/// When `at` is `None`, no reply is expected, acts as a callback on content access
	/// (eg access to a trie node value).
	///
	/// When `at` is `Some`, we also try to fetch additional content (eg if value
	/// of a trie node is stored externally for performance purpose).
	fn access_from(&self, _key: &H::Out, _at: Option<&H::Out>) -> Option<T> {
		None
	}

	/// Check for the existence of a hash-key.
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool;

	/// Insert a datum item into the DB and return the datum's hash for a later lookup. Insertions
	/// are counted and the equivalent number of `remove()`s must be performed before the data
	/// is considered dead.
	fn insert(&mut self, prefix: Prefix, value: &[u8]) -> H::Out;

	/// Like `insert()`, except you provide the key and the data is all moved.
	fn emplace(&mut self, key: H::Out, prefix: Prefix, value: T);

	/// `emplace` variant using reference to data.
	fn emplace_ref(&mut self, key: &H::Out, prefix: Prefix, value: &[u8]);

	/// Remove a datum previously inserted. Insertions can be "owed" such that the same number of
	/// `insert()`s may happen without the data being eventually being inserted into the DB.
	/// It can be "owed" more than once.
	fn remove(&mut self, key: &H::Out, prefix: Prefix);

	/// Insert with alternate hashing info.
	///
	/// This operation allows different hashing scheme.
	/// Currently `AltHashing` allows inner hashing of a range
	/// of byte (eg to exclude some values from a trie node proof when unaccessed).
	fn alt_insert(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		alt_hashing: AltHashing,
	) -> H::Out {
		if !alt_hashing.is_active() {
			return self.insert(prefix, value);
		}
		let key = alt_hashing.alt_hash::<H>(value);
		self.emplace_ref(&key, prefix, value);
		key
	}
}

/// Define how alternate hashing should be applied by the hash db.
#[derive(Default, Clone, Debug)]
pub struct AltHashing {
	/// Allow skipping first bytes when hashing.
	/// First bytes are then not part of trie state and do
	/// not modify trie root. First bytes can contain additional
	/// metadata.
	/// (eg indicate that a trie node in proof does not contains
	/// a value but its hash).
	pub encoded_offset: usize,

	/// Indicate a specific range of bytes, that could be used to apply
	/// some alternate hashing.
	/// Named `value_range` because first use case is with trie node
	/// where there value is hashed a first time internally.
	///
	/// This range is defined with offseted content included.
	pub value_range: Option<(usize, usize)>,
}

impl AltHashing {
	fn is_active(&self) -> bool {
		self.encoded_offset > 0 || self.value_range.is_some()
	}

	/// Apply hash with alternate hashing scheme.
	pub fn alt_hash<H: Hasher>(&self, value: &[u8]) -> H::Out {
		if !self.is_active() {
			return H::hash(value);
		}
		let hash_value = &value[self.encoded_offset..];
		if self.value_range.is_some() {
			let hash_value = alt_hashed_value::<H>(value, self.value_range);
			H::hash(hash_value.as_slice())
		} else {
			H::hash(hash_value)
		}

	}
}

/// Representation of hash db value before final hashing.
/// eg for a trie node with inner hashing of value, this is the encoded node with
/// value replaced by its hash.
pub fn alt_hashed_value<H: Hasher>(x: &[u8], range: Option<(usize, usize)>) -> Vec<u8> {
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

/// Trait for immutable reference of HashDB.
pub trait HashDBRef<H: Hasher, T> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T>;

	/// Callback for content access.
	fn access_from(&self, _key: &H::Out, _at: Option<&H::Out>) -> Option<T>;

	/// Check for the existance of a hash-key.
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool;
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a dyn HashDB<H, T> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> { HashDB::get(*self, key, prefix) }
	fn access_from(&self, key: &H::Out, at: Option<&H::Out>) -> Option<T> {
		HashDB::access_from(*self, key, at)
	}
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		HashDB::contains(*self, key, prefix)
	}
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a mut dyn HashDB<H, T> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> { HashDB::get(*self, key, prefix) }
	fn access_from(&self, key: &H::Out, at: Option<&H::Out>) -> Option<T> {
		HashDB::access_from(*self, key, at)
	}
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		HashDB::contains(*self, key, prefix)
	}
}

/// Upcast trait for HashDB.
pub trait AsHashDB<H: Hasher, T> {
	/// Perform upcast to HashDB for anything that derives from HashDB.
	fn as_hash_db(&self) -> &dyn HashDB<H, T>;
	/// Perform mutable upcast to HashDB for anything that derives from HashDB.
	fn as_hash_db_mut<'a>(&'a mut self) -> &'a mut (dyn HashDB<H, T> + 'a);
}

/// Upcast trait for PlainDB.
pub trait AsPlainDB<K, V> {
	/// Perform upcast to PlainDB for anything that derives from PlainDB.
	fn as_plain_db(&self) -> &dyn PlainDB<K, V>;
	/// Perform mutable upcast to PlainDB for anything that derives from PlainDB.
	fn as_plain_db_mut<'a>(&'a mut self) -> &'a mut (dyn PlainDB<K, V> + 'a);
}

// NOTE: There used to be a `impl<T> AsHashDB for T` but that does not work with generics.
// See https://stackoverflow.com/questions/48432842/
// implementing-a-trait-for-reference-and-non-reference-types-causes-conflicting-im
// This means we need concrete impls of AsHashDB in several places, which somewhat defeats
// the point of the trait.
impl<'a, H: Hasher, T> AsHashDB<H, T> for &'a mut dyn HashDB<H, T> {
	fn as_hash_db(&self) -> &dyn HashDB<H, T> { &**self }
	fn as_hash_db_mut<'b>(&'b mut self) -> &'b mut (dyn HashDB<H, T> + 'b) { &mut **self }
}

#[cfg(feature = "std")]
impl<'a, K, V> AsPlainDB<K, V> for &'a mut dyn PlainDB<K, V> {
	fn as_plain_db(&self) -> &dyn PlainDB<K, V> { &**self }
	fn as_plain_db_mut<'b>(&'b mut self) -> &'b mut (dyn PlainDB<K, V> + 'b) { &mut **self }
}

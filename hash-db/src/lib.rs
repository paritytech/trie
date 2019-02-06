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

//! Database of byte-slices keyed to their hash.

#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(core_intrinsics))]

#[cfg(feature = "std")]
use std::fmt::Debug;
#[cfg(feature = "std")]
use std::collections::HashMap;
#[cfg(feature = "std")]
use std::hash;
#[cfg(feature = "std")]
pub trait DebugIfStd: Debug {}
#[cfg(feature = "std")]
impl<T: Debug> DebugIfStd for T {}

#[cfg(not(feature = "std"))]
use core::hash;
#[cfg(not(feature = "std"))]
pub trait DebugIfStd {}
#[cfg(not(feature = "std"))]
impl<T> DebugIfStd for T {}

/// Trait describing an object that can hash a slice of bytes. Used to abstract
/// other types over the hashing algorithm. Defines a single `hash` method and an
/// `Out` associated type with the necessary bounds.
pub trait Hasher: Sync + Send {
	/// The output type of the `Hasher`
	type Out: AsRef<[u8]> + AsMut<[u8]> + Default + DebugIfStd + PartialEq + Eq + hash::Hash + Send + Sync + Clone + Copy;
	/// What to use to build `HashMap`s with this `Hasher`
	type StdHasher: Sync + Send + Default + hash::Hasher;
	/// The length in bytes of the `Hasher` output
	const LENGTH: usize;

	/// Compute the hash of the provided slice of bytes returning the `Out` type of the `Hasher`
	fn hash(x: &[u8]) -> Self::Out;
}

/// Trait modelling a plain datastore whose key is a fixed type.
/// The caller should ensure that a key only corresponds to
/// one value.
#[cfg(feature = "std")]
pub trait PlainDB<K, V>: Send + Sync + AsPlainDB<K, V> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &K) -> Option<V>;

	/// Check for the existance of a hash-key.
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
#[cfg(feature = "std")]
pub trait PlainDBRef<K, V> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &K) -> Option<V>;

	/// Check for the existance of a hash-key.
	fn contains(&self, key: &K) -> bool;
}

#[cfg(feature = "std")]
impl<'a, K, V> PlainDBRef<K, V> for &'a PlainDB<K, V> {
	fn get(&self, key: &K) -> Option<V> { PlainDB::get(*self, key) }
	fn contains(&self, key: &K) -> bool { PlainDB::contains(*self, key) }
}

#[cfg(feature = "std")]
impl<'a, K, V> PlainDBRef<K, V> for &'a mut PlainDB<K, V> {
	fn get(&self, key: &K) -> Option<V> { PlainDB::get(*self, key) }
	fn contains(&self, key: &K) -> bool { PlainDB::contains(*self, key) }
}

/// Trait modelling datastore keyed by a hash defined by the `Hasher`.
#[cfg(feature = "std")]
pub trait HashDB<H: Hasher, T>: Send + Sync + AsHashDB<H, T> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &H::Out) -> Option<T>;

	/// Check for the existance of a hash-key.
	fn contains(&self, key: &H::Out) -> bool;

	/// Insert a datum item into the DB and return the datum's hash for a later lookup. Insertions
	/// are counted and the equivalent number of `remove()`s must be performed before the data
	/// is considered dead.
	fn insert(&mut self, value: &[u8]) -> H::Out;

	/// Like `insert()`, except you provide the key and the data is all moved.
	fn emplace(&mut self, key: H::Out, value: T);

	/// Remove a datum previously inserted. Insertions can be "owed" such that the same number of `insert()`s may
	/// happen without the data being eventually being inserted into the DB. It can be "owed" more than once.
	fn remove(&mut self, key: &H::Out);
}

/// Trait for immutable reference of HashDB.
#[cfg(feature = "std")]
pub trait HashDBRef<H: Hasher, T> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &H::Out) -> Option<T>;

	/// Check for the existance of a hash-key.
	fn contains(&self, key: &H::Out) -> bool;
}

#[cfg(feature = "std")]
impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a HashDB<H, T> {
	fn get(&self, key: &H::Out) -> Option<T> { HashDB::get(*self, key) }
	fn contains(&self, key: &H::Out) -> bool { HashDB::contains(*self, key) }
}

#[cfg(feature = "std")]
impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a mut HashDB<H, T> {
	fn get(&self, key: &H::Out) -> Option<T> { HashDB::get(*self, key) }
	fn contains(&self, key: &H::Out) -> bool { HashDB::contains(*self, key) }
}

/// Upcast trait for HashDB.
#[cfg(feature = "std")]
pub trait AsHashDB<H: Hasher, T> {
	/// Perform upcast to HashDB for anything that derives from HashDB.
	fn as_hash_db(&self) -> &HashDB<H, T>;
	/// Perform mutable upcast to HashDB for anything that derives from HashDB.
	fn as_hash_db_mut<'a>(&'a mut self) -> &'a mut (HashDB<H, T> + 'a);
}

/// Upcast trait for PlainDB.
#[cfg(feature = "std")]
pub trait AsPlainDB<K, V> {
	/// Perform upcast to PlainDB for anything that derives from PlainDB.
	fn as_plain_db(&self) -> &PlainDB<K, V>;
	/// Perform mutable upcast to PlainDB for anything that derives from PlainDB.
	fn as_plain_db_mut<'a>(&'a mut self) -> &'a mut (PlainDB<K, V> + 'a);
}

// NOTE: There used to be a `impl<T> AsHashDB for T` but that does not work with generics. See https://stackoverflow.com/questions/48432842/implementing-a-trait-for-reference-and-non-reference-types-causes-conflicting-im
// This means we need concrete impls of AsHashDB in several places, which somewhat defeats the point of the trait.
#[cfg(feature = "std")]
impl<'a, H: Hasher, T> AsHashDB<H, T> for &'a mut HashDB<H, T> {
	fn as_hash_db(&self) -> &HashDB<H, T> { &**self }
	fn as_hash_db_mut<'b>(&'b mut self) -> &'b mut (HashDB<H, T> + 'b) { &mut **self }
}

#[cfg(feature = "std")]
impl<'a, K, V> AsPlainDB<K, V> for &'a mut PlainDB<K, V> {
	fn as_plain_db(&self) -> &PlainDB<K, V> { &**self }
	fn as_plain_db_mut<'b>(&'b mut self) -> &'b mut (PlainDB<K, V> + 'b) { &mut **self }
}

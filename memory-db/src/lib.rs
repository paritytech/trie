// Copyright 2017-2020 Parity Technologies
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

//! Reference-counted memory-based `HashDB` implementation.

#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(not(feature = "std"))]
extern crate alloc;

mod malloc_size_of;
pub use malloc_size_of::*;

use hash_db::{HashDB, HashDBRef, PlainDB, PlainDBRef, Hasher as KeyHasher,
	AsHashDB, AsPlainDB, Prefix};
use parity_util_mem::{MallocSizeOf, MallocSizeOfOps, MallocShallowSizeOf};
#[cfg(feature = "deprecated")]
#[cfg(feature = "std")]
use heapsize::HeapSizeOf;
#[cfg(feature = "std")]
use std::{
	collections::hash_map::Entry,
	collections::HashMap,
	hash,
	mem,
	marker::PhantomData,
	cmp::Eq,
	borrow::Borrow,
};

#[cfg(not(feature = "std"))]
use hashbrown::{
	HashMap,
	hash_map::Entry,
};

#[cfg(not(feature = "std"))]
use core::{
	hash,
	mem,
	marker::PhantomData,
	cmp::Eq,
	borrow::Borrow,
};

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
pub trait MaybeDebug: std::fmt::Debug {}
#[cfg(feature = "std")]
impl<T: std::fmt::Debug> MaybeDebug for T {}
#[cfg(not(feature = "std"))]
pub trait MaybeDebug {}
#[cfg(not(feature = "std"))]
impl<T> MaybeDebug for T {}

/// The default memory tracker used by [`MemoryDB`].
#[cfg(feature = "std")]
pub type DefaultMemTracker<T> = MemCounter<T>;
/// The default memory tracker used by [`MemoryDB`].
#[cfg(not(feature = "std"))]
pub type DefaultMemTracker<T> = NoopTracker<T>;

/// Reference-counted memory-based `HashDB` implementation.
///
/// Use `new()` to create a new database. Insert items with `insert()`, remove items
/// with `remove()`, check for existence with `contains()` and lookup a hash to derive
/// the data with `get()`. Clear with `clear()` and purge the portions of the data
/// that have no references with `purge()`.
///
/// If you're not using the `MallocSizeOf` implementation to track memory usage,
/// set the `M` type parameter to `NoopTracker`.
///
/// # Example
/// ```rust
///   use hash_db::{Hasher, HashDB, EMPTY_PREFIX};
///   use keccak_hasher::KeccakHasher;
///   use memory_db::{MemoryDB, HashKey};
///
///   let mut m = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
///   let d = "Hello world!".as_bytes();
///
///   let k = m.insert(EMPTY_PREFIX, d);
///   assert!(m.contains(&k, EMPTY_PREFIX));
///   assert_eq!(m.get(&k, EMPTY_PREFIX).unwrap(), d);
///
///   m.insert(EMPTY_PREFIX, d);
///   assert!(m.contains(&k, EMPTY_PREFIX));
///
///   m.remove(&k, EMPTY_PREFIX);
///   assert!(m.contains(&k, EMPTY_PREFIX));
///
///   m.remove(&k, EMPTY_PREFIX);
///   assert!(!m.contains(&k, EMPTY_PREFIX));
///
///   m.remove(&k, EMPTY_PREFIX);
///   assert!(!m.contains(&k, EMPTY_PREFIX));
///
///   m.insert(EMPTY_PREFIX, d);
///   assert!(!m.contains(&k, EMPTY_PREFIX));

///   m.insert(EMPTY_PREFIX, d);
///   assert!(m.contains(&k, EMPTY_PREFIX));
///   assert_eq!(m.get(&k, EMPTY_PREFIX).unwrap(), d);
///
///   m.remove(&k, EMPTY_PREFIX);
///   assert!(!m.contains(&k, EMPTY_PREFIX));
/// ```
pub struct MemoryDB<H, KF, T, M = DefaultMemTracker<T>>
where
	H: KeyHasher,
	KF: KeyFunction<H>,
	M: MemTracker<T>,
{
	data: HashMap<KF::Key, (T, i32)>,
	// We cache `size_of(data) - shallow_size_of(data)` to compute
	// `size_of(data)` incrementally and avoid iterating over the `data`.
	malloc_tracker: M,
	hashed_null_node: H::Out,
	null_node_data: T,
	_kf: PhantomData<KF>,
}

impl<H, KF, T, M> Clone for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	KF: KeyFunction<H>,
	T: Clone,
	M: MemTracker<T> + Copy,
{
	fn clone(&self) -> Self {
		Self {
			data: self.data.clone(),
			hashed_null_node: self.hashed_null_node,
			null_node_data: self.null_node_data.clone(),
			malloc_tracker: self.malloc_tracker,
			_kf: Default::default(),
		}
	}
}

impl<H, KF, T, M> PartialEq<MemoryDB<H, KF, T, M>> for MemoryDB<H, KF, T, M>
	where
	H: KeyHasher,
	KF: KeyFunction<H>,
	<KF as KeyFunction<H>>::Key: Eq + MaybeDebug,
	T: Eq + MaybeDebug,
	M: MemTracker<T> + PartialEq,
{
	fn eq(&self, other: &MemoryDB<H, KF, T, M>) -> bool {
		for a in self.data.iter() {
			match other.data.get(&a.0) {
				Some(v) if v != a.1 => return false,
				None => return false,
				_ => (),
			}
		}
		true
	}
}

impl<H, KF, T, M> Eq for MemoryDB<H, KF, T, M>
	where
		H: KeyHasher,
		KF: KeyFunction<H>,
		<KF as KeyFunction<H>>::Key: Eq + MaybeDebug,
		T: Eq + MaybeDebug,
		M: MemTracker<T> + Eq,
{}

pub trait KeyFunction<H: KeyHasher> {
	type Key: Send + Sync + Clone + hash::Hash + Eq;

	fn key(hash: &H::Out, prefix: Prefix) -> Self::Key;
}

/// Key function that only uses the hash
pub struct HashKey<H>(PhantomData<H>);

impl<H> Clone for HashKey<H> {
	fn clone(&self) -> Self {
		Self(Default::default())
	}
}

impl<H> core::fmt::Debug for HashKey<H> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		core::write!(f, "HashKey")
	}
}

impl<H: KeyHasher> KeyFunction<H> for HashKey<H> {
	type Key = H::Out;

	fn key(hash: &H::Out, prefix: Prefix) -> H::Out {
		hash_key::<H>(hash, prefix)
	}
}

/// Make database key from hash only.
pub fn hash_key<H: KeyHasher>(key: &H::Out, _prefix: Prefix) -> H::Out {
	*key
}

/// Key function that concatenates prefix and hash.
pub struct PrefixedKey<H>(PhantomData<H>);

impl<H> Clone for PrefixedKey<H> {
	fn clone(&self) -> Self {
		Self(Default::default())
	}
}

impl<H> core::fmt::Debug for PrefixedKey<H> {
	fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
		core::write!(f, "PrefixedKey")
	}
}

impl<H: KeyHasher> KeyFunction<H> for PrefixedKey<H> {
	type Key = Vec<u8>;

	fn key(hash: &H::Out, prefix: Prefix) -> Vec<u8> {
		prefixed_key::<H>(hash, prefix)
	}
}

/// Derive a database key from hash value of the node (key) and  the node prefix.
pub fn prefixed_key<H: KeyHasher>(key: &H::Out, prefix: Prefix) -> Vec<u8> {
	let mut prefixed_key = Vec::with_capacity(key.as_ref().len() + prefix.0.len() + 1);
	prefixed_key.extend_from_slice(prefix.0);
	if let Some(last) = prefix.1 {
		prefixed_key.push(last);
	}
	prefixed_key.extend_from_slice(key.as_ref());
	prefixed_key
}

/// Key function that concatenates prefix and hash.
/// This is doing useless computation and should only be
/// used for legacy purpose.
/// It shall be remove in the future.
#[derive(Clone, Debug)]
#[deprecated(since="0.22.0")]
pub struct LegacyPrefixedKey<H: KeyHasher>(PhantomData<H>);

#[allow(deprecated)]
impl<H: KeyHasher> KeyFunction<H> for LegacyPrefixedKey<H> {
	type Key = Vec<u8>;

	fn key(hash: &H::Out, prefix: Prefix) -> Vec<u8> {
		legacy_prefixed_key::<H>(hash, prefix)
	}
}

/// Legacy method for db using previous version of prefix encoding.
/// Only for trie radix 16 trie.
#[deprecated(since="0.22.0")]
pub fn legacy_prefixed_key<H: KeyHasher>(key: &H::Out, prefix: Prefix) -> Vec<u8> {
	let mut prefixed_key = Vec::with_capacity(key.as_ref().len() + prefix.0.len() + 1);
	if let Some(last) = prefix.1 {
		let mut prev = 0x01u8;
		for i in prefix.0.iter() {
			prefixed_key.push((prev << 4) + (*i >> 4));
			prev = *i;
		}
		prefixed_key.push((prev << 4) + (last >> 4));
	} else {
		prefixed_key.push(0);
		prefixed_key.extend_from_slice(prefix.0);
	}
	prefixed_key.extend_from_slice(key.as_ref());
	prefixed_key
}

impl<'a, H, KF, T, M> Default for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: From<&'a [u8]>,
	KF: KeyFunction<H>,
	M: MemTracker<T> + Default,
{
	fn default() -> Self {
		Self::from_null_node(&[0u8][..], [0u8][..].into())
	}
}

/// Create a new `MemoryDB` from a given null key/data
impl<H, KF, T, M> MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: Default,
	KF: KeyFunction<H>,
	M: MemTracker<T>,
{
	/// Remove an element and delete it from storage if reference count reaches zero.
	/// If the value was purged, return the old value.
	pub fn remove_and_purge(&mut self, key: &<H as KeyHasher>::Out, prefix: Prefix) -> Option<T> {
		if key == &self.hashed_null_node {
			return None;
		}
		let key = KF::key(key, prefix);
		match self.data.entry(key) {
			Entry::Occupied(mut entry) =>
				if entry.get().1 == 1 {
					let (value, _) = entry.remove();
					self.malloc_tracker.on_remove(&value);
					Some(value)
				} else {
					entry.get_mut().1 -= 1;
					None
				},
			Entry::Vacant(entry) => {
				let value = T::default();
				self.malloc_tracker.on_insert(&value);
				entry.insert((value, -1));
				None
			}
		}
	}

	/// Shrinks the capacity of the map as much as possible. It will drop
	/// down as much as possible while maintaining the internal rules
	/// and possibly leaving some space in accordance with the resize policy.
	#[inline]
	pub fn shrink_to_fit(&mut self) {
		self.data.shrink_to_fit();
	}
}

impl<'a, H, KF, T, M> MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: From<&'a [u8]>,
	KF: KeyFunction<H>,
	M: MemTracker<T> + Default,
{
	/// Create a new `MemoryDB` from a given null key/data
	pub fn from_null_node(null_key: &'a [u8], null_node_data: T) -> Self {
		MemoryDB {
			data: HashMap::default(),
			hashed_null_node: H::hash(null_key),
			null_node_data,
			malloc_tracker: M::default(),
			_kf: Default::default(),
		}
	}

	/// Create a new instance of `Self`.
	pub fn new(data: &'a [u8]) -> Self {
		Self::from_null_node(data, data.into())
	}

	/// Create a new default instance of `Self` and returns `Self` and the root hash.
	pub fn default_with_root() -> (Self, H::Out) {
		let db = Self::default();
		let root = db.hashed_null_node;

		(db, root)
	}

	/// Clear all data from the database.
	///
	/// # Examples
	/// ```rust
	/// extern crate hash_db;
	/// extern crate keccak_hasher;
	/// extern crate memory_db;
	///
	/// use hash_db::{Hasher, HashDB, EMPTY_PREFIX};
	/// use keccak_hasher::KeccakHasher;
	/// use memory_db::{MemoryDB, HashKey};
	///
	/// fn main() {
	///   let mut m = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
	///   let hello_bytes = "Hello world!".as_bytes();
	///   let hash = m.insert(EMPTY_PREFIX, hello_bytes);
	///   assert!(m.contains(&hash, EMPTY_PREFIX));
	///   m.clear();
	///   assert!(!m.contains(&hash, EMPTY_PREFIX));
	/// }
	/// ```
	pub fn clear(&mut self) {
		self.malloc_tracker.on_clear();
		self.data.clear();
	}

	/// Purge all zero-referenced data from the database.
	pub fn purge(&mut self) {
		let malloc_tracker = &mut self.malloc_tracker;
		self.data.retain(|_, (v, rc)| {
			let keep = *rc != 0;
			if !keep {
				malloc_tracker.on_remove(v);
			}
			keep
		});
	}

	/// Return the internal key-value HashMap, clearing the current state.
	pub fn drain(&mut self) -> HashMap<KF::Key, (T, i32)> {
		self.malloc_tracker.on_clear();
		mem::take(&mut self.data)
	}

	/// Grab the raw information associated with a key. Returns None if the key
	/// doesn't exist.
	///
	/// Even when Some is returned, the data is only guaranteed to be useful
	/// when the refs > 0.
	pub fn raw(&self, key: &<H as KeyHasher>::Out, prefix: Prefix) -> Option<(&T, i32)> {
		if key == &self.hashed_null_node {
			return Some((&self.null_node_data, 1));
		}
		self.data.get(&KF::key(key, prefix)).map(|(value, count)| (value, *count))
	}

	/// Consolidate all the entries of `other` into `self`.
	pub fn consolidate(&mut self, mut other: Self) {
		for (key, (value, rc)) in other.drain() {
			match self.data.entry(key) {
				Entry::Occupied(mut entry) => {
					if entry.get().1 < 0 {
						self.malloc_tracker.on_insert(&value);
						self.malloc_tracker.on_remove(&entry.get().0);
						entry.get_mut().0 = value;
					}

					entry.get_mut().1 += rc;
				}
				Entry::Vacant(entry) => {
					self.malloc_tracker.on_insert(&value);
					entry.insert((value, rc));
				}
			}
		}
	}

	/// Get the keys in the database together with number of underlying references.
	pub fn keys(&self) -> HashMap<KF::Key, i32> {
		self.data.iter()
			.filter_map(|(k, v)| if v.1 != 0 {
				Some((k.clone(), v.1))
			} else {
				None
			})
			.collect()
	}
}

#[cfg(feature = "deprecated")]
#[cfg(feature = "std")]
impl<H, KF, T> MemoryDB<H, KF, T>
where
	H: KeyHasher,
	T: HeapSizeOf,
	KF: KeyFunction<H>,
{
	#[deprecated(since="0.12.0", note="please use `size_of` instead")]
	/// Returns the size of allocated heap memory
	pub fn mem_used(&self) -> usize {
		0//self.data.heap_size_of_children()
		// TODO Reenable above when HeapSizeOf supports arrays.
	}
}

impl<H, KF, T, M> MallocSizeOf for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	H::Out: MallocSizeOf,
	T: MallocSizeOf,
	KF: KeyFunction<H>,
	KF::Key: MallocSizeOf,
	M: MemTracker<T>,
{
	fn size_of(&self, ops: &mut MallocSizeOfOps) -> usize {
		self.data.shallow_size_of(ops)
			+ self.malloc_tracker.get_size()
			+ self.null_node_data.size_of(ops)
			+ self.hashed_null_node.size_of(ops)
	}
}

impl<H, KF, T, M> PlainDB<H::Out, T> for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: Default + PartialEq<T> + for<'a> From<&'a [u8]> + Clone + Send + Sync,
	KF: Send + Sync + KeyFunction<H>,
	KF::Key: Borrow<[u8]> + for <'a> From<&'a [u8]>,
	M: MemTracker<T> + Send + Sync,
{
	fn get(&self, key: &H::Out) -> Option<T> {
		match self.data.get(key.as_ref()) {
			Some(&(ref d, rc)) if rc > 0 => Some(d.clone()),
			_ => None
		}
	}

	fn contains(&self, key: &H::Out) -> bool {
		match self.data.get(key.as_ref()) {
			Some(&(_, x)) if x > 0 => true,
			_ => false
		}
	}

	fn emplace(&mut self, key: H::Out, value: T) {
		match self.data.entry(key.as_ref().into()) {
			Entry::Occupied(mut entry) => {
				let &mut (ref mut old_value, ref mut rc) = entry.get_mut();
				if *rc <= 0 {
					self.malloc_tracker.on_insert(&value);
					self.malloc_tracker.on_remove(old_value);
					*old_value = value;
				}
				*rc += 1;
			},
			Entry::Vacant(entry) => {
				self.malloc_tracker.on_insert(&value);
				entry.insert((value, 1));
			},
		}
	}

	fn remove(&mut self, key: &H::Out) {
		match self.data.entry(key.as_ref().into()) {
			Entry::Occupied(mut entry) => {
				let &mut (_, ref mut rc) = entry.get_mut();
				*rc -= 1;
			},
			Entry::Vacant(entry) => {
				let value = T::default();
				self.malloc_tracker.on_insert(&value);
				entry.insert((value, -1));
			},
		}
	}
}

impl<H, KF, T, M> PlainDBRef<H::Out, T> for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: Default + PartialEq<T> + for<'a> From<&'a [u8]> + Clone + Send + Sync,
	KF: Send + Sync + KeyFunction<H>,
	KF::Key: Borrow<[u8]> + for <'a> From<&'a [u8]>,
	M: MemTracker<T> + Send + Sync,
{
	fn get(&self, key: &H::Out) -> Option<T> { PlainDB::get(self, key) }
	fn contains(&self, key: &H::Out) -> bool { PlainDB::contains(self, key) }
}

impl<H, KF, T, M> HashDB<H, T> for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: Default + PartialEq<T> + for<'a> From<&'a [u8]> + Clone + Send + Sync,
	KF: Send + Sync + KeyFunction<H>,
	M: MemTracker<T> + Send + Sync,
{
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> {
		if key == &self.hashed_null_node {
			return Some(self.null_node_data.clone());
		}

		let key = KF::key(key, prefix);
		match self.data.get(&key) {
			Some(&(ref d, rc)) if rc > 0 => Some(d.clone()),
			_ => None
		}
	}

	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		if key == &self.hashed_null_node {
			return true;
		}

		let key = KF::key(key, prefix);
		match self.data.get(&key) {
			Some(&(_, x)) if x > 0 => true,
			_ => false
		}
	}

	fn emplace(&mut self, key: H::Out, prefix: Prefix, value: T) {
		if value == self.null_node_data {
			return;
		}

		let key = KF::key(&key, prefix);
		match self.data.entry(key) {
			Entry::Occupied(mut entry) => {
				let &mut (ref mut old_value, ref mut rc) = entry.get_mut();
				if *rc <= 0 {
					self.malloc_tracker.on_insert(&value);
					self.malloc_tracker.on_remove(old_value);
					*old_value = value;
				}
				*rc += 1;
			},
			Entry::Vacant(entry) => {
				self.malloc_tracker.on_insert(&value);
				entry.insert((value, 1));
			},
		}
	}

	fn insert(&mut self, prefix: Prefix, value: &[u8]) -> H::Out {
		if T::from(value) == self.null_node_data {
			return self.hashed_null_node;
		}

		let key = H::hash(value);
		HashDB::emplace(self, key, prefix, value.into());
		key
	}

	fn remove(&mut self, key: &H::Out, prefix: Prefix) {
		if key == &self.hashed_null_node {
			return;
		}

		let key = KF::key(key, prefix);
		match self.data.entry(key) {
			Entry::Occupied(mut entry) => {
				let &mut (_, ref mut rc) = entry.get_mut();
				*rc -= 1;
			},
			Entry::Vacant(entry) => {
				let value = T::default();
				self.malloc_tracker.on_insert(&value);
				entry.insert((value, -1));
			},
		}
	}
}

impl<H, KF, T, M> HashDBRef<H, T> for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: Default + PartialEq<T> + for<'a> From<&'a [u8]> + Clone + Send + Sync,
	KF: KeyFunction<H> + Send + Sync,
	M: MemTracker<T> + Send + Sync,
{
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> { HashDB::get(self, key, prefix) }
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool { HashDB::contains(self, key, prefix) }
}

impl<H, KF, T, M> AsPlainDB<H::Out, T> for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: Default + PartialEq<T> + for<'a> From<&'a[u8]> + Clone + Send + Sync,
	KF: KeyFunction<H> + Send + Sync,
	KF::Key: Borrow<[u8]> + for <'a> From<&'a [u8]>,
	M: MemTracker<T> + Send + Sync,
{
	fn as_plain_db(&self) -> &dyn PlainDB<H::Out, T> { self }
	fn as_plain_db_mut(&mut self) -> &mut dyn PlainDB<H::Out, T> { self }
}

impl<H, KF, T, M> AsHashDB<H, T> for MemoryDB<H, KF, T, M>
where
	H: KeyHasher,
	T: Default + PartialEq<T> + for<'a> From<&'a[u8]> + Clone + Send + Sync,
	KF: KeyFunction<H> + Send + Sync,
	M: MemTracker<T> + Send + Sync,
{
	fn as_hash_db(&self) -> &dyn HashDB<H, T> { self }
	fn as_hash_db_mut(&mut self) -> &mut dyn HashDB<H, T> { self }
}

#[cfg(test)]
mod tests {
	use super::{MemoryDB, HashDB, KeyHasher, HashKey};
	use parity_util_mem::malloc_size;
	use hash_db::EMPTY_PREFIX;
	use keccak_hasher::KeccakHasher;

	#[test]
	fn memorydb_remove_and_purge() {
		let hello_bytes = b"Hello world!";
		let hello_key = KeccakHasher::hash(hello_bytes);

		let mut m = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
		m.remove(&hello_key, EMPTY_PREFIX);
		assert_eq!(m.raw(&hello_key, EMPTY_PREFIX).unwrap().1, -1);
		m.purge();
		assert_eq!(m.raw(&hello_key, EMPTY_PREFIX).unwrap().1, -1);
		m.insert(EMPTY_PREFIX, hello_bytes);
		assert_eq!(m.raw(&hello_key, EMPTY_PREFIX).unwrap().1, 0);
		m.purge();
		assert_eq!(m.raw(&hello_key, EMPTY_PREFIX), None);

		let mut m = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
		assert!(m.remove_and_purge(&hello_key, EMPTY_PREFIX).is_none());
		assert_eq!(m.raw(&hello_key, EMPTY_PREFIX).unwrap().1, -1);
		m.insert(EMPTY_PREFIX, hello_bytes);
		m.insert(EMPTY_PREFIX, hello_bytes);
		assert_eq!(m.raw(&hello_key, EMPTY_PREFIX).unwrap().1, 1);
		assert_eq!(&*m.remove_and_purge(&hello_key, EMPTY_PREFIX).unwrap(), hello_bytes);
		assert_eq!(m.raw(&hello_key, EMPTY_PREFIX), None);
		assert!(m.remove_and_purge(&hello_key, EMPTY_PREFIX).is_none());
	}

	#[test]
	fn consolidate() {
		let mut main = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
		let mut other = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
		let remove_key = other.insert(EMPTY_PREFIX, b"doggo");
		main.remove(&remove_key, EMPTY_PREFIX);

		let insert_key = other.insert(EMPTY_PREFIX, b"arf");
		main.emplace(insert_key, EMPTY_PREFIX, "arf".as_bytes().to_vec());

		let negative_remove_key = other.insert(EMPTY_PREFIX, b"negative");
		other.remove(&negative_remove_key, EMPTY_PREFIX);	// ref cnt: 0
		other.remove(&negative_remove_key, EMPTY_PREFIX);	// ref cnt: -1
		main.remove(&negative_remove_key, EMPTY_PREFIX);	// ref cnt: -1

		main.consolidate(other);

		assert_eq!(main.raw(&remove_key, EMPTY_PREFIX).unwrap(), (&"doggo".as_bytes().to_vec(), 0));
		assert_eq!(main.raw(&insert_key, EMPTY_PREFIX).unwrap(), (&"arf".as_bytes().to_vec(), 2));
		assert_eq!(
			main.raw(&negative_remove_key, EMPTY_PREFIX).unwrap(),
			(&"negative".as_bytes().to_vec(), -2),
		);
	}

	#[test]
	fn default_works() {
		let mut db = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
		let hashed_null_node = KeccakHasher::hash(&[0u8][..]);
		assert_eq!(db.insert(EMPTY_PREFIX, &[0u8][..]), hashed_null_node);

		let (db2, root) = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default_with_root();
		assert!(db2.contains(&root, EMPTY_PREFIX));
		assert!(db.contains(&root, EMPTY_PREFIX));
	}

	#[test]
	fn malloc_size_of() {
		let mut db = MemoryDB::<KeccakHasher, HashKey<_>, Vec<u8>>::default();
		for i in 0u32..1024 {
			let bytes = i.to_be_bytes();
			let prefix = (bytes.as_ref(), None);
			db.insert(prefix, &bytes);
		}
		assert_eq!(
			malloc_size(&db),
			malloc_size(&db.data) + malloc_size(&db.null_node_data) + malloc_size(&db.hashed_null_node)
		);
	}
}

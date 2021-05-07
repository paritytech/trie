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

#[cfg(feature = "std")]
use std::fmt::Debug;
#[cfg(feature = "std")]
use std::hash;
#[cfg(not(feature = "std"))]
use core::hash;

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
/// TODO should not expose ValueFunction but only Meta in this trait.
/// ValueFunction should be in memorydb | implementations only.
pub trait HashDB<H: Hasher, T, VF: ValueFunction<H, T>>: Send + Sync + AsHashDB<H, T, VF> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T>;

	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	/// Resolve associated meta.
	/// TODO variant with dropped meta? (sometime we do not use meta).
	fn get_with_meta(&self, key: &H::Out, prefix: Prefix) -> Option<(T, VF::Meta)> {
		self.get(key, prefix)
			.map(|value| VF::extract_value_owned(value))
	}

	/// Access additional content or indicate additional content already accessed and needed.
	///
	/// In one case `at` is `None` and no reply is expected, this is a callback to update meta.
	///
	/// In the other case `at` is `Some` and we also got additional content (eg if value
	/// of a trie node is stored externally for performance purpose).
	fn access_from(&self, key: &H::Out, prefix: Prefix, at: Option<H::Out>, meta: &mut VF::Meta) -> Option<T> {
		unimplemented!()
	}

	/// Check for the existence of a hash-key.
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool;

	/// Insert a datum item into the DB and return the datum's hash for a later lookup. Insertions
	/// are counted and the equivalent number of `remove()`s must be performed before the data
	/// is considered dead.
	fn insert(&mut self, prefix: Prefix, value: &[u8]) -> H::Out;

	/// Like `insert()`, except you provide the key and the data is all moved.
	fn emplace(&mut self, key: H::Out, prefix: Prefix, value: T);

	/// Remove a datum previously inserted. Insertions can be "owed" such that the same number of
	/// `insert()`s may happen without the data being eventually being inserted into the DB.
	/// It can be "owed" more than once.
	fn remove(&mut self, key: &H::Out, prefix: Prefix);

	/// Insert with inner meta.
	fn insert_with_meta(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		meta: VF::Meta,
	) -> H::Out;
}

/// Trait for immutable reference of HashDB.
pub trait HashDBRef<H: Hasher, T, VF: ValueFunction<H, T>> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T>;

	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	/// Resolve associated meta.
	fn get_with_meta(&self, key: &H::Out, prefix: Prefix) -> Option<(T, VF::Meta)> {
		self.get(key, prefix).map(|value| VF::extract_value_owned(value))
	}

	/// Check for the existance of a hash-key.
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool;
}

impl<'a, H: Hasher, T, VF: ValueFunction<H, T>> HashDBRef<H, T, VF> for &'a dyn HashDB<H, T, VF> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> { HashDB::get(*self, key, prefix) }
	fn get_with_meta(&self, key: &H::Out, prefix: Prefix) -> Option<(T, VF::Meta)> {
		HashDB::get_with_meta(*self, key, prefix)
	}
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		HashDB::contains(*self, key, prefix)
	}
}

impl<'a, H: Hasher, T, VF: ValueFunction<H, T>> HashDBRef<H, T, VF> for &'a mut dyn HashDB<H, T, VF> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> { HashDB::get(*self, key, prefix) }
	fn get_with_meta(&self, key: &H::Out, prefix: Prefix) -> Option<(T, VF::Meta)> {
		HashDB::get_with_meta(*self, key, prefix)
	}
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		HashDB::contains(*self, key, prefix)
	}
}

/// Upcast trait for HashDB.
pub trait AsHashDB<H: Hasher, T, VF> {
	/// Perform upcast to HashDB for anything that derives from HashDB.
	fn as_hash_db(&self) -> &dyn HashDB<H, T, VF>;
	/// Perform mutable upcast to HashDB for anything that derives from HashDB.
	fn as_hash_db_mut<'a>(&'a mut self) -> &'a mut (dyn HashDB<H, T, VF> + 'a);
}

/// Upcast trait for PlainDB.
pub trait AsPlainDB<K, V> {
	/// Perform upcast to PlainDB for anything that derives from PlainDB.
	fn as_plain_db(&self) -> &dyn PlainDB<K, V>;
	/// Perform mutable upcast to PlainDB for anything that derives from PlainDB.
	fn as_plain_db_mut<'a>(&'a mut self) -> &'a mut (dyn PlainDB<K, V> + 'a);
}

pub trait ValueFunction<H: Hasher, T>: Send + Sync {
	/// Additional content fetchable from storage.
	/// Default is for undefined (eg in some case null node).
	type Meta: Default + Clone;

	/// Produce hash, using given meta to allows different
	/// hashing scheme.
	fn hash(value: &[u8], meta: &Self::Meta) -> H::Out;

	/// Produce stored value, including meta.
	fn stored_value(value: &[u8], meta: Self::Meta) -> T;

	/// Owned version of stored value.
	fn stored_value_owned(value: T, meta: Self::Meta) -> T;

	/// Get meta and input value from stored.
	fn extract_value(stored: &[u8]) -> (&[u8], Self::Meta);

	/// Owned version of `extract_value`.
	fn extract_value_owned(stored: T) -> (T, Self::Meta);
}

/// Default `ValueFunction` implementation, stored value
/// is the same as hashed value, no meta data added.
pub struct NoMeta;

impl<H, T> ValueFunction<H, T> for NoMeta
	where
		H: Hasher,
		T: for<'a> From<&'a [u8]>,
{
	type Meta = ();

	fn hash(value: &[u8], _meta: &Self::Meta) -> H::Out {
		H::hash(value)
	}

	fn stored_value(value: &[u8], _meta: Self::Meta) -> T {
		value.into()
	}

	fn stored_value_owned(value: T, _meta: Self::Meta) -> T {
		value
	}

	fn extract_value(stored: &[u8]) -> (&[u8], Self::Meta) {
		(stored, ())
	}

	fn extract_value_owned(stored: T) -> (T, Self::Meta) {
		(stored, ())
	}
}

// NOTE: There used to be a `impl<T> AsHashDB for T` but that does not work with generics.
// See https://stackoverflow.com/questions/48432842/
// implementing-a-trait-for-reference-and-non-reference-types-causes-conflicting-im
// This means we need concrete impls of AsHashDB in several places, which somewhat defeats
// the point of the trait.
impl<'a, H: Hasher, T, VF> AsHashDB<H, T, VF> for &'a mut dyn HashDB<H, T, VF> {
	fn as_hash_db(&self) -> &dyn HashDB<H, T, VF> { &**self }
	fn as_hash_db_mut<'b>(&'b mut self) -> &'b mut (dyn HashDB<H, T, VF> + 'b) { &mut **self }
}

#[cfg(feature = "std")]
impl<'a, K, V> AsPlainDB<K, V> for &'a mut dyn PlainDB<K, V> {
	fn as_plain_db(&self) -> &dyn PlainDB<K, V> { &**self }
	fn as_plain_db_mut<'b>(&'b mut self) -> &'b mut (dyn PlainDB<K, V> + 'b) { &mut **self }
}

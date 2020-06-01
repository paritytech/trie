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

/// Small trait for to allow using buffer of type [u8; H::LENGTH * 2].
pub trait BinaryHasher: Hasher {
	/// Hash for the empty content (is hash(&[])).
	const NULL_HASH: &'static [u8];

	/// State buffer for hashing.
	type Buffer;

	fn init_buffer() -> Self::Buffer;
	fn reset_buffer(buf: &mut Self::Buffer);
	fn buffer_hash(buff: &mut Self::Buffer, x: &[u8]);

	/// After calling `buffer_finalize`, one do not have to call `reset_buffer`.
	fn buffer_finalize(buff: &mut Self::Buffer) -> Self::Out;
}

#[cfg(std)]
/// Test function to use on any binary buffer implementation.
pub fn test_binary_hasher<H: BinaryHasher>() {
	let size = <H as Hasher>::LENGTH * 2;
	let half_size = <H as Hasher>::LENGTH / 2;
	let mut val = vec![0u8; size];
	val[0] = 1;
	let mut buf = <H as BinaryHasher>::init_buffer();
	H::buffer_hash(&mut buf, &val[..half_size]);
	H::buffer_hash(&mut buf, &val[half_size..<H as Hasher>::LENGTH]);
	let three = core::cmp::min(3, half_size);
	H::buffer_hash(&mut buf, &val[<H as Hasher>::LENGTH..<H as Hasher>::LENGTH + three]);
	H::buffer_hash(&mut buf, &val[<H as Hasher>::LENGTH + three..]);
	let h = H::buffer_finalize(&mut buf);
	let h2 = H::hash(&val[..]);
	assert_eq!(h, h2);
	H::buffer_hash(&mut buf, &val[..]);
	let h = H::buffer_finalize(&mut buf);
	assert_eq!(h, h2);
	let null_hash = H::hash(&[]);
	H::reset_buffer(&mut buf);
	let null_hash2 = H::buffer_finalize(&mut buf);
	assert_eq!(H::NULL_HASH, null_hash.as_ref());
	assert_eq!(H::NULL_HASH, null_hash2.as_ref());
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
}

/// Trait for immutable reference of HashDB.
pub trait HashDBRef<H: Hasher, T> {
	/// Look up a given hash into the bytes that hash to it, returning None if the
	/// hash is not known.
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T>;

	/// Check for the existance of a hash-key.
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool;
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a dyn HashDB<H, T> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> { HashDB::get(*self, key, prefix) }
	fn contains(&self, key: &H::Out, prefix: Prefix) -> bool {
		HashDB::contains(*self, key, prefix)
	}
}

impl<'a, H: Hasher, T> HashDBRef<H, T> for &'a mut dyn HashDB<H, T> {
	fn get(&self, key: &H::Out, prefix: Prefix) -> Option<T> { HashDB::get(*self, key, prefix) }
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

/// Same as HashDB but can modify the value upon storage, and apply
/// `HasherHybrid`.
pub trait HashDBHybrid<H: HasherHybrid, T>: Send + Sync + HashDB<H, T> {
	/// `HashDB` is often use to load content from encoded node.
	/// This will not preserve insertion done through `insert_branch_hybrid` calls
	/// and break the proof.
	/// This function allows to use a callback (usually the call back
	/// will check the encoded value with codec and for branch it will
	/// emplace over the hash_hybrid key) for changing key of some content.
	/// Callback is allow to fail (since it will decode some node this indicates
	/// invalid content earlier), in this case we return false.
	fn insert_hybrid(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		callback: fn(&[u8]) -> core::result::Result<Option<H::Out>, ()>,
	) -> bool;

	/// Insert a datum item into the DB and return the datum's hash for a later lookup. Insertions
	/// are counted and the equivalent number of `remove()`s must be performed before the data
	/// is considered dead.
	fn insert_branch_hybrid<
		I: Iterator<Item = Option<H::Out>>,
	>(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		no_child_value: &[u8],
		nb_children: usize,
		children: I,
		buffer: &mut <H::InnerHasher as BinaryHasher>::Buffer,
	) -> H::Out;

	/// Insert with data from a proof.
	/// As a result, this function can fail.
	fn insert_branch_hybrid_proof<
		I: Iterator<Item = Option<H::Out>>,
		I2: Iterator<Item = H::Out>,
	>(
		&mut self,
		prefix: Prefix,
		value: &[u8],
		no_child_value: &[u8],
		nb_children: usize,
		children: I,
		additional_hashes: I2,
		buffer: &mut <H::InnerHasher as BinaryHasher>::Buffer,
	) -> Option<H::Out>;
}

pub trait HasherHybrid: BinaryHasher {
	type InnerHasher: BinaryHasher<Out = Self::Out>;

	/// Alternate hash with hybrid hashing allowed.
	fn hash_hybrid<
		I: Iterator<Item = Option<<Self as Hasher>::Out>>,
	>(
		encoded_node: &[u8],
		nb_children: usize,
		children: I,
		buffer: &mut <Self::InnerHasher as BinaryHasher>::Buffer,
	) -> Self::Out;

	/// Calculate hash from a proof, this can fail.
	fn hash_hybrid_proof<
		I: Iterator<Item = Option<<Self as Hasher>::Out>>,
		I2: Iterator<Item = <Self::InnerHasher as Hasher>::Out>,
	>(
		x: &[u8],
		nb_children: usize,
		children: I,
		additional_hashes: I2,
		buffer: &mut <Self::InnerHasher as BinaryHasher>::Buffer,
	) -> Option<Self::Out>;

}

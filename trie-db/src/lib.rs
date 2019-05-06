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
#![cfg_attr(not(feature = "std"), no_std)]
#![cfg_attr(not(feature = "std"), feature(alloc))]

//! Trie interface and implementation.

#[cfg(not(feature = "std"))]
extern crate alloc;

extern crate elastic_array;
extern crate hash_db;
extern crate rand;
#[macro_use]
extern crate log;

#[cfg(test)]
extern crate env_logger;
#[cfg(test)]
#[macro_use]
extern crate hex_literal;
#[cfg(test)]
extern crate trie_standardmap as standardmap;
#[cfg(test)]
extern crate trie_root;
#[cfg(test)]
extern crate memory_db;
#[cfg(test)]
extern crate keccak_hasher;
#[cfg(all(feature = "std", test))]
extern crate reference_trie;

#[cfg(not(feature = "std"))]
extern crate hashmap_core;

#[cfg(feature = "std")]
use std as core_;
#[cfg(not(feature = "std"))]
use core as core_;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

#[cfg(feature = "std")]
use std::error::Error;

#[cfg(feature = "std")]
use std::fmt;
#[cfg(feature = "std")]
pub trait MaybeDebug: fmt::Debug {}
#[cfg(feature = "std")]
impl<T: fmt::Debug> MaybeDebug for T {}


#[cfg(not(feature = "std"))]
pub trait MaybeDebug {}
#[cfg(not(feature = "std"))]
impl<T> MaybeDebug for T {}


pub mod node;
pub mod triedb;
pub mod triedbmut;
pub mod sectriedb;
pub mod sectriedbmut;
pub mod recorder;

mod fatdb;
mod fatdbmut;
mod lookup;
mod nibble;
mod node_codec;
mod iter_build;

pub use hash_db::{HashDB, HashDBRef, Hasher};
pub use self::triedb::{TrieDB, TrieDBIterator};
pub use self::triedbmut::{TrieDBMut, ChildReference};
pub use self::sectriedbmut::SecTrieDBMut;
pub use self::sectriedb::SecTrieDB;
pub use self::fatdb::{FatDB, FatDBIterator};
pub use self::fatdbmut::FatDBMut;
pub use self::recorder::{Recorder, Record};
pub use self::lookup::Lookup;
pub use self::nibble::{NibbleSlice, NibbleOps, NibbleHalf, NibbleQuarter};
pub use node_codec::{NodeCodec, Partial};
pub use iter_build::{trie_visit, trie_visit_no_ext, ProcessEncodedNode,
  TrieBuilder, TrieRoot, TrieRootUnhashed, CacheBuilder, Cache16, Cache4};

pub type DBValue = elastic_array::ElasticArray128<u8>;

/// Trie Errors.
///
/// These borrow the data within them to avoid excessive copying on every
/// trie operation.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum TrieError<T, E> {
	/// Attempted to create a trie with a state root not in the DB.
	InvalidStateRoot(T),
	/// Trie item not found in the database,
	IncompleteDatabase(T),
	/// Corrupt Trie item
	DecoderError(T, E),
}

#[cfg(feature = "std")]
impl<T, E> fmt::Display for TrieError<T, E> where T: MaybeDebug, E: MaybeDebug {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			TrieError::InvalidStateRoot(ref root) => write!(f, "Invalid state root: {:?}", root),
			TrieError::IncompleteDatabase(ref missing) => write!(f, "Database missing expected key: {:?}", missing),
			TrieError::DecoderError(ref hash, ref decoder_err) => {
				write!(f, "Decoding failed for hash {:?}; err: {:?}", hash, decoder_err)
			}
		}
	}
}

#[cfg(feature = "std")]
impl<T, E> Error for TrieError<T, E> where T: fmt::Debug, E: Error {
	fn description(&self) -> &str {
		match *self {
			TrieError::InvalidStateRoot(_) => "Invalid state root",
			TrieError::IncompleteDatabase(_) => "Incomplete database",
			TrieError::DecoderError(_, ref err) => err.description(),
		}
	}
}

/// Trie result type. Boxed to avoid copying around extra space for the `Hasher`s `Out` on successful queries.
pub type Result<T, H, E> = ::core_::result::Result<T, Box<TrieError<H, E>>>;


/// Trie-Item type used for iterators over trie data.
pub type TrieItem<'a, U, E> = Result<(Vec<u8>, DBValue), U, E>;

/// Description of what kind of query will be made to the trie.
///
/// This is implemented for any &mut recorder (where the query will return
/// a DBValue), any function taking raw bytes (where no recording will be made),
/// or any tuple of (&mut Recorder, FnOnce(&[u8]))
pub trait Query<H: Hasher> {
	/// Output item.
	type Item;

	/// Decode a byte-slice into the desired item.
	fn decode(self, data: &[u8]) -> Self::Item;

	/// Record that a node has been passed through.
	fn record(&mut self, _hash: &H::Out, _data: &[u8], _depth: u32) {}
}

impl<'a, H: Hasher> Query<H> for &'a mut Recorder<H::Out> {
	type Item = DBValue;
	fn decode(self, value: &[u8]) -> DBValue { DBValue::from_slice(value) }
	fn record(&mut self, hash: &H::Out, data: &[u8], depth: u32) {
		(&mut **self).record(hash, data, depth);
	}
}

impl<F, T, H: Hasher> Query<H> for F where F: for<'a> FnOnce(&'a [u8]) -> T {
	type Item = T;
	fn decode(self, value: &[u8]) -> T { (self)(value) }
}

impl<'a, F, T, H: Hasher> Query<H> for (&'a mut Recorder<H::Out>, F) where F: FnOnce(&[u8]) -> T {
	type Item = T;
	fn decode(self, value: &[u8]) -> T { (self.1)(value) }
	fn record(&mut self, hash: &H::Out, data: &[u8], depth: u32) {
		self.0.record(hash, data, depth)
	}
}

/// A key-value datastore implemented as a database-backed modified Merkle tree.
pub trait Trie<L: TrieLayOut> {
	/// Return the root of the trie.
	fn root(&self) -> &TrieHash<L>;

	/// Is the trie empty?
	fn is_empty(&self) -> bool { *self.root() == L::C::hashed_null_node() }

	/// Does the trie contain a given key?
	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.get(key).map(|x|x.is_some() )
	}

	/// What is the value of the given key in this trie?
	fn get<'a, 'key>(&'a self, key: &'key [u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> where 'a: 'key {
		self.get_with(key, DBValue::from_slice)
	}

	/// Search for the key with the given query parameter. See the docs of the `Query`
	/// trait for more details.
	fn get_with<'a, 'key, Q: Query<L::H>>(
		&'a self,
		key: &'key [u8],
		query: Q
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> where 'a: 'key;

	/// Returns a depth-first iterator over the elements of trie.
	fn iter<'a>(&'a self) -> Result<Box<TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L> >> + 'a>, TrieHash<L>, CError<L>>;
}

/// A key-value datastore implemented as a database-backed modified Merkle tree.
pub trait TrieMut<L: TrieLayOut> {
	/// Return the root of the trie.
	fn root(&mut self) -> &TrieHash<L>;

	/// Is the trie empty?
	fn is_empty(&self) -> bool;

	/// Does the trie contain a given key?
	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.get(key).map(|x| x.is_some())
	}

	/// What is the value of the given key in this trie?
	fn get<'a, 'key>(&'a self, key: &'key [u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> where 'a: 'key;

	/// Insert a `key`/`value` pair into the trie. An empty value is equivalent to removing
	/// `key` from the trie. Returns the old value associated with this key, if it existed.
	fn insert(&mut self, key: &[u8], value: &[u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>>;

	/// Remove a `key` from the trie. Equivalent to making it equal to the empty
	/// value. Returns the old value associated with this key, if it existed.
	fn remove(&mut self, key: &[u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>>;
}

/// A trie iterator that also supports random access (`seek()`).
pub trait TrieIterator<L: TrieLayOut>: Iterator {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>>;
}

/// Trie types
#[derive(Debug, PartialEq, Clone)]
pub enum TrieSpec {
	/// Generic trie.
	Generic,
	/// Secure trie.
	Secure,
	///	Secure trie with fat database.
	Fat,
}

impl Default for TrieSpec {
	fn default() -> TrieSpec {
		TrieSpec::Secure
	}
}

/// Trie factory.
#[derive(Default, Clone)]
pub struct TrieFactory<L: TrieLayOut> {
	spec: TrieSpec,
	layout: L,
}

/// All different kinds of tries.
/// This is used to prevent a heap allocation for every created trie.
pub enum TrieKinds<'db, L: TrieLayOut> {
	/// A generic trie db.
	Generic(TrieDB<'db, L>),
	/// A secure trie db.
	Secure(SecTrieDB<'db, L>),
	/// A fat trie db.
	Fat(FatDB<'db, L>),
}

// wrapper macro for making the match easier to deal with.
macro_rules! wrapper {
	($me: ident, $f_name: ident, $($param: ident),*) => {
		match *$me {
			TrieKinds::Generic(ref t) => t.$f_name($($param),*),
			TrieKinds::Secure(ref t) => t.$f_name($($param),*),
			TrieKinds::Fat(ref t) => t.$f_name($($param),*),
		}
	}
}

impl<'db, L: TrieLayOut> Trie<L> for TrieKinds<'db, L> {
	fn root(&self) -> &TrieHash<L> {
		wrapper!(self, root,)
	}

	fn is_empty(&self) -> bool {
		wrapper!(self, is_empty,)
	}

	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		wrapper!(self, contains, key)
	}

	fn get_with<'a, 'key, Q: Query<L::H>>(&'a self, key: &'key [u8], query: Q) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>>
		where 'a: 'key
	{
		wrapper!(self, get_with, key, query)
	}

	fn iter<'a>(&'a self) -> Result<Box<TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L>>> + 'a>, TrieHash<L>, CError<L>> {
		wrapper!(self, iter,)
	}
}

impl<'db, L> TrieFactory<L>
where
	L: TrieLayOut + 'db,
{
	/// Creates new factory.
	pub fn new(spec: TrieSpec, layout: L) -> Self {
		TrieFactory { spec, layout }
	}

	/// Create new immutable instance of Trie.
	pub fn readonly(
		&self,
		db: &'db HashDBRef<L::H, DBValue>,
		root: &'db TrieHash<L>
	) -> Result<TrieKinds<'db, L>, TrieHash<L>, CError<L>> {
		match self.spec {
			TrieSpec::Generic => Ok(TrieKinds::Generic(TrieDB::new(db, root)?)),
			TrieSpec::Secure => Ok(TrieKinds::Secure(SecTrieDB::new(db, root)?)),
			TrieSpec::Fat => Ok(TrieKinds::Fat(FatDB::new(db, root)?)),
		}
	}

	/// Create new mutable instance of Trie.
	pub fn create(&self, db: &'db mut HashDB<L::H, DBValue>, root: &'db mut TrieHash<L>) -> Box<TrieMut<L> + 'db> {
		match self.spec {
			TrieSpec::Generic => Box::new(TrieDBMut::<L>::new(db, root)),
			TrieSpec::Secure => Box::new(SecTrieDBMut::<L>::new(db, root)),
			TrieSpec::Fat => Box::new(FatDBMut::<L>::new(db, root)),
		}
	}

	/// Create new mutable instance of trie and check for errors.
	pub fn from_existing(
		&self,
		db: &'db mut HashDB<L::H, DBValue>,
		root: &'db mut TrieHash<L>,
	) -> Result<Box<TrieMut<L> + 'db>, TrieHash<L>, CError<L>> {
		match self.spec {
			TrieSpec::Generic => Ok(Box::new(TrieDBMut::<L>::from_existing(db, root)?)),
			TrieSpec::Secure => Ok(Box::new(SecTrieDBMut::<L>::from_existing(db, root)?)),
			TrieSpec::Fat => Ok(Box::new(FatDBMut::<L>::from_existing(db, root)?)),
		}
	}

	/// Returns true iff the trie DB is a fat DB (allows enumeration of keys).
	pub fn is_fat(&self) -> bool { self.spec == TrieSpec::Fat }
}

/// trait with definition of trie layout
pub trait TrieLayOut {
	/// does the trie use extension before its branch
	const USE_EXTENSION: bool;
	type H: Hasher;
	type C: NodeCodec<Self::H, Self::N>;
	type N: NibbleOps;
	type CB: CacheBuilder<<Self::H as Hasher>::Out>;
}

/// alias to acces hasher hash output type from a `TrieLayout`
pub type TrieHash<L> = <<L as TrieLayOut>::H as Hasher>::Out;
/// alias to acces `NodeCodec` `Error` type from a `TrieLayout`
pub type CError<L> = <<L as TrieLayOut>::C as NodeCodec<<L as TrieLayOut>::H, <L as TrieLayOut>::N>>::Error;


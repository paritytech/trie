// Copyright 2017, 2019 Parity Technologies
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

//! Trie interface and implementation.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
mod rstd {
	pub use std::{borrow, boxed, cmp, convert, fmt, hash, iter, marker, mem, ops, rc, result, vec};
	pub use std::collections::VecDeque;
	pub use std::error::Error;
}

#[cfg(not(feature = "std"))]
mod rstd {
	pub use core::{borrow, convert, cmp, iter, fmt, hash, marker, mem, ops, result};
	pub use alloc::{boxed, rc, vec};
	pub use alloc::collections::VecDeque;
	pub trait Error {}
	impl<T> Error for T {}
}

#[cfg(feature = "std")]
use self::rstd::{fmt, Error};

use hash_db::{MaybeDebug, MetaHasher};
use self::rstd::{boxed::Box, vec::Vec};

pub mod node;
pub mod proof;
pub mod triedb;
pub mod triedbmut;
pub mod sectriedb;
pub mod sectriedbmut;
pub mod recorder;

mod fatdb;
mod fatdbmut;
mod iter_build;
mod iterator;
mod lookup;
mod nibble;
mod node_codec;
mod trie_codec;

pub use hash_db::{HashDB, HashDBRef, Hasher};
pub use self::triedb::{TrieDB, TrieDBIterator};
pub use self::triedbmut::{TrieDBMut, ChildReference, Value};
pub use self::sectriedbmut::SecTrieDBMut;
pub use self::sectriedb::SecTrieDB;
pub use self::fatdb::{FatDB, FatDBIterator};
pub use self::fatdbmut::FatDBMut;
pub use self::recorder::{Recorder, Record};
pub use self::lookup::Lookup;
pub use self::nibble::{NibbleSlice, NibbleVec, nibble_ops};
pub use crate::node_codec::{NodeCodec, Partial};
pub use crate::iter_build::{trie_visit, ProcessEncodedNode,
	 TrieBuilder, TrieRoot, TrieRootUnhashed};
pub use crate::iterator::TrieDBNodeIterator;
pub use crate::trie_codec::{decode_compact, decode_compact_from_iter, encode_compact,
	encode_compact_keyed_callback};

#[cfg(feature = "std")]
pub use crate::iter_build::TrieRootPrint;

/// Database value
pub type DBValue = Vec<u8>;

/// Trie Errors.
///
/// These borrow the data within them to avoid excessive copying on every
/// trie operation.
#[derive(PartialEq, Eq, Clone, Debug)]
pub enum TrieError<T, E> {
	/// Attempted to create a trie with a state root not in the DB.
	InvalidStateRoot(T),
	/// Trie item not found in the database,
	IncompleteDatabase(T),
	/// A value was found in the trie with a nibble key that was not byte-aligned.
	/// The first parameter is the byte-aligned part of the prefix and the second parameter is the
	/// remaining nibble.
	ValueAtIncompleteKey(Vec<u8>, u8),
	/// Corrupt Trie item
	DecoderError(T, E),
	InvalidHash(T, Vec<u8>),
}

#[cfg(feature = "std")]
impl<T, E> fmt::Display for TrieError<T, E> where T: MaybeDebug, E: MaybeDebug {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			TrieError::InvalidStateRoot(ref root) =>
				write!(f, "Invalid state root: {:?}", root),
			TrieError::IncompleteDatabase(ref missing) =>
				write!(f, "Database missing expected key: {:?}", missing),
			TrieError::ValueAtIncompleteKey(ref bytes, ref extra) =>
				write!(f, "Value found in trie at incomplete key {:?} + {:?}", bytes, extra),
			TrieError::DecoderError(ref hash, ref decoder_err) => {
				write!(f, "Decoding failed for hash {:?}; err: {:?}", hash, decoder_err)
			}
			TrieError::InvalidHash(ref hash, ref data) =>
				write!(
					f,
					"Encoded node {:?} contains invalid hash reference with length: {}",
					hash, data.len()
				),
		}
	}
}

#[cfg(feature = "std")]
impl<T, E> Error for TrieError<T, E> where T: fmt::Debug, E: Error {}

/// Trie result type.
/// Boxed to avoid copying around extra space for the `Hasher`s `Out` on successful queries.
pub type Result<T, H, E> = crate::rstd::result::Result<T, Box<TrieError<H, E>>>;


/// Trie-Item type used for iterators over trie data.
pub type TrieItem<'a, U, E> = Result<(Vec<u8>, DBValue), U, E>;

/// Trie-Item type used for iterators over trie key only.
pub type TrieKeyItem<'a, U, E> = Result<Vec<u8>, U, E>;

/// Description of what kind of query will be made to the trie.
///
/// This is implemented for any &mut recorder (where the query will return
/// a DBValue), any function taking raw bytes (where no recording will be made),
/// or any tuple of (&mut Recorder, FnOnce(&[u8]))
pub trait Query<H: Hasher, M> {
	/// Output item.
	type Item;

	/// Decode a byte-slice into the desired item.
	fn decode(self, data: &[u8]) -> Self::Item;

	/// Record that a node has been passed through.
	fn record(&mut self, _hash: &H::Out, _data: &[u8], _depth: u32, _meta: &M) {}
}

impl<'a, H: Hasher, M: Clone> Query<H, M> for &'a mut Recorder<H::Out, M> {
	type Item = DBValue;
	fn decode(self, value: &[u8]) -> DBValue { value.to_vec() }
	fn record(&mut self, hash: &H::Out, data: &[u8], depth: u32, meta: &M) {
		(&mut **self).record(hash, data, depth, meta);
	}
}

impl<F, T, H: Hasher, M> Query<H, M> for F where F: for<'a> FnOnce(&'a [u8]) -> T {
	type Item = T;
	fn decode(self, value: &[u8]) -> T { (self)(value) }
}

impl<'a, F, T, H: Hasher, M: Clone> Query<H, M> for (&'a mut Recorder<H::Out, M>, F) where F: FnOnce(&[u8]) -> T {
	type Item = T;
	fn decode(self, value: &[u8]) -> T { (self.1)(value) }
	fn record(&mut self, hash: &H::Out, data: &[u8], depth: u32, meta : &M) {
		self.0.record(hash, data, depth, meta)
	}
}

/// A key-value datastore implemented as a database-backed modified Merkle tree.
pub trait Trie<L: TrieLayout> {
	/// Return the root of the trie.
	fn root(&self) -> &TrieHash<L>;

	/// Is the trie empty?
	fn is_empty(&self) -> bool { *self.root() == L::Codec::hashed_null_node() }

	/// Does the trie contain a given key?
	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.get(key).map(|x| x.is_some() )
	}

	/// What is the value of the given key in this trie?
	fn get<'a, 'key>(
		&'a self,
		key: &'key [u8],
	) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> where 'a: 'key {
		self.get_with(key, |v: &[u8]| v.to_vec() )
	}

	/// Search for the key with the given query parameter. See the docs of the `Query`
	/// trait for more details.
	fn get_with<'a, 'key, Q: Query<L::Hash, L::Meta>>(
		&'a self,
		key: &'key [u8],
		query: Q
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> where 'a: 'key;

	/// Returns a depth-first iterator over the elements of trie.
	fn iter<'a>(&'a self) -> Result<
		Box<dyn TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L> >> + 'a>,
		TrieHash<L>,
		CError<L>
	>;

	/// Returns a depth-first iterator over the keys of elemets of trie.
	fn key_iter<'a>(&'a self) -> Result<
		Box<dyn TrieIterator<L, Item = TrieKeyItem<TrieHash<L>, CError<L> >> + 'a>,
		TrieHash<L>,
		CError<L>
	>;
}

/// A key-value datastore implemented as a database-backed modified Merkle tree.
pub trait TrieMut<L: TrieLayout> {
	/// Return the root of the trie.
	fn root(&mut self) -> &TrieHash<L>;

	/// Is the trie empty?
	fn is_empty(&self) -> bool;

	/// Does the trie contain a given key?
	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.get(key).map(|x| x.is_some())
	}

	/// What is the value of the given key in this trie?
	fn get<'a, 'key>(
		&'a self,
		key: &'key [u8],
	) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> where 'a: 'key;

	/// Insert a `key`/`value` pair into the trie. An empty value is equivalent to removing
	/// `key` from the trie. Returns the old value associated with this key, if it existed.
	fn insert(
		&mut self,
		key: &[u8],
		value: &[u8],
	) -> Result<Value, TrieHash<L>, CError<L>>;

	/// Remove a `key` from the trie. Equivalent to making it equal to the empty
	/// value. Returns the old value associated with this key, if it existed.
	fn remove(&mut self, key: &[u8]) -> Result<Value, TrieHash<L>, CError<L>>;
}

/// A trie iterator that also supports random access (`seek()`).
pub trait TrieIterator<L: TrieLayout>: Iterator {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>>;
}

/// Trie types
#[derive(PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
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
pub struct TrieFactory<L: TrieLayout> {
	spec: TrieSpec,
	layout: L,
}

/// All different kinds of tries.
/// This is used to prevent a heap allocation for every created trie.
pub enum TrieKinds<'db, L: TrieLayout> {
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

impl<'db, L: TrieLayout> Trie<L> for TrieKinds<'db, L> {
	fn root(&self) -> &TrieHash<L> {
		wrapper!(self, root,)
	}

	fn is_empty(&self) -> bool {
		wrapper!(self, is_empty,)
	}

	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		wrapper!(self, contains, key)
	}

	fn get_with<'a, 'key, Q: Query<L::Hash, L::Meta>>(
		&'a self, key: &'key [u8],
		query: Q,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>>
		where 'a: 'key
	{
		wrapper!(self, get_with, key, query)
	}

	fn iter<'a>(&'a self) -> Result<
		Box<dyn TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		wrapper!(self, iter,)
	}

	fn key_iter<'a>(&'a self) -> Result<
		Box<dyn TrieIterator<L, Item = TrieKeyItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		wrapper!(self, key_iter,)
	}
}

impl<'db, L> TrieFactory<L>
where
	L: TrieLayout + 'db,
{
	/// Creates new factory.
	pub fn new(spec: TrieSpec, layout: L) -> Self {
		TrieFactory { spec, layout }
	}

	/// Create new immutable instance of Trie.
	pub fn readonly(
		&self,
		db: &'db dyn HashDBRef<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		root: &'db TrieHash<L>
	) -> Result<TrieKinds<'db, L>, TrieHash<L>, CError<L>> {
		match self.spec {
			TrieSpec::Generic => Ok(TrieKinds::Generic(TrieDB::new(db, root)?)),
			TrieSpec::Secure => Ok(TrieKinds::Secure(SecTrieDB::new(db, root)?)),
			TrieSpec::Fat => Ok(TrieKinds::Fat(FatDB::new(db, root)?)),
		}
	}

	/// Create new mutable instance of Trie.
	pub fn create(
		&self,
		db: &'db mut dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		root: &'db mut TrieHash<L>,
	) -> Box<dyn TrieMut<L> + 'db> {
		match self.spec {
			TrieSpec::Generic => Box::new(TrieDBMut::<L>::new(db, root)),
			TrieSpec::Secure => Box::new(SecTrieDBMut::<L>::new(db, root)),
			TrieSpec::Fat => Box::new(FatDBMut::<L>::new(db, root)),
		}
	}

	/// Create new mutable instance of trie and check for errors.
	pub fn from_existing(
		&self,
		db: &'db mut dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		root: &'db mut TrieHash<L>,
	) -> Result<Box<dyn TrieMut<L> + 'db>, TrieHash<L>, CError<L>> {
		match self.spec {
			TrieSpec::Generic => Ok(Box::new(TrieDBMut::<L>::from_existing(db, root)?)),
			TrieSpec::Secure => Ok(Box::new(SecTrieDBMut::<L>::from_existing(db, root)?)),
			TrieSpec::Fat => Ok(Box::new(FatDBMut::<L>::from_existing(db, root)?)),
		}
	}

	/// Returns true iff the trie DB is a fat DB (allows enumeration of keys).
	pub fn is_fat(&self) -> bool { self.spec == TrieSpec::Fat }
}

/// Trait with definition of trie layout.
/// Contains all associated trait needed for
/// a trie definition or implementation.
/// Structure implementing this trait can define contextual behavior
/// for trie, but should be small (clone cost should be insignifiant).
pub trait TrieLayout: Default + Clone {
	/// If true, the trie will use extension nodes and
	/// no partial in branch, if false the trie will only
	/// use branch and node with partials in both.
	const USE_EXTENSION: bool;
	/// If true, the trie will allow empty values into `TrieDBMut`
	const ALLOW_EMPTY: bool = false;
	/// Indicate if we need to manage meta, skipping some processing
	/// if we don't.
	/// TODO check if still used.
	const USE_META: bool = false;
	/// When this is set to true, trie on instantiation will read their root node
	/// and associated state meta.
	const READ_ROOT_STATE_META: bool = false;

	/// Hasher to use for this trie.
	type Hash: Hasher;
	/// Codec to use (needs to match hasher and nibble ops).
	type Codec: NodeCodec<Self::Meta, HashOut=<Self::Hash as Hasher>::Out>;
	/// Trait `Meta` implementation to use with this layout.
	type Meta: Meta;
	/// Value function to manage meta.
	type MetaHasher: MetaHasher<
		Self::Hash,
		DBValue,
		Meta = Self::Meta,
		GlobalMeta = GlobalMeta<Self>,
	>;

	/// Meta state input for new node.
	fn meta_for_new_node(&self) -> Self::Meta {
		<Self::Meta as Meta>::meta_for_new(self.layout_meta())
	}

	/// Meta state input for new node.
	fn meta_for_stored_inline_node(&self) -> Self::Meta {
		<Self::Meta as Meta>::meta_for_existing_inline_node(
			self.layout_meta(),
		)
	}

	/// When `READ_ROOT_STATE_META` is set, we complete layout value initialization
	/// from meta read in root node (state meta or non state meta).
	fn initialize_from_root_meta(&mut self, _root_meta: &Self::Meta) {
	}

	/// When `READ_ROOT_STATE_META` is set, we complete root meta with layout
	/// state before encoding.
	fn set_root_meta(_root_meta: &mut Self::Meta, _global_meta: GlobalMeta<Self>) {
	}

	/// Current global layout meta.
	/// TODO consider merging mith all meta input function.
	/// TODO rename simply 'meta'
	fn layout_meta(&self) -> GlobalMeta<Self>;
}

/// Trie node level meta.
/// Additional information stored with node or/and containing processing
/// transient information.
/// Can be use to do custom codec and serialization dependant on layout
/// state.
pub trait Meta: Clone {
	/// Global trie meta this will derive from.
	/// Usually it holds specific behavior from layout context.
	type GlobalMeta;

	/// Meta to encode in state.
	type StateMeta: Clone + MaybeDebug;

	/// Get state meta from node encoded form.
	fn read_state_meta(&mut self, input: &[u8]) -> crate::rstd::result::Result<usize, &'static str>;

	/// Encode state meta to be include in state.
	fn write_state_meta(&self) -> Vec<u8>;

	/// Insert associated state meta.
	fn set_state_meta(&mut self, state_meta: Self::StateMeta);

	/// Check if contains state meta (act as a value for trie structure).
	fn has_state_meta(&self) -> bool;

	/// Meta for inline node are not stored, but require a default instantiation
	/// in case it stops being inline.
	/// There is currently no good reason to avoid passing parent meta as in
	/// `meta_for_new` but the fact that it complicate code and is not required
	/// by current use cases.
	fn meta_for_existing_inline_node(
		input: Self::GlobalMeta,
	) -> Self;

	/// Leaf meta creation.
	fn meta_for_new(
		input: Self::GlobalMeta,
	) -> Self;

	/// Empty node meta creation.
	fn meta_for_empty(
	) -> Self;

	/// Value written at a given range (call from codec
	/// for node that contains value (leaf or branch)).
	fn encoded_value_callback(
		&mut self,
		value_plan: crate::node::ValuePlan,
	);

	/// Register info from node plan when decoded.
	fn decoded_callback(
		&mut self,
		node_plan: &crate::node::NodePlan,
	);

	/// Indicate if stored value is incomplete and only contains hash of value.
	fn contains_hash_of_value(&self) -> bool;

	/// Should value be store as a has if possible.
	/// (mostly for proof when value is not accessed).
	fn do_value_hash(&self) -> bool;
}

/// Small enum indicating representation of a given children.
pub enum ChildrenDecoded {
	/// Children is stored as a node.
	Hash,
	/// Children is stored as an inline node.
	Inline,
	/// No children is present.
	None,
}

impl Meta for () {
	type GlobalMeta = ();

	type StateMeta = ();

	fn set_state_meta(&mut self, _state_meta: Self::StateMeta) {
	}

	fn has_state_meta(&self) -> bool {
		false
	}

	fn read_state_meta(&mut self, _input: &[u8]) -> crate::rstd::result::Result<usize, &'static str> {
		Ok(0)
	}

	fn write_state_meta(&self) -> Vec<u8> {
		Vec::new()
	}

	fn meta_for_new(
		_input: Self::GlobalMeta,
	) -> Self {
		()
	}

	fn meta_for_existing_inline_node(
		_input: Self::GlobalMeta,
	) -> Self {
		()
	}

	fn meta_for_empty(
	) -> Self {
		()
	}

	fn encoded_value_callback(
		&mut self,
		_value_plan: crate::node::ValuePlan,
	) {
	}

	fn decoded_callback(
		&mut self,
		_node_plan: &crate::node::NodePlan,
	) {
	}

	fn contains_hash_of_value(&self) -> bool {
		false
	}

	fn do_value_hash(&self) -> bool {
		false
	}
}

/// This trait associates a trie definition with preferred methods.
/// It also contains own default implementations and can be
/// used to allow switching implementation.
pub trait TrieConfiguration: Sized + TrieLayout {
	/// Operation to build a trie db from its ordered iterator over its key/values.
	fn trie_build<DB, I, A, B>(&self, db: &mut DB, input: I) -> <Self::Hash as Hasher>::Out where
		DB: HashDB<Self::Hash, DBValue, Self::Meta, GlobalMeta<Self>>,
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		let mut cb = TrieBuilder::<Self, DB>::new(db);
		trie_visit::<Self, _, _, _, _>(input.into_iter(), &mut cb, self);
		cb.root.unwrap_or_default()
	}
	/// Determines a trie root given its ordered contents, closed form.
	fn trie_root<I, A, B>(&self, input: I) -> <Self::Hash as Hasher>::Out where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		let mut cb = TrieRoot::<Self>::default();
		trie_visit::<Self, _, _, _, _>(input.into_iter(), &mut cb, self);
		cb.root.unwrap_or_default()
	}
	/// Determines a trie root node's data given its ordered contents, closed form.
	fn trie_root_unhashed<I, A, B>(&self, input: I) -> Vec<u8> where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		let mut cb = TrieRootUnhashed::<Self>::default();
		trie_visit::<Self, _, _, _, _>(input.into_iter(), &mut cb, self);
		cb.root.unwrap_or_default()
	}
	/// Encoding of index as a key (when reusing general trie for
	/// indexed trie).
	fn encode_index(input: u32) -> Vec<u8> {
		// be for byte ordering
		input.to_be_bytes().to_vec()
	}
	/// A trie root formed from the items, with keys attached according to their
	/// compact-encoded index (using `parity-codec` crate).
	fn ordered_trie_root<I, A>(&self, input: I) -> <Self::Hash as Hasher>::Out
	where
		I: IntoIterator<Item = A>,
		A: AsRef<[u8]>,
	{
		self.trie_root(input
			.into_iter()
			.enumerate()
			.map(|(i, v)| (Self::encode_index(i as u32), v))
		)
	}
}

/// Alias accessor to hasher hash output type from a `TrieLayout`.
pub type TrieHash<L> = <<L as TrieLayout>::Hash as Hasher>::Out;
/// Alias accessor to state of meta.
pub type StateMeta<L> = <<L as TrieLayout>::Meta as Meta>::StateMeta;
/// Alias accessor to global meta.
pub type GlobalMeta<L> = <<L as TrieLayout>::Meta as Meta>::GlobalMeta;
/// Alias accessor to `NodeCodec` associated `Error` type from a `TrieLayout`.
pub type CError<L> = <<L as TrieLayout>::Codec as NodeCodec<<L as TrieLayout>::Meta>>::Error;

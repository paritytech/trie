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
#![cfg_attr(not(feature = "std"), no_std)]

//! Trie interface and implementation.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
mod rstd {
	pub use std::{
		borrow, boxed, cmp,
		collections::{BTreeMap, VecDeque},
		convert,
		error::Error,
		fmt, hash, iter, marker, mem, ops, result, sync, vec,
	};
}

#[cfg(not(feature = "std"))]
mod rstd {
	pub use alloc::{
		borrow, boxed,
		collections::{btree_map::BTreeMap, VecDeque},
		rc, sync, vec,
	};
	pub use core::{cmp, convert, fmt, hash, iter, marker, mem, ops, result};
	pub trait Error {}
	impl<T> Error for T {}
}

#[cfg(feature = "std")]
use self::rstd::{fmt, Error};

use self::rstd::{boxed::Box, vec::Vec};
pub use iterator::TrieDBNodeDoubleEndedIterator;
use node::NodeOwned;
use node_db::MaybeDebug;

#[cfg(feature = "bench")]
pub mod bench;
#[cfg(any(feature = "test_utils", test))]
pub mod keccak_hasher;
#[cfg(feature = "std")]
pub mod mem_tree_db;
pub mod memory_db;
pub mod node;
pub mod node_db;
pub mod proof;
pub mod recorder;
#[cfg(feature = "test_utils")]
pub mod test_utils;
pub mod trie_root;
pub mod triedb;
pub mod triedbmut;

mod iter_build;
mod iterator;
mod lookup;
mod nibble;
mod node_codec;
mod trie_codec;

pub use self::{
	lookup::Lookup,
	nibble::{nibble_ops, NibbleSlice, NibbleVec},
	recorder::Recorder,
	triedb::{TrieDB, TrieDBBuilder, TrieDBIterator, TrieDBKeyIterator},
	triedbmut::{
		Changeset, ChildReference, ExistingChangesetNode, NewChangesetNode, OwnedPrefix, TrieDBMut,
		TrieDBMutBuilder, Value,
	},
};
use crate::node_db::Hasher;
pub use crate::{
	iter_build::{trie_visit, ProcessEncodedNode, TrieBuilder, TrieRoot, TrieRootUnhashed},
	iterator::{TrieDBNodeIterator, TrieDBRawIterator},
	node_codec::{NodeCodec, Partial},
	trie_codec::{decode_compact, decode_compact_from_iter, encode_compact},
};

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
	/// Corrupt Trie item.
	DecoderError(T, E),
	/// Hash is not value.
	InvalidHash(T, Vec<u8>),
}

#[cfg(feature = "std")]
impl<T, E> fmt::Display for TrieError<T, E>
where
	T: MaybeDebug,
	E: MaybeDebug,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			TrieError::InvalidStateRoot(ref root) => write!(f, "Invalid state root: {:?}", root),
			TrieError::IncompleteDatabase(ref missing) =>
				write!(f, "Database missing expected key: {:?}", missing),
			TrieError::ValueAtIncompleteKey(ref bytes, ref extra) =>
				write!(f, "Value found in trie at incomplete key {:?} + {:?}", bytes, extra),
			TrieError::DecoderError(ref hash, ref decoder_err) => {
				write!(f, "Decoding failed for hash {:?}; err: {:?}", hash, decoder_err)
			},
			TrieError::InvalidHash(ref hash, ref data) => write!(
				f,
				"Encoded node {:?} contains invalid hash reference with length: {}",
				hash,
				data.len()
			),
		}
	}
}

#[cfg(feature = "std")]
impl<T, E> Error for TrieError<T, E>
where
	T: fmt::Debug,
	E: Error,
{
}

/// Trie result type.
/// Boxed to avoid copying around extra space for the `Hasher`s `Out` on successful queries.
pub type Result<T, H, E> = crate::rstd::result::Result<T, Box<TrieError<H, E>>>;

/// Trie-Item type used for iterators over trie data.
pub type TrieItem<U, E> = Result<(Vec<u8>, DBValue), U, E>;

/// Trie-Item type used for iterators over trie key only.
pub type TrieKeyItem<U, E> = Result<Vec<u8>, U, E>;

/// Description of what kind of query will be made to the trie.
pub trait Query<H: Hasher> {
	/// Output item.
	type Item;

	/// Decode a byte-slice into the desired item.
	fn decode(self, data: &[u8]) -> Self::Item;
}

/// Used to report the trie access to the [`TrieRecorder`].
///
/// As the trie can use a [`TrieCache`], there are multiple kinds of accesses.
/// If a cache is used, [`Self::Key`] and [`Self::NodeOwned`] are possible
/// values. Otherwise only [`Self::EncodedNode`] is a possible value.
#[cfg_attr(feature = "std", derive(Debug))]
pub enum TrieAccess<'a, H, L> {
	/// The given [`NodeOwned`] was accessed using its `hash`.
	NodeOwned { hash: H, node_owned: &'a NodeOwned<H, L> },
	/// The given `encoded_node` was accessed using its `hash`.
	EncodedNode { hash: H, encoded_node: rstd::borrow::Cow<'a, [u8]> },
	/// The given `value` was accessed using its `hash`.
	///
	/// The given `full_key` is the key to access this value in the trie.
	///
	/// Should map to [`RecordedForKey::Value`] when checking the recorder.
	Value { hash: H, value: rstd::borrow::Cow<'a, [u8]>, full_key: &'a [u8] },
	/// A value was accessed that is stored inline a node.
	///
	/// As the value is stored inline there is no need to separately record the value as it is part
	/// of a node. The given `full_key` is the key to access this value in the trie.
	///
	/// Should map to [`RecordedForKey::Value`] when checking the recorder.
	InlineValue { full_key: &'a [u8] },
	/// The hash of the value for the given `full_key` was accessed.
	///
	/// Should map to [`RecordedForKey::Hash`] when checking the recorder.
	Hash { full_key: &'a [u8] },
	/// The value/hash for `full_key` was accessed, but it couldn't be found in the trie.
	///
	/// Should map to [`RecordedForKey::Value`] when checking the recorder.
	NonExisting { full_key: &'a [u8] },
}

/// Result of [`TrieRecorder::trie_nodes_recorded_for_key`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordedForKey {
	/// We recorded all trie nodes up to the value for a storage key.
	///
	/// This should be returned when the recorder has seen the following [`TrieAccess`]:
	///
	/// - [`TrieAccess::Value`]: If we see this [`TrieAccess`], it means we have recorded all the
	///   trie nodes up to the value.
	/// - [`TrieAccess::NonExisting`]: If we see this [`TrieAccess`], it means we have recorded all
	///   the necessary  trie nodes to prove that the value doesn't exist in the trie.
	Value,
	/// We recorded all trie nodes up to the value hash for a storage key.
	///
	/// If we have a [`RecordedForKey::Value`], it means that we also have the hash of this value.
	/// This also means that if we first have recorded the hash of a value and then also record the
	/// value, the access should be upgraded to [`RecordedForKey::Value`].
	///
	/// This should be returned when the recorder has seen the following [`TrieAccess`]:
	///
	/// - [`TrieAccess::Hash`]: If we see this [`TrieAccess`], it means we have recorded all trie
	///   nodes to have the hash of the value.
	Hash,
	/// We haven't recorded any trie nodes yet for a storage key.
	///
	/// This means we have not seen any [`TrieAccess`] referencing the searched key.
	None,
}

impl RecordedForKey {
	/// Is `self` equal to [`Self::None`]?
	pub fn is_none(&self) -> bool {
		matches!(self, Self::None)
	}
}

/// A trie recorder that can be used to record all kind of [`TrieAccess`]'s.
///
/// To build a trie proof a recorder is required that records all trie accesses. These recorded trie
/// accesses can then be used to create the proof.
pub trait TrieRecorder<H, L> {
	/// Record the given [`TrieAccess`].
	///
	/// Depending on the [`TrieAccess`] a call of [`Self::trie_nodes_recorded_for_key`] afterwards
	/// must return the correct recorded state.
	fn record<'a>(&mut self, access: TrieAccess<'a, H, L>);

	/// Check if we have recorded any trie nodes for the given `key`.
	///
	/// Returns [`RecordedForKey`] to express the state of the recorded trie nodes.
	fn trie_nodes_recorded_for_key(&self, key: &[u8]) -> RecordedForKey;
}

impl<F, T, H: Hasher> Query<H> for F
where
	F: for<'a> FnOnce(&'a [u8]) -> T,
{
	type Item = T;
	fn decode(self, value: &[u8]) -> T {
		(self)(value)
	}
}

/// A key-value datastore implemented as a database-backed modified Merkle tree.
pub trait Trie<L: TrieLayout> {
	/// Return the root of the trie.
	fn root(&self) -> &TrieHash<L>;

	/// Return the root location of the trie if it was set.
	fn root_location(&self) -> L::Location {
		Default::default()
	}

	/// Is the trie empty?
	fn is_empty(&self) -> bool {
		*self.root() == L::Codec::hashed_null_node()
	}

	/// Does the trie contain a given key?
	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.get(key).map(|x| x.is_some())
	}

	/// Returns the hash of the value for `key`.
	fn get_hash(&self, key: &[u8]) -> Result<Option<TrieHash<L>>, TrieHash<L>, CError<L>>;

	/// What is the value of the given key in this trie?
	fn get(&self, key: &[u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		self.get_with(key, |v: &[u8]| v.to_vec())
	}

	/// Search for the key with the given query parameter. See the docs of the `Query`
	/// trait for more details.
	fn get_with<Q: Query<L::Hash>>(
		&self,
		key: &[u8],
		query: Q,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>>;

	/// Look up the [`MerkleValue`] of the node that is the closest descendant for the provided
	/// key.
	///
	/// When the provided key leads to a node, then the merkle value of that node
	/// is returned. However, if the key does not lead to a node, then the merkle value
	/// of the closest descendant is returned. `None` if no such descendant exists.
	fn lookup_first_descendant(
		&self,
		key: &[u8],
	) -> Result<Option<MerkleValue<TrieHash<L>>>, TrieHash<L>, CError<L>>;

	/// Returns a depth-first iterator over the elements of trie.
	fn iter<'a>(
		&'a self,
	) -> Result<
		Box<dyn TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	>;

	/// Returns a depth-first iterator over the keys of elemets of trie.
	fn key_iter<'a>(
		&'a self,
	) -> Result<
		Box<dyn TrieIterator<L, Item = TrieKeyItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	>;
}

/// A trie iterator that also supports random access (`seek()`).
pub trait TrieIterator<L: TrieLayout>: Iterator {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>>;
}

/// Extending the `TrieIterator` trait with `DoubleEndedIterator` trait.
pub trait TrieDoubleEndedIterator<L: TrieLayout>: TrieIterator<L> + DoubleEndedIterator {}

/// Trie types
#[derive(PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum TrieSpec {
	/// Generic trie.
	Generic,
}

impl Default for TrieSpec {
	fn default() -> TrieSpec {
		TrieSpec::Generic
	}
}

/// Trait with definition of trie layout.
/// Contains all associated trait needed for
/// a trie definition or implementation.
pub trait TrieLayout {
	/// If true, the trie will use extension nodes and
	/// no partial in branch, if false the trie will only
	/// use branch and node with partials in both.
	const USE_EXTENSION: bool;
	/// If true, the trie will allow empty values into `TrieDBMut`
	const ALLOW_EMPTY: bool = false;
	/// Threshold above which an external node should be
	/// use to store a node value.
	const MAX_INLINE_VALUE: Option<u32>;

	/// Hasher to use for this trie.
	type Hash: Hasher;
	/// Codec to use (needs to match hasher and nibble ops).
	type Codec: NodeCodec<HashOut = <Self::Hash as Hasher>::Out>;
	type Location: Location;
}

/// Trait alias for requirement of location with `TrieLayout`.
pub trait Location: Copy + Default + Eq + PartialEq + MaybeDebug {}

impl<T: Copy + Default + Eq + PartialEq + MaybeDebug> Location for T {}

/// This trait associates a trie definition with preferred methods.
/// It also contains own default implementations and can be
/// used to allow switching implementation.
pub trait TrieConfiguration: Sized + TrieLayout {
	/// Operation to build a trie db from its ordered iterator over its key/values.
	fn trie_build<I, A, B>(
		db: &mut memory_db::MemoryDB<Self::Hash, memory_db::HashKey<Self::Hash>, DBValue>,
		input: I,
	) -> <Self::Hash as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		let mut cb = TrieBuilder::<Self, memory_db::HashKey<Self::Hash>>::new(db);
		trie_visit::<Self, _, _, _, _>(input.into_iter(), &mut cb);
		cb.root.unwrap_or_default()
	}
	/// Determines a trie root given its ordered contents, closed form.
	fn trie_root<I, A, B>(input: I) -> <Self::Hash as Hasher>::Out
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		let mut cb = TrieRoot::<Self>::default();
		trie_visit::<Self, _, _, _, _>(input.into_iter(), &mut cb);
		cb.root.unwrap_or_default()
	}
	/// Determines a trie root node's data given its ordered contents, closed form.
	fn trie_root_unhashed<I, A, B>(input: I) -> Vec<u8>
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
	{
		let mut cb = TrieRootUnhashed::<Self>::default();
		trie_visit::<Self, _, _, _, _>(input.into_iter(), &mut cb);
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
	fn ordered_trie_root<I, A>(input: I) -> <Self::Hash as Hasher>::Out
	where
		I: IntoIterator<Item = A>,
		A: AsRef<[u8]>,
	{
		Self::trie_root(
			input.into_iter().enumerate().map(|(i, v)| (Self::encode_index(i as u32), v)),
		)
	}
}

/// Alias accessor to hasher hash output type from a `TrieLayout`.
pub type TrieHash<L> = <<L as TrieLayout>::Hash as Hasher>::Out;
/// Alias accessor to `NodeCodec` associated `Error` type from a `TrieLayout`.
pub type CError<L> = <<L as TrieLayout>::Codec as NodeCodec>::Error;

/// A value as cached by the [`TrieCache`].
#[derive(Clone, Debug)]
pub enum CachedValue<H, L> {
	/// The value doesn't exist in the trie.
	NonExisting,
	/// We cached the hash and location, because we did not yet accessed the data.
	ExistingHash(H, L),
	/// The value exists in the trie.
	Existing {
		/// The hash of the value.
		hash: H,
		/// The actual data of the value stored as [`BytesWeak`].
		///
		/// The original data [`Bytes`] is stored in the trie node
		/// that is also cached by the [`TrieCache`]. If this node is dropped,
		/// this data will also not be "upgradeable" anymore.
		data: BytesWeak,
	},
}

impl<H: Copy, L> CachedValue<H, L> {
	/// Returns the data of the value.
	///
	/// If a value doesn't exist in the trie or only the value hash is cached, this function returns
	/// `None`. If the reference to the data couldn't be upgraded (see [`Bytes::upgrade`]), this
	/// function returns `Some(None)`, aka the data needs to be fetched again from the trie.
	pub fn data(&self) -> Option<Option<Bytes>> {
		match self {
			Self::Existing { data, .. } => Some(data.upgrade()),
			_ => None,
		}
	}

	/// Returns the hash of the value.
	///
	/// Returns only `None` when the value doesn't exist.
	pub fn hash(&self) -> Option<H> {
		match self {
			Self::ExistingHash(hash, _) | Self::Existing { hash, .. } => Some(*hash),
			Self::NonExisting => None,
		}
	}
}

impl<H, L> From<(Bytes, H)> for CachedValue<H, L> {
	fn from(value: (Bytes, H)) -> Self {
		Self::Existing { hash: value.1, data: value.0.into() }
	}
}

impl<H, L> From<Option<(Bytes, H)>> for CachedValue<H, L> {
	fn from(value: Option<(Bytes, H)>) -> Self {
		value.map_or(Self::NonExisting, |v| Self::Existing { hash: v.1, data: v.0.into() })
	}
}

/// A cache that can be used to speed-up certain operations when accessing the trie.
///
/// The [`TrieDB`]/[`TrieDBMut`] by default are working with the internal hash-db in a non-owning
/// mode. This means that for every lookup in the trie, every node is always fetched and decoded on
/// the fly. Fetching and decoding a node always takes some time and can kill the performance of any
/// application that is doing quite a lot of trie lookups. To circumvent this performance
/// degradation, a cache can be used when looking up something in the trie. Any cache that should be
/// used with the [`TrieDB`]/[`TrieDBMut`] needs to implement this trait.
///
/// The trait is laying out a two level cache, first the trie nodes cache and then the value cache.
/// The trie nodes cache, as the name indicates, is for caching trie nodes as [`NodeOwned`]. These
/// trie nodes are referenced by their hash. The value cache is caching [`CachedValue`]'s and these
/// are referenced by the key to look them up in the trie. As multiple different tries can have
/// different values under the same key, it up to the cache implementation to ensure that the
/// correct value is returned. As each trie has a different root, this root can be used to
/// differentiate values under the same key.
pub trait TrieCache<NC: NodeCodec, L> {
	/// Lookup value for the given `key`.
	///
	/// Returns the `None` if the `key` is unknown or otherwise `Some(_)` with the associated
	/// value.
	///
	/// [`Self::cache_data_for_key`] is used to make the cache aware of data that is associated
	/// to a `key`.
	///
	/// # Attention
	///
	/// The cache can be used for different tries, aka with different roots. This means
	/// that the cache implementation needs to take care of always returning the correct value
	/// for the current trie root.
	fn lookup_value_for_key(&mut self, key: &[u8]) -> Option<&CachedValue<NC::HashOut, L>>;

	/// Cache the given `value` for the given `key`.
	///
	/// # Attention
	///
	/// The cache can be used for different tries, aka with different roots. This means
	/// that the cache implementation needs to take care of caching `value` for the current
	/// trie root.
	fn cache_value_for_key(&mut self, key: &[u8], value: CachedValue<NC::HashOut, L>);

	/// Get or insert a [`NodeOwned`].
	///
	/// The cache implementation should look up based on the given `hash` if the node is already
	/// known. If the node is not yet known, the given `fetch_node` function can be used to fetch
	/// the particular node.
	///
	/// Returns the [`NodeOwned`] or an error that happened on fetching the node.
	fn get_or_insert_node(
		&mut self,
		hash: NC::HashOut,
		location: L,
		fetch_node: &mut dyn FnMut() -> Result<NodeOwned<NC::HashOut, L>, NC::HashOut, NC::Error>,
	) -> Result<&NodeOwned<NC::HashOut, L>, NC::HashOut, NC::Error>;

	/// Get the [`NodeOwned`] that corresponds to the given `hash`.
	fn get_node(&mut self, hash: &NC::HashOut, location: L) -> Option<&NodeOwned<NC::HashOut, L>>;

	/// Put a new node. This is used to clear location info for existing nodes with the same hash.
	fn insert_new_node(&mut self, hash: &NC::HashOut);
}

/// A container for storing bytes.
///
/// This uses a reference counted pointer internally, so it is cheap to clone this object.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Bytes(rstd::sync::Arc<[u8]>);

impl rstd::ops::Deref for Bytes {
	type Target = [u8];

	fn deref(&self) -> &Self::Target {
		self.0.deref()
	}
}

impl From<Vec<u8>> for Bytes {
	fn from(bytes: Vec<u8>) -> Self {
		Self(bytes.into())
	}
}

impl From<&[u8]> for Bytes {
	fn from(bytes: &[u8]) -> Self {
		Self(bytes.into())
	}
}

impl<T: AsRef<[u8]>> PartialEq<T> for Bytes {
	fn eq(&self, other: &T) -> bool {
		self.as_ref() == other.as_ref()
	}
}

/// A weak reference of [`Bytes`].
///
/// A weak reference means that it doesn't prevent [`Bytes`] from being dropped because
/// it holds a non-owning reference to the associated [`Bytes`] object. With [`Self::upgrade`] it
/// is possible to upgrade it again to [`Bytes`] if the reference is still valid.
#[derive(Clone, Debug)]
pub struct BytesWeak(rstd::sync::Weak<[u8]>);

impl BytesWeak {
	/// Upgrade to [`Bytes`].
	///
	/// Returns `None` when the inner value was already dropped.
	pub fn upgrade(&self) -> Option<Bytes> {
		self.0.upgrade().map(Bytes)
	}
}

impl From<Bytes> for BytesWeak {
	fn from(bytes: Bytes) -> Self {
		Self(rstd::sync::Arc::downgrade(&bytes.0))
	}
}

/// Either the `hash` or `value` of a node depending on its size.
///
/// If the size of the node `value` is bigger or equal than `MAX_INLINE_VALUE` the `hash` is
/// returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum MerkleValue<H> {
	/// The merkle value is the node data itself when the
	/// node data is smaller than `MAX_INLINE_VALUE`.
	///
	/// Note: The case of inline nodes.
	Node(Vec<u8>),
	/// The merkle value is the hash of the node.
	Hash(H),
}

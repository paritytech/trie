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

use crate::{
	fatdb::FatDBDoubleEndedIterator,
	iterator::{TrieDBNodeDoubleEndedIterator, TrieDBRawIterator},
	lookup::Lookup,
	nibble::NibbleSlice,
	node::{decode_hash, NodeHandle, OwnedNode},
	rstd::boxed::Box,
	CError, DBValue, MerkleValue, Query, Result, Trie, TrieAccess, TrieCache,
	TrieDoubleEndedIterator, TrieError, TrieHash, TrieItem, TrieIterator, TrieKeyItem, TrieLayout,
	TrieRecorder,
};
#[cfg(feature = "std")]
use crate::{
	nibble::NibbleVec,
	node::Node,
	rstd::{fmt, vec::Vec},
};
use hash_db::{HashDBRef, Prefix, EMPTY_PREFIX};

/// A builder for creating a [`TrieDB`].
pub struct TrieDBBuilder<'db, 'cache, L: TrieLayout> {
	db: &'db dyn HashDBRef<L::Hash, DBValue>,
	root: &'db TrieHash<L>,
	cache: Option<&'cache mut dyn TrieCache<L::Codec>>,
	recorder: Option<&'cache mut dyn TrieRecorder<TrieHash<L>>>,
}

impl<'db, 'cache, L: TrieLayout> TrieDBBuilder<'db, 'cache, L> {
	/// Create a new trie-db builder with the backing database `db` and `root`.
	///
	/// This doesn't check if `root` exists in the given `db`. If `root` doesn't exist it will fail
	/// when trying to lookup any key.
	#[inline]
	pub fn new(db: &'db dyn HashDBRef<L::Hash, DBValue>, root: &'db TrieHash<L>) -> Self {
		Self { db, root, cache: None, recorder: None }
	}

	/// Use the given `cache` for the db.
	#[inline]
	pub fn with_cache(mut self, cache: &'cache mut dyn TrieCache<L::Codec>) -> Self {
		self.cache = Some(cache);
		self
	}

	/// Use the given optional `cache` for the db.
	#[inline]
	pub fn with_optional_cache<'ocache: 'cache>(
		mut self,
		cache: Option<&'ocache mut dyn TrieCache<L::Codec>>,
	) -> Self {
		// Make the compiler happy by "converting" the lifetime
		self.cache = cache.map(|c| c as _);
		self
	}

	/// Use the given `recorder` to record trie accesses.
	#[inline]
	pub fn with_recorder(mut self, recorder: &'cache mut dyn TrieRecorder<TrieHash<L>>) -> Self {
		self.recorder = Some(recorder);
		self
	}

	/// Use the given optional `recorder` to record trie accesses.
	#[inline]
	pub fn with_optional_recorder<'recorder: 'cache>(
		mut self,
		recorder: Option<&'recorder mut dyn TrieRecorder<TrieHash<L>>>,
	) -> Self {
		// Make the compiler happy by "converting" the lifetime
		self.recorder = recorder.map(|r| r as _);
		self
	}

	/// Build the [`TrieDB`].
	#[inline]
	pub fn build(self) -> TrieDB<'db, 'cache, L> {
		TrieDB {
			db: self.db,
			root: self.root,
			cache: self.cache.map(core::cell::RefCell::new),
			recorder: self.recorder.map(core::cell::RefCell::new),
		}
	}
}

/// A `Trie` implementation using a generic `HashDB` backing database, a `Hasher`
/// implementation to generate keys and a `NodeCodec` implementation to encode/decode
/// the nodes.
///
/// Use it as a `Trie` trait object. You can use `db()` to get the backing database object.
/// Use `get` and `contains` to query values associated with keys in the trie.
///
/// # Example
/// ```ignore
/// use hash_db::Hasher;
/// use reference_trie::{RefTrieDBMut, RefTrieDB, Trie, TrieMut};
/// use trie_db::DBValue;
/// use keccak_hasher::KeccakHasher;
/// use memory_db::*;
///
/// let mut memdb = MemoryDB::<KeccakHasher, HashKey<_>, _>::default();
/// let mut root = Default::default();
/// RefTrieDBMut::new(&mut memdb, &mut root).insert(b"foo", b"bar").unwrap();
/// let t = RefTrieDB::new(&memdb, &root);
/// assert!(t.contains(b"foo").unwrap());
/// assert_eq!(t.get(b"foo").unwrap().unwrap(), b"bar".to_vec());
/// ```
pub struct TrieDB<'db, 'cache, L>
where
	L: TrieLayout,
{
	db: &'db dyn HashDBRef<L::Hash, DBValue>,
	root: &'db TrieHash<L>,
	cache: Option<core::cell::RefCell<&'cache mut dyn TrieCache<L::Codec>>>,
	recorder: Option<core::cell::RefCell<&'cache mut dyn TrieRecorder<TrieHash<L>>>>,
}

impl<'db, 'cache, L> TrieDB<'db, 'cache, L>
where
	L: TrieLayout,
{
	/// Get the backing database.
	pub fn db(&'db self) -> &'db dyn HashDBRef<L::Hash, DBValue> {
		self.db
	}

	/// Create `TrieDBDoubleEndedIterator` from `TrieDB`.
	pub fn into_double_ended_iter(
		&'db self,
	) -> Result<TrieDBDoubleEndedIterator<'db, 'cache, L>, TrieHash<L>, CError<L>> {
		TrieDBDoubleEndedIterator::new(&self)
	}

	/// Create `TrieDBNodeDoubleEndedIterator` from `TrieDB`.
	pub fn into_node_double_ended_iter(
		&'db self,
	) -> Result<TrieDBNodeDoubleEndedIterator<'db, 'cache, L>, TrieHash<L>, CError<L>> {
		TrieDBNodeDoubleEndedIterator::new(&self)
	}

	/// create `TrieDBKeyDoubleEndedIterator` from `TrieDB`.
	pub fn into_key_double_ended_iter(
		&'db self,
	) -> Result<TrieDBKeyDoubleEndedIterator<'db, 'cache, L>, TrieHash<L>, CError<L>> {
		TrieDBKeyDoubleEndedIterator::new(&self)
	}

	/// create `FatDBDoubleEndedIterator` from `TrieDB`.
	pub fn into_fat_double_ended_iter(
		&'db self,
	) -> Result<FatDBDoubleEndedIterator<'db, 'cache, L>, TrieHash<L>, CError<L>> {
		FatDBDoubleEndedIterator::new(&self)
	}

	/// Given some node-describing data `node`, and node key return the actual node RLP.
	/// This could be a simple identity operation in the case that the node is sufficiently small,
	/// but may require a database lookup.
	///
	/// Return value is the node data and the node hash if the value was looked up in the database
	/// or None if it was returned raw.
	///
	/// `partial_key` is encoded nibble slice that addresses the node.
	///
	/// `record_access` should be set to `true` when the access to the trie should be recorded.
	/// However, this will only be done when there is a recorder set.
	pub(crate) fn get_raw_or_lookup(
		&self,
		parent_hash: TrieHash<L>,
		node_handle: NodeHandle,
		partial_key: Prefix,
		record_access: bool,
	) -> Result<(OwnedNode<DBValue>, Option<TrieHash<L>>), TrieHash<L>, CError<L>> {
		let (node_hash, node_data) = match node_handle {
			NodeHandle::Hash(data) => {
				let node_hash = decode_hash::<L::Hash>(data)
					.ok_or_else(|| Box::new(TrieError::InvalidHash(parent_hash, data.to_vec())))?;
				let node_data = self.db.get(&node_hash, partial_key).ok_or_else(|| {
					if partial_key == EMPTY_PREFIX {
						Box::new(TrieError::InvalidStateRoot(node_hash))
					} else {
						Box::new(TrieError::IncompleteDatabase(node_hash))
					}
				})?;

				(Some(node_hash), node_data)
			},
			NodeHandle::Inline(data) => (None, data.to_vec()),
		};
		let owned_node = OwnedNode::new::<L::Codec>(node_data)
			.map_err(|e| Box::new(TrieError::DecoderError(node_hash.unwrap_or(parent_hash), e)))?;

		if record_access {
			if let Some((hash, recorder)) =
				node_hash.as_ref().and_then(|h| self.recorder.as_ref().map(|r| (h, r)))
			{
				recorder.borrow_mut().record(TrieAccess::EncodedNode {
					hash: *hash,
					encoded_node: owned_node.data().into(),
				});
			}
		}

		Ok((owned_node, node_hash))
	}

	/// Fetch a value under the given `hash`.
	pub(crate) fn fetch_value(
		&self,
		hash: TrieHash<L>,
		prefix: Prefix,
	) -> Result<DBValue, TrieHash<L>, CError<L>> {
		let value = self
			.db
			.get(&hash, prefix)
			.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(hash)))?;

		if let Some(recorder) = self.recorder.as_ref() {
			debug_assert!(prefix.1.is_none(), "A value has never a partial key; qed");

			recorder.borrow_mut().record(TrieAccess::Value {
				hash,
				value: value.as_slice().into(),
				full_key: prefix.0,
			});
		}

		Ok(value)
	}
}

impl<'db, 'cache, L> Trie<L> for TrieDB<'db, 'cache, L>
where
	L: TrieLayout,
{
	fn root(&self) -> &TrieHash<L> {
		self.root
	}

	fn get_hash(&self, key: &[u8]) -> Result<Option<TrieHash<L>>, TrieHash<L>, CError<L>> {
		let mut cache = self.cache.as_ref().map(|c| c.borrow_mut());
		let mut recorder = self.recorder.as_ref().map(|r| r.borrow_mut());

		Lookup::<L, _> {
			db: self.db,
			query: |_: &[u8]| (),
			hash: *self.root,
			cache: cache.as_mut().map(|c| &mut ***c as &mut dyn TrieCache<L::Codec>),
			recorder: recorder.as_mut().map(|r| &mut ***r as &mut dyn TrieRecorder<TrieHash<L>>),
		}
		.look_up_hash(key, NibbleSlice::new(key))
	}

	fn get_with<Q: Query<L::Hash>>(
		&self,
		key: &[u8],
		query: Q,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let mut cache = self.cache.as_ref().map(|c| c.borrow_mut());
		let mut recorder = self.recorder.as_ref().map(|r| r.borrow_mut());

		Lookup::<L, Q> {
			db: self.db,
			query,
			hash: *self.root,
			cache: cache.as_mut().map(|c| &mut ***c as &mut dyn TrieCache<L::Codec>),
			recorder: recorder.as_mut().map(|r| &mut ***r as &mut dyn TrieRecorder<TrieHash<L>>),
		}
		.look_up(key, NibbleSlice::new(key))
	}

	fn lookup_first_descendant(
		&self,
		key: &[u8],
	) -> Result<Option<MerkleValue<TrieHash<L>>>, TrieHash<L>, CError<L>> {
		let mut cache = self.cache.as_ref().map(|c| c.borrow_mut());
		let mut recorder = self.recorder.as_ref().map(|r| r.borrow_mut());

		Lookup::<L, _> {
			db: self.db,
			query: |_: &[u8]| (),
			hash: *self.root,
			cache: cache.as_mut().map(|c| &mut ***c as &mut dyn TrieCache<L::Codec>),
			recorder: recorder.as_mut().map(|r| &mut ***r as &mut dyn TrieRecorder<TrieHash<L>>),
		}
		.lookup_first_descendant(key, NibbleSlice::new(key))
	}

	fn iter<'a>(
		&'a self,
	) -> Result<
		Box<dyn TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		TrieDBIterator::new(self).map(|iter| Box::new(iter) as Box<_>)
	}

	fn key_iter<'a>(
		&'a self,
	) -> Result<
		Box<dyn TrieIterator<L, Item = TrieKeyItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		TrieDBKeyIterator::new(self).map(|iter| Box::new(iter) as Box<_>)
	}
}

// This is for pretty debug output only
#[cfg(feature = "std")]
struct TrieAwareDebugNode<'db, 'cache, 'a, L>
where
	L: TrieLayout,
{
	trie: &'db TrieDB<'db, 'cache, L>,
	node_key: NodeHandle<'a>,
	partial_key: NibbleVec,
	index: Option<u8>,
}

#[cfg(feature = "std")]
impl<'db, 'cache, 'a, L> fmt::Debug for TrieAwareDebugNode<'db, 'cache, 'a, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.trie.get_raw_or_lookup(
			<TrieHash<L>>::default(),
			self.node_key,
			self.partial_key.as_prefix(),
			false,
		) {
			Ok((owned_node, _node_hash)) => match owned_node.node() {
				Node::Leaf(slice, value) => {
					let mut disp = f.debug_struct("Node::Leaf");
					if let Some(i) = self.index {
						disp.field("index", &i);
					}
					disp.field("slice", &slice).field("value", &value);
					disp.finish()
				},
				Node::Extension(slice, item) => {
					let mut disp = f.debug_struct("Node::Extension");
					if let Some(i) = self.index {
						disp.field("index", &i);
					}
					disp.field("slice", &slice).field(
						"item",
						&TrieAwareDebugNode {
							trie: self.trie,
							node_key: item,
							partial_key: self
								.partial_key
								.clone_append_optional_slice_and_nibble(Some(&slice), None),
							index: None,
						},
					);
					disp.finish()
				},
				Node::Branch(ref nodes, ref value) => {
					let nodes: Vec<TrieAwareDebugNode<L>> = nodes
						.into_iter()
						.enumerate()
						.filter_map(|(i, n)| n.map(|n| (i, n)))
						.map(|(i, n)| TrieAwareDebugNode {
							trie: self.trie,
							index: Some(i as u8),
							node_key: n,
							partial_key: self
								.partial_key
								.clone_append_optional_slice_and_nibble(None, Some(i as u8)),
						})
						.collect();
					let mut disp = f.debug_struct("Node::Branch");
					if let Some(i) = self.index {
						disp.field("index", &i);
					}
					disp.field("nodes", &nodes).field("value", &value);
					disp.finish()
				},
				Node::NibbledBranch(slice, nodes, value) => {
					let nodes: Vec<TrieAwareDebugNode<L>> = nodes
						.iter()
						.enumerate()
						.filter_map(|(i, n)| n.map(|n| (i, n)))
						.map(|(i, n)| TrieAwareDebugNode {
							trie: self.trie,
							index: Some(i as u8),
							node_key: n,
							partial_key: self.partial_key.clone_append_optional_slice_and_nibble(
								Some(&slice),
								Some(i as u8),
							),
						})
						.collect();
					let mut disp = f.debug_struct("Node::NibbledBranch");
					if let Some(i) = self.index {
						disp.field("index", &i);
					}
					disp.field("slice", &slice).field("nodes", &nodes).field("value", &value);
					disp.finish()
				},
				Node::Empty => {
					let mut disp = f.debug_struct("Node::Empty");
					disp.finish()
				},
			},
			Err(e) => f
				.debug_struct("BROKEN_NODE")
				.field("index", &self.index)
				.field("key", &self.node_key)
				.field("error", &format!("ERROR fetching node: {}", e))
				.finish(),
		}
	}
}

#[cfg(feature = "std")]
impl<'db, 'cache, L> fmt::Debug for TrieDB<'db, 'cache, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("TrieDB")
			.field(
				"root",
				&TrieAwareDebugNode {
					trie: self,
					node_key: NodeHandle::Hash(self.root().as_ref()),
					partial_key: NibbleVec::new(),
					index: None,
				},
			)
			.finish()
	}
}

/// Iterator for going through all values in the trie in pre-order traversal order.
pub struct TrieDBIterator<'a, 'cache, L: TrieLayout> {
	db: &'a TrieDB<'a, 'cache, L>,
	raw_iter: TrieDBRawIterator<L>,
}

/// Iterator for going through all of key with values in the trie in pre-order traversal order.
pub struct TrieDBKeyIterator<'a, 'cache, L: TrieLayout> {
	db: &'a TrieDB<'a, 'cache, L>,
	raw_iter: TrieDBRawIterator<L>,
}

/// Double ended iterator for going through all of key with values in the trie in pre-order
/// traversal order.
pub struct TrieDBKeyDoubleEndedIterator<'a, 'cache, L: TrieLayout> {
	db: &'a TrieDB<'a, 'cache, L>,
	raw_iter: TrieDBRawIterator<L>,
	back_raw_iter: TrieDBRawIterator<L>,
}

impl<'a, 'cache, L: TrieLayout> TrieDBKeyDoubleEndedIterator<'a, 'cache, L> {
	/// Create a new double ended iterator.
	pub fn new(db: &'a TrieDB<'a, 'cache, L>) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(Self {
			db,
			raw_iter: TrieDBRawIterator::new(db)?,
			back_raw_iter: TrieDBRawIterator::new(db)?,
		})
	}
}

/// Double ended iterator for going through all values in the trie in pre-order traversal order.
pub struct TrieDBDoubleEndedIterator<'a, 'cache, L: TrieLayout> {
	db: &'a TrieDB<'a, 'cache, L>,
	raw_iter: TrieDBRawIterator<L>,
	back_raw_iter: TrieDBRawIterator<L>,
}

impl<'a, 'cache, L: TrieLayout> TrieDBDoubleEndedIterator<'a, 'cache, L> {
	/// Create a new double ended iterator.
	pub fn new(db: &'a TrieDB<'a, 'cache, L>) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(Self {
			db,
			raw_iter: TrieDBRawIterator::new(db)?,
			back_raw_iter: TrieDBRawIterator::new(db)?,
		})
	}

	/// Create a new iterator, but limited to a given prefix.
	pub fn new_prefixed(
		db: &'a TrieDB<'a, 'cache, L>,
		prefix: &[u8],
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(Self {
			db,
			raw_iter: TrieDBRawIterator::new_prefixed(db, prefix)?,
			back_raw_iter: TrieDBRawIterator::new_prefixed(db, prefix)?,
		})
	}
}

impl<L: TrieLayout> TrieDoubleEndedIterator<L> for TrieDBDoubleEndedIterator<'_, '_, L> {}

impl<'a, 'cache, L: TrieLayout> TrieDBIterator<'a, 'cache, L> {
	/// Create a new iterator.
	pub fn new(db: &'a TrieDB<'a, 'cache, L>) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(Self { db, raw_iter: TrieDBRawIterator::new(db)? })
	}

	/// Create a new iterator, but limited to a given prefix.
	pub fn new_prefixed(
		db: &'a TrieDB<'a, 'cache, L>,
		prefix: &[u8],
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(Self { db, raw_iter: TrieDBRawIterator::new_prefixed(db, prefix)? })
	}

	/// Create a new iterator, but limited to a given prefix.
	/// It then do a seek operation from prefixed context (using `seek` lose
	/// prefix context by default).
	pub fn new_prefixed_then_seek(
		db: &'a TrieDB<'a, 'cache, L>,
		prefix: &[u8],
		start_at: &[u8],
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(Self { db, raw_iter: TrieDBRawIterator::new_prefixed_then_seek(db, prefix, start_at)? })
	}

	/// Restore an iterator from a raw iterator.
	pub fn from_raw(db: &'a TrieDB<'a, 'cache, L>, raw_iter: TrieDBRawIterator<L>) -> Self {
		Self { db, raw_iter }
	}

	/// Convert the iterator to a raw iterator.
	pub fn into_raw(self) -> TrieDBRawIterator<L> {
		self.raw_iter
	}
}

impl<'a, 'cache, L: TrieLayout> TrieIterator<L> for TrieDBIterator<'a, 'cache, L> {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		self.raw_iter.seek(self.db, key, true).map(|_| ())
	}
}

impl<'a, 'cache, L: TrieLayout> Iterator for TrieDBIterator<'a, 'cache, L> {
	type Item = TrieItem<TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.raw_iter.next_item(self.db)
	}
}

impl<'a, 'cache, L: TrieLayout> TrieIterator<L> for TrieDBDoubleEndedIterator<'a, 'cache, L> {
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		self.raw_iter.seek(self.db, key, true).map(|_| ())?;
		self.back_raw_iter.seek(self.db, key, false).map(|_| ())
	}
}

impl<'a, 'cache, L: TrieLayout> Iterator for TrieDBDoubleEndedIterator<'a, 'cache, L> {
	type Item = TrieItem<TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.raw_iter.next_item(self.db)
	}
}

impl<'a, 'cache, L: TrieLayout> DoubleEndedIterator for TrieDBDoubleEndedIterator<'a, 'cache, L> {
	fn next_back(&mut self) -> Option<Self::Item> {
		self.back_raw_iter.prev_item(self.db)
	}
}

impl<'a, 'cache, L: TrieLayout> TrieDBKeyIterator<'a, 'cache, L> {
	/// Create a new iterator.
	pub fn new(db: &'a TrieDB<'a, 'cache, L>) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(Self { db, raw_iter: TrieDBRawIterator::new(db)? })
	}

	/// Create a new iterator, but limited to a given prefix.
	pub fn new_prefixed(
		db: &'a TrieDB<'a, 'cache, L>,
		prefix: &[u8],
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(Self { db, raw_iter: TrieDBRawIterator::new_prefixed(db, prefix)? })
	}

	/// Create a new iterator, but limited to a given prefix.
	/// It then do a seek operation from prefixed context (using `seek` lose
	/// prefix context by default).
	pub fn new_prefixed_then_seek(
		db: &'a TrieDB<'a, 'cache, L>,
		prefix: &[u8],
		start_at: &[u8],
	) -> Result<TrieDBKeyIterator<'a, 'cache, L>, TrieHash<L>, CError<L>> {
		Ok(Self { db, raw_iter: TrieDBRawIterator::new_prefixed_then_seek(db, prefix, start_at)? })
	}

	/// Restore an iterator from a raw iterator.
	pub fn from_raw(db: &'a TrieDB<'a, 'cache, L>, raw_iter: TrieDBRawIterator<L>) -> Self {
		Self { db, raw_iter }
	}

	/// Convert the iterator to a raw iterator.
	pub fn into_raw(self) -> TrieDBRawIterator<L> {
		self.raw_iter
	}
}

impl<'a, 'cache, L: TrieLayout> TrieIterator<L> for TrieDBKeyIterator<'a, 'cache, L> {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		self.raw_iter.seek(self.db, key, true).map(|_| ())
	}
}

impl<'a, 'cache, L: TrieLayout> Iterator for TrieDBKeyIterator<'a, 'cache, L> {
	type Item = TrieKeyItem<TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.raw_iter.next_key(self.db)
	}
}

impl<'a, 'cache, L: TrieLayout> TrieIterator<L> for TrieDBKeyDoubleEndedIterator<'a, 'cache, L> {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		self.raw_iter.seek(self.db, key, true).map(|_| ())?;
		self.back_raw_iter.seek(self.db, key, false).map(|_| ())
	}
}

impl<'a, 'cache, L: TrieLayout> Iterator for TrieDBKeyDoubleEndedIterator<'a, 'cache, L> {
	type Item = TrieKeyItem<TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.raw_iter.next_key(self.db)
	}
}

impl<'a, 'cache, L: TrieLayout> DoubleEndedIterator
	for TrieDBKeyDoubleEndedIterator<'a, 'cache, L>
{
	fn next_back(&mut self) -> Option<Self::Item> {
		self.back_raw_iter.prev_key(self.db)
	}
}

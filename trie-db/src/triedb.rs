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

#[cfg(feature = "std")]
use super::nibble::NibbleVec;
use super::{
	lookup::Lookup,
	node::{decode_hash, Node, NodeHandle, OwnedNode, Value},
	CError, Query, Result, Trie, TrieError, TrieHash, TrieItem, TrieIterator, TrieKeyItem,
	TrieLayout,
};
use crate::{iterator::TrieDBNodeIterator, nibble::NibbleSlice, rstd::boxed::Box, DBValue};
use hash_db::{HashDBRef, Prefix, EMPTY_PREFIX};

#[cfg(feature = "std")]
use crate::rstd::{fmt, vec::Vec};

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
/// let t = RefTrieDB::new(&memdb, &root).unwrap();
/// assert!(t.contains(b"foo").unwrap());
/// assert_eq!(t.get(b"foo").unwrap().unwrap(), b"bar".to_vec());
/// ```
pub struct TrieDB<'db, L>
where
	L: TrieLayout,
{
	db: &'db dyn HashDBRef<L::Hash, DBValue>,
	root: &'db TrieHash<L>,
	/// The number of hashes performed so far in operations on this trie.
	hash_count: usize,
}

impl<'db, L> TrieDB<'db, L>
where
	L: TrieLayout,
{
	/// Create a new trie with the backing database `db` and `root`
	/// Returns an error if `root` does not exist
	pub fn new(
		db: &'db dyn HashDBRef<L::Hash, DBValue>,
		root: &'db TrieHash<L>,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		if !db.contains(root, EMPTY_PREFIX) {
			Err(Box::new(TrieError::InvalidStateRoot(*root)))
		} else {
			Ok(TrieDB { db, root, hash_count: 0 })
		}
	}

	/// `new_with_layout`, but do not check root presence, if missing
	/// this will fail at first node access.
	pub fn new_unchecked(db: &'db dyn HashDBRef<L::Hash, DBValue>, root: &'db TrieHash<L>) -> Self {
		TrieDB { db, root, hash_count: 0 }
	}

	/// Get the backing database.
	pub fn db(&'db self) -> &'db dyn HashDBRef<L::Hash, DBValue> {
		self.db
	}

	/// Given some node-describing data `node`, and node key return the actual node RLP.
	/// This could be a simple identity operation in the case that the node is sufficiently small,
	/// but may require a database lookup.
	///
	/// Return value is the node data and the node hash if the value was looked up in the database
	/// or None if it was returned raw.
	///
	/// `partial_key` is encoded nibble slice that addresses the node.
	pub(crate) fn get_raw_or_lookup(
		&self,
		parent_hash: TrieHash<L>,
		node_handle: NodeHandle,
		partial_key: Prefix,
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
		Ok((owned_node, node_hash))
	}
}

impl<'db, L> Trie<L> for TrieDB<'db, L>
where
	L: TrieLayout,
{
	fn root(&self) -> &TrieHash<L> {
		self.root
	}

	fn get_with<'a, 'key, Q: Query<L::Hash>>(
		&'a self,
		key: &'key [u8],
		query: Q,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>>
	where
		'a: 'key,
	{
		Lookup::<L, Q> { db: self.db, query, hash: *self.root }.look_up(NibbleSlice::new(key))
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

#[cfg(feature = "std")]
// This is for pretty debug output only
struct TrieAwareDebugNode<'db, 'a, L>
where
	L: TrieLayout,
{
	trie: &'db TrieDB<'db, L>,
	node_key: NodeHandle<'a>,
	partial_key: NibbleVec,
	index: Option<u8>,
}

#[cfg(feature = "std")]
impl<'db, 'a, L> fmt::Debug for TrieAwareDebugNode<'db, 'a, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		match self.trie.get_raw_or_lookup(
			<TrieHash<L>>::default(),
			self.node_key,
			self.partial_key.as_prefix(),
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
impl<'db, L> fmt::Debug for TrieDB<'db, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("TrieDB")
			.field("hash_count", &self.hash_count)
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
pub struct TrieDBIterator<'a, L: TrieLayout> {
	inner: TrieDBNodeIterator<'a, L>,
}

/// Iterator for going through all of key with values in the trie in pre-order traversal order.
pub struct TrieDBKeyIterator<'a, L: TrieLayout> {
	inner: TrieDBNodeIterator<'a, L>,
}

/// When there is guaranties the storage backend do not change,
/// this can be use to suspend and restore the iterator.
pub struct SuspendedTrieDBKeyIterator<L: TrieLayout> {
	inner: crate::iterator::SuspendedTrieDBNodeIterator<L>,
}

impl<L: TrieLayout> SuspendedTrieDBKeyIterator<L> {
	/// Restore iterator.
	pub fn unsafe_restore<'a>(self, db: &'a TrieDB<'a, L>) -> TrieDBKeyIterator<'a, L> {
		TrieDBKeyIterator { inner: self.inner.unsafe_restore(db) }
	}
}

impl<'a, L: TrieLayout> TrieDBIterator<'a, L> {
	/// Create a new iterator.
	pub fn new(db: &'a TrieDB<L>) -> Result<TrieDBIterator<'a, L>, TrieHash<L>, CError<L>> {
		let inner = TrieDBNodeIterator::new(db)?;
		Ok(TrieDBIterator { inner })
	}

	/// Create a new iterator, but limited to a given prefix.
	pub fn new_prefixed(
		db: &'a TrieDB<L>,
		prefix: &[u8],
	) -> Result<TrieDBIterator<'a, L>, TrieHash<L>, CError<L>> {
		let mut inner = TrieDBNodeIterator::new(db)?;
		inner.prefix(prefix)?;

		Ok(TrieDBIterator { inner })
	}

	/// Create a new iterator, but limited to a given prefix.
	/// It then do a seek operation from prefixed context (using `seek` lose
	/// prefix context by default).
	pub fn new_prefixed_then_seek(
		db: &'a TrieDB<L>,
		prefix: &[u8],
		start_at: &[u8],
	) -> Result<TrieDBIterator<'a, L>, TrieHash<L>, CError<L>> {
		let mut inner = TrieDBNodeIterator::new(db)?;
		inner.prefix_then_seek(prefix, start_at)?;

		Ok(TrieDBIterator { inner })
	}
}

impl<'a, L: TrieLayout> TrieIterator<L> for TrieDBIterator<'a, L> {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		TrieIterator::seek(&mut self.inner, key)
	}
}

impl<'a, L: TrieLayout> TrieDBKeyIterator<'a, L> {
	/// Create a new iterator.
	pub fn new(db: &'a TrieDB<L>) -> Result<TrieDBKeyIterator<'a, L>, TrieHash<L>, CError<L>> {
		let inner = TrieDBNodeIterator::new(db)?;
		Ok(TrieDBKeyIterator { inner })
	}

	/// Suspend iterator. Warning this does not hold guaranties it can be restore later.
	/// Restoring require that trie backend did not change.
	pub fn suspend(self) -> SuspendedTrieDBKeyIterator<L> {
		SuspendedTrieDBKeyIterator { inner: self.inner.suspend() }
	}

	/// Create a new iterator, but limited to a given prefix.
	pub fn new_prefixed(
		db: &'a TrieDB<L>,
		prefix: &[u8],
	) -> Result<TrieDBKeyIterator<'a, L>, TrieHash<L>, CError<L>> {
		let mut inner = TrieDBNodeIterator::new(db)?;
		inner.prefix(prefix)?;

		Ok(TrieDBKeyIterator { inner })
	}

	/// Create a new iterator, but limited to a given prefix.
	/// It then do a seek operation from prefixed context (using `seek` lose
	/// prefix context by default).
	pub fn new_prefixed_then_seek(
		db: &'a TrieDB<L>,
		prefix: &[u8],
		start_at: &[u8],
	) -> Result<TrieDBKeyIterator<'a, L>, TrieHash<L>, CError<L>> {
		let mut inner = TrieDBNodeIterator::new(db)?;
		inner.prefix_then_seek(prefix, start_at)?;

		Ok(TrieDBKeyIterator { inner })
	}
}

impl<'a, L: TrieLayout> TrieIterator<L> for TrieDBKeyIterator<'a, L> {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		TrieIterator::seek(&mut self.inner, key)
	}
}

impl<'a, L: TrieLayout> Iterator for TrieDBIterator<'a, L> {
	type Item = TrieItem<'a, TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		while let Some(item) = self.inner.next() {
			match item {
				Ok((mut prefix, _, node)) => {
					let maybe_value = match node.node() {
						Node::Leaf(partial, value) => {
							prefix.append_partial(partial.right());
							Some(value)
						},
						Node::Branch(_, value) => value,
						Node::NibbledBranch(partial, _, value) => {
							prefix.append_partial(partial.right());
							value
						},
						_ => None,
					};
					if maybe_value.is_none() {
						continue
					}
					let (key_slice, maybe_extra_nibble) = prefix.as_prefix();
					let key = key_slice.to_vec();
					if let Some(extra_nibble) = maybe_extra_nibble {
						return Some(Err(Box::new(TrieError::ValueAtIncompleteKey(
							key,
							extra_nibble,
						))))
					}
					let value = match maybe_value.expect("None checked above.") {
						Value::Node(hash, None) => {
							if let Some(value) = self.inner.fetch_value(&hash, (key_slice, None)) {
								value
							} else {
								let mut res = TrieHash::<L>::default();
								res.as_mut().copy_from_slice(hash);
								return Some(Err(Box::new(TrieError::IncompleteDatabase(res))))
							}
						},
						Value::Inline(value) => value.to_vec(),
						Value::Node(_hash, Some(value)) => value,
					};
					return Some(Ok((key, value)))
				},
				Err(err) => return Some(Err(err)),
			}
		}
		None
	}
}

impl<'a, L: TrieLayout> Iterator for TrieDBKeyIterator<'a, L> {
	type Item = TrieKeyItem<'a, TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		while let Some(item) = self.inner.next() {
			match item {
				Ok((mut prefix, _, node)) => {
					let maybe_value = match node.node() {
						Node::Leaf(partial, value) => {
							prefix.append_partial(partial.right());
							Some(value)
						},
						Node::Branch(_, value) => value,
						Node::NibbledBranch(partial, _, value) => {
							prefix.append_partial(partial.right());
							value
						},
						_ => None,
					};
					if maybe_value.is_none() {
						continue
					} else {
						let (key_slice, maybe_extra_nibble) = prefix.as_prefix();
						let key = key_slice.to_vec();
						if let Some(extra_nibble) = maybe_extra_nibble {
							return Some(Err(Box::new(TrieError::ValueAtIncompleteKey(
								key,
								extra_nibble,
							))))
						}
						return Some(Ok(key))
					}
				},
				Err(err) => return Some(Err(err)),
			}
		}
		None
	}
}

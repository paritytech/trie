// Copyright 2017, 2020 Parity Technologies
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

use hash_db::{HashDBRef, Prefix, EMPTY_PREFIX};
use crate::nibble::NibbleSlice;
use crate::iterator::TrieDBNodeIterator;
use crate::rstd::boxed::Box;
use crate::{DBValue, GlobalMeta};
use super::node::{NodeHandle, Node, Value, OwnedNode, decode_hash};
use super::lookup::Lookup;
use super::{Result, Trie, TrieItem, TrieKeyItem, TrieError, TrieIterator, Query,
	TrieLayout, CError, TrieHash};
use super::nibble::NibbleVec;

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
	layout: L,
	db: &'db dyn HashDBRef<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
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
		db: &'db dyn HashDBRef<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		root: &'db TrieHash<L>,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Self::new_with_layout(db, root, Default::default())
	}

	/// Create a new trie with backing database `db` and empty `root`.
	/// Returns an error if `root` does not exist
	/// This can use a context specific layout.
	pub fn new_with_layout(
		db: &'db dyn HashDBRef<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		root: &'db TrieHash<L>,
		mut layout: L,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		if L::READ_ROOT_STATE_META {
			if let Some((encoded, mut meta)) = db.get_with_meta(root, EMPTY_PREFIX, layout.layout_meta()) {
				// read state meta
				use crate::node_codec::NodeCodec;
				let _ = L::Codec::decode_plan(encoded.as_slice(), &mut meta)
					.map_err(|e| Box::new(TrieError::DecoderError(*root, e)))?;
				layout.initialize_from_root_meta(&meta);
				Ok(TrieDB {db, root, hash_count: 0, layout})
			} else {
				Err(Box::new(TrieError::InvalidStateRoot(*root)))
			}
		} else if !db.contains(root, EMPTY_PREFIX) {
			Err(Box::new(TrieError::InvalidStateRoot(*root)))
		} else {
			Ok(TrieDB {db, root, hash_count: 0, layout})
		}
	}

	/// Get the backing database.
	pub fn db(&'db self) -> &'db dyn HashDBRef<L::Hash, DBValue, L::Meta, GlobalMeta<L>> {
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
	) -> Result<(OwnedNode<DBValue>, Option<TrieHash<L>>, L::Meta), TrieHash<L>, CError<L>> {
		let (node_hash, node_data, mut meta) = match node_handle {
			NodeHandle::Hash(data) => {
				let node_hash = decode_hash::<L::Hash>(data)
					.ok_or_else(|| Box::new(TrieError::InvalidHash(parent_hash, data.to_vec())))?;
				let (node_data, meta) = self.db
					.get_with_meta(&node_hash, partial_key, self.layout.layout_meta())
					.ok_or_else(|| {
						if partial_key == EMPTY_PREFIX {
							Box::new(TrieError::InvalidStateRoot(node_hash))
						} else {
							Box::new(TrieError::IncompleteDatabase(node_hash))
						}
					})?;

				(Some(node_hash), node_data, meta)
			}
			NodeHandle::Inline(data) => (None, data.to_vec(), self.layout.meta_for_stored_inline_node()),
		};
		let owned_node = OwnedNode::new::<L::Meta, L::Codec>(node_data, &mut meta)
			.map_err(|e| Box::new(TrieError::DecoderError(node_hash.unwrap_or(parent_hash), e)))?;
		Ok((owned_node, node_hash, meta))
	}

	/// Get current value of Trie layout.
	pub fn layout(&self) -> L {
		self.layout.clone()
	}
}

impl<'db, L> Trie<L> for TrieDB<'db, L>
where
	L: TrieLayout,
{
	fn root(&self) -> &TrieHash<L> { self.root }

	fn get_with<'a, 'key, Q: Query<L::Hash, L::Meta>>(
		&'a self,
		key: &'key [u8],
		query: Q,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>>
		where 'a: 'key,
	{
		Lookup::<L, Q> {
			db: self.db,
			query,
			hash: *self.root,
			layout: self.layout.clone(),
		}.look_up(NibbleSlice::new(key))
	}

	fn iter<'a>(&'a self)-> Result<
		Box<dyn TrieIterator<L, Item=TrieItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		TrieDBIterator::new(self).map(|iter| Box::new(iter) as Box<_>)
	}

	fn key_iter<'a>(&'a self)-> Result<
		Box<dyn TrieIterator<L, Item=TrieKeyItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		TrieDBKeyIterator::new(self).map(|iter| Box::new(iter) as Box<_>)
	}
}


#[cfg(feature="std")]
// This is for pretty debug output only
struct TrieAwareDebugNode<'db, 'a, L>
where
	L: TrieLayout,
{
	trie: &'db TrieDB<'db, L>,
	node_key: NodeHandle<'a>,
	partial_key: NibbleVec,
	index: Option<u8>,
	show_meta: bool,
}

#[cfg(feature="std")]
impl<'db, 'a, L> fmt::Debug for TrieAwareDebugNode<'db, 'a, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let show_meta = self.show_meta;
		match self.trie.get_raw_or_lookup(
			<TrieHash<L>>::default(),
			self.node_key,
			self.partial_key.as_prefix()
		) {
			Ok((owned_node, _node_hash, meta)) => match owned_node.node() {
				Node::Leaf(slice, value) => {
					let mut disp = f.debug_struct("Node::Leaf");
					if let Some(i) = self.index {
						disp.field("index", &i);
					}
					disp.field("slice", &slice)
						.field("value", &value);
					if show_meta {
						disp.field("meta", &meta);
					}
					disp.finish()
				},
				Node::Extension(slice, item) => {
					let mut disp = f.debug_struct("Node::Extension");
					if let Some(i) = self.index {
						disp.field("index", &i);
					}
					disp.field("slice", &slice)
						.field("item", &TrieAwareDebugNode {
							trie: self.trie,
							node_key: item,
							partial_key: self.partial_key
								.clone_append_optional_slice_and_nibble(Some(&slice), None),
							index: None,
							show_meta,
						});
					if show_meta {
						disp.field("meta", &meta);
					}
					disp.finish()
				},
				Node::Branch(ref nodes, ref value) => {
					let nodes: Vec<TrieAwareDebugNode<L>> = nodes.into_iter()
						.enumerate()
						.filter_map(|(i, n)| n.map(|n| (i, n)))
						.map(|(i, n)| TrieAwareDebugNode {
							trie: self.trie,
							index: Some(i as u8),
							node_key: n,
							partial_key: self.partial_key
								.clone_append_optional_slice_and_nibble(None, Some(i as u8)),
							show_meta,
						})
						.collect();
					let mut disp = f.debug_struct("Node::Branch");
					if let Some(i) = self.index {
						disp.field("index", &i);
					}
					disp.field("nodes", &nodes)
						.field("value", &value);
					if show_meta {
						disp.field("meta", &meta);
					}
					disp.finish()
				},
				Node::NibbledBranch(slice, nodes, value) => {
					let nodes: Vec<TrieAwareDebugNode<L>> = nodes.iter()
						.enumerate()
						.filter_map(|(i, n)| n.map(|n| (i, n)))
						.map(|(i, n)| TrieAwareDebugNode {
							trie: self.trie,
							index: Some(i as u8),
							node_key: n,
							partial_key: self.partial_key
								.clone_append_optional_slice_and_nibble(Some(&slice), Some(i as u8)),
							show_meta,
						}).collect();
					let mut disp = f.debug_struct("Node::NibbledBranch");
					if let Some(i) = self.index {
						disp.field("index", &i);
					}
					disp.field("slice", &slice)
						.field("nodes", &nodes)
						.field("value", &value);
					if show_meta {
						disp.field("meta", &meta);
					}
					disp.finish()
				},
				Node::Empty => {
					let mut disp = f.debug_struct("Node::Empty");
					if show_meta {
						disp.field("meta", &meta);
					}
					disp.finish()
				},
			},
			Err(e) => f.debug_struct("BROKEN_NODE")
				.field("index", &self.index)
				.field("key", &self.node_key)
				.field("error", &format!("ERROR fetching node: {}", e))
				.finish(),
		}
	}
}

#[cfg(feature="std")]
impl<'db, L> fmt::Debug for TrieDB<'db, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("TrieDB")
			.field("hash_count", &self.hash_count)
			.field("root", &TrieAwareDebugNode {
				trie: self,
				node_key: NodeHandle::Hash(self.root().as_ref()),
				partial_key: NibbleVec::new(),
				index: None,
				show_meta: false,
			})
			.finish()
	}
}

/// Use this struct to display a trie with associated
/// nodes metas.
#[cfg(feature="std")]
pub struct DebugWithMeta<'db, L: TrieLayout>(pub &'db TrieDB<'db, L>);

#[cfg(feature="std")]
impl<'db, L> fmt::Debug for DebugWithMeta<'db, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		f.debug_struct("TrieDBWithMeta")
			.field("hash_count", &self.0.hash_count)
			.field("root", &TrieAwareDebugNode {
				trie: self.0,
				node_key: NodeHandle::Hash(self.0.root().as_ref()),
				partial_key: NibbleVec::new(),
				index: None,
				show_meta: true,
			})
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

impl<'a, L: TrieLayout> TrieDBIterator<'a, L> {
	/// Create a new iterator.
	pub fn new(db: &'a TrieDB<L>) -> Result<TrieDBIterator<'a, L>, TrieHash<L>, CError<L>> {
		let inner = TrieDBNodeIterator::new(db)?;
		Ok(TrieDBIterator { inner })
	}

	/// Create a new iterator, but limited to a given prefix.
	pub fn new_prefixed(db: &'a TrieDB<L>, prefix: &[u8]) -> Result<TrieDBIterator<'a, L>, TrieHash<L>, CError<L>> {
		let mut inner = TrieDBNodeIterator::new(db)?;
		inner.prefix(prefix)?;

		Ok(TrieDBIterator {
			inner,
		})
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

	/// Create a new iterator, but limited to a given prefix.
	pub fn new_prefixed(db: &'a TrieDB<L>, prefix: &[u8]) -> Result<TrieDBKeyIterator<'a, L>, TrieHash<L>, CError<L>> {
		let mut inner = TrieDBNodeIterator::new(db)?;
		inner.prefix(prefix)?;

		Ok(TrieDBKeyIterator {
			inner,
		})
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
				Ok((mut prefix, node_key, _meta, node)) => {
					let maybe_value = match node.node() {
						Node::Leaf(partial, value) => {
							prefix.append_partial(partial.right());
							value
						}
						Node::Branch(_, value) => value,
						Node::NibbledBranch(partial, _, value) => {
							prefix.append_partial(partial.right());
							value
						}
						_ => Value::NoValue,
					};
					match &maybe_value {
						Value::Value(_value) =>  {
							if let Some(key) = node_key.as_ref() {
								self.inner.db().access_from(key, None);
							}
						},
						Value::HashedValue(hash, _) =>  {
							let mut res = TrieHash::<L>::default();
							res.as_mut().copy_from_slice(hash);
							if let Some(key) = node_key.as_ref() {
								if let Some(_) = self.inner.db().access_from(key, Some(&res)) {
									unimplemented!("Reinject value in value and continue");
								}
							}

							return Some(Err(Box::new(
								TrieError::IncompleteDatabase(res)
							)));
						},
						Value::NoValue => (),
					}
					if let Value::Value(value) = maybe_value {
						let (key_slice, maybe_extra_nibble) = prefix.as_prefix();
						let key = key_slice.to_vec();
						if let Some(extra_nibble) = maybe_extra_nibble {
							return Some(Err(Box::new(
								TrieError::ValueAtIncompleteKey(key, extra_nibble)
							)));
						}
						return Some(Ok((key, value.to_vec())));
					}
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
				Ok((mut prefix, _, _, node)) => {
					let maybe_value = match node.node() {
						Node::Leaf(partial, value) => {
							prefix.append_partial(partial.right());
							value
						}
						Node::Branch(_, value) => value,
						Node::NibbledBranch(partial, _, value) => {
							prefix.append_partial(partial.right());
							value
						}
						_ => Value::NoValue,
					};
					if let Value::NoValue = maybe_value {
						continue;
					} else {
						let (key_slice, maybe_extra_nibble) = prefix.as_prefix();
						let key = key_slice.to_vec();
						if let Some(extra_nibble) = maybe_extra_nibble {
							return Some(Err(Box::new(
								TrieError::ValueAtIncompleteKey(key, extra_nibble)
							)));
						}
						return Some(Ok(key));
					}
				},
				Err(err) => return Some(Err(err)),
			}
		}
		None
	}
}

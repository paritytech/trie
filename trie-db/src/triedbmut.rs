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

//! In-memory trie representation.

use super::{DBValue, node::NodeKey};
use super::{Result, TrieError, TrieMut, TrieLayout, TrieHash, CError};
use super::lookup::Lookup;
use super::node::{NodeHandle as EncodedNodeHandle, Node as EncodedNode, decode_hash};

use crate::node_codec::HashDBComplexDyn;
use hash_db::{HashDB, Hasher, Prefix, EMPTY_PREFIX};
use hashbrown::HashSet;

use crate::node_codec::{NodeCodec, EncodedNoChild};
use crate::nibble::{NibbleVec, NibbleSlice, nibble_ops, BackingByteVec};
use crate::rstd::{
	boxed::Box, convert::TryFrom, hash::Hash, mem, ops::Index, result, vec::Vec, VecDeque,
	ops::Range,
};

#[cfg(feature = "std")]
use log::trace;

#[cfg(feature = "std")]
use crate::rstd::fmt::{self, Debug};


// For lookups into the Node storage buffer.
// This is deliberately non-copyable.
#[cfg_attr(feature = "std", derive(Debug))]
struct StorageHandle(usize);

// Handles to nodes in the trie.
#[cfg_attr(feature = "std", derive(Debug))]
enum NodeHandle<H> {
	/// Loaded into memory.
	InMemory(StorageHandle),
	/// Either a hash or an inline node
	Hash(H),
}

impl<H> From<StorageHandle> for NodeHandle<H> {
	fn from(handle: StorageHandle) -> Self {
		NodeHandle::InMemory(handle)
	}
}

fn empty_children<H>() -> Box<[Option<NodeHandle<H>>; 16]> {
	Box::new([
		None, None, None, None, None, None, None, None,
		None, None, None, None, None, None, None, None,
	])
}

/// Type alias to indicate the nible covers a full key,
/// therefore its left side is a full prefix.
type NibbleFullKey<'key> = NibbleSlice<'key>;

/// Node types in the Trie.
enum Node<H> {
	/// Empty node.
	Empty,
	/// A leaf node contains the end of a key and a value.
	/// This key is encoded from a `NibbleSlice`, meaning it contains
	/// a flag indicating it is a leaf.
	Leaf(NodeKey, DBValue),
	/// An extension contains a shared portion of a key and a child node.
	/// The shared portion is encoded from a `NibbleSlice` meaning it contains
	/// a flag indicating it is an extension.
	/// The child node is always a branch.
	Extension(NodeKey, NodeHandle<H>),
	/// A branch has up to 16 children and an optional value.
	Branch(Box<[Option<NodeHandle<H>>; 16]>, Option<DBValue>),
	/// Branch node with support for a nibble (to avoid extension node).
	NibbledBranch(NodeKey, Box<[Option<NodeHandle<H>>; 16]>, Option<DBValue>),
}

#[cfg(feature = "std")]
struct ToHex<'a>(&'a [u8]);
#[cfg(feature = "std")]
impl<'a> Debug for ToHex<'a> {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		let hex = rustc_hex::ToHexIter::new(self.0.iter());
		for b in hex {
			write!(fmt, "{}", b)?;
		}
		Ok(())
	}
}

#[cfg(feature = "std")]
impl<H: Debug> Debug for Node<H> {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Self::Empty => write!(fmt, "Empty"),
			Self::Leaf((ref a, ref b), ref c) =>
				write!(fmt, "Leaf({:?}, {:?})", (a, ToHex(&*b)), ToHex(&*c)),
			Self::Extension((ref a, ref b), ref c) =>
				write!(fmt, "Extension({:?}, {:?})", (a, ToHex(&*b)), c),
			Self::Branch(ref a, ref b) =>
				write!(fmt, "Branch({:?}, {:?}", a, b.as_ref().map(Vec::as_slice).map(ToHex)),
			Self::NibbledBranch((ref a, ref b), ref c, ref d) =>
				write!(fmt, "NibbledBranch({:?}, {:?}, {:?})", (a, ToHex(&*b)), c, d.as_ref().map(Vec::as_slice).map(ToHex)),
		}
	}
}

impl<O> Node<O>
where
	O: AsRef<[u8]> + AsMut<[u8]> + Default + crate::MaybeDebug
		+ PartialEq + Eq + Hash + Send + Sync + Clone + Copy
{
	// load an inline node into memory or get the hash to do the lookup later.
	fn inline_or_hash<C, H>(
		parent_hash: H::Out,
		child: EncodedNodeHandle,
		db: &dyn HashDBComplexDyn<H, DBValue>,
		storage: &mut NodeStorage<H::Out>
	) -> Result<NodeHandle<H::Out>, H::Out, C::Error>
	where
		C: NodeCodec<HashOut=O>,
		H: Hasher<Out=O>,
	{
		let handle = match child {
			EncodedNodeHandle::Hash(data) => {
				let hash = decode_hash::<H>(data)
					.ok_or_else(|| Box::new(TrieError::InvalidHash(parent_hash, data.to_vec())))?;
				NodeHandle::Hash(hash)
			},
			EncodedNodeHandle::Inline(data) => {
				let child = Node::from_encoded::<C, H>(parent_hash, data, db, storage)?;
				NodeHandle::InMemory(storage.alloc(Stored::New(child)))
			},
		};
		Ok(handle)
	}

	// Decode a node from encoded bytes.
	fn from_encoded<'a, 'b, C, H>(
		node_hash: H::Out,
		data: &'a[u8],
		db: &dyn HashDBComplexDyn<H, DBValue>,
		storage: &'b mut NodeStorage<H::Out>,
	) -> Result<Self, H::Out, C::Error>
		where
			C: NodeCodec<HashOut = O>, H: Hasher<Out = O>,
	{
		let encoded_node = C::decode(data)
			.map_err(|e| Box::new(TrieError::DecoderError(node_hash, e)))?;
		let node = match encoded_node {
			EncodedNode::Empty => Node::Empty,
			EncodedNode::Leaf(k, v) => Node::Leaf(k.into(), v.to_vec()),
			EncodedNode::Extension(key, cb) => {
				Node::Extension(
					key.into(),
					Self::inline_or_hash::<C, H>(node_hash, cb, db, storage)?
				)
			},
			EncodedNode::Branch(encoded_children, val) => {
				let mut child = |i:usize| match encoded_children[i] {
					Some(child) => Self::inline_or_hash::<C, H>(node_hash, child, db, storage)
						.map(Some),
					None => Ok(None),
				};

				let children = Box::new([
					child(0)?, child(1)?, child(2)?, child(3)?,
					child(4)?, child(5)?, child(6)?, child(7)?,
					child(8)?, child(9)?, child(10)?, child(11)?,
					child(12)?, child(13)?, child(14)?, child(15)?,
				]);

				Node::Branch(children, val.map(|v| v.to_vec()))
			},
			EncodedNode::NibbledBranch(k, encoded_children, val) => {
				let mut child = |i:usize| match encoded_children[i] {
					Some(child) => Self::inline_or_hash::<C, H>(node_hash, child, db, storage)
						.map(Some),
					None => Ok(None),
				};

				let children = Box::new([
					child(0)?, child(1)?, child(2)?, child(3)?,
					child(4)?, child(5)?, child(6)?, child(7)?,
					child(8)?, child(9)?, child(10)?, child(11)?,
					child(12)?, child(13)?, child(14)?, child(15)?,
				]);

				Node::NibbledBranch(k.into(), children, val.map(|v| v.to_vec()))
			},
		};
		Ok(node)
	}

	// TODO: parallelize
	fn into_encoded<F, C, H>(
		self,
		mut child_cb: F,
		register_children: Option<&mut [Option<Range<usize>>]>,
	) -> (Vec<u8>, EncodedNoChild) where
		C: NodeCodec<HashOut=O>,
		F: FnMut(NodeHandle<H::Out>, Option<&NibbleSlice>, Option<u8>) -> ChildReference<H::Out>,
		H: Hasher<Out = O>,
	{
		match self {
			Node::Empty => (C::empty_node().to_vec(), EncodedNoChild::Unused),
			Node::Leaf(partial, value) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				(C::leaf_node(pr.right(), &value), EncodedNoChild::Unused)
			},
			Node::Extension(partial, child) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				let it = pr.right_iter();
				let c = child_cb(child, Some(&pr), None);
				(C::extension_node(
					it,
					pr.len(),
					c,
				), EncodedNoChild::Unused)
			},
			Node::Branch(mut children, value) => {
				C::branch_node(
					// map the `NodeHandle`s from the Branch to `ChildReferences`
					children.iter_mut()
						.map(Option::take)
						.enumerate()
						.map(|(i, maybe_child)| {
							maybe_child.map(|child| child_cb(child, None, Some(i as u8)))
						}),
					value.as_ref().map(|v| &v[..]),
					register_children,
				)
			},
			Node::NibbledBranch(partial, mut children, value) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				let it = pr.right_iter();
				C::branch_node_nibbled(
					it,
					pr.len(),
					// map the `NodeHandle`s from the Branch to `ChildReferences`
					children.iter_mut()
						.map(Option::take)
						.enumerate()
						.map(|(i, maybe_child)| {
							//let branch_index = [i as u8];
							maybe_child.map(|child| {
								let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
								child_cb(child, Some(&pr), Some(i as u8))
							})
						}),
					value.as_ref().map(|v| &v[..]),
					register_children,
				)
			},
		}
	}
}

// post-inspect action.
enum Action<H> {
	// Replace a node with a new one.
	Replace(Node<H>),
	// Restore the original node. This trusts that the node is actually the original.
	Restore(Node<H>),
	// if it is a new node, just clears the storage.
	Delete,
}

// post-insert action. Same as action without delete
enum InsertAction<H> {
	// Replace a node with a new one.
	Replace(Node<H>),
	// Restore the original node.
	Restore(Node<H>),
}

impl<H> InsertAction<H> {
	fn into_action(self) -> Action<H> {
		match self {
			InsertAction::Replace(n) => Action::Replace(n),
			InsertAction::Restore(n) => Action::Restore(n),
		}
	}

	// unwrap the node, disregarding replace or restore state.
	fn unwrap_node(self) -> Node<H> {
		match self {
			InsertAction::Replace(n) | InsertAction::Restore(n) => n,
		}
	}
}

// What kind of node is stored here.
enum Stored<H> {
	// A new node.
	New(Node<H>),
	// A cached node, loaded from the DB.
	Cached(Node<H>, H),
}

/// Used to build a collection of child nodes from a collection of `NodeHandle`s
#[derive(Clone, Copy)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ChildReference<HO> { // `HO` is e.g. `H256`, i.e. the output of a `Hasher`
	Hash(HO),
	Inline(HO, usize), // usize is the length of the node data we store in the `H::Out`
}

impl<'a, HO> TryFrom<EncodedNodeHandle<'a>> for ChildReference<HO>
	where HO: AsRef<[u8]> + AsMut<[u8]> + Default + Clone + Copy
{
	type Error = Vec<u8>;

	fn try_from(handle: EncodedNodeHandle<'a>) -> result::Result<Self, Vec<u8>> {
		match handle {
			EncodedNodeHandle::Hash(data) => {
				let mut hash = HO::default();
				if data.len() != hash.as_ref().len() {
					return Err(data.to_vec());
				}
				hash.as_mut().copy_from_slice(data);
				Ok(ChildReference::Hash(hash))
			}
			EncodedNodeHandle::Inline(data) => {
				let mut hash = HO::default();
				if data.len() > hash.as_ref().len() {
					return Err(data.to_vec());
				}
				&mut hash.as_mut()[..data.len()].copy_from_slice(data);
				Ok(ChildReference::Inline(hash, data.len()))
			}
		}
	}
}

/// Compact and cache-friendly storage for Trie nodes.
struct NodeStorage<H> {
	nodes: Vec<Stored<H>>,
	free_indices: VecDeque<usize>,
}

impl<H> NodeStorage<H> {
	/// Create a new storage.
	fn empty() -> Self {
		NodeStorage {
			nodes: Vec::new(),
			free_indices: VecDeque::new(),
		}
	}

	/// Allocate a new node in the storage.
	fn alloc(&mut self, stored: Stored<H>) -> StorageHandle {
		if let Some(idx) = self.free_indices.pop_front() {
			self.nodes[idx] = stored;
			StorageHandle(idx)
		} else {
			self.nodes.push(stored);
			StorageHandle(self.nodes.len() - 1)
		}
	}

	/// Remove a node from the storage, consuming the handle and returning the node.
	fn destroy(&mut self, handle: StorageHandle) -> Stored<H> {
		let idx = handle.0;

		self.free_indices.push_back(idx);
		mem::replace(&mut self.nodes[idx], Stored::New(Node::Empty))
	}
}

impl<'a, H> Index<&'a StorageHandle> for NodeStorage<H> {
	type Output = Node<H>;

	fn index(&self, handle: &'a StorageHandle) -> &Node<H> {
		match self.nodes[handle.0] {
			Stored::New(ref node) => node,
			Stored::Cached(ref node, _) => node,
		}
	}
}

/// A `Trie` implementation using a generic `HashDBComplexDyn` backing database.
///
/// Use it as a `TrieMut` trait object. You can use `db()` to get the backing database object.
/// Note that changes are not committed to the database until `commit` is called.
///
/// Querying the root or dropping the trie will commit automatically.
///
///
/// # Example
/// ```
/// use hash_db::Hasher;
/// use reference_trie::{RefTrieDBMut, TrieMut};
/// use trie_db::DBValue;
/// use keccak_hasher::KeccakHasher;
/// use memory_db::*;
///
/// let mut memdb = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
/// let mut root = Default::default();
/// let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
/// assert!(t.is_empty());
/// assert_eq!(*t.root(), KeccakHasher::hash(&[0u8][..]));
/// t.insert(b"foo", b"bar").unwrap();
/// assert!(t.contains(b"foo").unwrap());
/// assert_eq!(t.get(b"foo").unwrap().unwrap(), b"bar".to_vec());
/// t.remove(b"foo").unwrap();
/// assert!(!t.contains(b"foo").unwrap());
/// ```
pub struct TrieDBMut<'a, L>
where
	L: TrieLayout,
{
	storage: NodeStorage<TrieHash<L>>,
	db: &'a mut dyn HashDBComplexDyn<L::Hash, DBValue>,
	root: &'a mut TrieHash<L>,
	root_handle: NodeHandle<TrieHash<L>>,
	death_row: HashSet<(TrieHash<L>, (BackingByteVec, Option<u8>))>,
	/// The number of hash operations this trie has performed.
	/// Note that none are performed until changes are committed.
	hash_count: usize,
}

impl<'a, L> TrieDBMut<'a, L>
where
	L: TrieLayout,
{
	#[inline]
	fn register_children_buf(node: &Node<TrieHash<L>>) -> Option<[Option<Range<usize>>; 16]> {
		match node {
			Node::NibbledBranch(..) | Node::Branch(..) => if L::COMPLEX_HASH {
				Some(Default::default())
			} else {
				None
			},
			_ => None,
		}
		
	}
	/// Create a new trie with backing database `db` and empty `root`.
	pub fn new(db: &'a mut dyn HashDBComplexDyn<L::Hash, DBValue>, root: &'a mut TrieHash<L>) -> Self {
		*root = L::Codec::hashed_null_node();
		let root_handle = NodeHandle::Hash(L::Codec::hashed_null_node());

		TrieDBMut {
			storage: NodeStorage::empty(),
			db,
			root,
			root_handle,
			death_row: HashSet::new(),
			hash_count: 0,
		}
	}

	/// Create a new trie with the backing database `db` and `root.
	/// Returns an error if `root` does not exist.
	pub fn from_existing(
		db: &'a mut dyn HashDBComplexDyn<L::Hash, DBValue>,
		root: &'a mut TrieHash<L>,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		if !db.contains(root, EMPTY_PREFIX) {
			return Err(Box::new(TrieError::InvalidStateRoot(*root)));
		}

		let root_handle = NodeHandle::Hash(*root);
		Ok(TrieDBMut {
			storage: NodeStorage::empty(),
			db,
			root,
			root_handle,
			death_row: HashSet::new(),
			hash_count: 0,
		})
	}
	/// Get the backing database.
	pub fn db(&self) -> &dyn HashDBComplexDyn<L::Hash, DBValue> {
		self.db
	}

	/// Get the backing database mutably.
	pub fn db_mut(&mut self) -> &mut dyn HashDBComplexDyn<L::Hash, DBValue> {
		self.db
	}

	// Cache a node by hash.
	fn cache(
		&mut self,
		hash: TrieHash<L>,
		key: Prefix,
	) -> Result<StorageHandle, TrieHash<L>, CError<L>> {
		let node_encoded = self.db.get(&hash, key)
			.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(hash)))?;
		let node = Node::from_encoded::<L::Codec, L::Hash>(
			hash,
			&node_encoded,
			&*self.db,
			&mut self.storage
		)?;
		Ok(self.storage.alloc(Stored::Cached(node, hash)))
	}

	// Inspect a node, choosing either to replace, restore, or delete it.
	// If restored or replaced, returns the new node along with a flag of whether it was changed.
	fn inspect<F>(
		&mut self,
		stored: Stored<TrieHash<L>>,
		key: &mut NibbleFullKey,
		inspector: F,
	) -> Result<Option<(Stored<TrieHash<L>>, bool)>, TrieHash<L>, CError<L>>
		where
			F: FnOnce(
				&mut Self,
				Node<TrieHash<L>>,
				&mut NibbleFullKey,
			) -> Result<Action<TrieHash<L>>, TrieHash<L>, CError<L>>,
	{
		Ok(match stored {
			Stored::New(node) => match inspector(self, node, key)? {
				Action::Restore(node) => Some((Stored::New(node), false)),
				Action::Replace(node) => Some((Stored::New(node), true)),
				Action::Delete => None,
			},
			Stored::Cached(node, hash) => match inspector(self, node, key)? {
				Action::Restore(node) => Some((Stored::Cached(node, hash), false)),
				Action::Replace(node) => {
					self.death_row.insert((hash, key.left_owned()));
					Some((Stored::New(node), true))
				}
				Action::Delete => {
					self.death_row.insert((hash, key.left_owned()));
					None
				}
			},
		})
	}

	// Walk the trie, attempting to find the key's node.
	fn lookup<'x, 'key>(
		&'x self,
		mut partial: NibbleSlice<'key>,
		handle: &NodeHandle<TrieHash<L>>,
	) -> Result<Option<DBValue>, TrieHash<L>, CError<L>>
		where 'x: 'key
	{
		let mut handle = handle;
		loop {
			let (mid, child) = match *handle {
				NodeHandle::Hash(ref hash) => return Lookup::<L, _> {
					db: &self.db,
					query: |v: &[u8]| v.to_vec(),
					hash: hash.clone(),
				}.look_up(partial),
				NodeHandle::InMemory(ref handle) => match self.storage[handle] {
					Node::Empty => return Ok(None),
					Node::Leaf(ref key, ref value) => {
						if NibbleSlice::from_stored(key) == partial {
							return Ok(Some(value.to_vec()));
						} else {
							return Ok(None);
						}
					},
					Node::Extension(ref slice, ref child) => {
						let slice = NibbleSlice::from_stored(slice);
						if partial.starts_with(&slice) {
							(slice.len(), child)
						} else {
							return Ok(None);
						}
					},
					Node::Branch(ref children, ref value) => {
						if partial.is_empty() {
							return Ok(value.as_ref().map(|v| v.to_vec()));
						} else {
							let idx = partial.at(0);
							match children[idx as usize].as_ref() {
								Some(child) => (1, child),
								None => return Ok(None),
							}
						}
					},
					Node::NibbledBranch(ref slice, ref children, ref value) => {
						let slice = NibbleSlice::from_stored(slice);
						if partial.is_empty() {
							return Ok(value.as_ref().map(|v| v.to_vec()));
						} else if partial.starts_with(&slice) {
							let idx = partial.at(0);
							match children[idx as usize].as_ref() {
								Some(child) => (1 + slice.len(), child),
								None => return Ok(None),
							}
						} else {
							return Ok(None)
						}
					},
				}
			};

			partial = partial.mid(mid);
			handle = child;
		}
	}

	/// Insert a key-value pair into the trie, creating new nodes if necessary.
	fn insert_at(
		&mut self,
		handle: NodeHandle<TrieHash<L>>,
		key: &mut NibbleFullKey,
		value: DBValue,
		old_val: &mut Option<DBValue>,
	) -> Result<(StorageHandle, bool), TrieHash<L>, CError<L>> {
		let h = match handle {
			NodeHandle::InMemory(h) => h,
			NodeHandle::Hash(h) => self.cache(h, key.left())?,
		};
		// cache then destroy for hash handle (handle being root in most case)
		let stored = self.storage.destroy(h);
		let (new_stored, changed) = self.inspect(stored, key, move |trie, stored, key| {
			trie.insert_inspector(stored, key, value, old_val).map(|a| a.into_action())
		})?.expect("Insertion never deletes.");

		Ok((self.storage.alloc(new_stored), changed))
	}

	/// The insertion inspector.
	fn insert_inspector(
		&mut self,
		node: Node<TrieHash<L>>,
		key: &mut NibbleFullKey,
		value: DBValue,
		old_val: &mut Option<DBValue>,
	) -> Result<InsertAction<TrieHash<L>>, TrieHash<L>, CError<L>> {
		let partial = key.clone();

		#[cfg(feature = "std")]
		trace!(target: "trie", "augmented (partial: {:?}, value: {:?})", partial, ToHex(&value));

		Ok(match node {
			Node::Empty => {
				#[cfg(feature = "std")]
				trace!(target: "trie", "empty: COMPOSE");
				InsertAction::Replace(Node::Leaf(partial.to_stored(), value))
			},
			Node::Branch(mut children, stored_value) => {
				debug_assert!(L::USE_EXTENSION);
				#[cfg(feature = "std")]
				trace!(target: "trie", "branch: ROUTE,AUGMENT");

				if partial.is_empty() {
					let unchanged = stored_value.as_ref() == Some(&value);
					let branch = Node::Branch(children, Some(value));
					*old_val = stored_value;

					match unchanged {
						true => InsertAction::Restore(branch),
						false => InsertAction::Replace(branch),
					}
				} else {
					let idx = partial.at(0) as usize;
					key.advance(1);
					if let Some(child) = children[idx].take() {
						// Original had something there. recurse down into it.
						let (new_child, changed) = self.insert_at(child, key, value, old_val)?;
						children[idx] = Some(new_child.into());
						if !changed {
							// The new node we composed didn't change.
							// It means our branch is untouched too.
							return Ok(InsertAction::Restore(Node::Branch(children, stored_value)));
						}
					} else {
						// Original had nothing there. compose a leaf.
						let leaf = self.storage.alloc(
							Stored::New(Node::Leaf(key.to_stored(), value))
						);
						children[idx] = Some(leaf.into());
					}

					InsertAction::Replace(Node::Branch(children, stored_value))
				}
			},
			Node::NibbledBranch(encoded, mut children, stored_value) => {
				debug_assert!(!L::USE_EXTENSION);
				#[cfg(feature = "std")]
				trace!(target: "trie", "branch: ROUTE,AUGMENT");
				let existing_key = NibbleSlice::from_stored(&encoded);

				let common = partial.common_prefix(&existing_key);
				if common == existing_key.len() && common == partial.len() {
					let unchanged = stored_value.as_ref() == Some(&value);
					let branch = Node::NibbledBranch(
						existing_key.to_stored(),
						children,
						Some(value),
					);
					*old_val = stored_value;

					match unchanged {
						true => InsertAction::Restore(branch),
						false => InsertAction::Replace(branch),
					}
				} else if common < existing_key.len() {
					// insert a branch value in between
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"partially-shared-prefix (exist={:?}; new={:?}; common={:?}):\
							 AUGMENT-AT-END",
						existing_key.len(),
						partial.len(),
						common,
					);
					let nbranch_partial = existing_key.mid(common + 1).to_stored();
					let low = Node::NibbledBranch(nbranch_partial, children, stored_value);
					let ix = existing_key.at(common);
					let mut children = empty_children();
					let alloc_storage = self.storage.alloc(Stored::New(low));


					children[ix as usize] = Some(alloc_storage.into());

					if partial.len() - common == 0 {
						InsertAction::Replace(Node::NibbledBranch(
							existing_key.to_stored_range(common),
							children,
							Some(value),
							)
						)
					} else {
						let ix = partial.at(common);
						let stored_leaf = Node::Leaf(partial.mid(common + 1).to_stored(), value);
						let leaf = self.storage.alloc(Stored::New(stored_leaf));

						children[ix as usize] = Some(leaf.into());
						InsertAction::Replace(Node::NibbledBranch(
							existing_key.to_stored_range(common),
							children,
							None,
							)
						)

					}

				} else {
					// Append after common == existing_key and partial > common
					#[cfg(feature = "std")]
					trace!(target: "trie", "branch: ROUTE,AUGMENT");
					let idx = partial.at(common) as usize;
					key.advance(common + 1);
					if let Some(child) = children[idx].take() {
						// Original had something there. recurse down into it.
						let (new_child, changed) = self.insert_at(child, key, value, old_val)?;
						children[idx] = Some(new_child.into());
						if !changed {
							// The new node we composed didn't change.
							// It means our branch is untouched too.
							let n_branch = Node::NibbledBranch(
								existing_key.to_stored(),
								children,
								stored_value,
							);
							return Ok(InsertAction::Restore(n_branch));
						}
					} else {
						// Original had nothing there. compose a leaf.
						let leaf = self.storage.alloc(
							Stored::New(Node::Leaf(key.to_stored(), value)),
						);
						children[idx] = Some(leaf.into());
					}
					InsertAction::Replace(Node::NibbledBranch(
						existing_key.to_stored(),
						children,
						stored_value,
					))
				}
			},
			Node::Leaf(encoded, stored_value) => {
				let existing_key = NibbleSlice::from_stored(&encoded);
				let common = partial.common_prefix(&existing_key);
				if common == existing_key.len() && common == partial.len() {
					#[cfg(feature = "std")]
					trace!(target: "trie", "equivalent-leaf: REPLACE");
					// equivalent leaf.
					let unchanged = stored_value == value;
					*old_val = Some(stored_value);

					match unchanged {
						// unchanged. restore
						true => InsertAction::Restore(Node::Leaf(encoded.clone(), value)),
						false => InsertAction::Replace(Node::Leaf(encoded.clone(), value)),
					}
				} else if (L::USE_EXTENSION && common == 0)
					|| (!L::USE_EXTENSION && common < existing_key.len()) {
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"lesser-common-prefix, not-both-empty (exist={:?}; new={:?}):\
							TRANSMUTE,AUGMENT",
						existing_key.len(),
						partial.len(),
					);

					// one of us isn't empty: transmute to branch here
					let mut children = empty_children();
					let branch = if L::USE_EXTENSION && existing_key.is_empty() {
						// always replace since branch isn't leaf.
						Node::Branch(children, Some(stored_value))
					} else {
						let idx = existing_key.at(common) as usize;
						let new_leaf = Node::Leaf(
							existing_key.mid(common + 1).to_stored(),
							stored_value,
						);
						children[idx] = Some(self.storage.alloc(Stored::New(new_leaf)).into());

						if L::USE_EXTENSION {
							Node::Branch(children, None)
						} else {
							Node::NibbledBranch(partial.to_stored_range(common), children, None)
						}
					};

					// always replace because whatever we get out here
					// is not the branch we started with.
					let branch_action = self.insert_inspector(branch, key, value, old_val)?
						.unwrap_node();
					InsertAction::Replace(branch_action)
				} else if !L::USE_EXTENSION {
					#[cfg(feature = "std")]
					trace!(target: "trie", "complete-prefix (common={:?}): AUGMENT-AT-END", common);

					// fully-shared prefix for an extension.
					// make a stub branch
					let branch = Node::NibbledBranch(
						existing_key.to_stored(),
						empty_children(),
						Some(stored_value),
					);
					// augment the new branch.
					let branch = self.insert_inspector(branch, key, value, old_val)?
						.unwrap_node();

					InsertAction::Replace(branch)

				} else if common == existing_key.len() {
					debug_assert!(L::USE_EXTENSION);
					#[cfg(feature = "std")]
					trace!(target: "trie", "complete-prefix (common={:?}): AUGMENT-AT-END", common);

					// fully-shared prefix for an extension.
					// make a stub branch and an extension.
					let branch = Node::Branch(empty_children(), Some(stored_value));
					// augment the new branch.
					key.advance(common);
					let branch = self.insert_inspector(branch, key, value, old_val)?.unwrap_node();

					// always replace since we took a leaf and made an extension.
					let branch_handle = self.storage.alloc(Stored::New(branch)).into();
					InsertAction::Replace(Node::Extension(existing_key.to_stored(), branch_handle))
				} else {
					debug_assert!(L::USE_EXTENSION);
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"partially-shared-prefix (exist={:?}; new={:?}; common={:?}):\
							 AUGMENT-AT-END",
						existing_key.len(),
						partial.len(),
						common,
					);

					// partially-shared prefix for an extension.
					// start by making a leaf.
					let low = Node::Leaf(existing_key.mid(common).to_stored(), stored_value);

					// augment it. this will result in the Leaf -> common == 0 routine,
					// which creates a branch.
					key.advance(common);
					let augmented_low = self.insert_inspector(low, key, value, old_val)?
						.unwrap_node();
					// make an extension using it. this is a replacement.
					InsertAction::Replace(Node::Extension(
						existing_key.to_stored_range(common),
						self.storage.alloc(Stored::New(augmented_low)).into()
					))
				}
			},
			Node::Extension(encoded, child_branch) => {
				debug_assert!(L::USE_EXTENSION);
				let existing_key = NibbleSlice::from_stored(&encoded);
				let common = partial.common_prefix(&existing_key);
				if common == 0 {
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"no-common-prefix, not-both-empty (exist={:?}; new={:?}):\
							 TRANSMUTE,AUGMENT",
						existing_key.len(),
						partial.len(),
					);

					// partial isn't empty: make a branch here
					// extensions may not have empty partial keys.
					assert!(!existing_key.is_empty());
					let idx = existing_key.at(0) as usize;

					let mut children = empty_children();
					children[idx] = if existing_key.len() == 1 {
						// direct extension, just replace.
						Some(child_branch)
					} else {
						// more work required after branching.
						let ext = Node::Extension(existing_key.mid(1).to_stored(), child_branch);
						Some(self.storage.alloc(Stored::New(ext)).into())
					};

					// continue inserting.
					let branch_action = self.insert_inspector(
						Node::Branch(children, None),
						key,
						value,
						old_val,
					)?.unwrap_node();
					InsertAction::Replace(branch_action)
				} else if common == existing_key.len() {
					#[cfg(feature = "std")]
					trace!(target: "trie", "complete-prefix (common={:?}): AUGMENT-AT-END", common);

					// fully-shared prefix.

					// insert into the child node.
					key.advance(common);
					let (new_child, changed) = self.insert_at(child_branch, key, value, old_val)?;
					let new_ext = Node::Extension(existing_key.to_stored(), new_child.into());

					// if the child branch wasn't changed, meaning this extension remains the same.
					match changed {
						true => InsertAction::Replace(new_ext),
						false => InsertAction::Restore(new_ext),
					}
				} else {
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"partially-shared-prefix (exist={:?}; new={:?}; common={:?}):\
							 AUGMENT-AT-END",
						existing_key.len(),
						partial.len(),
						common,
					);

					// partially-shared.
					let low = Node::Extension(existing_key.mid(common).to_stored(), child_branch);
					// augment the extension. this will take the common == 0 path,
					// creating a branch.
					key.advance(common);
					let augmented_low = self.insert_inspector(low, key, value, old_val)?
						.unwrap_node();

					// always replace, since this extension is not the one we started with.
					// this is known because the partial key is only the common prefix.
					InsertAction::Replace(Node::Extension(
						existing_key.to_stored_range(common),
						self.storage.alloc(Stored::New(augmented_low)).into()
					))
				}
			},
		})
	}

	/// Removes a node from the trie based on key.
	fn remove_at(
		&mut self,
		handle: NodeHandle<TrieHash<L>>,
		key: &mut NibbleFullKey,
		old_val: &mut Option<DBValue>,
	) -> Result<Option<(StorageHandle, bool)>, TrieHash<L>, CError<L>> {
		let stored = match handle {
			NodeHandle::InMemory(h) => self.storage.destroy(h),
			NodeHandle::Hash(h) => {
				let handle = self.cache(h, key.left())?;
				self.storage.destroy(handle)
			}
		};

		let opt = self.inspect(
			stored,
			key,
			move |trie, node, key| trie.remove_inspector(node, key, old_val),
		)?;

		Ok(opt.map(|(new, changed)| (self.storage.alloc(new), changed)))
	}

	/// The removal inspector.
	fn remove_inspector(
		&mut self,
		node: Node<TrieHash<L>>,
		key: &mut NibbleFullKey,
		old_val: &mut Option<DBValue>,
	) -> Result<Action<TrieHash<L>>, TrieHash<L>, CError<L>> {
		let partial = key.clone();
		Ok(match (node, partial.is_empty()) {
			(Node::Empty, _) => Action::Delete,
			(Node::Branch(c, None), true) => Action::Restore(Node::Branch(c, None)),
			(Node::NibbledBranch(n, c, None), true) =>
				Action::Restore(Node::NibbledBranch(n, c, None)),
			(Node::Branch(children, Some(val)), true) => {
				*old_val = Some(val);
				// always replace since we took the value out.
				Action::Replace(self.fix(Node::Branch(children, None), key.clone())?)
			},
			(Node::NibbledBranch(n, children, Some(val)), true) => {
				*old_val = Some(val);
				// always replace since we took the value out.
				Action::Replace(self.fix(Node::NibbledBranch(n, children, None), key.clone())?)
			},
			(Node::Branch(mut children, value), false) => {
				let idx = partial.at(0) as usize;
				if let Some(child) = children[idx].take() {
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"removing value out of branch child, partial={:?}",
						partial,
					);
					let prefix = key.clone();
					key.advance(1);
					match self.remove_at(child, key, old_val)? {
						Some((new, changed)) => {
							children[idx] = Some(new.into());
							let branch = Node::Branch(children, value);
							match changed {
								// child was changed, so we were too.
								true => Action::Replace(branch),
								// unchanged, so we are too.
								false => Action::Restore(branch),
							}
						}
						None => {
							// the child we took was deleted.
							// the node may need fixing.
							#[cfg(feature = "std")]
							trace!(target: "trie", "branch child deleted, partial={:?}", partial);
							Action::Replace(self.fix(Node::Branch(children, value), prefix)?)
						}
					}
				} else {
					// no change needed.
					Action::Restore(Node::Branch(children, value))
				}
			},
			(Node::NibbledBranch(encoded, mut children, value), false) => {
				let (common, existing_length) = {
					let existing_key = NibbleSlice::from_stored(&encoded);
					(existing_key.common_prefix(&partial), existing_key.len())
				};
				if common == existing_length && common == partial.len() {

					// replace val
					if let Some(val) = value {
						*old_val = Some(val);

						let f = self.fix(Node::NibbledBranch(encoded, children, None), key.clone());
						Action::Replace(f?)
					} else {
						Action::Restore(Node::NibbledBranch(encoded, children, None))
					}
				} else if common < existing_length {
					// partway through an extension -- nothing to do here.
					Action::Restore(Node::NibbledBranch(encoded, children, value))
				} else {
					// common == existing_length && common < partial.len() : check children
					let idx = partial.at(common) as usize;

					if let Some(child) = children[idx].take() {
						#[cfg(feature = "std")]
						trace!(
							target: "trie",
							"removing value out of branch child, partial={:?}",
							partial,
						);
						let prefix = key.clone();
						key.advance(common + 1);
						match self.remove_at(child, key, old_val)? {
							Some((new, changed)) => {
								children[idx] = Some(new.into());
								let branch = Node::NibbledBranch(encoded, children, value);
								match changed {
									// child was changed, so we were too.
									true => Action::Replace(branch),
									// unchanged, so we are too.
									false => Action::Restore(branch),
								}
							},
							None => {
								// the child we took was deleted.
								// the node may need fixing.
								#[cfg(feature = "std")]
								trace!(
									target: "trie",
									"branch child deleted, partial={:?}",
									partial,
								);
								Action::Replace(
									self.fix(Node::NibbledBranch(encoded, children, value), prefix)?
								)
							},
						}
					} else {
						// no change needed.
						Action::Restore(Node::NibbledBranch(encoded, children, value))
					}
				}
			},
			(Node::Leaf(encoded, value), _) => {
				if NibbleSlice::from_stored(&encoded) == partial {
					// this is the node we were looking for. Let's delete it.
					*old_val = Some(value);
					Action::Delete
				} else {
					// leaf the node alone.
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"restoring leaf wrong partial, partial={:?}, existing={:?}",
						partial,
						NibbleSlice::from_stored(&encoded),
					);
					Action::Restore(Node::Leaf(encoded, value))
				}
			},
			(Node::Extension(encoded, child_branch), _) => {
				let (common, existing_length) = {
					let existing_key = NibbleSlice::from_stored(&encoded);
					(existing_key.common_prefix(&partial), existing_key.len())
				};
				if common == existing_length {
					// try to remove from the child branch.
					#[cfg(feature = "std")]
					trace!(target: "trie", "removing from extension child, partial={:?}", partial);
					let prefix = key.clone();
					key.advance(common);
					match self.remove_at(child_branch, key, old_val)? {
						Some((new_child, changed)) => {
							let new_child = new_child.into();

							// if the child branch was unchanged, then the extension is too.
							// otherwise, this extension may need fixing.
							match changed {
								true => Action::Replace(
									self.fix(Node::Extension(encoded, new_child), prefix)?
								),
								false => Action::Restore(Node::Extension(encoded, new_child)),
							}
						}
						None => {
							// the whole branch got deleted.
							// that means that this extension is useless.
							Action::Delete
						}
					}
				} else {
					// partway through an extension -- nothing to do here.
					Action::Restore(Node::Extension(encoded, child_branch))
				}
			},
		})
	}

	/// Given a node which may be in an _invalid state_, fix it such that it is then in a valid
	/// state.
	///
	/// _invalid state_ means:
	/// - Branch node where there is only a single entry;
	/// - Extension node followed by anything other than a Branch node.
	fn fix(
		&mut self,
		node: Node<TrieHash<L>>,
		key: NibbleSlice,
	) -> Result<Node<TrieHash<L>>, TrieHash<L>, CError<L>> {
		match node {
			Node::Branch(mut children, value) => {
				// if only a single value, transmute to leaf/extension and feed through fixed.
				#[cfg_attr(feature = "std", derive(Debug))]
				enum UsedIndex {
					None,
					One(u8),
					Many,
				};
				let mut used_index = UsedIndex::None;
				for i in 0..16 {
					match (children[i].is_none(), &used_index) {
						(false, &UsedIndex::None) => used_index = UsedIndex::One(i as u8),
						(false, &UsedIndex::One(_)) => {
							used_index = UsedIndex::Many;
							break;
						}
						_ => continue,
					}
				}

				match (used_index, value) {
					(UsedIndex::None, None) =>
						panic!("Branch with no subvalues. Something went wrong."),
					(UsedIndex::One(a), None) => {
						// only one onward node. make an extension.

						let new_partial = NibbleSlice::new_offset(&[a], 1).to_stored();
						let child = children[a as usize].take()
							.expect("used_index only set if occupied; qed");
						let new_node = Node::Extension(new_partial, child);
						self.fix(new_node, key)
					}
					(UsedIndex::None, Some(value)) => {
						// make a leaf.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: branch -> leaf");
						Ok(Node::Leaf(NibbleSlice::new(&[]).to_stored(), value))
					}
					(_, value) => {
						// all is well.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: restoring branch");
						Ok(Node::Branch(children, value))
					}
				}
			},
			Node::NibbledBranch(enc_nibble, mut children, value) => {
				// if only a single value, transmute to leaf/extension and feed through fixed.
				#[cfg_attr(feature = "std", derive(Debug))]
				enum UsedIndex {
					None,
					One(u8),
					Many,
				};
				let mut used_index = UsedIndex::None;
				for i in 0..16 {
					match (children[i].is_none(), &used_index) {
						(false, &UsedIndex::None) => used_index = UsedIndex::One(i as u8),
						(false, &UsedIndex::One(_)) => {
							used_index = UsedIndex::Many;
							break;
						}
						_ => continue,
					}
				}

				match (used_index, value) {
					(UsedIndex::None, None) =>
						panic!("Branch with no subvalues. Something went wrong."),
					(UsedIndex::One(a), None) => {
						// only one onward node. use child instead
						let child = children[a as usize].take()
							.expect("used_index only set if occupied; qed");
						let mut key2 = key.clone();
						key2.advance((enc_nibble.1.len() * nibble_ops::NIBBLE_PER_BYTE) - enc_nibble.0);
						let (start, alloc_start, prefix_end) = match key2.left() {
							(start, None) => (start, None, Some(nibble_ops::push_at_left(0, a, 0))),
							(start, Some(v)) => {
								let mut so: BackingByteVec = start.into();
								so.push(nibble_ops::pad_left(v) | a);
								(start, Some(so), None)
							},
						};
						let child_prefix = (alloc_start.as_ref().map(|start| &start[..]).unwrap_or(start), prefix_end);
						let stored = match child {
							NodeHandle::InMemory(h) => self.storage.destroy(h),
							NodeHandle::Hash(h) => {
								let handle = self.cache(h, child_prefix)?;
								self.storage.destroy(handle)
							}
						};
						let child_node = match stored {
							Stored::New(node) => node,
							Stored::Cached(node, hash) => {
								self.death_row.insert((
									hash,
									(child_prefix.0[..].into(), child_prefix.1),
								));
								node
							},
						};
						match child_node {
							Node::Leaf(sub_partial, value) => {
								let mut enc_nibble = enc_nibble;
								combine_key(
									&mut enc_nibble,
									(nibble_ops::NIBBLE_PER_BYTE - 1, &[a][..]),
								);
								combine_key(
									&mut enc_nibble,
									(sub_partial.0, &sub_partial.1[..]),
								);
								Ok(Node::Leaf(enc_nibble, value))
							},
							Node::NibbledBranch(sub_partial, ch_children, ch_value) => {
								let mut enc_nibble = enc_nibble;
								combine_key(
									&mut enc_nibble,
									(nibble_ops::NIBBLE_PER_BYTE - 1, &[a][..]),
								);
								combine_key(
									&mut enc_nibble,
									(sub_partial.0, &sub_partial.1[..]),
								);
								Ok(Node::NibbledBranch(enc_nibble, ch_children, ch_value))
							},
							_ => unreachable!(),
						}
					},
					(UsedIndex::None, Some(value)) => {
						// make a leaf.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: branch -> leaf");
						Ok(Node::Leaf(enc_nibble, value))
					},
					(_, value) => {
						// all is well.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: restoring branch");
						Ok(Node::NibbledBranch(enc_nibble, children, value))
					},
				}
			},
			Node::Extension(partial, child) => {
				// We could advance key, but this code can also be called
				// recursively, so there might be some prefix from branch.
				let last = partial.1[partial.1.len() - 1] & (255 >> 4);
				let mut key2 = key.clone();
				key2.advance((partial.1.len() * nibble_ops::NIBBLE_PER_BYTE) - partial.0 - 1);
				let (start, alloc_start, prefix_end) = match key2.left() {
					(start, None) => (start, None, Some(nibble_ops::push_at_left(0, last, 0))),
					(start, Some(v)) => {
						let mut so: BackingByteVec = start.into();
						// Complete last byte with `last`.
						so.push(nibble_ops::pad_left(v) | last);
						(start, Some(so), None)
					},
				};
				let child_prefix = (alloc_start.as_ref().map(|start| &start[..]).unwrap_or(start), prefix_end);

				let stored = match child {
					NodeHandle::InMemory(h) => self.storage.destroy(h),
					NodeHandle::Hash(h) => {
						let handle = self.cache(h, child_prefix)?;
						self.storage.destroy(handle)
					}
				};

				let (child_node, maybe_hash) = match stored {
					Stored::New(node) => (node, None),
					Stored::Cached(node, hash) => (node, Some(hash))
				};

				match child_node {
					Node::Extension(sub_partial, sub_child) => {
						// combine with node below.
						if let Some(hash) = maybe_hash {
							// delete the cached child since we are going to replace it.
							self.death_row.insert(
								(hash, (child_prefix.0[..].into(), child_prefix.1)),
							);
						}
						// subpartial
						let mut partial = partial;
						combine_key(&mut partial, (sub_partial.0, &sub_partial.1[..]));
						#[cfg(feature = "std")]
						trace!(
							target: "trie",
							"fixing: extension combination. new_partial={:?}",
							partial,
						);
						self.fix(Node::Extension(partial, sub_child), key)
					}
					Node::Leaf(sub_partial, value) => {
						// combine with node below.
						if let Some(hash) = maybe_hash {
							// delete the cached child since we are going to replace it.
							self.death_row.insert((hash, (child_prefix.0[..].into(), child_prefix.1)));
						}
						// subpartial oly
						let mut partial = partial;
						combine_key(&mut partial, (sub_partial.0, &sub_partial.1[..]));
						#[cfg(feature = "std")]
						trace!(
							target: "trie",
							"fixing: extension -> leaf. new_partial={:?}",
							partial,
						);
						Ok(Node::Leaf(partial, value))
					}
					child_node => {
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: restoring extension");

						// reallocate the child node.
						let stored = if let Some(hash) = maybe_hash {
							Stored::Cached(child_node, hash)
						} else {
							Stored::New(child_node)
						};

						Ok(Node::Extension(partial, self.storage.alloc(stored).into()))
					}
				}
			},
			other => Ok(other), // only ext and branch need fixing.
		}
	}

	/// Commit the in-memory changes to disk, freeing their storage and
	/// updating the state root.
	pub fn commit(&mut self) {
		#[cfg(feature = "std")]
		trace!(target: "trie", "Committing trie changes to db.");

		// always kill all the nodes on death row.
		#[cfg(feature = "std")]
		trace!(target: "trie", "{:?} nodes to remove from db", self.death_row.len());
		for (hash, prefix) in self.death_row.drain() {
			self.db.remove(&hash, (&prefix.0[..], prefix.1));
		}

		let handle = match self.root_handle() {
			NodeHandle::Hash(_) => return, // no changes necessary.
			NodeHandle::InMemory(h) => h,
		};

		match self.storage.destroy(handle) {
			Stored::New(node) => {
				let mut k = NibbleVec::new();
				let mut register_children = Self::register_children_buf(&node);
				let (encoded_root, no_node) = node.into_encoded::<_, L::Codec, L::Hash>(
					|child, o_slice, o_index| {
						let mov = k.append_optional_slice_and_nibble(o_slice, o_index);
						let cr = self.commit_child(child, &mut k);
						k.drop_lasts(mov);
						cr
					},
					register_children.as_mut().map(|a| &mut a[..]),
				);
				#[cfg(feature = "std")]
				trace!(target: "trie", "encoded root node: {:#x?}", &encoded_root[..]);
				if let Some(children) = register_children {
					*self.root = self.db.insert_complex(
						EMPTY_PREFIX,
						&encoded_root[..],
						&children[..],
						no_node,
					);
				} else {
					*self.root = self.db.insert(EMPTY_PREFIX, &encoded_root[..]);
				}
				self.hash_count += 1;

				self.root_handle = NodeHandle::Hash(*self.root);
			}
			Stored::Cached(node, hash) => {
				// probably won't happen, but update the root and move on.
				*self.root = hash;
				self.root_handle = NodeHandle::InMemory(
					self.storage.alloc(Stored::Cached(node, hash)),
				);
			}
		}
	}

	/// Commit a node by hashing it and writing it to the db. Returns a
	/// `ChildReference` which in most cases carries a normal hash but for the
	/// case where we can fit the actual data in the `Hasher`s output type, we
	/// store the data inline. This function is used as the callback to the
	/// `into_encoded` method of `Node`.
	fn commit_child(
		&mut self,
		handle: NodeHandle<TrieHash<L>>,
		prefix: &mut NibbleVec,
	) -> ChildReference<TrieHash<L>> {
		match handle {
			NodeHandle::Hash(hash) => ChildReference::Hash(hash),
			NodeHandle::InMemory(storage_handle) => {
				match self.storage.destroy(storage_handle) {
					Stored::Cached(_, hash) => ChildReference::Hash(hash),
					Stored::New(node) => {
						let mut register_children = Self::register_children_buf(&node);
						let (encoded, no_node) = {
							let commit_child = |
								node_handle,
								o_slice: Option<&NibbleSlice>,
								o_index: Option<u8>
							| {
								let mov = prefix.append_optional_slice_and_nibble(o_slice, o_index);
								let cr = self.commit_child(node_handle, prefix);
								prefix.drop_lasts(mov);
								cr
							};
							node.into_encoded::<_, L::Codec, L::Hash>(
								commit_child,
								register_children.as_mut().map(|a| &mut a[..]),
							)
						};
						if encoded.len() >= L::Hash::LENGTH {
							let hash = if let Some(children) = register_children {
								self.db.insert_complex(
									prefix.as_prefix(),
									&encoded[..],
									&children[..],
									no_node,
								)
							} else {
								self.db.insert(prefix.as_prefix(), &encoded[..])
							};
	
							self.hash_count +=1;
							ChildReference::Hash(hash)
						} else {
							// it's a small value, so we cram it into a `TrieHash<L>`
							// and tag with length
							let mut h = <TrieHash<L>>::default();
							let len = encoded.len();
							h.as_mut()[..len].copy_from_slice(&encoded[..len]);
							ChildReference::Inline(h, len)
						}
					}
				}
			}
		}
	}

	// a hack to get the root node's handle
	fn root_handle(&self) -> NodeHandle<TrieHash<L>> {
		match self.root_handle {
			NodeHandle::Hash(h) => NodeHandle::Hash(h),
			NodeHandle::InMemory(StorageHandle(x)) => NodeHandle::InMemory(StorageHandle(x)),
		}
	}
}


impl<'a, L> TrieMut<L> for TrieDBMut<'a, L>
where
	L: TrieLayout,
{
	fn root(&mut self) -> &TrieHash<L> {
		self.commit();
		self.root
	}

	fn is_empty(&self) -> bool {
		match self.root_handle {
			NodeHandle::Hash(h) => h == L::Codec::hashed_null_node(),
			NodeHandle::InMemory(ref h) => match self.storage[h] {
				Node::Empty => true,
				_ => false,
			}
		}
	}

	fn get<'x, 'key>(&'x self, key: &'key [u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>>
		where 'x: 'key
	{
		self.lookup(NibbleSlice::new(key), &self.root_handle)
	}

	fn insert(
		&mut self,
		key: &[u8],
		value: &[u8],
	) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		if value.is_empty() { return self.remove(key) }

		let mut old_val = None;

		#[cfg(feature = "std")]
		trace!(target: "trie", "insert: key={:#x?}, value={:?}", key, ToHex(&value));

		let root_handle = self.root_handle();
		let (new_handle, _changed) = self.insert_at(
			root_handle,
			&mut NibbleSlice::new(key),
			value.to_vec(),
			&mut old_val,
		)?;

		#[cfg(feature = "std")]
		trace!(target: "trie", "insert: altered trie={}", _changed);
		self.root_handle = NodeHandle::InMemory(new_handle);

		Ok(old_val)
	}

	fn remove(&mut self, key: &[u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		#[cfg(feature = "std")]
		trace!(target: "trie", "remove: key={:#x?}", key);

		let root_handle = self.root_handle();
		let mut key = NibbleSlice::new(key);
		let mut old_val = None;

		match self.remove_at(root_handle, &mut key, &mut old_val)? {
			Some((handle, _changed)) => {
				#[cfg(feature = "std")]
				trace!(target: "trie", "remove: altered trie={}", _changed);
				self.root_handle = NodeHandle::InMemory(handle);
			}
			None => {
				#[cfg(feature = "std")]
				trace!(target: "trie", "remove: obliterated trie");
				self.root_handle = NodeHandle::Hash(L::Codec::hashed_null_node());
				*self.root = L::Codec::hashed_null_node();
			}
		}

		Ok(old_val)
	}
}

impl<'a, L> Drop for TrieDBMut<'a, L>
where
	L: TrieLayout,
{
	fn drop(&mut self) {
		self.commit();
	}
}

/// combine two NodeKeys
fn combine_key(start: &mut NodeKey, end: (usize, &[u8])) {
	debug_assert!(start.0 < nibble_ops::NIBBLE_PER_BYTE);
	debug_assert!(end.0 < nibble_ops::NIBBLE_PER_BYTE);
	let final_offset = (start.0 + end.0) % nibble_ops::NIBBLE_PER_BYTE;
	let _shifted = nibble_ops::shift_key(start, final_offset);
	let st = if end.0 > 0 {
		let sl = start.1.len();
		start.1[sl - 1] |= nibble_ops::pad_right(end.1[0]);
		1
	} else {
		0
	};
	(st..end.1.len()).for_each(|i| start.1.push(end.1[i]));
}

#[cfg(test)]
mod tests {
	use env_logger;
	use trie_standardmap::*;
	use log::debug;
	use crate::DBValue;
	use memory_db::{MemoryDB, PrefixedKey};
	use hash_db::Hasher;
	use keccak_hasher::KeccakHasher;
	use reference_trie::{RefTrieDBMutNoExt, RefTrieDBMut, TrieMut, NodeCodec, HashDBComplexDyn,
		ReferenceNodeCodec, reference_trie_root_iter_build as reference_trie_root,
		reference_trie_root_no_extension_iter_build as reference_trie_root_no_extension};
	use crate::nibble::BackingByteVec;

	fn populate_trie<'db>(
		db: &'db mut dyn HashDBComplexDyn<KeccakHasher, DBValue>,
		root: &'db mut <KeccakHasher as Hasher>::Out,
		v: &[(Vec<u8>, Vec<u8>)]
	) -> RefTrieDBMut<'db> {
		let mut t = RefTrieDBMut::new(db, root);
		for i in 0..v.len() {
			let key: &[u8]= &v[i].0;
			let val: &[u8] = &v[i].1;
			t.insert(key, val).unwrap();
		}
		t
	}

	fn unpopulate_trie<'db>(t: &mut RefTrieDBMut<'db>, v: &[(Vec<u8>, Vec<u8>)]) {
		for i in v {
			let key: &[u8]= &i.0;
			t.remove(key).unwrap();
		}
	}

	fn populate_trie_no_extension<'db>(
		db: &'db mut dyn HashDBComplexDyn<KeccakHasher, DBValue>,
		root: &'db mut <KeccakHasher as Hasher>::Out,
		v: &[(Vec<u8>, Vec<u8>)]
	) -> RefTrieDBMutNoExt<'db> {
		let mut t = RefTrieDBMutNoExt::new(db, root);
		for i in 0..v.len() {
			let key: &[u8]= &v[i].0;
			let val: &[u8] = &v[i].1;
			t.insert(key, val).unwrap();
		}
		t
	}

	fn unpopulate_trie_no_extension<'db>(t: &mut RefTrieDBMutNoExt<'db>, v: &[(Vec<u8>, Vec<u8>)]) {
		for i in v {
			let key: &[u8]= &i.0;
			t.remove(key).unwrap();
		}
	}

	fn reference_hashed_null_node() -> <KeccakHasher as Hasher>::Out {
		<ReferenceNodeCodec<KeccakHasher> as NodeCodec>::hashed_null_node()
	}

	#[test]
	fn playpen() {
		env_logger::init();
		let mut seed = Default::default();
		for test_i in 0..10 {
			if test_i % 50 == 0 {
				debug!("{:?} of 10000 stress tests done", test_i);
			}
			let x = StandardMap {
				alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
				min_key: 5,
				journal_key: 0,
				value_mode: ValueMode::Index,
				count: 100,
			}.make_with(&mut seed);

			let real = reference_trie_root(x.clone());
			let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
			let mut root = Default::default();
			let mut memtrie = populate_trie(&mut memdb, &mut root, &x);

			memtrie.commit();
			if *memtrie.root() != real {
				println!("TRIE MISMATCH");
				println!("");
				println!("{:?} vs {:?}", memtrie.root(), real);
				for i in &x {
					println!("{:#x?} -> {:#x?}", i.0, i.1);
				}
			}
			assert_eq!(*memtrie.root(), real);
			unpopulate_trie(&mut memtrie, &x);
			memtrie.commit();
			let hashed_null_node = reference_hashed_null_node();
			if *memtrie.root() != hashed_null_node {
				println!("- TRIE MISMATCH");
				println!("");
				println!("{:#x?} vs {:#x?}", memtrie.root(), hashed_null_node);
				for i in &x {
					println!("{:#x?} -> {:#x?}", i.0, i.1);
				}
			}
			assert_eq!(*memtrie.root(), hashed_null_node);
		}

		// no_extension
		let mut seed = Default::default();
		for test_i in 0..10 {
			if test_i % 50 == 0 {
				debug!("{:?} of 10000 stress tests done", test_i);
			}
			let x = StandardMap {
				alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
				min_key: 5,
				journal_key: 0,
				value_mode: ValueMode::Index,
				count: 100,
			}.make_with(&mut seed);

			let real = reference_trie_root_no_extension(x.clone());
			let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
			let mut root = Default::default();
			let mut memtrie = populate_trie_no_extension(&mut memdb, &mut root, &x);

			memtrie.commit();
			if *memtrie.root() != real {
				println!("TRIE MISMATCH");
				println!("");
				println!("{:?} vs {:?}", memtrie.root(), real);
				for i in &x {
					println!("{:#x?} -> {:#x?}", i.0, i.1);
				}
			}
			assert_eq!(*memtrie.root(), real);
			unpopulate_trie_no_extension(&mut memtrie, &x);
			memtrie.commit();
			let hashed_null_node = reference_hashed_null_node();
			if *memtrie.root() != hashed_null_node {
				println!("- TRIE MISMATCH");
				println!("");
				println!("{:#x?} vs {:#x?}", memtrie.root(), hashed_null_node);
				for i in &x {
					println!("{:#x?} -> {:#x?}", i.0, i.1);
				}
			}
			assert_eq!(*memtrie.root(), hashed_null_node);
		}
	}

	#[test]
	fn init() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		let hashed_null_node = reference_hashed_null_node();
		assert_eq!(*t.root(), hashed_null_node);
	}

	#[test]
	fn insert_on_empty() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		assert_eq!(
			*t.root(),
			reference_trie_root(vec![ (vec![0x01u8, 0x23], vec![0x01u8, 0x23]) ]),
		);
	}

	#[test]
	fn remove_to_empty() {
		let big_value = b"00000000000000000000000000000000";

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);

		t.insert(&[0x01], big_value).unwrap();
		t.insert(&[0x01, 0x23], big_value).unwrap();
		t.insert(&[0x01, 0x34], big_value).unwrap();
		t.remove(&[0x01]).unwrap();
	}

	#[test]
	fn remove_to_empty_no_extension() {
		let big_value = b"00000000000000000000000000000000";
		let big_value2 = b"00000000000000000000000000000002";
		let big_value3 = b"00000000000000000000000000000004";

		let mut memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);

			t.insert(&[0x01, 0x23], big_value3).unwrap();
			t.insert(&[0x01], big_value2).unwrap();
			t.insert(&[0x01, 0x34], big_value).unwrap();
			t.remove(&[0x01]).unwrap();
			// commit on drop
		}
		assert_eq!(&root[..], &reference_trie::calc_root_no_extension(vec![
		 (vec![0x01u8, 0x23], big_value3.to_vec()),
		 (vec![0x01u8, 0x34], big_value.to_vec()),
		])[..]);
	}

	#[test]
	fn insert_replace_root() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0x01u8, 0x23], &[0x23u8, 0x45]).unwrap();
		assert_eq!(
			*t.root(),
			reference_trie_root(vec![ (vec![0x01u8, 0x23], vec![0x23u8, 0x45]) ]),
		);
	}

	#[test]
	fn insert_make_branch_root() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0x11u8, 0x23], &[0x11u8, 0x23]).unwrap();
		assert_eq!(*t.root(), reference_trie_root(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x11u8, 0x23], vec![0x11u8, 0x23])
		]));
	}

	#[test]
	fn insert_into_branch_root() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0xf1u8, 0x23], &[0xf1u8, 0x23]).unwrap();
		t.insert(&[0x81u8, 0x23], &[0x81u8, 0x23]).unwrap();
		assert_eq!(*t.root(), reference_trie_root(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x81u8, 0x23], vec![0x81u8, 0x23]),
			(vec![0xf1u8, 0x23], vec![0xf1u8, 0x23]),
		]));
	}

	#[test]
	fn insert_value_into_branch_root() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[], &[0x0]).unwrap();
		assert_eq!(*t.root(), reference_trie_root(vec![
			(vec![], vec![0x0]),
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
		]));
	}

	#[test]
	fn insert_split_leaf() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0x01u8, 0x34], &[0x01u8, 0x34]).unwrap();
		assert_eq!(*t.root(), reference_trie_root(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x01u8, 0x34], vec![0x01u8, 0x34]),
		]));
	}

	#[test]
	fn insert_split_extenstion() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01, 0x23, 0x45], &[0x01]).unwrap();
		t.insert(&[0x01, 0xf3, 0x45], &[0x02]).unwrap();
		t.insert(&[0x01, 0xf3, 0xf5], &[0x03]).unwrap();
		assert_eq!(*t.root(), reference_trie_root(vec![
			(vec![0x01, 0x23, 0x45], vec![0x01]),
			(vec![0x01, 0xf3, 0x45], vec![0x02]),
			(vec![0x01, 0xf3, 0xf5], vec![0x03]),
		]));
	}

	#[test]
	fn insert_big_value() {
		let big_value0 = b"00000000000000000000000000000000";
		let big_value1 = b"11111111111111111111111111111111";

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], big_value0).unwrap();
		t.insert(&[0x11u8, 0x23], big_value1).unwrap();
		assert_eq!(*t.root(), reference_trie_root(vec![
			(vec![0x01u8, 0x23], big_value0.to_vec()),
			(vec![0x11u8, 0x23], big_value1.to_vec())
		]));
	}

	#[test]
	fn insert_duplicate_value() {
		let big_value = b"00000000000000000000000000000000";

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], big_value).unwrap();
		t.insert(&[0x11u8, 0x23], big_value).unwrap();
		assert_eq!(*t.root(), reference_trie_root(vec![
			(vec![0x01u8, 0x23], big_value.to_vec()),
			(vec![0x11u8, 0x23], big_value.to_vec())
		]));
	}

	#[test]
	fn test_at_empty() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let t = RefTrieDBMut::new(&mut memdb, &mut root);
		assert_eq!(t.get(&[0x5]).unwrap(), None);
	}

	#[test]
	fn test_at_one() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), vec![0x1u8, 0x23]);
		t.commit();
		assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), vec![0x1u8, 0x23]);
	}

	#[test]
	fn test_at_three() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		t.insert(&[0xf1u8, 0x23], &[0xf1u8, 0x23]).unwrap();
		t.insert(&[0x81u8, 0x23], &[0x81u8, 0x23]).unwrap();
		assert_eq!(t.get(&[0x01, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
		assert_eq!(t.get(&[0xf1, 0x23]).unwrap().unwrap(), vec![0xf1u8, 0x23]);
		assert_eq!(t.get(&[0x81, 0x23]).unwrap().unwrap(), vec![0x81u8, 0x23]);
		assert_eq!(t.get(&[0x82, 0x23]).unwrap(), None);
		t.commit();
		assert_eq!(t.get(&[0x01, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
		assert_eq!(t.get(&[0xf1, 0x23]).unwrap().unwrap(), vec![0xf1u8, 0x23]);
		assert_eq!(t.get(&[0x81, 0x23]).unwrap().unwrap(), vec![0x81u8, 0x23]);
		assert_eq!(t.get(&[0x82, 0x23]).unwrap(), None);
	}

	#[test]
	fn stress() {
		let mut seed = Default::default();
		for _ in 0..50 {
			let x = StandardMap {
				alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
				min_key: 5,
				journal_key: 0,
				value_mode: ValueMode::Index,
				count: 4,
			}.make_with(&mut seed);

			let real = reference_trie_root(x.clone());
			let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
			let mut root = Default::default();
			let mut memtrie = populate_trie(&mut memdb, &mut root, &x);
			let mut y = x.clone();
			y.sort_by(|ref a, ref b| a.0.cmp(&b.0));
			let mut memdb2 = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
			let mut root2 = Default::default();
			let mut memtrie_sorted = populate_trie(&mut memdb2, &mut root2, &y);
			if *memtrie.root() != real || *memtrie_sorted.root() != real {
				println!("TRIE MISMATCH");
				println!("");
				println!("ORIGINAL... {:#x?}", memtrie.root());
				for i in &x {
					println!("{:#x?} -> {:#x?}", i.0, i.1);
				}
				println!("SORTED... {:#x?}", memtrie_sorted.root());
				for i in &y {
					println!("{:#x?} -> {:#x?}", i.0, i.1);
				}
			}
			assert_eq!(*memtrie.root(), real);
			assert_eq!(*memtrie_sorted.root(), real);
		}
	}

	#[test]
	fn test_trie_existing() {
		let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut db, &mut root);
			t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		}

		{
			 let _ = RefTrieDBMut::from_existing(&mut db, &mut root);
		}
	}

	#[test]
	fn insert_empty() {
		let mut seed = Default::default();
		let x = StandardMap {
				alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
				min_key: 5,
				journal_key: 0,
				value_mode: ValueMode::Index,
				count: 4,
		}.make_with(&mut seed);

		let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut db, &mut root);
		for &(ref key, ref value) in &x {
			t.insert(key, value).unwrap();
		}

		assert_eq!(*t.root(), reference_trie_root(x.clone()));

		for &(ref key, _) in &x {
			t.insert(key, &[]).unwrap();
		}

		assert!(t.is_empty());
		let hashed_null_node = reference_hashed_null_node();
		assert_eq!(*t.root(), hashed_null_node);
	}

	#[test]
	fn return_old_values() {
		let mut seed = Default::default();
		let x = StandardMap {
				alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
				min_key: 5,
				journal_key: 0,
				value_mode: ValueMode::Index,
				count: 2,
		}.make_with(&mut seed);

		let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut t = RefTrieDBMut::new(&mut db, &mut root);
		for &(ref key, ref value) in &x {
			assert!(t.insert(key, value).unwrap().is_none());
			assert_eq!(t.insert(key, value).unwrap(), Some(value.clone()));
		}
		for (key, value) in x {
			assert_eq!(t.remove(&key).unwrap(), Some(value));
			assert!(t.remove(&key).unwrap().is_none());
		}
	}

	#[test]
	fn combine_test() {
		let a: BackingByteVec = [0x12, 0x34][..].into();
		let b: &[u8] = [0x56, 0x78][..].into();
		let test_comb = |a: (_, &BackingByteVec), b, c| {
			let mut a = (a.0, a.1.clone());
			super::combine_key(&mut a, b);
			assert_eq!((a.0, &a.1[..]), c);
		};
		test_comb((0, &a), (0, &b), (0, &[0x12, 0x34, 0x56, 0x78][..]));
		test_comb((1, &a), (0, &b), (1, &[0x12, 0x34, 0x56, 0x78][..]));
		test_comb((0, &a), (1, &b), (1, &[0x01, 0x23, 0x46, 0x78][..]));
		test_comb((1, &a), (1, &b), (0, &[0x23, 0x46, 0x78][..]));
	}

	#[test]
	fn nice_debug_for_node() {
		use super::Node;
		let e: Node<u32> = Node::Leaf((1, vec![1, 2, 3].into()), vec![4, 5, 6]);
		assert_eq!(format!("{:?}", e), "Leaf((1, 010203), 040506)");
	}

}

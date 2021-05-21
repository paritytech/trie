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

//! In-memory trie representation.

use super::{DBValue, node::NodeKey, Meta, GlobalMeta};
use super::{Result, TrieError, TrieMut, TrieLayout, TrieHash, CError};
use super::lookup::Lookup;
use super::node::{NodeHandle as EncodedNodeHandle, Node as EncodedNode,
	Value as EncodedValue, decode_hash};

use hash_db::{HashDB, Hasher, Prefix, EMPTY_PREFIX};
use hashbrown::HashSet;

use crate::node_codec::NodeCodec;
use crate::nibble::{NibbleVec, NibbleSlice, nibble_ops, BackingByteVec};
use crate::rstd::{
	boxed::Box, convert::TryFrom, mem, ops::Index, result, vec::Vec, VecDeque,
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

fn empty_children<H>() -> Box<[Option<NodeHandle<H>>; nibble_ops::NIBBLE_LENGTH]> {
	Box::new([
		None, None, None, None, None, None, None, None,
		None, None, None, None, None, None, None, None,
	])
}

/// Type alias to indicate the nible covers a full key,
/// therefore its left side is a full prefix.
type NibbleFullKey<'key> = NibbleSlice<'key>;

/// Value representation for Node.
#[derive(Clone, PartialEq, Eq)]
pub enum Value {
	/// Node with no value attached.
	NoValue,
	/// Value bytes.
	Value(DBValue),
	/// Hash of bytes and original value length.
	HashedValue(DBValue, usize),
}

impl<'a> From<EncodedValue<'a>> for Value {
	fn from(v: EncodedValue<'a>) -> Self {
		match v {
			EncodedValue::NoValue => Value::NoValue,
			EncodedValue::Value(value) => Value::Value(value.to_vec()),
			EncodedValue::HashedValue(hash, size) => Value::HashedValue(hash.to_vec(), size),
		}
	}
}

impl From<Option<DBValue>> for Value {
	fn from(v: Option<DBValue>) -> Self {
		match v {
			Some(value) => Value::Value(value.to_vec()),
			None => Value::NoValue,
		}
	}
}


impl Value {
	fn as_slice(&self) -> EncodedValue {
		match self {
			Value::NoValue => EncodedValue::NoValue,
			Value::Value(value) => EncodedValue::Value(value.as_slice()),
			Value::HashedValue(hash, size) => EncodedValue::HashedValue(hash.as_slice(), *size),
		}
	}

	fn value_fetch<L: TrieLayout> (&self) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		match self {
			Value::NoValue => Ok(None),
			Value::Value(value) => Ok(Some(value.clone())),
			Value::HashedValue(hash, _size) => {
				// TODO this is only for inline node so most likely never this.
				// but still considerr using access_from
				let mut res = TrieHash::<L>::default();
				res.as_mut().copy_from_slice(hash.as_slice());
				Err(Box::new(TrieError::IncompleteDatabase(res)))
			},
		}
	}
}


/// Node types in the Trie.
/// `M` is associated meta, no meta indicates
/// an inline node.
enum Node<L: TrieLayout> {
	/// Empty node.
	Empty(L::Meta),
	/// A leaf node contains the end of a key and a value.
	/// This key is encoded from a `NibbleSlice`, meaning it contains
	/// a flag indicating it is a leaf.
	Leaf(NodeKey, Value, L::Meta),
	/// An extension contains a shared portion of a key and a child node.
	/// The shared portion is encoded from a `NibbleSlice` meaning it contains
	/// a flag indicating it is an extension.
	/// The child node is always a branch.
	Extension(NodeKey, NodeHandle<TrieHash<L>>, L::Meta),
	/// A branch has up to 16 children and an optional value.
	Branch(Box<[Option<NodeHandle<TrieHash<L>>>; nibble_ops::NIBBLE_LENGTH]>, Value, L::Meta),
	/// Branch node with support for a nibble (to avoid extension node).
	NibbledBranch(NodeKey, Box<[Option<NodeHandle<TrieHash<L>>>; nibble_ops::NIBBLE_LENGTH]>, Value, L::Meta),
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
impl Debug for Value {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::NoValue => write!(fmt, "None"),
			Self::Value(value) => write!(fmt, "Some({:?})", ToHex(value)),
			Self::HashedValue(value, _) => write!(fmt, "Hashed({:?})", ToHex(value)),
		}
	}
}

#[cfg(feature = "std")]
impl<L: TrieLayout> Debug for Node<L>
	where L::Hash: Debug,
{
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		match *self {
			Self::Empty(_) => write!(fmt, "Empty"),
			Self::Leaf((ref a, ref b), ref c, _) =>
				write!(fmt, "Leaf({:?}, {:?})", (a, ToHex(&*b)), c),
			Self::Extension((ref a, ref b), ref c, _) =>
				write!(fmt, "Extension({:?}, {:?})", (a, ToHex(&*b)), c),
			Self::Branch(ref a, ref b, _) =>
				write!(fmt, "Branch({:?}, {:?}", a, b),
			Self::NibbledBranch((ref a, ref b), ref c, ref d, _) =>
				write!(fmt, "NibbledBranch({:?}, {:?}, {:?})", (a, ToHex(&*b)), c, d),
		}
	}
}

impl<L: TrieLayout> Node<L>
{
	// load an inline node into memory or get the hash to do the lookup later.
	fn inline_or_hash(
		parent_hash: TrieHash<L>,
		child: EncodedNodeHandle,
		db: &dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		storage: &mut NodeStorage<L>,
		layout: &L,
	) -> Result<NodeHandle<TrieHash<L>>, TrieHash<L>, CError<L>> {
		let handle = match child {
			EncodedNodeHandle::Hash(data) => {
				let hash = decode_hash::<L::Hash>(data)
					.ok_or_else(|| Box::new(TrieError::InvalidHash(parent_hash, data.to_vec())))?;
				NodeHandle::Hash(hash)
			},
			EncodedNodeHandle::Inline(data) => {
				let meta = layout.meta_for_stored_inline_node();
				let child = Node::from_encoded(parent_hash, data, db, storage, meta, layout)?;
				NodeHandle::InMemory(storage.alloc(Stored::New(child)))
			},
		};
		Ok(handle)
	}

	// Decode a node from encoded bytes.
	fn from_encoded<'a, 'b>(
		node_hash: TrieHash<L>,
		data: &'a[u8],
		db: &dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		storage: &'b mut NodeStorage<L>,
		mut meta: L::Meta, 
		layout: &L,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		let encoded_node = L::Codec::decode(data, &mut meta)
			.map_err(|e| Box::new(TrieError::DecoderError(node_hash, e)))?;
		let node = match encoded_node {
			EncodedNode::Empty => Node::Empty(meta),
			EncodedNode::Leaf(k, v) => Node::Leaf(k.into(), v.into(), meta),
			EncodedNode::Extension(key, cb) => Node::Extension(
				key.into(),
				Self::inline_or_hash(node_hash, cb, db, storage, layout)?,
				meta,
			),
			EncodedNode::Branch(encoded_children, val) => {
				let mut child = |i:usize| match encoded_children[i] {
					Some(child) => Self::inline_or_hash(node_hash, child, db, storage, layout)
						.map(Some),
					None => Ok(None),
				};

				let children = Box::new([
					child(0)?, child(1)?, child(2)?, child(3)?,
					child(4)?, child(5)?, child(6)?, child(7)?,
					child(8)?, child(9)?, child(10)?, child(11)?,
					child(12)?, child(13)?, child(14)?, child(15)?,
				]);

				Node::Branch(children, val.into(), meta)
			},
			EncodedNode::NibbledBranch(k, encoded_children, val) => {
				let mut child = |i:usize| match encoded_children[i] {
					Some(child) => Self::inline_or_hash(node_hash, child, db, storage, layout)
						.map(Some),
					None => Ok(None),
				};

				let children = Box::new([
					child(0)?, child(1)?, child(2)?, child(3)?,
					child(4)?, child(5)?, child(6)?, child(7)?,
					child(8)?, child(9)?, child(10)?, child(11)?,
					child(12)?, child(13)?, child(14)?, child(15)?,
				]);

				Node::NibbledBranch(k.into(), children, val.into(), meta)
			},
		};
		Ok(node)
	}

	// TODO: parallelize
	fn into_encoded<F>(self, child_cb: F) -> (Vec<u8>, L::Meta)
	where
		F: FnMut(NodeHandle<TrieHash<L>>, Option<&NibbleSlice>, Option<u8>) -> ChildReference<TrieHash<L>>,
	{
		Self::into_encoded_with_root_meta(self, child_cb, None)
	}

	fn into_encoded_with_root_meta<F>(
		mut self,
		mut child_cb: F,
		root_meta: Option<GlobalMeta<L>>,
	) -> (Vec<u8>, L::Meta)
	where
		F: FnMut(NodeHandle<TrieHash<L>>, Option<&NibbleSlice>, Option<u8>) -> ChildReference<TrieHash<L>>,
	{
		if let Some(root_meta) = root_meta {
			L::set_root_meta(self.meta_mut(), root_meta);
		}

		match self {
			Node::Empty(mut meta) => (L::Codec::empty_node(&mut meta).to_vec(), meta),
			Node::Leaf(partial, value, mut meta) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				(L::Codec::leaf_node(pr.right(), value.as_slice(), &mut meta), meta)
			},
			Node::Extension(partial, child, mut meta) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				let it = pr.right_iter();
				let c = child_cb(child, Some(&pr), None);
				(L::Codec::extension_node(
					it,
					pr.len(),
					c,
					&mut meta,
				), meta)
			},
			Node::Branch(mut children, value, mut meta) => {
				(L::Codec::branch_node(
					// map the `NodeHandle`s from the Branch to `ChildReferences`
					children.iter_mut()
						.map(Option::take)
						.enumerate()
						.map(|(i, maybe_child)| {
							maybe_child.map(|child| child_cb(child, None, Some(i as u8)))
						}),
					value.as_slice(),
					&mut meta,
				), meta)
			},
			Node::NibbledBranch(partial, mut children, value, mut meta) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				let it = pr.right_iter();
				(L::Codec::branch_node_nibbled(
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
					value.as_slice(),
					&mut meta,
				), meta)
			},
		}
	}

	pub(crate) fn meta_mut(&mut self) -> &mut L::Meta {
		match self {
			Node::Leaf(_, _, meta)
			| Node::Extension(_, _, meta)
			| Node::Branch(_, _, meta)
			| Node::NibbledBranch(_, _, _, meta)
			| Node::Empty(meta) => meta,
		}
	}
}

// post-inspect action.
enum Action<L: TrieLayout> {
	// Replace a node with a new one.
	Replace(Node<L>),
	// Restore the original node. This trusts that the node is actually the original.
	Restore(Node<L>),
	// if it is a new node, just clears the storage.
	Delete,
}

// post-insert action. Same as action without delete
enum InsertAction<L: TrieLayout> {
	// Replace a node with a new one.
	Replace(Node<L>),
	// Restore the original node.
	Restore(Node<L>),
}

impl<L: TrieLayout> InsertAction<L> {
	fn into_action(self) -> Action<L> {
		match self {
			InsertAction::Replace(n) => Action::Replace(n),
			InsertAction::Restore(n) => Action::Restore(n),
		}
	}

	// unwrap the node, disregarding replace or restore state.
	fn unwrap_node(self) -> Node<L> {
		match self {
			InsertAction::Replace(n) | InsertAction::Restore(n) => n,
		}
	}
}

// What kind of node is stored here.
enum Stored<L: TrieLayout> {
	// A new node.
	New(Node<L>),
	// A cached node, loaded from the DB.
	Cached(Node<L>, TrieHash<L>),
}

/// Used to build a collection of child nodes from a collection of `NodeHandle`s
#[derive(Clone, Copy)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ChildReference<HO> { // `HO` is e.g. `H256`, i.e. the output of a `Hasher`
	Hash(HO),
	Inline(HO, usize), // usize is the length of the node data we store in the `H::Out`
}

impl<HO> ChildReference<HO> {
	/// Is child reference inline.
	pub fn is_inline(&self) -> bool {
		matches!(self, ChildReference::Inline(..))
	}
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
struct NodeStorage<L: TrieLayout> {
	nodes: Vec<Stored<L>>,
	free_indices: VecDeque<usize>,
}

impl<L: TrieLayout> NodeStorage<L>
{
	/// Create a new storage.
	fn empty() -> Self {
		NodeStorage {
			nodes: Vec::new(),
			free_indices: VecDeque::new(),
		}
	}

	/// Allocate a new node in the storage.
	fn alloc(&mut self, stored: Stored<L>) -> StorageHandle {
		if let Some(idx) = self.free_indices.pop_front() {
			self.nodes[idx] = stored;
			StorageHandle(idx)
		} else {
			self.nodes.push(stored);
			StorageHandle(self.nodes.len() - 1)
		}
	}

	/// Remove a node from the storage, consuming the handle and returning the node.
	fn destroy(&mut self, handle: StorageHandle, layout: &L) -> Stored<L> {
		let idx = handle.0;

		self.free_indices.push_back(idx);
		let meta = L::Meta::meta_for_empty(layout.layout_meta());
		mem::replace(&mut self.nodes[idx], Stored::New(Node::Empty(meta)))
	}
}

impl<'a, L: TrieLayout> Index<&'a StorageHandle> for NodeStorage<L> {
	type Output = Node<L>;

	fn index(&self, handle: &'a StorageHandle) -> &Node<L> {
		match self.nodes[handle.0] {
			Stored::New(ref node) => node,
			Stored::Cached(ref node, _) => node,
		}
	}
}

/// A `Trie` implementation using a generic `HashDB` backing database.
///
/// Use it as a `TrieMut` trait object. You can use `db()` to get the backing database object.
/// Note that changes are not committed to the database until `commit` is called.
///
/// Querying the root or dropping the trie will commit automatically.
///
///
/// # Example
/// ```ignore
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
	layout: L,
	storage: NodeStorage<L>,
	db: &'a mut dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
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
	/// Create a new trie with backing database `db` and empty `root`.
	pub fn new(db: &'a mut dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>, root: &'a mut TrieHash<L>) -> Self {
		Self::new_with_layout(db, root, Default::default())
	}

	/// Create a new trie with backing database `db` and empty `root`.
	/// This could use a context specific layout.
	pub fn new_with_layout(
		db: &'a mut dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		root: &'a mut TrieHash<L>,
		layout: L,
	) -> Self {
		*root = L::Codec::hashed_null_node();
		let root_handle = NodeHandle::Hash(L::Codec::hashed_null_node());

		TrieDBMut {
			layout,
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
		db: &'a mut dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		root: &'a mut TrieHash<L>,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Self::from_existing_with_layout(db, root, Default::default())
	}

	/// Create a new trie with the backing database `db` and `root.
	/// Returns an error if `root` does not exist.
	pub fn from_existing_with_layout(
		db: &'a mut dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>>,
		root: &'a mut TrieHash<L>,
		mut layout: L,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		if !db.contains(root, EMPTY_PREFIX) {
			return Err(Box::new(TrieError::InvalidStateRoot(*root)));
		}
		if L::READ_ROOT_STATE_META {
			if let Some((encoded, mut meta)) = db.get_with_meta(root, EMPTY_PREFIX, layout.layout_meta()) {
				// read state meta
				let _ = L::Codec::decode_plan(encoded.as_slice(), &mut meta)
					.map_err(|e| Box::new(TrieError::DecoderError(*root, e)))?;
				layout.initialize_from_root_meta(&meta);
			} else {
				return Err(Box::new(TrieError::InvalidStateRoot(*root)))
			}
		} else if !db.contains(root, EMPTY_PREFIX) {
			return Err(Box::new(TrieError::InvalidStateRoot(*root)))
		}

		let root_handle = NodeHandle::Hash(*root);
		Ok(TrieDBMut {
			layout,
			storage: NodeStorage::empty(),
			db,
			root,
			root_handle,
			death_row: HashSet::new(),
			hash_count: 0,
		})
	}
	/// Get the backing database.
	pub fn db(&self) -> &dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>> {
		self.db
	}

	/// Get the backing database mutably.
	pub fn db_mut(&mut self) -> &mut dyn HashDB<L::Hash, DBValue, L::Meta, GlobalMeta<L>> {
		self.db
	}

	// Cache a node by hash.
	fn cache(
		&mut self,
		hash: TrieHash<L>,
		key: Prefix,
	) -> Result<StorageHandle, TrieHash<L>, CError<L>> {
		let (node_encoded, meta) = self.db.get_with_meta(&hash, key, self.layout.layout_meta())
			.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(hash)))?;
		let node = Node::from_encoded(
			hash,
			&node_encoded,
			&*self.db,
			&mut self.storage,
			meta,
			&self.layout,
		)?;
		Ok(self.storage.alloc(Stored::Cached(node, hash)))
	}

	// Inspect a node, choosing either to replace, restore, or delete it.
	// If restored or replaced, returns the new node along with a flag of whether it was changed.
	fn inspect<F>(
		&mut self,
		stored: Stored<L>,
		key: &mut NibbleFullKey,
		inspector: F,
	) -> Result<Option<(Stored<L>, bool)>, TrieHash<L>, CError<L>>
		where
			F: FnOnce(
				&mut Self,
				Node<L>,
				&mut NibbleFullKey,
			) -> Result<Action<L>, TrieHash<L>, CError<L>>,
	{
		let current_key = *key;
		Ok(match stored {
			Stored::New(node) => match inspector(self, node, key)? {
				Action::Restore(node) => Some((Stored::New(node), false)),
				Action::Replace(node) => Some((Stored::New(node), true)),
				Action::Delete => None,
			},
			Stored::Cached(node, hash) => match inspector(self, node, key)? {
				Action::Restore(node) => Some((Stored::Cached(node, hash), false)),
				Action::Replace(node) => {
					self.death_row.insert((hash, current_key.left_owned()));
					Some((Stored::New(node), true))
				}
				Action::Delete => {
					self.death_row.insert((hash, current_key.left_owned()));
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
					hash: *hash,
					layout: self.layout.clone(),
				}.look_up(partial),
				NodeHandle::InMemory(ref handle) => match self.storage[handle] {
					Node::Empty(_) => return Ok(None),
					Node::Leaf(ref key, ref value, _) => {
						if NibbleSlice::from_stored(key) == partial {
							return Ok(value.value_fetch::<L>()?);
						} else {
							return Ok(None);
						}
					},
					Node::Extension(ref slice, ref child, _) => {
						let slice = NibbleSlice::from_stored(slice);
						if partial.starts_with(&slice) {
							(slice.len(), child)
						} else {
							return Ok(None);
						}
					},
					Node::Branch(ref children, ref value, _) => {
						if partial.is_empty() {
							return Ok(value.value_fetch::<L>()?);
						} else {
							let idx = partial.at(0);
							match children[idx as usize].as_ref() {
								Some(child) => (1, child),
								None => return Ok(None),
							}
						}
					},
					Node::NibbledBranch(ref slice, ref children, ref value, _) => {
						let slice = NibbleSlice::from_stored(slice);
						if partial.is_empty() {
							return Ok(value.value_fetch::<L>()?);
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
		old_val: &mut Value,
	) -> Result<(StorageHandle, bool), TrieHash<L>, CError<L>> {
		let h = match handle {
			NodeHandle::InMemory(h) => h,
			NodeHandle::Hash(h) => self.cache(h, key.left())?,
		};
		// cache then destroy for hash handle (handle being root in most case)
		let stored = self.storage.destroy(h, &self.layout);
		let (new_stored, changed) = self.inspect(stored, key, move |trie, stored, key| {
			trie.insert_inspector(stored, key, value, old_val).map(|a| a.into_action())
		})?.expect("Insertion never deletes.");

		Ok((self.storage.alloc(new_stored), changed))
	}

	/// The insertion inspector.
	fn insert_inspector(
		&mut self,
		node: Node<L>,
		key: &mut NibbleFullKey,
		value: DBValue,
		old_val: &mut Value,
	) -> Result<InsertAction<L>, TrieHash<L>, CError<L>> {
		let partial = *key;

		#[cfg(feature = "std")]
		trace!(target: "trie", "augmented (partial: {:?}, value: {:?})", partial, ToHex(&value));

		Ok(match node {
			Node::Empty(meta) => {
				#[cfg(feature = "std")]
				trace!(target: "trie", "empty: COMPOSE");
				InsertAction::Replace(Node::Leaf(partial.to_stored(), Value::Value(value), meta))
			},
			Node::Branch(mut children, stored_value, meta) => {
				debug_assert!(L::USE_EXTENSION);
				#[cfg(feature = "std")]
				trace!(target: "trie", "branch: ROUTE,AUGMENT");

				if partial.is_empty() {
					let unchanged = stored_value.as_slice() == EncodedValue::Value(&value);
					let branch = Node::Branch(children, Value::Value(value), meta);
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
							return Ok(InsertAction::Restore(Node::Branch(children, stored_value, meta)));
						}
					} else {
						// Original had nothing there. compose a leaf.
						let meta_leaf = self.layout.meta_for_new_node();
						let leaf = self.storage.alloc(
							Stored::New(Node::Leaf(key.to_stored(), Value::Value(value), meta_leaf))
						);
						children[idx] = Some(leaf.into());
					}

					InsertAction::Replace(Node::Branch(children, stored_value, meta))
				}
			},
			Node::NibbledBranch(encoded, mut children, stored_value, meta) => {
				debug_assert!(!L::USE_EXTENSION);
				#[cfg(feature = "std")]
				trace!(target: "trie", "branch: ROUTE,AUGMENT");
				let existing_key = NibbleSlice::from_stored(&encoded);

				let common = partial.common_prefix(&existing_key);
				if common == existing_key.len() && common == partial.len() {
					let unchanged = stored_value.as_slice() == EncodedValue::Value(&value);
					let branch = Node::NibbledBranch(
						existing_key.to_stored(),
						children,
						Value::Value(value),
						meta,
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
					let low = Node::NibbledBranch(nbranch_partial, children, stored_value, meta);
					let ix = existing_key.at(common);
					let mut children = empty_children();
					let alloc_storage = self.storage.alloc(Stored::New(low));

					let meta_branch = self.layout.meta_for_new_node();
					children[ix as usize] = Some(alloc_storage.into());

					if partial.len() - common == 0 {
						InsertAction::Replace(Node::NibbledBranch(
							existing_key.to_stored_range(common),
							children,
							Value::Value(value),
							meta_branch,
						))
					} else {
						let ix = partial.at(common);
						let meta_leaf = self.layout.meta_for_new_node();
						let stored_leaf = Node::Leaf(partial.mid(common + 1).to_stored(), Value::Value(value), meta_leaf);
						let leaf = self.storage.alloc(Stored::New(stored_leaf));

						children[ix as usize] = Some(leaf.into());
						InsertAction::Replace(Node::NibbledBranch(
							existing_key.to_stored_range(common),
							children,
							Value::NoValue,
							meta_branch,
						))
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
								meta,
							);
							return Ok(InsertAction::Restore(n_branch));
						}
					} else {
						// Original had nothing there. compose a leaf.
						let meta_leaf = self.layout.meta_for_new_node();
						let leaf = self.storage.alloc(
							Stored::New(Node::Leaf(key.to_stored(), Value::Value(value), meta_leaf)),
						);

						children[idx] = Some(leaf.into());
					}
					InsertAction::Replace(Node::NibbledBranch(
						existing_key.to_stored(),
						children,
						stored_value,
						meta,
					))
				}
			},
			Node::Leaf(encoded, stored_value, meta) => {
				let existing_key = NibbleSlice::from_stored(&encoded);
				let common = partial.common_prefix(&existing_key);
				if common == existing_key.len() && common == partial.len() {
					#[cfg(feature = "std")]
					trace!(target: "trie", "equivalent-leaf: REPLACE");
					// equivalent leaf.
					let unchanged = stored_value.as_slice() == EncodedValue::Value(&value);
					*old_val = stored_value;
					match unchanged {
						// unchanged. restore
						true => InsertAction::Restore(Node::Leaf(encoded.clone(), Value::Value(value), meta)),
						false => InsertAction::Replace(Node::Leaf(encoded.clone(), Value::Value(value), meta)),
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
						Node::Branch(children, stored_value, meta)
					} else {
						let idx = existing_key.at(common) as usize;
						let meta_branch = self.layout.meta_for_new_node();
						let new_leaf = Node::Leaf(
							existing_key.mid(common + 1).to_stored(),
							stored_value,
							meta,
						);
						children[idx] = Some(self.storage.alloc(Stored::New(new_leaf)).into());

						if L::USE_EXTENSION {
							Node::Branch(children, Value::NoValue, meta_branch)
						} else {
							Node::NibbledBranch(partial.to_stored_range(common), children, Value::NoValue, meta_branch)
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
						stored_value,
						meta,
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
					let branch = Node::Branch(empty_children(), stored_value, meta);
					// augment the new branch.
					key.advance(common);
					let branch = self.insert_inspector(branch, key, value, old_val)?.unwrap_node();

					// always replace since we took a leaf and made an extension.
					let leaf = self.storage.alloc(Stored::New(branch));
					let meta_extension = self.layout.meta_for_new_node();
					InsertAction::Replace(Node::Extension(existing_key.to_stored(), leaf.into(), meta_extension))
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
					let low = Node::Leaf(existing_key.mid(common).to_stored(), stored_value, meta);

					// augment it. this will result in the Leaf -> common == 0 routine,
					// which creates a branch.
					key.advance(common);
					let augmented_low = self.insert_inspector(low, key, value, old_val)?
						.unwrap_node();
					// make an extension using it. this is a replacement.
					InsertAction::Replace(Node::Extension(
						existing_key.to_stored_range(common),
						self.storage.alloc(Stored::New(augmented_low)).into(),
						self.layout.meta_for_new_node(),
					))
				}
			},
			Node::Extension(encoded, child_branch, meta) => {
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
						// No need to register set branch (was here before).
						// Note putting a branch in extension requires fix.
						let ext = Node::Extension(existing_key.mid(1).to_stored(), child_branch, meta);
						Some(self.storage.alloc(Stored::New(ext)).into())
					};

					// continue inserting.
					let meta_branch = self.layout.meta_for_new_node();
					let branch_action = self.insert_inspector(
						Node::Branch(children, Value::NoValue, meta_branch),
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
	
					let new_ext = Node::Extension(existing_key.to_stored(), new_child.into(), meta);

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
					let low = Node::Extension(existing_key.mid(common).to_stored(), child_branch, meta);
					// augment the extension. this will take the common == 0 path,
					// creating a branch.
					key.advance(common);
					let augmented_low = self.insert_inspector(low, key, value, old_val)?
						.unwrap_node();

					let new_meta = self.layout.meta_for_new_node();
					// always replace, since this extension is not the one we started with.
					// this is known because the partial key is only the common prefix.
					InsertAction::Replace(Node::Extension(
						existing_key.to_stored_range(common),
						self.storage.alloc(Stored::New(augmented_low)).into(),
						new_meta,
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
		old_val: &mut Value,
	) -> Result<Option<(StorageHandle, bool)>, TrieHash<L>, CError<L>> {
		let stored = match handle {
			NodeHandle::InMemory(h) => self.storage.destroy(h, &self.layout),
			NodeHandle::Hash(h) => {
				let handle = self.cache(h, key.left())?;
				self.storage.destroy(handle, &self.layout)
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
		node: Node<L>,
		key: &mut NibbleFullKey,
		old_val: &mut Value,
	) -> Result<Action<L>, TrieHash<L>, CError<L>> {
		let partial = *key;
		Ok(match (node, partial.is_empty()) {
			(Node::Empty(_), _) => Action::Delete,
			(Node::Branch(c, Value::NoValue, meta), true) => {
				Action::Restore(Node::Branch(c, Value::NoValue, meta))
			},
			(Node::NibbledBranch(n, c, Value::NoValue, meta), true) => {
				Action::Restore(Node::NibbledBranch(n, c, Value::NoValue, meta))
			},
			(Node::Branch(children, val, meta), true) => {
				*old_val = val;
				// always replace since we took the value out.
				Action::Replace(self.fix(Node::Branch(children, Value::NoValue, meta), *key)?)
			},
			(Node::NibbledBranch(n, children, val, meta), true) => {
				*old_val = val;
				// always replace since we took the value out.
				Action::Replace(self.fix(Node::NibbledBranch(n, children, Value::NoValue, meta), *key)?)
			},
			(Node::Branch(mut children, value, meta), false) => {
				let idx = partial.at(0) as usize;
				if let Some(child) = children[idx].take() {
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"removing value out of branch child, partial={:?}",
						partial,
					);
					let prefix = *key;
					key.advance(1);
					match self.remove_at(child, key, old_val)? {
						Some((new, changed)) => {
							children[idx] = Some(new.into());
							let branch = Node::Branch(children, value, meta);
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
							Action::Replace(self.fix(Node::Branch(children, value, meta), prefix)?)
						}
					}
				} else {
					// no change needed.
					Action::Restore(Node::Branch(children, value, meta))
				}
			},
			(Node::NibbledBranch(encoded, mut children, value, meta), false) => {
				let (common, existing_length) = {
					let existing_key = NibbleSlice::from_stored(&encoded);
					(existing_key.common_prefix(&partial), existing_key.len())
				};
				if common == existing_length && common == partial.len() {

					// replace val
					if let Value::NoValue = value {
						Action::Restore(Node::NibbledBranch(encoded, children, Value::NoValue, meta))
					} else {
						*old_val = value;
						let f = self.fix(Node::NibbledBranch(encoded, children, Value::NoValue, meta), *key);
						Action::Replace(f?)
					}
				} else if common < existing_length {
					// partway through an extension -- nothing to do here.
					Action::Restore(Node::NibbledBranch(encoded, children, value, meta))
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
						let prefix = *key;
						key.advance(common + 1);
						match self.remove_at(child, key, old_val)? {
							Some((new, changed)) => {
								children[idx] = Some(new.into());
								let branch = Node::NibbledBranch(encoded, children, value, meta);
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
									self.fix(Node::NibbledBranch(encoded, children, value, meta), prefix)?
								)
							},
						}
					} else {
						// no change needed.
						Action::Restore(Node::NibbledBranch(encoded, children, value, meta))
					}
				}
			},
			(Node::Leaf(encoded, value, meta), _) => {
				if NibbleSlice::from_stored(&encoded) == partial {
					// this is the node we were looking for. Let's delete it.
					*old_val = value;
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
					Action::Restore(Node::Leaf(encoded, value, meta))
				}
			},
			(Node::Extension(encoded, child_branch, meta), _) => {
				let (common, existing_length) = {
					let existing_key = NibbleSlice::from_stored(&encoded);
					(existing_key.common_prefix(&partial), existing_key.len())
				};
				if common == existing_length {
					// try to remove from the child branch.
					#[cfg(feature = "std")]
					trace!(target: "trie", "removing from extension child, partial={:?}", partial);
					let prefix = *key;
					key.advance(common);
					match self.remove_at(child_branch, key, old_val)? {
						Some((new_child, changed)) => {
							// if the child branch was unchanged, then the extension is too.
							// otherwise, this extension may need fixing.
							match changed {
								true => Action::Replace(
									self.fix(Node::Extension(encoded, new_child.into(), meta), prefix)?
								),
								false => Action::Restore(Node::Extension(encoded, new_child.into(), meta)),
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
					Action::Restore(Node::Extension(encoded, child_branch, meta))
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
		node: Node<L>,
		key: NibbleSlice,
	) -> Result<Node<L>, TrieHash<L>, CError<L>> {
		match node {
			Node::Branch(mut children, value, meta) => {
				// if only a single value, transmute to leaf/extension and feed through fixed.
				#[cfg_attr(feature = "std", derive(Debug))]
				enum UsedIndex {
					None,
					One(u8),
					Many,
				}
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
					(UsedIndex::None, Value::NoValue) =>
						panic!("Branch with no subvalues. Something went wrong."),
					(UsedIndex::One(a), Value::NoValue) => {
						// only one onward node. make an extension.

						let new_partial = NibbleSlice::new_offset(&[a], 1).to_stored();
						let child = children[a as usize].take()
							.expect("used_index only set if occupied; qed");
						let new_node = Node::Extension(new_partial, child, meta);
						self.fix(new_node, key)
					}
					(UsedIndex::None, value) => {
						// make a leaf.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: branch -> leaf");
						Ok(Node::Leaf(NibbleSlice::new(&[]).to_stored(), value, meta))
					}
					(_, value) => {
						// all is well.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: restoring branch");
						Ok(Node::Branch(children, value, meta))
					}
				}
			},
			Node::NibbledBranch(enc_nibble, mut children, value, meta) => {
				// if only a single value, transmute to leaf/extension and feed through fixed.
				#[cfg_attr(feature = "std", derive(Debug))]
				enum UsedIndex {
					None,
					One(u8),
					Many,
				}
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
					(UsedIndex::None, Value::NoValue) =>
						panic!("Branch with no subvalues. Something went wrong."),
					(UsedIndex::One(a), Value::NoValue) => {
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
							NodeHandle::InMemory(h) => self.storage.destroy(h, &self.layout),
							NodeHandle::Hash(h) => {
								let handle = self.cache(h, child_prefix)?;
								self.storage.destroy(handle, &self.layout)
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
							Node::Leaf(sub_partial, value, meta) => {
								let mut enc_nibble = enc_nibble;
								combine_key(
									&mut enc_nibble,
									(nibble_ops::NIBBLE_PER_BYTE - 1, &[a][..]),
								);
								combine_key(
									&mut enc_nibble,
									(sub_partial.0, &sub_partial.1[..]),
								);
								Ok(Node::Leaf(enc_nibble, value, meta))
							},
							Node::NibbledBranch(sub_partial, ch_children, ch_value, meta) => {
								let mut enc_nibble = enc_nibble;
								combine_key(
									&mut enc_nibble,
									(nibble_ops::NIBBLE_PER_BYTE - 1, &[a][..]),
								);
								combine_key(
									&mut enc_nibble,
									(sub_partial.0, &sub_partial.1[..]),
								);
								Ok(Node::NibbledBranch(enc_nibble, ch_children, ch_value, meta))
							},
							_ => unreachable!(),
						}
					},
					(UsedIndex::None, value) => {
						// make a leaf.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: branch -> leaf");
						Ok(Node::Leaf(enc_nibble, value, meta))
					},
					(_, value) => {
						// all is well.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: restoring branch");
						Ok(Node::NibbledBranch(enc_nibble, children, value, meta))
					},
				}
			},
			Node::Extension(partial, child, meta) => {
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
					NodeHandle::InMemory(h) => self.storage.destroy(h, &self.layout),
					NodeHandle::Hash(h) => {
						let handle = self.cache(h, child_prefix)?;
						self.storage.destroy(handle, &self.layout)
					}
				};

				let (child_node, maybe_hash) = match stored {
					Stored::New(node) => (node, None),
					Stored::Cached(node, hash) => (node, Some(hash))
				};

				match child_node {
					Node::Extension(sub_partial, sub_child, meta) => {
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
						self.fix(Node::Extension(partial, sub_child, meta), key)
					}
					Node::Leaf(sub_partial, value, meta) => {
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
						Ok(Node::Leaf(partial, value, meta))
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

						Ok(Node::Extension(partial, self.storage.alloc(stored).into(), meta))
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

		match self.storage.destroy(handle, &self.layout) {
			Stored::New(node) => {
				let mut k = NibbleVec::new();

				let global_meta  = if L::READ_ROOT_STATE_META {
					Some(self.layout.layout_meta())
				} else {
					None
				};
				let (encoded_root, meta) = node.into_encoded_with_root_meta(
					|child, o_slice, o_index| {
						let mov = k.append_optional_slice_and_nibble(o_slice, o_index);
						let cr = self.commit_child(child, &mut k);
						k.drop_lasts(mov);
						cr
					},
					global_meta,
				);
				#[cfg(feature = "std")]
				trace!(target: "trie", "encoded root node: {:#x?}", &encoded_root[..]);

				*self.root = self.db.insert_with_meta(EMPTY_PREFIX, &encoded_root[..], meta);
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
				match self.storage.destroy(storage_handle, &self.layout) {
					Stored::Cached(_, hash) => ChildReference::Hash(hash),
					Stored::New(node) => {
						let (encoded, meta) = {
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
							node.into_encoded(commit_child)
						};
						if encoded.len() >= L::Hash::LENGTH {
							let hash = self.db.insert_with_meta(prefix.as_prefix(), &encoded[..], meta);
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

	/// Force update of meta in state from layout value (update root even
	/// if there was no changes done).
	pub fn force_layout_meta(
		&mut self,
	) -> Result<(), TrieHash<L>, CError<L>> {
		if L::READ_ROOT_STATE_META {
			let root = match self.root_handle {
				NodeHandle::Hash(h) => self.cache(h, EMPTY_PREFIX)?,
				NodeHandle::InMemory(StorageHandle(x)) => StorageHandle(x),
			};
			match self.storage.destroy(root, &self.layout) {
				Stored::Cached(node, hash) => {
					self.death_row.insert((hash, Default::default()));
					self.root_handle = NodeHandle::InMemory(self.storage.alloc(Stored::New(node)));
				},
				Stored::New(_node) => (),
			}
		}
		Ok(())
	}

	/// Get current value of Trie layout.
	pub fn layout(&self) -> L {
		self.layout.clone()
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
				Node::Empty(_) => true,
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
	) -> Result<Value, TrieHash<L>, CError<L>> {
		if !L::ALLOW_EMPTY && value.is_empty() { return self.remove(key) }

		let mut old_val = Value::NoValue;

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

	fn remove(&mut self, key: &[u8]) -> Result<Value, TrieHash<L>, CError<L>> {
		#[cfg(feature = "std")]
		trace!(target: "trie", "remove: key={:#x?}", key);

		let root_handle = self.root_handle();
		let mut key = NibbleSlice::new(key);
		let mut old_val = Value::NoValue;

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
	use crate::nibble::BackingByteVec;

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
}

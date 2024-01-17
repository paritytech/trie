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

//! In-memory trie representation.

use crate::{
	lookup::Lookup,
	nibble::{nibble_ops, BackingByteVec, NibbleSlice, NibbleVec},
	node::{
		decode_hash, Node as EncodedNode, NodeHandle as EncodedNodeHandle, NodeHandleOwned,
		NodeKey, NodeOwned, Value as EncodedValue, ValueOwned,
	},
	node_codec::NodeCodec,
	rstd::{boxed::Box, convert::TryFrom, mem, ops::Index, result, vec::Vec, VecDeque},
	Bytes, CError, DBValue, Result, TrieAccess, TrieCache, TrieError, TrieHash, TrieLayout,
	TrieRecorder,
};

use hash_db::{HashDB, Hasher, Prefix};

#[cfg(feature = "std")]
use std::collections::BTreeMap;
#[cfg(feature = "std")]
use std::collections::HashSet as Set;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
#[cfg(not(feature = "std"))]
use alloc::collections::btree_set::BTreeMap;
#[cfg(not(feature = "std"))]
use alloc::collections::btree_set::BTreeSet as Set;

#[cfg(feature = "std")]
use log::trace;
use memory_db::MemoryDB;

#[cfg(feature = "std")]
use crate::rstd::fmt::{self, Debug};

// For lookups into the Node storage buffer.
// This is deliberately non-copyable.
#[cfg_attr(feature = "std", derive(Debug))]
struct StorageHandle(usize);

// Handles to nodes in the trie.
#[cfg_attr(feature = "std", derive(Debug))]
enum NodeHandle<H, L> {
	/// Loaded into memory.
	InMemory(StorageHandle),
	/// Either a hash or an inline node
	Hash(H, L),
}

impl<H, L> From<StorageHandle> for NodeHandle<H, L> {
	fn from(handle: StorageHandle) -> Self {
		NodeHandle::InMemory(handle)
	}
}

fn empty_children<H, L>() -> Box<[Option<NodeHandle<H, L>>; nibble_ops::NIBBLE_LENGTH]> {
	Box::new([
		None, None, None, None, None, None, None, None, None, None, None, None, None, None, None,
		None,
	])
}

pub type ChildChangeset<L> = Box<ChangesetNodeRef<TrieHash<L>, <L as TrieLayout>::Location>>;

/// Type alias to indicate the nible covers a full key,
/// therefore its left side is a full prefix.
type NibbleFullKey<'key> = NibbleSlice<'key>;

/// Value representation for Node.
#[derive(Clone, Eq)]
pub enum Value<L: TrieLayout> {
	/// Value bytes inlined in a trie node.
	Inline(Bytes),
	/// Hash of the value.
	Node(TrieHash<L>, L::Location),
	/// Hash of value bytes if calculated and value bytes.
	/// The hash may be undefined until it node is added
	/// to the db.
	NewNode(Option<TrieHash<L>>, Bytes),
}

impl<L: TrieLayout> PartialEq<Self> for Value<L> {
	fn eq(&self, other: &Self) -> bool {
		match (self, other) {
			(Value::Inline(v), Value::Inline(ov)) => v == ov,
			(Value::Node(h, _), Value::Node(oh, _)) => h == oh,
			(Value::NewNode(Some(h), _), Value::NewNode(Some(oh), _)) => h == oh,
			(Value::NewNode(_, v), Value::NewNode(_, ov)) => v == ov,
			// Note that for uncalculated hash we do not calculate it and default to true.
			// This is rather similar to default Eq implementation.
			_ => false,
		}
	}
}

impl<'a, L: TrieLayout> From<EncodedValue<'a, L::Location>> for Value<L> {
	fn from(v: EncodedValue<'a, L::Location>) -> Self {
		match v {
			EncodedValue::Inline(value) => Value::Inline(value.into()),
			EncodedValue::Node(hash, l) => {
				let mut h = TrieHash::<L>::default();
				h.as_mut().copy_from_slice(hash);
				Value::Node(h, l)
			},
		}
	}
}

impl<L: TrieLayout> From<&ValueOwned<TrieHash<L>, L::Location>> for Value<L> {
	fn from(val: &ValueOwned<TrieHash<L>, L::Location>) -> Self {
		match val {
			ValueOwned::Inline(data, _) => Self::Inline(data.clone()),
			ValueOwned::Node(hash, location) => Self::Node(*hash, *location),
		}
	}
}

impl<L: TrieLayout> From<(Bytes, Option<u32>)> for Value<L> {
	fn from((v, threshold): (Bytes, Option<u32>)) -> Self {
		match v {
			value =>
				if threshold.map_or(false, |threshold| value.len() >= threshold as usize) {
					Value::NewNode(None, value)
				} else {
					Value::Inline(value)
				},
		}
	}
}

enum NodeToEncode<'a, H, L> {
	Node(&'a [u8]),
	TrieNode(NodeHandle<H, L>),
}

impl<L: TrieLayout> Value<L> {
	fn new(value: Bytes, new_threshold: Option<u32>) -> Self {
		(value, new_threshold).into()
	}

	fn into_encoded<'a, F>(
		&'a mut self,
		partial: Option<&NibbleSlice>,
		f: &mut F,
	) -> EncodedValue<'a, L::Location>
	where
		F: FnMut(
			NodeToEncode<TrieHash<L>, L::Location>,
			Option<&NibbleSlice>,
			Option<u8>,
		) -> ChildReference<TrieHash<L>, L::Location>,
	{
		if let Value::NewNode(hash, value) = self {
			let new_hash = if let ChildReference::Hash(hash, _) =
				f(NodeToEncode::Node(&value), partial, None)
			{
				hash
			} else {
				unreachable!("Value node can never be inlined; qed")
			};
			if let Some(h) = hash.as_ref() {
				debug_assert!(h == &new_hash);
			} else {
				*hash = Some(new_hash);
			}
		} else if let Value::Node(hash, location) = self {
			f(NodeToEncode::TrieNode(NodeHandle::Hash(*hash, *location)), partial, None);
		}
		let value = match &*self {
			Value::Inline(value) => EncodedValue::Inline(&value),
			Value::Node(hash, location) => EncodedValue::Node(hash.as_ref(), *location),
			Value::NewNode(Some(hash), _value) =>
				EncodedValue::Node(hash.as_ref(), Default::default()),
			Value::NewNode(None, _value) =>
				unreachable!("New external value are always added before encoding anode"),
		};
		value
	}

	fn in_memory_fetched_value(
		&self,
		prefix: Prefix,
		db: &dyn HashDB<L::Hash, DBValue, L::Location>,
		recorder: &Option<core::cell::RefCell<&mut dyn TrieRecorder<TrieHash<L>, L::Location>>>,
		full_key: &[u8],
	) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		Ok(Some(match self {
			Value::Inline(value) => value.to_vec(),
			Value::NewNode(_, value) => value.to_vec(),
			Value::Node(hash, location) =>
				if let Some((value, _)) = db.get(hash, prefix, *location) {
					recorder.as_ref().map(|r| {
						r.borrow_mut().record(TrieAccess::Value {
							hash: *hash,
							value: value.as_slice().into(),
							full_key,
						})
					});

					value
				} else {
					return Err(Box::new(TrieError::IncompleteDatabase(hash.clone())))
				},
		}))
	}
}

/// Node types in the Trie.
enum Node<L: TrieLayout> {
	/// Empty node.
	Empty,
	/// A leaf node contains the end of a key and a value.
	/// This key is encoded from a `NibbleSlice`, meaning it contains
	/// a flag indicating it is a leaf.
	Leaf(NodeKey, Value<L>, Option<ChildChangeset<L>>),
	/// An extension contains a shared portion of a key and a child node.
	/// The shared portion is encoded from a `NibbleSlice` meaning it contains
	/// a flag indicating it is an extension.
	/// The child node is always a branch.
	Extension(NodeKey, NodeHandle<TrieHash<L>, L::Location>),
	/// A branch has up to 16 children and an optional value.
	Branch(
		Box<[Option<NodeHandle<TrieHash<L>, L::Location>>; nibble_ops::NIBBLE_LENGTH]>,
		Option<Value<L>>,
		Option<ChildChangeset<L>>,
	),
	/// Branch node with support for a nibble (to avoid extension node).
	NibbledBranch(
		NodeKey,
		Box<[Option<NodeHandle<TrieHash<L>, L::Location>>; nibble_ops::NIBBLE_LENGTH]>,
		Option<Value<L>>,
		Option<ChildChangeset<L>>,
	),
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
impl<L: TrieLayout> Debug for Value<L> {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Inline(value) => write!(fmt, "Some({:?})", ToHex(value)),
			Self::Node(hash, _l) => write!(fmt, "Hash({:?})", ToHex(hash.as_ref())),
			Self::NewNode(Some(hash), _) => write!(fmt, "Hash({:?})", ToHex(hash.as_ref())),
			Self::NewNode(_hash, value) => write!(fmt, "Some({:?})", ToHex(value)),
		}
	}
}

#[cfg(feature = "std")]
impl<L: TrieLayout> Debug for Node<L>
where
	L::Hash: Debug,
	L::Location: Debug,
{
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Empty => write!(fmt, "Empty"),
			Self::Leaf((a, b), c, _) => write!(fmt, "Leaf({:?}, {:?})", (a, ToHex(&*b)), c),
			Self::Extension((a, b), c) => write!(fmt, "Extension({:?}, {:?})", (a, ToHex(&*b)), c),
			Self::Branch(a, b, _) => write!(fmt, "Branch({:?}, {:?}", a, b),
			Self::NibbledBranch((a, b), c, d, _) =>
				write!(fmt, "NibbledBranch({:?}, {:?}, {:?})", (a, ToHex(&*b)), c, d),
		}
	}
}

impl<L: TrieLayout> Node<L> {
	// load an inline node into memory or get the hash to do the lookup later.
	fn inline_or_hash(
		parent_hash: TrieHash<L>,
		child: EncodedNodeHandle<L::Location>,
		storage: &mut NodeStorage<L>,
	) -> Result<NodeHandle<TrieHash<L>, L::Location>, TrieHash<L>, CError<L>> {
		let handle = match child {
			EncodedNodeHandle::Hash(data, location) => {
				let hash = decode_hash::<L::Hash>(data)
					.ok_or_else(|| Box::new(TrieError::InvalidHash(parent_hash, data.to_vec())))?;
				NodeHandle::Hash(hash, location)
			},
			EncodedNodeHandle::Inline(data) => {
				let child = Node::from_encoded(parent_hash, data, &[], storage)?;
				NodeHandle::InMemory(storage.alloc(Stored::New(child)))
			},
		};
		Ok(handle)
	}

	// load an inline node into memory or get the hash to do the lookup later.
	fn inline_or_hash_owned(
		child: &NodeHandleOwned<TrieHash<L>, L::Location>,
		storage: &mut NodeStorage<L>,
	) -> NodeHandle<TrieHash<L>, L::Location> {
		match child {
			NodeHandleOwned::Hash(hash, location) => NodeHandle::Hash(*hash, *location),
			NodeHandleOwned::Inline(node) => {
				let child = Node::from_node_owned(&**node, storage);
				NodeHandle::InMemory(storage.alloc(Stored::New(child)))
			},
		}
	}

	// Decode a node from encoded bytes.
	fn from_encoded<'a, 'b>(
		node_hash: TrieHash<L>,
		data: &'a [u8],
		locations: &[L::Location],
		storage: &'b mut NodeStorage<L>,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		let encoded_node = L::Codec::decode(data, locations)
			.map_err(|e| Box::new(TrieError::DecoderError(node_hash, e)))?;
		let node = match encoded_node {
			EncodedNode::Empty => Node::Empty,
			EncodedNode::Leaf(k, v) => Node::Leaf(k.into(), v.into(), None),
			EncodedNode::Extension(key, cb) =>
				Node::Extension(key.into(), Self::inline_or_hash(node_hash, cb, storage)?),
			EncodedNode::Branch(encoded_children, val) => {
				let mut child = |i: usize| match encoded_children[i] {
					Some(child) => Self::inline_or_hash(node_hash, child, storage).map(Some),
					None => Ok(None),
				};

				let children = Box::new([
					child(0)?,
					child(1)?,
					child(2)?,
					child(3)?,
					child(4)?,
					child(5)?,
					child(6)?,
					child(7)?,
					child(8)?,
					child(9)?,
					child(10)?,
					child(11)?,
					child(12)?,
					child(13)?,
					child(14)?,
					child(15)?,
				]);

				Node::Branch(children, val.map(Into::into), None)
			},
			EncodedNode::NibbledBranch(k, encoded_children, val) => {
				let mut child = |i: usize| match encoded_children[i] {
					Some(child) => Self::inline_or_hash(node_hash, child, storage).map(Some),
					None => Ok(None),
				};

				let children = Box::new([
					child(0)?,
					child(1)?,
					child(2)?,
					child(3)?,
					child(4)?,
					child(5)?,
					child(6)?,
					child(7)?,
					child(8)?,
					child(9)?,
					child(10)?,
					child(11)?,
					child(12)?,
					child(13)?,
					child(14)?,
					child(15)?,
				]);

				Node::NibbledBranch(k.into(), children, val.map(Into::into), None)
			},
		};
		Ok(node)
	}

	/// Decode a node from a [`NodeOwned`].
	fn from_node_owned(
		node_owned: &NodeOwned<TrieHash<L>, L::Location>,
		storage: &mut NodeStorage<L>,
	) -> Self {
		match node_owned {
			NodeOwned::Empty => Node::Empty,
			NodeOwned::Leaf(k, v) => Node::Leaf(k.into(), v.into(), None),
			NodeOwned::Extension(key, cb) =>
				Node::Extension(key.into(), Self::inline_or_hash_owned(cb, storage)),
			NodeOwned::Branch(encoded_children, val) => {
				let mut child = |i: usize| {
					encoded_children[i]
						.as_ref()
						.map(|child| Self::inline_or_hash_owned(child, storage))
				};

				let children = Box::new([
					child(0),
					child(1),
					child(2),
					child(3),
					child(4),
					child(5),
					child(6),
					child(7),
					child(8),
					child(9),
					child(10),
					child(11),
					child(12),
					child(13),
					child(14),
					child(15),
				]);

				Node::Branch(children, val.as_ref().map(Into::into), None)
			},
			NodeOwned::NibbledBranch(k, encoded_children, val) => {
				let mut child = |i: usize| {
					encoded_children[i]
						.as_ref()
						.map(|child| Self::inline_or_hash_owned(child, storage))
				};

				let children = Box::new([
					child(0),
					child(1),
					child(2),
					child(3),
					child(4),
					child(5),
					child(6),
					child(7),
					child(8),
					child(9),
					child(10),
					child(11),
					child(12),
					child(13),
					child(14),
					child(15),
				]);

				Node::NibbledBranch(k.into(), children, val.as_ref().map(Into::into), None)
			},
			NodeOwned::Value(_, _) =>
				unreachable!("`NodeOwned::Value` can only be returned for the hash of a value."),
		}
	}

	// TODO: parallelize
	/// Here `child_cb` should process the first parameter to either insert an external
	/// node value or to encode and add a new branch child node.
	fn into_encoded<F>(self, mut child_cb: F) -> (Vec<u8>, Option<ChildChangeset<L>>)
	where
		F: FnMut(
			NodeToEncode<TrieHash<L>, L::Location>,
			Option<&NibbleSlice>,
			Option<u8>,
		) -> ChildReference<TrieHash<L>, L::Location>,
	{
		match self {
			Node::Empty => (L::Codec::empty_node().to_vec(), None),
			Node::Leaf(partial, mut value, child_changes) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				let value = value.into_encoded::<F>(Some(&pr), &mut child_cb);
				(L::Codec::leaf_node(pr.right_iter(), pr.len(), value), child_changes)
			},
			Node::Extension(partial, child) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				let it = pr.right_iter();
				let c = child_cb(NodeToEncode::TrieNode(child), Some(&pr), None);
				(L::Codec::extension_node(it, pr.len(), c), None)
			},
			Node::Branch(mut children, mut value, child_changes) => {
				let value = value.as_mut().map(|v| v.into_encoded::<F>(None, &mut child_cb));
				(
					L::Codec::branch_node(
						// map the `NodeHandle`s from the Branch to `ChildReferences`
						children.iter_mut().map(Option::take).enumerate().map(
							|(i, maybe_child)| {
								maybe_child.map(|child| {
									child_cb(NodeToEncode::TrieNode(child), None, Some(i as u8))
								})
							},
						),
						value,
					),
					child_changes,
				)
			},
			Node::NibbledBranch(partial, mut children, mut value, child_changes) => {
				let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
				let value = value.as_mut().map(|v| v.into_encoded::<F>(Some(&pr), &mut child_cb));
				let it = pr.right_iter();
				(
					L::Codec::branch_node_nibbled(
						it,
						pr.len(),
						// map the `NodeHandle`s from the Branch to `ChildReferences`
						children.iter_mut().map(Option::take).enumerate().map(
							|(i, maybe_child)| {
								//let branch_index = [i as u8];
								maybe_child.map(|child| {
									let pr = NibbleSlice::new_offset(&partial.1[..], partial.0);
									child_cb(
										NodeToEncode::TrieNode(child),
										Some(&pr),
										Some(i as u8),
									)
								})
							},
						),
						value,
					),
					child_changes,
				)
			},
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
	Delete(Option<ChildChangeset<L>>),
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
	Cached(Node<L>, TrieHash<L>, L::Location),
}

/// Used to build a collection of child nodes from a collection of `NodeHandle`s
#[derive(Clone, Copy)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ChildReference<HO, L> {
	// `HO` is e.g. `H256`, i.e. the output of a `Hasher`
	Hash(HO, L),
	Inline(HO, usize), // usize is the length of the node data we store in the `H::Out`
}

impl<'a, HO, L> TryFrom<EncodedNodeHandle<'a, L>> for ChildReference<HO, L>
where
	HO: AsRef<[u8]> + AsMut<[u8]> + Default + Clone + Copy,
{
	type Error = Vec<u8>;

	fn try_from(handle: EncodedNodeHandle<'a, L>) -> result::Result<Self, Vec<u8>> {
		match handle {
			EncodedNodeHandle::Hash(data, location) => {
				let mut hash = HO::default();
				if data.len() != hash.as_ref().len() {
					return Err(data.to_vec())
				}
				hash.as_mut().copy_from_slice(data);
				Ok(ChildReference::Hash(hash, location))
			},
			EncodedNodeHandle::Inline(data) => {
				let mut hash = HO::default();
				if data.len() > hash.as_ref().len() {
					return Err(data.to_vec())
				}
				hash.as_mut()[..data.len()].copy_from_slice(data);
				Ok(ChildReference::Inline(hash, data.len()))
			},
		}
	}
}

/// Compact and cache-friendly storage for Trie nodes.
struct NodeStorage<L: TrieLayout> {
	nodes: Vec<Stored<L>>,
	free_indices: VecDeque<usize>,
}

impl<L: TrieLayout> NodeStorage<L> {
	/// Create a new storage.
	fn empty() -> Self {
		NodeStorage { nodes: Vec::new(), free_indices: VecDeque::new() }
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
	fn destroy(&mut self, handle: StorageHandle) -> Stored<L> {
		let idx = handle.0;

		self.free_indices.push_back(idx);
		mem::replace(&mut self.nodes[idx], Stored::New(Node::Empty))
	}
}

impl<'a, L: TrieLayout> Index<&'a StorageHandle> for NodeStorage<L> {
	type Output = Node<L>;

	fn index(&self, handle: &'a StorageHandle) -> &Node<L> {
		match self.nodes[handle.0] {
			Stored::New(ref node) => node,
			Stored::Cached(ref node, _, _) => node,
		}
	}
}

/// A builder for creating a [`TrieDBMut`].
pub struct TrieDBMutBuilder<'db, L: TrieLayout> {
	db: &'db dyn HashDB<L::Hash, DBValue, L::Location>,
	root: TrieHash<L>,
	root_location: L::Location,
	cache: Option<&'db mut dyn TrieCache<L::Codec, L::Location>>,
	recorder: Option<&'db mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
}

impl<'db, L: TrieLayout> TrieDBMutBuilder<'db, L> {
	/// Create a builder for constructing a new trie with the backing database `db` and empty
	/// `root`.
	pub fn new(db: &'db dyn HashDB<L::Hash, DBValue, L::Location>) -> Self {
		let root = L::Codec::hashed_null_node();
		Self { root, db, cache: None, recorder: None, root_location: Default::default() }
	}

	/// Create a builder for constructing a new trie with the backing database `db` and `root`.
	///
	/// This doesn't check if `root` exists in the given `db`. If `root` doesn't exist it will fail
	/// when trying to lookup any key.
	pub fn from_existing(
		db: &'db dyn HashDB<L::Hash, DBValue, L::Location>,
		root: TrieHash<L>,
	) -> Self {
		Self { db, root, cache: None, recorder: None, root_location: Default::default() }
	}

	/// Same as `from_existing` but force a db location to access root.
	/// Note root in parameter is not checked.
	pub fn from_existing_with_db_location(
		db: &'db dyn HashDB<L::Hash, DBValue, L::Location>,
		root: TrieHash<L>,
		root_location: L::Location,
	) -> Self {
		Self { db, root, cache: None, recorder: None, root_location }
	}

	/// Use the given `cache` for the db.
	pub fn with_cache(mut self, cache: &'db mut dyn TrieCache<L::Codec, L::Location>) -> Self {
		self.cache = Some(cache);
		self
	}

	/// Use the given optional `cache` for the db.
	pub fn with_optional_cache<'cache: 'db>(
		mut self,
		cache: Option<&'cache mut dyn TrieCache<L::Codec, L::Location>>,
	) -> Self {
		// Make the compiler happy by "converting" the lifetime
		self.cache = cache.map(|c| c as _);
		self
	}

	/// Use the given `recorder` to record trie accesses.
	pub fn with_recorder(
		mut self,
		recorder: &'db mut dyn TrieRecorder<TrieHash<L>, L::Location>,
	) -> Self {
		self.recorder = Some(recorder);
		self
	}

	/// Use the given optional `recorder` to record trie accesses.
	pub fn with_optional_recorder<'recorder: 'db>(
		mut self,
		recorder: Option<&'recorder mut dyn TrieRecorder<TrieHash<L>, L::Location>>,
	) -> Self {
		// Make the compiler happy by "converting" the lifetime
		self.recorder = recorder.map(|r| r as _);
		self
	}

	/// Build the [`TrieDBMut`].
	pub fn build(self) -> TrieDBMut<'db, L> {
		let root_handle = NodeHandle::Hash(self.root, self.root_location);

		TrieDBMut {
			db: self.db,
			root: self.root,
			cache: self.cache,
			recorder: self.recorder.map(core::cell::RefCell::new),
			hash_count: 0,
			storage: NodeStorage::empty(),
			death_row: Default::default(),
			death_row_child: Default::default(),
			root_handle,
		}
	}
}

#[derive(Debug)]
pub struct NewChangesetNode<H, DL> {
	pub hash: H,
	pub prefix: OwnedPrefix,
	pub data: Vec<u8>,
	pub children: Vec<ChangesetNodeRef<H, DL>>,
	// Storing the key and removed nodes (only needed for old trie).
	pub key_childset: Option<(Vec<u8>, Vec<(H, OwnedPrefix)>)>,
}

#[derive(Debug)]
pub struct ExistingChangesetNode<H, DL> {
	pub hash: H,
	pub prefix: OwnedPrefix,
	pub location: DL,
}

#[derive(Debug)]
pub enum ChangesetNodeRef<H, DL> {
	New(NewChangesetNode<H, DL>),
	Existing(ExistingChangesetNode<H, DL>),
}

impl<H, DL> ChangesetNodeRef<H, DL> {
	pub fn hash(&self) -> &H {
		match self {
			ChangesetNodeRef::New(node) => &node.hash,
			ChangesetNodeRef::Existing(node) => &node.hash,
		}
	}
}

#[derive(Debug)]
pub struct Changeset<H, DL> {
	pub root: ChangesetNodeRef<H, DL>,
	pub removed: Vec<(H, OwnedPrefix)>,
}

pub fn prefix_prefix(ks: &[u8], prefix: Prefix) -> (Vec<u8>, Option<u8>) {
	let mut result = Vec::with_capacity(ks.len() + prefix.0.len());
	result.extend_from_slice(ks);
	result.extend_from_slice(prefix.0);
	(result, prefix.1)
}

impl<H: Copy, DL: Default> Changeset<H, DL> {
	pub fn apply_to<K, MH>(&self, mem_db: &mut MemoryDB<MH, K, DBValue>) -> H
	where
		K: memory_db::KeyFunction<MH> + Send + Sync,
		MH: Hasher<Out = H> + Send + Sync,
	{
		for (hash, prefix) in &self.removed {
			mem_db.remove(hash, (prefix.0.as_slice(), prefix.1));
		}

		fn apply_node<H, DL, MH, K>(
			node: &ChangesetNodeRef<H, DL>,
			mem_db: &mut MemoryDB<MH, K, DBValue>,
			ks: Option<&[u8]>,
		) where
			K: memory_db::KeyFunction<MH> + Send + Sync,
			MH: Hasher<Out = H> + Send + Sync,
		{
			match node {
				ChangesetNodeRef::New(node) => {
					let ks = if ks.is_some() {
						ks
					} else if let Some((k, removed)) = node.key_childset.as_ref() {
						for (hash, p) in removed.iter() {
							let prefixed = prefix_prefix(k.as_slice(), (p.0.as_slice(), p.1));
							mem_db.remove(hash, (prefixed.0.as_slice(), prefixed.1));
						}
						Some(k.as_slice())
					} else {
						None
					};
					for child in &node.children {
						apply_node(child, mem_db, ks);
					}
					if let Some(ks) = ks {
						let prefixed = prefix_prefix(ks, (node.prefix.0.as_slice(), node.prefix.1));
						mem_db.insert((prefixed.0.as_slice(), prefixed.1), &node.data);
					} else {
						mem_db.insert((node.prefix.0.as_slice(), node.prefix.1), &node.data);
					}
				},
				ChangesetNodeRef::Existing(_) => {},
			}
		}
		apply_node::<H, DL, MH, K>(&self.root, mem_db, None);
		self.root_hash()
	}

	pub fn apply_with_prefix<K, MH>(&self, mem_db: &mut MemoryDB<MH, K, DBValue>, ks: &[u8]) -> H
	where
		K: memory_db::KeyFunction<MH> + Send + Sync,
		MH: Hasher<Out = H> + Send + Sync,
	{
		fn apply_node<H, DL, MH, K>(
			node: &ChangesetNodeRef<H, DL>,
			ks: &[u8],
			mem_db: &mut MemoryDB<MH, K, DBValue>,
		) where
			K: memory_db::KeyFunction<MH> + Send + Sync,
			MH: Hasher<Out = H> + Send + Sync,
		{
			match node {
				ChangesetNodeRef::New(node) => {
					for child in &node.children {
						apply_node(child, ks, mem_db);
					}
					let prefixed = prefix_prefix(ks, (node.prefix.0.as_slice(), node.prefix.1));
					mem_db.insert((prefixed.0.as_slice(), prefixed.1), &node.data);
				},
				ChangesetNodeRef::Existing(_) => {},
			}
		}

		for (hash, p) in &self.removed {
			let prefixed = prefix_prefix(ks, (p.0.as_slice(), p.1));
			mem_db.remove(hash, (prefixed.0.as_slice(), prefixed.1));
		}
		apply_node(&self.root, ks, mem_db);
		self.root_hash()
	}

	pub fn root_hash(&self) -> H {
		match &self.root {
			ChangesetNodeRef::New(node) => node.hash,
			ChangesetNodeRef::Existing(node) => node.hash,
		}
	}

	pub fn empty(root: H) -> Self {
		Self {
			root: ChangesetNodeRef::Existing(ExistingChangesetNode {
				hash: root,
				prefix: (BackingByteVec::new(), None),
				location: Default::default(),
			}),
			removed: Default::default(),
		}
	}
}

pub type OwnedPrefix = (BackingByteVec, Option<u8>);

/// A `Trie` implementation using a generic `HashDB` backing database.
///
/// Use it as a `TrieMut` trait object. You can use `db()` to get the backing database object.
/// Note that changes are not committed to the database until `commit` is called.
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
	storage: NodeStorage<L>,
	db: &'a dyn HashDB<L::Hash, DBValue, L::Location>,
	root: TrieHash<L>,
	root_handle: NodeHandle<TrieHash<L>, L::Location>,
	death_row: Set<(TrieHash<L>, OwnedPrefix)>,
	death_row_child: Vec<ChildChangeset<L>>,
	/// The number of hash operations this trie has performed.
	/// Note that none are performed until changes are committed.
	hash_count: usize,
	/// Optional cache for speeding up the lookup of nodes.
	cache: Option<&'a mut dyn TrieCache<L::Codec, L::Location>>,
	/// Optional trie recorder for recording trie accesses.
	recorder: Option<core::cell::RefCell<&'a mut dyn TrieRecorder<TrieHash<L>, L::Location>>>,
}

impl<'a, L> TrieDBMut<'a, L>
where
	L: TrieLayout,
{
	/// Get the backing database.
	pub fn db(&self) -> &dyn HashDB<L::Hash, DBValue, L::Location> {
		self.db
	}

	// Cache a node by hash.
	fn cache(
		&mut self,
		hash: TrieHash<L>,
		key: Prefix,
		location: L::Location,
	) -> Result<StorageHandle, TrieHash<L>, CError<L>> {
		// We only check the `cache` for a node with `get_node` and don't insert
		// the node if it wasn't there, because in substrate we only access the node while computing
		// a new trie (aka some branch). We assume that this node isn't that important
		// to have it being cached.
		let node = match self.cache.as_mut().and_then(|c| c.get_node(&hash, location)) {
			Some(node) => {
				if let Some(recorder) = self.recorder.as_mut() {
					recorder.borrow_mut().record(TrieAccess::NodeOwned { hash, node_owned: &node });
				}

				Node::from_node_owned(&node, &mut self.storage)
			},
			None => {
				let (node_encoded, locations) = self
					.db
					.get(&hash, key, location)
					.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(hash)))?;

				if let Some(recorder) = self.recorder.as_mut() {
					recorder.borrow_mut().record(TrieAccess::EncodedNode {
						hash,
						encoded_node: node_encoded.as_slice().into(),
					});
				}

				Node::from_encoded(hash, &node_encoded, &locations, &mut self.storage)?
			},
		};

		Ok(self.storage.alloc(Stored::Cached(node, hash, location)))
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
				Action::Delete(child_changes) => {
					child_changes.map(|c| self.death_row_child.push(c));
					None
				},
			},
			Stored::Cached(node, hash, location) => match inspector(self, node, key)? {
				Action::Restore(node) => Some((Stored::Cached(node, hash, location), false)),
				Action::Replace(node) => {
					self.death_row.insert((hash, current_key.left_owned()));
					Some((Stored::New(node), true))
				},
				Action::Delete(child_changes) => {
					self.death_row.insert((hash, current_key.left_owned()));
					child_changes.map(|c| self.death_row_child.push(c));
					None
				},
			},
		})
	}

	// Walk the trie, attempting to find the key's node.
	fn lookup(
		&self,
		full_key: &[u8],
		mut partial: NibbleSlice,
		handle: &NodeHandle<TrieHash<L>, L::Location>,
	) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		let mut handle = handle;
		// prefix only use for value node access, so this is always correct.
		let prefix = (full_key, None);
		loop {
			let (mid, child) = match handle {
				NodeHandle::Hash(hash, location) => {
					let mut recorder = self.recorder.as_ref().map(|r| r.borrow_mut());

					return Lookup::<L, _> {
						db: self.db,
						query: |v: &[u8]| v.to_vec(),
						hash: *hash,
						location: *location,
						cache: None,
						recorder: recorder
							.as_mut()
							.map(|r| &mut ***r as &mut dyn TrieRecorder<TrieHash<L>, L::Location>),
					}
					.look_up(full_key, partial)
				},
				NodeHandle::InMemory(handle) => match &self.storage[handle] {
					Node::Empty => return Ok(None),
					Node::Leaf(slice, value, _) =>
						if NibbleSlice::from_stored(slice) == partial {
							return Ok(value.in_memory_fetched_value(
								prefix,
								self.db,
								&self.recorder,
								full_key,
							)?)
						} else {
							return Ok(None)
						},
					Node::Extension(slice, child) => {
						let slice = NibbleSlice::from_stored(slice);
						if partial.starts_with(&slice) {
							(slice.len(), child)
						} else {
							return Ok(None)
						}
					},
					Node::Branch(children, value, _) =>
						if partial.is_empty() {
							return Ok(if let Some(v) = value.as_ref() {
								v.in_memory_fetched_value(
									prefix,
									self.db,
									&self.recorder,
									full_key,
								)?
							} else {
								None
							})
						} else {
							let idx = partial.at(0);
							match children[idx as usize].as_ref() {
								Some(child) => (1, child),
								None => return Ok(None),
							}
						},
					Node::NibbledBranch(slice, children, value, _) => {
						let slice = NibbleSlice::from_stored(slice);
						if slice == partial {
							return Ok(if let Some(v) = value.as_ref() {
								v.in_memory_fetched_value(
									prefix,
									self.db,
									&self.recorder,
									full_key,
								)?
							} else {
								None
							})
						} else if partial.starts_with(&slice) {
							let idx = partial.at(slice.len());
							match children[idx as usize].as_ref() {
								Some(child) => (1 + slice.len(), child),
								None => return Ok(None),
							}
						} else {
							return Ok(None)
						}
					},
				},
			};

			partial = partial.mid(mid);
			handle = child;
		}
	}

	/// Insert a key-value pair into the trie, creating new nodes if necessary.
	fn insert_at(
		&mut self,
		handle: NodeHandle<TrieHash<L>, L::Location>,
		key: &mut NibbleFullKey,
		value: Bytes,
		old_val: &mut Option<Value<L>>,
		child_changes: Option<ChildChangeset<L>>,
	) -> Result<(StorageHandle, bool), TrieHash<L>, CError<L>> {
		let h = match handle {
			NodeHandle::InMemory(h) => h,
			NodeHandle::Hash(h, l) => self.cache(h, key.left(), l)?,
		};
		// cache then destroy for hash handle (handle being root in most case)
		let stored = self.storage.destroy(h);
		let (new_stored, changed) = self
			.inspect(stored, key, move |trie, stored, key| {
				trie.insert_inspector(stored, key, value, old_val, child_changes)
					.map(|a| a.into_action())
			})?
			.expect("Insertion never deletes.");

		Ok((self.storage.alloc(new_stored), changed))
	}

	fn replace_old_value(
		&mut self,
		old_value: &mut Option<Value<L>>,
		stored_value: Option<Value<L>>,
		prefix: Prefix,
	) {
		match &stored_value {
			Some(Value::NewNode(Some(hash), _)) // also removing new node in case commit is called multiple times
			| Some(Value::Node(hash, _)) => {
				self.death_row.insert((
					hash.clone(),
					(prefix.0.into(), prefix.1),
				));
			},
			_ => (),
		}
		*old_value = stored_value;
	}

	/// The insertion inspector.
	fn insert_inspector(
		&mut self,
		node: Node<L>,
		key: &mut NibbleFullKey,
		value: Bytes,
		old_val: &mut Option<Value<L>>,
		child_changes: Option<ChildChangeset<L>>,
	) -> Result<InsertAction<L>, TrieHash<L>, CError<L>> {
		let partial = *key;

		#[cfg(feature = "std")]
		trace!(target: "trie", "augmented (partial: {:?}, value: {:?})", partial, ToHex(&value));

		Ok(match node {
			Node::Empty => {
				#[cfg(feature = "std")]
				trace!(target: "trie", "empty: COMPOSE");
				let value = Value::new(value, L::MAX_INLINE_VALUE);
				InsertAction::Replace(Node::Leaf(partial.to_stored(), value, child_changes))
			},
			Node::Branch(mut children, stored_value, b_child_changes) => {
				debug_assert!(L::USE_EXTENSION);
				#[cfg(feature = "std")]
				trace!(target: "trie", "branch: ROUTE,AUGMENT");

				if partial.is_empty() {
					let value = Some(Value::new(value, L::MAX_INLINE_VALUE));
					let unchanged = stored_value == value;
					let branch = Node::Branch(children, value, child_changes);

					self.replace_old_value(old_val, stored_value, key.left());

					if unchanged {
						InsertAction::Restore(branch)
					} else {
						InsertAction::Replace(branch)
					}
				} else {
					let idx = partial.at(0) as usize;
					key.advance(1);
					if let Some(child) = children[idx].take() {
						// Original had something there. recurse down into it.
						let (new_child, changed) =
							self.insert_at(child, key, value, old_val, child_changes)?;
						children[idx] = Some(new_child.into());
						if !changed {
							// The new node we composed didn't change.
							// It means our branch is untouched too.
							return Ok(InsertAction::Restore(Node::Branch(
								children,
								stored_value,
								b_child_changes,
							)))
						}
					} else {
						// Original had nothing there. compose a leaf.
						let value = Value::new(value, L::MAX_INLINE_VALUE);
						let leaf = self.storage.alloc(Stored::New(Node::Leaf(
							key.to_stored(),
							value,
							child_changes,
						)));
						children[idx] = Some(leaf.into());
					}

					InsertAction::Replace(Node::Branch(children, stored_value, b_child_changes))
				}
			},
			Node::NibbledBranch(encoded, mut children, stored_value, b_child_changes) => {
				debug_assert!(!L::USE_EXTENSION);
				#[cfg(feature = "std")]
				trace!(target: "trie", "branch: ROUTE,AUGMENT");
				let existing_key = NibbleSlice::from_stored(&encoded);

				let common = partial.common_prefix(&existing_key);
				if common == existing_key.len() && common == partial.len() {
					let value = Some(Value::new(value, L::MAX_INLINE_VALUE));
					let unchanged = stored_value == value;
					let branch = Node::NibbledBranch(
						existing_key.to_stored(),
						children,
						value,
						child_changes,
					);

					let mut key_val = key.clone();
					key_val.advance(existing_key.len());
					self.replace_old_value(old_val, stored_value, key_val.left());

					if unchanged {
						InsertAction::Restore(branch)
					} else {
						InsertAction::Replace(branch)
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
					let low = Node::NibbledBranch(
						nbranch_partial,
						children,
						stored_value,
						b_child_changes,
					);
					let ix = existing_key.at(common);
					let mut children = empty_children();
					let alloc_storage = self.storage.alloc(Stored::New(low));

					children[ix as usize] = Some(alloc_storage.into());

					let value = Value::new(value, L::MAX_INLINE_VALUE);
					if partial.len() - common == 0 {
						InsertAction::Replace(Node::NibbledBranch(
							existing_key.to_stored_range(common),
							children,
							Some(value),
							child_changes,
						))
					} else {
						let ix = partial.at(common);
						let stored_leaf =
							Node::Leaf(partial.mid(common + 1).to_stored(), value, child_changes);

						let leaf = self.storage.alloc(Stored::New(stored_leaf));

						children[ix as usize] = Some(leaf.into());
						InsertAction::Replace(Node::NibbledBranch(
							existing_key.to_stored_range(common),
							children,
							None,
							None,
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
						let (new_child, changed) =
							self.insert_at(child, key, value, old_val, child_changes)?;
						children[idx] = Some(new_child.into());
						if !changed {
							// The new node we composed didn't change.
							// It means our branch is untouched too.
							let n_branch = Node::NibbledBranch(
								existing_key.to_stored(),
								children,
								stored_value,
								b_child_changes,
							);
							return Ok(InsertAction::Restore(n_branch))
						}
					} else {
						// Original had nothing there. compose a leaf.
						let value = Value::new(value, L::MAX_INLINE_VALUE);
						let leaf = self.storage.alloc(Stored::New(Node::Leaf(
							key.to_stored(),
							value,
							child_changes,
						)));

						children[idx] = Some(leaf.into());
					}
					InsertAction::Replace(Node::NibbledBranch(
						existing_key.to_stored(),
						children,
						stored_value,
						b_child_changes,
					))
				}
			},
			Node::Leaf(encoded, stored_value, l_child_changes) => {
				let existing_key = NibbleSlice::from_stored(&encoded);
				let common = partial.common_prefix(&existing_key);
				if common == existing_key.len() && common == partial.len() {
					#[cfg(feature = "std")]
					trace!(target: "trie", "equivalent-leaf: REPLACE");
					// equivalent leaf.
					let value = Value::new(value, L::MAX_INLINE_VALUE);
					let unchanged = stored_value == value;
					let mut key_val = key.clone();
					key_val.advance(existing_key.len());
					self.replace_old_value(old_val, Some(stored_value), key_val.left());
					if unchanged {
						// unchanged. restore
						InsertAction::Restore(Node::Leaf(encoded.clone(), value, l_child_changes))
					} else {
						InsertAction::Replace(Node::Leaf(encoded.clone(), value, child_changes))
					}
				} else if (L::USE_EXTENSION && common == 0) ||
					(!L::USE_EXTENSION && common < existing_key.len())
				{
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
						Node::Branch(children, Some(stored_value), l_child_changes)
					} else {
						let idx = existing_key.at(common) as usize;
						let new_leaf = Node::Leaf(
							existing_key.mid(common + 1).to_stored(),
							stored_value,
							l_child_changes,
						);
						children[idx] = Some(self.storage.alloc(Stored::New(new_leaf)).into());

						if L::USE_EXTENSION {
							Node::Branch(children, None, None)
						} else {
							Node::NibbledBranch(
								partial.to_stored_range(common),
								children,
								None,
								None,
							)
						}
					};

					// always replace because whatever we get out here
					// is not the branch we started with.
					let branch_action = self
						.insert_inspector(branch, key, value, old_val, child_changes)?
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
						l_child_changes,
					);
					// augment the new branch.
					let branch = self
						.insert_inspector(branch, key, value, old_val, child_changes)?
						.unwrap_node();

					InsertAction::Replace(branch)
				} else if common == existing_key.len() {
					debug_assert!(L::USE_EXTENSION);
					#[cfg(feature = "std")]
					trace!(target: "trie", "complete-prefix (common={:?}): AUGMENT-AT-END", common);

					// fully-shared prefix for an extension.
					// make a stub branch and an extension.
					let branch =
						Node::Branch(empty_children(), Some(stored_value), l_child_changes);
					// augment the new branch.
					key.advance(common);
					let branch = self
						.insert_inspector(branch, key, value, old_val, child_changes)?
						.unwrap_node();

					// always replace since we took a leaf and made an extension.
					let leaf = self.storage.alloc(Stored::New(branch));
					InsertAction::Replace(Node::Extension(existing_key.to_stored(), leaf.into()))
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
					let low = Node::Leaf(
						existing_key.mid(common).to_stored(),
						stored_value,
						l_child_changes,
					);

					// augment it. this will result in the Leaf -> common == 0 routine,
					// which creates a branch.
					key.advance(common);
					let augmented_low = self
						.insert_inspector(low, key, value, old_val, child_changes)?
						.unwrap_node();
					// make an extension using it. this is a replacement.
					InsertAction::Replace(Node::Extension(
						existing_key.to_stored_range(common),
						self.storage.alloc(Stored::New(augmented_low)).into(),
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
						// No need to register set branch (was here before).
						// Note putting a branch in extension requires fix.
						let ext = Node::Extension(existing_key.mid(1).to_stored(), child_branch);
						Some(self.storage.alloc(Stored::New(ext)).into())
					};

					// continue inserting.
					let branch_action = self
						.insert_inspector(
							Node::Branch(children, None, None),
							key,
							value,
							old_val,
							child_changes,
						)?
						.unwrap_node();
					InsertAction::Replace(branch_action)
				} else if common == existing_key.len() {
					#[cfg(feature = "std")]
					trace!(target: "trie", "complete-prefix (common={:?}): AUGMENT-AT-END", common);

					// fully-shared prefix.

					// insert into the child node.
					key.advance(common);
					let (new_child, changed) =
						self.insert_at(child_branch, key, value, old_val, child_changes)?;

					let new_ext = Node::Extension(existing_key.to_stored(), new_child.into());

					// if the child branch wasn't changed, meaning this extension remains the same.
					if changed {
						InsertAction::Replace(new_ext)
					} else {
						InsertAction::Restore(new_ext)
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
					let augmented_low = self
						.insert_inspector(low, key, value, old_val, child_changes)?
						.unwrap_node();

					// always replace, since this extension is not the one we started with.
					// this is known because the partial key is only the common prefix.
					InsertAction::Replace(Node::Extension(
						existing_key.to_stored_range(common),
						self.storage.alloc(Stored::New(augmented_low)).into(),
					))
				}
			},
		})
	}

	/// Removes a node from the trie based on key.
	fn remove_at(
		&mut self,
		handle: NodeHandle<TrieHash<L>, L::Location>,
		key: &mut NibbleFullKey,
		old_val: &mut Option<Value<L>>,
		child_changes: Option<ChildChangeset<L>>,
	) -> Result<Option<(StorageHandle, bool)>, TrieHash<L>, CError<L>> {
		let stored = match handle {
			NodeHandle::InMemory(h) => self.storage.destroy(h),
			NodeHandle::Hash(h, l) => {
				let handle = self.cache(h, key.left(), l)?;
				self.storage.destroy(handle)
			},
		};

		let opt = self.inspect(stored, key, move |trie, node, key| {
			trie.remove_inspector(node, key, old_val, child_changes)
		})?;

		Ok(opt.map(|(new, changed)| (self.storage.alloc(new), changed)))
	}

	/// The removal inspector.
	fn remove_inspector(
		&mut self,
		node: Node<L>,
		key: &mut NibbleFullKey,
		old_val: &mut Option<Value<L>>,
		child_changes: Option<ChildChangeset<L>>,
	) -> Result<Action<L>, TrieHash<L>, CError<L>> {
		let partial = *key;
		Ok(match (node, partial.is_empty()) {
			(Node::Empty, _) => Action::Delete(None),
			(Node::Branch(c, None, _), true) =>
				Action::Restore(Node::Branch(c, None, child_changes)),
			(Node::NibbledBranch(n, c, None, _), true) =>
				Action::Restore(Node::NibbledBranch(n, c, None, child_changes)),
			(Node::Branch(children, val, _), true) => {
				self.replace_old_value(old_val, val, key.left());
				// always replace since we took the value out.
				Action::Replace(self.fix(Node::Branch(children, None, child_changes), *key)?)
			},
			(Node::NibbledBranch(n, children, val, _), true) => {
				self.replace_old_value(old_val, val, key.left());
				// always replace since we took the value out.
				Action::Replace(
					self.fix(Node::NibbledBranch(n, children, None, child_changes), *key)?,
				)
			},
			(Node::Branch(mut children, value, b_childset), false) => {
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
					match self.remove_at(child, key, old_val, child_changes)? {
						Some((new, changed)) => {
							children[idx] = Some(new.into());
							let branch = Node::Branch(children, value, b_childset);
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
							trace!(target: "trie", "branch child deleted, partial={:?}", partial);
							Action::Replace(
								self.fix(Node::Branch(children, value, b_childset), prefix)?,
							)
						},
					}
				} else {
					// no change needed.
					Action::Restore(Node::Branch(children, value, b_childset))
				}
			},
			(Node::NibbledBranch(encoded, mut children, value, b_childset), false) => {
				let (common, existing_length) = {
					let existing_key = NibbleSlice::from_stored(&encoded);
					(existing_key.common_prefix(&partial), existing_key.len())
				};
				if common == existing_length && common == partial.len() {
					// replace val
					if let Some(value) = value {
						let mut key_val = key.clone();
						key_val.advance(existing_length);
						self.replace_old_value(old_val, Some(value), key_val.left());
						let f = self
							.fix(Node::NibbledBranch(encoded, children, None, child_changes), *key);
						Action::Replace(f?)
					} else {
						Action::Restore(Node::NibbledBranch(encoded, children, None, child_changes))
					}
				} else if common < existing_length {
					// partway through an extension -- nothing to do here.
					Action::Restore(Node::NibbledBranch(encoded, children, value, b_childset))
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
						match self.remove_at(child, key, old_val, child_changes)? {
							Some((new, changed)) => {
								children[idx] = Some(new.into());
								let branch =
									Node::NibbledBranch(encoded, children, value, b_childset);
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
								Action::Replace(self.fix(
									Node::NibbledBranch(encoded, children, value, b_childset),
									prefix,
								)?)
							},
						}
					} else {
						// no change needed.
						Action::Restore(Node::NibbledBranch(encoded, children, value, b_childset))
					}
				}
			},
			(Node::Leaf(encoded, value, l_childset), _) => {
				let existing_key = NibbleSlice::from_stored(&encoded);
				if existing_key == partial {
					// this is the node we were looking for. Let's delete it.
					let mut key_val = key.clone();
					key_val.advance(existing_key.len());
					self.replace_old_value(old_val, Some(value), key_val.left());
					Action::Delete(child_changes)
				} else {
					// leaf the node alone.
					#[cfg(feature = "std")]
					trace!(
						target: "trie",
						"restoring leaf wrong partial, partial={:?}, existing={:?}",
						partial,
						NibbleSlice::from_stored(&encoded),
					);
					Action::Restore(Node::Leaf(encoded, value, l_childset))
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
					let prefix = *key;
					key.advance(common);
					match self.remove_at(child_branch, key, old_val, child_changes)? {
						Some((new_child, changed)) => {
							// if the child branch was unchanged, then the extension is too.
							// otherwise, this extension may need fixing.
							match changed {
								true => Action::Replace(
									self.fix(Node::Extension(encoded, new_child.into()), prefix)?,
								),
								false =>
									Action::Restore(Node::Extension(encoded, new_child.into())),
							}
						},
						None => {
							// the whole branch got deleted.
							// that means that this extension is useless.
							Action::Delete(None)
						},
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
	fn fix(&mut self, node: Node<L>, key: NibbleSlice) -> Result<Node<L>, TrieHash<L>, CError<L>> {
		self.fix_inner(node, key, false)
	}
	fn fix_inner(
		&mut self,
		node: Node<L>,
		key: NibbleSlice,
		recurse_extension: bool,
	) -> Result<Node<L>, TrieHash<L>, CError<L>> {
		match node {
			Node::Branch(mut children, value, b_childset) => {
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
							break
						},
						_ => continue,
					}
				}

				match (used_index, value) {
					(UsedIndex::None, None) => {
						panic!("Branch with no subvalues. Something went wrong.")
					},
					(UsedIndex::One(a), None) => {
						// only one onward node. make an extension.

						let new_partial = NibbleSlice::new_offset(&[a], 1).to_stored();
						let child = children[a as usize]
							.take()
							.expect("used_index only set if occupied; qed");
						let new_node = Node::Extension(new_partial, child);
						self.fix(new_node, key)
					},
					(UsedIndex::None, Some(value)) => {
						// make a leaf.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: branch -> leaf");
						Ok(Node::Leaf(NibbleSlice::new(&[]).to_stored(), value, b_childset))
					},
					(_, value) => {
						// all is well.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: restoring branch");
						Ok(Node::Branch(children, value, b_childset))
					},
				}
			},
			Node::NibbledBranch(enc_nibble, mut children, value, b_childset) => {
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
							break
						},
						_ => continue,
					}
				}

				match (used_index, value) {
					(UsedIndex::None, None) => {
						panic!("Branch with no subvalues. Something went wrong.")
					},
					(UsedIndex::One(a), None) => {
						// only one onward node. use child instead
						let child = children[a as usize]
							.take()
							.expect("used_index only set if occupied; qed");
						let mut key2 = key.clone();
						key2.advance(
							(enc_nibble.1.len() * nibble_ops::NIBBLE_PER_BYTE) - enc_nibble.0,
						);
						let (start, alloc_start, prefix_end) = match key2.left() {
							(start, None) => (start, None, Some(nibble_ops::push_at_left(0, a, 0))),
							(start, Some(v)) => {
								let mut so: BackingByteVec = start.into();
								so.push(nibble_ops::pad_left(v) | a);
								(start, Some(so), None)
							},
						};
						let child_prefix = (
							alloc_start.as_ref().map(|start| &start[..]).unwrap_or(start),
							prefix_end,
						);
						let stored = match child {
							NodeHandle::InMemory(h) => self.storage.destroy(h),
							NodeHandle::Hash(h, l) => {
								let handle = self.cache(h, child_prefix, l)?;
								self.storage.destroy(handle)
							},
						};
						let child_node = match stored {
							Stored::New(node) => node,
							Stored::Cached(node, hash, _location) => {
								self.death_row
									.insert((hash, (child_prefix.0[..].into(), child_prefix.1)));
								node
							},
						};
						b_childset.map(|c| self.death_row_child.push(c));
						match child_node {
							Node::Leaf(sub_partial, value, l_childset) => {
								let mut enc_nibble = enc_nibble;
								combine_key(
									&mut enc_nibble,
									(nibble_ops::NIBBLE_PER_BYTE - 1, &[a][..]),
								);
								combine_key(&mut enc_nibble, (sub_partial.0, &sub_partial.1[..]));
								Ok(Node::Leaf(enc_nibble, value, l_childset))
							},
							Node::NibbledBranch(sub_partial, ch_children, ch_value, n_childset) => {
								let mut enc_nibble = enc_nibble;
								combine_key(
									&mut enc_nibble,
									(nibble_ops::NIBBLE_PER_BYTE - 1, &[a][..]),
								);
								combine_key(&mut enc_nibble, (sub_partial.0, &sub_partial.1[..]));
								Ok(Node::NibbledBranch(
									enc_nibble,
									ch_children,
									ch_value,
									n_childset,
								))
							},
							_ => unreachable!(),
						}
					},
					(UsedIndex::None, Some(value)) => {
						// make a leaf.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: branch -> leaf");
						Ok(Node::Leaf(enc_nibble, value, b_childset))
					},
					(_, value) => {
						// all is well.
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: restoring branch");
						Ok(Node::NibbledBranch(enc_nibble, children, value, b_childset))
					},
				}
			},
			Node::Extension(partial, child) => {
				let mut key2 = key.clone();
				let (start, alloc_start, prefix_end) = if !recurse_extension {
					// We could advance key, but this code can also be called
					// recursively, so there might be some prefix from branch.
					let last = partial.1[partial.1.len() - 1] & (255 >> 4);
					key2.advance((partial.1.len() * nibble_ops::NIBBLE_PER_BYTE) - partial.0 - 1);
					match key2.left() {
						(start, None) => (start, None, Some(nibble_ops::push_at_left(0, last, 0))),
						(start, Some(v)) => {
							let mut so: BackingByteVec = start.into();
							// Complete last byte with `last`.
							so.push(nibble_ops::pad_left(v) | last);
							(start, Some(so), None)
						},
					}
				} else {
					let k2 = key2.left();

					let mut so: NibbleVec = Default::default();
					so.append_optional_slice_and_nibble(Some(&NibbleSlice::new(k2.0)), None);
					if let Some(n) = k2.1 {
						so.push(n >> nibble_ops::BIT_PER_NIBBLE);
					}
					so.append_optional_slice_and_nibble(
						Some(&NibbleSlice::from_stored(&partial)),
						None,
					);
					let so = so.as_prefix();
					(k2.0, Some(so.0.into()), so.1)
				};
				let child_prefix =
					(alloc_start.as_ref().map(|start| &start[..]).unwrap_or(start), prefix_end);

				let stored = match child {
					NodeHandle::InMemory(h) => self.storage.destroy(h),
					NodeHandle::Hash(h, l) => {
						let handle = self.cache(h, child_prefix, l)?;
						self.storage.destroy(handle)
					},
				};

				let (child_node, maybe_hash, child_location) = match stored {
					Stored::New(node) => (node, None, Default::default()),
					Stored::Cached(node, hash, location) => (node, Some(hash), location),
				};

				match child_node {
					Node::Extension(sub_partial, sub_child) => {
						// combine with node below.
						if let Some(hash) = maybe_hash {
							// delete the cached child since we are going to replace it.
							self.death_row
								.insert((hash, (child_prefix.0[..].into(), child_prefix.1)));
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

						self.fix_inner(Node::Extension(partial, sub_child), key.into(), true)
					},
					Node::Leaf(sub_partial, value, l_childset) => {
						// combine with node below.
						if let Some(hash) = maybe_hash {
							// delete the cached child since we are going to replace it.
							self.death_row
								.insert((hash, (child_prefix.0[..].into(), child_prefix.1)));
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
						Ok(Node::Leaf(partial, value, l_childset))
					},
					child_node => {
						#[cfg(feature = "std")]
						trace!(target: "trie", "fixing: restoring extension");

						// reallocate the child node.
						let stored = if let Some(hash) = maybe_hash {
							Stored::Cached(child_node, hash, child_location)
						} else {
							Stored::New(child_node)
						};

						Ok(Node::Extension(partial, self.storage.alloc(stored).into()))
					},
				}
			},
			other => Ok(other), // only ext and branch need fixing.
		}
	}

	/// Calculate the changeset for the trie.
	pub fn commit(mut self) -> Changeset<TrieHash<L>, L::Location> {
		#[cfg(feature = "std")]
		trace!(target: "trie", "Committing trie changes to db.");

		// always kill all the nodes on death row.
		trace!(target: "trie", "{:?} nodes to remove from db", self.death_row.len());
		let mut removed = Vec::with_capacity(self.death_row.len());

		for (hash, prefix) in self.death_row.drain() {
			removed.push((hash, prefix));
		}

		let handle = match self.root_handle() {
			NodeHandle::Hash(hash, location) =>
				return Changeset {
					root: ChangesetNodeRef::Existing(ExistingChangesetNode {
						hash,
						prefix: Default::default(),
						location,
					}),
					removed,
				}, // no changes necessary.
			NodeHandle::InMemory(h) => h,
		};

		match self.storage.destroy(handle) {
			Stored::New(node) => {
				let mut k = NibbleVec::new();
				let mut children = Vec::new();

				let (encoded_root, root_childset) = node.into_encoded(|node, o_slice, o_index| {
					let mov = k.append_optional_slice_and_nibble(o_slice, o_index);
					match node {
						NodeToEncode::Node(value) => {
							let value_hash = self.db.hash(value);
							self.cache_value(k.inner(), value, value_hash);
							children.push(ChangesetNodeRef::New(NewChangesetNode {
								hash: value_hash,
								prefix: k.as_owned_prefix(),
								data: value.to_vec(), //TODO: avoid allocation
								children: Default::default(),
								key_childset: None,
							}));

							k.drop_lasts(mov);
							ChildReference::Hash(value_hash, Default::default())
						},
						NodeToEncode::TrieNode(child) => {
							let result = self.commit_child(child, &mut k, &mut children);
							k.drop_lasts(mov);
							result
						},
					}
				});
				root_childset.map(|c| {
					children.push(*c);
				});
				#[cfg(feature = "std")]
				trace!(target: "trie", "encoded root node: {:?}", ToHex(&encoded_root[..]));

				self.root = self.db.hash(&encoded_root);
				self.hash_count += 1;

				self.cache_node(self.root);

				self.root_handle = NodeHandle::Hash(self.root, Default::default());
				Changeset {
					root: ChangesetNodeRef::New(NewChangesetNode {
						hash: self.root.clone(),
						prefix: Default::default(),
						data: encoded_root,
						children,
						key_childset: None,
					}),
					removed,
				}
			},
			Stored::Cached(node, hash, location) => {
				// probably won't happen, but update the root and move on.
				self.root = hash;
				self.root_handle = NodeHandle::InMemory(self.storage.alloc(Stored::Cached(
					node,
					hash,
					// TODO should we use location here?? likely yes TODO write a test with cache
					// usage and location in triedbmut
					Default::default(),
				)));
				Changeset {
					root: ChangesetNodeRef::Existing(ExistingChangesetNode {
						hash,
						prefix: Default::default(),
						location,
					}),
					removed,
				}
			},
		}
	}

	/// Cache the given `encoded` node.
	fn cache_node(&mut self, hash: TrieHash<L>) {
		// Mark the node as new so that it is removed from the shared cache.
		if let Some(cache) = self.cache.as_mut() {
			cache.insert_new_node(&hash);
		}
	}

	/// Cache the given `value`.
	///
	/// `hash` is the hash of `value`.
	fn cache_value(&mut self, _full_key: &[u8], _value: impl Into<Bytes>, _hash: TrieHash<L>) {}

	/// Commit a node by hashing it and writing it to the db. Returns a
	/// `ChildReference` which in most cases carries a normal hash but for the
	/// case where we can fit the actual data in the `Hasher`s output type, we
	/// store the data inline. This function is used as the callback to the
	/// `into_encoded` method of `Node`.
	fn commit_child(
		&mut self,
		handle: NodeHandle<TrieHash<L>, L::Location>,
		prefix: &mut NibbleVec,
		children: &mut Vec<ChangesetNodeRef<TrieHash<L>, L::Location>>,
	) -> ChildReference<TrieHash<L>, L::Location> {
		match handle {
			NodeHandle::Hash(hash, location) => {
				children.push(ChangesetNodeRef::Existing(ExistingChangesetNode {
					hash,
					prefix: prefix.as_owned_prefix(),
					location,
				}));
				ChildReference::Hash(hash, location)
			},
			NodeHandle::InMemory(storage_handle) => {
				match self.storage.destroy(storage_handle) {
					Stored::Cached(_, hash, location) => {
						children.push(ChangesetNodeRef::Existing(ExistingChangesetNode {
							hash,
							prefix: prefix.as_owned_prefix(),
							location,
						}));
						ChildReference::Hash(hash, location)
					},
					Stored::New(node) => {
						let mut sub_children = Vec::new();
						let (encoded, child_set) = {
							let commit_child = |node: NodeToEncode<TrieHash<L>, L::Location>,
							                    o_slice: Option<&NibbleSlice>,
							                    o_index: Option<u8>| {
								let mov = prefix.append_optional_slice_and_nibble(o_slice, o_index);
								match node {
									NodeToEncode::Node(value) => {
										let value_hash = self.db.hash(value);
										sub_children.push(ChangesetNodeRef::New(
											NewChangesetNode {
												hash: value_hash,
												prefix: prefix.as_owned_prefix(),
												data: value.to_vec(), //TODO: avoid allocation
												children: Default::default(),
												key_childset: None,
											},
										));

										self.cache_value(prefix.inner(), value, value_hash);

										prefix.drop_lasts(mov);
										ChildReference::Hash(value_hash, Default::default())
									},
									NodeToEncode::TrieNode(node_handle) => {
										let result = self.commit_child(
											node_handle,
											prefix,
											&mut sub_children,
										);
										prefix.drop_lasts(mov);
										result
									},
								}
							};
							node.into_encoded(commit_child)
						};
						let result = if encoded.len() >= L::Hash::LENGTH {
							let hash = self.db.hash(&encoded);
							self.cache_node(hash);
							child_set.map(|c| {
								sub_children.push(*c);
							});
							children.push(ChangesetNodeRef::New(NewChangesetNode {
								hash,
								prefix: prefix.as_owned_prefix(),
								data: encoded,
								children: sub_children,
								key_childset: None,
							}));
							self.hash_count += 1;
							ChildReference::Hash(hash, Default::default())
						} else {
							// it's a small value, so we cram it into a `TrieHash<L>`
							// and tag with length
							let mut h = <TrieHash<L>>::default();
							let len = encoded.len();
							h.as_mut()[..len].copy_from_slice(&encoded[..len]);

							ChildReference::Inline(h, len)
						};
						result
					},
				}
			},
		}
	}

	// a hack to get the root node's handle
	fn root_handle(&self) -> NodeHandle<TrieHash<L>, L::Location> {
		match self.root_handle {
			NodeHandle::Hash(h, l) => NodeHandle::Hash(h, l),
			NodeHandle::InMemory(StorageHandle(x)) => NodeHandle::InMemory(StorageHandle(x)),
		}
	}

	pub fn is_empty(&self) -> bool {
		match self.root_handle {
			NodeHandle::Hash(h, _) => h == L::Codec::hashed_null_node(),
			NodeHandle::InMemory(ref h) => match self.storage[h] {
				Node::Empty => true,
				_ => false,
			},
		}
	}

	pub fn get<'x, 'key>(
		&'x self,
		key: &'key [u8],
	) -> Result<Option<DBValue>, TrieHash<L>, CError<L>>
	where
		'x: 'key,
	{
		self.lookup(key, NibbleSlice::new(key), &self.root_handle)
	}

	pub fn insert(
		&mut self,
		key: &[u8],
		value: &[u8],
	) -> Result<Option<Value<L>>, TrieHash<L>, CError<L>> {
		self.insert_with_child_changes(key, value, None)
	}

	pub fn insert_with_child_changes(
		&mut self,
		key: &[u8],
		value: &[u8],
		child_changes: Option<ChildChangeset<L>>,
	) -> Result<Option<Value<L>>, TrieHash<L>, CError<L>> {
		// expect for the child changes to have a key.
		debug_assert!(child_changes
			.as_ref()
			.map(|c| if let ChangesetNodeRef::New(set) = c.as_ref() {
				set.key_childset.is_some()
			} else {
				true
			})
			.unwrap_or(true));
		if !L::ALLOW_EMPTY && value.is_empty() {
			return self.remove(key)
		}

		let mut old_val = None;

		#[cfg(feature = "std")]
		trace!(target: "trie", "insert: key={:?}, value={:?}", ToHex(key), ToHex(&value));

		let value = Bytes::from(value);
		let root_handle = self.root_handle();
		let (new_handle, _changed) = self.insert_at(
			root_handle,
			&mut NibbleSlice::new(key),
			value,
			&mut old_val,
			child_changes,
		)?;

		#[cfg(feature = "std")]
		trace!(target: "trie", "insert: altered trie={}", _changed);
		self.root_handle = NodeHandle::InMemory(new_handle);

		Ok(old_val)
	}

	pub fn remove(&mut self, key: &[u8]) -> Result<Option<Value<L>>, TrieHash<L>, CError<L>> {
		self.remove_with_child_changes(key, None)
	}

	pub fn remove_with_child_changes(
		&mut self,
		key: &[u8],
		child_changes: Option<ChildChangeset<L>>,
	) -> Result<Option<Value<L>>, TrieHash<L>, CError<L>> {
		// expect for the child changes to have a key.
		debug_assert!(child_changes
			.as_ref()
			.map(|c| if let ChangesetNodeRef::New(set) = c.as_ref() {
				set.key_childset.is_some()
			} else {
				true
			})
			.unwrap_or(true));

		#[cfg(feature = "std")]
		trace!(target: "trie", "remove: key={:?}", ToHex(key));

		let root_handle = self.root_handle();
		let mut key_slice = NibbleSlice::new(key);
		let mut old_val = None;

		match self.remove_at(root_handle, &mut key_slice, &mut old_val, child_changes)? {
			Some((handle, _changed)) => {
				#[cfg(feature = "std")]
				trace!(target: "trie", "remove: altered trie={}", _changed);
				self.root_handle = NodeHandle::InMemory(handle);
			},
			None => {
				#[cfg(feature = "std")]
				trace!(target: "trie", "remove: obliterated trie");
				self.root_handle =
					NodeHandle::Hash(L::Codec::hashed_null_node(), Default::default());
				self.root = L::Codec::hashed_null_node();
			},
		}

		Ok(old_val)
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

// Copyright 2017, 2019 Parity Technologies
//
// Licensed under the Apache License, Version .0 (the "License");
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

//! Traverse a trie following a given set of keys.
//!
//! The traversal stack is updatable, and is therefore usable for
//! batch update of ordered key values.
//!
//! Note that this part of trie crate currently do not support extension
//! node. Regarding how the code is designed, implementing extension should
//! be done by using a tuple of extension and branch node as a branch (storing
//! an additional hash in branch and only adapting fetch and write methods).

use crate::triedbmut::{NibbleFullKey};
use crate::node::{OwnedNode, NodeHandle, NodeKey, StorageHandle};
use crate::nibble::{NibbleVec, nibble_ops, NibbleSlice};
#[cfg(feature = "std")]
use std::borrow::Borrow;
#[cfg(not(feature = "std"))]
use core::borrow::Borrow;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use crate::{TrieLayout, TrieHash, CError, Result, TrieError};
use crate::nibble::{BackingByteVec, OwnedPrefix};
use hash_db::{HashDBRef, Prefix, EMPTY_PREFIX};
use crate::NodeCodec;
use crate::rstd::mem;
use crate::rstd::boxed::Box;


type Node<H> = crate::triedbmut::NodeMut<H, StorageHandle>;

type OwnedNodeHandle<H> = crate::triedbmut::NodeHandleMut<H, StorageHandle>;

/// StackedNodeState can be updated.
/// A state can be use.
enum StackedNodeState<B, T>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	/// Read node.
	Unchanged(OwnedNode<B>),
	/// Read node, attached, we need to update
	/// parent hash or root.
	UnchangedAttached(OwnedNode<B>),
	/// Modified node.
	Changed(Node<TrieHash<T>>),
	/// Deleted node.
	Deleted,
}

/// Item on stack it contains updatable traverse
/// specific field to manage update that split
/// partial from a node, and for buffering the first
/// child of a node to avoid storing node that will
/// be change later by a fuse operation (removing
/// a branch without value and a single child).
struct StackedItem<B, T>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	/// the given node item.
	item: StackedNode<B, T>,
	/// Store split child data created when adding a new node in an existing
	/// partial.
	/// That is the only situation where we got a modified item that may need
	/// a to be iterated on at a next iteration.
	/// Note that this cannot be fuse with `first_modified_child` because of
	/// the case where a split child is at a bigger child index than the first
	/// modified and will later be deleted, leading to a single child without
	/// value fuse branch trigger.
	split_child: Option<StackedNode<B, T>>,
	/// Store first child, until `exit` get call, this is needed
	/// to be able to fuse branch containing a single child (delay
	/// `exit` call of first element after process of the second one).
	/// Store child and the key use when storing (to calculate final
	/// nibble, this is more memory costy than strictly necessary).
	/// Note that split_child is always a first_modified_child.
	first_modified_child: Option<StackedNode<B, T>>,
	/// true as long as the value can be deleted and no more
	/// than one branch cannot be deleted.
	can_fuse: bool,
}

/// Variant of stacked item to store first changed node.
struct StackedNode<B, T>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	/// Internal node representation.
	node: StackedNodeState<B, T>,
	/// Hash and prefix used to access this node, for inline node (except root) and
	/// new nodes this is None.
	previous_db_handle: Option<(TrieHash<T>, OwnedPrefix)>,
	/// Index of prefix.
	depth_prefix: usize,
	/// Depth of node, it is prefix depth and partial depth.
	depth: usize,
	/// parent index (only relevant when parent is a branch).
	parent_index: u8,
}

impl<B, T> From<StackedItem<B, T>> for StackedNode<B, T>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	fn from(item: StackedItem<B, T>) -> Self {
		item.item
	}
}

impl<B, T> StackedItem<B, T>
	where
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		T: TrieLayout,
{
	fn split_child_index(&self) -> Option<u8> {
		match self.split_child.as_ref() {
			Some(child) => Some(child.parent_index),
			_ => None,
		}
	}

	fn first_modified_child_index(&self) -> Option<u8> {
		self.first_modified_child.as_ref().map(|c| c.parent_index)
	}

	fn is_split_child(&self, index: u8) -> bool {
		self.split_child_index().map(|child_index| child_index == index).unwrap_or(false)
	}

	// take first child (used for fusing, otherwhise process_first_modified_child is probably what you want)
	fn take_first_modified_child(&mut self) -> Option<StackedItem<B, T>> {
		// descending in first child is only for fusizg node
		// so we do not update self first child status (will be deleted).
		if let Some(item) = self.first_modified_child.take() {
				Some(StackedItem {
					item,
					first_modified_child: None,
					split_child: None,
					can_fuse: false,
			})
		} else {
			None
		}
	}

	fn descend_child(&mut self, index: u8, db: &dyn HashDBRef<T::Hash, B>, prefix: Prefix) -> Result<
		Option<StackedItem<B, T>>,
		TrieHash<T>,
		CError<T>
	> {
		Ok(if self.is_split_child(index) {
			if let Some(item) = self.split_child.take() {
				// from a split child key is none (partial changed on split)
				Some(StackedItem {
					item,
					first_modified_child: None,
					split_child: None,
					can_fuse: true,
				})
			} else {
				unreachable!("Broken split expectation, visited twice");
			}
		} else {
			if let Some(node_handle) = self.item.node.child(index) {

				let (node, previous_db_handle) = match node_handle {
					NodeHandle::Hash(handle_hash) => {
						let mut hash = <TrieHash<T> as Default>::default();
						hash.as_mut()[..].copy_from_slice(handle_hash.as_ref());
						(StackedNodeState::fetch(
								db, &hash, prefix,
						)?, Some((hash, owned_prefix(&prefix))))
					},
					NodeHandle::Inline(node_encoded) => {
						// Instantiating B is only for inline node, still costy.
						(StackedNodeState::Unchanged(
							OwnedNode::new::<T::Codec>(B::from(node_encoded))
								.map_err(|e| Box::new(TrieError::DecoderError(
									self.item.previous_db_handle.clone().map(|i| i.0).unwrap_or_else(Default::default),
									e,
								)))?
						), None)
					},
				};
				let depth_prefix = self.item.depth + 1;
				let depth = depth_prefix + node.partial().map(|p| p.len()).unwrap_or(0);
				Some(StackedItem {
					item: StackedNode {
						node,
						previous_db_handle,
						parent_index: index,
						depth_prefix,
						depth,
					},
					first_modified_child: None,
					split_child: None,
					can_fuse: true,
				})
			} else {
				None
			}
		})
	}

	// replace self by new branch at split and adding to self as a stacked item child.
	fn do_split_child<
		F: ProcessStack<B, T>,
	>(&mut self, mid_index: usize, key: &[u8], callback: &mut F) {
//		// if self got split child, it can be processed
//		// (we went up and this is a next key) (ordering)
		self.process_first_modified_child(key, callback);
		self.process_split_child(key, callback);
		// or it means we need to store key to
//		debug_assert!(self.split_child_index().is_none());
		let dest_branch = if mid_index % nibble_ops::NIBBLE_PER_BYTE == 0 {
			let new_slice = NibbleSlice::new_offset(
				&key[..mid_index / nibble_ops::NIBBLE_PER_BYTE],
				self.item.depth_prefix,
			);
			Node::empty_branch(new_slice)
		} else {
			let new_slice = NibbleSlice::new_offset(
				&key[..],
				self.item.depth_prefix,
			);
			let owned = new_slice.to_stored_range(mid_index - self.item.depth_prefix);
			Node::empty_branch(NibbleSlice::from_stored(&owned))
		};

		let old_depth = self.item.depth;
		self.item.depth = mid_index;
		let mut child = mem::replace(
			&mut self.item.node,
			StackedNodeState::Changed(dest_branch),
		);

		let parent_index = child.partial()
			.map(|p| p.at(mid_index - self.item.depth_prefix)).unwrap_or(0);

		child.advance_partial(1 + mid_index - self.item.depth_prefix);
//		// split occurs before visiting a single child
//		debug_assert!(self.first_modified_child.is_none());
		// debug_assert!(!self.cannot_fuse);
		// ordering key also ensure
	//	debug_assert!(self.split_child_index().is_none());

		// not setting child relation (will be set on exit)
		let child = StackedNode {
			node: child,
			previous_db_handle: None,
			depth_prefix: 1 + mid_index,
			depth: old_depth,
			parent_index,
		};
		debug_assert!(self.first_modified_child.is_none());
		self.split_child = Some(child);
	}

	fn append_child<
		F: ProcessStack<B, T>,
	>(&mut self, child: StackedNode<B, T>, prefix: Prefix, callback: &mut F) {
		if let Some(handle) = callback.exit(
			prefix,
			child.node,
			child.previous_db_handle,
		) {
			self.item.node.set_handle(handle, child.parent_index);
		}
	}

	fn process_split_child<
		F: ProcessStack<B, T>,
	>(&mut self, key: &[u8], callback: &mut F) {
		if let Some(child) = self.split_child.take() {
			// prefix is slice
			let mut build_prefix = NibbleVec::from(key, self.item.depth_prefix);
			self.item.node.partial().map(|p| build_prefix.append_partial(p.right()));
			build_prefix.push(child.parent_index);
			self.append_child(child, build_prefix.as_prefix(), callback);
		}
	}

	fn process_first_modified_child<
		F: ProcessStack<B, T>,
	>(&mut self, key: &[u8], callback: &mut F) {
		if let Some(child) = self.first_modified_child.take() {
			if let Some(split_child_index) = self.split_child_index() {
				if split_child_index < child.parent_index {
					self.process_split_child(key.as_ref(), callback);
				}
			}

			let mut build_prefix = NibbleVec::from(key, self.item.depth_prefix);
			self.item.node.partial().map(|p| build_prefix.append_partial(p.right()));
			build_prefix.push(child.parent_index);
			self.append_child(child, build_prefix.as_prefix(), callback);
		}
	}

	fn process_child<
		F: ProcessStack<B, T>,
	>(&mut self, mut child: StackedItem<B, T>, key: &[u8], callback: &mut F) {

		if let Some(first_modified_child_index) = self.first_modified_child_index() {
			if first_modified_child_index < child.item.parent_index {
				self.process_first_modified_child(key, callback);
			}
		}
		if let Some(split_child_index) = self.split_child_index() {
			if split_child_index < child.item.parent_index {
				self.process_split_child(key.as_ref(), callback);
			}
		}
		// split child can be unprocessed (when going up it is kept after second node
		// in expectation of other children process.
		child.process_first_modified_child(key, callback);
		child.process_split_child(key, callback);
		let nibble_slice = NibbleSlice::new_offset(key.as_ref(), child.item.depth_prefix);
		self.append_child(child.into(), nibble_slice.left(), callback);
		self.can_fuse = false;
	}

	fn process_root<
		F: ProcessStack<B, T>,
	>(mut self, key: &[u8], callback: &mut F) {
		self.process_first_modified_child(key, callback);
		self.process_split_child(key, callback);
		callback.exit_root(
			self.item.node,
			self.item.previous_db_handle,
		)
	}

	// consume branch and return item to attach to parent
	fn fuse_branch<
		F: ProcessStack<B, T>,
	>(&mut self, mut child: StackedItem<B, T>, key: &[u8], callback: &mut F) {
		let child_depth = self.item.depth + 1 + child.item.node.partial().map(|p| p.len()).unwrap_or(0);
		let _ = mem::replace(&mut self.item.node, child.item.node);
		// delete child
		callback.exit(
			EMPTY_PREFIX,
			StackedNodeState::Deleted, child.item.previous_db_handle.take(),
		).expect("no new node on empty");

		let partial = NibbleSlice::new_offset(key, self.item.depth_prefix)
			.to_stored_range(child_depth - self.item.depth_prefix);
		self.item.node.set_partial(partial);
		self.item.depth = child_depth;
		self.can_fuse = true;
		self.first_modified_child = None;
		self.split_child = None;
	}

	fn fuse_node<F: ProcessStack<B, T>>(
		&mut self,
		key: &[u8],
		db: &dyn HashDBRef<T::Hash, B>,
		callback: &mut F,
	) -> Result<bool, TrieHash<T>, CError<T>> {
		let first_modified_child_index = self.first_modified_child_index();
		let (deleted, fuse_index) = self.item.node.fuse_node((first_modified_child_index, self.split_child_index()));
		// needed also to resolve
		if let Some(fuse_index) = fuse_index {
			// try first child
			if let Some(child) = self.take_first_modified_child() {
				debug_assert!(child.item.parent_index == fuse_index);
				let mut prefix = NibbleVec::from(key.as_ref(), self.item.depth);
				prefix.push(fuse_index);
				child.item.node.partial().map(|p| prefix.append_partial(p.right()));
				self.fuse_branch(child, prefix.inner(), callback);
			} else {
				let mut prefix = NibbleVec::from(key.as_ref(), self.item.depth);
				prefix.push(fuse_index);
				let child = self.descend_child(fuse_index, db, prefix.as_prefix())?
					.expect("result of first child is define if consistent db");
				child.item.node.partial().map(|p| prefix.append_partial(p.right()));
				self.fuse_branch(child, prefix.inner(), callback);
			}
			Ok(true)
		} else {
			Ok(deleted)
		}
	}
}

impl<B, T> StackedNodeState<B, T>
	where
		B: Borrow<[u8]> + AsRef<[u8]>,
		T: TrieLayout,
{
	/// Get extension part of the node (partial) if any.
	fn is_empty(&self) -> bool {
		match self {
			StackedNodeState::Unchanged(node) => node.is_empty(),
			StackedNodeState::UnchangedAttached(node) => node.is_empty(),
			StackedNodeState::Changed(node) => node.is_empty(),
			StackedNodeState::Deleted => true,
		}
	}

	/// Get extension part of the node (partial) if any.
	fn partial(&self) -> Option<NibbleSlice> {
		match self {
			StackedNodeState::Unchanged(node) => node.partial(),
			StackedNodeState::UnchangedAttached(node) => node.partial(),
			StackedNodeState::Changed(node) => node.partial(),
			StackedNodeState::Deleted => None,
		}
	}

	/// Try to access child.
	fn child(&self, ix: u8) -> Option<NodeHandle> {
		match self {
			StackedNodeState::Unchanged(node) => node.child(ix),
			StackedNodeState::UnchangedAttached(node) => node.child(ix),
			StackedNodeState::Changed(node) => node.child(ix),
			StackedNodeState::Deleted => None,
		}
	}

	/// Tell if there is a value defined at this node position.
	fn has_value(&self) -> bool {
		match self {
			StackedNodeState::Unchanged(node) => node.has_value(),
			StackedNodeState::UnchangedAttached(node) => node.has_value(),
			StackedNodeState::Changed(node) => node.has_value(),
			StackedNodeState::Deleted => false,
		}
	}

	/// Set a value if the node can contain one.
	fn set_value(&mut self, value: &[u8]) {
		match self {
			StackedNodeState::UnchangedAttached(node)
			| StackedNodeState::Unchanged(node) => {
				if let Some(new) = node.set_value(value) {
					*self = StackedNodeState::Changed(new);
				}
			},
			StackedNodeState::Changed(node) => node.set_value(value),
			StackedNodeState::Deleted => (),
		}
	}

	/// Change a partial if the node contains one.
	fn advance_partial(&mut self, nb: usize) {
		match self {
			StackedNodeState::UnchangedAttached(node)
			| StackedNodeState::Unchanged(node) => {
				if let Some(new) = node.advance_partial(nb) {
					*self = StackedNodeState::Changed(new);
				}
			},
			StackedNodeState::Changed(node) => node.advance_partial(nb),
			StackedNodeState::Deleted => (),
		}
	}

	/// Set a new partial.
	fn set_partial(&mut self, partial: NodeKey) {
		match self {
			StackedNodeState::UnchangedAttached(node)
			| StackedNodeState::Unchanged(node) => {
				if let Some(new) = node.set_partial(partial) {
					*self = StackedNodeState::Changed(new);
				}
			},
			StackedNodeState::Changed(node) => node.set_partial(partial),
			StackedNodeState::Deleted => (),
		}
	}

	/// Remove a value if the node contains one.
	fn remove_value(&mut self) {
		match self {
			StackedNodeState::UnchangedAttached(node)
			| StackedNodeState::Unchanged(node) => {
				match node.remove_value() {
					Some(Some(new)) =>
						*self = StackedNodeState::Changed(new),
					Some(None) =>
						*self = StackedNodeState::Deleted,
					None => (),
				}
			},
			StackedNodeState::Changed(node) => {
				if node.remove_value() {
					*self = StackedNodeState::Deleted;
				}
			},
			StackedNodeState::Deleted => (),
		}
	}

	/// Set a handle to a child node or remove it if handle is none.
	fn set_handle(&mut self, handle: Option<OwnedNodeHandle<TrieHash<T>>>, index: u8) {
		match self {
			StackedNodeState::UnchangedAttached(node)
			| StackedNodeState::Unchanged(node) => {
				let change = node.set_handle(handle, index);
				match change {
					Some(new) => *self = StackedNodeState::Changed(new),
					None => (),
				}
			},
			StackedNodeState::Changed(node) => {
				node.set_handle(handle, index);
			},
			StackedNodeState::Deleted => unreachable!(),
		}
	}

	/// Returns index of node to fuse if node was fused.
	fn fuse_node(&mut self, pending: (Option<u8>, Option<u8>)) -> (bool, Option<u8>) {
		match self {
			StackedNodeState::Deleted
			| StackedNodeState::UnchangedAttached(..)
			| StackedNodeState::Unchanged(..) => (false, None),
			StackedNodeState::Changed(node) => {
				let (deleted, fuse) = node.try_fuse_node(pending);
				if deleted {
					*self = StackedNodeState::Deleted;
				}
				(deleted, fuse)
			},
		}
	}

	/// Encode node
	fn into_encoded(self) -> Vec<u8> {
		match self {
			StackedNodeState::UnchangedAttached(node)
			| StackedNodeState::Unchanged(node) => node.data().to_vec(),
			StackedNodeState::Changed(node) => node.into_encoded::<_, T::Codec, T::Hash>(
				|child, _o_slice, _o_index| {
					child.into_child_ref::<T::Hash>()
				}),
			StackedNodeState::Deleted => T::Codec::empty_node().to_vec(),
		}
	}

	/// Fetch by hash, no caching.
	fn fetch(
		db: &dyn HashDBRef<T::Hash, B>,
		hash: &TrieHash<T>,
		key: Prefix,
	) -> Result<Self, TrieHash<T>, CError<T>> {
		Ok(StackedNodeState::Unchanged(
			Self::fetch_node(db, hash, key)?
		))
	}

	/// Fetch a node by hash.
	fn fetch_node(
		db: &dyn HashDBRef<T::Hash, B>,
		hash: &TrieHash<T>,
		key: Prefix,
	) -> Result<OwnedNode<B>, TrieHash<T>, CError<T>> {
		let node_encoded = db.get(hash, key)
			.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(*hash)))?;

		Ok(
				OwnedNode::new::<T::Codec>(node_encoded)
					.map_err(|e| Box::new(TrieError::DecoderError(*hash, e)))?
		)
	}
}

/// Visitor trait to implement when using `trie_traverse_key`.
trait ProcessStack<B, T>
	where
		T: TrieLayout,
		B: Borrow<[u8]> + AsRef<[u8]>,
{
	/// Descend node, it should (if we want update):
	/// - return a new child for the new value.
	/// - replace `self` by a new branch with `self` as its split child
	///		and a new child for the new value.
	/// - change value of `self` only.
	fn enter_terminal(
		&mut self,
		stacked: &mut StackedItem<B, T>,
		key_element: &[u8],
		action: InputAction<&[u8], &TrieHash<T>>,
		to_attach_node: Option<OwnedNode<B>>,
		state: TraverseState,
	) -> Option<StackedItem<B, T>>;

	/// Callback on exit a node, commit action on change node should be applied here.
	fn exit(&mut self, prefix: Prefix, stacked: StackedNodeState<B, T>, prev_db: Option<(TrieHash<T>, OwnedPrefix)>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>>;
	/// Callback on a detached node.
	fn exit_detached(&mut self, key_element: &[u8], prefix: Prefix, stacked: StackedNodeState<B, T>, prev_db: Option<(TrieHash<T>, OwnedPrefix)>);
	/// Same as `exit` but for root (very last exit call).
	fn exit_root(&mut self, stacked: StackedNodeState<B, T>, prev_db: Option<(TrieHash<T>, OwnedPrefix)>);
}

/// State when descending
enum TraverseState {
	/// This is the right node for value.
	ValueMatch,
	/// after node
	AfterNode,
	/// Mid partial and index
	MidPartial(usize),
}

/// Action for a key to traverse.
pub enum InputAction<V, H> {
	/// Delete a value if it exists.
	Delete,
	/// Insert a value. If value is already define,
	/// it will be overwrite.
	Insert(V),
	/// Detach trie content at a given.
	/// Handle detached nodes is managed by process stack logic.
	Detach,
	/// Attach a trie with given hash.
	/// Handle of conflict is managed by process stack logic.
	/// More common strategie would be to replace content and handle
	/// the replaced content as a detached content is handled.
	Attach(H),
}

impl<V: AsRef<[u8]>, H> InputAction<V, H> {

	/// Alternative to `std::convert::AsRef`.
	/// Retun optionally a reference to a hash to an node to fetch for this action.
	pub fn as_ref(&self) -> (InputAction<&[u8], &H>, Option<&H>) {
		match self {
			InputAction::Insert(v) => (InputAction::Insert(v.as_ref()), None),
			InputAction::Delete => (InputAction::Delete, None),
			InputAction::Attach(attach_root) => (InputAction::Attach(&attach_root), Some(&attach_root)),
			InputAction::Detach => (InputAction::Detach, None),
		}
	}
}

/// The main entry point for traversing a trie by a set of keys.
fn trie_traverse_key<'a, T, I, K, V, B, F>(
	db: &'a dyn HashDBRef<T::Hash, B>,
	root_hash: &'a TrieHash<T>,
	elements: I,
	callback: &mut F,
) -> Result<(), TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
		I: Iterator<Item = (K, InputAction<V, TrieHash<T>>)>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		F: ProcessStack<B, T>,
{

	// Stack of traversed nodes
	let mut stack: smallvec::SmallVec<[StackedItem<B, T>; 16]> = Default::default();

	let current = if let Ok(root) = StackedNodeState::fetch(db, root_hash, EMPTY_PREFIX) {
		root
	} else {
		return Err(Box::new(TrieError::InvalidStateRoot(*root_hash)));
	};

	let depth = current.partial().map(|p| p.len()).unwrap_or(0);
	let mut current = StackedItem {
		item: StackedNode {
			node: current,
			previous_db_handle: Some((*root_hash, owned_prefix(&EMPTY_PREFIX))),
			depth_prefix: 0,
			depth,
			parent_index: 0,
		},
		first_modified_child: None,
		split_child: None,
		can_fuse: true,
	};

	let mut previous_key: Option<K> = None;

	for next_query in elements.into_iter().map(|e| Some(e)).chain(Some(None)) {

		let last = next_query.is_none();

		// PATH UP over the previous key and value
		if let Some(key) = previous_key.as_ref() {

			// Pop deleted (empty) nodes.
			if current.item.node.is_empty() {
				assert!(current.first_modified_child.is_none());
				assert!(current.split_child.is_none());
				if let Some(mut parent) = stack.pop() {
					let prefix = NibbleSlice::new_offset(key.as_ref(), current.item.depth_prefix);
					parent.append_child(current.into(), prefix.left(), callback);
					current = parent;
				} else {
					// Empty trie, next additional value is therefore a leaf.
					// Also delete this entry (could have been something else than empty before).
					debug_assert!(current.item.depth_prefix == 0);
					match next_query.as_ref() {
						Some((key, InputAction::Insert(value))) => {
							callback.exit(
								EMPTY_PREFIX,
								current.item.node,
								current.item.previous_db_handle,
							);
							let leaf = Node::new_leaf(
								NibbleSlice::new(key.as_ref()),
								value.as_ref(),
							);
							current = StackedItem {
								item: StackedNode {
									node: StackedNodeState::Changed(leaf),
									previous_db_handle: None,
									depth_prefix: 0,
									depth: key.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE,
									parent_index: 0,
								},
								first_modified_child: None,
								split_child: None,
								can_fuse: true,
							};
							continue;
						},
						Some((key, InputAction::Attach(attach_root))) => {
							let root_prefix = (key.as_ref(), None);
							let node = StackedNodeState::<B, T>::fetch(db, &attach_root, root_prefix)?;
							if !node.is_empty() {
								let depth = node.partial().map(|p| p.len()).unwrap_or(0);
								current = StackedItem {
									item: StackedNode {
										node,
										previous_db_handle: None,
										depth_prefix: 0,
										depth,
										parent_index: 0,
									},
									first_modified_child: None,
									split_child: None,
									can_fuse: true,
								};
							}
							continue;
						},
						Some((_key, InputAction::Detach))
						| Some((_key, InputAction::Delete)) => {
							continue;
						},
						None => {
							callback.exit_root(
								current.item.node,
								current.item.previous_db_handle,
							);
							return Ok(());
						},
					}
				}
			}

			let target_common_depth = next_query.as_ref().map(|(next, _)| nibble_ops::biggest_depth(
				key.as_ref(),
				next.as_ref(),
			)).unwrap_or(0); // last element goes up to root

			current.fuse_node(key.as_ref(), db, callback)?;

			// unstack nodes if needed
			while last || target_common_depth < current.item.depth_prefix {
				// child change or addition
				if let Some(mut parent) = stack.pop() {
					if !parent.can_fuse {
						// process exit, as we already assert two child, no need to store in case of parent
						// fusing.
						// Deletion case is guaranted by ordering of input (fix delete only if no first
						// and no split).
						current.process_first_modified_child(key.as_ref(), callback);
						current.process_split_child(key.as_ref(), callback);
						let prefix = NibbleSlice::new_offset(key.as_ref(), current.item.depth_prefix);
						parent.append_child(current.into(), prefix.left(), callback);
					} else if let Some(first_modified_child_index) = parent.first_modified_child_index() {
						debug_assert!(first_modified_child_index < current.item.parent_index);
						parent.process_child(current, key.as_ref(), callback);
					} else {
						if let Some(split_child_index) = parent.split_child_index() {
							if split_child_index < current.item.parent_index {
								parent.can_fuse = false;
							}
						}
						if parent.can_fuse && parent.item.node.has_value() {
							// this could not be fuse (delete value occurs before),
							// no stacking of first child
							parent.can_fuse = false;
						}
						if !parent.can_fuse {
							parent.process_child(current, key.as_ref(), callback);
						} else {
							current.process_first_modified_child(key.as_ref(), callback);
							// split child is after first child (would be processed otherwhise), so no need to
							// order the two instructions.
							current.process_split_child(key.as_ref(), callback);
							// first node visited on a fusable element, store in parent first child and process later.
							// Process an eventual split child (index after current).
							parent.first_modified_child = Some(current.into());
						}
					}
					current = parent;
				} else {
					if last {
						current.process_first_modified_child(key.as_ref(), callback);
						current.process_split_child(key.as_ref(), callback);
						current.process_root(key.as_ref(), callback);
						return Ok(());
					} else {
						// move to next key
						break;
					}
				}

				if current.fuse_node(key.as_ref(), db, callback)? {
					// no need to try to go down when fuse succeed
					continue;
				}
			}
		}

		// PATH DOWN descending in next_query.
		if let Some((key, value)) = next_query {
			let dest_slice = NibbleFullKey::new(key.as_ref());
			let dest_depth = key.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE;
			let mut descend_mid_index = None;
			loop {
				let common_index = current.item.node.partial()
					.map(|current_partial| {
						let target_partial = NibbleSlice::new_offset(key.as_ref(), current.item.depth_prefix);
						current.item.depth_prefix + current_partial.common_prefix(&target_partial)
					}).unwrap_or(current.item.depth_prefix);
				if common_index == current.item.depth && dest_depth > current.item.depth {
					let next_index = dest_slice.at(current.item.depth);
					let prefix = NibbleSlice::new_offset(key.as_ref(), current.item.depth + 1);
					if let Some(child) = current.descend_child(next_index, db, prefix.left())? {
						stack.push(current);
						current = child;
					} else {
						break;
					}
				} else {
					if common_index < current.item.depth {
						descend_mid_index = Some(common_index);
					}
					break;
				}
			}

			let traverse_state = if let Some(mid_index) = descend_mid_index {
				TraverseState::MidPartial(mid_index)
			} else if dest_depth > current.item.depth {
				// over callback
				TraverseState::AfterNode
			} else {
				debug_assert!(dest_depth == current.item.depth);
				// value replace callback
				TraverseState::ValueMatch
			};

			let (value, do_fetch) = value.as_ref();
			let fetch = if let Some(hash) = do_fetch {
				 // This is fetching node to attach
				let root_prefix = (key.as_ref(), None);
				let hash = StackedNodeState::<_, T>::fetch_node(db, &hash, root_prefix)?;
				Some(hash)
			} else {
				None
			};
			if let Some(new_child) = callback.enter_terminal(
				&mut current,
				key.as_ref(),
				value,
				fetch,
				traverse_state,
			) {
				stack.push(current);
				current = new_child;
			}
			previous_key = Some(key);
		}
	}

	Ok(())
}

/// Contains ordered node change for this iteration.
/// The resulting root hash.
/// The latest changed node.
struct BatchUpdate<H, C, CD, D> {
	register_update: C,
	register_update_attach_detach: CD,
	register_detached: D,
	root: H,
}

impl<B, T, C, CD, D> ProcessStack<B, T> for BatchUpdate<TrieHash<T>, C, CD, D>
	where
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		T: TrieLayout,
		C: FnMut((OwnedPrefix, TrieHash<T>, Option<Vec<u8>>)),
		CD: FnMut((OwnedPrefix, TrieHash<T>, Option<Vec<u8>>)),
		D: FnMut((Vec<u8>, OwnedPrefix, TrieHash<T>)),
{
	fn enter_terminal(
		&mut self,
		stacked: &mut StackedItem<B, T>,
		key_element: &[u8],
		action: InputAction<&[u8], &TrieHash<T>>,
		to_attach_node: Option<OwnedNode<B>>,
		state: TraverseState,
	) -> Option<StackedItem<B, T>> {
		match state {
			TraverseState::ValueMatch => {
				match action {
					InputAction::Insert(value) => {
						stacked.item.node.set_value(value);
					},
					InputAction::Delete => {
						stacked.item.node.remove_value();
					},
					InputAction::Attach(attach_root) => {
						let prefix_nibble = NibbleSlice::new_offset(&key_element[..], stacked.item.depth_prefix);
						let prefix = prefix_nibble.left();
						let to_attach = to_attach_node
							.expect("Attachment resolution must be done before calling this function");
						let mut to_attach = StackedNodeState::UnchangedAttached(to_attach);
						if stacked.item.depth_prefix != stacked.item.depth {
							match to_attach.partial() {
								Some(partial) if partial.len() > 0 => {
									let mut build_partial: NodeKey = NibbleSlice::new_offset(key_element, stacked.item.depth_prefix).into();
									crate::triedbmut::combine_key(&mut build_partial, partial.right_ref());
									to_attach.set_partial(build_partial);
								},
								_ => {
									if let Some(partial) = stacked.item.node.partial() {
										to_attach.set_partial(partial.into());
									}
								},
							}
							stacked.item.node.advance_partial(stacked.item.depth - stacked.item.depth_prefix);
						}
						let detached = mem::replace(&mut stacked.item.node, to_attach);
						let detached_db = mem::replace(
							&mut stacked.item.previous_db_handle,
							Some((attach_root.clone(), owned_prefix(&(key_element, None)))),
						);
						stacked.item.depth = stacked.item.depth_prefix + stacked.item.node.partial().map(|p| p.len()).unwrap_or(0);
						self.exit_detached(key_element, prefix, detached, detached_db);
					},
					InputAction::Detach => {
						let prefix_nibble = NibbleSlice::new_offset(&key_element[..], stacked.item.depth_prefix);
						let prefix = prefix_nibble.left();
						let to_attach = StackedNodeState::Deleted;
						if stacked.item.depth_prefix != stacked.item.depth {
							stacked.item.node.advance_partial(stacked.item.depth - stacked.item.depth_prefix);
						}
						let detached = mem::replace(&mut stacked.item.node, to_attach);
						let detached_db = mem::replace(&mut stacked.item.previous_db_handle, None);
						self.exit_detached(key_element, prefix, detached, detached_db);
					},
				}
				None
			},
			TraverseState::AfterNode => {
				match action {
					InputAction::Insert(val) => {
						// corner case of empty trie.
						let offset = if stacked.item.node.is_empty() { 0 } else { 1 };
						// dest is a leaf appended to terminal
						let dest_leaf = Node::new_leaf(
							NibbleSlice::new_offset(key_element, stacked.item.depth + offset),
							val,
						);
						let parent_index = NibbleSlice::new(key_element).at(stacked.item.depth);
						let mut new_child = StackedItem {
							item: StackedNode {
								node: StackedNodeState::Changed(dest_leaf),
								previous_db_handle: None,
								depth_prefix: stacked.item.depth + offset,
								depth: key_element.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE,
								parent_index,
							},
							split_child: None,
							first_modified_child: None,
							can_fuse: false,
						};
						return if stacked.item.node.is_empty() {
							// replace empty.
							new_child.item.previous_db_handle = stacked.item.previous_db_handle.take();
							*stacked = new_child;
							None
						} else {
							// append to parent is done on exit through changed nature of the new leaf.
							Some(new_child)
						}
					},
					InputAction::Delete => {
						// nothing to delete.
						None
					},
					InputAction::Attach(attach_root) => {
						let offset = if stacked.item.node.is_empty() { 0 } else { 1 };
						let parent_index = NibbleSlice::new(key_element).at(stacked.item.depth);
						let to_attach = to_attach_node
							.expect("Attachment resolution must be done before calling this function");
						let mut to_attach = StackedNodeState::UnchangedAttached(to_attach);
						let depth_prefix = stacked.item.depth + offset;
						match to_attach.partial() {
							Some(partial) if partial.len() > 0 => {
								let mut build_partial: NodeKey = NibbleSlice::new_offset(key_element, depth_prefix).into();
								crate::triedbmut::combine_key(&mut build_partial, partial.right_ref());
									to_attach.set_partial(build_partial);
							},
							_ => {
								let partial: NodeKey = NibbleSlice::new_offset(key_element, depth_prefix).into();
								to_attach.set_partial(partial.into());
							},
						};

						let depth = depth_prefix + to_attach.partial().map(|p| p.len()).unwrap_or(0);
						let mut new_child = StackedItem {
							item: StackedNode {
								node: to_attach,
								// Attach root is prefixed at attach key
								previous_db_handle: Some((attach_root.clone(), owned_prefix(&(key_element, None)))),
								depth_prefix,
								depth,
								parent_index,
							},
							split_child: None,
							first_modified_child: None,
							can_fuse: false,
						};
						return if stacked.item.node.is_empty() {
							// replace empty.
							let detached_db = mem::replace(&mut new_child.item.previous_db_handle, stacked.item.previous_db_handle.take());
							self.exit_detached(key_element, EMPTY_PREFIX, StackedNodeState::<B, T>::Deleted, detached_db);
							*stacked = new_child;
							None
						} else {
							// append to parent is done on exit through changed nature of the new leaf.
							Some(new_child)
						}
					},
					InputAction::Detach => {
						// nothing to detach
						None
					},
				}
			},
			TraverseState::MidPartial(mid_index) => {
				match action {
					InputAction::Insert(value) => {
						assert!(!stacked.item.node.is_empty());
						stacked.do_split_child(mid_index, key_element, self);
						let (offset, parent_index) = if key_element.len() == 0 {
							// corner case of adding at top of trie
							(0, 0)
						} else {
							(1, NibbleSlice::new(key_element).at(mid_index))
						};
						let child = Node::new_leaf(
							NibbleSlice::new_offset(key_element, offset + mid_index),
							value.as_ref(),
						);
						return if mid_index == key_element.len() * nibble_ops::NIBBLE_PER_BYTE {

							// set value in new branch
							stacked.item.node.set_value(value);
							stacked.can_fuse = false;
							None
						} else {
							let child = StackedItem {
								item: StackedNode {
									node: StackedNodeState::Changed(child),
									previous_db_handle: None,
									depth_prefix: offset + mid_index,
									depth: key_element.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE,
									parent_index,
								},
								split_child: None,
								first_modified_child: None,
								can_fuse: false,
							};
							Some(child)
						}
					},
					InputAction::Delete => {
						// nothing to delete.
						None
					},
					InputAction::Attach(attach_root) => {
						let prefix_nibble = NibbleSlice::new(&key_element[..]);
						let prefix = prefix_nibble.left();
						let to_attach = to_attach_node
							.expect("Attachment resolution must be done before calling this function");
						let mut to_attach = StackedNodeState::UnchangedAttached(to_attach);
						match to_attach.partial() {
							Some(partial) if partial.len() > 0 => {
								let mut build_partial: NodeKey = NibbleSlice::new_offset(key_element, stacked.item.depth_prefix).into();
								crate::triedbmut::combine_key(&mut build_partial, partial.right_ref());
								to_attach.set_partial(build_partial);
							},
							_ => {
								let build_partial = NibbleSlice::new_offset(key_element, stacked.item.depth_prefix);
								if build_partial.len() > 0 {
									to_attach.set_partial(build_partial.into());
								}
							},
						}
						if mid_index > 0 {
							stacked.item.node.advance_partial(mid_index - stacked.item.depth_prefix);
						}
						let detached = mem::replace(&mut stacked.item.node, to_attach);
						//detached.advance_partial(mid_index);
						let detached_db = mem::replace(
							&mut stacked.item.previous_db_handle,
							Some((attach_root.clone(), owned_prefix(&(key_element, None)))),
						);
						stacked.item.depth = stacked.item.depth_prefix + stacked.item.node.partial().map(|p| p.len()).unwrap_or(0);
						self.exit_detached(key_element, prefix, detached, detached_db);
						None
					},
					InputAction::Detach => {
						if mid_index == NibbleSlice::new(key_element).len() {
							// on a path do a switch
							if stacked.item.node.is_empty() {
								unreachable!("we should not iterate in middle of an empty; this is a bug");
							}
							let prefix_nibble = NibbleSlice::new(&key_element[..]);
							let prefix = prefix_nibble.left();
							let to_attach = StackedNodeState::Deleted;
							let mut detached = mem::replace(&mut stacked.item.node, to_attach);
							detached.advance_partial(mid_index - stacked.item.depth_prefix);
							let detached_db = mem::replace(&mut stacked.item.previous_db_handle, None);
							self.exit_detached(key_element, prefix, detached, detached_db);
						}
						None
					},
				}
			},
		}
	}

	fn exit(&mut self, prefix: Prefix, stacked: StackedNodeState<B, T>, prev_db: Option<(TrieHash<T>, OwnedPrefix)>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>> {
		let register = &mut self.register_update;
		match stacked {
			StackedNodeState::Changed(node) => Some(Some({
				if let Some((h, p)) = prev_db {
					register((p, h, None));
				}
				let encoded = node.into_encoded::<_, T::Codec, T::Hash>(
					|child, _o_slice, _o_index| {
						child.into_child_ref::<T::Hash>()
					}
				);
				if encoded.len() < <T::Hash as hash_db::Hasher>::LENGTH {
					OwnedNodeHandle::InMemory(encoded)
				} else {
					let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
					// costy clone (could get read from here)
					register((owned_prefix(&prefix), hash.clone(), Some(encoded)));
					OwnedNodeHandle::Hash(hash)
				}
			})),
			StackedNodeState::Deleted => {
				if let Some((h, p)) = prev_db {
					register((p, h.clone(), None));
				}
				Some(None)
			},
			StackedNodeState::UnchangedAttached(node) => Some(Some({
				let encoded = node.data().to_vec();
				if encoded.len() < <T::Hash as hash_db::Hasher>::LENGTH {
					if let Some((h, p)) = prev_db {
						register((p, h, None));
					}
					OwnedNodeHandle::InMemory(encoded)
				} else {
					OwnedNodeHandle::Hash(<T::Hash as hash_db::Hasher>::hash(&encoded[..]))
				}
			})),
			_ => None,
		}
	}

	fn exit_root(&mut self, stacked: StackedNodeState<B, T>, prev_db: Option<(TrieHash<T>, OwnedPrefix)>) {
		let prefix = EMPTY_PREFIX;
		let register = &mut self.register_update;
		match stacked {
			s@StackedNodeState::Deleted
			| s@StackedNodeState::Changed(..) => {
				let encoded = s.into_encoded();
				let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
				self.root = hash.clone();
				if let Some((h, p)) = prev_db {
					register((p, h.clone(), None));
				}
				register((owned_prefix(&prefix), hash, Some(encoded)));
			},
			StackedNodeState::UnchangedAttached(node) => {
				let encoded = node.data().to_vec();
				let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
				self.root = hash.clone();
			},
			_ => (),
		}
	}

	fn exit_detached(&mut self, key_element: &[u8], prefix: Prefix, stacked: StackedNodeState<B, T>, prev_db: Option<(TrieHash<T>, OwnedPrefix)>) {
		let detached_prefix = (key_element, None);

		let is_empty_node = stacked.is_empty();
		let register_up = &mut self.register_update_attach_detach;
		let register = &mut self.register_detached;
		match stacked {
			s@StackedNodeState::Deleted
			| s@StackedNodeState::Changed(..) => {
				// same as root: also hash inline nodes.
				if let Some((h, p)) = prev_db {
					register_up((p, h.clone(), None));
				}
				if !is_empty_node {
					let encoded = s.into_encoded();
					let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
					register_up((owned_prefix(&detached_prefix), hash.clone(), Some(encoded)));
					register((key_element.to_vec(), owned_prefix(&prefix), hash));
				}
			},
			s@StackedNodeState::UnchangedAttached(..)
			| s@StackedNodeState::Unchanged(..) => {
				if !is_empty_node {
					let hash = if let Some((not_inline, _previous_prefix)) = prev_db {
						not_inline
					} else {
						let encoded = s.into_encoded();
						let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
						register_up((owned_prefix(&detached_prefix), hash.clone(), Some(encoded)));
						hash
					};
					register((key_element.to_vec(), owned_prefix(&prefix), hash));
				}
			},
		}
	}
}


fn owned_prefix(prefix: &Prefix) -> (BackingByteVec, Option<u8>) {
	(prefix.0.into(), prefix.1)
}

/// Extract prefix from a owned prefix.
pub fn from_owned_prefix(prefix: &OwnedPrefix) -> Prefix {
	(&prefix.0[..], prefix.1)
}

/// Update trie, returning deltas and root.
pub fn batch_update<'a, T, I, K, V, B>(
	db: &'a dyn HashDBRef<T::Hash, B>,
	root_hash: &'a TrieHash<T>,
	elements: I,
) -> Result<(
	TrieHash<T>,
	Vec<(OwnedPrefix, TrieHash<T>, Option<Vec<u8>>)>,
	Vec<(OwnedPrefix, TrieHash<T>, Option<Vec<u8>>)>,
	Vec<(Vec<u8>, OwnedPrefix, TrieHash<T>)>,
),TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
		I: Iterator<Item = (K, InputAction<V, TrieHash<T>>)>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
{
	let mut dest = Vec::new();
	let mut dest2 = Vec::new();
	let mut dest_detached = Vec::new();
	let mut batch_update = BatchUpdate {
		register_update: |update| {
			dest.push(update)
		},
		register_update_attach_detach: |update| {
			dest2.push(update)
		},
		register_detached: |update| {
			dest_detached.push(update)
		},
		root: root_hash.clone(),
	};
	trie_traverse_key::<T, _, _, _, _, _>(db, root_hash, elements, &mut batch_update)?;
	Ok((batch_update.root, dest, dest2, dest_detached))
}



/// For a dettached trie root, remove prefix.
/// Usually the prefix is the key path used to detach the node
/// for a key function that attach prefix.
/// This transformation is not needed if there is no prefix
/// added by the key function of the backend db.
/// This method maitain all trie key in memory, a different implementation
/// should be use if inner mutability is possible (trie iterator touch each
/// key only once so it should be safe to delete immediatly).
pub fn unprefixed_detached_trie<T: TrieLayout>(
	source_db: &mut dyn hash_db::HashDB<T::Hash, Vec<u8>>,
	mut target_db: Option<&mut dyn hash_db::HashDB<T::Hash, Vec<u8>>>,
	root: TrieHash<T>,
	prefix: &[u8],
)  -> Result<(),TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
{
	let mapped_source = PrefixedDBRef::<T>(source_db, prefix);
	let input = crate::TrieDB::<T>::new(&mapped_source, &root)?;
	let mut keys: Vec<(NibbleVec, TrieHash<T>)> = Vec::new();
	for elt in crate::TrieDBNodeIterator::new(&input)? {
		if let Ok((prefix, Some(hash), _)) = elt {
			keys.push((prefix, hash));
		}
	}
	let mut prefix_slice = prefix.to_vec();
	let prefix_slice_len = prefix_slice.len();
	for (prefix, hash) in keys.into_iter() {
		let prefix = prefix.as_prefix();
		prefix_slice.truncate(prefix_slice_len);
		prefix_slice.extend_from_slice(prefix.0);
		let prefix_source = (prefix_slice.as_ref(), prefix.1);
		if let Some(value) = source_db.get(&hash, prefix_source) {
			source_db.remove(&hash, prefix_source);
			if let Some(target) = target_db.as_mut() {
				target.emplace(hash, prefix, value);
			} else {
				source_db.emplace(hash, prefix, value);
			}
		}
	}
	Ok(())
}

struct PrefixedDBRef<'a, T: TrieLayout>(&'a mut dyn hash_db::HashDB<T::Hash, Vec<u8>>, &'a [u8]);

impl<'a, T: TrieLayout> hash_db::HashDBRef<T::Hash, Vec<u8>> for PrefixedDBRef<'a, T> {
	fn get(&self, key: &TrieHash<T>, prefix: Prefix) -> Option<Vec<u8>> {
		let mut prefix_slice = self.1.to_vec();
		prefix_slice.extend_from_slice(prefix.0);
		self.0.get(key, (prefix_slice.as_ref(), prefix.1))
	}

	fn contains(&self, key: &TrieHash<T>, prefix: Prefix) -> bool {
		let mut prefix_slice = self.1.to_vec();
		prefix_slice.extend_from_slice(prefix.0);
		self.0.contains(key, (prefix_slice.as_ref(), prefix.1))
	}
}

pub fn prefixed_detached_trie<T: TrieLayout>(
	source_db: &mut dyn hash_db::HashDB<T::Hash, Vec<u8>>,
	mut target_db: Option<&mut dyn hash_db::HashDB<T::Hash, Vec<u8>>>,
	root: TrieHash<T>,
	prefix: &[u8],
)  -> Result<(),TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
{
	let input = crate::TrieDB::<T>::new(&source_db, &root)?;
	let mut keys: Vec<(NibbleVec, TrieHash<T>)> = Vec::new();
	for elt in crate::TrieDBNodeIterator::new(&input)? {
		if let Ok((prefix, Some(hash), _)) = elt {
			keys.push((prefix, hash));
		}
	}
	let mut prefix_slice = prefix.to_vec();
	let prefix_slice_len = prefix_slice.len();
	for (prefix, hash) in keys.into_iter() {
		let prefix = prefix.as_prefix();
		if let Some(value) = source_db.get(&hash, prefix) {
			prefix_slice.truncate(prefix_slice_len);
			prefix_slice.extend_from_slice(prefix.0);
			let prefix_dest = (prefix_slice.as_ref(), prefix.1);
			source_db.remove(&hash, prefix);
			if let Some(target) = target_db.as_mut() {
				target.emplace(hash, prefix_dest, value);
			} else {
				source_db.emplace(hash, prefix_dest, value);
			}
		}
	}
	Ok(())
}

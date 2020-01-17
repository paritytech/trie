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

//! Traverse a trie.
//!
//! The traversal stack is updatable, and is therefore usable for
//! batch update of ordered key values.

use crate::triedbmut::{Node, NibbleFullKey};
use crate::triedbmut::NodeHandle as NodeHandleTrieMut;
use crate::node::{OwnedNode, NodeHandle, NodeKey};
use crate::nibble::{NibbleVec, nibble_ops, NibbleSlice};
#[cfg(feature = "std")]
use std::borrow::Borrow;
#[cfg(not(feature = "std"))]
use core::borrow::Borrow;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
#[cfg(not(feature = "std"))]
use alloc::boxed::Box;
use crate::{TrieLayout, TrieHash, CError, Result, TrieError};
use crate::nibble::{BackingByteVec, OwnedPrefix};
use hash_db::{HashDBRef, Prefix, EMPTY_PREFIX};
use crate::NodeCodec;
use ::core_::cmp::*;
use ::core_::mem;

type StorageHandle = Vec<u8>;
type OwnedNodeHandle<H> = NodeHandleTrieMut<H, StorageHandle>;

/// StackedNode can be updated.
/// A state can be use.
enum StackedNode<B, T>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	/// Read node.
	Unchanged(OwnedNode<B>),
	/// Modified node.
	Changed(Node<TrieHash<T>, StorageHandle>),
	/// Deleted node.
	Deleted,
}

impl<B, T> StackedNode<B, T>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	fn is_deleted(&self) -> bool {
		if let StackedNode::Deleted = self {
			true
		} else {
			false
		}
	}
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
	/// Internal node representation.
	node: StackedNode<B, T>,
	/// Hash used to access this node, for inline node and
	/// new nodes this is None.
	hash: Option<TrieHash<T>>,
	/// Index of prefix. 
	depth_prefix: usize,
	/// Depth of node, it is prefix depth and partial depth.
	depth: usize,
	/// parent index (only relevant when parent is a branch).
	parent_index: u8,
	/// Store split child to create after we did insert a branch
	/// into a partial. We keep index (second field) in case we descend
	/// into this split child: TODO rational seems bad (we descend into the
	/// branch so when we call fix we pass this anyway. TODO in fixnode
	/// add a check for this index not being set (only if from second field).
	split_child: Option<(Option<StackedItemChild<B, T>>, Option<u8>)>,
	/// Store first child, until `exit` get call, this is needed
	/// to be able to fuse branch containing a single child (delay
	/// `exit` call of first element after process of the second one).
	/// Store child and the key use when storing (to calculate final
	/// nibble, this is more memory costy than strictly necessary).
	/// Note that split_child is always a first_child.
	/// TODO rename to first modified child (non delete).
	first_child: Option<(StackedItemChild<B, T>, Vec<u8>)>,
	/// If a two child where already asserted or the node is deleted.
	did_first_child: bool,
}


/// Variant of stacked item to store first changed node.
struct StackedItemChild<B, T>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	/// Internal node representation.
	node: StackedNode<B, T>,
	/// Hash used to access this node, for inline node and
	/// new nodes this is None.
	hash: Option<TrieHash<T>>,
	/// Index of prefix.
	depth_prefix: usize,
	/// Depth of node, it is prefix depth and partial depth.
	depth: usize,
	/// parent index (only relevant when parent is a branch).
	parent_index: u8,
}

impl<B, T> From<StackedItem<B, T>> for StackedItemChild<B, T>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	fn from(item: StackedItem<B, T>) -> Self {
		let StackedItem {
			node,
			hash,
			depth_prefix,
			depth,
			parent_index,
			..
		} = item;
		StackedItemChild {
			node,
			hash,
			depth_prefix,
			depth,
			parent_index,
		}
	}
}

impl<B, T> StackedItem<B, T>
	where
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		T: TrieLayout,
{
	fn split_child_fuse_index(&self) -> Option<u8> {
		match self.split_child.as_ref() {
			Some((Some(child), _)) => Some(child.parent_index),
			Some((_, Some(parent_index))) => Some(*parent_index),
			None => None,
			_ => unreachable!("This pair is Either, TODO swith to enum"),
		}
	}

	fn split_child_index(&self) -> Option<u8> {
		match self.split_child.as_ref() {
			Some((Some(child), _)) => Some(child.parent_index),
			_ => None,
		}
	}

	fn first_child_index(&self) -> Option<u8> {
		self.first_child.as_ref().map(|c| c.0.parent_index)
	}

	fn is_split_child(&self, index: u8) -> bool {
		self.split_child_index().map(|child_index| child_index == index).unwrap_or(false)
	}

	// take first child (used for fusing, otherwhise process_first_child is probably what you want)
	fn take_first_child(&mut self) -> Option<(StackedItem<B, T>, Vec<u8>)> {
		// descending in first child is only for fusizg node
		// so we do not update self first child status (will be deleted).
		if let Some((StackedItemChild {
			node,
			depth,
			depth_prefix,
			hash,
			parent_index,
			..
		}, child_key)) = self.first_child.take() {
				Some((StackedItem {
				node,
				depth,
				depth_prefix,
				first_child: None,
				split_child: None,
				hash,
				parent_index,
				did_first_child: false,
			}, child_key))
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
			if let Some((Some(StackedItemChild {
				node,
				depth,
				depth_prefix,
				hash,
				parent_index,
				..
			}), None)) = self.split_child.take() {
				self.split_child = Some((None, Some(parent_index)));
				// from a split child key is none (partial changed on split)
				Some(StackedItem {
					node,
					depth,
					depth_prefix,
					first_child: None,
					split_child: None,
					hash,
					parent_index,
					did_first_child: false,
				})
			} else {
				unreachable!("Broken split expectation, visited twice");
			}
		} else {
			if let Some(node_handle) = self.node.child(index) {

				let (node, hash) = match node_handle {
					NodeHandle::Hash(handle_hash) => {
						let mut hash = <TrieHash<T> as Default>::default();
						hash.as_mut()[..].copy_from_slice(handle_hash.as_ref());
						(StackedNode::Unchanged(
							fetch::<T, B>(
								db, &hash, prefix,
						)?), Some(hash))
					},
					NodeHandle::Inline(node_encoded) => {
						// Instantiating B is only for inline node, still costy.
						(StackedNode::Unchanged(
							OwnedNode::new::<T::Codec>(B::from(node_encoded))
								.map_err(|e| Box::new(TrieError::DecoderError(
									self.hash.clone().unwrap_or_else(Default::default),
									e,
								)))?
						), None)
					},
				};
				let depth_prefix = self.depth + 1;
				let depth = depth_prefix + node.partial().map(|p| p.len()).unwrap_or(0);
				Some(StackedItem {
					node,
					hash,
					parent_index: index,
					depth_prefix,
					depth,
					first_child: None,
					split_child: None,
					did_first_child: false,
				})
			} else {
				None
			}
		})
	}

	// replace self by new branch at split and adding to self as a stacked item child.
	fn split_child(&mut self, mid_index: usize, key: &[u8]) {
		let dest_branch = if mid_index % nibble_ops::NIBBLE_PER_BYTE == 0 {
			let new_slice = NibbleSlice::new_offset(
				&key[..mid_index / nibble_ops::NIBBLE_PER_BYTE],
				self.depth_prefix,
			);
			Node::new_branch(new_slice)
		} else {
			let new_slice = NibbleSlice::new_offset(
				&key[..],
				self.depth_prefix,
			);
			let owned = new_slice.to_stored_range(mid_index - self.depth_prefix);
			// TODO EMCH refactor new_leaf to take BackingByteVec (stored) as input
			Node::new_branch(NibbleSlice::from_stored(&owned))
		};

		let old_depth = self.depth;
		self.depth = mid_index;
		let mut child = mem::replace(
			&mut self.node,
			StackedNode::Changed(dest_branch),
		);

		let parent_index = child.partial()
			.map(|p| p.at(mid_index - self.depth_prefix)).unwrap_or(0);

		child.advance_partial(1 + mid_index - self.depth_prefix);

		// split occurs before visiting a single child
		debug_assert!(self.first_child.is_none());
		// debug_assert!(!self.did_first_child);
		// ordering key also ensure
		debug_assert!(self.split_child_index().is_none());

		// not setting child relation (will be set on exit)
		let child = StackedItemChild {
			node: child,
			hash: None,
			depth_prefix: 1 + mid_index,
			depth: old_depth,
			parent_index,
		};
		self.split_child = Some((Some(child), None));
	}

	fn append_child<
		F: ProcessStack<B, T>,
	>(&mut self, child: StackedItemChild<B, T>, prefix: Prefix, callback: &mut F) {
		if let Some(handle) = callback.exit(
			prefix,
			child.node,
			child.hash.as_ref(),
		) {
			self.node.set_handle(handle, child.parent_index);
		}
	}

	fn process_split_child<
		F: ProcessStack<B, T>,
	>(&mut self, key: &[u8], callback: &mut F) {
		if let Some((Some(child), None)) = self.split_child.take() {
			self.split_child = Some((None, Some(child.parent_index)));
			// prefix is slice
			let mut build_prefix = NibbleVec::from(key, self.depth);
			build_prefix.push(child.parent_index);
			self.append_child(child, build_prefix.as_prefix(), callback);
		}
	}

	fn process_first_child<
		F: ProcessStack<B, T>,
	>(&mut self, callback: &mut F) {
		if let Some((child, key)) = self.first_child.take() {
			if let Some(split_child_index) = self.split_child_index() {
				if split_child_index < child.parent_index {
					self.process_split_child(key.as_ref(), callback);
				}
			}
			let nibble_slice = NibbleSlice::new_offset(key.as_ref(), child.depth_prefix);
			self.append_child(child, nibble_slice.left(), callback);
		}
	}

	fn process_child<
		F: ProcessStack<B, T>,
	>(&mut self, mut child: StackedItem<B, T>, key: &[u8], callback: &mut F) {
		// TODO switch to debug assert if correct asumption or call process first
		// child ordered with split child.
		assert!(child.first_child.is_none(), "guaranted by call to fix_node");

		if let Some(first_child_index) = self.first_child_index() {
			if first_child_index < child.parent_index {
				self.process_first_child(callback);
			}
		}
		if let Some(split_child_index) = self.split_child_index() {
			if split_child_index < child.parent_index {
				self.process_split_child(key.as_ref(), callback);
			}
		}
		// split child can be unprocessed (when going up it is kept after second node
		// in expectation of other children process.
		child.process_split_child(key, callback);
		let nibble_slice = NibbleSlice::new_offset(key.as_ref(), child.depth_prefix);
		self.append_child(child.into(), nibble_slice.left(), callback);
	}

	fn process_root<
		F: ProcessStack<B, T>,
	>(mut self, key: &[u8], callback: &mut F) {
		self.process_first_child(callback);
		self.process_split_child(key.as_ref(), callback);
		callback.exit_root(
			self.node,
			self.hash.as_ref(),
		)
	}

	// consume branch and return item to attach to parent
	fn fuse_branch<
		F: ProcessStack<B, T>,
	>(&mut self, child: StackedItem<B, T>, key: &[u8], callback: &mut F) {
		let child_depth = self.depth + 1 + child.node.partial().map(|p| p.len()).unwrap_or(0);
		let to_rem = mem::replace(&mut self.node, child.node);
		// delete current
		callback.exit(
			NibbleSlice::new_offset(key.as_ref(), self.depth_prefix).left(),
			to_rem, self.hash.as_ref(),
		).expect("no new node on empty");

		let partial = NibbleSlice::new_offset(key, self.depth_prefix)
			.to_stored_range(child_depth - self.depth_prefix);
		self.node.set_partial(partial);
		self.hash = child.hash;
		self.depth = child_depth;
		self.did_first_child = false;
		self.first_child = None;
		self.split_child = None;
	}
}

impl<B, T> StackedNode<B, T>
	where
		B: Borrow<[u8]> + AsRef<[u8]>,
		T: TrieLayout,
{
	/// Get extension part of the node (partial) if any.
	fn is_empty(&self) -> bool {
		match self {
			StackedNode::Unchanged(node) => node.is_empty(),
			StackedNode::Changed(node) => node.is_empty(),
			StackedNode::Deleted => true,
		}
	}

	/// Get extension part of the node (partial) if any.
	fn partial(&self) -> Option<NibbleSlice> {
		match self {
			StackedNode::Unchanged(node) => node.partial(),
			StackedNode::Changed(node) => node.partial(),
			StackedNode::Deleted => None,
		}
	}

	/// Try to access child.
	fn child(&self, ix: u8) -> Option<NodeHandle> {
		match self {
			StackedNode::Unchanged(node) => node.child(ix),
			StackedNode::Changed(node) => node.child(ix),
			StackedNode::Deleted => None,
		}
	}

	/// Tell if there is a value defined at this node position.
	fn has_value(&self) -> bool {
		match self {
			StackedNode::Unchanged(node) => node.has_value(),
			StackedNode::Changed(node) => node.has_value(),
			StackedNode::Deleted => false,
		}
	}

	/// Set a value if the node can contain one.
	fn set_value(&mut self, value: &[u8]) {
		match self {
			StackedNode::Unchanged(node) => {
				if let Some(new) = node.set_value(value) {
					*self = StackedNode::Changed(new);
				}
			},
			StackedNode::Changed(node) => node.set_value(value),
			StackedNode::Deleted => (),
		}
	}

	/// Change a partial if the node contains one.
	fn advance_partial(&mut self, nb: usize) {
		match self {
			StackedNode::Unchanged(node) => {
				if let Some(new) = node.advance_partial(nb) {
					*self = StackedNode::Changed(new);
				}
			},
			StackedNode::Changed(node) => node.advance_partial(nb),
			StackedNode::Deleted => (),
		}
	}

	/// Set a new partial.
	fn set_partial(&mut self, partial: NodeKey) {
		match self {
			StackedNode::Unchanged(node) => {
				if let Some(new) = node.set_partial(partial) {
					*self = StackedNode::Changed(new);
				}
			},
			StackedNode::Changed(node) => node.set_partial(partial),
			StackedNode::Deleted => (),
		}
	}


	/// Remove a value if the node contains one.
	fn remove_value(&mut self) {
		match self {
			StackedNode::Unchanged(node) => {
				match node.remove_value() {
					Some(Some(new)) =>
						*self = StackedNode::Changed(new),
					Some(None) =>
						*self = StackedNode::Deleted,
					None => (),
				}
			},
			StackedNode::Changed(node) => {
				if node.remove_value() {
					*self = StackedNode::Deleted;
				}
			},
			StackedNode::Deleted => (),
		}
	}

	/// Set a handle to a child node or remove it if handle is none.
	fn set_handle(&mut self, handle: Option<OwnedNodeHandle<TrieHash<T>>>, index: u8) {
		match self {
			StackedNode::Unchanged(node) => {
				let change = node.set_handle(handle, index);
				match change {
					Some(new) => *self = StackedNode::Changed(new),
					None => (),
				}
			},
			StackedNode::Changed(node) => {
				node.set_handle(handle, index);
			},
			StackedNode::Deleted => unreachable!(),
		}
	}

	/// Returns index of node to fuse with if fused require.
	fn fix_node(&mut self, pending: (Option<u8>, Option<u8>)) -> Option<u8> {
		match self {
			StackedNode::Deleted
			| StackedNode::Unchanged(..) => None,
			StackedNode::Changed(node) => {
				let (deleted, fuse) = node.fix_node(pending);
				if deleted {
					*self = StackedNode::Deleted;
				}
				fuse
			},
		}
	}
}

impl<B, T> StackedNode<B, T>
	where
		B: Borrow<[u8]> + AsRef<[u8]>,
		T: TrieLayout,
{

	/// Encode node
	fn into_encoded(self) -> Vec<u8> {
		match self {
			StackedNode::Unchanged(node) => node.data().to_vec(),
			StackedNode::Changed(node) => node.into_encoded::<_, T::Codec, T::Hash>(
				|child, _o_slice, _o_index| {
					child.as_child_ref::<T::Hash>()
				}),
			StackedNode::Deleted => T::Codec::empty_node().to_vec(),
		}
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
		value_element: Option<&[u8]>,
		state: TraverseState,
	) -> Option<StackedItem<B, T>>;

	/// Callback on exit a node, commit action on change node should be applied here.
	fn exit(&mut self, prefix: Prefix, stacked: StackedNode<B, T>, prev_hash: Option<&TrieHash<T>>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>>;
	/// Same as `exit` but for root (very last exit call).
	fn exit_root(&mut self, stacked: StackedNode<B, T>, prev_hash: Option<&TrieHash<T>>);
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

/// The main entry point for traversing a trie by a set of keys.
fn trie_traverse_key<'a, T, I, K, V, B, F>(
	db: &'a dyn HashDBRef<T::Hash, B>,
	root_hash: &'a TrieHash<T>,
	elements: I,
	callback: &mut F,
) -> Result<(), TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
		I: IntoIterator<Item = (K, Option<V>)>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		F: ProcessStack<B, T>,
{
	// Stack of traversed nodes
	let mut stack: Vec<StackedItem<B, T>> = Vec::with_capacity(32);

	let root = if let Ok(root) = fetch::<T, B>(db, root_hash, EMPTY_PREFIX) {
		root
	} else {
		return Err(Box::new(TrieError::InvalidStateRoot(*root_hash)));
	};

	// TODO encapsulate fetch in stacked item, also split or others
	let current = StackedNode::<B, T>::Unchanged(root);
	let depth = current.partial().map(|p| p.len()).unwrap_or(0);
	let mut current = StackedItem {
		node: current,
		hash: Some(*root_hash),
		depth_prefix: 0,
		depth,
		parent_index: 0,
		first_child: None,
		split_child: None,
		did_first_child: false,
	};

	let mut previous_key: Option<K> = None;

	for next_query in elements.into_iter().map(|e| Some(e)).chain(Some(None)) {

		// PATH UP over the previous key and value
		if let Some(key) = previous_key.as_ref() {
			let target_common_depth = next_query.as_ref().map(|(next, _)| nibble_ops::biggest_depth(
				key.as_ref(),
				next.as_ref(),
			)).unwrap_or(0); // last element goes up to root

			let last = next_query.is_none();
			// unstack nodes if needed
			while last || target_common_depth < current.depth_prefix {
	
				// TODO check if fuse (num child is 1).
				// child change or addition
				if let Some(mut parent) = stack.pop() {
					let first_child_index = current.first_child.as_ref().map(|c| c.0.parent_index);
					// needed also to resolve
					if let Some(fuse_index) = current.node.fix_node((first_child_index, current.split_child_fuse_index())) {
						// try first child
						if let Some((child, child_key)) = current.take_first_child() {
							debug_assert!(child.parent_index == fuse_index);
							//
							current.fuse_branch(child, child_key.as_ref(), callback);
						} else {
							let mut prefix = NibbleVec::from(key.as_ref(), current.depth);
							prefix.push(fuse_index);
							let child = current.descend_child(fuse_index, db, prefix.as_prefix())?
								.expect("result of first child is define if consistent db");
							child.node.partial().map(|p| prefix.append_partial(p.right()));
							current.fuse_branch(child, prefix.inner(), callback);
						}
						// fuse child opteration did switch current context.
						continue;
					}
					if parent.did_first_child || current.node.is_deleted() {
						// process exit, as we already assert two child, no need to store in case of parent
						// fusing.
						// Deletion case is guaranted by ordering of input (fix delete only if no first
						// and no split).
						if let Some(handle) = callback.exit(
							NibbleSlice::new_offset(key.as_ref(), current.depth_prefix).left(),
							current.node, current.hash.as_ref(),
						) {
							parent.node.set_handle(handle, current.parent_index);
						}
					} else if let Some(first_child_index) = parent.first_child_index() {
						debug_assert!(first_child_index < current.parent_index);
						parent.did_first_child = true;
						parent.process_child(current, key.as_ref(), callback);
					} else {
						if let Some(split_child_index) = parent.split_child_index() {
							if split_child_index < current.parent_index {
								parent.did_first_child = true;
							}
						}
						if !parent.did_first_child && parent.node.has_value() {
							// this could not be fuse (delete value occurs before),
							// no stacking of first child
							parent.did_first_child = true;
						}
						if parent.did_first_child {
							parent.process_child(current, key.as_ref(), callback);
						} else {
							// first node visited on a fusable element, store in parent first child and process later.
							parent.first_child = Some((current.into(), key.as_ref().to_vec()));
						}
					}
					current = parent;
				} else {
					current.process_root(key.as_ref(), callback);
					return Ok(());
				}
			}
		}

		// PATH DOWN descending in next_query.
		if let Some((key, value)) = next_query {
			let dest_slice = NibbleFullKey::new(key.as_ref());
			let dest_depth = key.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE;
			let mut descend_mid_index = None;
			if !current.node.is_empty() {
				// corner case do not descend in empty node (else condition)
				loop {
					let common_index = current.node.partial()
						.map(|current_partial| {
							let target_partial = NibbleSlice::new_offset(key.as_ref(), current.depth_prefix);
							current.depth_prefix + current_partial.common_prefix(&target_partial)
						}).unwrap_or(current.depth_prefix);
					// TODO not sure >= or just >.
					if common_index == current.depth && dest_depth > current.depth {
						let next_index = dest_slice.at(current.depth);
						let prefix = NibbleSlice::new_offset(key.as_ref(), current.depth + 1);
						if let Some(child) = current.descend_child(next_index, db, prefix.left())? {
							current = child;
						} else {
							break;
						}
					} else {
						if common_index < current.depth {
							descend_mid_index = Some(common_index);
						}
						break;
					}
				}
			}
			let traverse_state = if let Some(mid_index) = descend_mid_index {
				TraverseState::MidPartial(mid_index)
			} else if dest_depth < current.depth {
				// TODO this might be unreachable from previous loop
				// split child (insert in current prefix -> try fuzzing on unreachable
				let mid_index = current.node.partial()
					.map(|current_partial| {
						let target_partial = NibbleSlice::new_offset(key.as_ref(), current.depth_prefix);
						current.depth_prefix + current_partial.common_prefix(&target_partial)
					}).expect("Covered by previous iteration for well formed trie");
				TraverseState::MidPartial(mid_index)
			} else if dest_depth > current.depth {
				// over callback
				TraverseState::AfterNode
			} else {
				// value replace callback
				TraverseState::ValueMatch
			};
			if let Some(new_child) = callback.enter_terminal(
				&mut current,
				key.as_ref(),
				value.as_ref().map(|v| v.as_ref()),
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

/// Fetch a node by hash, do not cache it.
fn fetch<T: TrieLayout, B: Borrow<[u8]>>(
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

/// Contains ordered node change for this iteration.
/// The resulting root hash.
/// The latest changed node.
struct BatchUpdate<H>(
	Vec<(OwnedPrefix, H, Option<Vec<u8>>)>,
	H,
	Option<usize>,
);

impl<B, T> ProcessStack<B, T> for BatchUpdate<TrieHash<T>>
	where
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		T: TrieLayout,
{
	fn enter_terminal(
		&mut self,
		stacked: &mut StackedItem<B, T>,
		key_element: &[u8],
		value_element: Option<&[u8]>,
		state: TraverseState,
	) -> Option<StackedItem<B, T>> {
		match state {
			TraverseState::ValueMatch => {
				if let Some(value) = value_element {
					stacked.node.set_value(value);
				} else {
					stacked.node.remove_value();
				}
				None
			},
			TraverseState::AfterNode => {
				
				if let Some(val) = value_element {
					// corner case of empty trie.
					let offset = if stacked.node.is_empty() {
						0
					} else {
						1
					};
					// dest is a leaf appended to terminal
					let dest_leaf = Node::new_leaf(
						NibbleSlice::new_offset(key_element, stacked.depth + offset),
						val,
					);
					let parent_index = NibbleSlice::new(key_element).at(stacked.depth);
					let mut new_child = StackedItem {
						node: StackedNode::Changed(dest_leaf),
						hash: None,
						depth_prefix: stacked.depth + offset,
						depth: key_element.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE,
						parent_index,
						split_child: None,
						first_child: None,
						did_first_child: false,
					};
					return if stacked.node.is_empty() {
						// replace empty.
						new_child.hash = stacked.hash;
						*stacked = new_child;
						None
					} else {
						// append to parent is done on exit through changed nature of the new leaf.
						Some(new_child)
					};
				} else {
					// nothing to delete.
					return None;
				}
			},
			TraverseState::MidPartial(mid_index) => {
				if let Some(value) = value_element {
					stacked.split_child(mid_index, key_element);
					let (offset, parent_index) = if key_element.len() == 0 {
						// corner case of adding at top of trie
						(0, 0)
					} else {
						// TODO not sure on index
						(1, NibbleSlice::new(key_element).at(mid_index))
					};
					let child = Node::new_leaf(
						// TODO not sure on '1 +'
						NibbleSlice::new_offset(key_element, offset + mid_index),
						value.as_ref(),
					);
					return if mid_index == key_element.len() * nibble_ops::NIBBLE_PER_BYTE {
						// set value in new branch
						stacked.node.set_value(value);
						None
					} else {
						let child = StackedItem {
							node: StackedNode::Changed(child),
							hash: None,
							depth_prefix: offset + mid_index,
							depth: key_element.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE,
							parent_index,
							split_child: None,
							first_child: None,
							did_first_child: false,
						};
						Some(child)
					}
				} else {
					// nothing to delete.
					return None;
				}
			},
		}
	
	}


	fn exit(&mut self, prefix: Prefix, stacked: StackedNode<B, T>, prev_hash: Option<&TrieHash<T>>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>> {
		match stacked {
			StackedNode::Changed(node) => Some(Some({
				let encoded = node.into_encoded::<_, T::Codec, T::Hash>(
					|child, _o_slice, _o_index| {
						child.as_child_ref::<T::Hash>()
					}
				);
				if encoded.len() < 32 {
					OwnedNodeHandle::InMemory(encoded)
				} else {
					let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
					// register latest change
					self.2 = Some(self.0.len());
					// costy clone (could get read from here)
					self.0.push((owned_prefix(&prefix), hash.clone(), Some(encoded)));
					if let Some(h) = prev_hash {
						self.0.push((owned_prefix(&prefix), h.clone(), None));
					}
					OwnedNodeHandle::Hash(hash)
				}
			})),
			StackedNode::Deleted => {
				if let Some(h) = prev_hash {
					self.0.push((owned_prefix(&prefix), h.clone(), None));
				}
				Some(None)
			},
			_ => None,
		}
	}
	
	fn exit_root(&mut self, stacked: StackedNode<B, T>, prev_hash: Option<&TrieHash<T>>) {
		let prefix = EMPTY_PREFIX;
		match stacked {
			s@StackedNode::Deleted
			| s@StackedNode::Changed(..) => {
				let encoded = s.into_encoded();
				let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
				self.1 = hash.clone();
				self.0.push((owned_prefix(&prefix), hash, Some(encoded)));
				if let Some(h) = prev_hash {
					self.0.push((owned_prefix(&prefix), h.clone(), None));
				}
			},
			_ => (),
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
/// TODO this put all in memory in a vec: we could stream the process
/// (would be really good for very big updates). -> then remove root
/// from result and Batch update (is simply latest hash of iter (given
/// delete after insert)).
pub fn batch_update<'a, T, I, K, V, B>(
	db: &'a dyn HashDBRef<T::Hash, B>,
	root_hash: &'a TrieHash<T>,
	elements: I,
) -> Result<(TrieHash<T>, impl Iterator<Item = (OwnedPrefix, TrieHash<T>, Option<Vec<u8>>)>), TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
		I: IntoIterator<Item = (K, Option<V>)>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
{
	let mut batch_update = BatchUpdate(
		Default::default(),
		root_hash.clone(),
		None,
	);
	trie_traverse_key::<T, _, _, _, _, _>(db, root_hash, elements, &mut batch_update)?;
	// TODO when remove third elt of batchupdate the map gets useless
	Ok((batch_update.1, batch_update.0.into_iter().map(|i| (i.0, i.1, i.2))))
}

#[cfg(test)]
mod tests {
	use reference_trie::{RefTrieDBMutNoExt, RefTrieDBNoExt, TrieMut,
		trie_traverse_key_no_extension_build,
	};

	use memory_db::{MemoryDB, PrefixedKey};
	use keccak_hasher::KeccakHasher;
	use crate::{DBValue, OwnedPrefix};
	use hash_db::HashDB;
	use crate::triedbmut::tests::populate_trie_no_extension;

	type H256 = <KeccakHasher as hash_db::Hasher>::Out;

	fn memory_db_from_delta(
		delta: impl Iterator<Item = (OwnedPrefix, H256, Option<Vec<u8>>)>,
		mdb: &mut MemoryDB<KeccakHasher, PrefixedKey<KeccakHasher>, DBValue>,
	) {
		for (p, h, v) in delta {
			if let Some(v) = v {
				let prefix = (p.0.as_ref(), p.1);
				// damn elastic array in value looks costy
				mdb.emplace(h, prefix, v[..].into());
			} else {
				let prefix = (p.0.as_ref(), p.1);
				mdb.remove(&h, prefix);
			}
		}
	}

	fn compare_with_triedbmut(
		x: &[(Vec<u8>, Vec<u8>)],
		v: &[(Vec<u8>, Option<Vec<u8>>)],
	) {
		let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		populate_trie_no_extension(&mut db, &mut root, x).commit();
		{
			let t = RefTrieDBNoExt::new(&db, &root);
			println!("bef {:?}", t);
		}

		println!("AB {:?}",  db.clone().drain());
		let initial_root = root.clone();
		let mut initial_db = db.clone();
		// reference
		{
			let mut t = RefTrieDBMutNoExt::from_existing(&mut db, &mut root).unwrap();
			for i in 0..v.len() {
				let key: &[u8]= &v[i].0;
				if let Some(val) = v[i].1.as_ref() {
					t.insert(key, val.as_ref()).unwrap();
				} else {
					t.remove(key).unwrap();
				}
			}
		}
		println!("AA {:?}",  db.clone().drain());
		{
			let t = RefTrieDBNoExt::new(&db, &root);
			println!("aft {:?}", t);
		}

//		let mut reference_delta = db;

		let (calc_root, payload) = trie_traverse_key_no_extension_build(
			&mut initial_db,
			&initial_root,
			v.iter().map(|(a, b)| (a, b.as_ref())),
		);
		
		assert_eq!(calc_root, root);
		let mut batch_delta = initial_db;

//
		memory_db_from_delta(payload, &mut batch_delta);
/*
		// sort
		let batch_delta: std::collections::BTreeMap<_, _> = batch_delta.drain().into_iter().collect();
		// TODO this revel an issue with triedbmut implementation (some incorrect RC and therefore
		// node being kept).
		assert_eq!(
			batch_delta,
			reference_delta.drain().into_iter()
				// TODO there is something utterly wrong with
				// triedbmut: nodes getting removed more than once
				// and hash comming from nowhere
				// from now simply skip -1 counted
//				.filter(|(_, (_, rc))| rc >= &0)
				.collect(),
		);
*/

//		println!("{:?}", batch_delta.drain());
//		println!("{:?}", db.drain());
		// test by checking both triedb only
		let t2 = RefTrieDBNoExt::new(&db, &root).unwrap();
		println!("{:?}", t2);
		let t2b = RefTrieDBNoExt::new(&batch_delta, &calc_root).unwrap();
		println!("{:?}", t2b);
	
//		let t1 = RefTrieDBNoExt::new(&batch_delta, &root).unwrap();
//		assert_eq!(format!("{:?}", t1), format!("{:?}", t2));


//		panic!("!!END!!");

	}
	#[test]
	fn empty_node_null_key() {
		compare_with_triedbmut(
			&[],
			&[
				(vec![], Some(vec![0xffu8, 0x33])),
			],
		);
	}
	#[test]
	fn non_empty_node_null_key() {
		compare_with_triedbmut(
			&[
				(vec![0x0u8], vec![4, 32]),
			],
			&[
				(vec![], Some(vec![0xffu8, 0x33])),
			],
		);
	}
	#[test]
	fn empty_node_with_key() {
		compare_with_triedbmut(
			&[],
			&[
				(vec![0x04u8], Some(vec![0xffu8, 0x33])),
			],
		);
	}
	#[test]
	fn dummy1() {
		compare_with_triedbmut(
			&[
				(vec![0x04u8], vec![4, 32]),
			],
			&[
				(vec![0x06u8], Some(vec![0xffu8, 0x33])),
				(vec![0x08u8], Some(vec![0xffu8, 0x33])),
			],
		);
	}
	#[test]
	fn two_recursive_mid_insert() {
		compare_with_triedbmut(
			&[
				(vec![0x0u8], vec![4, 32]),
			],
			&[
				(vec![0x04u8], Some(vec![0xffu8, 0x33])),
				(vec![0x20u8], Some(vec![0xffu8, 0x33])),
				//(vec![0x06u8], Some(vec![0xffu8, 0x33])),
			],
		);
	}
	#[test]
	fn dummy2() {
		compare_with_triedbmut(
			&[
				(vec![0x01u8, 0x01u8, 0x23], vec![0x01u8; 32]),
				(vec![0x01u8, 0x81u8, 0x23], vec![0x02u8; 32]),
				(vec![0x01u8, 0xf1u8, 0x23], vec![0x01u8, 0x24]),
			],
			&[
				(vec![0x01u8, 0x01u8, 0x23], Some(vec![0xffu8; 32])),
				(vec![0x01u8, 0x81u8, 0x23], Some(vec![0xfeu8; 32])),
				(vec![0x01u8, 0x81u8, 0x23], None),
//				(vec![0x01u8, 0xf1u8, 0x23], Some(vec![0xffu8, 0x34])),
			],
		);
	}

	#[test]
	fn dummy3() {
		compare_with_triedbmut(
			&[
				(vec![2, 254u8], vec![4u8; 33]),
				(vec![1, 254u8], vec![4u8; 33]),
				(vec![1, 255u8], vec![5u8; 36]),
			],
			&[
				(vec![1, 254u8], None),
			],
		);
	}

	#[test]
	fn dummy4() {
		compare_with_triedbmut(
			&[
				(vec![255u8, 251, 127, 255, 255], vec![255, 255]),
				(vec![255, 255, 127, 112, 255], vec![0, 4]),
				(vec![255, 127, 114, 253, 195], vec![1, 2]),
			],
			&[
				(vec![0u8], Some(vec![4; 251])),
				(vec![255, 251, 127, 255, 255], Some(vec![1, 2])),
			],
		);
	}

	#[test]
	fn dummy6() {
		compare_with_triedbmut(
			&[
				(vec![0, 144, 64, 212, 141, 1, 0, 0, 255, 144, 64, 212, 141, 1, 0, 141, 206, 0], vec![255, 255]),
				(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], vec![0, 4]),
				(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 208, 208, 208, 208, 208, 208], vec![1, 2]),
			],
			&[
				(vec![0, 6, 8, 21, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 199, 215], Some(vec![4, 251])),
				(vec![0, 144, 64, 212, 141, 1, 0, 0, 255, 144, 64, 212, 141, 1, 0, 141, 206, 0], None),
				(vec![141, 135, 207, 0, 63, 203, 216, 185, 162, 77, 154, 214, 210, 0, 0, 0, 0, 128], Some(vec![49, 251])),
				(vec![208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 8, 21, 1, 4, 0], Some(vec![4, 21])),
			],
		);
	}

	#[test]
	fn dummy5() {
		compare_with_triedbmut(
			&[
				(vec![9, 9, 9, 9, 9, 9, 9, 9, 9, 9], vec![1, 2]),
			],
			&[
				(vec![9, 1, 141, 44, 212, 0, 0, 51, 138, 32], Some(vec![4, 251])),
				(vec![9, 9, 9, 9, 9, 9, 9, 9, 9, 9], None),
				(vec![128], Some(vec![49, 251])),
			],
		);
	}

	#[test]
	fn single_latest_change_value_does_not_work() {
		compare_with_triedbmut(
			&[
				(vec![0, 0, 0, 0], vec![255;32]),
				(vec![0, 0, 0, 3], vec![5; 32]),
				(vec![0, 0, 6, 0], vec![6; 32]),
				(vec![0, 0, 0, 170], vec![1; 32]),
				(vec![0, 0, 73, 0], vec![2; 32]),
				(vec![0, 0, 0, 0], vec![3; 32]),
				(vec![0, 199, 141, 0], vec![4; 32]),
			],
			&[
				(vec![0, 0, 0, 0], Some(vec![0; 32])),
				(vec![0, 0, 199, 141], Some(vec![0; 32])),
				(vec![0, 199, 141, 0], None),
				(vec![12, 0, 128, 0, 0, 0, 0, 0, 0, 4, 64, 2, 4], Some(vec![0; 32])),
				(vec![91], None),
			],
		);
	}

	#[test]
	fn chained_fuse() {
		compare_with_triedbmut(
			&[
				(vec![0u8], vec![1; 32]),
				(vec![0, 212], vec![2; 32]),
				(vec![0, 212, 96], vec![3; 32]),
				(vec![0, 212, 96, 88], vec![3; 32]),
			],
			&[
				(vec![0u8], None),
				(vec![0, 212], None),
				(vec![0, 212, 96], None),
				(vec![0, 212, 96, 88], Some(vec![3; 32])),
			],
		);
	}
}

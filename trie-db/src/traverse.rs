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
use crate::node::{OwnedNode, NodePlan, NodeHandle};
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
use crate::{DBValue, nibble::BackingByteVec};
use hash_db::{HashDB, Prefix, EMPTY_PREFIX, Hasher};
use crate::NodeCodec;
use ::core_::cmp::*;
use ::core_::mem;
//#[cfg(feature = "std")]
//use std::collections::VecDeque;
//#[cfg(not(feature = "std"))]
//use alloc::collections::vec_deque::VecDeque;

// TODO make it deletion aware : do not stack unchanged key and pass them
// to exit when not needed.

type StorageHandle = Vec<u8>;
type OwnedNodeHandle<H> = NodeHandleTrieMut<H, StorageHandle>;

/// StackedNode can be updated.
/// A state can be use.
pub enum StackedNode<B, T, S>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	/// Read node.
	Unchanged(OwnedNode<B>, S),
	/// Modified node.
	Changed(Node<TrieHash<T>, StorageHandle>, S),
	/// Deleted node.
	Deleted(S),
}

pub struct StackedItem<B, T, S>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{

	/// Interanl node representation.
	pub node: StackedNode<B, T, S>,
	/// Hash used to access this node, for inline node and
	/// new nodes this is None.
	pub hash: Option<TrieHash<T>>,
	/// Index of prefix. 
	pub depth_prefix: usize,
	/// Depth of node, it is prefix depth and partial depth.
	pub depth: usize,
	/// parent index (only relevant when parent is a branch).
	pub parent_index: u8,
	/// Tell if a split child has been created for this branch.
	pub split_child: bool,
}

impl<B, T, S> StackedNode<B, T, S>
	where
		B: Borrow<[u8]> + AsRef<[u8]>,
		T: TrieLayout,
		S: Clone,
//		TrieHash<T>: AsRef<[u8]>,
{
	/// Get extension part of the node (partial) if any.
	pub fn is_empty(&self) -> bool {
		match self {
			StackedNode::Unchanged(node, ..) => node.is_empty(),
			StackedNode::Changed(node, ..) => node.is_empty(),
			StackedNode::Deleted(..) => true,
		}
	}

	/// Get extension part of the node (partial) if any.
	pub fn partial(&self) -> Option<NibbleSlice> {
		match self {
			StackedNode::Unchanged(node, ..) => node.partial(),
			StackedNode::Changed(node, ..) => node.partial(),
			StackedNode::Deleted(..) => None,
		}
	}

	/// Try to access child.
	pub fn child(&self, ix: u8) -> Option<NodeHandle> {
		match self {
			StackedNode::Unchanged(node, ..) => node.child(ix),
			StackedNode::Changed(node, ..) => node.child(ix),
			StackedNode::Deleted(..) => None,
		}
	}

	/// Set a value if the node can contain one.
	pub fn set_value(&mut self, value: &[u8]) {
		match self {
			StackedNode::Unchanged(node, state) => {
				if let Some(new) = node.set_value(value) {
					*self = StackedNode::Changed(new, state.clone());
				}
			},
			StackedNode::Changed(node, ..) => node.set_value(value),
			StackedNode::Deleted(..) => (),
		}
	}

	/// Change a partial if the node contains one.
	pub fn advance_partial(&mut self, nb: usize) {
		match self {
			StackedNode::Unchanged(node, state) => {
				if let Some(new) = node.advance_partial(nb) {
					*self = StackedNode::Changed(new, state.clone());
				}
			},
			StackedNode::Changed(node, ..) => node.advance_partial(nb),
			StackedNode::Deleted(..) => (),
		}
	}


	/// Remove a value if the node contains one.
	pub fn remove_value(&mut self) {
		match self {
			StackedNode::Unchanged(node, state) => {
				match node.remove_value() {
					Some(Some(new)) =>
						*self = StackedNode::Changed(new, state.clone()),
					Some(None) =>
						*self = StackedNode::Deleted(state.clone()),
					None => (),
				}
			},
			StackedNode::Changed(node, state) => {
				if node.remove_value() {
					*self = StackedNode::Deleted(state.clone());
				}
			},
			StackedNode::Deleted(..) => (),
		}
	}

	/// Set a handle to a child node, changing existing to a new branch, and returning the new child.
	pub fn set_mid_handle(
		&mut self,
		handle: OwnedNodeHandle<TrieHash<T>>,
		index: u8,
		common_depth: usize,
	) -> Self {
		match self {
			StackedNode::Unchanged(node, state) => {
				let (new, child) = node.set_mid_handle(handle, index, common_depth);
				let result = StackedNode::Changed(child, state.clone());
				*self = StackedNode::Changed(new, state.clone());
				result
			},
			StackedNode::Changed(node, state) => {
				StackedNode::Changed(node.set_mid_handle(handle, index, common_depth), state.clone())
			},
			StackedNode::Deleted(..) => unreachable!(),
		}
	}

	/// Set a handle to a child node or remove it if handle is none.
	pub fn set_handle(&mut self, handle: Option<OwnedNodeHandle<TrieHash<T>>>, index: u8) {
		match self {
			StackedNode::Unchanged(node, state) => {
				let change = node.set_handle(handle, index);
				match change {
					Some(new) =>
						*self = StackedNode::Changed(new, state.clone()),
					None => (),
				}
			},
			StackedNode::Changed(node, state) => {
				node.set_handle(handle, index);
			},
			StackedNode::Deleted(..) => unreachable!(),
		}
	}

	/// Returns index of node to fuse with in case after removal of handle
	/// a branch with a single child and no value remain.
	pub fn fix_node(&mut self) -> Option<u8> {
		match self {
			StackedNode::Deleted(..)
			| StackedNode::Unchanged(..) => None,
			StackedNode::Changed(node, state) => {
				let (deleted, fuse) = node.fix_node();
				if deleted {
					*self = StackedNode::Deleted(state.clone());
				}
				fuse
			},
		}
	}

	/// Fuse changed node that need to be reduce to a child node,
	/// returns additional length to prefix.
	pub fn fuse_child(&mut self, child: OwnedNode<B>, child_ix: u8) -> usize {
		match self {
			StackedNode::Unchanged(node, state) => unreachable!(),
			StackedNode::Changed(node, state) => {
				node.fuse_child(child, child_ix)
			},
			StackedNode::Deleted(..) => unreachable!(),
		}
	}

}

impl<B, T, S> StackedNode<B, T, S>
	where
		B: Borrow<[u8]> + AsRef<[u8]>,
		T: TrieLayout,
		S: Clone,
{

	/// Encode node
	pub fn into_encoded(self) -> Vec<u8> {
		match self {
			StackedNode::Unchanged(node, ..) => node.data().to_vec(),
			StackedNode::Changed(node, ..) => node.into_encoded::<_, T::Codec, T::Hash>(
				|child, o_slice, o_index| {
					child.as_child_ref::<T::Hash>()
				}),
			StackedNode::Deleted(..) => T::Codec::empty_node().to_vec(),
		}
	}
}

/// Visitor trait to implement when using `trie_traverse_key`.
pub trait ProcessStack<B, T, K, V, S>
	where
		T: TrieLayout,
		S: Clone,
		B: Borrow<[u8]> + AsRef<[u8]>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
{
	// /// Callback on enter a node, change can be applied here.
	// fn enter(&mut self, prefix: NibbleSlice, stacked: &mut StackedNode<B, T, S>);
	/// Same as `enter` but at terminal node element (terminal considering next key so branch is
	/// possible here).
	/// TODO prefix semantic here is strange: it is prefix of child.
	fn enter_terminal(
		&mut self,
		stacked: &mut StackedItem<B, T, S>,
		key_element: &[u8],
		value_element: Option<&[u8]>,
		state: TraverseState,
	) -> Option<StackedItem<B, T, S>>;
	/// Callback on exit a node, commit action on change node should be applied here.
	fn exit(&mut self, prefix: Prefix, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>>;
	/// Same as `exit` but for root (very last exit call).
	fn exit_root(&mut self, prefix: Prefix, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>);


	/// Fetching a fuse latest, that is the latest changed value of a branch.
	/// This is called once per level in case of removal/fusion of a branch with
	/// a child
	/// This is only needed if changes are made by process stack.
	/// Access to this method means that the node need to be remove or invalidate (this is handled
	/// by this method (no call to exit on it)).
	/// TODO EMCH this method should be removed, by only calling exit for child of branch when going
	/// up (keeping a reference to each child instead of current only!!).
	fn fuse_latest_changed(&mut self, prefix: Prefix, hash: &TrieHash<T>) -> Option<&[u8]>;
}

/// State when descending
pub enum TraverseState {
	/// This is the right node for value.
	ValueMatch,
	/// after node
	AfterNode,
	/// Mid partial and index
	MidPartial(usize),
}

/// Descend into a node, depending on callback it can produce a new node
/// (and change existing one).
fn descend_terminal<T, K, V, S, B, F>(
	item: &mut StackedItem<B, T, S>,
	key: &K,
	value: Option<&V>,
	dest_depth: usize,
	callback: &mut F,
) -> (Option<StackedItem<B, T, S>>, Option<StackedItem<B, T, S>>)
	where
		T: TrieLayout,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
		S: Default + Clone,
		B: Borrow<[u8]> + AsRef<[u8]>,
		F: ProcessStack<B, T, K, V, S>,
{
	let key_dest = key.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE;
	let slice_dest = NibbleSlice::new_offset(key.as_ref(), item.depth_prefix);
	// TODO optimize common_prefix function ?? totally since needed in loop
	let target_common_depth = item.node.partial()
		.map(|p| item.depth_prefix + p.common_prefix(&slice_dest))
		.unwrap_or(item.depth);
	debug_assert!(!(target_common_depth < item.depth_prefix), "Descend should not be call in this state");
	if target_common_depth < item.depth {
		// insert into prefix
		(None, callback.enter_terminal(
			item,
			key.as_ref(),
			value.as_ref().map(|v| v.as_ref()),
			TraverseState::MidPartial(target_common_depth),
		))
	} else if key_dest == item.depth {
		// set value
		let n = callback.enter_terminal(
			item,
			key.as_ref(),
			value.as_ref().map(|v| v.as_ref()),
			TraverseState::ValueMatch,
		);
		debug_assert!(n.is_none());
		(None, None)
	} else {
		// extend
		(callback.enter_terminal(
			item,
			key.as_ref(),
			value.as_ref().map(|v| v.as_ref()),
			TraverseState::AfterNode,
		), None)
	}
}

/// The main entry point for traversing a trie by a set of keys.
pub fn trie_traverse_key<'a, T, I, K, V, S, B, F>(
	db: &'a mut dyn HashDB<T::Hash, B>,
	root_hash: &'a TrieHash<T>,
	elements: I,
	callback: &mut F,
) -> Result<(), TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
		I: IntoIterator<Item = (K, Option<V>)>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
		S: Default + Clone,
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		F: ProcessStack<B, T, K, V, S>,
{
	// stack of traversed nodes
	// first usize is depth, second usize is the parent index.
	let mut stack: Vec<StackedItem<B, T, S>> = Vec::with_capacity(32);

	// TODO EMCH do following update (used for error only)
	let root = if let Ok(root) = fetch::<T, B>(db, root_hash, EMPTY_PREFIX) {
		root
	} else {
		return Err(Box::new(TrieError::InvalidStateRoot(*root_hash)));
	};
//	stack.push(StackedNode::Unchanged(root, Default::default()));

	let current = StackedNode::<B, T, S>::Unchanged(root, Default::default());
	let depth = current.partial().map(|p| p.len()).unwrap_or(0);
	let mut current = StackedItem {
		node: current,
		hash: Some(*root_hash),
		depth_prefix: 0,
		depth,
		parent_index: 0,
		split_child: false,
	};

	let mut k: Option<K> = None;

	// TODO smal child that ?
	let mut split_child: Vec<(StackedItem<B, T, S>, Vec<u8>)> = Default::default();
	let mut limit_common = usize::max_value();
	for (next_k, v) in elements.into_iter() {
		if let Some(previous_key) = k {
			let mut target_common_depth = nibble_ops::biggest_depth(
				previous_key.as_ref(),
				next_k.as_ref(),
			);
			/*if target_common_depth == limit_common {
				// try to see if more common in current node
				// TODO this is redundant with start of descend.
				let slice_dest = NibbleSlice::new_offset(previous_key.as_ref(), current.depth_prefix);
				target_common_depth = current.node.partial()
					.map(|p| current.depth_prefix + p.common_prefix(&slice_dest))
					.unwrap_or(current.depth_prefix);
			} else {
				target_common_depth = min(limit_common, target_common_depth);
			}*/
			//target_common_depth = min(limit_common, target_common_depth);
			while target_common_depth < current.depth_prefix {
				// go up
				if let Some(mut last) = stack.pop() {
					if !last.node.is_empty() {
						align_node(db, callback, &mut current, previous_key.as_ref(), None, &mut split_child)?;
						if let Some(handle) = callback.exit(
							NibbleSlice::new_offset(previous_key.as_ref(), current.depth_prefix).left(),
							current.node, current.hash.as_ref(),
						) {
							last.node.set_handle(handle, current.parent_index);
						}
						current = last;
					}
				} else {
					align_node(db, callback, &mut current, previous_key.as_ref(), None, &mut split_child)?;
					callback.exit_root(EMPTY_PREFIX, current.node, current.hash.as_ref());
					return Ok(());
				}
			}
		}
		k = Some(next_k);
		
		if let Some(k) = k.as_ref() {
			let dest = NibbleFullKey::new(k.as_ref());
			let dest_depth = k.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE;
			
			loop {
				let slice_dest = NibbleSlice::new_offset(k.as_ref(), current.depth_prefix);
			
				limit_common = usize::max_value();
				let target_common_depth = current.node.partial()
					.map(|p| current.depth_prefix + p.common_prefix(&slice_dest))
					.unwrap_or(current.depth_prefix);
				let (child, parent_index) = if target_common_depth == current.depth {
					if dest_depth > current.depth {
						let next_index = dest.at(current.depth);
						if current.split_child {
							if next_index == split_child.last().map(|(c, _)| c.parent_index)
								.expect("split child set before") {
								current.split_child = false;
								stack.push(current);
								let (ch, v) = split_child.pop()
									.expect("split child set before");
								current = ch;
								continue;
							}
						}
						(current.node.child(next_index), next_index)
					} else {
						(None, 0)
					}
				} else {
					// TODO here we could use this common depth to avoid double calc in descend!!
					(None, 0)
				};
				if dest_depth > current.depth && child.is_some() {
					// non terminal
					let depth_prefix = current.depth + 1;
					let (node, hash) = match child {
						Some(NodeHandle::Hash(handle_hash)) => {
							let mut hash = <TrieHash<T> as Default>::default();
							hash.as_mut()[..].copy_from_slice(handle_hash.as_ref());
							(StackedNode::Unchanged(
								fetch::<T, B>(
									db, &hash,
									NibbleSlice::new_offset(k.as_ref(), depth_prefix).left(),
								)?,
								Default::default(),
							), Some(hash))
						},
						Some(NodeHandle::Inline(node_encoded)) => {
							(StackedNode::Unchanged(
								// Instantiating B is only for inline node, still costy.
								OwnedNode::new::<T::Codec>(B::from(node_encoded))
									.map_err(|e| Box::new(TrieError::DecoderError(
										current.hash.clone().unwrap_or_else(Default::default),
										e,
									)))?,
								Default::default(),
							), None)
						},
						None => {
							unreachable!("Depth checked previously");
						},
					};
					let depth = depth_prefix + node.partial().map(|p| p.len()).unwrap_or(0);
					stack.push(current);
					current = StackedItem {
						node,
						hash,
						depth_prefix,
						depth,
						parent_index,
						split_child: false,
					};
				} else {
					// remove empties
					while current.node.is_empty() && stack.len() > 0 {
						// TODO runing into this is not expected
						if let Some(mut prev) = stack.pop() {
							callback.exit(
								NibbleSlice::new_offset(k.as_ref(), current.depth_prefix).left(),
								current.node, current.hash.as_ref(),
							).expect("no new node on empty");
							prev.node.set_handle(None, current.parent_index);
							current = prev;
						}
					}
					if current.node.is_empty() {
						// corner case of empty trie
						if let Some(v) = v.as_ref() {
							let leaf = Node::new_leaf(
								NibbleSlice::new_offset(k.as_ref(), current.depth_prefix),
								v.as_ref(),
							);
							current = StackedItem {
								node: StackedNode::Changed(leaf, Default::default()),
								hash: current.hash,
								depth_prefix: current.depth_prefix,
								depth: k.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE - current.depth_prefix,
								parent_index: current.parent_index,
								split_child: false,
							}
						}
					} else {
						// terminal case
						match descend_terminal(&mut current, k, v.as_ref(), dest_depth, callback) {
							(Some(new), _) => {
								stack.push(current);
								current = new;
								limit_common = target_common_depth;
							},
							(_, Some(split)) => {
								split_child.push((split, k.as_ref().to_vec()));
								continue;
							},
							_ => (),
						}
					}
					// go next key
					break;
				}
			}
		}
	}

	if let Some(previous_key) = k {
		// go up
		while let Some(mut last) = stack.pop() {
			if !last.node.is_empty() {
				align_node(db, callback, &mut current, previous_key.as_ref(), None, &mut split_child)?;
				if let Some(handle) = callback.exit(
					NibbleSlice::new_offset(previous_key.as_ref(), current.depth_prefix).left(),
					current.node, current.hash.as_ref(),
				) {
					last.node.set_handle(handle, current.parent_index);
				}
				current = last;
			}
		}
		align_node(db, callback, &mut current, previous_key.as_ref(), None, &mut split_child)?;
		callback.exit_root(EMPTY_PREFIX, current.node, current.hash.as_ref());
		return Ok(());
	}

	Ok(())
}

fn align_node<'a, T, K, V, S, B, F>(
	db: &'a mut dyn HashDB<T::Hash, B>,
	callback: &mut F,
	branch: &mut StackedItem<B, T, S>,
	key: &[u8],
	mut prefix: Option<&mut NibbleVec>,
	split_child: &mut Vec<(StackedItem<B, T, S>, Vec<u8>)>,
) -> Result<(), TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
		S: Default + Clone,
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		F: ProcessStack<B, T, K, V, S>,
{
	let init_prefix_len = prefix.as_ref().map(|p| p.len())
		.unwrap_or(0);
	if branch.split_child {
		branch.split_child = false;
		let (mut child, check) = split_child.pop()
			.expect("trie correct parsing ensure it is set");
		let mut build_prefix: NibbleVec;
		// Rebuild the right prefix by removing last nibble and adding parent child.
		let prefix: &mut NibbleVec = if let Some(prefix) = prefix.as_mut() {
			prefix
		} else {
			build_prefix = NibbleVec::from(key, branch.depth_prefix);
			&mut build_prefix
		};
		branch.node.partial().map(|p| {
			prefix.append_partial(p.right());
		});
		prefix.push(child.parent_index);
/*		child.node.partial().map(|p| {
			prefix.append_partial(p.right());
		});*/
		let len_prefix = prefix.len();
		align_node(db, callback, &mut child, key, Some(prefix), split_child)?;
		prefix.drop_lasts(prefix.len() - len_prefix);
		let handle = callback.exit(
			prefix.as_prefix(),
			child.node, child.hash.as_ref(),
		).expect("split child is always a changed node");
		// TODO if it is single handle, then fix node will reaccess that:
		// that is one hash creation here and one access then deletion afterward.
		branch.node.set_handle(handle, child.parent_index);
	}
	if let Some(fuse_index) = branch.node.fix_node() {
		let mut build_prefix: NibbleVec;
		let (child, hash) = match branch.node.child(fuse_index) {
			Some(NodeHandle::Hash(handle_hash)) => {
				let mut hash = <TrieHash<T> as Default>::default();
				hash.as_mut()[..].copy_from_slice(handle_hash.as_ref());
				let prefix: &mut NibbleVec = if let Some(prefix) = prefix.as_mut() {
					let len_prefix = prefix.len();
					if len_prefix > init_prefix_len {
						prefix.drop_lasts(len_prefix - init_prefix_len);
					}
					prefix
				} else {
					build_prefix = NibbleVec::from(key, branch.depth_prefix);
					&mut build_prefix
				};
				branch.node.partial().map(|p| {
					prefix.append_partial(p.right());
				});
			
				// TODO conversion to NibbleVec is slow
				prefix.push(fuse_index);
				let prefix = prefix.as_prefix();
				if let Some(node_encoded) = callback.fuse_latest_changed(
					prefix,
					&hash,
				) {
					// costy encode decode round trip, but this is a corner case.
					(OwnedNode::new::<T::Codec>(B::from(node_encoded))
						.map_err(|e| Box::new(TrieError::DecoderError(
							branch.hash.clone().unwrap_or_else(Default::default),
							e,
					)))?, None)
				} else {
					(fetch::<T, B>(
						db,
						&hash,
						prefix,
					)?, Some((hash, prefix)))
				}
			},
			Some(NodeHandle::Inline(node_encoded)) => {
				(OwnedNode::new::<T::Codec>(B::from(node_encoded))
					.map_err(|e| Box::new(TrieError::DecoderError(
						branch.hash.clone().unwrap_or_else(Default::default),
						e,
				)))?, None)
			},
			None => unreachable!("correct index used"),
		};
		if let Some((hash, prefix)) = hash {
			// register delete
			callback.exit(
				NibbleSlice::new_offset(key, branch.depth).left(),
				StackedNode::Deleted(Default::default()),
				Some(&hash),
			).expect("No new node on deleted allowed");
		}
		branch.depth += branch.node.fuse_child(child, fuse_index);
	}

	Ok(())
}


/// Fetch a node by hash, do not cache it.
fn fetch<T: TrieLayout, B: Borrow<[u8]>>(
	db: &mut dyn HashDB<T::Hash, B>,
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
pub struct BatchUpdate<H>(
	pub Vec<((BackingByteVec, Option<u8>), H, Option<Vec<u8>>, bool)>,
	pub H,
	pub Option<usize>,
);

impl<B, T, K, V, S> ProcessStack<B, T, K, V, S> for BatchUpdate<TrieHash<T>>
	where
		T: TrieLayout,
		S: Clone + Default,
		B: Borrow<[u8]> + AsRef<[u8]>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
{
	//fn enter(&mut self, prefix: NibbleSlice, stacked: &mut StackedNode<B, T, S>) {
	//}

	fn enter_terminal(
		&mut self,
		stacked: &mut StackedItem<B, T, S>,
		key_element: &[u8],
		value_element: Option<&[u8]>,
		state: TraverseState,
	) -> Option<StackedItem<B, T, S>> {
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
					// append to parent is done on exit through changed nature of the new leaf.
					return Some(StackedItem {
						node: StackedNode::Changed(dest_leaf, Default::default()),
						hash: None,
						depth_prefix: stacked.depth + offset,
						depth: key_element.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE,
						parent_index,
						split_child: false,
					});
				} else {
					// nothing to delete.
					return None;
				}
			},
			TraverseState::MidPartial(mid_index) => {
				if let Some(val) = value_element {
					let dest_branch = if mid_index % nibble_ops::NIBBLE_PER_BYTE == 0 {
						let new_slice = NibbleSlice::new_offset(
							&key_element[..mid_index / nibble_ops::NIBBLE_PER_BYTE],
							stacked.depth_prefix,
						);
						Node::new_branch(new_slice)
					} else {
						let new_slice = NibbleSlice::new_offset(
							&key_element[..],
							stacked.depth_prefix,
						);
						let owned = new_slice.to_stored_range(mid_index - stacked.depth_prefix);
						// TODO EMCH refactor new_leaf to take BackingByteVec (stored) as input
						Node::new_branch(NibbleSlice::from_stored(&owned))
					};
					let old_depth = stacked.depth;
					stacked.depth = mid_index;
					let mut child = mem::replace(
						&mut stacked.node,
						StackedNode::Changed(dest_branch, Default::default()),
					);

					let parent_index = child.partial()
						.map(|p| p.at(mid_index - stacked.depth_prefix)).unwrap_or(0);

					child.advance_partial(1 + mid_index - stacked.depth_prefix);
					// not setting child relation (will be set on exit)
					let child = StackedItem {
						node: child,
						hash: None,
						depth_prefix: 1 + mid_index,
						depth: old_depth,
						parent_index,
						split_child: stacked.split_child,
					};
					stacked.split_child = true;
					return Some(child);
				} else {
					// nothing to delete.
					return None;
				}
			},
		}
	}

	fn exit(&mut self, prefix: Prefix, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>> {
		match stacked {
			StackedNode::Changed(node, _) => Some(Some({
				let encoded = node.into_encoded::<_, T::Codec, T::Hash>(
					|child, o_slice, o_index| {
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
					self.0.push((owned_prefix(&prefix), hash.clone(), Some(encoded), true));
					if let Some(h) = prev_hash {
						self.0.push((owned_prefix(&prefix), h.clone(), None, true));
					}
					OwnedNodeHandle::Hash(hash)
				}
			})),
			StackedNode::Deleted(..) => {
				if let Some(h) = prev_hash {
					self.0.push((owned_prefix(&prefix), h.clone(), None, true));
				}
				Some(None)
			},
			_ => None,
		}
	}
	
	fn exit_root(&mut self, prefix: Prefix, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>) {
		match stacked {
			s@StackedNode::Deleted(..)
			| s@StackedNode::Changed(..) => {
				let encoded = s.into_encoded();
				let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
				self.1 = hash.clone();
				self.0.push((owned_prefix(&prefix), hash, Some(encoded), true));
				if let Some(h) = prev_hash {
					self.0.push((owned_prefix(&prefix), h.clone(), None, true));
				}
			},
			_ => (),
		}
	}

	fn fuse_latest_changed(&mut self, prefix: Prefix, hash: &TrieHash<T>) -> Option<&[u8]> {
		for latest in 0..self.0.len() {
			let stored_slice = from_owned_prefix(&self.0[latest].0);
			if hash == &self.0[latest].1 && prefix == stored_slice {
				self.0[latest].3 = false;
				return self.0[latest].2.as_ref().map(|s| &s[..]);
			}
		}
		None
	}
}


fn owned_prefix(prefix: &Prefix) -> (BackingByteVec, Option<u8>) { 
	(prefix.0.into(), prefix.1)
}

fn from_owned_prefix(prefix: &(BackingByteVec, Option<u8>)) -> Prefix { 
	(&prefix.0[..], prefix.1)
}

#[cfg(test)]
mod tests {
	use reference_trie::{RefTrieDBMutNoExt, RefTrieDBNoExt, TrieMut, NodeCodec,
		ReferenceNodeCodec, reference_trie_root, reference_trie_root_no_extension,
		NoExtensionLayout, TrieLayout, trie_traverse_key_no_extension_build, BatchUpdate,
		NibbleVec,
	};

	use memory_db::{MemoryDB, PrefixedKey};
	use keccak_hasher::KeccakHasher;
	use crate::{DBValue, nibble::BackingByteVec};
	use hash_db::{EMPTY_PREFIX, Prefix, HashDB};
	use crate::triedbmut::tests::populate_trie_no_extension;

	type H256 = <KeccakHasher as hash_db::Hasher>::Out;

	fn memory_db_from_delta(
		delta: Vec<((BackingByteVec, Option<u8>), H256, Option<Vec<u8>>, bool)>,
		mdb: &mut MemoryDB<KeccakHasher, PrefixedKey<KeccakHasher>, DBValue>,
	) {
		for (p, h, v, d) in delta {
			if d {
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

		let reference_root = root.clone();
	
		let mut batch_update = BatchUpdate(Default::default(), initial_root.clone(), None);
		trie_traverse_key_no_extension_build(
			&mut initial_db,
			&initial_root,
			v.iter().map(|(a, b)| (a, b.as_ref())),
			&mut batch_update,
		);
		
		assert_eq!(batch_update.1, reference_root);
println!("{:?}", batch_update.0);
		let mut batch_delta = initial_db;

		let r2 = batch_update.1.clone();
//
		memory_db_from_delta(batch_update.0, &mut batch_delta);
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
		let t2b = RefTrieDBNoExt::new(&batch_delta, &r2).unwrap();
		println!("{:?}", t2b);
	
//		let t1 = RefTrieDBNoExt::new(&batch_delta, &root).unwrap();
//		assert_eq!(format!("{:?}", t1), format!("{:?}", t2));


		panic!("!!END!!");

	}

	#[test]
	fn dummy1() {
		compare_with_triedbmut(
			&[
				(vec![0x0u8], vec![4, 32]),
			],
			&[
				(vec![0x04u8], Some(vec![0xffu8, 0x33])),
				(vec![32u8], Some(vec![0xffu8, 0x33])),
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

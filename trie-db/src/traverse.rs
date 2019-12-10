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
use crate::{TrieLayout, TrieHash, CError, Result, TrieError};
use crate::DBValue;
use hash_db::{HashDB, Prefix, EMPTY_PREFIX, Hasher};
use crate::NodeCodec;
use ::core_::cmp::*;
use ::core_::mem;
use elastic_array::ElasticArray36;

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
				match node.set_handle(handle, index) {
					Some(Some(new)) =>
						*self = StackedNode::Changed(new, state.clone()),
					Some(None) =>
						*self = StackedNode::Deleted(state.clone()),
					None => (),
				}
			},
			StackedNode::Changed(node, state) => {
				if node.set_handle(handle, index) {
					*self = StackedNode::Deleted(state.clone());
				}
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
	fn exit(&mut self, prefix: NibbleSlice, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>>;
	/// Same as `exit` but for root (very last exit call).
	fn exit_root(&mut self, prefix: NibbleSlice, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>);
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
) -> Option<StackedItem<B, T, S>>
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
		callback.enter_terminal(
			item,
			key.as_ref(),
			value.as_ref().map(|v| v.as_ref()),
			TraverseState::MidPartial(target_common_depth),
		)
	} else if key_dest == item.depth {
		// set value
		let n = callback.enter_terminal(
			item,
			key.as_ref(),
			value.as_ref().map(|v| v.as_ref()),
			TraverseState::ValueMatch,
		);
		debug_assert!(n.is_none());
		None
	} else {
		// extend
		callback.enter_terminal(
			item,
			key.as_ref(),
			value.as_ref().map(|v| v.as_ref()),
			TraverseState::AfterNode,
		)
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
	};

	let mut k: Option<K> = None;

	let mut limit_common = usize::max_value();
	for (next_k, v) in elements.into_iter() {
		if let Some(previous_key) = k {
			let mut target_common_depth = nibble_ops::biggest_depth(
				&previous_key.as_ref()[..current.depth / nibble_ops::NIBBLE_PER_BYTE],
				next_k.as_ref(),
			);
			target_common_depth = min(current.depth, target_common_depth);
			target_common_depth = min(limit_common, target_common_depth);
		
			while target_common_depth < current.depth_prefix {
				// go up
				if let Some(mut last) = stack.pop() {
					if !last.node.is_empty() {
						if let Some(handle) = callback.exit(
							NibbleSlice::new_offset(previous_key.as_ref(), current.depth_prefix),
							current.node, current.hash.as_ref(),
						) {
							if last.depth >= current.depth_prefix {
								if let Some(handle) = handle {
									let common = current.depth_prefix - 1;
									let nibble_common = common - last.depth_prefix;
									let parent_index = last.node.partial()
										.map(|p| p.at(nibble_common)).unwrap_or(0);
									let child = last.node
										.set_mid_handle(handle, current.parent_index, nibble_common);
									current = StackedItem {
										node: child,
										hash: None,
										depth: last.depth,
										depth_prefix: common + 1,
										parent_index
									};
									last.depth = common;
									stack.push(last);
									continue;
								}
							} else {
								last.node.set_handle(handle, current.parent_index);
							}
						}
						current = last;
					}
				} else {
					callback.exit_root(NibbleSlice::new(&[]), current.node, current.hash.as_ref());
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
					};
				} else {
					// remove empties
					while current.node.is_empty() && stack.len() > 0 {
						if let Some(prev) = stack.pop() {
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
							}
						}
					} else {
						// terminal case
						if let Some(new) = descend_terminal(&mut current, k, v.as_ref(), dest_depth, callback) {
							stack.push(current);
							current = new;
							limit_common = target_common_depth;
						};
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
				if let Some(handle) = callback.exit(
					NibbleSlice::new_offset(previous_key.as_ref(), current.depth_prefix),
					current.node, current.hash.as_ref(),
				) {
					if last.depth >= current.depth_prefix {
						if let Some(handle) = handle {
							let common = current.depth_prefix - 1;
							let nibble_common = common - last.depth_prefix;
							let parent_index = last.node.partial()
								.map(|p| p.at(nibble_common)).unwrap_or(0);
							let child = last.node
								.set_mid_handle(handle, current.parent_index, nibble_common);
							current = StackedItem {
								node: child,
								hash: None,
								depth: last.depth,
								depth_prefix: common + 1,
								parent_index
							};
							last.depth = common;
							stack.push(last);
							continue;
						}
					} else {
						last.node.set_handle(handle, current.parent_index);
					}
				}
				current = last;
			}
		}
		callback.exit_root(NibbleSlice::new(&[]), current.node, current.hash.as_ref());
		return Ok(());
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
pub struct BatchUpdate<H>(pub Vec<((ElasticArray36<u8>, Option<u8>), H, Option<Vec<u8>>)>, pub H);

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
					});
				} else {
					// nothing to delete.
					return None;
				}
			},
			TraverseState::MidPartial(mid_index) => {
				if let Some(val) = value_element {
					// can differ from mid_index (then need on exit to create an additional child
					// leaf for value)
					let mid_dest = key_element.len() * nibble_ops::NIBBLE_PER_BYTE;
					// here we could create branch but this way we use valid node
					let dest_branch = if mid_dest % nibble_ops::NIBBLE_PER_BYTE == 0 {
						let new_slice = NibbleSlice::new_offset(
							&key_element[..mid_dest / nibble_ops::NIBBLE_PER_BYTE],
							stacked.depth_prefix,
						);
						Node::new_leaf(new_slice, val)
					} else {
						let new_slice = NibbleSlice::new_offset(
							&key_element[..],
							stacked.depth_prefix,
						);
						let owned = new_slice.to_stored_range(mid_dest - stacked.depth_prefix);
						// TODO EMCH refactor new_leaf to take NodeKey (stored) as input
						Node::new_leaf(NibbleSlice::from_stored(&owned), val)
					};
					let old_depth = stacked.depth;
					stacked.depth = mid_dest;
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
					};
					return Some(child);
				} else {
					// nothing to delete.
					return None;
				}
			},
		}
	}

	fn exit(&mut self, prefix: NibbleSlice, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>> {
		match stacked {
			s@StackedNode::Changed(..) => Some(Some({
				let encoded = s.into_encoded();
				if encoded.len() < 32 {
					OwnedNodeHandle::InMemory(encoded)
				} else {
					let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
					// costy clone (could get read from here)
					self.0.push((prefix.left_owned(), hash.clone(), Some(encoded)));
					if let Some(h) = prev_hash {
						self.0.push((prefix.left_owned(), h.clone(), None));
					}
					OwnedNodeHandle::Hash(hash)
				}
			})),
			StackedNode::Deleted(..) => {
				if let Some(h) = prev_hash {
					self.0.push((prefix.left_owned(), h.clone(), None));
				}
				Some(None)
			},
			_ => None,
		}
	}
	
	fn exit_root(&mut self, prefix: NibbleSlice, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>) {
		match stacked {
			s@StackedNode::Deleted(..)
			| s@StackedNode::Changed(..) => {
				let encoded = s.into_encoded();
				let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
				self.1 = hash.clone();
				self.0.push((prefix.left_owned(), hash, Some(encoded)));
				if let Some(h) = prev_hash {
					self.0.push((prefix.left_owned(), h.clone(), None));
				}
			},
			_ => (),
		}
	}
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
	use DBValue;
	use hash_db::{EMPTY_PREFIX, Prefix, HashDB};
	use crate::triedbmut::tests::populate_trie_no_extension;
	use elastic_array::ElasticArray36;

	type H256 = <KeccakHasher as hash_db::Hasher>::Out;

	fn memory_db_from_delta(
		delta: Vec<((ElasticArray36<u8>, Option<u8>), H256, Option<Vec<u8>>)>,
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

		let reference_root = root.clone();
	
		let mut batch_update = BatchUpdate(Default::default(), initial_root.clone());
		trie_traverse_key_no_extension_build(
			&mut initial_db,
			&initial_root,
			v.iter().map(|(a, b)| (a, b.as_ref())),
			&mut batch_update,
		);
		
		//assert_eq!(batch_update.1, reference_root);

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
				(vec![0x01u8, 0x01u8, 0x23], vec![0x01u8, 0x23]),
				(vec![0x01u8, 0x01u8, 0x23, 0x45, 0x67], vec![0xafu8, 0x33]),
				(vec![0x01u8, 0x81u8, 0x23], vec![0x01u8, 0x25]),
				(vec![0x01u8, 0xf1u8, 0x23], vec![0x01u8, 0x24]),
			],
			&[
				(vec![0x01u8, 0x01u8, 0x23, 0x45], Some(vec![0xffu8, 0x33])),
//				(vec![0x01u8, 0x01u8, 0x23], Some(vec![0xffu8, 0x33])),
//				(vec![0x01u8, 0x81u8, 0x23], Some(vec![0x01u8, 0x35])),
//				(vec![0x01u8, 0x81u8, 0x23], None),
//				(vec![0x01u8, 0xf1u8, 0x23], Some(vec![0xffu8, 0x34])),
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
				//(vec![0x00u8], vec![0x00u8, 0]),
				(vec![0x00u8], vec![4u8, 248]),
			],
			&[
				(vec![0xfeu8], Some(vec![248u8, 0])),
				(vec![0xffu8], Some(vec![0u8, 0])),
//				(vec![0x00u8], Some(vec![0x00u8, 0])),
//				(vec![0x04u8], Some(vec![32u8, 26])),
//				(vec![0x20u8], Some(vec![26u8, 0])),
				//(vec![0x04u8], Some(vec![0x01u8, 0x24])),
				//(vec![0x32u8], Some(vec![0x01u8, 0x24])),
			],
		);
	}


}

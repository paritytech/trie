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

impl<B, T, S> StackedNode<B, T, S>
	where
		B: Borrow<[u8]> + AsRef<[u8]>,
		T: TrieLayout,
		S: Clone,
//		TrieHash<T>: AsRef<[u8]>,
{
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
		B: Borrow<[u8]>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
{
	/// Callback on enter a node, change can be applied here.
	fn enter(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>);
	/// Same as `enter` but at terminal node element (terminal considering next key so branch is
	/// possible here).
	fn enter_terminal(
		&mut self,
		prefix: &NibbleVec,
		stacked: &mut StackedNode<B, T, S>,
		index_element: usize,
		key_element: &[u8],
		value_element: Option<&[u8]>,
	) -> Option<(Node<TrieHash<T>, Vec<u8>>, S)>;
	/// Callback on exit a node, commit action on change node should be applied here.
	fn exit(&mut self, prefix: &NibbleVec, stacked: StackedNode<B, T, S>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>>;
	/// Same as `exit` but for root (very last exit call).
	fn exit_root(&mut self, prefix: &NibbleVec, stacked: StackedNode<B, T, S>);
}

/// The main entry point for traversing a trie by a set of keys.
pub fn trie_traverse_key<'a, T, I, K, V, S, B, F>(
	db: &'a mut dyn HashDB<T::Hash, B>,
	root: &'a TrieHash<T>,
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
	let mut stack: Vec<(StackedNode<B, T, S>, usize, u8)> = Vec::with_capacity(32);

	// TODO EMCH do following update (used for error only)
	let mut last_hash = root;
	let root = if let Ok(root) = fetch::<T, B>(db, root, EMPTY_PREFIX) {
		root
	} else {
		return Err(Box::new(TrieError::InvalidStateRoot(*root)));
	};
//	stack.push(StackedNode::Unchanged(root, Default::default()));

	let mut prefix = NibbleVec::new();
	let mut current = StackedNode::<B, T, S>::Unchanged(root, Default::default());
	let mut common_depth = 0;
	callback.enter(&prefix, &mut current);
	current.partial().map(|p| {
		common_depth += p.len();
		prefix.append_partial(p.right())
	});

	let mut switch_iter: bool;
	let mut next_index: u8 = 0;
	for (el_index, (k, v)) in elements.into_iter().enumerate() {
		let mut switch_iter = true;
		loop {
			let mut common_depth = nibble_ops::biggest_depth(prefix.inner(), k.as_ref());
			common_depth = min(prefix.len(), common_depth);

			if common_depth < prefix.len() {
				while common_depth < prefix.len() {
					// go up
					if let Some((mut c, d, ix)) = stack.pop() {
						prefix.drop_lasts(d);
						if let Some(handle) = callback.exit(&prefix, current) {
							c.set_handle(handle, ix);
						}
						current = c;
					} else {
						prefix.clear();
						callback.exit_root(&prefix, current);
						return Ok(());
					}
					//common_depth = nibble_ops::biggest_depth(prefix.inner(), k.as_ref());
					common_depth = min(prefix.len(), common_depth);
				}
				if !switch_iter {
					// going up not on a new key means we need to switch to next one
					break;
				}
			}

			switch_iter = false;
			let dest  = NibbleFullKey::new(k.as_ref());
			let dest_depth = k.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE;

			// TODO EMCH go down extension here
			debug_assert!(common_depth <= dest_depth);
			if common_depth == dest_depth {
				if let Some((new, s)) = callback.enter_terminal(
					&prefix,
					&mut current,
					el_index,
					k.as_ref(),
					v.as_ref().map(|v| v.as_ref()),
				) {
					stack.push((current, common_depth, next_index));
					new.partial().map(|p| {
						common_depth += p.len();
						prefix.append_partial(p.right())
					});
					current = StackedNode::Changed(new, s);
				} else {
					// go next key
					break;
				}
			} else {

				// try go down
				next_index = dest.at(common_depth);
				let next_node = match current.child(next_index) {
					Some(NodeHandle::Hash(handle_hash)) => {
						let mut hash = <TrieHash<T> as Default>::default();
						hash.as_mut()[..].copy_from_slice(handle_hash.as_ref());
						StackedNode::Unchanged(
							fetch::<T, B>(db, &hash, prefix.as_prefix())?,
							Default::default(),
						)
					},
					Some(NodeHandle::Inline(node_encoded)) => {

						StackedNode::Unchanged(
							// Instantiating B is only for inline node, still costy.
							OwnedNode::new::<T::Codec>(B::from(node_encoded))
								.map_err(|e| Box::new(TrieError::DecoderError(*last_hash, e)))?,
							Default::default(),
						)
					},
					None => {
						// this is a terminal node
						if let Some((new, s)) = callback.enter_terminal(
							&prefix,
							&mut current,
							el_index,
							k.as_ref(),
							v.as_ref().map(|v| v.as_ref()),
						) {
							new.partial().map(|p| {
								common_depth += p.len();
								prefix.append_partial(p.right())
							});
							StackedNode::Changed(new, s)
						} else {
							// go next key
							break;
						}
					},
				};

				callback.enter(&prefix, &mut current);
				prefix.push(next_index);
				let add_levels = next_node.partial().map(|p| {
					prefix.append_partial(p.right());
					p.len()
				}).unwrap_or(0) + 1;
				common_depth += add_levels;
				stack.push((current, add_levels, next_index));
				current = next_node;
			}
		}

	}

	// empty stack
	while let Some((mut c, d, ix)) = stack.pop() {
		prefix.drop_lasts(d);
		if let Some(handle) = callback.exit(&prefix, current) {
			c.set_handle(handle, ix);
		}
		current = c;
	}
	prefix.clear();
	callback.exit_root(&prefix, current);

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
pub struct BatchUpdate<H>(pub Vec<(NibbleVec, H, Vec<u8>)>);

impl<B, T, K, V, S> ProcessStack<B, T, K, V, S> for BatchUpdate<TrieHash<T>>
	where
		T: TrieLayout,
		S: Clone,
		B: Borrow<[u8]> + AsRef<[u8]>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
{
	fn enter(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>) {
	}

	fn enter_terminal(
		&mut self,
		prefix: &NibbleVec,
		stacked: &mut StackedNode<B, T, S>,
		index_element: usize,
		key_element: &[u8],
		value_element: Option<&[u8]>,
	) -> Option<(Node<TrieHash<T>, Vec<u8>>, S)> {
		if key_element.len() * nibble_ops::NIBBLE_PER_BYTE == prefix.len() {
			if let Some(value) = value_element {
				stacked.set_value(value);
			} else {
				stacked.remove_value();
			}
			None
		} else {
			Some(unimplemented!())
		}
	}

	fn exit(&mut self, prefix: &NibbleVec, stacked: StackedNode<B, T, S>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>> {
		println!("exit prefix: {:?}", prefix);
		match stacked {
			s@StackedNode::Changed(..) => Some(Some({
				println!("push exit");
				let encoded = s.into_encoded();
				if encoded.len() < 32 {
					OwnedNodeHandle::InMemory(encoded)
				} else {
					let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
					// costy clone (could get read from here)
					self.0.push((prefix.clone(), hash.clone(), encoded));
					OwnedNodeHandle::Hash(hash)
				}
			})),
			StackedNode::Deleted(..) => Some(None),
			_ => None,
		}
	}
	
	fn exit_root(&mut self, prefix: &NibbleVec, stacked: StackedNode<B, T, S>) {
		println!("exit prefix r: {:?}", prefix);
		match stacked {
			s@StackedNode::Changed(..) => {
				let encoded = s.into_encoded();
				let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
				println!("push exit_roto");
				self.0.push((prefix.clone(), hash, encoded));
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

	type H256 = <KeccakHasher as hash_db::Hasher>::Out;

	fn memory_db_from_delta(
		delta: Vec<(NibbleVec, H256, Vec<u8>)>,
		mdb: &mut MemoryDB<KeccakHasher, PrefixedKey<KeccakHasher>, DBValue>,
	) {
		for (p, h, v) in delta {
			// damn elastic array in value looks costy
			mdb.emplace(h, p.as_prefix(), v[..].into());
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
		{
			let t = RefTrieDBNoExt::new(&db, &root);
			println!("aft {:?}", t);
		}

		let mut reference_delta = db;

		let reference_root = root.clone();
	
		let mut batch_update = BatchUpdate(Default::default());
		trie_traverse_key_no_extension_build(
		&mut initial_db, &initial_root, v.iter().map(|(a, b)| (a, b.as_ref())), &mut batch_update);
		
		let mut batch_delta = initial_db;
		memory_db_from_delta(batch_update.0, &mut batch_delta);

		// sort
		let batch_delta: std::collections::BTreeMap<_, _> = batch_delta.drain().into_iter().collect();
		assert_eq!(
			batch_delta,
			reference_delta.drain().into_iter().filter(|(_, (_, rc))| rc >= &0).collect(),
		);

		panic!("end");

	}

	#[test]
	fn dummy1() {
		compare_with_triedbmut(
			&[
				(vec![0x01u8, 0x01u8, 0x23], vec![0x01u8, 0x23]),
				(vec![0x01u8, 0x81u8, 0x23], vec![0x01u8, 0x25]),
				(vec![0x01u8, 0xf1u8, 0x23], vec![0x01u8, 0x24]),
			],
			&[
				(vec![0x01u8, 0x01u8, 0x23], Some(vec![0xffu8, 0x33])),
//				(vec![0x01u8, 0x81u8, 0x23], Some(vec![0x01u8, 0x35])),
//				(vec![0x01u8, 0x81u8, 0x23], None),
//				(vec![0x01u8, 0xf1u8, 0x23], Some(vec![0xffu8, 0x34])),
			],
		);
	}
}

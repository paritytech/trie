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
	fn enter(&mut self, prefix: NibbleSlice, stacked: &mut StackedNode<B, T, S>);
	/// Same as `enter` but at terminal node element (terminal considering next key so branch is
	/// possible here).
	/// TODO prefix semantic here is strange: it is prefix of child.
	fn enter_terminal(
		&mut self,
		prefix: NibbleSlice,
		stacked: &mut StackedNode<B, T, S>,
		index_element: usize,
		key_element: &[u8],
		value_element: Option<&[u8]>,
	) -> Option<(Node<TrieHash<T>, Vec<u8>>, S)>;
	/// Callback on exit a node, commit action on change node should be applied here.
	fn exit(&mut self, prefix: NibbleSlice, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>)
		-> Option<Option<OwnedNodeHandle<TrieHash<T>>>>;
	/// Same as `exit` but for root (very last exit call).
	fn exit_root(&mut self, prefix: NibbleSlice, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>);
}

struct StackItem<B: Borrow<[u8]>, T: TrieLayout, S> {
	node: StackedNode<B, T, S>,
	// depth of stack aka prefix size
	depth: usize,
	// depth after item
	depth_child: usize,
	parent_index: u8,
	hash: Option<TrieHash<T>>,
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
	let mut stack: Vec<StackItem<B, T, S>> = Vec::with_capacity(32);

	// TODO EMCH do following update (used for error only)
	let mut last_hash: Option<TrieHash<T>> = Some(*root_hash);
	let root = if let Ok(root) = fetch::<T, B>(db, root_hash, EMPTY_PREFIX) {
		root
	} else {
		return Err(Box::new(TrieError::InvalidStateRoot(*root_hash)));
	};
	let root_hash = Some(root_hash);
//	stack.push(StackedNode::Unchanged(root, Default::default()));

	let mut current = StackedNode::<B, T, S>::Unchanged(root, Default::default());
	let mut common_depth = 0;
	let mut common_depth_child = current.partial().map(|p| {
		p.len() + 1
	}).unwrap_or(1);

	let mut k: Option<K> = None;
	callback.enter(NibbleSlice::new(&[]), &mut current);

	let mut next_index: u8 = 0;
	for (el_index, (next_k, v)) in elements.into_iter().enumerate() {
		if let Some(k) = k.as_ref() {

			let mut previous_common_depth_child = common_depth_child - 1;
			let mut target_common_depth =
				nibble_ops::biggest_depth(&k.as_ref()[..previous_common_depth_child / 2], next_k.as_ref());
			target_common_depth = min(common_depth, target_common_depth);
	
			if target_common_depth < previous_common_depth_child {
				while target_common_depth < previous_common_depth_child {
					// go up
					if let Some(StackItem{mut node, depth, depth_child, parent_index, hash}) = stack.pop() {
						common_depth = depth;
						common_depth_child = depth_child;
						previous_common_depth_child = depth_child - 1;
						if let Some(handle) = callback.exit(
							NibbleSlice::new_offset(k.as_ref(), depth_child),
							current, hash.as_ref(),
						) {
							node.set_handle(handle, parent_index);
						}
						current = node;
					} else {
						callback.exit_root(NibbleSlice::new(&[]), current, root_hash);
						return Ok(());
					}
				}
			}
			
		}
		
		k = Some(next_k);
		if let Some(k) = k.as_ref() {
		let dest = NibbleFullKey::new(k.as_ref());
		let dest_depth = k.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE;

		loop {
			// TODO EMCH go down extension here
			debug_assert!(common_depth <= dest_depth);
			if common_depth_child - 1 == dest_depth {
				if let Some((new, s)) = callback.enter_terminal(
					NibbleSlice::new_offset(k.as_ref(), common_depth_child - 1),
					&mut current,
					el_index,
					k.as_ref(),
					v.as_ref().map(|v| v.as_ref()),
				) {
					stack.push(StackItem {
						node: current,
						depth: common_depth,
						depth_child: common_depth_child,
						parent_index: next_index,
						hash: last_hash,
					});
					common_depth = common_depth_child;
					new.partial().map(|p| {
						common_depth_child += p.len() + 1;
					});
					current = StackedNode::Changed(new, s);
				} else {
					// go next key
					break;
				}
			} else {
				// try go down
				next_index = dest.at(common_depth_child - 1);
				let next_node = match current.child(next_index) {
					Some(NodeHandle::Hash(handle_hash)) => {
						let mut hash = <TrieHash<T> as Default>::default();
						hash.as_mut()[..].copy_from_slice(handle_hash.as_ref());
						let n = StackedNode::Unchanged(
							fetch::<T, B>(
								db, &hash,
								NibbleSlice::new_offset(k.as_ref(), common_depth_child).left(),
							)?,
							Default::default(),
						);
						last_hash = Some(hash);
						n
					},
					Some(NodeHandle::Inline(node_encoded)) => {
						last_hash = None; 
						StackedNode::Unchanged(
							// Instantiating B is only for inline node, still costy.
							OwnedNode::new::<T::Codec>(B::from(node_encoded))
								.map_err(|e| Box::new(TrieError::DecoderError(
									last_hash.clone().unwrap_or_else(Default::default),
									e,
								)))?,
							Default::default(),
						)
					},
					None => {
						// this is a terminal node
						if let Some((new, s)) = callback.enter_terminal(
							NibbleSlice::new_offset(k.as_ref(), common_depth_child - 1),
							&mut current,
							el_index,
							k.as_ref(),
							v.as_ref().map(|v| v.as_ref()),
						) {
							StackedNode::Changed(new, s)
						} else {
							// go next key
							break;
						}
					},
				};

				callback.enter(
					NibbleSlice::new_offset(k.as_ref(), common_depth_child - 1),
					&mut current,
				);

				let add_levels = next_node.partial().map(|p| {
					p.len() + 1
				}).unwrap_or(1);
				stack.push(StackItem {
					node: current,
					depth: common_depth,
					depth_child: common_depth_child,
					parent_index: next_index,
					hash: last_hash,
				});
				common_depth = common_depth_child;
				common_depth_child += add_levels;
				current = next_node;
			}
		}}

	}

	// empty stack
	while let Some(StackItem{mut node, depth, depth_child, parent_index, hash}) = stack.pop() {
		if let Some(k) = k.as_ref() {
		if let Some(handle) = callback.exit(
			NibbleSlice::new_offset(k.as_ref(), depth_child),
			current, hash.as_ref(),
		) {
			node.set_handle(handle, parent_index);
		}
		current = node;
	}}
	callback.exit_root(NibbleSlice::new(&[]), current, root_hash);

	Ok(())
}

/// Fetch a node by hash, do not cache it.
fn fetch<T: TrieLayout, B: Borrow<[u8]>>(
	db: &mut dyn HashDB<T::Hash, B>,
	hash: &TrieHash<T>,
	key: Prefix,
) -> Result<OwnedNode<B>, TrieHash<T>, CError<T>> {
	println!("a {:?}", key);
	let node_encoded = db.get(hash, key)
		.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(*hash)))?;

	println!("b");
	Ok(
		OwnedNode::new::<T::Codec>(node_encoded)
			.map_err(|e| Box::new(TrieError::DecoderError(*hash, e)))?
	)
}

/// Contains ordered node change for this iteration.
pub struct BatchUpdate<H>(pub Vec<((ElasticArray36<u8>, Option<u8>), H, Option<Vec<u8>>)>);

impl<B, T, K, V, S> ProcessStack<B, T, K, V, S> for BatchUpdate<TrieHash<T>>
	where
		T: TrieLayout,
		S: Clone,
		B: Borrow<[u8]> + AsRef<[u8]>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]>,
{
	fn enter(&mut self, prefix: NibbleSlice, stacked: &mut StackedNode<B, T, S>) {
	}

	fn enter_terminal(
		&mut self,
		prefix: NibbleSlice, 
		stacked: &mut StackedNode<B, T, S>,
		index_element: usize,
		key_element: &[u8],
		value_element: Option<&[u8]>,
	) -> Option<(Node<TrieHash<T>, Vec<u8>>, S)> {
		if key_element.len() * nibble_ops::NIBBLE_PER_BYTE == prefix.left_len() {
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

	fn exit(&mut self, prefix: NibbleSlice, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>)
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
					println!("push one");
					// costy clone (could get read from here)
					self.0.push((prefix.left_owned(), hash.clone(), Some(encoded)));
					if let Some(h) = prev_hash {
						println!("rem one");
						self.0.push((prefix.left_owned(), h.clone(), None));
					}
					OwnedNodeHandle::Hash(hash)
				}
			})),
			StackedNode::Deleted(..) => {
				if let Some(h) = prev_hash {
						println!("remd one");
					self.0.push((prefix.left_owned(), h.clone(), None));
				}
				Some(None)
			},
			_ => None,
		}
	}
	
	fn exit_root(&mut self, prefix: NibbleSlice, stacked: StackedNode<B, T, S>, prev_hash: Option<&TrieHash<T>>) {
		println!("exit prefix r: {:?}", prefix);
		match stacked {
			s@StackedNode::Changed(..) => {
				let encoded = s.into_encoded();
				let hash = <T::Hash as hash_db::Hasher>::hash(&encoded[..]);
					println!("pushr one");
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
	
		let mut batch_update = BatchUpdate(Default::default());
		trie_traverse_key_no_extension_build(
		&mut initial_db, &initial_root, v.iter().map(|(a, b)| (a, b.as_ref())), &mut batch_update);
		
		let mut batch_delta = initial_db;
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

		// test by checking both triedb only
		let t1 = RefTrieDBNoExt::new(&batch_delta, &root).unwrap();
		let t2 = RefTrieDBNoExt::new(&db, &root).unwrap();
		assert_eq!(format!("{:?}", t1), format!("{:?}", t2));


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
				(vec![0x01u8, 0x81u8, 0x23], Some(vec![0x01u8, 0x35])),
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
//				(vec![0x01u8, 0xf1u8, 0x23], vec![0x01u8, 0x24]),
			],
			&[
				(vec![0x01u8, 0x01u8, 0x23], Some(vec![0xffu8; 32])),
				(vec![0x01u8, 0x81u8, 0x23], Some(vec![0xfeu8; 32])),
//				(vec![0x01u8, 0x81u8, 0x23], None),
//				(vec![0x01u8, 0xf1u8, 0x23], Some(vec![0xffu8, 0x34])),
			],
		);
	}

}

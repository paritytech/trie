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

/// StackedNode can be updated.
/// A state can be use.
pub(crate) enum StackedNode<B, T, S>
	where
		B: Borrow<[u8]>,
		T: TrieLayout,
{
	/// Read node.
	Unchanged(OwnedNode<B>, S),
	/// Modified node.
	Changed(Node<T::Hash, B>, S),
}

impl<B, T, S> StackedNode<B, T, S>
	where
		B: Borrow<[u8]> + AsRef<[u8]>,
		T: TrieLayout,
{
	/// Get extension part of the node (partial) if any.
	pub fn partial(&self) -> Option<NibbleSlice> {
		match self {
			StackedNode::Unchanged(node, ..) => node.partial(),
			StackedNode::Changed(node, ..) => node.partial(),
		}
	}

	/// Try to access child.
	pub fn child(&self, ix: u8) -> Option<NodeHandle> {
		match self {
			StackedNode::Unchanged(node, ..) => node.child(ix),
			StackedNode::Changed(node, ..) => node.child(ix),
		}
	}
}

impl<B, T, S> StackedNode<B, T, S>
	where
		B: AsRef<[u8]> + AsMut<[u8]> + Default + crate::MaybeDebug
		+ PartialEq + Eq + ::core_::hash::Hash + Send + Sync + Clone + Copy + Borrow<[u8]>,
		T: TrieLayout,
{

	/// Encode node
	/// TODO EMCH can optimize unchange to their backed data by consuming.
	pub fn into_encoded(&self) -> Vec<u8> {
		match self {
			StackedNode::Unchanged(node, ..) => node.data().to_vec(),
			StackedNode::Changed(node, ..) => node.into_encoded::<_, T::Codec, T::Hash>(
				|child, o_slice, o_index| {
					child.as_ref().data().to_vec()
				}),
		}
	}

}

/// Visitor trait to implement when using `trie_traverse_key`.
pub(crate) trait ProcessStack<B, T, K, V, S>
	where
		T: TrieLayout,
		B: Borrow<[u8]>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]> + Into<DBValue>,
{
	/// Callback on enter a node, change can be applied here.
	fn enter(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>);
	/// Same as `enter` but at terminal node element (terminal considering next key so branch is
	/// possible here).
	fn enter_terminal(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>)
		-> Option<(Node<T::Hash, B>, S)>;
	/// Callback on exit a node, commit action on change node should be applied here.
	fn exit(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>);
	/// Same as `exit` but for root (very last exit call).
	fn exit_root(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>);
}

/// The main entry point for traversing a trie by a set of keys.
pub(crate) fn trie_traverse_key<'a, T, I, K, V, S, B, F>(
	db: &'a mut dyn HashDB<T::Hash, B>,
	root: &'a TrieHash<T>,
	elements: I,
	callback: &mut F,
) -> Result<(), TrieHash<T>, CError<T>>
	where
		T: TrieLayout,
		I: IntoIterator<Item = (K, Option<V>)>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]> + Into<DBValue>,
		S: Default,
		B: Borrow<[u8]> + AsRef<[u8]> + for<'b> From<&'b [u8]>,
		F: ProcessStack<B, T, K, V, S>,
{
	// stack of traversed nodes
	let mut stack: Vec<(StackedNode<B, T, S>, usize)> = Vec::with_capacity(32);

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
	current.partial().map(|p| {
		common_depth += p.len();
		prefix.append_partial(p.right())
	});

	for (k, v) in elements {
		let dest  = NibbleFullKey::new(k.as_ref());
		let dest_depth = k.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE;
		loop {
			// TODO EMCH go down extension here
			if common_depth >= dest_depth {
				if let Some((new, s)) = callback.enter_terminal(&prefix, &mut current) {
					stack.push((current, common_depth));
					new.partial().map(|p| {
						common_depth += p.len();
						prefix.append_partial(p.right())
					});
					current = StackedNode::Changed(new, s);
				};
				// go next key
				break;
			} else {

				// try go down
				let next_index = dest.at(common_depth + 1);
				let next_node = match current.child(next_index) {
					Some(NodeHandle::Hash(handle_hash)) => {
						let mut hash = <TrieHash<T> as Default>::default();
						hash.as_mut()[..].copy_from_slice(handle_hash.as_ref());
						fetch::<T, B>(db, &hash, prefix.as_prefix())?
					},
					Some(NodeHandle::Inline(node_encoded)) => {
						// Instantiating B is only for inline node, still costy.
						OwnedNode::new::<T::Codec>(B::from(node_encoded))
								.map_err(|e| Box::new(TrieError::DecoderError(*last_hash, e)))?
					},
					None => {
						// advance key by breaking loop
						break;
					},
				};

				callback.enter(&prefix, &mut current);
				stack.push((current, common_depth));
				current = StackedNode::Unchanged(next_node, Default::default());
				current.partial().map(|p| {
					common_depth += p.len();
					prefix.append_partial(p.right())
				});
			}
		}
		let mut common_depth = nibble_ops::biggest_depth(prefix.inner(), k.as_ref());
		common_depth = min(prefix.len(), common_depth);
		while common_depth < prefix.len() {
			// go up
			if let Some((c, d)) = stack.pop() {
				callback.exit(&prefix, &mut current);
				current = c;
				prefix.drop_lasts(prefix.len() - d);
			} else {
				callback.exit_root(&prefix, &mut current);
				return Ok(());
			}
			common_depth = nibble_ops::biggest_depth(prefix.inner(), k.as_ref());
			common_depth = min(prefix.len(), common_depth);
		}

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
pub struct BatchUpdate(pub Vec<Vec<u8>>);

impl<B, T, K, V, S> ProcessStack<B, T, K, V, S> for BatchUpdate
	where
		T: TrieLayout,
		B: Borrow<[u8]>,
		K: AsRef<[u8]> + Ord,
		V: AsRef<[u8]> + Into<DBValue>,
{
	fn enter(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>) {
	}

	fn enter_terminal(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>)
		-> Option<(Node<T::Hash, B>, S)> {
			None
	}

	fn exit(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>) {
		self.0.push(stacked.into_encoded());
	}
	
	fn exit_root(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode<B, T, S>) {
		self.0.push(stacked.into_encoded());
	}
}

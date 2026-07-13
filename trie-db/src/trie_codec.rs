// Copyright 2019, 2021 Parity Technologies
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

//! Compact encoding/decoding functions for partial Merkle-Patricia tries.
//!
//! A partial trie is a subset of the nodes in a complete trie, which can still be used to
//! perform authenticated lookups on a subset of keys. A naive encoding is the set of encoded nodes
//! in the partial trie. This, however, includes redundant hashes of other nodes in the partial
//! trie which could be computed directly. The compact encoding strips out all hash child
//! references to other nodes in the partial trie and replaces them with empty inline references,
//! indicating that the child reference is omitted. The nodes are then ordered in pre-order
//! traversal order so that the full nodes can be efficiently reconstructed recursively. Note that
//! hash references to nodes not in the partial trie are left intact. The compact encoding can be
//! expected to save roughly (n - 1) hashes in size where n is the number of nodes in the partial
//! trie.
//!
//! A value node contained in the partial trie (see `TrieLayout::MAX_INLINE_VALUE`) is
//! "detached": the referencing node is emitted with an escape header (see
//! `NodeCodec::ESCAPE_HEADER`) and an empty inline value, directly followed by the value bytes
//! as a standalone item. A node whose value node is *not* part of the partial trie is emitted
//! unmodified, still referencing its value by hash.
//!
//! `encode_compact` re-emits an item shared by multiple positions once per position: a detached
//! value node once per referencing node, a duplicated subtree once per occurrence.
//! [`encode_compact_skip_duplicates`] emits each distinct item only once — later referencing
//! nodes keep a plain hash reference, exactly like references to items outside the partial trie —
//! see there for the requirements this puts on decoding.

use crate::{
	nibble_ops::NIBBLE_LENGTH,
	node::{Node, NodeHandle, NodeHandlePlan, NodePlan, OwnedNode, Value, ValuePlan},
	rstd::{
		boxed::Box, convert::TryInto, marker::PhantomData, result, sync::Arc, vec, vec::Vec,
		BTreeMap, BTreeSet,
	},
	CError, ChildReference, DBValue, NibbleVec, NodeCodec, Result, TrieDB, TrieDBRawIterator,
	TrieError, TrieHash, TrieLayout,
};
use hash_db::{HashDB, Hasher, Prefix};

const OMIT_VALUE_HASH: crate::node::Value<'static> = crate::node::Value::Inline(&[]);

struct EncoderStackEntry<C: NodeCodec> {
	/// The prefix is the nibble path to the node in the trie.
	prefix: NibbleVec,
	/// Node in memory content.
	node: Arc<OwnedNode<DBValue>>,
	/// The next entry in the stack is a child of the preceding entry at this index. For branch
	/// nodes, the index is in [0, NIBBLE_LENGTH] and for extension nodes, the index is in [0, 1].
	child_index: usize,
	/// Flags indicating whether each child is omitted in the encoded node.
	omit_children: Vec<bool>,
	/// Skip value if value node is after.
	omit_value: bool,
	/// The encoding of the subtrie nodes rooted at this entry, which is built up in
	/// `encode_compact`.
	output_index: usize,
	_marker: PhantomData<C>,
}

impl<C: NodeCodec> EncoderStackEntry<C> {
	/// Given the prefix of the next child node, identify its index and advance `child_index` to
	/// that. For a given entry, this must be called sequentially only with strictly increasing
	/// child prefixes. Returns an error if the child prefix is not a child of this entry or if
	/// called with children out of order.
	///
	/// Preconditions:
	/// - self.prefix + partial must be a prefix of child_prefix.
	/// - if self.node is a branch, then child_prefix must be longer than self.prefix + partial.
	fn advance_child_index(
		&mut self,
		child_prefix: &NibbleVec,
	) -> result::Result<(), &'static str> {
		match self.node.node_plan() {
			NodePlan::Empty | NodePlan::Leaf { .. } =>
				return Err("empty and leaf nodes have no children"),
			NodePlan::Extension { .. } =>
				if self.child_index != 0 {
					return Err("extension node cannot have multiple children")
				},
			NodePlan::Branch { .. } => {
				if child_prefix.len() <= self.prefix.len() {
					return Err("child_prefix does not contain prefix")
				}
				let child_index = child_prefix.at(self.prefix.len()) as usize;
				if child_index < self.child_index {
					return Err("iterator returned children in non-ascending order by prefix")
				}
				self.child_index = child_index;
			},
			NodePlan::NibbledBranch { partial, .. } => {
				if child_prefix.len() <= self.prefix.len() + partial.len() {
					return Err("child_prefix does not contain prefix and node partial")
				}
				let child_index = child_prefix.at(self.prefix.len() + partial.len()) as usize;
				if child_index < self.child_index {
					return Err("iterator returned children in non-ascending order by prefix")
				}
				self.child_index = child_index;
			},
		}
		Ok(())
	}

	/// Generates the encoding of the subtrie rooted at this entry.
	fn encode_node(&mut self) -> Result<Vec<u8>, C::HashOut, C::Error> {
		let node_data = self.node.data();
		let node_plan = self.node.node_plan();
		let mut encoded = match node_plan {
			NodePlan::Empty => node_data.to_vec(),
			NodePlan::Leaf { partial, value: _ } =>
				if self.omit_value {
					let partial = partial.build(node_data);
					C::leaf_node(partial.right_iter(), partial.len(), OMIT_VALUE_HASH)
				} else {
					node_data.to_vec()
				},
			NodePlan::Extension { partial, child: _ } =>
				if !self.omit_children[0] {
					node_data.to_vec()
				} else {
					let partial = partial.build(node_data);
					let empty_child = ChildReference::Inline(C::HashOut::default(), 0);
					C::extension_node(partial.right_iter(), partial.len(), empty_child)
				},
			NodePlan::Branch { value, children } => {
				let value = if self.omit_value {
					value.is_some().then_some(OMIT_VALUE_HASH)
				} else {
					value.as_ref().map(|v| v.build(node_data))
				};
				C::branch_node(
					Self::branch_children(node_data, &children, &self.omit_children)?.iter(),
					value,
				)
			},
			NodePlan::NibbledBranch { partial, value, children } => {
				let partial = partial.build(node_data);
				let value = if self.omit_value {
					value.is_some().then_some(OMIT_VALUE_HASH)
				} else {
					value.as_ref().map(|v| v.build(node_data))
				};
				C::branch_node_nibbled(
					partial.right_iter(),
					partial.len(),
					Self::branch_children(node_data, &children, &self.omit_children)?.iter(),
					value,
				)
			},
		};

		if self.omit_value {
			if let Some(header) = C::ESCAPE_HEADER {
				encoded.insert(0, header);
			} else {
				return Err(Box::new(TrieError::InvalidStateRoot(Default::default())))
			}
		}
		Ok(encoded)
	}

	/// Generate the list of child references for a branch node with certain children omitted.
	///
	/// Preconditions:
	/// - omit_children has size NIBBLE_LENGTH.
	/// - omit_children[i] is only true if child_handles[i] is Some
	fn branch_children(
		node_data: &[u8],
		child_handles: &[Option<NodeHandlePlan>; NIBBLE_LENGTH],
		omit_children: &[bool],
	) -> Result<[Option<ChildReference<C::HashOut>>; NIBBLE_LENGTH], C::HashOut, C::Error> {
		let empty_child = ChildReference::Inline(C::HashOut::default(), 0);
		let mut children = [None; NIBBLE_LENGTH];
		for i in 0..NIBBLE_LENGTH {
			children[i] = if omit_children[i] {
				Some(empty_child)
			} else if let Some(child_plan) = &child_handles[i] {
				let child_ref = child_plan.build(node_data).try_into().map_err(|hash| {
					Box::new(TrieError::InvalidHash(C::HashOut::default(), hash))
				})?;
				Some(child_ref)
			} else {
				None
			};
		}
		Ok(children)
	}
}

/// Detached value if included does write a reserved header,
/// followed by node encoded with 0 length value and the value
/// as a standalone vec.
///
/// When `seen_hashes` is given, a value whose hash is already in the set is not detached again.
/// Only hashes of actually emitted values are added to the set.
fn detached_value<L: TrieLayout>(
	db: &TrieDB<L>,
	value: &ValuePlan,
	node_data: &[u8],
	node_prefix: Prefix,
	seen_hashes: Option<&mut BTreeSet<Vec<u8>>>,
) -> Option<Vec<u8>> {
	let hash_plan = match value {
		ValuePlan::Node(hash_plan) => hash_plan,
		_ => return None,
	};
	let value_hash = &node_data[hash_plan.clone()];
	if let Some(seen_hashes) = &seen_hashes {
		if seen_hashes.contains(value_hash) {
			return None
		}
	}
	let fetched = match TrieDBRawIterator::fetch_value(db, value_hash, node_prefix) {
		Ok(value) => value,
		Err(_) => return None,
	};
	if let Some(seen_hashes) = seen_hashes {
		seen_hashes.insert(value_hash.to_vec());
	}
	Some(fetched)
}

/// Generates a compact representation of the partial trie stored in the given DB. The encoding
/// is a vector of mutated trie nodes with those child references omitted. The mutated trie nodes
/// are listed in pre-order traversal order so that the full nodes can be efficiently
/// reconstructed recursively.
///
/// A shared detached value node is emitted once per referencing node and a duplicated subtree
/// once per occurrence (see [`encode_compact_skip_duplicates`]).
///
/// This function makes the assumption that all child references in an inline trie node are inline
/// references.
pub fn encode_compact<L>(db: &TrieDB<L>) -> Result<Vec<Vec<u8>>, TrieHash<L>, CError<L>>
where
	L: TrieLayout,
{
	encode_compact_inner(db, None)
}

/// Variant of [`encode_compact`] that emits each distinct item — trie node or detached value
/// node — only once. Later occurrences keep a plain hash reference to the already emitted item:
/// a node referencing an emitted value node stays unmodified, a node whose child subtree was
/// already emitted keeps the child hash reference, exactly like references to items that are not
/// part of the partial trie at all. Since only nodes at least as large as a hash can be
/// referenced by hash, a skipped duplicate never increases the encoding size.
///
/// `seen_hashes` collects the hashes of all emitted items. Pass `&mut Default::default()` for a
/// standalone encoding, or thread one set through successive calls to deduplicate across
/// concatenated encodings (decoding must then thread its known-items map the same way). The
/// first item of each encoding (the root node) is always emitted, even if its hash is already in
/// `seen_hashes`, so every encoding remains individually decodable.
///
/// Any decoder reconstructs a readable hash-keyed (prefix-ignoring) database from the result.
/// Reconstructing the exact database of an unmodified encoding — every duplicated position
/// populated in a position-keyed (prefixed) database, reference counts matching the number of
/// referencing positions — requires a decoder that re-inserts deduplicated items, i.e.
/// [`decode_compact_from_iter_with_known_items`] or the decode functions delegating to it.
///
/// Skipping a subtree assumes its occurrences are interchangeable, which holds when `db` reads
/// the partial trie from a hash-keyed database. Encoding from a position-keyed database in which
/// a duplicated subtree is populated only below a later occurrence would drop the nodes resolving
/// only there.
pub fn encode_compact_skip_duplicates<L>(
	db: &TrieDB<L>,
	seen_hashes: &mut BTreeSet<Vec<u8>>,
) -> Result<Vec<Vec<u8>>, TrieHash<L>, CError<L>>
where
	L: TrieLayout,
{
	encode_compact_inner(db, Some(seen_hashes))
}

fn encode_compact_inner<L>(
	db: &TrieDB<L>,
	mut seen_hashes: Option<&mut BTreeSet<Vec<u8>>>,
) -> Result<Vec<Vec<u8>>, TrieHash<L>, CError<L>>
where
	L: TrieLayout,
{
	let mut output = Vec::new();

	// The stack of nodes through a path in the trie. Each entry is a child node of the preceding
	// entry.
	let mut stack: Vec<EncoderStackEntry<L::Codec>> = Vec::new();

	// TrieDBRawIterator guarantees that:
	// - It yields at least one node.
	// - The first node yielded is the root node with an empty prefix and is not inline.
	// - The prefixes yielded are in strictly increasing lexographic order.
	let mut iter = TrieDBRawIterator::new(db)?;

	// Following from the guarantees about TrieDBRawIterator, we guarantee that after the first
	// iteration of the loop below, the stack always has at least one entry and the bottom (front)
	// of the stack is the root node, which is not inline. Furthermore, the iterator is not empty,
	// so at least one iteration always occurs.
	while let Some(item) = iter.next_raw_item(db, true) {
		match item {
			Ok((prefix, node_hash, node)) => {
				// Skip inline nodes, as they cannot contain hash references to other nodes by
				// assumption.
				let node_hash = match node_hash {
					Some(node_hash) => node_hash,
					None => continue,
				};

				if let Some(seen_hashes) = seen_hashes.as_deref_mut() {
					// A subtree whose root node was already emitted is skipped entirely; the
					// parent's `omit_children` bit stays unset, keeping the plain hash reference.
					// The root of the encoding is never skipped (`seen_hashes` may be threaded
					// through successive encodings), so that every encoding starts with its root
					// and remains individually decodable.
					if !stack.is_empty() && seen_hashes.contains(node_hash.as_ref()) {
						iter.skip_current_subtree();
						continue
					}
					seen_hashes.insert(node_hash.as_ref().to_vec());
				}

				// Unwind the stack until the new entry is a child of the last entry on the stack.
				// If the stack entry prefix is a prefix of the new entry prefix, then it must be a
				// direct parent as the nodes are yielded from the iterator in pre-order traversal
				// order.
				while let Some(mut last_entry) = stack.pop() {
					if prefix.starts_with(&last_entry.prefix) {
						// advance_child_index preconditions are satisfied because of iterator
						// correctness.
						last_entry.advance_child_index(&prefix).expect(
							"all errors from advance_child_index indicate bugs with \
								TrieDBRawIterator or this function",
						);
						last_entry.omit_children[last_entry.child_index] = true;
						last_entry.child_index += 1;
						stack.push(last_entry);
						break
					} else {
						output[last_entry.output_index] = last_entry.encode_node()?;
					}
				}

				let (children_len, detached_value) = match node.node_plan() {
					NodePlan::Empty => (0, None),
					NodePlan::Leaf { value, .. } => (
						0,
						detached_value(
							db,
							value,
							node.data(),
							prefix.as_prefix(),
							seen_hashes.as_deref_mut(),
						),
					),
					NodePlan::Extension { .. } => (1, None),
					NodePlan::NibbledBranch { value: Some(value), .. } |
					NodePlan::Branch { value: Some(value), .. } => (
						NIBBLE_LENGTH,
						detached_value(
							db,
							value,
							node.data(),
							prefix.as_prefix(),
							seen_hashes.as_deref_mut(),
						),
					),
					NodePlan::NibbledBranch { value: None, .. } |
					NodePlan::Branch { value: None, .. } => (NIBBLE_LENGTH, None),
				};

				stack.push(EncoderStackEntry {
					prefix: prefix.clone(),
					node: node.clone(),
					child_index: 0,
					omit_children: vec![false; children_len],
					omit_value: detached_value.is_some(),
					output_index: output.len(),
					_marker: PhantomData::default(),
				});
				// Insert a placeholder into output which will be replaced when this new entry is
				// popped from the stack.
				output.push(Vec::new());
				if let Some(value) = detached_value {
					output.push(value);
				}
			},
			Err(err) => match *err {
				// If we hit an IncompleteDatabaseError, just ignore it and continue encoding the
				// incomplete trie. This encoding must support partial tries, which can be used for
				// space-efficient storage proofs.
				TrieError::IncompleteDatabase(_) => {},
				_ => return Err(err),
			},
		}
	}

	while let Some(mut entry) = stack.pop() {
		output[entry.output_index] = entry.encode_node()?;
	}

	Ok(output)
}

struct DecoderStackEntry<'a, C: NodeCodec> {
	node: Node<'a>,
	/// The next entry in the stack is a child of the preceding entry at this index. For branch
	/// nodes, the index is in [0, NIBBLE_LENGTH] and for extension nodes, the index is in [0, 1].
	child_index: usize,
	/// The reconstructed child references.
	children: Vec<Option<ChildReference<C::HashOut>>>,
	/// Bit mask of children that the encoded node kept as plain hash references (as opposed to
	/// omitted children reconstructed from subsequent items). These may reference subtrees
	/// deduplicated into an earlier occurrence, see [`encode_compact_skip_duplicates`].
	hash_ref_children: u16,
	/// A value attached as a node. The node will need to use its hash as value.
	attached_value: Option<&'a [u8]>,
	_marker: PhantomData<C>,
}

impl<'a, C: NodeCodec> DecoderStackEntry<'a, C> {
	/// Advance the child index until either it exceeds the number of children or the child is
	/// marked as omitted. Omitted children are indicated by an empty inline reference. For each
	/// child that is passed over and not omitted, copy over the child reference from the node to
	/// this entries `children` list.
	///
	/// Returns true if the child index is past the last child, meaning the `children` references
	/// list is complete. If this returns true and the entry is an extension node, then
	/// `children[0]` is guaranteed to be Some.
	fn advance_child_index(&mut self) -> Result<bool, C::HashOut, C::Error> {
		match self.node {
			Node::Extension(_, child) if self.child_index == 0 => {
				match child {
					NodeHandle::Inline(data) if data.is_empty() => return Ok(false),
					_ => {
						let child_ref = child.try_into().map_err(|hash| {
							Box::new(TrieError::InvalidHash(C::HashOut::default(), hash))
						})?;
						if let ChildReference::Hash(_) = child_ref {
							self.hash_ref_children |= 1u16 << self.child_index;
						}
						self.children[self.child_index] = Some(child_ref);
					},
				}
				self.child_index += 1;
			},
			Node::Branch(children, _) | Node::NibbledBranch(_, children, _) => {
				while self.child_index < NIBBLE_LENGTH {
					match children[self.child_index] {
						Some(NodeHandle::Inline(data)) if data.is_empty() => return Ok(false),
						Some(child) => {
							let child_ref = child.try_into().map_err(|hash| {
								Box::new(TrieError::InvalidHash(C::HashOut::default(), hash))
							})?;
							if let ChildReference::Hash(_) = child_ref {
								self.hash_ref_children |= 1u16 << self.child_index;
							}
							self.children[self.child_index] = Some(child_ref);
						},
						None => {},
					}
					self.child_index += 1;
				}
			},
			_ => {},
		}
		Ok(true)
	}

	/// Push the partial key of this entry's node (including the branch nibble) to the given
	/// prefix.
	fn push_to_prefix(&self, prefix: &mut NibbleVec) {
		match self.node {
			Node::Empty => {},
			Node::Leaf(partial, _) | Node::Extension(partial, _) => {
				prefix.append_partial(partial.right());
			},
			Node::Branch(_, _) => {
				prefix.push(self.child_index as u8);
			},
			Node::NibbledBranch(partial, _, _) => {
				prefix.append_partial(partial.right());
				prefix.push(self.child_index as u8);
			},
		}
	}

	/// Pop the partial key of this entry's node (including the branch nibble) from the given
	/// prefix.
	fn pop_from_prefix(&self, prefix: &mut NibbleVec) {
		match self.node {
			Node::Empty => {},
			Node::Leaf(partial, _) | Node::Extension(partial, _) => {
				prefix.drop_lasts(partial.len());
			},
			Node::Branch(_, _) => {
				prefix.pop();
			},
			Node::NibbledBranch(partial, _, _) => {
				prefix.pop();
				prefix.drop_lasts(partial.len());
			},
		}
	}

	/// Reconstruct the encoded full trie node from the node and the entry's child references.
	///
	/// Preconditions:
	/// - if node is an extension node, then `children[0]` is Some.
	fn encode_node(self, attached_hash: Option<&[u8]>) -> Vec<u8> {
		let attached_hash = attached_hash.map(|h| crate::node::Value::Node(h));
		match self.node {
			Node::Empty => C::empty_node().to_vec(),
			Node::Leaf(partial, value) =>
				C::leaf_node(partial.right_iter(), partial.len(), attached_hash.unwrap_or(value)),
			Node::Extension(partial, _) => C::extension_node(
				partial.right_iter(),
				partial.len(),
				self.children[0].expect("required by method precondition; qed"),
			),
			Node::Branch(_, value) => C::branch_node(
				self.children.into_iter(),
				if attached_hash.is_some() { attached_hash } else { value },
			),
			Node::NibbledBranch(partial, _, value) => C::branch_node_nibbled(
				partial.right_iter(),
				partial.len(),
				self.children.iter(),
				if attached_hash.is_some() { attached_hash } else { value },
			),
		}
	}
}

/// Re-insert the subtrees deduplicated into an earlier occurrence (see
/// [`encode_compact_skip_duplicates`]) that `entry`'s node references through plain hash-reference
/// children, replaying what decoding the corresponding un-deduplicated encoding would have
/// inserted below this node. Hashes missing from `known_items` reference items outside the
/// encoding and are skipped, matching the holes an un-deduplicated encoding of the same partial
/// trie would leave.
///
/// `prefix` is the prefix of `entry`'s node; it is restored before returning.
fn reinsert_known_subtrees<L, DB>(
	db: &mut DB,
	known_items: &BTreeMap<Vec<u8>, DBValue>,
	entry: &DecoderStackEntry<L::Codec>,
	prefix: &mut NibbleVec,
) -> Result<(), TrieHash<L>, CError<L>>
where
	L: TrieLayout,
	DB: HashDB<L::Hash, DBValue>,
{
	let partial_len = match &entry.node {
		Node::Extension(partial, _) | Node::NibbledBranch(partial, _, _) => {
			prefix.append_partial(partial.right());
			partial.len()
		},
		_ => 0,
	};
	for index in 0..entry.children.len() {
		if entry.hash_ref_children & (1u16 << index) == 0 {
			continue
		}
		let hash = match &entry.children[index] {
			Some(ChildReference::Hash(hash)) => hash,
			_ => continue,
		};
		// An extension's child sits directly below the partial; branch children add their nibble.
		let result = if matches!(&entry.node, Node::Extension(..)) {
			reinsert_known_subtree::<L, DB>(db, known_items, hash.as_ref(), prefix)
		} else {
			prefix.push(index as u8);
			let result = reinsert_known_subtree::<L, DB>(db, known_items, hash.as_ref(), prefix);
			prefix.pop();
			result
		};
		result?;
	}
	prefix.drop_lasts(partial_len);
	Ok(())
}

/// Re-insert at `prefix` the subtree rooted at the known node with `hash`: the node, its known
/// detached value and, transitively, its known child subtrees, each at the position it would
/// occupy below `prefix`.
fn reinsert_known_subtree<L, DB>(
	db: &mut DB,
	known_items: &BTreeMap<Vec<u8>, DBValue>,
	hash: &[u8],
	prefix: &NibbleVec,
) -> Result<(), TrieHash<L>, CError<L>>
where
	L: TrieLayout,
	DB: HashDB<L::Hash, DBValue>,
{
	// Work items are `(prefix, hash, is_value)`. Value items are inserted verbatim; node items
	// are decoded to enqueue their hash-referenced value and children. Recorded node items always
	// decode (they are canonical encodings); a failure can only mean the hash was recorded for a
	// value whose bytes do not form a node, so it is not treated as an error.
	let mut work = vec![(prefix.clone(), hash.to_vec(), false)];
	while let Some((prefix, hash, is_value)) = work.pop() {
		let item = match known_items.get(&hash) {
			Some(item) => item,
			None => continue,
		};
		if is_value {
			db.insert(prefix.as_prefix(), item);
			continue
		}
		let node = match L::Codec::decode(item) {
			Ok(node) => node,
			Err(_) => continue,
		};
		db.insert(prefix.as_prefix(), item);
		match node {
			Node::Empty => {},
			Node::Leaf(partial, value) =>
				if let Value::Node(value_hash) = value {
					let mut value_prefix = prefix;
					value_prefix.append_partial(partial.right());
					work.push((value_prefix, value_hash.to_vec(), true));
				},
			Node::Extension(partial, child) =>
				if let NodeHandle::Hash(child_hash) = child {
					let mut child_prefix = prefix;
					child_prefix.append_partial(partial.right());
					work.push((child_prefix, child_hash.to_vec(), false));
				},
			Node::Branch(children, value) => {
				if let Some(Value::Node(value_hash)) = value {
					work.push((prefix.clone(), value_hash.to_vec(), true));
				}
				for (index, child) in children.iter().enumerate() {
					if let Some(NodeHandle::Hash(child_hash)) = child {
						let mut child_prefix = prefix.clone();
						child_prefix.push(index as u8);
						work.push((child_prefix, child_hash.to_vec(), false));
					}
				}
			},
			Node::NibbledBranch(partial, children, value) => {
				let mut node_prefix = prefix;
				node_prefix.append_partial(partial.right());
				if let Some(Value::Node(value_hash)) = value {
					work.push((node_prefix.clone(), value_hash.to_vec(), true));
				}
				for (index, child) in children.iter().enumerate() {
					if let Some(NodeHandle::Hash(child_hash)) = child {
						let mut child_prefix = node_prefix.clone();
						child_prefix.push(index as u8);
						work.push((child_prefix, child_hash.to_vec(), false));
					}
				}
			},
		}
	}
	Ok(())
}

/// Reconstructs a partial trie DB from a compact representation. The encoding is a vector of
/// mutated trie nodes with those child references omitted. The decode function reads them in order
/// from the given slice, reconstructing the full nodes and inserting them into the given `HashDB`.
/// It stops after fully constructing one partial trie and returns the root hash and the number of
/// nodes read. If an error occurs during decoding, there are no guarantees about which entries
/// were or were not added to the DB.
///
/// The number of nodes read may be fewer than the total number of items in `encoded`. This allows
/// one to concatenate multiple compact encodings together and still reconstruct them all.
//
/// This function makes the assumption that all child references in an inline trie node are inline
/// references.
pub fn decode_compact<L, DB>(
	db: &mut DB,
	encoded: &[Vec<u8>],
) -> Result<(TrieHash<L>, usize), TrieHash<L>, CError<L>>
where
	L: TrieLayout,
	DB: HashDB<L::Hash, DBValue>,
{
	decode_compact_from_iter::<L, DB, _>(db, encoded.iter().map(Vec::as_slice))
}

/// Variant of 'decode_compact' that accept an iterator of encoded nodes as input.
pub fn decode_compact_from_iter<'a, L, DB, I>(
	db: &mut DB,
	encoded: I,
) -> Result<(TrieHash<L>, usize), TrieHash<L>, CError<L>>
where
	L: TrieLayout,
	DB: HashDB<L::Hash, DBValue>,
	I: IntoIterator<Item = &'a [u8]>,
{
	decode_compact_from_iter_with_known_items::<L, DB, I>(db, encoded, &mut BTreeMap::new())
}

/// Variant of [`decode_compact_from_iter`] that lets the caller thread the map of already
/// decoded items — attached values and reconstructed nodes, keyed by their hash — through
/// successive calls.
///
/// All attached values and all reconstructed nodes are recorded in `known_items`. A node
/// referencing a known item only by hash (see [`encode_compact_skip_duplicates`]) gets the item —
/// for a subtree: the item and everything known below it — re-inserted at the referencing
/// position, reconstructing the same database as an encoding without deduplication. Threading
/// one map through successive calls is only needed for encodings deduplicated with a shared
/// `seen_hashes` set.
///
/// Note that decoding work is proportional to the *un-deduplicated* encoding: re-inserting
/// duplicated subtrees at every occurrence can touch far more positions than there are items in
/// `encoded`. Callers decoding untrusted input should bound the logical (un-deduplicated) size,
/// not just the encoded size.
pub fn decode_compact_from_iter_with_known_items<'a, L, DB, I>(
	db: &mut DB,
	encoded: I,
	known_items: &mut BTreeMap<Vec<u8>, DBValue>,
) -> Result<(TrieHash<L>, usize), TrieHash<L>, CError<L>>
where
	L: TrieLayout,
	DB: HashDB<L::Hash, DBValue>,
	I: IntoIterator<Item = &'a [u8]>,
{
	// The stack of nodes through a path in the trie. Each entry is a child node of the preceding
	// entry.
	let mut stack: Vec<DecoderStackEntry<L::Codec>> = Vec::new();

	// The prefix of the next item to be read from the slice of encoded items.
	let mut prefix = NibbleVec::new();

	// The number of items consumed so far, including attached values.
	let mut used;

	let mut iter = encoded.into_iter().enumerate();
	while let Some((i, encoded_node)) = iter.next() {
		used = i + 1;
		let mut attached_node = 0;
		if let Some(header) = L::Codec::ESCAPE_HEADER {
			if encoded_node.starts_with(&[header]) {
				attached_node = 1;
			}
		}
		let node = L::Codec::decode(&encoded_node[attached_node..])
			.map_err(|err| Box::new(TrieError::DecoderError(<TrieHash<L>>::default(), err)))?;

		let children_len = match node {
			Node::Empty | Node::Leaf(..) => 0,
			Node::Extension(..) => 1,
			Node::Branch(..) | Node::NibbledBranch(..) => NIBBLE_LENGTH,
		};
		let mut last_entry = DecoderStackEntry {
			node,
			child_index: 0,
			children: vec![None; children_len],
			hash_ref_children: 0,
			attached_value: None,
			_marker: PhantomData::default(),
		};

		if attached_node > 0 {
			// Read value
			if let Some((i, fetched_value)) = iter.next() {
				used = i + 1;
				last_entry.attached_value = Some(fetched_value);
				// Record immediately: a node deduplicated against this one can complete before
				// this node does, e.g. a leaf below a branch carrying the value.
				known_items
					.insert(L::Hash::hash(fetched_value).as_ref().to_vec(), fetched_value.to_vec());
			} else {
				return Err(Box::new(TrieError::IncompleteDatabase(<TrieHash<L>>::default())))
			}
		}

		loop {
			if !last_entry.advance_child_index()? {
				last_entry.push_to_prefix(&mut prefix);
				stack.push(last_entry);
				break
			}

			// Since `advance_child_index` returned true, the preconditions for `encode_node` are
			// satisfied.
			let hash = last_entry.attached_value.as_ref().map(|value| {
				let partial_prefix_len = match &last_entry.node {
					Node::Leaf(partial, _) | Node::NibbledBranch(partial, _, _) => {
						prefix.append_partial(partial.right());
						partial.len()
					},
					_ => 0,
				};
				let hash = db.insert(prefix.as_prefix(), value);
				prefix.drop_lasts(partial_prefix_len);
				hash
			});
			if hash.is_none() {
				// The node's detached value may have been deduplicated into an earlier occurrence
				// (see `encode_compact_skip_duplicates`). Re-insert it at this position as well,
				// so the reconstructed `db` matches an encoding without deduplication. A miss
				// means the value node is not part of the encoding, which is legal.
				let value_hash = match &last_entry.node {
					Node::Leaf(_, Value::Node(hash)) => Some(*hash),
					Node::Branch(_, Some(Value::Node(hash))) |
					Node::NibbledBranch(_, _, Some(Value::Node(hash))) => Some(*hash),
					_ => None,
				};
				if let Some(value) = value_hash.and_then(|hash| known_items.get(hash)) {
					let partial_prefix_len = match &last_entry.node {
						Node::Leaf(partial, _) | Node::NibbledBranch(partial, _, _) => {
							prefix.append_partial(partial.right());
							partial.len()
						},
						_ => 0,
					};
					db.insert(prefix.as_prefix(), value);
					prefix.drop_lasts(partial_prefix_len);
				}
			}
			// Children the encoded node kept as plain hash references may point at subtrees
			// deduplicated into an earlier occurrence; re-insert them at this position as well.
			// Misses again mean the referenced nodes are not part of the encoding.
			if last_entry.hash_ref_children != 0 {
				reinsert_known_subtrees::<L, DB>(db, known_items, &last_entry, &mut prefix)?;
			}
			let node_data = last_entry.encode_node(hash.as_ref().map(|h| h.as_ref()));
			let node_hash = db.insert(prefix.as_prefix(), node_data.as_ref());
			// Record for re-insertion of subtrees deduplicated against this node. Recording at
			// completion is early enough: a node keeping a deduplicated reference to this one
			// completes only after this subtree — emitted strictly earlier in pre-order, outside
			// the referencing node's own subtree — has fully completed.
			known_items.insert(node_hash.as_ref().to_vec(), node_data);

			if let Some(entry) = stack.pop() {
				last_entry = entry;
				last_entry.pop_from_prefix(&mut prefix);
				last_entry.children[last_entry.child_index] = Some(ChildReference::Hash(node_hash));
				last_entry.child_index += 1;
			} else {
				return Ok((node_hash, used))
			}
		}
	}

	Err(Box::new(TrieError::IncompleteDatabase(<TrieHash<L>>::default())))
}

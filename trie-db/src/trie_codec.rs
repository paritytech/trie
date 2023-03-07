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

use crate::{
	nibble_ops::NIBBLE_LENGTH,
	node::{Node, NodeHandle, NodeHandlePlan, NodePlan, OwnedNode, ValuePlan},
	rstd::{boxed::Box, convert::TryInto, marker::PhantomData, result, sync::Arc, vec, vec::Vec},
	CError, ChildReference, DBValue, NibbleVec, NodeCodec, Result, TrieDB, TrieDBRawIterator,
	TrieError, TrieHash, TrieLayout,
};
use hash_db::{HashDB, Prefix};

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
		let mut modified_node_plan;
		let node_plan = if self.omit_value {
			modified_node_plan = self.node.node_plan().clone();
			if let Some(value) = modified_node_plan.value_plan_mut() {
				// 0 length value.
				*value = ValuePlan::Inline(0..0);
			}
			&modified_node_plan
		} else {
			self.node.node_plan()
		};
		let mut encoded = match node_plan {
			NodePlan::Empty => node_data.to_vec(),
			NodePlan::Leaf { partial, value } => {
				if self.omit_value {
					let partial = partial.build(node_data);
				let value = value.build(node_data);
				C::leaf_node(partial.right_iter(), partial.len(), value)
				} else {
					node_data.to_vec()
				}
			},
			NodePlan::Extension { partial, child: _ } =>
				if !self.omit_children[0] {
					node_data.to_vec()
				} else {
					let partial = partial.build(node_data);
					let empty_child = ChildReference::Inline(C::HashOut::default(), 0);
					C::extension_node(partial.right_iter(), partial.len(), empty_child)
				},
			NodePlan::Branch { value, children } => C::branch_node(
				Self::branch_children(node_data, &children, &self.omit_children)?.iter(),
				value.as_ref().map(|v| v.build(node_data)),
			),
			NodePlan::NibbledBranch { partial, value, children } => {
				let partial = partial.build(node_data);
				C::branch_node_nibbled(
					partial.right_iter(),
					partial.len(),
					Self::branch_children(node_data, &children, &self.omit_children)?.iter(),
					value.as_ref().map(|v| v.build(node_data)),
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
fn detached_value<L: TrieLayout>(
	db: &TrieDB<L>,
	value: &ValuePlan,
	node_data: &[u8],
	node_prefix: Prefix,
) -> Option<Vec<u8>> {
	let fetched;
	match value {
		ValuePlan::Node(hash_plan) => {
			if let Ok(value) =
				TrieDBRawIterator::fetch_value(db, &node_data[hash_plan.clone()], node_prefix)
			{
				fetched = value;
			} else {
				return None
			}
		},
		_ => return None,
	}
	Some(fetched)
}

/// Generates a compact representation of the partial trie stored in the given DB. The encoding
/// is a vector of mutated trie nodes with those child references omitted. The mutated trie nodes
/// are listed in pre-order traversal order so that the full nodes can be efficiently
/// reconstructed recursively.
///
/// This function makes the assumption that all child references in an inline trie node are inline
/// references.
pub fn encode_compact<L>(db: &TrieDB<L>) -> Result<Vec<Vec<u8>>, TrieHash<L>, CError<L>>
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
	while let Some(item) = iter.next_raw_item(db) {
		match item {
			Ok((prefix, node_hash, node)) => {
				// Skip inline nodes, as they cannot contain hash references to other nodes by
				// assumption.
				if node_hash.is_none() {
					continue
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
					NodePlan::Leaf { value, .. } =>
						(0, detached_value(db, value, node.data(), prefix.as_prefix())),
					NodePlan::Extension { .. } => (1, None),
					NodePlan::NibbledBranch { value: Some(value), .. } |
					NodePlan::Branch { value: Some(value), .. } =>
						(NIBBLE_LENGTH, detached_value(db, value, node.data(), prefix.as_prefix())),
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
	// The stack of nodes through a path in the trie. Each entry is a child node of the preceding
	// entry.
	let mut stack: Vec<DecoderStackEntry<L::Codec>> = Vec::new();

	// The prefix of the next item to be read from the slice of encoded items.
	let mut prefix = NibbleVec::new();

	let mut iter = encoded.into_iter().enumerate();
	while let Some((i, encoded_node)) = iter.next() {
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
			attached_value: None,
			_marker: PhantomData::default(),
		};

		if attached_node > 0 {
			// Read value
			if let Some((_, fetched_value)) = iter.next() {
				last_entry.attached_value = Some(fetched_value);
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
			let hash = last_entry
				.attached_value
				.as_ref()
				.map(|value| db.insert(prefix.as_prefix(), value));
			let node_data = last_entry.encode_node(hash.as_ref().map(|h| h.as_ref()));
			let node_hash = db.insert(prefix.as_prefix(), node_data.as_ref());

			if let Some(entry) = stack.pop() {
				last_entry = entry;
				last_entry.pop_from_prefix(&mut prefix);
				last_entry.children[last_entry.child_index] = Some(ChildReference::Hash(node_hash));
				last_entry.child_index += 1;
			} else {
				return Ok((node_hash, i + 1))
			}
		}
	}

	Err(Box::new(TrieError::IncompleteDatabase(<TrieHash<L>>::default())))
}

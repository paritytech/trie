// Copyright 2019 Parity Technologies
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

//! Generation of compact proofs for Merkle-Patricia tries.

use crate::rstd::{
	boxed::Box, convert::TryInto, marker::PhantomData, ops::Range, vec, vec::Vec,
};

use hash_db::Hasher;

use crate::node_codec::Bitmap;
use crate::{
	CError, ChildReference, nibble::LeftNibbleSlice, nibble_ops::NIBBLE_LENGTH, NibbleSlice, node::{NodeHandle, NodeHandlePlan, NodePlan, OwnedNode}, NodeCodec, Recorder,
	Result as TrieResult, Trie, TrieError, TrieHash,
	TrieLayout,
};
use ordered_trie::BinaryHasher;

struct StackEntry<'a, C: NodeCodec, H> {
	/// The prefix is the nibble path to the node in the trie.
	prefix: LeftNibbleSlice<'a>,
	node: OwnedNode<Vec<u8>>,
	/// The hash of the node or None if it is referenced inline.
	node_hash: Option<C::HashOut>,
	/// Whether the value should be omitted in the generated proof.
	omit_value: bool,
	/// The next entry in the stack is a child of the preceding entry at this index. For branch
	/// nodes, the index is in [0, NIBBLE_LENGTH] and for extension nodes, the index is in [0, 1].
	child_index: usize,
	/// The child references to use in constructing the proof nodes.
	children: Vec<Option<ChildReference<C::HashOut>>>,
	/// The index into the proof vector that the encoding of this entry should be placed at.
	output_index: Option<usize>,
	is_inline: bool,
	_marker: PhantomData<(C, H)>,
}

impl<'a, C: NodeCodec, H: BinaryHasher> StackEntry<'a, C, H>
	where
		H: BinaryHasher<Out = C::HashOut>,
{
	fn new(
		prefix: LeftNibbleSlice<'a>,
		node_data: Vec<u8>,
		node_hash: Option<C::HashOut>,
		output_index: Option<usize>,
		is_inline: bool,
	) -> TrieResult<Self, C::HashOut, C::Error>
	{
		let node = OwnedNode::new::<C>(node_data)
			.map_err(|err| Box::new(
				TrieError::DecoderError(node_hash.unwrap_or_default(), err)
			))?;
		let children_len = match node.node_plan() {
			NodePlan::Empty | NodePlan::Leaf { .. } => 0,
			NodePlan::Extension { .. } => 1,
			NodePlan::Branch { .. } | NodePlan::NibbledBranch { .. } => NIBBLE_LENGTH,
		};
		Ok(StackEntry {
			prefix,
			node,
			node_hash,
			omit_value: false,
			child_index: 0,
			children: vec![None; children_len],
			output_index,
			is_inline,
			_marker: PhantomData::default(),
		})
	}

	/// Encode this entry to an encoded trie node with data properly omitted.
	fn encode_node(
		mut self,
		complex: bool,
		hash_buf: &mut H::Buffer,
	) -> TrieResult<Vec<u8>, C::HashOut, C::Error> {
		let node_data = self.node.data();
		Ok(match self.node.node_plan() {
			NodePlan::Empty => node_data.to_vec(),
			NodePlan::Leaf { .. } if !self.omit_value => node_data.to_vec(),
			NodePlan::Leaf { partial, value: _ } => {
				let partial = partial.build(node_data);
				C::leaf_node(partial.right(), &[])
			}
			NodePlan::Extension { .. } if self.child_index == 0 => node_data.to_vec(),
			NodePlan::Extension { partial: partial_plan, child: _ } => {
				let partial = partial_plan.build(node_data);
				let child = self.children[0]
					.expect(
						"for extension nodes, children[0] is guaranteed to be Some when \
						child_index > 0; \
						the branch guard guarantees that child_index > 0"
					);
				C::extension_node(
					partial.right_iter(),
					partial.len(),
					child
				)
			}
			NodePlan::Branch { value, children } => {
				Self::complete_branch_children(
					node_data,
					children,
					self.child_index,
					&mut self.children,
				)?;
				if !self.is_inline && complex {
					let mut register_children: [Option<_>; NIBBLE_LENGTH] = Default::default();
					let register_children = &mut register_children[..];
					let (mut result, no_child) = C::branch_node(
						self.children.iter(),
						value_with_omission(node_data, value, self.omit_value),
						Some(register_children),
					);
					no_child.trim_no_child(&mut result);
					let bitmap_start = result.len();
					result.push(0u8);
					result.push(0u8);
					let mut in_proof_children = [false; NIBBLE_LENGTH];
					// write all inline nodes and ommitted node
					// TODO again register for nothing
					for (ix, child) in self.children.iter().enumerate() {
						if let Some(ChildReference::Inline(h, nb)) = child.as_ref() {
							if *nb > 0 {
								debug_assert!(*nb < 128);
									result.push(*nb as u8);
								result.push(ix as u8);
								result.extend_from_slice(&h.as_ref()[..*nb]);
							}
								in_proof_children[ix] = true;
						}
					}
					Bitmap::encode(in_proof_children.iter().map(|b| *b), &mut result[bitmap_start..]);
					let additional_hashes = crate::trie_codec::binary_additional_hashes::<H>(
						&self.children[..],
							&in_proof_children[..],
						hash_buf,
					);
					result.push((additional_hashes.len() as u8) | 128); // first bit at one indicates we are on additional hashes
					for hash in additional_hashes {
						result.extend_from_slice(hash.as_ref());
					}
					result
				} else {
					C::branch_node(
						self.children.into_iter(),
						value_with_omission(node_data, value, self.omit_value),
						None, // TODO allow complex here
					).0
				}
			},
			NodePlan::NibbledBranch { partial: partial_plan, value, children } => {
				let partial = partial_plan.build(node_data);
				Self::complete_branch_children(
					node_data,
					children,
					self.child_index,
					&mut self.children
				)?;
				if !self.is_inline && complex {
					// TODO factor with non nibbled!!
					let mut register_children: [Option<_>; NIBBLE_LENGTH] = Default::default();
					let register_children = &mut register_children[..];
					let (mut result, no_child) = C::branch_node_nibbled(
						partial.right_iter(),
						partial.len(),
						self.children.iter(),
						value_with_omission(node_data, value, self.omit_value),
						Some(register_children),
					);
					no_child.trim_no_child(&mut result);
					let bitmap_start = result.len();
					result.push(0u8);
					result.push(0u8);
					let mut in_proof_children = [false; NIBBLE_LENGTH];
					// write all inline nodes and ommitted node
					// TODO again register for nothing
					for (ix, child) in self.children.iter().enumerate() {
						if let Some(ChildReference::Inline(h, nb)) = child.as_ref() {
							if *nb > 0 {
								debug_assert!(*nb < 128);
								result.push(*nb as u8);
								result.push(ix as u8);
								result.extend_from_slice(&h.as_ref()[..*nb]);
							}
							in_proof_children[ix] = true;
						}
					}
					Bitmap::encode(in_proof_children.iter().map(|b| *b), &mut result[bitmap_start..]);
					let additional_hashes = crate::trie_codec::binary_additional_hashes::<H>(
						&self.children[..],
						&in_proof_children[..],
						hash_buf,
					);
					result.push((additional_hashes.len() as u8) | 128); // first bit at one indicates we are on additional hashes
					for hash in additional_hashes {
						result.extend_from_slice(hash.as_ref());
					}
					result
				} else {
					C::branch_node_nibbled(
						partial.right_iter(),
						partial.len(),
						self.children.into_iter(),
						value_with_omission(node_data, value, self.omit_value),
						None, // TODO allow complex here
					).0
				}
			},
		})
	}

	/// Populate the remaining references in `children` with references copied from
	/// `child_handles`.
	///
	/// Preconditions:
	/// - children has size NIBBLE_LENGTH.
	fn complete_branch_children(
		node_data: &[u8],
		child_handles: &[Option<NodeHandlePlan>; NIBBLE_LENGTH],
		child_index: usize,
		children: &mut [Option<ChildReference<C::HashOut>>],
	) -> TrieResult<(), C::HashOut, C::Error>
	{
		for i in child_index..NIBBLE_LENGTH {
			children[i] = child_handles[i]
				.as_ref()
				.map(|child_plan|
					child_plan
						.build(node_data)
						.try_into()
						.map_err(|hash| Box::new(
							TrieError::InvalidHash(C::HashOut::default(), hash)
						))
				)
				.transpose()?;
		}
		Ok(())
	}

	/// Sets the reference for the child at index `child_index`. If the child is hash-referenced in
	/// the trie, the proof node reference will be an omitted child. If the child is
	/// inline-referenced in the trie, the proof node reference will also be inline.
	fn set_child(&mut self, encoded_child: &[u8]) {
		let child_ref = match self.node.node_plan() {
			NodePlan::Empty | NodePlan::Leaf { .. } => panic!(
				"empty and leaf nodes have no children; \
				thus they are never descended into; \
				thus set_child will not be called on an entry with one of these types"
			),
			NodePlan::Extension { child, ..  } => {
				assert_eq!(
					self.child_index, 0,
					"extension nodes only have one child; \
					set_child is called when the only child is popped from the stack; \
					child_index is 0 before child is pushed to the stack; qed"
				);
				Some(Self::replacement_child_ref(encoded_child, child))
			}
			NodePlan::Branch { children, .. } | NodePlan::NibbledBranch { children, .. } => {
				assert!(
					self.child_index < NIBBLE_LENGTH,
					"extension nodes have at most NIBBLE_LENGTH children; \
					set_child is called when the only child is popped from the stack; \
					child_index is <NIBBLE_LENGTH before child is pushed to the stack; qed"
				);
				children[self.child_index]
					.as_ref()
					.map(|child| Self::replacement_child_ref(encoded_child, child))
			}
		};
		self.children[self.child_index] = child_ref;
		self.child_index += 1;
	}

	/// Build a proof node child reference. If the child is hash-referenced in the trie, the proof
	/// node reference will be an omitted child. If the child is inline-referenced in the trie, the
	/// proof node reference will also be inline.
	fn replacement_child_ref(encoded_child: &[u8], child: &NodeHandlePlan)
							 -> ChildReference<C::HashOut>
	{
		match child {
			NodeHandlePlan::Hash(_) => ChildReference::Inline(C::HashOut::default(), 0),
			NodeHandlePlan::Inline(_) => {
				let mut hash = C::HashOut::default();
				assert!(
					encoded_child.len() <= hash.as_ref().len(),
					"the encoding of the raw inline node is checked to be at most the hash length
					before descending; \
					the encoding of the proof node is always smaller than the raw node as data is \
					only stripped"
				);
				&mut hash.as_mut()[..encoded_child.len()].copy_from_slice(encoded_child);
				ChildReference::Inline(hash, encoded_child.len())
			}
		}
	}
}

/// Generate a compact proof for key-value pairs in a trie given a set of keys.
///
/// Assumes inline nodes have only inline children.
pub fn generate_proof<'a, T, L, I, K>(trie: &T, keys: I)
									  -> TrieResult<Vec<Vec<u8>>, TrieHash<L>, CError<L>>
	where
		T: Trie<L>,
		L: TrieLayout,
		I: IntoIterator<Item=&'a K>,
		K: 'a + AsRef<[u8]>
{
	// Sort and deduplicate keys.
	let mut keys = keys.into_iter()
		.map(|key| key.as_ref())
		.collect::<Vec<_>>();
	keys.sort();
	keys.dedup();
	let mut hash_buf = <L::Hash as BinaryHasher>::Buffer::default();
	let hash_buf = &mut hash_buf;


	// The stack of nodes through a path in the trie. Each entry is a child node of the preceding
	// entry.
	let mut stack = <Vec<StackEntry<L::Codec, L::Hash>>>::new();

	// The mutated trie nodes comprising the final proof.
	let mut proof_nodes = Vec::new();

	for key_bytes in keys {
		let key = LeftNibbleSlice::new(key_bytes);

		// Unwind the stack until the new entry is a child of the last entry on the stack.
		unwind_stack(&mut stack, &mut proof_nodes, Some(&key), L::COMPLEX_HASH, hash_buf)?;

		// Perform the trie lookup for the next key, recording the sequence of nodes traversed.
		let mut recorder = Recorder::new();
		let expected_value = trie.get_with(key_bytes, &mut recorder)?;
		let mut recorded_nodes = recorder.drain().into_iter().peekable();

		// Skip over recorded nodes already on the stack. Their indexes into the respective vector
		// (either `stack` or `recorded_nodes`) match under the assumption that inline nodes have
		// only inline children.
		{
			let mut stack_iter = stack.iter().peekable();
			while let (Some(next_record), Some(next_entry)) =
			(recorded_nodes.peek(), stack_iter.peek())
				{
					if next_entry.node_hash != Some(next_record.hash) {
						break;
					}
					recorded_nodes.next();
					stack_iter.next();
				}
		}

		loop {
			let step = match stack.last_mut() {
				Some(entry) => match_key_to_node::<L::Codec>(
					entry.node.data(),
					entry.node.node_plan(),
					&mut entry.omit_value,
					&mut entry.child_index,
					&mut entry.children,
					&key,
					entry.prefix.len(),
				)?,
				// If stack is empty, descend into the root node.
				None => Step::Descend {
					child_prefix_len: 0,
					child: NodeHandle::Hash(trie.root().as_ref()),
				},
			};

			match step {
				Step::Descend { child_prefix_len, child } => {
					let child_prefix = key.truncate(child_prefix_len);
					let child_entry = match child {
						NodeHandle::Hash(hash) => {
							let child_record = recorded_nodes.next()
								.expect(
									"this function's trie traversal logic mirrors that of Lookup; \
									thus the sequence of traversed nodes must be the same; \
									so the next child node must have been recorded and must have \
									the expected hash"
								);
							// Proof for `assert_eq` is in the `expect` proof above.
							assert_eq!(child_record.hash.as_ref(), hash);

							let output_index = proof_nodes.len();
							// Insert a placeholder into output which will be replaced when this
							// new entry is popped from the stack.
							proof_nodes.push(Vec::new());
							StackEntry::new(
								child_prefix,
								child_record.data,
								Some(child_record.hash),
								Some(output_index),
								false,
							)?
						}
						NodeHandle::Inline(data) => {
							if data.len() > L::Hash::LENGTH {
								return Err(Box::new(
									TrieError::InvalidHash(<TrieHash<L>>::default(), data.to_vec())
								));
							}
							StackEntry::new(
								child_prefix,
								data.to_vec(),
								None,
								None,
								true,
							)?
						}
					};
					stack.push(child_entry);
				}
				Step::FoundValue(value) => {
					assert_eq!(
						value,
						expected_value.as_ref().map(|v| v.as_ref()),
						"expected_value is found using `trie_db::Lookup`; \
						value is found by traversing the same nodes recorded during the lookup \
						using the same logic; \
						thus the values found must be equal"
					);
					assert!(
						recorded_nodes.next().is_none(),
						"the recorded nodes are only recorded on the lookup path to the current \
						key; \
						recorded nodes is the minimal sequence of trie nodes on the lookup path; \
						the value was found by traversing recorded nodes, so there must be none \
						remaining"
					);
					break;
				}
			}
		}
	}

	unwind_stack(&mut stack, &mut proof_nodes, None, L::COMPLEX_HASH, hash_buf)?;
	Ok(proof_nodes)
}

enum Step<'a> {
	Descend {
		child_prefix_len: usize,
		child: NodeHandle<'a>,
	},
	FoundValue(Option<&'a [u8]>),
}

/// Determine the next algorithmic step to take by matching the current key against the current top
/// entry on the stack.
fn match_key_to_node<'a, C: NodeCodec>(
	node_data: &'a [u8],
	node_plan: &NodePlan,
	omit_value: &mut bool,
	child_index: &mut usize,
	children: &mut [Option<ChildReference<C::HashOut>>],
	key: &LeftNibbleSlice,
	prefix_len: usize,
) -> TrieResult<Step<'a>, C::HashOut, C::Error>
{
	Ok(match node_plan {
		NodePlan::Empty => Step::FoundValue(None),
		NodePlan::Leaf { partial: partial_plan, value: value_range } => {
			let partial = partial_plan.build(node_data);
			if key.contains(&partial, prefix_len) &&
				key.len() == prefix_len + partial.len()
			{
				*omit_value = true;
				Step::FoundValue(Some(&node_data[value_range.clone()]))
			} else {
				Step::FoundValue(None)
			}
		}
		NodePlan::Extension { partial: partial_plan, child: child_plan } => {
			let partial = partial_plan.build(node_data);
			if key.contains(&partial, prefix_len) {
				assert_eq!(*child_index, 0);
				let child_prefix_len = prefix_len + partial.len();
				let child = child_plan.build(&node_data);
				Step::Descend { child_prefix_len, child }
			} else {
				Step::FoundValue(None)
			}
		}
		NodePlan::Branch { value, children: child_handles } =>
			match_key_to_branch_node::<C>(
				node_data,
				value,
				&child_handles,
				omit_value,
				child_index,
				children,
				key,
				prefix_len,
				NibbleSlice::new(&[]),
			)?,
		NodePlan::NibbledBranch { partial: partial_plan, value, children: child_handles } =>
			match_key_to_branch_node::<C>(
				node_data,
				value,
				&child_handles,
				omit_value,
				child_index,
				children,
				key,
				prefix_len,
				partial_plan.build(node_data),
			)?,
	})
}

fn match_key_to_branch_node<'a, 'b, C: NodeCodec>(
	node_data: &'a [u8],
	value_range: &'b Option<Range<usize>>,
	child_handles: &'b [Option<NodeHandlePlan>; NIBBLE_LENGTH],
	omit_value: &mut bool,
	child_index: &mut usize,
	children: &mut [Option<ChildReference<C::HashOut>>],
	key: &'b LeftNibbleSlice<'b>,
	prefix_len: usize,
	partial: NibbleSlice<'b>,
) -> TrieResult<Step<'a>, C::HashOut, C::Error>
{
	if !key.contains(&partial, prefix_len) {
		return Ok(Step::FoundValue(None));
	}

	if key.len() == prefix_len + partial.len() {
		*omit_value = true;
		let value = value_range.clone().map(|range| &node_data[range]);
		return Ok(Step::FoundValue(value));
	}

	let new_index = key.at(prefix_len + partial.len())
		.expect(
			"key contains partial key after entry key offset; \
			thus key len is greater than equal to entry key len plus partial key len; \
			also they are unequal due to else condition;
			qed"
		)
		as usize;
	assert!(*child_index <= new_index);
	while *child_index < new_index {
		children[*child_index] = child_handles[*child_index]
			.as_ref()
			.map(|child_plan|
				child_plan
					.build(node_data)
					.try_into()
					.map_err(|hash| Box::new(
						TrieError::InvalidHash(C::HashOut::default(), hash)
					))
			)
			.transpose()?;
		*child_index += 1;
	}
	if let Some(child_plan) = &child_handles[*child_index] {
		Ok(Step::Descend {
			child_prefix_len: prefix_len + partial.len() + 1,
			child: child_plan.build(node_data),
		})
	} else {
		Ok(Step::FoundValue(None))
	}
}

fn value_with_omission<'a>(
	node_data: &'a [u8],
	value_range: &Option<Range<usize>>,
	omit: bool
) -> Option<&'a [u8]>
{
	if omit {
		None
	} else {
		value_range.clone().map(|range| &node_data[range])
	}
}

/// Unwind the stack until the given key is prefixed by the entry at the top of the stack. If the
/// key is None, unwind the stack completely. As entries are popped from the stack, they are
/// encoded into proof nodes and added to the finalized proof.
fn unwind_stack<C: NodeCodec, H: BinaryHasher>(
	stack: &mut Vec<StackEntry<C, H>>,
	proof_nodes: &mut Vec<Vec<u8>>,
	maybe_key: Option<&LeftNibbleSlice>,
	complex: bool,
	hash_buf: &mut H::Buffer,
) -> TrieResult<(), C::HashOut, C::Error>
	where
		H: BinaryHasher<Out = C::HashOut>,
{
	while let Some(entry) = stack.pop() {
		match maybe_key {
			Some(key) if key.starts_with(&entry.prefix) => {
				// Stop if the key lies below this entry in the trie.
				stack.push(entry);
				break;
			}
			_ => {
				// Pop and finalize node from the stack.
				let index = entry.output_index;
				let encoded = entry.encode_node(complex, hash_buf)?;
				if let Some(parent_entry) = stack.last_mut() {
					parent_entry.set_child(&encoded);
				}
				if let Some(index) = index {
					proof_nodes[index] = encoded;
				}
			}
		}
	}
	Ok(())
}

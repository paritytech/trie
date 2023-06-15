// Copyright 2023, 2023 Parity Technologies
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

//! Iterate on multiple values following a specific query plan.
//! Can be use on a trie db to register a proof, or
//! be use on a proof directly.
//! When use on a proof, process can be interrupted, checked and
//! restore (at the cost of additional hashes in proof).
//!
//! Because nodes are guaranted to be accessed only once and recorded
//! in proof, we do not use a cache (or only the node caching part).

use core::marker::PhantomData;

use crate::{
	content_proof::Op,
	nibble::{nibble_ops, nibble_ops::NIBBLE_LENGTH, LeftNibbleSlice, NibbleSlice},
	node::{NodeHandle, NodePlan, OwnedNode, Value},
	node_codec::NodeCodec,
	proof::VerifyError,
	rstd::{
		borrow::{Borrow, Cow},
		boxed::Box,
		cmp::*,
		result::Result,
	},
	CError, ChildReference, DBValue, NibbleVec, Trie, TrieDB, TrieHash, TrieLayout,
};
use hash_db::Hasher;
pub use record::{record_query_plan, HaltedStateRecord, Recorder};
pub use verify::verify_query_plan_iter;
use verify::HaltedStateCheckNode;
pub use verify_content::verify_query_plan_iter_content;
use verify_content::HaltedStateCheckContent;

mod record;
mod verify;
mod verify_content;

/// Item to query, in memory.
#[derive(Default)]
pub struct InMemQueryPlanItem {
	key: Vec<u8>,
	hash_only: bool,
	//	hash_only: bool, TODO implement
	as_prefix: bool,
}

impl InMemQueryPlanItem {
	/// Create new item.
	pub fn new(key: Vec<u8>, hash_only: bool, as_prefix: bool) -> Self {
		Self { key, hash_only, as_prefix }
	}
	/// Get ref.
	pub fn as_ref(&self) -> QueryPlanItem {
		QueryPlanItem { key: &self.key, hash_only: self.hash_only, as_prefix: self.as_prefix }
	}
}

/// Item to query.
#[derive(Clone, Debug)]
pub struct QueryPlanItem<'a> {
	pub key: &'a [u8],
	pub hash_only: bool,
	pub as_prefix: bool,
}

impl<'a> QueryPlanItem<'a> {
	fn before(&self, other: &Self) -> (bool, usize) {
		let (common_depth, ordering) = nibble_ops::biggest_depth_and_order(&self.key, &other.key);

		(
			match ordering {
				Ordering::Less => {
					if self.as_prefix {
						// do not allow querying content inside a prefix
						!other.key.starts_with(self.key)
					} else {
						true
					}
				},
				Ordering::Greater | Ordering::Equal => false,
			},
			common_depth,
		)
	}

	fn to_owned(&self) -> InMemQueryPlanItem {
		InMemQueryPlanItem {
			key: self.key.to_vec(),
			hash_only: self.hash_only,
			as_prefix: self.as_prefix,
		}
	}
}

/// Query plan in memory.
pub struct InMemQueryPlan {
	pub items: Vec<InMemQueryPlanItem>,
	pub kind: ProofKind,
	// TODO rem
	pub ignore_unordered: bool,
}

/// Iterator as type of mapped slice iter is very noisy.
pub struct QueryPlanItemIter<'a>(&'a Vec<InMemQueryPlanItem>, usize);

impl<'a> Iterator for QueryPlanItemIter<'a> {
	type Item = QueryPlanItem<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.1 >= self.0.len() {
			return None
		}
		self.1 += 1;
		Some(self.0[self.1 - 1].as_ref())
	}
}

impl InMemQueryPlan {
	/// Get ref.
	pub fn as_ref(&self) -> QueryPlan<QueryPlanItemIter> {
		QueryPlan {
			items: QueryPlanItemIter(&self.items, 0),
			kind: self.kind,
			ignore_unordered: self.ignore_unordered,
			_ph: PhantomData,
		}
	}
}

/// Query plan.
pub struct QueryPlan<'a, I> {
	pub items: I,
	pub ignore_unordered: bool,
	pub kind: ProofKind,
	pub _ph: PhantomData<&'a ()>,
}

/// Different proof support.
#[derive(Clone, Copy, PartialEq, Eq)]
pub enum ProofKind {
	/// Proof is a sequence of fully encoded node, this is not
	/// size efficient but allows streaming a proof better, since
	/// the consumer can halt at the first invalid node.
	FullNodes,

	/// Proof got its accessed hash and value removed (same scheme
	/// as in trie_codec.rs ordering is same as full node, from
	/// root and in lexicographic order).
	///
	/// Checking this proof requires to read it fully. When stopping
	/// recording, the partial proof stays valid, but it will
	/// contains hashes that would not be needed if creating the
	/// proof at once.
	CompactNodes,

	/* TODO does not seem usefull, CompactContent is strictly better
	/// Same encoding as CompactNodes, but with an alternate ordering that allows streaming
	/// node and avoid unbound memory when building proof.
	///
	/// Ordering is starting at first met proof and parent up to intersection with next
	/// sibling access in a branch, then next leaf, and repeating, finishing with root node.
	CompactNodesStream,
	*/
	/// Content oriented proof, no nodes are written, just a
	/// sequence of accessed by lexicographical order as described
	/// in content_proof::Op.
	/// As with compact node, checking validity of proof need to
	/// load the full proof or up to the halt point.
	CompactContent,
}

impl ProofKind {
	// Do we need to record child hash and inline value individually.
	fn record_inline(&self) -> bool {
		match self {
			ProofKind::FullNodes | ProofKind::CompactNodes => false,
			ProofKind::CompactContent => true,
		}
	}
}

#[derive(Default, Clone, Copy)]
struct Bitmap(u16);

pub(crate) trait BitmapAccess: Copy {
	fn at(&self, i: usize) -> bool;
}

impl BitmapAccess for Bitmap {
	fn at(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}
}

impl<'a> BitmapAccess for &'a [bool] {
	fn at(&self, i: usize) -> bool {
		self[i]
	}
}

impl Bitmap {
	fn set(&mut self, i: usize, v: bool) {
		if v {
			self.0 |= 1u16 << i
		} else {
			self.0 &= !(1u16 << i)
		}
	}
}

// TODO rename
#[derive(Clone)]
struct CompactEncodingInfos {
	/// Node in memory content.
	node: OwnedNode<DBValue>,
	/// Flags indicating whether each child is omitted in the encoded node.
	/// For some encoding, it also record if the child has already been written.
	accessed_children_node: Bitmap,
	/// Skip value if value node is after.
	accessed_value_node: bool,
	/// Depth of node in nible.
	depth: usize,
	/// Next descended child, can also be use to get node position in parent
	/// (this minus one).
	next_descended_child: u8,
	/// Is the node inline.
	is_inline: bool,
}

/// Allows sending proof recording as it is produced.
pub trait RecorderOutput {
	/// Append bytes.
	fn write_bytes(&mut self, bytes: &[u8]);

	/// Bytes buf len.
	fn buf_len(&self) -> usize;

	/// Append a delimited sequence of bytes (usually a node).
	fn write_entry(&mut self, bytes: Cow<[u8]>);
}

/// Simple in memory recorder.
/// Depending on type of proof, nodes or buffer should
/// be used.
/// Sequence is guaranteed by pushing buffer in nodes
/// every time a node is written.
#[derive(Default)]
pub struct InMemoryRecorder {
	pub nodes: Vec<DBValue>,
	pub buffer: Vec<u8>,
}

impl RecorderOutput for InMemoryRecorder {
	fn write_bytes(&mut self, bytes: &[u8]) {
		self.buffer.extend_from_slice(bytes)
	}

	fn buf_len(&self) -> usize {
		self.buffer.len()
	}

	fn write_entry(&mut self, bytes: Cow<[u8]>) {
		if !self.buffer.is_empty() {
			self.nodes.push(core::mem::take(&mut self.buffer));
		}
		self.nodes.push(bytes.into_owned());
	}
}

/// Limits to size proof to record.
struct Limits {
	remaining_node: Option<usize>,
	remaining_size: Option<usize>,
	kind: ProofKind,
}

impl Limits {
	#[must_use]
	fn add_node(&mut self, size: usize, hash_size: usize, is_root: bool) -> bool {
		let mut res = false;
		match self.kind {
			ProofKind::CompactNodes | ProofKind::FullNodes => {
				if let Some(rem_size) = self.remaining_size.as_mut() {
					if let ProofKind::CompactNodes = self.kind {
						if !is_root {
							// remove a parent hash
							*rem_size += hash_size;
						}
					}
					if *rem_size >= size {
						*rem_size -= size;
					} else {
						*rem_size = 0;
						res = true;
					}
				}
				if let Some(rem_node) = self.remaining_node.as_mut() {
					if *rem_node > 1 {
						*rem_node -= 1;
					} else {
						*rem_node = 0;
						res = true;
					}
				}
			},
			ProofKind::CompactContent => {
				// everything is counted as a node.
				if let Some(rem_size) = self.remaining_size.as_mut() {
					if *rem_size >= size {
						*rem_size -= size;
					} else {
						*rem_size = 0;
						res = true;
					}
				}
				if let Some(rem_node) = self.remaining_node.as_mut() {
					if *rem_node > 1 {
						*rem_node -= 1;
					} else {
						*rem_node = 0;
						res = true;
					}
				}
			},
		}
		res
	}

	#[must_use]
	fn add_value(&mut self, size: usize, hash_size: usize) -> bool {
		let mut res = false;
		match self.kind {
			ProofKind::CompactNodes | ProofKind::FullNodes => {
				if let Some(rem_size) = self.remaining_size.as_mut() {
					if let ProofKind::CompactNodes = self.kind {
						// remove a parent value hash
						*rem_size += hash_size;
					}
					if *rem_size >= size {
						*rem_size -= size;
					} else {
						*rem_size = 0;
						res = true;
					}
				}
				if let Some(rem_node) = self.remaining_node.as_mut() {
					if *rem_node > 1 {
						*rem_node -= 1;
					} else {
						*rem_node = 0;
						res = true;
					}
				}
			},
			ProofKind::CompactContent => {
				unreachable!()
			},
		}
		res
	}
}

/// When process is halted keep execution state
/// to restore later.
pub enum HaltedStateCheck<'a, L: TrieLayout, C, D: SplitFirst> {
	Node(HaltedStateCheckNode<'a, L, C, D>),
	Content(HaltedStateCheckContent<'a, L, C>),
}

enum TryStackChildResult {
	Stacked,
	NotStackedBranch,
	NotStacked,
	StackedDescendIncomplete,
	Halted,
}

#[derive(Eq, PartialEq)]
enum ReadProofState {
	/// Iteration not started.
	NotStarted,
	/// Iterating.
	Running,
	/// Switch next item.
	SwitchQueryPlan,
	/// Proof read.
	PlanConsumed,
	/// Proof read.
	Halted,
	/// Iteration finished.
	Finished,
}

struct ItemStack<L: TrieLayout, D: SplitFirst> {
	node: ItemStackNode<D>,
	children: Vec<Option<ChildReference<TrieHash<L>>>>,
	attached_value_hash: Option<TrieHash<L>>,
	depth: usize,
	next_descended_child: u8,
}

#[derive(Clone)]
enum ValueSet<H, V> {
	None,
	Standard(V),
	HashOnly(H),
	//	ForceInline(V),
	//	ForceHashed(V),
	BranchHash(H, u8),
}

impl<H, V> ValueSet<H, V> {
	fn as_ref(&self) -> Option<&V> {
		match self {
			ValueSet::Standard(v) => Some(v),
			//ValueSet::ForceInline(v) | ValueSet::ForceHashed(v) => Some(v),
			ValueSet::HashOnly(..) | ValueSet::BranchHash(..) | ValueSet::None => None,
		}
	}
}

impl<H, V> From<Op<H, V>> for ValueSet<H, V> {
	fn from(op: Op<H, V>) -> Self {
		match op {
			Op::HashChild(hash, child_ix) => ValueSet::BranchHash(hash, child_ix),
			Op::HashValue(hash) => ValueSet::HashOnly(hash),
			Op::Value(value) => ValueSet::Standard(value),
			//Op::ValueForceInline(value) => ValueSet::ForceInline(value),
			//Op::ValueForceHashed(value) => ValueSet::ForceHashed(value),
			_ => ValueSet::None,
		}
	}
}

struct ItemContentStack<L: TrieLayout> {
	children: Vec<Option<ChildReference<TrieHash<L>>>>,
	value: ValueSet<TrieHash<L>, Vec<u8>>,
	depth: usize,
}

impl<L: TrieLayout, D: SplitFirst> Clone for ItemStack<L, D> {
	fn clone(&self) -> Self {
		ItemStack {
			node: self.node.clone(),
			children: self.children.clone(),
			attached_value_hash: self.attached_value_hash,
			depth: self.depth,
			next_descended_child: self.next_descended_child,
		}
	}
}

impl<L: TrieLayout> Clone for ItemContentStack<L> {
	fn clone(&self) -> Self {
		ItemContentStack {
			children: self.children.clone(),
			value: self.value.clone(),
			depth: self.depth,
		}
	}
}

#[derive(Clone)]
enum ItemStackNode<D: SplitFirst> {
	Inline(OwnedNode<Vec<u8>>),
	Node(OwnedNode<D>),
}

impl<L: TrieLayout, D: SplitFirst> From<(ItemStackNode<D>, bool)> for ItemStack<L, D> {
	fn from((node, is_compact): (ItemStackNode<D>, bool)) -> Self {
		let children = if !is_compact {
			Vec::new()
		} else {
			match &node {
				ItemStackNode::Inline(_) => Vec::new(),
				ItemStackNode::Node(node) => match node.node_plan() {
					NodePlan::Empty | NodePlan::Leaf { .. } => Vec::new(),
					NodePlan::Extension { child, .. } => {
						let mut result: Vec<Option<ChildReference<TrieHash<L>>>> = vec![None; 1];
						let node_data = node.data();
						match child.build(node_data) {
							NodeHandle::Inline(data) if data.is_empty() => (),
							child => {
								use std::convert::TryInto;
								let child_ref =
									child.try_into().expect("TODO proper error and not using From");

								result[0] = Some(child_ref);
							},
						}
						result
					},
					NodePlan::Branch { children, .. } |
					NodePlan::NibbledBranch { children, .. } => {
						let mut i = 0;
						let mut result: Vec<Option<ChildReference<TrieHash<L>>>> =
							vec![None; NIBBLE_LENGTH];
						let node_data = node.data();
						while i < NIBBLE_LENGTH {
							match children[i].as_ref().map(|c| c.build(node_data)) {
								Some(NodeHandle::Inline(data)) if data.is_empty() => (),
								Some(child) => {
									use std::convert::TryInto;
									let child_ref = child
										.try_into()
										.expect("TODO proper error and not using From");

									result[i] = Some(child_ref);
								},
								None => {},
							}
							i += 1;
						}
						result
					},
				},
			}
		};

		ItemStack { node, depth: 0, next_descended_child: 0, children, attached_value_hash: None }
	}
}

impl<L: TrieLayout, D: SplitFirst> ItemStack<L, D> {
	fn data(&self) -> &[u8] {
		match &self.node {
			ItemStackNode::Inline(n) => n.data(),
			ItemStackNode::Node(n) => n.data(),
		}
	}

	fn node_plan(&self) -> &NodePlan {
		match &self.node {
			ItemStackNode::Inline(n) => n.node_plan(),
			ItemStackNode::Node(n) => n.node_plan(),
		}
	}
}

struct ReadStack<L: TrieLayout, D: SplitFirst> {
	items: Vec<ItemStack<L, D>>,
	prefix: NibbleVec,
	// limit and wether we return value and if hash only iteration.
	iter_prefix: Option<(usize, bool, bool)>,
	start_items: usize,
	is_compact: bool,
	expect_value: bool,
	_ph: PhantomData<L>,
}

struct ReadContentStack<L: TrieLayout> {
	items: Vec<ItemContentStack<L>>,
	prefix: NibbleVec,
	// limit and wether we return value and if hash only iteration.
	// TODO should be removable (just check current).
	iter_prefix: Option<(usize, bool, bool)>,
	start_items: usize,
	is_prev_hash_child: Option<u8>,
	expect_value: bool,
	is_prev_push_key: bool,
	is_prev_pop_key: bool,
	first: bool,
	_ph: PhantomData<L>,
}

impl<L: TrieLayout, D: SplitFirst> Clone for ReadStack<L, D> {
	fn clone(&self) -> Self {
		ReadStack {
			items: self.items.clone(),
			prefix: self.prefix.clone(),
			start_items: self.start_items.clone(),
			iter_prefix: self.iter_prefix,
			is_compact: self.is_compact,
			expect_value: self.expect_value,
			_ph: PhantomData,
		}
	}
}

impl<L: TrieLayout> Clone for ReadContentStack<L> {
	fn clone(&self) -> Self {
		ReadContentStack {
			items: self.items.clone(),
			prefix: self.prefix.clone(),
			start_items: self.start_items.clone(),
			iter_prefix: self.iter_prefix,
			expect_value: self.expect_value,
			is_prev_push_key: self.is_prev_push_key,
			is_prev_pop_key: self.is_prev_pop_key,
			is_prev_hash_child: self.is_prev_hash_child,
			first: self.first,
			_ph: PhantomData,
		}
	}
}

fn verify_hash<L: TrieLayout>(
	data: &[u8],
	expected: &[u8],
) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
	let checked_hash = L::Hash::hash(data);
	if checked_hash.as_ref() != expected {
		let mut error_hash = TrieHash::<L>::default();
		error_hash.as_mut().copy_from_slice(expected);
		Err(VerifyError::HashMismatch(error_hash))
	} else {
		Ok(())
	}
}

/// Byte array where we can remove first item.
/// This is only needed for the ESCAPE_HEADER of COMPACT which
/// itself is not strictly needed (we can know if escaped from
/// query plan).
pub trait SplitFirst: Borrow<[u8]> + Clone {
	fn split_first(&mut self);
}

impl SplitFirst for Vec<u8> {
	fn split_first(&mut self) {
		*self = self.split_off(1);
	}
}

impl<'a> SplitFirst for &'a [u8] {
	fn split_first(&mut self) {
		*self = &self[1..];
	}
}

impl<L: TrieLayout, D: SplitFirst> ReadStack<L, D> {
	fn try_stack_child(
		&mut self,
		child_index: u8,
		proof: &mut impl Iterator<Item = D>,
		expected_root: &Option<TrieHash<L>>,
		mut slice_query: Option<&mut NibbleSlice>,
		query_prefix: bool,
	) -> Result<TryStackChildResult, VerifyError<TrieHash<L>, CError<L>>> {
		let check_hash = expected_root.is_some();
		let child_handle = if let Some(node) = self.items.last_mut() {
			let node_data = node.data();

			match node.node_plan() {
				NodePlan::Empty | NodePlan::Leaf { .. } =>
					return Ok(TryStackChildResult::NotStacked),
				NodePlan::Extension { .. } => {
					unreachable!("Extension never stacked")
				},
				NodePlan::NibbledBranch { children, .. } | NodePlan::Branch { children, .. } =>
					if let Some(child) = &children[child_index as usize] {
						child.build(node_data)
					} else {
						return Ok(TryStackChildResult::NotStackedBranch)
					},
			}
		} else {
			if self.is_compact {
				NodeHandle::Inline(&[])
			} else {
				NodeHandle::Hash(expected_root.as_ref().map(AsRef::as_ref).unwrap_or(&[]))
			}
		};
		let mut node: ItemStack<_, _> = match child_handle {
			NodeHandle::Inline(data) =>
				if self.is_compact && data.len() == 0 {
					// ommitted hash
					let Some(mut encoded_node) = proof.next() else {
					// halt happens with a hash, this is not.
					return Err(VerifyError::IncompleteProof);
				};
					if self.is_compact &&
						encoded_node.borrow().len() > 0 &&
						Some(encoded_node.borrow()[0]) ==
							<L::Codec as crate::node_codec::NodeCodec>::ESCAPE_HEADER
					{
						self.expect_value = true;
						// no value to visit TODO set a boolean to ensure we got a hash and don
						// t expect reanding a node value
						encoded_node.split_first();
					}
					let node = match OwnedNode::new::<L::Codec>(encoded_node) {
						Ok(node) => node,
						Err(e) => return Err(VerifyError::DecodeError(e)),
					};
					(ItemStackNode::Node(node), self.is_compact).into()
				} else {
					// try access in inline then return
					(
						ItemStackNode::Inline(match OwnedNode::new::<L::Codec>(data.to_vec()) {
							Ok(node) => node,
							Err(e) => return Err(VerifyError::DecodeError(e)),
						}),
						self.is_compact,
					)
						.into()
				},
			NodeHandle::Hash(hash) => {
				// TODO if is_compact allow only if restart bellow depth (otherwhise should be
				// inline(0)) or means halted (if something in proof it is extraneous node)
				let Some(mut encoded_node) = proof.next() else {
					return Ok(TryStackChildResult::Halted);
				};
				if self.is_compact &&
					encoded_node.borrow().len() > 0 &&
					Some(encoded_node.borrow()[0]) ==
						<L::Codec as crate::node_codec::NodeCodec>::ESCAPE_HEADER
				{
					self.expect_value = true;
					// no value to visit TODO set a boolean to ensure we got a hash and don
					// t expect reanding a node value
					encoded_node.split_first();
				}
				let node = match OwnedNode::new::<L::Codec>(encoded_node) {
					Ok(node) => node,
					Err(e) => return Err(VerifyError::DecodeError(e)),
				};
				if !self.is_compact && check_hash {
					verify_hash::<L>(node.data(), hash)?;
				}
				(ItemStackNode::Node(node), self.is_compact).into()
			},
		};
		let node_data = node.data();

		let mut prefix_incomplete = false;
		match node.node_plan() {
			NodePlan::Branch { .. } => (),
			| NodePlan::Empty => (),
			NodePlan::Leaf { partial, .. } |
			NodePlan::NibbledBranch { partial, .. } |
			NodePlan::Extension { partial, .. } => {
				let partial = partial.build(node_data);
				if self.items.len() > 0 {
					if let Some(slice) = slice_query.as_mut() {
						slice.advance(1);
					}
				}
				let ok = if let Some(slice) = slice_query.as_mut() {
					if slice.starts_with(&partial) {
						true
					} else if query_prefix {
						prefix_incomplete = true;
						partial.starts_with(slice)
					} else {
						false
					}
				} else {
					true
				};
				if prefix_incomplete {
					// end of query
					slice_query = None;
				}
				if ok {
					if self.items.len() > 0 {
						self.prefix.push(child_index);
					}
					if let Some(slice) = slice_query.as_mut() {
						slice.advance(partial.len());
					}
					self.prefix.append_partial(partial.right());
				} else {
					return Ok(TryStackChildResult::StackedDescendIncomplete)
				}
			},
		}
		if let NodePlan::Extension { child, .. } = node.node_plan() {
			let node_data = node.data();
			let child = child.build(node_data);
			match child {
				NodeHandle::Hash(hash) => {
					let Some(encoded_branch) = proof.next() else {
						// No halt on extension node (restart over a child index).
						return Err(VerifyError::IncompleteProof);
					};
					if self.is_compact {
						let mut error_hash = TrieHash::<L>::default();
						error_hash.as_mut().copy_from_slice(hash);
						return Err(VerifyError::ExtraneousHashReference(error_hash))
					}
					if check_hash {
						verify_hash::<L>(encoded_branch.borrow(), hash)?;
					}
					node = match OwnedNode::new::<L::Codec>(encoded_branch) {
						Ok(node) => (ItemStackNode::Node(node), self.is_compact).into(),
						Err(e) => return Err(VerifyError::DecodeError(e)),
					};
				},
				NodeHandle::Inline(data) => {
					if self.is_compact && data.len() == 0 {
						unimplemented!("This requires to put extension in stack");
					/*
					// ommitted hash
					let Some(encoded_node) = proof.next() else {
						// halt happens with a hash, this is not.
						return Err(VerifyError::IncompleteProof);
					};
					node = match OwnedNode::new::<L::Codec>(encoded_node) {
						Ok(node) => (ItemStackNode::Node(node), self.is_compact).into(),
						Err(e) => return Err(VerifyError::DecodeError(e)),
					};
					*/
					} else {
						node = match OwnedNode::new::<L::Codec>(data.to_vec()) {
							Ok(node) => (ItemStackNode::Inline(node), self.is_compact).into(),
							Err(e) => return Err(VerifyError::DecodeError(e)),
						};
					}
				},
			}
			let NodePlan::Branch { .. } = node.node_plan() else {
				return Err(VerifyError::IncompleteProof) // TODO make error type??
			};
		}
		node.depth = self.prefix.len();
		// needed for compact
		self.items.last_mut().map(|parent| {
			parent.next_descended_child = child_index + 1;
		});
		self.items.push(node);
		if prefix_incomplete {
			Ok(TryStackChildResult::StackedDescendIncomplete)
		} else {
			Ok(TryStackChildResult::Stacked)
		}
	}

	fn access_value(
		&mut self,
		proof: &mut impl Iterator<Item = D>,
		check_hash: bool,
		hash_only: bool,
	) -> Result<(Option<Vec<u8>>, Option<TrieHash<L>>), VerifyError<TrieHash<L>, CError<L>>> {
		if let Some(node) = self.items.last() {
			let node_data = node.data();

			let value = match node.node_plan() {
				NodePlan::Leaf { value, .. } => Some(value.build(node_data)),
				NodePlan::Branch { value, .. } | NodePlan::NibbledBranch { value, .. } =>
					value.as_ref().map(|v| v.build(node_data)),
				_ => return Ok((None, None)),
			};
			if let Some(value) = value {
				match value {
					Value::Inline(value) =>
						if self.expect_value {
							assert!(self.is_compact);
							self.expect_value = false;
							if hash_only {
								return Err(VerifyError::ExtraneousValue(Default::default()))
							}

							let Some(value) = proof.next() else {
								return Err(VerifyError::IncompleteProof);
							};
							if check_hash {
								let hash = L::Hash::hash(value.borrow());
								self.items.last_mut().map(|i| i.attached_value_hash = Some(hash));
							}
							return Ok((Some(value.borrow().to_vec()), None))
						} else {
							if hash_only {
								let hash = L::Hash::hash(value.borrow());
								return Ok((None, Some(hash)))
							}
							return Ok((Some(value.to_vec()), None))
						},
					Value::Node(hash) => {
						if self.expect_value {
							if hash_only {
								return Err(VerifyError::ExtraneousValue(Default::default()))
							}
							self.expect_value = false;
							let mut error_hash = TrieHash::<L>::default();
							error_hash.as_mut().copy_from_slice(hash);
							return Err(VerifyError::ExtraneousHashReference(error_hash))
						}
						if hash_only {
							let mut result_hash = TrieHash::<L>::default();
							result_hash.as_mut().copy_from_slice(hash);
							return Ok((None, Some(result_hash)))
						}
						let Some(value) = proof.next() else {
							return Err(VerifyError::IncompleteProof);
						};
						if check_hash {
							verify_hash::<L>(value.borrow(), hash)?;
						}
						return Ok((Some(value.borrow().to_vec()), None))
					},
				}
			}
		} else {
			return Err(VerifyError::IncompleteProof)
		}

		Ok((None, None))
	}

	fn pop(
		&mut self,
		expected_root: &Option<TrieHash<L>>,
	) -> Result<bool, VerifyError<TrieHash<L>, CError<L>>> {
		if self.iter_prefix.as_ref().map(|p| p.0 == self.items.len()).unwrap_or(false) {
			return Ok(false)
		}
		if let Some(last) = self.items.pop() {
			let depth = self.items.last().map(|i| i.depth).unwrap_or(0);
			self.prefix.drop_lasts(self.prefix.len() - depth);
			if self.is_compact && expected_root.is_some() {
				match last.node {
					ItemStackNode::Inline(_) => (),
					ItemStackNode::Node(node) => {
						let origin = self.start_items;
						let node_data = node.data();
						let node = node.node_plan().build(node_data);
						let encoded_node = crate::trie_codec::encode_read_node_internal::<L::Codec>(
							node,
							&last.children,
							last.attached_value_hash.as_ref().map(|h| h.as_ref()),
						);

						//println!("{:?}", encoded_node);
						if self.items.len() == origin {
							if let Some(parent) = self.items.last() {
								let at = parent.next_descended_child - 1;
								if let Some(Some(ChildReference::Hash(expected))) =
									parent.children.get(at as usize)
								{
									verify_hash::<L>(&encoded_node, expected.as_ref())?;
								} else {
									return Err(VerifyError::RootMismatch(Default::default()))
								}
							} else {
								let expected = expected_root.as_ref().expect("checked above");
								verify_hash::<L>(&encoded_node, expected.as_ref())?;
							}
						} else if self.items.len() < origin {
							// popped origin, need to check against new origin
							self.start_items = self.items.len();
						} else {
							let hash = L::Hash::hash(&encoded_node);
							if let Some(parent) = self.items.last_mut() {
								let at = parent.next_descended_child - 1;
								match parent.children[at as usize] {
									Some(ChildReference::Hash(expected)) => {
										// can append if chunks are concatenated (not progressively
										// checked)
										verify_hash::<L>(&encoded_node, expected.as_ref())?;
									},
									None => {
										// Complete
										parent.children[at as usize] =
											Some(ChildReference::Hash(hash));
									},
									Some(ChildReference::Inline(_h, size)) if size == 0 => {
										// Complete
										parent.children[at as usize] =
											Some(ChildReference::Hash(hash));
									},
									_ =>
									// only non inline are stacked
										return Err(VerifyError::RootMismatch(Default::default())),
								}
							} else {
								if &Some(hash) != expected_root {
									return Err(VerifyError::RootMismatch(hash))
								}
							}
						}
					},
				}
			}
			Ok(true)
		} else {
			Ok(false)
		}
	}

	fn pop_until(
		&mut self,
		target: usize,
		expected_root: &Option<TrieHash<L>>,
		check_only: bool,
	) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
		if self.is_compact && expected_root.is_some() {
			// TODO pop with check only, here unefficient implementation where we just restore

			let mut restore = None;
			if check_only {
				restore = Some(self.clone());
				self.iter_prefix = None;
			}
			// one by one
			while let Some(last) = self.items.last() {
				match last.depth.cmp(&target) {
					Ordering::Greater => (),
					// depth should match.
					Ordering::Less => {
						// TODO other error
						return Err(VerifyError::ExtraneousNode)
					},
					Ordering::Equal => return Ok(()),
				}
				// one by one
				let _ = self.pop(expected_root)?;
			}

			if let Some(old) = restore.take() {
				*self = old;
				return Ok(())
			}
		}
		loop {
			if let Some(last) = self.items.last() {
				match last.depth.cmp(&target) {
					Ordering::Greater => (),
					// depth should match.
					Ordering::Less => break,
					Ordering::Equal => {
						self.prefix.drop_lasts(self.prefix.len() - last.depth);
						return Ok(())
					},
				}
			} else {
				if target == 0 {
					return Ok(())
				} else {
					break
				}
			}
			let _ = self.items.pop();
		}
		// TODO other error
		Err(VerifyError::ExtraneousNode)
	}

	fn enter_prefix_iter(&mut self, hash_only: bool) {
		self.iter_prefix = Some((self.items.len(), false, hash_only));
	}

	fn exit_prefix_iter(&mut self) {
		self.iter_prefix = None
	}
}

impl<L: TrieLayout> ReadContentStack<L> {
	fn pop_until(
		&mut self,
		target: usize,
		check_only: bool, // TODO used?
	) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
		// TODO pop with check only, here unefficient implementation where we just restore

		let mut restore = None;
		if check_only {
			restore = Some(self.clone());
			self.iter_prefix = None;
		}
		// one by one
		while let Some(last) = self.items.last() {
			// depth should match.
			match last.depth.cmp(&target) {
				Ordering::Greater => {
					// TODO could implicit pop here with a variant
					// that do not write redundant pop.
					return Err(VerifyError::ExtraneousNode) // TODO more precise error
				},
				Ordering::Less => {
					if self.first {
						// allowed to have next at a upper level
					} else {
						return Err(VerifyError::ExtraneousNode)
					}
				},
				Ordering::Equal => return Ok(()),
			}

			// start_items update.
			self.start_items = core::cmp::min(self.start_items, self.items.len());
			// one by one
			let _ = self.items.pop();
		}

		if let Some(old) = restore.take() {
			*self = old;
			return Ok(())
		}
		if self.items.is_empty() && target == 0 {
			Ok(())
		} else {
			Err(VerifyError::ExtraneousNode)
		}
	}

	#[inline(always)]
	fn stack_empty(&mut self, depth: usize) {
		/*
		items: Vec<ItemContentStack<L>>,
		prefix: NibbleVec,
		// limit and wether we return value and if hash only iteration.
		iter_prefix: Option<(usize, bool, bool)>,
		start_items: usize,
			*/

		self.items.push(ItemContentStack {
			children: vec![None; NIBBLE_LENGTH],
			value: ValueSet::None,
			depth,
		})
	}

	#[inline(always)]
	fn stack_pop(
		&mut self,
		nb_nibble: Option<usize>,
		expected_root: &Option<TrieHash<L>>,
	) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
		let target_depth = nb_nibble.map(|n| self.prefix.len() - n);
		let mut first = true;
		while self
			.items
			.last()
			.map(|item| target_depth.map(|target| item.depth > target).unwrap_or(true))
			.unwrap_or(false)
		{
			let item = self.items.pop().expect("Checked");
			let mut from_depth =
				self.items.last().map(|item| item.depth).unwrap_or(target_depth.unwrap_or(0));
			if let Some(from) = target_depth {
				if from > from_depth {
					self.stack_empty(from);
					from_depth = from;
				}
			}
			let depth = item.depth;
			let is_root = target_depth.is_none() && self.items.is_empty();
			let inc = if is_root { 0 } else { 1 };

			let child_reference = if item.children.iter().any(|child| child.is_some()) {
				let nkey = (depth > (from_depth + inc))
					.then(|| (from_depth + inc, depth - from_depth - inc));
				if L::USE_EXTENSION {
					let extension_only = first &&
						matches!(&item.value, &ValueSet::None) &&
						item.children.iter().filter(|child| child.is_some()).count() == 1;
					self.items.push(item); // TODO this looks bad (pop then push, branch or leaf function should or should
					   // not pop instead)
					   // encode branch
					self.standard_extension(depth, is_root, nkey, extension_only)
				} else {
					self.items.push(item); // TODO this looks bad (pop then push, branch or leaf function should or should
					   // not pop instead)
					   // encode branch
					self.no_extension(depth, is_root, nkey)
				}
			} else {
				// leaf with value
				self.flush_value_change(from_depth + inc, item.depth, &item.value, is_root)
			};

			if self.items.is_empty() && !is_root {
				self.stack_empty(from_depth);
			}

			let items_len = self.items.len();
			if let Some(item) = self.items.last_mut() {
				let child_ix = self.prefix.at(item.depth);
				if let Some(hash) = item.children[child_ix as usize].as_ref() {
					if items_len == self.start_items + 1 {
						if expected_root.is_some() && hash != &child_reference {
							return Err(VerifyError::HashMismatch(*child_reference.disp_hash()))
						}
					} else {
						return Err(VerifyError::ExtraneousHashReference(*hash.disp_hash()))
						// return Err(CompactDecoderError::HashChildNotOmitted.into())
					}
				}
				item.children[child_ix as usize] = Some(child_reference);
			} else {
				if let Some(root) = expected_root.as_ref() {
					if nb_nibble.is_none() {
						if root != child_reference.disp_hash() {
							return Err(VerifyError::RootMismatch(*child_reference.disp_hash()))
						}
					}
				}
			}
			first = false;
			// TODO can skip hash checks when above start_items.
			self.start_items = core::cmp::min(self.start_items, self.items.len());
		}
		Ok(())
	}

	fn process(encoded_node: Vec<u8>, is_root: bool) -> ChildReference<TrieHash<L>> {
		let len = encoded_node.len();
		if !is_root && len < <L::Hash as Hasher>::LENGTH {
			let mut h = <<L::Hash as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);
			return ChildReference::Inline(h, len)
		}
		let hash = <L::Hash as Hasher>::hash(encoded_node.as_slice());
		ChildReference::Hash(hash)
	}

	// TODO factor with iter_build (reuse cacheaccum here).
	#[inline(always)]
	fn standard_extension(
		&mut self,
		branch_d: usize,
		is_root: bool,
		nkey: Option<(usize, usize)>,
		extension_only: bool,
	) -> ChildReference<TrieHash<L>> {
		let key_branch = &self.prefix.inner().as_ref()[..];
		let last = self.items.len() - 1;
		assert_eq!(self.items[last].depth, branch_d);

		let ItemContentStack { children, value: v, depth, .. } = self.items.pop().expect("checked");

		debug_assert!(branch_d == depth);

		let hashed;
		let value = if let Some(v) = v.as_ref() {
			Some(if let Some(value) = Value::new_inline(v.as_ref(), L::MAX_INLINE_VALUE) {
				value
			} else {
				let mut prefix = NibbleSlice::new_offset(&key_branch, 0);
				prefix.advance(branch_d);

				hashed = <L::Hash as Hasher>::hash(v.as_ref());
				Value::Node(hashed.as_ref())
			})
		} else {
			None
		};

		// encode branch
		let branch_hash = if !extension_only {
			let encoded = L::Codec::branch_node(children.iter(), value);
			Self::process(encoded, is_root && nkey.is_none())
		} else {
			// This is hacky but extension only store as first children
			children[0].unwrap()
		};

		if let Some(nkeyix) = nkey {
			let pr = NibbleSlice::new_offset(&key_branch, nkeyix.0);
			let nib = pr.right_range_iter(nkeyix.1);
			let encoded = L::Codec::extension_node(nib, nkeyix.1, branch_hash);
			Self::process(encoded, is_root)
		} else {
			branch_hash
		}
	}

	#[inline(always)]
	fn no_extension(
		&mut self,
		branch_d: usize,
		is_root: bool,
		nkey: Option<(usize, usize)>,
	) -> ChildReference<TrieHash<L>> {
		let key_branch = &self.prefix.inner().as_ref()[..];
		let ItemContentStack { children, value: v, depth, .. } = self.items.pop().expect("checked");

		debug_assert!(branch_d == depth);
		// encode branch
		let nkeyix = nkey.unwrap_or((branch_d, 0));
		let pr = NibbleSlice::new_offset(&key_branch, nkeyix.0);
		let hashed;
		let value = if let Some(v) = v.as_ref() {
			Some(if let Some(value) = Value::new_inline(v.as_ref(), L::MAX_INLINE_VALUE) {
				value
			} else {
				let mut prefix = NibbleSlice::new_offset(&key_branch, 0);
				prefix.advance(branch_d);
				hashed = <L::Hash as Hasher>::hash(v.as_ref());
				Value::Node(hashed.as_ref())
			})
		} else {
			if let ValueSet::HashOnly(h) = &v {
				Some(Value::Node(h.as_ref()))
			} else {
				None
			}
		};

		let encoded = L::Codec::branch_node_nibbled(
			pr.right_range_iter(nkeyix.1),
			nkeyix.1,
			children.iter(),
			value,
		);
		Self::process(encoded, is_root)
	}

	fn flush_value_change<'a>(
		&mut self,
		from_depth: usize,
		to_depth: usize,
		value: &ValueSet<TrieHash<L>, Vec<u8>>,
		is_root: bool,
	) -> ChildReference<TrieHash<L>> {
		let key_content = &self.prefix.inner().as_ref()[..];
		let k2 = &key_content[..to_depth / nibble_ops::NIBBLE_PER_BYTE];
		let pr = NibbleSlice::new_offset(k2, from_depth);

		let hashed;
		let value = match value {
			ValueSet::Standard(v) =>
				if let Some(value) = Value::new_inline(v.as_ref(), L::MAX_INLINE_VALUE) {
					value
				} else {
					hashed = <L::Hash as Hasher>::hash(v.as_ref());
					Value::Node(hashed.as_ref())
				},
			ValueSet::HashOnly(h) => {
				Value::Node(h.as_ref()) // TODO may have following hash and fail? ont if leaf
			},
			ValueSet::BranchHash(..) | ValueSet::None => unreachable!("Not in cache accum"),
		};
		let encoded = L::Codec::leaf_node(pr.right_iter(), pr.len(), value);
		Self::process(encoded, is_root)
	}

	#[inline(always)]
	fn set_cache_change(
		&mut self,
		change: ValueSet<TrieHash<L>, Vec<u8>>,
	) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
		if self.items.is_empty() {
			self.stack_empty(0);
		}
		let last = self.items.len() - 1;
		let mut item = &mut self.items[last];
		match change {
			ValueSet::BranchHash(h, i) => {
				if let Some(hash) = item.children[i as usize].as_ref() {
					return Err(VerifyError::ExtraneousHashReference(*hash.disp_hash()))
					//return Err(CompactDecoderError::HashChildNotOmitted.into()) TODO
				}
				item.children[i as usize] = Some(ChildReference::Hash(h));
			},
			value => item.value = value,
		}
		Ok(())
	}
}

/// Content return on success when reading proof.
pub enum ReadProofItem<'a, L: TrieLayout, C, D: SplitFirst> {
	/// Successfull read of proof, not all content read.
	Halted(Box<HaltedStateCheck<'a, L, C, D>>),
	/// Seen value and key in proof.
	/// We only return content matching the query plan.
	/// TODO should be possible to return &Vec<u8>
	Value(Cow<'a, [u8]>, Vec<u8>),
	/// Seen hash of value and key in proof.
	/// We only return content matching the query plan.
	Hash(Cow<'a, [u8]>, TrieHash<L>),
	/// No value seen for a key in the input query plan.
	NoValue(&'a [u8]),
	/// Seen fully covered prefix in proof, this is only
	/// return when we read the proof with the query input (otherwhise
	/// we would need to indicate every child without a hash as a prefix).
	/// TODO unused implement
	StartPrefix(&'a [u8]),
	/// End of a previously start prefix.
	/// TODO unused implement
	EndPrefix,
}

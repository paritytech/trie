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
#[derive(Clone)]
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
	/// in compact_content_proof::Op.
	/// As with compact node, checking validity of proof need to
	/// load the full proof or up to the halt point.
	CompactContent,
}

impl ProofKind {
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

/// Simplified recorder.
pub struct Recorder<O: RecorderOutput, L: TrieLayout> {
	output: RecorderStateInner<O>,
	limits: Limits,
	// on restore only record content AFTER this position.
	start_at: Option<usize>,
	_ph: PhantomData<L>,
}

/// Limits to size proof to record.
struct Limits {
	remaining_node: Option<usize>,
	remaining_size: Option<usize>,
	kind: ProofKind,
}

impl<O: RecorderOutput, L: TrieLayout> Recorder<O, L> {
	fn mark_inline_access(&self) -> bool {
		match &self.output {
			RecorderStateInner::Content { .. } => true,
			_ => false,
		}
	}

	/// Check and update start at record.
	/// When return true, do record.
	fn check_start_at(&mut self, depth: usize) -> bool {
		if self.start_at.map(|s| s > depth).unwrap_or(false) {
			false
		} else {
			self.start_at = None;
			true
		}
	}

	/// Get back output handle from a recorder.
	pub fn output(self) -> O {
		match self.output {
			RecorderStateInner::Stream(output) |
			RecorderStateInner::Compact { output, .. } |
			RecorderStateInner::Content { output, .. } => output,
		}
	}

	/// Instantiate a new recorder.
	pub fn new(
		kind: ProofKind,
		output: O,
		limit_node: Option<usize>,
		limit_size: Option<usize>,
	) -> Self {
		let output = match kind {
			ProofKind::FullNodes => RecorderStateInner::Stream(output),
			ProofKind::CompactNodes =>
				RecorderStateInner::Compact { output, proof: Vec::new(), stacked_pos: Vec::new() },
			ProofKind::CompactContent =>
				RecorderStateInner::Content { output, stacked_push: None, stacked_pop: None },
		};
		let limits = Limits { remaining_node: limit_node, remaining_size: limit_size, kind };
		Self { output, limits, start_at: None, _ph: PhantomData }
	}

	#[must_use]
	fn record_stacked_node(
		&mut self,
		item: &CompactEncodingInfos,
		is_root: bool,
		parent_index: u8,
		items: &Vec<CompactEncodingInfos>,
	) -> bool {
		if !self.check_start_at(item.depth) {
			return false
		}
		let mut res = false;
		match &mut self.output {
			RecorderStateInner::Stream(output) =>
				if !item.is_inline {
					res = self.limits.add_node(
						item.node.data().len(),
						L::Codec::DELTA_COMPACT_OMITTED_NODE,
						is_root,
					);
					output.write_entry(item.node.data().into());
				},
			RecorderStateInner::Compact { output: _, proof, stacked_pos } =>
				if !item.is_inline {
					res = self.limits.add_node(
						item.node.data().len(),
						L::Codec::DELTA_COMPACT_OMITTED_NODE,
						is_root,
					);
					stacked_pos.push(proof.len());
					proof.push(Vec::new());
				},
			RecorderStateInner::Content { output, stacked_push, stacked_pop } => {
				if Self::flush_compact_content_pop(
					output,
					stacked_pop,
					items,
					None,
					&mut self.limits,
				) {
					res = true
				}
				if stacked_push.is_none() {
					*stacked_push = Some(NibbleVec::new());
				}
				if let Some(buff) = stacked_push.as_mut() {
					if !is_root {
						buff.push(parent_index);
					}
					let node_data = item.node.data();

					match item.node.node_plan() {
						NodePlan::Branch { .. } => (),
						| NodePlan::Empty => (),
						NodePlan::Leaf { partial, .. } |
						NodePlan::NibbledBranch { partial, .. } |
						NodePlan::Extension { partial, .. } => {
							let partial = partial.build(node_data);
							buff.append_optional_slice_and_nibble(Some(&partial), None);
						},
					}
				}
			},
		}
		res
	}

	#[must_use]
	fn flush_compact_content_pushes(&mut self, depth: usize) -> bool {
		let mut res = false;
		if !self.check_start_at(depth) {
			// TODO actually should be unreachable
			return res
		}
		if let RecorderStateInner::Content { output, stacked_push, .. } = &mut self.output {
			if let Some(buff) = stacked_push.take() {
				let mask = if buff.len() % 2 == 0 { 0xff } else { 0xf0 };
				let op = compact_content_proof::Op::<TrieHash<L>, Vec<u8>>::KeyPush(
					buff.inner().to_vec(),
					mask,
				);
				let init_len = output.buf_len();
				op.encode_into(output);
				let written = output.buf_len() - init_len;
				res = self.limits.add_node(written, 0, false);
			}
		}
		res
	}

	#[must_use]
	fn flush_compact_content_pop(
		out: &mut O,
		stacked_from: &mut Option<usize>,
		items: &[CompactEncodingInfos],
		add_depth: Option<usize>,
		limits: &mut Limits,
	) -> bool {
		let Some(from) = stacked_from.take() else {
			return false
		};
		let pop_to = add_depth.unwrap_or_else(|| items.last().map(|i| i.depth).unwrap_or(0));
		debug_assert!(from > pop_to);

		debug_assert!(from - pop_to <= u16::max_value() as usize);
		// Warning this implies key size limit of u16::max
		let op = compact_content_proof::Op::<TrieHash<L>, Vec<u8>>::KeyPop((from - pop_to) as u16);
		let init_len = out.buf_len();
		op.encode_into(out);
		let written = out.buf_len() - init_len;
		limits.add_node(written, 0, false)
	}

	#[must_use]
	fn record_popped_node(
		&mut self,
		item: &CompactEncodingInfos,
		items: &[CompactEncodingInfos],
	) -> bool {
		let mut res = false;
		if !self.check_start_at(item.depth) {
			return res
		}
		if let RecorderStateInner::Content { .. } = &self.output {
			// if no value accessed, then we can have push then stack pop.
			if self.flush_compact_content_pushes(item.depth) {
				res = true;
			}
		}

		match &mut self.output {
			RecorderStateInner::Stream(_) => (),
			RecorderStateInner::Compact { proof, stacked_pos, .. } =>
				if !item.is_inline {
					if let Some(at) = stacked_pos.pop() {
						proof[at] = crate::trie_codec::encode_node_internal::<L::Codec>(
							&item.node,
							item.accessed_value_node,
							item.accessed_children_node,
						)
						.expect("TODO error handling, can it actually fail?");
					} // else when restarting record, this is not to be recorded
				},
			RecorderStateInner::Content { output, stacked_pop, .. } => {
				if stacked_pop.is_none() {
					*stacked_pop = Some(item.depth);
				}
				// two case: children to register or all children accessed.
				let mut has_hash_to_write = false;
				let node_data = item.node.data();
				if let Some(last_item) = items.last() {
					match last_item.node.node_plan() {
						NodePlan::Branch { children, .. } |
						NodePlan::NibbledBranch { children, .. } =>
							for i in 0..children.len() {
								if children[i].is_some() && !last_item.accessed_children_node.at(i)
								{
									has_hash_to_write = true;
									break
								}
							},
						_ => (),
					}
				}

				match item.node.node_plan() {
					NodePlan::Branch { children, .. } |
					NodePlan::NibbledBranch { children, .. } => {
						for i in 0..children.len() {
							if let Some(child) = &children[i] {
								if !item.accessed_children_node.at(i) {
									match child.build(node_data) {
										NodeHandle::Hash(hash_slice) => {
											let mut hash = TrieHash::<L>::default();
											hash.as_mut().copy_from_slice(hash_slice);
											let op = compact_content_proof::Op::<
												TrieHash<L>,
												Vec<u8>,
											>::HashChild(hash, i as u8);
											let init_len = output.buf_len();
											op.encode_into(output);
											let written = output.buf_len() - init_len;
											res = self.limits.add_node(written, 0, false)
										},
										NodeHandle::Inline(_) => {
											// As been accessed if needed (inline are not mark).
										},
									}
								}
							}
						}
					},
					_ => (),
				}
				if has_hash_to_write {
					if Self::flush_compact_content_pop(
						output,
						stacked_pop,
						items,
						None,
						&mut self.limits,
					) {
						res = true;
					}
				}
			},
		}
		res
	}

	#[must_use]
	fn record_value_node(&mut self, value: Vec<u8>, depth: usize) -> bool {
		if !self.check_start_at(depth) {
			return false
		}

		let mut res = false;
		if let RecorderStateInner::Content { .. } = &self.output {
			res = self.flush_compact_content_pushes(depth);
		}
		match &mut self.output {
			RecorderStateInner::Stream(output) => {
				res = self.limits.add_value(value.len(), L::Codec::DELTA_COMPACT_OMITTED_VALUE);
				output.write_entry(value.into());
			},
			RecorderStateInner::Compact { output: _, proof, stacked_pos: _ } => {
				res = self.limits.add_value(value.len(), L::Codec::DELTA_COMPACT_OMITTED_VALUE);
				proof.push(value.into());
			},
			RecorderStateInner::Content { output, .. } => {
				let op = compact_content_proof::Op::<TrieHash<L>, Vec<u8>>::Value(value);
				let init_len = output.buf_len();
				op.encode_into(output);
				let written = output.buf_len() - init_len;
				res |= self.limits.add_node(written, 0, false)
			},
		}
		res
	}

	#[must_use]
	fn record_value_inline(&mut self, value: &[u8], depth: usize) -> bool {
		let mut res = false;
		if !self.check_start_at(depth) {
			return res
		}
		if let RecorderStateInner::Content { .. } = &self.output {
			if self.flush_compact_content_pushes(depth) {
				res = true;
			}
		}

		match &mut self.output {
			RecorderStateInner::Compact { .. } | RecorderStateInner::Stream(_) => {
				// not writing inline value (already
				// in parent node).
			},
			RecorderStateInner::Content { output, .. } => {
				let op = compact_content_proof::Op::<TrieHash<L>, &[u8]>::Value(value);
				let init_len = output.buf_len();
				op.encode_into(output);
				let written = output.buf_len() - init_len;
				res = self.limits.add_node(written, 0, false);
			},
		}
		res
	}

	// TODO this should be call also in all node (not only when not finding value):
	// then could just be part of enter node?
	#[must_use]
	fn record_skip_value(&mut self, items: &mut Vec<CompactEncodingInfos>) -> bool {
		let mut res = false;
		let mut op = None;
		if let RecorderStateInner::Content { .. } = &self.output {
			if let Some(item) = items.last_mut() {
				if item.accessed_value_node {
					return res
				}
				item.accessed_value_node = true;
				if !self.check_start_at(item.depth) {
					return res
				}
				let node_data = item.node.data();

				match item.node.node_plan() {
					NodePlan::Leaf { value, .. } |
					NodePlan::Branch { value: Some(value), .. } |
					NodePlan::NibbledBranch { value: Some(value), .. } => {
						op = Some(match value.build(node_data) {
							Value::Node(hash_slice) => {
								let mut hash = TrieHash::<L>::default();
								hash.as_mut().copy_from_slice(hash_slice);
								compact_content_proof::Op::<_, Vec<u8>>::HashValue(hash)
							},
							Value::Inline(value) =>
								compact_content_proof::Op::<TrieHash<L>, Vec<u8>>::Value(
									value.to_vec(),
								),
						});
					},
					_ => return res,
				}

				if self.flush_compact_content_pushes(item.depth) {
					res = true;
				}
			}
		}

		if let Some(op) = op {
			match &mut self.output {
				RecorderStateInner::Content { output, .. } => {
					let init_len = output.buf_len();
					op.encode_into(output);
					let written = output.buf_len() - init_len;
					res = self.limits.add_node(written, 0, false);
				},
				_ => (),
			}
		}
		res
	}

	fn finalize(&mut self, items: &Vec<CompactEncodingInfos>) {
		match &mut self.output {
			RecorderStateInner::Compact { output, proof, stacked_pos } => {
				let restarted_from = 0;
				if stacked_pos.len() > restarted_from {
					// halted: complete up to 0 and write all nodes keeping stack.
					let mut items = items.iter().rev();
					while let Some(pos) = stacked_pos.pop() {
						loop {
							let item = items.next().expect("pos stacked with an item");
							if !item.is_inline {
								proof[pos] = crate::trie_codec::encode_node_internal::<L::Codec>(
									&item.node,
									item.accessed_value_node,
									item.accessed_children_node,
								)
								.expect("TODO error handling, can it actually fail?");
								break
							}
						}
					}
				}
				for entry in core::mem::take(proof) {
					output.write_entry(entry.into());
				}
			},
			RecorderStateInner::Stream(_output) => {
				// all written
			},
			RecorderStateInner::Content { output: _, stacked_push, stacked_pop: _ } => {
				// TODO protect existing stack as for compact
				assert!(stacked_push.is_none());
				// TODO could use function with &item and &[item] as param
				// to skip this clone.
				for i in (0..items.len()).rev() {
					let item = items.get(i).expect("bounded iter");
					let items = &items[..i];
					let _ = self.record_popped_node(item, &items);
				}
			},
		}
	}
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

enum RecorderStateInner<O: RecorderOutput> {
	/// For FullNodes proofs, just send node to this stream.
	Stream(O),
	/// For FullNodes proofs, Requires keeping all proof before sending it.
	Compact {
		output: O,
		proof: Vec<Vec<u8>>,
		/// Stacked position in proof to modify proof as needed
		/// when information got accessed.
		stacked_pos: Vec<usize>,
	},
	/// For FullNodes proofs, just send node to this stream.
	Content {
		output: O,
		// push current todos.
		stacked_push: Option<NibbleVec>,
		// pop from depth.
		stacked_pop: Option<usize>,
	},
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateRecord<O: RecorderOutput, L: TrieLayout> {
	currently_query_item: Option<InMemQueryPlanItem>,
	stack: RecordStack<O, L>,
	// This indicate a restore point, it takes precedence over
	// stack and currently_query_item.
	from: Option<(Vec<u8>, bool)>,
}

impl<O: RecorderOutput, L: TrieLayout> HaltedStateRecord<O, L> {
	/// Indicate we reuse the query plan iterator
	/// and stack.
	pub fn statefull(&mut self, recorder: Recorder<O, L>) -> Recorder<O, L> {
		let result = core::mem::replace(&mut self.stack.recorder, recorder);
		result
	}

	/// Indicate to use stateless (on a fresh proof
	/// and a fresh query plan iterator).
	pub fn stateless(&mut self, recorder: Recorder<O, L>) -> Recorder<O, L> {
		let new_start = Self::from_start(recorder);
		let old = core::mem::replace(self, new_start);
		self.from = old.from;
		self.currently_query_item = None;
		old.stack.recorder
	}

	/// Init from start.
	pub fn from_start(recorder: Recorder<O, L>) -> Self {
		Self::from_at(recorder, None)
	}

	/// Init from position or start.
	pub fn from_at(recorder: Recorder<O, L>, at: Option<(Vec<u8>, bool)>) -> Self {
		HaltedStateRecord {
			currently_query_item: None,
			stack: RecordStack {
				recorder,
				items: Vec::new(),
				prefix: NibbleVec::new(),
				iter_prefix: None,
				halt: false,
				seek: None,
			},
			from: at,
		}
	}

	pub fn stopped_at(&self) -> Option<(Vec<u8>, bool)> {
		self.from.clone()
	}

	pub fn is_finished(&self) -> bool {
		self.from == None
	}

	pub fn finish(self) -> Recorder<O, L> {
		self.stack.recorder
	}
}

/// When process is halted keep execution state
/// to restore later.
pub enum HaltedStateCheck<'a, L: TrieLayout, C, D: SplitFirst> {
	Node(HaltedStateCheckNode<'a, L, C, D>),
	Content(HaltedStateCheckContent<'a, L, C>),
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateCheckNode<'a, L: TrieLayout, C, D: SplitFirst> {
	query_plan: QueryPlan<'a, C>,
	current: Option<QueryPlanItem<'a>>,
	stack: ReadStack<L, D>,
	state: ReadProofState,
	restore_offset: usize,
}

impl<'a, L: TrieLayout, C, D: SplitFirst> From<QueryPlan<'a, C>>
	for HaltedStateCheckNode<'a, L, C, D>
{
	fn from(query_plan: QueryPlan<'a, C>) -> Self {
		let is_compact = match query_plan.kind {
			ProofKind::FullNodes => false,
			ProofKind::CompactNodes => true,
			_ => false,
		};

		HaltedStateCheckNode {
			stack: ReadStack {
				items: Default::default(),
				start_items: 0,
				prefix: Default::default(),
				is_compact,
				expect_value: false,
				iter_prefix: None,
				_ph: PhantomData,
			},
			state: ReadProofState::NotStarted,
			current: None,
			restore_offset: 0,
			query_plan,
		}
	}
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateCheckContent<'a, L: TrieLayout, C> {
	query_plan: QueryPlan<'a, C>,
	current: Option<QueryPlanItem<'a>>,
	stack: ReadContentStack<L>,
	state: ReadProofState,
	restore_offset: usize,
}

impl<'a, L: TrieLayout, C> From<QueryPlan<'a, C>> for HaltedStateCheckContent<'a, L, C> {
	fn from(query_plan: QueryPlan<'a, C>) -> Self {
		HaltedStateCheckContent {
			stack: ReadContentStack {
				items: Default::default(),
				start_items: 0,
				prefix: Default::default(),
				expect_value: false,
				iter_prefix: None,
				_ph: PhantomData,
			},
			state: ReadProofState::NotStarted,
			current: None,
			restore_offset: 0,
			query_plan,
		}
	}
}

struct RecordStack<O: RecorderOutput, L: TrieLayout> {
	recorder: Recorder<O, L>,
	items: Vec<CompactEncodingInfos>,
	prefix: NibbleVec,
	iter_prefix: Option<(usize, bool)>,
	seek: Option<NibbleVec>,
	halt: bool,
}

/// Run query plan on a full db and record it.
///
/// TODO output and restart are mutually exclusive. -> enum
/// or remove output from halted state.
pub fn record_query_plan<
	'a,
	L: TrieLayout,
	I: Iterator<Item = QueryPlanItem<'a>>,
	O: RecorderOutput,
>(
	db: &TrieDB<L>,
	query_plan: &mut QueryPlan<'a, I>,
	mut from: HaltedStateRecord<O, L>,
) -> Result<HaltedStateRecord<O, L>, VerifyError<TrieHash<L>, CError<L>>> {
	// TODO
	//) resto
	//	let restore_buf;
	let dummy_parent_hash = TrieHash::<L>::default();
	let mut stateless = false;
	let mut statefull = None;
	// When define we iter prefix in a node but really want the next non inline.
	if let Some(lower_bound) = from.from.take() {
		if from.currently_query_item.is_none() {
			stateless = true;
			let mut bound = NibbleVec::new();
			bound.append_optional_slice_and_nibble(Some(&NibbleSlice::new(&lower_bound.0)), None);
			if lower_bound.1 {
				bound.pop();
			}
			from.stack.recorder.start_at = Some(bound.len());
			from.stack.seek = Some(bound);
		} else {
			let bound_len = lower_bound.0.len() * nibble_ops::NIBBLE_PER_BYTE -
				if lower_bound.1 { 2 } else { 1 };
			//			from.stack.recorder.start_at = Some(bound_len);
			statefull = Some(bound_len);
		}
	}

	let mut stack = &mut from.stack;

	let mut prev_query: Option<QueryPlanItem> = None;
	let from_query = from.currently_query_item.take();
	let mut from_query_ref = from_query.as_ref().map(|f| f.as_ref());
	while let Some(query) = from_query_ref.clone().or_else(|| query_plan.items.next()) {
		if stateless {
			let bound = stack.seek.as_ref().expect("Initiated for stateless");
			let bound = bound.as_leftnibbleslice();
			let query_slice = LeftNibbleSlice::new(&query.key);
			if query_slice.starts_with(&bound) {
			} else if query.as_prefix {
				if bound.starts_with(&query_slice) {
				} else {
					continue
				}
			} else {
				continue
			}
			stateless = false;
			if !query.as_prefix {
				stack.seek = None;
			}
		}
		let common_nibbles = if let Some(slice_at) = statefull.take() {
			slice_at
		} else {
			let (ordered, common_nibbles) =
				prev_query.as_ref().map(|p| p.before(&query)).unwrap_or((true, 0));
			if !ordered {
				if query_plan.ignore_unordered {
					continue
				} else {
					return Err(VerifyError::UnorderedKey(query.key.to_vec()))
				}
			}
			loop {
				match stack.prefix.len().cmp(&common_nibbles) {
					Ordering::Equal | Ordering::Less => break,
					Ordering::Greater => {
						if query_plan.kind.record_inline() {
							from = try_stack_inline_child(from, db, NIBBLE_LENGTH as u8)?;
							stack = &mut from.stack;
						}
						if !stack.pop() {
							stack.recorder.finalize(&stack.items);
							return Ok(from)
						}
					},
				}
			}
			common_nibbles
		};
		if let Some((_, hash_only)) = stack.iter_prefix.clone() {
			// statefull halted during iteration.
			let (f, halt) = iter_prefix::<L, O>(from, Some(&query), db, hash_only, false, false)?;
			if halt {
				return Ok(f)
			} else {
				from = f;
				stack = &mut from.stack;
			}
			from_query_ref = None;
			prev_query = Some(query);
			continue
		}
		// descend
		let mut slice_query = NibbleSlice::new_offset(&query.key, common_nibbles);
		let touched = loop {
			if !stack.items.is_empty() {
				if slice_query.is_empty() {
					if query.as_prefix {
						let (f, halt) = iter_prefix::<L, O>(
							from,
							Some(&query),
							db,
							query.hash_only,
							true,
							false,
						)?;
						if halt {
							return Ok(f)
						} else {
							from = f;
							stack = &mut from.stack;
						}
						break false
					} else {
						break true
					}
				} else {
					if stack.recorder.record_skip_value(&mut stack.items) {
						stack.halt = true;
					}
				}
			}

			let child_index = if stack.items.is_empty() { 0 } else { slice_query.at(0) };
			if query_plan.kind.record_inline() {
				from = try_stack_inline_child(from, db, child_index)?;
				stack = &mut from.stack;
			}
			stack.items.last_mut().map(|i| {
				// TODO only needed for content but could be better to be always aligned
				i.next_descended_child = child_index + 1;
			});
			match stack.try_stack_child(
				child_index,
				db,
				dummy_parent_hash,
				Some(&mut slice_query),
				false,
			)? {
				TryStackChildResult::Stacked => {},
				TryStackChildResult::NotStackedBranch | TryStackChildResult::NotStacked =>
					break false,
				TryStackChildResult::StackedDescendIncomplete => {
					if query.as_prefix {
						let (f, halt) = iter_prefix::<L, O>(
							from,
							Some(&query),
							db,
							query.hash_only,
							true,
							false,
						)?;
						if halt {
							return Ok(f)
						} else {
							from = f;
							stack = &mut from.stack;
						}
					}
					break false
				},
				TryStackChildResult::Halted => {
					stack.halt = false;
					stack.prefix.push(child_index);
					from.from = Some((
						stack.prefix.inner().to_vec(),
						(stack.prefix.len() % nibble_ops::NIBBLE_PER_BYTE) != 0,
					));
					stack.prefix.pop();
					from.currently_query_item = Some(query.to_owned());
					stack.recorder.finalize(&stack.items);
					return Ok(from)
				},
			}
		};

		if touched {
			// try access value
			stack.access_value(db, query.hash_only)?;
		}
		from_query_ref = None;
		prev_query = Some(query);
	}
	loop {
		if query_plan.kind.record_inline() {
			from = try_stack_inline_child(from, db, NIBBLE_LENGTH as u8)?;
			stack = &mut from.stack;
		}

		if !stack.pop() {
			break
		}
	}
	stack.recorder.finalize(&stack.items);
	Ok(from)
}

fn try_stack_inline_child<'a, L: TrieLayout, O: RecorderOutput>(
	mut from: HaltedStateRecord<O, L>,
	db: &TrieDB<L>,
	upper: u8,
) -> Result<HaltedStateRecord<O, L>, VerifyError<TrieHash<L>, CError<L>>> {
	let dummy_parent_hash = TrieHash::<L>::default();
	let mut stack = &mut from.stack;
	if let Some(item) = stack.items.last() {
		let pre = item.next_descended_child; // TODO put next_descended child to 16 for leaf (skip some noop iter)
		for i in pre..upper as u8 {
			match stack.try_stack_child(i, db, dummy_parent_hash, None, true)? {
				// only expect a stacked prefix here
				TryStackChildResult::Stacked => {
					let (f, halt) = iter_prefix::<L, O>(from, None, db, false, true, true)?;
					if halt {
						// no halt on inline.
						unreachable!()
					} else {
						from = f;
						stack = &mut from.stack;
						stack.pop();
					}
				},
				TryStackChildResult::NotStackedBranch => (),
				_ => break,
			}
		}
	}
	stack.items.last_mut().map(|i| i.next_descended_child = upper);
	Ok(from)
}

fn iter_prefix<L: TrieLayout, O: RecorderOutput>(
	mut from: HaltedStateRecord<O, L>,
	prev_query: Option<&QueryPlanItem>,
	db: &TrieDB<L>,
	hash_only: bool,
	first_iter: bool,
	inline_iter: bool,
) -> Result<(HaltedStateRecord<O, L>, bool), VerifyError<TrieHash<L>, CError<L>>> {
	let stack = &mut from.stack;
	let dummy_parent_hash = TrieHash::<L>::default();
	if first_iter {
		stack.enter_prefix_iter(hash_only);
	}

	// run prefix iteration
	let mut stacked = first_iter;
	loop {
		// descend
		loop {
			if stacked {
				// try access value in next node
				stack.access_value(db, hash_only)?;
				stacked = false;
			}

			let child_index = if let Some(mut item) = stack.items.last_mut() {
				if item.next_descended_child as usize >= NIBBLE_LENGTH {
					break
				}
				item.next_descended_child += 1;
				item.next_descended_child - 1
			} else {
				break
			};

			match stack.try_stack_child(child_index, db, dummy_parent_hash, None, inline_iter)? {
				TryStackChildResult::Stacked => {
					stacked = true;
				},
				TryStackChildResult::NotStackedBranch => (),
				TryStackChildResult::NotStacked => break,
				TryStackChildResult::StackedDescendIncomplete => {
					unreachable!("no slice query")
				},
				TryStackChildResult::Halted => {
					if let Some(mut item) = stack.items.last_mut() {
						item.next_descended_child -= 1;
					}
					stack.halt = false;
					stack.prefix.push(child_index);
					from.from = Some((
						stack.prefix.inner().to_vec(),
						(stack.prefix.len() % nibble_ops::NIBBLE_PER_BYTE) != 0,
					));
					stack.prefix.pop();
					from.currently_query_item = prev_query.map(|q| q.to_owned());
					stack.recorder.finalize(&stack.items);
					return Ok((from, true))
				},
			}
		}

		// pop
		if !stack.pop() {
			break
		}
	}
	stack.exit_prefix_iter();
	Ok((from, false))
}

enum TryStackChildResult {
	Stacked,
	NotStackedBranch,
	NotStacked,
	StackedDescendIncomplete,
	Halted,
}

impl<O: RecorderOutput, L: TrieLayout> RecordStack<O, L> {
	fn try_stack_child<'a>(
		&mut self,
		child_index: u8,
		db: &TrieDB<L>,
		parent_hash: TrieHash<L>,
		mut slice_query: Option<&mut NibbleSlice>,
		inline_only: bool,
	) -> Result<TryStackChildResult, VerifyError<TrieHash<L>, CError<L>>> {
		let mut is_inline = false;
		let prefix = &mut self.prefix;
		let stack = &mut self.items;
		let mut descend_incomplete = false;
		let mut stack_extension = false;
		let mut from_branch = None;
		let child_handle = if let Some(item) = stack.last_mut() {
			let node_data = item.node.data();

			match item.node.node_plan() {
				NodePlan::Empty | NodePlan::Leaf { .. } =>
					return Ok(TryStackChildResult::NotStacked),
				NodePlan::Extension { child, .. } =>
					if child_index == 0 {
						let child_handle = child.build(node_data);
						if let &NodeHandle::Hash(_) = &child_handle {
							item.accessed_children_node.set(child_index as usize, true);
						}
						child_handle
					} else {
						return Ok(TryStackChildResult::NotStacked)
					},
				NodePlan::NibbledBranch { children, .. } | NodePlan::Branch { children, .. } =>
					if let Some(child) = &children[child_index as usize] {
						from_branch = Some(&mut item.accessed_children_node);
						child.build(node_data)
					} else {
						return Ok(TryStackChildResult::NotStackedBranch)
					},
			}
		} else {
			NodeHandle::Hash(db.root().as_ref())
		};
		if let &NodeHandle::Inline(_) = &child_handle {
			// TODO consider not going into inline for all proof but content.
			// Returning NotStacked here sounds safe, then the is_inline field is not needed.
			is_inline = true;
		} else {
			if inline_only {
				return Ok(TryStackChildResult::NotStackedBranch)
			}
			if self.halt && from_branch.is_some() {
				return Ok(TryStackChildResult::Halted)
			}
		}
		if let Some(accessed_children_node) = from_branch {
			if !is_inline || self.recorder.mark_inline_access() {
				accessed_children_node.set(child_index as usize, true);
			}

			slice_query.as_mut().map(|s| s.advance(1));
			prefix.push(child_index);
		}
		// TODO handle cache first
		let child_node = db
			.get_raw_or_lookup_with_cache(parent_hash, child_handle, prefix.as_prefix(), false)
			.map_err(|_| VerifyError::IncompleteProof)?; // actually incomplete db: TODO consider switching error

		// TODO put in proof (only if Hash or inline for content one)

		let node_data = child_node.0.data();
		//println!("r: {:?}", &node_data);

		match child_node.0.node_plan() {
			NodePlan::Branch { .. } => (),
			| NodePlan::Empty => (),
			NodePlan::Leaf { partial, .. } |
			NodePlan::NibbledBranch { partial, .. } |
			NodePlan::Extension { partial, .. } => {
				let partial = partial.build(node_data);
				prefix.append_partial(partial.right());
				if let Some(s) = slice_query.as_mut() {
					if s.starts_with(&partial) {
						s.advance(partial.len());
					} else {
						descend_incomplete = true;
					}
				}
			},
		}
		if let NodePlan::Extension { .. } = child_node.0.node_plan() {
			stack_extension = true;
		}
		let next_descended_child = if let Some(seek) = self.seek.as_ref() {
			if prefix.len() < seek.len() {
				seek.at(prefix.len())
			} else {
				self.seek = None;
				0
			}
		} else {
			0
		};
		let infos = CompactEncodingInfos {
			node: child_node.0,
			accessed_children_node: Default::default(),
			accessed_value_node: false,
			depth: prefix.len(),
			next_descended_child,
			is_inline,
		};
		if self
			.recorder
			.record_stacked_node(&infos, stack.is_empty(), child_index, &*stack)
		{
			self.halt = true;
		}
		stack.push(infos);
		if stack_extension {
			let sbranch = self.try_stack_child(0, db, parent_hash, slice_query, inline_only)?;
			let TryStackChildResult::Stacked = sbranch else {
				return Err(VerifyError::InvalidChildReference(b"branch in db should follow extension".to_vec()));
			};
		}

		if descend_incomplete {
			Ok(TryStackChildResult::StackedDescendIncomplete)
		} else {
			Ok(TryStackChildResult::Stacked)
		}
	}

	fn access_value<'a>(
		&mut self,
		db: &TrieDB<L>,
		hash_only: bool,
	) -> Result<bool, VerifyError<TrieHash<L>, CError<L>>> {
		let Some(item)= self.items.last_mut() else {
			return Ok(false)
		};
		// TODO this could be reuse from iterator, but it seems simple
		// enough here too.
		let node_data = item.node.data();

		let value = match item.node.node_plan() {
			NodePlan::Leaf { value, .. } => value.build(node_data),
			NodePlan::Branch { value, .. } | NodePlan::NibbledBranch { value, .. } => {
				if let Some(value) = value {
					value.build(node_data)
				} else {
					return Ok(false)
				}
			},
			_ => return Ok(false),
		};
		match value {
			Value::Node(hash_slice) =>
				if !hash_only {
					item.accessed_value_node = true;
					let mut hash = TrieHash::<L>::default();
					hash.as_mut().copy_from_slice(hash_slice);
					let Some(value) = db.db().get(&hash, self.prefix.as_prefix()) else {
						return Err(VerifyError::IncompleteProof);
					};
					if self.recorder.record_value_node(value, self.prefix.len()) {
						self.halt = true;
					}
				} else {
					if self.recorder.record_skip_value(&mut self.items) {
						self.halt = true;
					}
				},
			Value::Inline(value) =>
				if self.recorder.record_value_inline(value, self.prefix.len()) {
					self.halt = true;
				},
		}
		Ok(true)
	}

	fn pop(&mut self) -> bool {
		if self.iter_prefix.map(|(l, _)| l == self.items.len()).unwrap_or(false) {
			return false
		}
		if let Some(item) = self.items.pop() {
			if self.recorder.record_popped_node(&item, &self.items) {
				self.halt = true;
			}
			let depth = self.items.last().map(|i| i.depth).unwrap_or(0);
			self.prefix.drop_lasts(self.prefix.len() - depth);
			if depth == item.depth {
				// Two consecutive identical depth is an extension
				self.pop();
			}
			true
		} else {
			false
		}
	}

	fn enter_prefix_iter(&mut self, hash_only: bool) {
		self.iter_prefix = Some((self.items.len(), hash_only));
	}

	fn exit_prefix_iter(&mut self) {
		self.iter_prefix = None
	}
}

/// Proof reading iterator.
pub struct ReadProofIterator<'a, L, C, D, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = D>,
	D: SplitFirst,
{
	// always needed, this is option only
	// to avoid unsafe code when halting.
	query_plan: Option<QueryPlan<'a, C>>,
	proof: P,
	is_compact: bool,
	expected_root: Option<TrieHash<L>>,
	current: Option<QueryPlanItem<'a>>,
	state: ReadProofState,
	stack: ReadStack<L, D>,
	restore_offset: usize,
}

/// Proof reading iterator.
pub struct ReadProofContentIterator<'a, L, C, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = Option<compact_content_proof::Op<TrieHash<L>, Vec<u8>>>>,
{
	// always needed, this is option only
	// to avoid unsafe code when halting.
	query_plan: Option<QueryPlan<'a, C>>,
	proof: P,
	expected_root: Option<TrieHash<L>>,
	current: Option<QueryPlanItem<'a>>,
	state: ReadProofState,
	stack: ReadContentStack<L>,
	restore_offset: usize,
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

struct ItemContentStack<L: TrieLayout> {
	children: Vec<Option<TrieHash<L>>>,
	inline_value: Option<Vec<u8>>,
	attached_value_hash: Option<TrieHash<L>>,
	depth: usize,
	next_descended_child: u8,
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
	iter_prefix: Option<(usize, bool, bool)>,
	start_items: usize,
	expect_value: bool,
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

/// Content return on success when reading proof.
pub enum ReadProofItem<'a, L: TrieLayout, C, D: SplitFirst> {
	/// Successfull read of proof, not all content read.
	Halted(Box<HaltedStateCheck<'a, L, C, D>>),
	/// Seen value and key in proof.
	/// We only return content matching the query plan.
	Value(Cow<'a, [u8]>, Vec<u8>),
	/// Seen hash of value and key in proof.
	/// We only return content matching the query plan.
	Hash(Cow<'a, [u8]>, TrieHash<L>),
	/// No value seen for a key in the input query plan.
	NoValue(&'a [u8]),
	/// Seen fully covered prefix in proof, this is only
	/// return when we read the proof with the query input (otherwhise
	/// we would need to indicate every child without a hash as a prefix).
	StartPrefix(&'a [u8]),
	/// End of a previously start prefix.
	EndPrefix,
}

impl<'a, L, C, D, P> Iterator for ReadProofIterator<'a, L, C, D, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = D>,
	D: SplitFirst,
{
	type Item = Result<ReadProofItem<'a, L, C, D>, VerifyError<TrieHash<L>, CError<L>>>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.state == ReadProofState::Finished {
			return None
		}
		let check_hash = self.expected_root.is_some();
		let mut to_check_slice = if self.state == ReadProofState::Halted {
			self.state = ReadProofState::Running;
			self.current
				.as_ref()
				.map(|n| NibbleSlice::new_offset(n.key, self.restore_offset))
		} else {
			self.current.as_ref().map(|n| NibbleSlice::new(n.key))
		};

		// read proof
		loop {
			if self.state == ReadProofState::SwitchQueryPlan ||
				self.state == ReadProofState::NotStarted
			{
				let query_plan = self.query_plan.as_mut().expect("Removed with state");
				if let Some(next) = query_plan.items.next() {
					let (ordered, common_nibbles) = if let Some(old) = self.current.as_ref() {
						old.before(&next)
					} else {
						(true, 0)
					};
					if !ordered {
						if query_plan.ignore_unordered {
							continue
						} else {
							self.state = ReadProofState::Finished;
							return Some(Err(VerifyError::UnorderedKey(next.key.to_vec())))
						}
					}

					let r = self.stack.pop_until(common_nibbles, &self.expected_root, false);
					if let Err(e) = r {
						self.state = ReadProofState::Finished;
						return Some(Err(e))
					}
					self.state = ReadProofState::Running;
					self.current = Some(next);
					to_check_slice = self
						.current
						.as_ref()
						.map(|n| NibbleSlice::new_offset(n.key, common_nibbles));
				} else {
					self.state = ReadProofState::PlanConsumed;
					self.current = None;
					break
				}
			};
			let did_prefix = self.stack.iter_prefix.is_some();
			while let Some((_, accessed_value_node, hash_only)) = self.stack.iter_prefix.clone() {
				// prefix iteration
				if !accessed_value_node {
					self.stack.iter_prefix.as_mut().map(|s| {
						s.1 = true;
					});
					match self.stack.access_value(&mut self.proof, check_hash, hash_only) {
						Ok((Some(value), None)) =>
							return Some(Ok(ReadProofItem::Value(
								self.stack.prefix.inner().to_vec().into(),
								value,
							))),
						Ok((None, Some(hash))) =>
							return Some(Ok(ReadProofItem::Hash(
								self.stack.prefix.inner().to_vec().into(),
								hash,
							))),
						Ok((None, None)) => (),
						Ok(_) => unreachable!(),
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
					};
				}
				while let Some(child_index) = self.stack.items.last_mut().and_then(|last| {
					if last.next_descended_child as usize >= NIBBLE_LENGTH {
						None
					} else {
						let child_index = last.next_descended_child;
						last.next_descended_child += 1;
						Some(child_index)
					}
				}) {
					let r = match self.stack.try_stack_child(
						child_index,
						&mut self.proof,
						&self.expected_root,
						None,
						false,
					) {
						Ok(r) => r,
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
					};
					match r {
						TryStackChildResult::Stacked => {
							self.stack.iter_prefix.as_mut().map(|p| {
								p.1 = false;
							});
							break
						},
						TryStackChildResult::StackedDescendIncomplete => {
							unreachable!("slice query none");
						},
						TryStackChildResult::NotStacked => break,
						TryStackChildResult::NotStackedBranch => (),
						TryStackChildResult::Halted => {
							if let Some(last) = self.stack.items.last_mut() {
								last.next_descended_child -= 1;
							}
							return self.halt(None)
						},
					}
				}
				if self.stack.iter_prefix.as_ref().map(|p| p.1).unwrap_or_default() {
					if !match self.stack.pop(&self.expected_root) {
						Ok(r) => r,
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
					} {
						// end iter
						self.stack.exit_prefix_iter();
					}
				}
			}
			if did_prefix {
				// exit a prefix iter, next content looping
				self.state = ReadProofState::SwitchQueryPlan;
				continue
			}
			let to_check = self.current.as_ref().expect("Init above");
			let to_check_len = to_check.key.len() * nibble_ops::NIBBLE_PER_BYTE;
			let mut to_check_slice = to_check_slice.as_mut().expect("Init above");
			let as_prefix = to_check.as_prefix; // TODO useless?
			let hash_only = to_check.hash_only; // TODO useless?
			let mut at_value = false;
			match self.stack.prefix.len().cmp(&to_check_len) {
				Ordering::Equal =>
					if !self.stack.items.is_empty() {
						at_value = true;
					},
				Ordering::Less => (),
				Ordering::Greater => {
					unreachable!();
				},
			}

			if at_value {
				if as_prefix {
					self.stack.enter_prefix_iter(hash_only);
					continue
				}
				self.state = ReadProofState::SwitchQueryPlan;
				match self.stack.access_value(&mut self.proof, check_hash, hash_only) {
					Ok((Some(value), None)) =>
						return Some(Ok(ReadProofItem::Value(to_check.key.into(), value))),
					Ok((None, Some(hash))) =>
						return Some(Ok(ReadProofItem::Hash(to_check.key.into(), hash))),
					Ok((None, None)) => return Some(Ok(ReadProofItem::NoValue(to_check.key))),
					Ok(_) => unreachable!(),
					Err(e) => {
						self.state = ReadProofState::Finished;
						return Some(Err(e))
					},
				}
			}

			let child_index = if self.stack.items.len() == 0 {
				// dummy
				0
			} else {
				to_check_slice.at(0)
			};
			let r = match self.stack.try_stack_child(
				child_index,
				&mut self.proof,
				&self.expected_root,
				Some(&mut to_check_slice),
				to_check.as_prefix,
			) {
				Ok(r) => r,
				Err(e) => {
					self.state = ReadProofState::Finished;
					return Some(Err(e))
				},
			};
			match r {
				TryStackChildResult::Stacked => (),
				TryStackChildResult::StackedDescendIncomplete => {
					if as_prefix {
						self.stack.enter_prefix_iter(hash_only);
						continue
					}
					self.state = ReadProofState::SwitchQueryPlan;
					return Some(Ok(ReadProofItem::NoValue(to_check.key)))
				},
				TryStackChildResult::NotStacked => {
					self.state = ReadProofState::SwitchQueryPlan;
					return Some(Ok(ReadProofItem::NoValue(to_check.key)))
				},
				TryStackChildResult::NotStackedBranch => {
					self.state = ReadProofState::SwitchQueryPlan;
					return Some(Ok(ReadProofItem::NoValue(to_check.key)))
				},
				TryStackChildResult::Halted => return self.halt(Some(to_check_slice)),
			}
		}

		debug_assert!(self.state == ReadProofState::PlanConsumed);
		if self.is_compact {
			let stack_to = 0; // TODO restart is different
				  //					let r = self.stack.pop_until(common_nibbles, &self.expected_root);
			let r = self.stack.pop_until(stack_to, &self.expected_root, false);
			if let Err(e) = r {
				self.state = ReadProofState::Finished;
				return Some(Err(e))
			}
		} else {
			if self.proof.next().is_some() {
				self.state = ReadProofState::Finished;
				return Some(Err(VerifyError::ExtraneousNode))
			}
		}
		self.state = ReadProofState::Finished;
		return None
	}
}

impl<'a, L, C, P> Iterator for ReadProofContentIterator<'a, L, C, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = Option<compact_content_proof::Op<TrieHash<L>, Vec<u8>>>>,
{
	type Item = Result<ReadProofItem<'a, L, C, Vec<u8>>, VerifyError<TrieHash<L>, CError<L>>>;

	fn next(&mut self) -> Option<Self::Item> {
		todo!()
		/*
		if self.state == ReadProofState::Finished {
			return None
		}
		let check_hash = self.expected_root.is_some();
		let mut to_check_slice = if self.state == ReadProofState::Halted {
			self.state = ReadProofState::Running;
			self.current
				.as_ref()
				.map(|n| NibbleSlice::new_offset(n.key, self.restore_offset))
		} else {
			self.current.as_ref().map(|n| NibbleSlice::new(n.key))
		};

		// read proof
		loop {
			if self.state == ReadProofState::SwitchQueryPlan ||
				self.state == ReadProofState::NotStarted
			{
				let query_plan = self.query_plan.as_mut().expect("Removed with state");
				if let Some(next) = query_plan.items.next() {
					let (ordered, common_nibbles) = if let Some(old) = self.current.as_ref() {
						old.before(&next)
					} else {
						(true, 0)
					};
					if !ordered {
						if query_plan.ignore_unordered {
							continue
						} else {
							self.state = ReadProofState::Finished;
							return Some(Err(VerifyError::UnorderedKey(next.key.to_vec())))
						}
					}

					let r = self.stack.pop_until(common_nibbles, &self.expected_root, false);
					if let Err(e) = r {
						self.state = ReadProofState::Finished;
						return Some(Err(e))
					}
					self.state = ReadProofState::Running;
					self.current = Some(next);
					to_check_slice = self
						.current
						.as_ref()
						.map(|n| NibbleSlice::new_offset(n.key, common_nibbles));
				} else {
					self.state = ReadProofState::PlanConsumed;
					self.current = None;
					break
				}
			};
			let did_prefix = self.stack.iter_prefix.is_some();
			while let Some((_, accessed_value_node, hash_only)) = self.stack.iter_prefix.clone() {
				// prefix iteration
				if !accessed_value_node {
					self.stack.iter_prefix.as_mut().map(|s| {
						s.1 = true;
					});
					match self.stack.access_value(&mut self.proof, check_hash, hash_only) {
						Ok((Some(value), None)) =>
							return Some(Ok(ReadProofItem::Value(
								self.stack.prefix.inner().to_vec().into(),
								value,
							))),
						Ok((None, Some(hash))) =>
							return Some(Ok(ReadProofItem::Hash(
								self.stack.prefix.inner().to_vec().into(),
								hash,
							))),
						Ok((None, None)) => (),
						Ok(_) => unreachable!(),
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
					};
				}
				while let Some(child_index) = self.stack.items.last_mut().and_then(|last| {
					if last.next_descended_child as usize >= NIBBLE_LENGTH {
						None
					} else {
						let child_index = last.next_descended_child;
						last.next_descended_child += 1;
						Some(child_index)
					}
				}) {
					let r = match self.stack.try_stack_child(
						child_index,
						&mut self.proof,
						&self.expected_root,
						None,
						false,
					) {
						Ok(r) => r,
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
					};
					match r {
						TryStackChildResult::Stacked => {
							self.stack.iter_prefix.as_mut().map(|p| {
								p.1 = false;
							});
							break
						},
						TryStackChildResult::StackedDescendIncomplete => {
							unreachable!("slice query none");
						},
						TryStackChildResult::NotStacked => break,
						TryStackChildResult::NotStackedBranch => (),
						TryStackChildResult::Halted => {
							if let Some(last) = self.stack.items.last_mut() {
								last.next_descended_child -= 1;
							}
							return self.halt(None)
						},
					}
				}
				if self.stack.iter_prefix.as_ref().map(|p| p.1).unwrap_or_default() {
					if !match self.stack.pop(&self.expected_root) {
						Ok(r) => r,
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
					} {
						// end iter
						self.stack.exit_prefix_iter();
					}
				}
			}
			if did_prefix {
				// exit a prefix iter, next content looping
				self.state = ReadProofState::SwitchQueryPlan;
				continue
			}
			let to_check = self.current.as_ref().expect("Init above");
			let to_check_len = to_check.key.len() * nibble_ops::NIBBLE_PER_BYTE;
			let mut to_check_slice = to_check_slice.as_mut().expect("Init above");
			let as_prefix = to_check.as_prefix; // TODO useless?
			let hash_only = to_check.hash_only; // TODO useless?
			let mut at_value = false;
			match self.stack.prefix.len().cmp(&to_check_len) {
				Ordering::Equal =>
					if !self.stack.items.is_empty() {
						at_value = true;
					},
				Ordering::Less => (),
				Ordering::Greater => {
					unreachable!();
				},
			}

			if at_value {
				if as_prefix {
					self.stack.enter_prefix_iter(hash_only);
					continue
				}
				self.state = ReadProofState::SwitchQueryPlan;
				match self.stack.access_value(&mut self.proof, check_hash, hash_only) {
					Ok((Some(value), None)) =>
						return Some(Ok(ReadProofItem::Value(to_check.key.into(), value))),
					Ok((None, Some(hash))) =>
						return Some(Ok(ReadProofItem::Hash(to_check.key.into(), hash))),
					Ok((None, None)) => return Some(Ok(ReadProofItem::NoValue(to_check.key))),
					Ok(_) => unreachable!(),
					Err(e) => {
						self.state = ReadProofState::Finished;
						return Some(Err(e))
					},
				}
			}

			let child_index = if self.stack.items.len() == 0 {
				// dummy
				0
			} else {
				to_check_slice.at(0)
			};
			let r = match self.stack.try_stack_child(
				child_index,
				&mut self.proof,
				&self.expected_root,
				Some(&mut to_check_slice),
				to_check.as_prefix,
			) {
				Ok(r) => r,
				Err(e) => {
					self.state = ReadProofState::Finished;
					return Some(Err(e))
				},
			};
			match r {
				TryStackChildResult::Stacked => (),
				TryStackChildResult::StackedDescendIncomplete => {
					if as_prefix {
						self.stack.enter_prefix_iter(hash_only);
						continue
					}
					self.state = ReadProofState::SwitchQueryPlan;
					return Some(Ok(ReadProofItem::NoValue(to_check.key)))
				},
				TryStackChildResult::NotStacked => {
					self.state = ReadProofState::SwitchQueryPlan;
					return Some(Ok(ReadProofItem::NoValue(to_check.key)))
				},
				TryStackChildResult::NotStackedBranch => {
					self.state = ReadProofState::SwitchQueryPlan;
					return Some(Ok(ReadProofItem::NoValue(to_check.key)))
				},
				TryStackChildResult::Halted => return self.halt(Some(to_check_slice)),
			}
		}

		debug_assert!(self.state == ReadProofState::PlanConsumed);
		if self.is_compact {
			let stack_to = 0; // TODO restart is different
				  //					let r = self.stack.pop_until(common_nibbles, &self.expected_root);
			let r = self.stack.pop_until(stack_to, &self.expected_root, false);
			if let Err(e) = r {
				self.state = ReadProofState::Finished;
				return Some(Err(e))
			}
		} else {
			if self.proof.next().is_some() {
				self.state = ReadProofState::Finished;
				return Some(Err(VerifyError::ExtraneousNode))
			}
		}
		self.state = ReadProofState::Finished;
		return None
			*/
	}
}

impl<'a, L, C, D, P> ReadProofIterator<'a, L, C, D, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = D>,
	D: SplitFirst,
{
	fn halt(
		&mut self,
		to_check_slice: Option<&mut NibbleSlice>,
	) -> Option<Result<ReadProofItem<'a, L, C, D>, VerifyError<TrieHash<L>, CError<L>>>> {
		if self.is_compact {
			let stack_to = 0; // TODO restart is different
			let r = self.stack.pop_until(stack_to, &self.expected_root, true);
			if let Err(e) = r {
				self.state = ReadProofState::Finished;
				return Some(Err(e))
			}
		}
		self.state = ReadProofState::Finished;
		let query_plan = crate::rstd::mem::replace(&mut self.query_plan, None);
		let query_plan = query_plan.expect("Init with state");
		let current = crate::rstd::mem::take(&mut self.current);
		let mut stack = crate::rstd::mem::replace(
			&mut self.stack,
			ReadStack {
				items: Default::default(),
				start_items: 0,
				prefix: Default::default(),
				is_compact: self.is_compact,
				expect_value: false,
				iter_prefix: None,
				_ph: PhantomData,
			},
		);
		stack.start_items = stack.items.len();
		Some(Ok(ReadProofItem::Halted(Box::new(HaltedStateCheck::Node(HaltedStateCheckNode {
			query_plan,
			current,
			stack,
			state: ReadProofState::Halted,
			restore_offset: to_check_slice.map(|s| s.offset()).unwrap_or(0),
		})))))
	}
}

/// Read the proof.
///
/// If expected root is None, then we do not check hashes at all.
pub fn verify_query_plan_iter<'a, L, C, D, P>(
	state: HaltedStateCheck<'a, L, C, D>,
	proof: P,
	expected_root: Option<TrieHash<L>>,
) -> Result<ReadProofIterator<'a, L, C, D, P>, VerifyError<TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = D>,
	D: SplitFirst,
{
	let HaltedStateCheck::Node(state) = state else {
		return Err(VerifyError::IncompleteProof) // TODO not kind as param if keeping CompactContent
	};
	let HaltedStateCheckNode { query_plan, current, stack, state, restore_offset } = state;

	match query_plan.kind {
		ProofKind::CompactContent => {
			return Err(VerifyError::IncompleteProof) // TODO not kind as param if keeping CompactContent
		},
		_ => (),
	};

	Ok(ReadProofIterator {
		query_plan: Some(query_plan),
		proof,
		is_compact: stack.is_compact,
		expected_root,
		current,
		state,
		stack,
		restore_offset,
	})
}

/// Read the proof.
///
/// If expected root is None, then we do not check hashes at all.
pub fn verify_query_plan_iter_content<'a, L, C, P>(
	state: HaltedStateCheck<'a, L, C, Vec<u8>>,
	proof: P,
	expected_root: Option<TrieHash<L>>,
) -> Result<ReadProofContentIterator<'a, L, C, P>, VerifyError<TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = Option<compact_content_proof::Op<TrieHash<L>, Vec<u8>>>>,
{
	let HaltedStateCheck::Content(state) = state else {
		return Err(VerifyError::IncompleteProof) // TODO not kind as param if keeping CompactContent
	};

	let HaltedStateCheckContent { query_plan, current, stack, state, restore_offset } = state;

	match query_plan.kind {
		ProofKind::CompactContent => (),
		_ => {
			return Err(VerifyError::IncompleteProof) // TODO not kind as param if keeping CompactContent
		},
	};

	Ok(ReadProofContentIterator {
		query_plan: Some(query_plan),
		proof,
		expected_root,
		current,
		state,
		stack,
		restore_offset,
	})
}

pub mod compact_content_proof {
	use super::RecorderOutput;
	use core::marker::PhantomData;

	/// Representation of each encoded action
	/// for building the proof.
	/// TODO ref variant for encoding ?? or key using V and use Op<&H, &[u8]>.
	#[derive(Debug)]
	pub enum Op<H, V> {
		// key content followed by a mask for last byte.
		// If mask erase some content the content need to
		// be set at 0 (or error).
		// Two consecutive `KeyPush` are invalid.
		KeyPush(Vec<u8>, u8), /* TODO could use BackingByteVec (but Vec for new as it scale
		                       * encode) */
		// Last call to pop is implicit (up to root), defining
		// one will result in an error.
		// Two consecutive `KeyPop` are invalid.
		// TODO should be compact encoding of number.
		KeyPop(u16),
		// u8 is child index, shorthand for key push one nibble followed by key pop.
		HashChild(H, u8),
		// All value variant are only after a `KeyPush` or at first position.
		HashValue(H),
		Value(V),
		// This is not strictly necessary, only if the proof is not sized, otherwhise if we know
		// the stream will end it can be skipped.
		EndProof,
	}

	// Limiting size to u32 (could also just use a terminal character).
	#[derive(Debug, PartialEq, Eq)]
	#[repr(transparent)]
	struct VarInt(u32);

	impl VarInt {
		fn encoded_len(&self) -> usize {
			if self.0 == 0 {
				return 1
			}
			let len = 32 - self.0.leading_zeros() as usize;
			if len % 7 == 0 {
				len / 7
			} else {
				len / 7 + 1
			}
			/*
			match self.0 {
				l if l < 2 ^ 7 => 1, // leading 0: 25
				l if l < 2 ^ 14 => 2, // leading 0: 18

				l if l < 2 ^ 21 => 3, // 11
				l if l < 2 ^ 28 => 4, // 4
				_ => 5,
			}
			*/
		}

		fn encode_into(&self, out: &mut impl RecorderOutput) {
			let mut to_encode = self.0;
			for _ in 0..self.encoded_len() - 1 {
				out.write_bytes(&[0b1000_0000 | to_encode as u8]);
				to_encode >>= 7;
			}
			out.write_bytes(&[to_encode as u8]);
		}

		fn decode(encoded: &[u8]) -> Result<(Self, usize), ()> {
			let mut value = 0u32;
			for (i, byte) in encoded.iter().enumerate() {
				let last = byte & 0b1000_0000 == 0;
				value |= ((byte & 0b0111_1111) as u32) << (i * 7);
				if last {
					return Ok((VarInt(value), i + 1))
				}
			}
			Err(())
		}
	}

	#[test]
	fn varint_encode_decode() {
		let mut buf = super::InMemoryRecorder::default();
		for i in 0..u16::MAX as u32 + 1 {
			VarInt(i).encode_into(&mut buf);
			assert_eq!(buf.buffer.len(), VarInt(i).encoded_len());
			assert_eq!(Ok((VarInt(i), buf.buffer.len())), VarInt::decode(&buf.buffer));
			buf.buffer.clear();
		}
	}

	impl<H: AsRef<[u8]>, V: AsRef<[u8]>> Op<H, V> {
		/// Calculate encoded len.
		pub fn encoded_len(&self) -> usize {
			let mut len = 1;
			match self {
				Op::KeyPush(key, _mask) => {
					len += VarInt(key.len() as u32).encoded_len();
					len += key.len();
					len += 1;
				},
				Op::KeyPop(nb) => {
					len += VarInt(*nb as u32).encoded_len();
				},
				Op::HashChild(hash, _at) => {
					len += hash.as_ref().len();
					len += 1;
				},
				Op::HashValue(hash) => {
					len += hash.as_ref().len();
				},
				Op::Value(value) => {
					len += VarInt(value.as_ref().len() as u32).encoded_len();
					len += value.as_ref().len();
				},
				Op::EndProof => (),
			}
			len
		}

		/// Write op.
		pub fn encode_into(&self, out: &mut impl RecorderOutput) {
			match self {
				Op::KeyPush(key, mask) => {
					out.write_bytes(&[0]);
					VarInt(key.len() as u32).encode_into(out);
					out.write_bytes(&key);
					out.write_bytes(&[*mask]);
				},
				Op::KeyPop(nb) => {
					out.write_bytes(&[1]);
					VarInt(*nb as u32).encode_into(out);
				},
				Op::HashChild(hash, at) => {
					out.write_bytes(&[2]);
					out.write_bytes(hash.as_ref());
					out.write_bytes(&[*at]);
				},
				Op::HashValue(hash) => {
					out.write_bytes(&[3]);
					out.write_bytes(hash.as_ref());
				},
				Op::Value(value) => {
					out.write_bytes(&[4]);
					let value = value.as_ref();
					VarInt(value.len() as u32).encode_into(out);
					out.write_bytes(&value);
				},
				Op::EndProof => {
					out.write_bytes(&[5]);
				},
			}
		}
	}

	impl<H: AsRef<[u8]> + AsMut<[u8]> + Default> Op<H, Vec<u8>> {
		/// Read an op, return op and number byte read. Or error if invalid encoded.
		pub fn decode(encoded: &[u8]) -> Result<(Self, usize), ()> {
			let mut i = 0;
			if i >= encoded.len() {
				return Err(())
			}
			Ok(match encoded[i] {
				0 => {
					let (len, offset) = VarInt::decode(&encoded[i + 1..])?;
					i += 1 + offset;
					if i + len.0 as usize >= encoded.len() {
						return Err(())
					}
					let key = &encoded[i..i + len.0 as usize];
					let mask = encoded[i + len.0 as usize];
					(Op::KeyPush(key.to_vec(), mask), i + len.0 as usize + 1)
				},
				1 => {
					let (len, offset) = VarInt::decode(&encoded[i + 1..])?;
					if len.0 > u16::MAX as u32 {
						return Err(())
					}
					(Op::KeyPop(len.0 as u16), i + 1 + offset)
				},
				2 => {
					let mut hash = H::default();
					let end = i + 1 + hash.as_ref().len();
					if end >= encoded.len() {
						return Err(())
					}
					hash.as_mut().copy_from_slice(&encoded[i + 1..end]);
					let mask = encoded[end];
					(Op::HashChild(hash, mask), end + 1)
				},
				3 => {
					let mut hash = H::default();
					let end = i + 1 + hash.as_ref().len();
					if end >= encoded.len() {
						return Err(())
					}
					hash.as_mut().copy_from_slice(&encoded[i + 1..end]);
					(Op::HashValue(hash), end)
				},
				4 => {
					let (len, offset) = VarInt::decode(&encoded[i + 1..])?;
					i += 1 + offset;
					if i + len.0 as usize > encoded.len() {
						return Err(())
					}
					let value = &encoded[i..i + len.0 as usize];
					(Op::Value(value.to_vec()), i + len.0 as usize)
				},
				5 => (Op::EndProof, 1),
				_ => return Err(()),
			})
		}
	}

	/// Iterator on op from a in memory encoded proof.
	pub struct IterOpProof<H: AsRef<[u8]> + AsMut<[u8]> + Default, B: AsRef<[u8]>>(
		B,
		usize,
		PhantomData<H>,
	);

	impl<H: AsRef<[u8]> + AsMut<[u8]> + Default, B: AsRef<[u8]>> From<B> for IterOpProof<H, B> {
		fn from(b: B) -> Self {
			Self(b, 0, PhantomData)
		}
	}

	impl<H: AsRef<[u8]> + AsMut<[u8]> + Default, B: AsRef<[u8]>> Iterator for IterOpProof<H, B> {
		type Item = Option<Op<H, Vec<u8>>>;

		fn next(&mut self) -> Option<Self::Item> {
			match Op::decode(self.0.as_ref()) {
				Ok((op, len)) => {
					self.1 += len;
					Some(Some(op))
				},
				Err(_) => Some(None),
			}
		}
	}
}

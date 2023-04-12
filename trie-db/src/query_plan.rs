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
	proof::VerifyError,
	rstd::{
		borrow::{Borrow, Cow},
		boxed::Box,
		cmp::*,
		result::Result,
	},
	CError, ChildReference, DBValue, NibbleVec, Trie, TrieDB, TrieError, TrieHash, TrieLayout,
};
use hash_db::Hasher;

/// Item to query, in memory.
#[derive(Default)]
pub struct InMemQueryPlanItem {
	key: Vec<u8>,
	as_prefix: bool,
}

impl InMemQueryPlanItem {
	/// Create new item.
	pub fn new(key: Vec<u8>, as_prefix: bool) -> Self {
		Self { key, as_prefix }
	}
	/// Get ref.
	pub fn as_ref(&self) -> QueryPlanItem {
		QueryPlanItem { key: &self.key, as_prefix: self.as_prefix }
	}
}

/// Item to query.
#[derive(Clone)]
pub struct QueryPlanItem<'a> {
	key: &'a [u8],
	as_prefix: bool,
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
		InMemQueryPlanItem { key: self.key.to_vec(), as_prefix: self.as_prefix }
	}
}

/// Query plan in memory.
pub struct InMemQueryPlan {
	pub items: Vec<InMemQueryPlanItem>,
	pub kind: ProofKind,
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
	items: I,
	ignore_unordered: bool,
	kind: ProofKind,
	_ph: PhantomData<&'a ()>,
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

	/// Same encoding as CompactNodes, but with an alternate ordering that allows streaming
	/// node and avoid unbound memory when building proof.
	///
	/// Ordering is starting at first met proof and parent up to intersection with next
	/// sibling access in a branch, then next leaf, and repeating, finishing with root node.
	CompactNodesStream,

	/// Content oriented proof, no nodes are written, just a
	/// sequence of accessed by lexicographical order as described
	/// in compact_content_proof::Op.
	/// As with compact node, checking validity of proof need to
	/// load the full proof or up to the halt point.
	CompactContent,
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
struct CompactEncodingInfos {
	/// Node in memory content.
	node: OwnedNode<DBValue>,
	/// Flags indicating whether each child is omitted in the encoded node.
	accessed_children: Bitmap,
	/// Skip value if value node is after.
	accessed_value: bool,
	/// Depth of node in nible.
	depth: usize,
	/// Next descended child, this is only really needed when iterating on
	/// prefix.
	next_descended_child: u8,
	/// Is the node inline.
	is_inline: bool,
}

/// Allows sending proof recording as it is produced.
pub trait RecorderOutput {
	/// Append bytes.
	fn write_bytes(&mut self, bytes: &[u8]);

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
		if !self.buffer.is_empty() {
			self.nodes.push(core::mem::take(&mut self.buffer));
		}
		self.buffer.extend_from_slice(bytes)
	}

	fn write_entry(&mut self, bytes: Cow<[u8]>) {
		self.nodes.push(bytes.into_owned());
	}
}

/// Simplified recorder.
pub struct Recorder<O: RecorderOutput> {
	output: RecorderStateInner<O>,
	limits: Limits,
	// on restore only record content AFTER this position.
	start_at: Option<usize>,
}

/// Limits to size proof to record.
struct Limits {
	remaining_node: Option<usize>,
	remaining_size: Option<usize>,
	kind: ProofKind,
}

impl<O: RecorderOutput> Recorder<O> {
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
			RecorderStateInner::CompactStream(output) |
			RecorderStateInner::Content(output) => output,
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
			ProofKind::CompactNodesStream => RecorderStateInner::CompactStream(output),
			ProofKind::CompactContent => RecorderStateInner::Content(output),
		};
		let limits = Limits { remaining_node: limit_node, remaining_size: limit_size, kind };
		Self { output, limits, start_at: None }
	}

	#[must_use]
	fn record_stacked_node(&mut self, item: &CompactEncodingInfos, _stack_pos: usize) -> bool {
		if !self.check_start_at(item.depth) {
			return false
		}
		let mut res = false;
		match &mut self.output {
			RecorderStateInner::Stream(output) =>
				if !item.is_inline {
					res = self.limits.add_node(item.node.data().len());
					output.write_entry(item.node.data().into());
				},
			RecorderStateInner::Compact { output, proof, stacked_pos } =>
				if !item.is_inline {
					res = self.limits.add_node(item.node.data().len());
					stacked_pos.push(proof.len());
					proof.push(Vec::new());
				},
			RecorderStateInner::CompactStream(output) => {
				unimplemented!()
			},
			RecorderStateInner::Content(output) => {
				unimplemented!()
			},
		}
		res
	}

	fn record_popped_node<L: TrieLayout>(&mut self, item: &CompactEncodingInfos, stack_pos: usize) {
		if !self.check_start_at(item.depth) {
			return
		}

		match &mut self.output {
			RecorderStateInner::Stream(_) => (),
			RecorderStateInner::Compact { output, proof, stacked_pos } =>
				if !item.is_inline {
					let at = stacked_pos.pop().expect("always stacked");
					proof[at] = crate::trie_codec::encode_node_internal::<L::Codec>(
						&item.node,
						item.accessed_value,
						item.accessed_children,
					)
					.expect("TODO error handling, can it actually fail?");
				},
			RecorderStateInner::CompactStream(output) => {
				unimplemented!()
			},
			RecorderStateInner::Content(output) => {
				unimplemented!()
			},
		}
	}

	#[must_use]
	fn record_value_node(&mut self, value: Vec<u8>, depth: usize) -> bool {
		if !self.check_start_at(depth) {
			return false
		}

		let mut res = false;
		match &mut self.output {
			RecorderStateInner::Stream(output) => {
				res = self.limits.add_value(value.len());
				output.write_entry(value.into());
			},
			RecorderStateInner::Compact { output, proof, stacked_pos } => {
				res = self.limits.add_value(value.len());
				proof.push(value.into());
			},
			RecorderStateInner::CompactStream(output) => {
				unimplemented!()
			},
			RecorderStateInner::Content(output) => {
				unimplemented!()
			},
		}
		res
	}

	fn record_value_inline(&mut self, value: &[u8], depth: usize) {
		if !self.check_start_at(depth) {
			return
		}

		match &mut self.output {
			RecorderStateInner::Compact { .. } | RecorderStateInner::Stream(_) => {
				// not writing inline value (already
				// in parent node).
			},
			RecorderStateInner::CompactStream(output) => {
				unimplemented!()
			},
			RecorderStateInner::Content(output) => {
				unimplemented!()
			},
		}
	}

	fn finalize(&mut self) {
		match &mut self.output {
			RecorderStateInner::Compact { output, proof, stacked_pos } => {
				if stacked_pos.len() > 0 {
					// halted: complete up to 0 and write all nodes keeping stack.
					unimplemented!()
				} else {
					for entry in core::mem::take(proof) {
						output.write_entry(entry.into());
					}
				}
			},
			RecorderStateInner::Stream(output) => {
				// all written
			},
			RecorderStateInner::CompactStream(output) => {
				unimplemented!()
			},
			RecorderStateInner::Content(output) => {
				unimplemented!()
			},
		}
	}
}

impl Limits {
	#[must_use]
	fn add_node(&mut self, size: usize) -> bool {
		let mut res = false;
		match self.kind {
			ProofKind::CompactNodes | ProofKind::FullNodes => {
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
			ProofKind::CompactNodesStream => {
				unimplemented!()
			},
			ProofKind::CompactContent => {
				unimplemented!()
			},
		}
		res
	}

	#[must_use]
	fn add_value(&mut self, size: usize) -> bool {
		let mut res = false;
		match self.kind {
			ProofKind::CompactNodes | ProofKind::FullNodes => {
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
			ProofKind::CompactNodesStream => {
				unimplemented!()
			},
			ProofKind::CompactContent => {
				unimplemented!()
			},
		}
		res
	}

	fn reclaim_child_hash(&mut self, size: usize) {
		match self.kind {
			ProofKind::FullNodes => unreachable!(),
			ProofKind::CompactNodes => {
				// replaced by a 0 len inline hash so same size encoding
				if let Some(rem_size) = self.remaining_size.as_mut() {
					*rem_size += size;
				}
			},
			ProofKind::CompactNodesStream => {
				unimplemented!()
			},
			ProofKind::CompactContent => {
				unimplemented!()
			},
		}
	}

	fn reclaim_value_hash(&mut self, size: usize) {
		match self.kind {
			ProofKind::FullNodes => unreachable!(),
			ProofKind::CompactNodes => {
				if let Some(rem_size) = self.remaining_size.as_mut() {
					// escape byte added
					*rem_size += size - 1;
				}
			},
			ProofKind::CompactNodesStream => {
				unimplemented!()
			},
			ProofKind::CompactContent => {
				unimplemented!()
			},
		}
	}
}

// TODO may be useless
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
	CompactStream(O),
	/// For FullNodes proofs, just send node to this stream.
	Content(O),
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateRecord<O: RecorderOutput> {
	currently_query_item: Option<InMemQueryPlanItem>,
	stack: RecordStack<O>,
	// This indicate a restore point, it takes precedence over
	// stack and currently_query_item.
	from: Option<(Vec<u8>, bool)>,
}

impl<O: RecorderOutput> HaltedStateRecord<O> {
	/// Indicate we reuse the query plan iterator
	/// and stack.
	pub fn statefull(&mut self, recorder: Recorder<O>) -> Recorder<O> {
		let result = core::mem::replace(&mut self.stack.recorder, recorder);
		result
	}

	/// Indicate to use stateless (on a fresh proof
	/// and a fresh query plan iterator).
	pub fn stateless(&mut self, recorder: Recorder<O>) -> Recorder<O> {
		let new_start = Self::from_start(recorder);
		let old = core::mem::replace(self, new_start);
		self.from = old.from;
		self.currently_query_item = None;
		old.stack.recorder
	}

	/// Init from start.
	pub fn from_start(recorder: Recorder<O>) -> Self {
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
			from: None,
		}
	}

	pub fn is_finished(&self) -> bool {
		self.from == None
	}

	pub fn finish(self) -> Recorder<O> {
		self.stack.recorder
	}
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateCheck<'a, L: TrieLayout, C, D> {
	query_plan: QueryPlan<'a, C>,
	current: Option<QueryPlanItem<'a>>,
	stack: ReadStack<L, D>,
	state: ReadProofState,
	restore_offset: usize,
}

impl<'a, L: TrieLayout, C, D> From<QueryPlan<'a, C>> for HaltedStateCheck<'a, L, C, D> {
	fn from(query_plan: QueryPlan<'a, C>) -> Self {
		let is_compact = match query_plan.kind {
			ProofKind::FullNodes => false,
			ProofKind::CompactNodesStream => true,
			ProofKind::CompactNodes => true,
			_ => false,
		};

		HaltedStateCheck {
			stack: ReadStack {
				items: Default::default(),
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

struct RecordStack<O: RecorderOutput> {
	recorder: Recorder<O>,
	items: Vec<CompactEncodingInfos>,
	prefix: NibbleVec,
	iter_prefix: Option<usize>,
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
	mut from: HaltedStateRecord<O>,
) -> Result<HaltedStateRecord<O>, VerifyError<TrieHash<L>, CError<L>>> {
	// TODO
	//) resto
	//	let restore_buf;
	let dummy_parent_hash = TrieHash::<L>::default();
	let mut stateless = false;
	let mut statefull = None;
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
			statefull = Some(
				lower_bound.0.len() * nibble_ops::NIBBLE_PER_BYTE -
					if lower_bound.1 { 2 } else { 1 },
			);
		}
	}

	let stack = &mut from.stack;

	let mut prev_query: Option<QueryPlanItem> = None;
	/*
	let mut prev_query: Option<QueryPlanItem> = if stateless {
		Some(QueryPlanItem {
			key: restore_buf2.as_slice(),
			as_prefix: false, // not checked only to advance.
		})
	} else {
		None
	};
	*/
	let mut from_query = from.currently_query_item.take();
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
					return Err(VerifyError::UnorderedKey(query.key.to_vec())) // TODO not kind as param if keeping
					                                      // CompactContent
				}
			}
			loop {
				match stack.prefix.len().cmp(&common_nibbles) {
					Ordering::Equal | Ordering::Less => break,
					Ordering::Greater =>
						if !stack.pop::<L>() {
							stack.recorder.finalize();
							return Ok(from)
						},
				}
			}
			common_nibbles
		};
		let mut first_iter = false;
		if stack.iter_prefix.is_none() {
			// descend
			let mut slice_query = NibbleSlice::new_offset(&query.key, common_nibbles);
			let mut touched = false;
			loop {
				if slice_query.is_empty() && !stack.items.is_empty() {
					if query.as_prefix {
						first_iter = true;
						stack.enter_prefix_iter();
					} else {
						touched = true;
					}
					break
				}

				let child_index = if stack.items.is_empty() { 0 } else { slice_query.at(0) };
				match stack.try_stack_child(
					child_index,
					db,
					dummy_parent_hash,
					Some(&mut slice_query),
				)? {
					TryStackChildResult::Stacked => {},
					TryStackChildResult::NotStackedBranch | TryStackChildResult::NotStacked =>
						break,
					TryStackChildResult::StackedDescendIncomplete => {
						if query.as_prefix {
							first_iter = true; // TODO reorder to avoid this bool?
							stack.enter_prefix_iter();
						}
						break
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
						stack.recorder.finalize();
						return Ok(from)
					},
				}
			}

			if touched {
				// try access value
				stack.access_value(db)?;
				touched = false;
			}
		}
		from_query_ref = None;
		prev_query = Some(query);

		if let Some(prefix_stack_depth) = stack.iter_prefix.clone() {
			// run prefix iteration
			let mut stacked = first_iter;
			loop {
				// descend
				loop {
					if stacked {
						// try access value in next node
						stack.access_value(db)?;
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

					match stack.try_stack_child(child_index, db, dummy_parent_hash, None)? {
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
							stack.recorder.finalize();
							return Ok(from)
						},
					}
				}

				// pop
				if !stack.pop::<L>() {
					break
				}
			}
			stack.exit_prefix_iter();
		}
	}

	while stack.pop::<L>() {}
	stack.recorder.finalize();
	Ok(from)
}

enum TryStackChildResult {
	Stacked,
	NotStackedBranch,
	NotStacked,
	StackedDescendIncomplete,
	Halted,
}

impl<O: RecorderOutput> RecordStack<O> {
	fn try_stack_child<'a, L: TrieLayout>(
		&mut self,
		child_index: u8,
		db: &TrieDB<L>,
		parent_hash: TrieHash<L>,
		mut slice_query: Option<&mut NibbleSlice>,
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
						item.accessed_children.set(child_index as usize, true);
						child.build(node_data)
					} else {
						return Ok(TryStackChildResult::NotStacked)
					},
				NodePlan::NibbledBranch { children, .. } | NodePlan::Branch { children, .. } =>
					if let Some(child) = &children[child_index as usize] {
						from_branch = Some(&mut item.accessed_children);
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
			if self.halt && from_branch.is_some() {
				return Ok(TryStackChildResult::Halted)
			}
		}
		if let Some(accessed_children) = from_branch {
			accessed_children.set(child_index as usize, true);

			slice_query.as_mut().map(|s| s.advance(1));
			prefix.push(child_index);
		}
		// TODO handle cache first
		let child_node = db
			.get_raw_or_lookup_with_cache(
				parent_hash,
				child_handle,
				prefix.as_prefix(),
				false,
				true,
			)
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
			accessed_children: Default::default(),
			accessed_value: false,
			depth: prefix.len(),
			next_descended_child,
			is_inline,
		};
		if self.recorder.record_stacked_node(&infos, stack.len()) {
			self.halt = true;
		}
		stack.push(infos);
		if stack_extension {
			let sbranch = self.try_stack_child(0, db, parent_hash, slice_query)?;
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

	fn access_value<'a, L: TrieLayout>(
		&mut self,
		db: &TrieDB<L>,
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
		item.accessed_value = true;
		match value {
			Value::Node(hash_slice) => {
				let mut hash = TrieHash::<L>::default();
				hash.as_mut().copy_from_slice(hash_slice);
				let Some(value) = db.db().get(&hash, self.prefix.as_prefix()) else {
					return Err(VerifyError::IncompleteProof);
				};
				if self.recorder.record_value_node(value, self.prefix.len()) {
					self.halt = true;
				}
			},
			Value::Inline(value) => {
				self.recorder.record_value_inline(value, self.prefix.len());
			},
		}
		Ok(true)
	}

	fn pop<L: TrieLayout>(&mut self) -> bool {
		if self.iter_prefix == Some(self.items.len()) {
			return false
		}
		if let Some(item) = self.items.pop() {
			self.recorder.record_popped_node::<L>(&item, self.items.len());
			let depth = self.items.last().map(|i| i.depth).unwrap_or(0);
			self.prefix.drop_lasts(self.prefix.len() - depth);
			if depth == item.depth {
				// Two consecutive identical depth is an extension
				self.pop::<L>();
			}
			true
		} else {
			false
		}
	}

	fn enter_prefix_iter(&mut self) {
		self.iter_prefix = Some(self.items.len());
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
	D: Borrow<[u8]>,
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

struct ItemStack<L: TrieLayout, D> {
	node: ItemStackNode<D>,
	children: Vec<Option<ChildReference<TrieHash<L>>>>,
	attached_value_hash: Option<TrieHash<L>>,
	depth: usize,
	next_descended_child: u8,
}

enum ItemStackNode<D> {
	Inline(OwnedNode<Vec<u8>>),
	Node(OwnedNode<D>),
}

impl<L: TrieLayout, D: Borrow<[u8]>> From<(ItemStackNode<D>, bool)> for ItemStack<L, D> {
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

impl<L: TrieLayout, D: Borrow<[u8]>> ItemStack<L, D> {
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

struct ReadStack<L: TrieLayout, D> {
	items: Vec<ItemStack<L, D>>,
	prefix: NibbleVec,
	iter_prefix: Option<(usize, bool)>, // limit and wether we return value
	is_compact: bool,
	expect_value: bool,
	_ph: PhantomData<L>,
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
pub trait SplitFirst: Borrow<[u8]> {
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
				let Some(encoded_node) = proof.next() else {
					return Ok(TryStackChildResult::Halted);
				};
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
				if self.prefix.len() > 0 {
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
					if self.prefix.len() > 0 {
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
					if check_hash {
						verify_hash::<L>(encoded_branch.borrow(), hash)?;
					}
					node = match OwnedNode::new::<L::Codec>(encoded_branch) {
						Ok(node) => (ItemStackNode::Node(node), self.is_compact).into(),
						Err(e) => return Err(VerifyError::DecodeError(e)),
					};
				},
				NodeHandle::Inline(encoded_branch) => {
					node = match OwnedNode::new::<L::Codec>(encoded_branch.to_vec()) {
						Ok(node) => (ItemStackNode::Inline(node), self.is_compact).into(),
						Err(e) => return Err(VerifyError::DecodeError(e)),
					};
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
	) -> Result<Option<Vec<u8>>, VerifyError<TrieHash<L>, CError<L>>> {
		if let Some(node) = self.items.last() {
			let node_data = node.data();

			let value = match node.node_plan() {
				NodePlan::Leaf { value, .. } => Some(value.build(node_data)),
				NodePlan::Branch { value, .. } | NodePlan::NibbledBranch { value, .. } =>
					value.as_ref().map(|v| v.build(node_data)),
				_ => return Ok(None),
			};
			if let Some(value) = value {
				match value {
					Value::Inline(value) =>
						if self.expect_value {
							assert!(self.is_compact);
							self.expect_value = false;
							let Some(value) = proof.next() else {
								return Err(VerifyError::IncompleteProof);
							};
							if check_hash {
								let hash = L::Hash::hash(value.borrow());
								self.items.last_mut().map(|i| i.attached_value_hash = Some(hash));
							}
							return Ok(Some(value.borrow().to_vec()))
						} else {
							return Ok(Some(value.to_vec()))
						},
					Value::Node(hash) => {
						if self.expect_value {
							let mut error_hash = TrieHash::<L>::default();
							error_hash.as_mut().copy_from_slice(hash);
							return Err(VerifyError::ExtraneousHashReference(error_hash))
						}
						let Some(value) = proof.next() else {
							return Err(VerifyError::IncompleteProof);
						};
						if check_hash {
							verify_hash::<L>(value.borrow(), hash)?;
						}
						return Ok(Some(value.borrow().to_vec()))
					},
				}
			}
		} else {
			return Err(VerifyError::IncompleteProof)
		}

		Ok(None)
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
						let origin = 0; // TODO restart depth in stack
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
								unimplemented!("check agains right child");
							} else {
								let expected = expected_root.as_ref().expect("checked above");
								verify_hash::<L>(&encoded_node, expected.as_ref())?;
							}
						} else {
							let hash = L::Hash::hash(&encoded_node);
							if let Some(parent) = self.items.last_mut() {
								let at = parent.next_descended_child - 1;
								parent.children[at as usize] = Some(ChildReference::Hash(hash));
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
	) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
		if self.is_compact && expected_root.is_some() {
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

	fn enter_prefix_iter(&mut self) {
		self.iter_prefix = Some((self.items.len(), false));
	}

	fn exit_prefix_iter(&mut self) {
		self.iter_prefix = None
	}
}

/// Content return on success when reading proof.
pub enum ReadProofItem<'a, L: TrieLayout, C, D> {
	/// Successfull read of proof, not all content read.
	Halted(Box<HaltedStateCheck<'a, L, C, D>>),
	/// Seen value and key in proof.
	/// When we set the query plan, we only return content
	/// matching the query plan.
	Value(Cow<'a, [u8]>, Vec<u8>),
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

					let r = self.stack.pop_until(common_nibbles, &self.expected_root);
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
					to_check_slice = None;
					break
				}
			};
			let did_prefix = self.stack.iter_prefix.is_some();
			while let Some((_, accessed_value)) = self.stack.iter_prefix.clone() {
				// prefix iteration
				if !accessed_value {
					self.stack.iter_prefix.as_mut().map(|s| {
						s.1 = true;
					});
					match self.stack.access_value(&mut self.proof, check_hash) {
						Ok(Some(value)) =>
							return Some(Ok(ReadProofItem::Value(
								self.stack.prefix.inner().to_vec().into(),
								value,
							))),
						Ok(None) => (),
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
			let as_prefix = to_check.as_prefix;
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
					self.stack.enter_prefix_iter();
					continue
				}
				self.state = ReadProofState::SwitchQueryPlan;
				match self.stack.access_value(&mut self.proof, check_hash) {
					Ok(Some(value)) =>
						return Some(Ok(ReadProofItem::Value(to_check.key.into(), value))),
					Ok(None) => return Some(Ok(ReadProofItem::NoValue(to_check.key))),
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
						self.stack.enter_prefix_iter();
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
			let r = self.stack.pop_until(stack_to, &self.expected_root);
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
			unimplemented!("check hash from stack");
		}
		self.state = ReadProofState::Finished;
		let query_plan = crate::rstd::mem::replace(&mut self.query_plan, None);
		let query_plan = query_plan.expect("Init with state");
		let current = crate::rstd::mem::take(&mut self.current);
		let stack = crate::rstd::mem::replace(
			&mut self.stack,
			ReadStack {
				items: Default::default(),
				prefix: Default::default(),
				is_compact: self.is_compact,
				expect_value: false,
				iter_prefix: None,
				_ph: PhantomData,
			},
		);
		Some(Ok(ReadProofItem::Halted(Box::new(HaltedStateCheck {
			query_plan,
			current,
			stack,
			state: ReadProofState::Halted,
			restore_offset: to_check_slice.map(|s| s.offset()).unwrap_or(0),
		}))))
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
	let HaltedStateCheck { query_plan, current, stack, state, restore_offset } = state;

	match query_plan.kind {
		ProofKind::CompactNodesStream | ProofKind::CompactContent => {
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

mod compact_content_proof {

	use codec::{Decode, Encode};

	/// Representation of each encoded action
	/// for building the proof.
	/// TODO ref variant for encoding ??
	#[derive(Encode, Decode, Debug)]
	pub(crate) enum Op<H, V> {
		// key content followed by a mask for last byte.
		// If mask erase some content the content need to
		// be set at 0 (or error).
		// Two consecutive `KeyPush` are invalid.
		KeyPush(Vec<u8>, u8), /* TODO could use BackingByteVec (but Vec for new as it scale
		                       * encode) */
		// Last call to pop is implicit (up to root), defining
		// one will result in an error.
		// Two consecutive `KeyPush` are invalid.
		// TODO should be compact encoding of number.
		KeyPop(u16),
		// u8 is child index, shorthand for key push one nibble followed by key pop.
		HashChild(Enc<H>, u8),
		// All value variant are only after a `KeyPush` or at first position.
		HashValue(Enc<H>),
		Value(V),
		// This is not strictly necessary, only if the proof is not sized, otherwhise if we know
		// the stream will end it can be skipped.
		EndProof,
	}

	#[derive(Debug)]
	#[repr(transparent)]
	pub struct Enc<H>(pub H);

	impl<H: AsRef<[u8]>> Encode for Enc<H> {
		fn size_hint(&self) -> usize {
			self.0.as_ref().len()
		}

		fn encoded_size(&self) -> usize {
			self.0.as_ref().len()
		}

		fn encode_to<T: codec::Output + ?Sized>(&self, dest: &mut T) {
			dest.write(self.0.as_ref())
		}
	}

	impl<H: AsMut<[u8]> + Default> Decode for Enc<H> {
		fn decode<I: codec::Input>(input: &mut I) -> core::result::Result<Self, codec::Error> {
			let mut dest = H::default();
			input.read(dest.as_mut())?;
			Ok(Enc(dest))
		}
	}
}

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
	nibble::{nibble_ops, LeftNibbleSlice, NibbleSlice},
	node::{NodeHandle, NodePlan, OwnedNode, Value},
	proof::VerifyError,
	rstd::{
		borrow::{Borrow, Cow},
		cmp::*,
		result::Result,
	},
	CError, DBValue, NibbleVec, Trie, TrieDB, TrieError, TrieHash, TrieLayout,
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
}

/// Query plan in memory.
pub struct InMemQueryPlan {
	pub items: Vec<InMemQueryPlanItem>,
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
			ignore_unordered: self.ignore_unordered,
		}
	}
}

/// Query plan.
pub struct QueryPlan<'a, I>
where
	I: Iterator<Item = QueryPlanItem<'a>>,
{
	items: I,
	ignore_unordered: bool,
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

impl Bitmap {
	fn at(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}

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

/* likely compact encoding is enough
struct ContentEncodingInfos {
	/// Node in memory content.
	node: OwnedNode<Vec<u8>>,
	/// Flags indicating whether each child is omitted in the encoded node.
	omit_children: Bitmap,
	/// Skip value if value node is after.
	omit_value: bool,
}
*/

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
pub struct Recorder<O: RecorderOutput>(RecorderStateInner<O>);

impl<O: RecorderOutput> Recorder<O> {
	/// Get back output handle from a recorder.
	pub fn output(self) -> O {
		match self.0 {
			RecorderStateInner::Stream(output) |
			RecorderStateInner::Compact { output, .. } |
			RecorderStateInner::CompactStream(output) |
			RecorderStateInner::Content(output) => output,
		}
	}

	/// Instantiate a new recorder.
	pub fn new(proof_kind: ProofKind, output: O) -> Self {
		let recorder = match proof_kind {
			ProofKind::FullNodes => RecorderStateInner::Stream(output),
			ProofKind::CompactNodes =>
				RecorderStateInner::Compact { output, proof: Vec::new(), stacked_pos: Vec::new() },
			ProofKind::CompactNodesStream => RecorderStateInner::CompactStream(output),
			ProofKind::CompactContent => RecorderStateInner::Content(output),
		};
		Self(recorder)
	}

	fn record_stacked_node(&mut self, item: &CompactEncodingInfos, stack_pos: usize) {
		match &mut self.0 {
			RecorderStateInner::Stream(output) => {
				output.write_entry(item.node.data().into());
			},
			RecorderStateInner::Compact { output, proof, stacked_pos } => {
				unimplemented!()
			},
			RecorderStateInner::CompactStream(output) => {
				unimplemented!()
			},
			RecorderStateInner::Content(output) => {
				unimplemented!()
			},
		}
	}

	fn record_popped_node(&mut self, item: &CompactEncodingInfos, stack_pos: usize) {
		match &mut self.0 {
			RecorderStateInner::Stream(_) => (),
			RecorderStateInner::Compact { output, proof, stacked_pos } => {
				unimplemented!()
			},
			RecorderStateInner::CompactStream(output) => {
				unimplemented!()
			},
			RecorderStateInner::Content(output) => {
				unimplemented!()
			},
		}
	}

	fn record_value_node(&mut self, value: Vec<u8>) {
		match &mut self.0 {
			RecorderStateInner::Stream(output) => {
				output.write_entry(value.into());
			},
			RecorderStateInner::Compact { output, proof, stacked_pos } => {
				unimplemented!()
			},
			RecorderStateInner::CompactStream(output) => {
				unimplemented!()
			},
			RecorderStateInner::Content(output) => {
				unimplemented!()
			},
		}
	}

	fn record_value_inline(&mut self, value: &[u8]) {
		match &mut self.0 {
			RecorderStateInner::Stream(output) => {
				// not writing inline value (already
				// in parent node).
			},
			RecorderStateInner::Compact { output, proof, stacked_pos } => {
				unimplemented!()
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
	pub fn from_start(recorder: Recorder<O>) -> Self {
		HaltedStateRecord {
			currently_query_item: None,
			stack: RecordStack {
				recorder,
				items: Vec::new(),
				prefix: NibbleVec::new(),
				iter_prefix: None,
			},
			from: Some(Default::default()),
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
pub struct HaltedStateCheck {
	stack: (),
	stack_content: (),
	currently_query_item: Option<InMemQueryPlanItem>,
}

struct RecordStack<O: RecorderOutput> {
	recorder: Recorder<O>,
	items: Vec<CompactEncodingInfos>,
	prefix: NibbleVec,
	iter_prefix: Option<usize>,
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
	mut query_plan: QueryPlan<'a, I>,
	mut from: HaltedStateRecord<O>,
) -> Result<HaltedStateRecord<O>, VerifyError<TrieHash<L>, CError<L>>> {
	// TODO
	//) resto
	let dummy_parent_hash = TrieHash::<L>::default();
	if let Some(lower_bound) = from.from.take() {
		// TODO implement stack building from lower bound: fetch in stack and don't record.
		// First also advance iterator to skip and init currently_query_item.
	}

	let stack = &mut from.stack;

	let prev_query: Option<QueryPlanItem> = None;
	let mut from_query = from.currently_query_item.take();
	while let Some(query) =
		from_query.as_ref().map(|f| f.as_ref()).or_else(|| query_plan.items.next())
	{
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
					if !stack.pop() {
						return Ok(from)
					},
			}
		}

		// descend
		let mut slice_query = NibbleSlice::new_offset(&query.key, common_nibbles);
		let mut touched = false;
		loop {
			if slice_query.is_empty() {
				if query.as_prefix {
					stack.enter_prefix_iter();
				} else {
					touched = true;
				}
				break
			}

			let child_index = slice_query.at(0);
			match stack.try_stack_child(
				child_index,
				db,
				dummy_parent_hash,
				Some(&mut slice_query),
			)? {
				TryStackChildResult::Stacked => {},
				TryStackChildResult::NotStackedBranch | TryStackChildResult::NotStacked => break,
				TryStackChildResult::StackedDescendIncomplete => {
					if query.as_prefix {
						stack.enter_prefix_iter();
					}
					break
				},
			}
		}

		from_query = None;

		if touched {
			// try access value
			stack.access_value(db)?;
		}
		if let Some(prefix_stack_depth) = stack.iter_prefix.clone() {
			// run prefix iteration
			loop {
				// descend
				let mut stacked = true;
				loop {
					if stacked {
						// try access value in next node
						stack.access_value(db)?;
						stacked = false;
					}

					let child_index = if let Some(mut item) = stack.items.last_mut() {
						if item.next_descended_child as usize >= crate::nibble_ops::NIBBLE_LENGTH {
							continue
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
					}
				}

				// pop

				if !stack.pop() {
					break
				}
			}
			stack.exit_prefix_iter();
		}
	}

	Ok(from)
}

enum TryStackChildResult {
	Stacked,
	NotStackedBranch,
	NotStacked,
	StackedDescendIncomplete,
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
		let child_handle = if let Some(item) = stack.last_mut() {
			let node_data = item.node.data();

			match item.node.node_plan() {
				NodePlan::Empty | NodePlan::Leaf { .. } =>
					return Ok(TryStackChildResult::NotStacked),
				NodePlan::Extension { child, .. } => {
					stack_extension = true;
					child.build(node_data)
				},
				NodePlan::NibbledBranch { children, .. } | NodePlan::Branch { children, .. } =>
					if let Some(child) = &children[child_index as usize] {
						slice_query.as_mut().map(|s| s.advance(1));
						prefix.push(child_index);
						item.accessed_children.set(child_index as usize, true);
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
		}
		// TODO handle cache first
		let child_node = db
			.get_raw_or_lookup(parent_hash, child_handle, prefix.as_prefix(), false)
			.map_err(|_| VerifyError::IncompleteProof)?; // actually incomplete db: TODO consider switching error

		// TODO put in proof (only if Hash or inline for content one)

		let node_data = child_node.0.data();

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
		if stack_extension {
			// rec call to stack branch
			let sbranch = self.try_stack_child(child_index, db, parent_hash, slice_query)?;
			let TryStackChildResult::Stacked = sbranch else {
				return Err(VerifyError::InvalidChildReference(b"branch in db should follow extension".to_vec()));
			};
		} else {
			let infos = CompactEncodingInfos {
				node: child_node.0,
				accessed_children: Default::default(),
				accessed_value: false,
				depth: prefix.len(),
				next_descended_child: child_index + 1,
				is_inline,
			};
			self.recorder.record_stacked_node(&infos, stack.len());
			stack.push(infos);
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
				self.recorder.record_value_node(value);
			},
			Value::Inline(value) => {
				self.recorder.record_value_inline(value);
			},
		}
		Ok(true)
	}

	fn pop(&mut self) -> bool {
		if self.iter_prefix == Some(self.items.len()) {
			return false
		}
		if let Some(item) = self.items.pop() {
			self.recorder.record_popped_node(&item, self.items.len());
			let depth = self.items.last().map(|i| i.depth).unwrap_or(0);
			self.prefix.drop_lasts(self.prefix.len() - depth);
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
	query_plan: QueryPlan<'a, C>,
	proof: P,
	is_compact: bool,
	expected_root: Option<TrieHash<L>>,
	next_content: Option<QueryPlanItem<'a>>,
	rem_next_content: bool,
	stack: Vec<ItemStack<D>>,
	prefix: NibbleVec,

	_ph: PhantomData<&'a L>,
}

enum ItemStack<D: Borrow<[u8]>> {
	Inline(OwnedNode<Vec<u8>>, usize),
	Node(OwnedNode<D>, usize),
}

impl<D: Borrow<[u8]>> ItemStack<D> {
	fn depth(&self) -> usize {
		match self {
			ItemStack::Inline(_, d) => *d,
			ItemStack::Node(_, d) => *d,
		}
	}
	fn set_depth(&mut self, d: usize) {
		*match self {
			ItemStack::Inline(_, d) => d,
			ItemStack::Node(_, d) => d,
		} = d;
	}

	fn data(&self) -> &[u8] {
		match self {
			ItemStack::Inline(n, _) => n.data(),
			ItemStack::Node(n, _) => n.data(),
		}
	}

	fn node_plan(&self) -> &NodePlan {
		match self {
			ItemStack::Inline(n, _) => n.node_plan(),
			ItemStack::Node(n, _) => n.node_plan(),
		}
	}
}

/// Content return on success when reading proof.
pub enum ReadProofItem<'a> {
	/// Successfull read of proof, not all content read.
	Halted(HaltedStateCheck),
	/// Seen value and key in proof.
	/// When we set the query plan, we only return content
	/// matching the query plan.
	/// TODO try ref for value??
	Value(&'a [u8], Vec<u8>),
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
	D: Borrow<[u8]>,
{
	type Item = Result<ReadProofItem<'a>, VerifyError<TrieHash<L>, CError<L>>>;

	fn next(&mut self) -> Option<Self::Item> {
		let mut exit = false;
		// read proof
		loop {
			if self.rem_next_content || self.next_content.is_none() {
				if let Some(next) = self.query_plan.items.next() {
					let (ordered, common_nibbles) = if let Some(old) = self.next_content.as_ref() {
						old.before(&next)
					} else {
						(true, 0)
					};
					if !ordered {
						if self.query_plan.ignore_unordered {
							continue
						} else {
							return Some(Err(VerifyError::UnorderedKey(next.key.to_vec()))) // TODO not kind as param if keeping
							                                   // CompactContent
						}
					}

					while let Some(last) = self.stack.last() {
						if last.depth() == common_nibbles {
							self.prefix.drop_lasts(self.prefix.len() - last.depth());
							break
						}
						if last.depth() < common_nibbles {
							// depth should match.
							return Some(Err(VerifyError::ExtraneousNode))
						}
					}
					// TODO pop until common

					self.rem_next_content = false;
					self.next_content = Some(next);
				} else {
					self.rem_next_content = false;
					self.next_content = None;
					exit = true;
					break
				}
			};
			let to_check = self.next_content.as_ref().expect("Init above");
			let mut at_value = false;
			let mut to_check_slice = NibbleSlice::new(to_check.key);
			match self.prefix.len().cmp(&to_check_slice.len()) {
				Ordering::Equal => {
					at_value = true;
				},
				Ordering::Greater => (),
				Ordering::Less => {
					unreachable!();
				},
			}

			if at_value {
				self.rem_next_content = true;
				if let Some(node) = self.stack.last() {
					let node_data = node.data();

					let value = match node.node_plan() {
						NodePlan::Leaf { value, .. } => Some(value.build(node_data)),
						NodePlan::Branch { value, .. } | NodePlan::NibbledBranch { value, .. } =>
							value.as_ref().map(|v| v.build(node_data)),
						_ => None,
					};
					if let Some(value) = value {
						match value {
							Value::Inline(value) =>
								return Some(Ok(ReadProofItem::Value(to_check.key, value.to_vec()))),
							Value::Node(hash) => {
								let Some(value) = self.proof.next() else {
									return Some(Err(VerifyError::IncompleteProof));
								};
								if self.expected_root.is_some() {
									let checked_hash = L::Hash::hash(value.borrow());
									if checked_hash.as_ref() != hash {
										let mut error_hash = TrieHash::<L>::default();
										error_hash.as_mut().copy_from_slice(hash);
										return Some(Err(VerifyError::HashMismatch(error_hash)))
									}
								}
								return Some(Ok(ReadProofItem::Value(
									to_check.key,
									value.borrow().to_vec(),
								)))
							},
						}
					}

					return Some(Ok(ReadProofItem::NoValue(to_check.key)))
				} else {
					unreachable!();
				}
			}

			let child_index = to_check_slice.at(self.prefix.len() + 1);
			let child_handle = if let Some(node) = self.stack.last_mut() {
				let node_data = node.data();

				match node.node_plan() {
					NodePlan::Empty | NodePlan::Leaf { .. } => {
						self.rem_next_content = true;
						return Some(Ok(ReadProofItem::NoValue(to_check.key)))
					},
					NodePlan::Extension { .. } => {
						unreachable!("Extension never stacked")
					},
					NodePlan::NibbledBranch { children, .. } |
					NodePlan::Branch { children, .. } =>
						if let Some(child) = &children[child_index as usize] {
							child.build(node_data)
						} else {
							self.rem_next_content = true;
							return Some(Ok(ReadProofItem::NoValue(to_check.key)))
						},
				}
			} else {
				NodeHandle::Hash(self.expected_root.as_ref().map(AsRef::as_ref).unwrap_or(&[]))
			};

			let mut node = match child_handle {
				NodeHandle::Inline(data) =>
				// try access in inline then return
					ItemStack::Inline(
						match OwnedNode::new::<L::Codec>(data.to_vec()) {
							Ok(node) => node,
							Err(e) => return Some(Err(VerifyError::DecodeError(e))),
						},
						0,
					),
				NodeHandle::Hash(hash) => {
					let Some(encoded_node) = self.proof.next() else {
						exit = true;
						break
					};
					let node = match OwnedNode::new::<L::Codec>(encoded_node) {
						Ok(node) => node,
						Err(e) => return Some(Err(VerifyError::DecodeError(e))),
					};
					if self.expected_root.is_some() {
						let checked_hash = L::Hash::hash(node.data());
						if checked_hash.as_ref() != hash {
							let mut error_hash = TrieHash::<L>::default();
							error_hash.as_mut().copy_from_slice(hash);
							return Some(Err(VerifyError::HashMismatch(error_hash)))
						}
					}
					ItemStack::Node(node, 0)
				},
			};

			let mut descend_incomplete = false;
			let node_data = node.data();

			match node.node_plan() {
				NodePlan::Branch { .. } => (),
				| NodePlan::Empty => (),
				NodePlan::Leaf { partial, .. } |
				NodePlan::NibbledBranch { partial, .. } |
				NodePlan::Extension { partial, .. } => {
					let partial = partial.build(node_data);
					if to_check_slice.starts_with(&partial) {
						if self.prefix.len() > 0 {
							self.prefix.push(child_index);
							to_check_slice.advance(1);
						}
						to_check_slice.advance(partial.len());
						self.prefix.append_partial(partial.right());
					} else {
						descend_incomplete = true;
					}
				},
			}
			if descend_incomplete {
				self.rem_next_content = true;
				return Some(Ok(ReadProofItem::NoValue(to_check.key)))
			}
			if let NodePlan::Extension { child, .. } = node.node_plan() {
				let node_data = node.data();
				let child = child.build(node_data);
				match child {
					NodeHandle::Hash(hash) => {
						let Some(encoded_branch) = self.proof.next() else {
							return Some(Err(VerifyError::IncompleteProof));
						};

						if self.expected_root.is_some() {
							let checked_hash = L::Hash::hash(encoded_branch.borrow());
							if checked_hash.as_ref() != hash {
								let mut error_hash = TrieHash::<L>::default();
								error_hash.as_mut().copy_from_slice(hash);
								return Some(Err(VerifyError::HashMismatch(error_hash)))
							}
						}
						node = match OwnedNode::new::<L::Codec>(encoded_branch) {
							Ok(node) => ItemStack::Node(node, 0),
							Err(e) => return Some(Err(VerifyError::DecodeError(e))),
						};
					},
					NodeHandle::Inline(encoded_branch) => {
						node = match OwnedNode::new::<L::Codec>(encoded_branch.to_vec()) {
							Ok(node) => ItemStack::Inline(node, 0),
							Err(e) => return Some(Err(VerifyError::DecodeError(e))),
						};
					},
				}
				let NodePlan::Branch { .. } = node.node_plan() else {
					return Some(Err(VerifyError::IncompleteProof)) // TODO make error type??
				};
			}
			node.set_depth(self.prefix.len());
			self.stack.push(node);
		}

		if exit {
			if self.rem_next_content {
				self.next_content = None;
				// TODO unstack check for compact

				if self.proof.next().is_some() {
					return Some(Err(VerifyError::ExtraneousNode))
				}
				// successfully finished
				return None
			} else {
				// incomplete proof: TODO for compact check root
				unimplemented!("TODO return Halted read proof item");
			}
		}
		unimplemented!()
	}
}

/// Read the proof.
///
/// If expected root is None, then we do not check hashes at all.
pub fn verify_query_plan_iter<'a, L, C, D, P>(
	mut query_plan: QueryPlan<'a, C>,
	proof: P,
	restart: Option<HaltedStateCheck>,
	kind: ProofKind,
	expected_root: Option<TrieHash<L>>,
) -> Result<ReadProofIterator<'a, L, C, D, P>, VerifyError<TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = D>,
	D: Borrow<[u8]>,
{
	let is_compact = match kind {
		ProofKind::CompactNodes | ProofKind::CompactContent => {
			return Err(VerifyError::IncompleteProof) // TODO not kind as param if keeping CompactContent
		},
		ProofKind::FullNodes => false,
		ProofKind::CompactNodesStream => true,
	};

	let next_content = query_plan.items.next();
	Ok(ReadProofIterator {
		query_plan,
		proof,
		is_compact,
		expected_root,
		next_content,
		rem_next_content: false,
		prefix: Default::default(),
		stack: Default::default(),
		_ph: PhantomData,
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

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

//! Record query plan proof.

use super::*;

/// Simplified recorder.
pub struct Recorder<L: TrieLayout> {
	output: RecorderStateInner,
	limits: Limits,
	// on restore only record content AFTER this position.
	start_at: Option<usize>,
	_ph: PhantomData<L>,
}

impl<L: TrieLayout> Recorder<L> {
	/// Check and update start at record.
	/// When return true, do record.
	/// Else already was.
	fn check_start_at(&mut self, depth: usize) -> bool {
		if self.start_at.map(|s| s >= depth).unwrap_or(false) {
			false
		} else {
			self.start_at = None;
			true
		}
	}

	/// Get back output handle from a recorder.
	pub fn output(self) -> Vec<DBValue> {
		match self.output {
			RecorderStateInner::Stream(output) | RecorderStateInner::Compact { output, .. } =>
				output,
		}
	}

	/// Instantiate a new recorder.
	pub fn new(
		kind: ProofKind,
		output: Vec<DBValue>,
		limit_node: Option<usize>,
		limit_size: Option<usize>,
	) -> Self {
		let output = match kind {
			ProofKind::FullNodes => RecorderStateInner::Stream(output),
			ProofKind::CompactNodes =>
				RecorderStateInner::Compact { output, proof: Vec::new(), stacked_pos: Vec::new() },
		};
		let limits = Limits { remaining_node: limit_node, remaining_size: limit_size, kind };
		Self { output, limits, start_at: None, _ph: PhantomData }
	}

	#[must_use]
	fn record_stacked_node(&mut self, item: &StackedNodeRecord, is_root: bool) -> bool {
		if !self.check_start_at(item.depth) {
			return false
		}
		let mut res = false;
		match &mut self.output {
			RecorderStateInner::Stream(output) =>
				if !item.is_inline {
					res |= self.limits.add_node(
						item.node.data().len(),
						L::Codec::DELTA_COMPACT_OMITTED_NODE,
						is_root,
					);
					output.push(item.node.data().into());
				},
			RecorderStateInner::Compact { output: _, proof, stacked_pos } =>
				if !item.is_inline {
					res |= self.limits.add_node(
						item.node.data().len(),
						L::Codec::DELTA_COMPACT_OMITTED_NODE,
						is_root,
					);
					stacked_pos.push(proof.len());
					proof.push(Vec::new());
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
		match &mut self.output {
			RecorderStateInner::Stream(output) => {
				res |= self.limits.add_value(value.len(), L::Codec::DELTA_COMPACT_OMITTED_VALUE);
				output.push(value.into());
			},
			RecorderStateInner::Compact { output: _, proof, stacked_pos: _ } => {
				res |= self.limits.add_value(value.len(), L::Codec::DELTA_COMPACT_OMITTED_VALUE);
				proof.push(value.into());
			},
		}
		res
	}
}

enum RecorderStateInner {
	/// For FullNodes proofs, just send node to this stream.
	Stream(Vec<DBValue>),
	/// For FullNodes proofs, Requires keeping all proof before sending it.
	Compact {
		output: Vec<DBValue>,
		proof: Vec<Vec<u8>>,
		/// Stacked position in proof to modify proof as needed
		/// when information got accessed.
		stacked_pos: Vec<usize>,
	},
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateRecord<L: TrieLayout> {
	currently_query_item: Option<InMemQueryPlanItem>,
	stack: RecordStack<L>,
	// This indicate a restore point, it takes precedence over
	// stack and currently_query_item.
	from: Option<(Vec<u8>, bool)>,
}

impl<L: TrieLayout> HaltedStateRecord<L> {
	/// Indicate we reuse the query plan iterator
	/// and stack.
	pub fn statefull(&mut self, recorder: Recorder<L>) -> Vec<DBValue> {
		let result = core::mem::replace(&mut self.stack.recorder, recorder);
		result.output()
	}

	/// Indicate to use stateless (on a fresh proof
	/// and a fresh query plan iterator).
	pub fn stateless(&mut self, recorder: Recorder<L>) -> Vec<DBValue> {
		let new_start = Self::from_start(recorder);
		let old = core::mem::replace(self, new_start);
		self.from = old.from;
		self.currently_query_item = None;
		old.stack.recorder.output()
	}

	/// Init from start.
	pub fn from_start(recorder: Recorder<L>) -> Self {
		Self::from_at(recorder, None)
	}

	/// Init from position or start.
	pub fn from_at(recorder: Recorder<L>, at: Option<(Vec<u8>, bool)>) -> Self {
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

	/// If halted, postition where it was halted.
	pub fn stopped_at(&self) -> Option<(Vec<u8>, bool)> {
		self.from.clone()
	}

	/// Check if the state is halted.
	pub fn is_halted(&self) -> bool {
		self.from.is_some()
	}

	/// Finalize state, and return the proof output.
	pub fn finish(self) -> Vec<DBValue> {
		self.stack.recorder.output()
	}

	fn finalize(&mut self) -> Result<(), Error<TrieHash<L>, CError<L>>> {
		let stack = &mut self.stack;
		let items = &stack.items;
		match &mut stack.recorder.output {
			RecorderStateInner::Compact { output, proof, stacked_pos } => {
				// TODO apply same as content : record popped node calls??
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
								.map_err(|e| {
									if let Some(data) = e {
										// invalid node handle conversion for data
										Error::InvalidNodeHandle(data)
									} else {
										// unexpected node in proof
										Error::ExtraneousNode
									}
								})?;
								break
							}
						}
					}
				}
				for entry in core::mem::take(proof) {
					output.push(entry.into());
				}
			},
			RecorderStateInner::Stream(_output) => {
				// all written on access
			},
		}
		Ok(())
	}

	/// Callback on node before a node in the stack.
	/// `at` is the the position in the stack (in some case we keep
	/// the stack and will not pop the node).
	fn record_popped_node(&mut self, at: usize) -> Result<(), Error<TrieHash<L>, CError<L>>> {
		let item = self.stack.items.get(at).expect("bounded check call");
		if !self.stack.recorder.check_start_at(item.depth) {
			return Ok(())
		}

		match &mut self.stack.recorder.output {
			RecorderStateInner::Stream(_) => (),
			RecorderStateInner::Compact { proof, stacked_pos, .. } =>
				if !item.is_inline {
					if let Some(at) = stacked_pos.pop() {
						proof[at] = crate::trie_codec::encode_node_internal::<L::Codec>(
							&item.node,
							item.accessed_value_node,
							item.accessed_children_node,
						)
						.map_err(|e| {
							if let Some(data) = e {
								// invalid node handle conversion for data
								Error::InvalidNodeHandle(data)
							} else {
								// unexpected node in proof
								Error::ExtraneousNode
							}
						})?;
					} // else when restarting record, this is not to be recorded
				},
		}
		Ok(())
	}

	fn pop(&mut self) -> Result<bool, Error<TrieHash<L>, CError<L>>> {
		if self
			.stack
			.iter_prefix
			.map(|(l, _)| l == self.stack.items.len())
			.unwrap_or(false)
		{
			return Ok(false)
		}
		let at = self.stack.items.len();
		if at > 0 {
			self.record_popped_node(at - 1)?;
		}
		Ok(if let Some(item) = self.stack.items.pop() {
			let depth = self.stack.items.last().map(|i| i.depth).unwrap_or(0);
			self.stack.prefix.drop_lasts(self.stack.prefix.len() - depth);
			if depth == item.depth {
				// Two consecutive identical depth is an extension
				self.pop()?;
			}
			true
		} else {
			false
		})
	}

	fn iter_prefix(
		&mut self,
		prev_query: Option<&QueryPlanItem>,
		db: Option<&TrieDB<L>>,
		hash_only: bool,
		first_iter: bool,
	) -> Result<bool, Error<TrieHash<L>, CError<L>>> {
		let dummy_parent_hash = TrieHash::<L>::default();
		if first_iter {
			self.stack.enter_prefix_iter(hash_only);
		}

		// run prefix iteration
		let mut stacked = first_iter;
		loop {
			// descend
			loop {
				if stacked {
					// try access value in next node
					self.stack.access_value(db, hash_only)?;
					stacked = false;
				}

				let child_index = if let Some(item) = self.stack.items.last_mut() {
					if item.next_descended_child as usize >= NIBBLE_LENGTH {
						break
					}
					item.next_descended_child += 1;
					item.next_descended_child - 1
				} else {
					break
				};

				match self.stack.try_stack_child(child_index, db, dummy_parent_hash, None)? {
					TryStackChildResult::StackedFull => {
						stacked = true;
					},
					TryStackChildResult::StackedInto => unreachable!("Not following plan"),
					TryStackChildResult::StackedAfter => unreachable!("Not following plan"),
					TryStackChildResult::NotStackedBranch => (),
					TryStackChildResult::NotStacked => break,
					TryStackChildResult::Halted => {
						if let Some(item) = self.stack.items.last_mut() {
							item.next_descended_child -= 1;
						}
						self.stack.halt = false;
						self.stack.prefix.push(child_index);
						let dest_from = Some((
							self.stack.prefix.inner().to_vec(),
							(self.stack.prefix.len() % nibble_ops::NIBBLE_PER_BYTE) != 0,
						));
						self.stack.prefix.pop();
						self.finalize()?;
						self.stack.halt = false;
						self.from = dest_from;
						self.currently_query_item = prev_query.map(|q| q.to_owned());
						return Ok(true)
					},
				}
			}

			// pop
			if !self.pop()? {
				break
			}
		}
		self.stack.exit_prefix_iter();
		Ok(false)
	}
}

struct RecordStack<L: TrieLayout> {
	recorder: Recorder<L>,
	items: Vec<StackedNodeRecord>,
	prefix: NibbleVec,
	iter_prefix: Option<(usize, bool)>,
	seek: Option<NibbleVec>,
	halt: bool,
}

/// Run query plan on a full db and record it.
///
/// TODO output and restart are mutually exclusive. -> enum
/// or remove output from halted state.
pub fn record_query_plan<'a, L: TrieLayout, I: Iterator<Item = QueryPlanItem<'a>>>(
	db: &TrieDB<L>,
	query_plan: &mut QueryPlan<'a, I>,
	from: &mut HaltedStateRecord<L>,
) -> Result<(), Error<TrieHash<L>, CError<L>>> {
	let dummy_parent_hash = TrieHash::<L>::default();
	let mut stateless = false;
	let mut statefull = None;
	// From indicate we restart,.
	if let Some(lower_bound) = from.from.take() {
		if from.currently_query_item.is_none() {
			stateless = true;
			let mut bound = NibbleVec::new();
			bound.append_optional_slice_and_nibble(Some(&NibbleSlice::new(&lower_bound.0)), None);
			if lower_bound.1 {
				bound.pop();
			}
			from.stack.recorder.start_at = Some(bound.len() - 1);
			from.stack.seek = Some(bound);
		} else {
			// statefull case
			let bound_len = lower_bound.0.len() * nibble_ops::NIBBLE_PER_BYTE -
				if lower_bound.1 { 2 } else { 1 };
			from.stack.recorder.start_at = Some(bound_len);
			statefull = Some(bound_len);
		}
	}

	let mut prev_query: Option<QueryPlanItem> = None;
	let from_query = from.currently_query_item.take();
	let mut from_query_ref = from_query.as_ref().map(|f| f.as_ref());
	while let Some(query) = from_query_ref.clone().or_else(|| query_plan.items.next()) {
		if stateless {
			// advance query plan
			let bound = from.stack.seek.as_ref().expect("Initiated for stateless");
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
				from.stack.seek = None;
			}
		}
		if statefull.take().is_none() {
			let (ordered, common_nibbles) =
				prev_query.as_ref().map(|p| p.before(&query)).unwrap_or((true, 0));
			if !ordered {
				return Err(Error::UnorderedKey(query.key.to_vec()))
			}
			let skip_query = loop {
				match from.stack.prefix.len().cmp(&common_nibbles) {
					Ordering::Equal => break false,
					Ordering::Less => break true,
					Ordering::Greater =>
						if !from.pop()? {
							from.finalize()?;
							return Ok(())
						},
				}
			};
			if skip_query {
				// will go down in same branch, skip query_plan
				from_query_ref = None;
				prev_query = Some(query);
				continue
			}
		};
		if let Some((_, hash_only)) = from.stack.iter_prefix.clone() {
			// statefull halted during iteration.
			let halt = from.iter_prefix(Some(&query), Some(db), hash_only, false)?;
			if halt {
				return Ok(())
			}
			from_query_ref = None;
			prev_query = Some(query);
			continue
		}
		// descend
		let mut slice_query = NibbleSlice::new_offset(&query.key, from.stack.prefix.len());

		let touched = loop {
			if !from.stack.items.is_empty() {
				if slice_query.is_empty() {
					if query.as_prefix {
						let halt =
							from.iter_prefix(Some(&query), Some(db), query.hash_only, true)?;
						if halt {
							return Ok(())
						}
						break false
					} else {
						break true
					}
				}
			}

			let child_index = if from.stack.items.is_empty() { 0 } else { slice_query.at(0) };
			from.stack.items.last_mut().map(|i| {
				// TODO only needed for content but could be better to be always aligned
				i.next_descended_child = child_index + 1;
			});
			match from.stack.try_stack_child(
				child_index,
				Some(db),
				dummy_parent_hash,
				Some(&mut slice_query),
			)? {
				TryStackChildResult::StackedFull => {},
				TryStackChildResult::NotStackedBranch | TryStackChildResult::NotStacked =>
					break false,
				TryStackChildResult::StackedAfter => break false,
				TryStackChildResult::StackedInto => {
					if query.as_prefix {
						let halt =
							from.iter_prefix(Some(&query), Some(db), query.hash_only, true)?;
						if halt {
							return Ok(())
						}
					}
					break false
				},
				TryStackChildResult::Halted => {
					from.stack.halt = false;
					from.stack.prefix.push(child_index);
					from.from = Some((
						from.stack.prefix.inner().to_vec(),
						(from.stack.prefix.len() % nibble_ops::NIBBLE_PER_BYTE) != 0,
					));
					from.stack.prefix.pop();
					from.currently_query_item = Some(query.to_owned());
					from.finalize()?;
					return Ok(())
				},
			}
		};

		if touched {
			// try access value
			from.stack.access_value(Some(db), query.hash_only)?;
		}
		from_query_ref = None;
		prev_query = Some(query);
	}
	/*
	// TODO loop redundant with finalize??
	loop {
		if query_plan.kind.record_inline() {
			from.try_stack_content_child()?;
		}

		if !from.pop() {
			break
		}
	}
	*/
	from.finalize()?;
	Ok(())
}

impl<L: TrieLayout> RecordStack<L> {
	fn try_stack_child<'a>(
		&mut self,
		child_index: u8,
		db: Option<&TrieDB<L>>,
		parent_hash: TrieHash<L>,
		mut slice_query: Option<&mut NibbleSlice>,
	) -> Result<TryStackChildResult, Error<TrieHash<L>, CError<L>>> {
		let inline_only = db.is_none();
		let mut is_inline = false;
		let prefix = &mut self.prefix;
		let mut stack_extension = false;
		let mut from_branch = None;
		let child_handle = if let Some(item) = self.items.last_mut() {
			//if inline_only && item.accessed_children_node.at(child_index as usize) {
			debug_assert!(!item.accessed_children_node.at(child_index as usize));
			/*			if item.accessed_children_node.at(child_index as usize) {
				// No reason to go twice in a same branch
				return Ok(TryStackChildResult::NotStackedBranch)
			}*/

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
						if inline_only {
							// mark all accesses (
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
			NodeHandle::Hash(db.expect("Inline call on non empty stack only").root().as_ref())
		};
		match &child_handle {
			NodeHandle::Inline(_) => {
				// TODO consider not going into inline for all proof but content.
				// Returning NotStacked here sounds safe, then the is_inline field is not needed.
				is_inline = true;
			},
			NodeHandle::Hash(_) => {
				if inline_only {
					/* TODO this should write on pop not on stack...
					if self.recorder.touched_child_hash(hash, child_index) {
						self.halt = true;
					}
					*/
					return Ok(TryStackChildResult::NotStackedBranch)
				} else if self.halt && from_branch.is_some() {
					// halt condition
					return Ok(TryStackChildResult::Halted)
				}
			},
		}
		if let Some(accessed_children_node) = from_branch {
			if !is_inline {
				accessed_children_node.set(child_index as usize, true);
			}

			slice_query.as_mut().map(|s| s.advance(1));
			prefix.push(child_index);
		}
		let child_node = if let Some(db) = db {
			db.get_raw_or_lookup_with_cache(parent_hash, child_handle, prefix.as_prefix(), false)
				.map_err(|_| Error::IncompleteProof)?
				.0 // actually incomplete db: TODO consider switching error
		} else {
			let NodeHandle::Inline(node_data) = child_handle else {
				unreachable!("call on non inline node when db is None");
			};
			OwnedNode::new::<L::Codec>(node_data.to_vec()).map_err(|_| Error::IncompleteProof)?
		};

		let node_data = child_node.data();
		//println!("r: {:?}", &node_data);

		let result = match child_node.node_plan() {
			NodePlan::Branch { .. } | NodePlan::Empty => TryStackChildResult::StackedFull,
			NodePlan::Leaf { partial, .. } |
			NodePlan::NibbledBranch { partial, .. } |
			NodePlan::Extension { partial, .. } => {
				let partial = partial.build(node_data);
				prefix.append_partial(partial.right());
				if let Some(s) = slice_query.as_mut() {
					let common = partial.common_prefix(s);
					// s starts with partial
					let r = if common == partial.len() {
						TryStackChildResult::StackedFull
					} else if common == s.len() {
						// partial strats with s
						TryStackChildResult::StackedInto
					} else {
						TryStackChildResult::StackedAfter
					};
					s.advance(common);
					r
				} else {
					TryStackChildResult::StackedFull
				}
			},
		};
		if let NodePlan::Extension { .. } = child_node.node_plan() {
			stack_extension = true;
		}
		let next_descended_child = if let Some(seek) = self.seek.as_ref() {
			if result != TryStackChildResult::StackedAfter && prefix.len() < seek.len() {
				seek.at(prefix.len())
			} else {
				self.seek = None;
				0
			}
		} else {
			0
		};
		let infos = StackedNodeRecord {
			node: child_node,
			accessed_children_node: Default::default(),
			accessed_value_node: false,
			depth: prefix.len(),
			next_descended_child,
			is_inline,
		};
		self.halt |= self.recorder.record_stacked_node(&infos, self.items.is_empty());
		self.items.push(infos);
		if stack_extension {
			let sbranch = self.try_stack_child(0, db, parent_hash, slice_query)?;
			let TryStackChildResult::StackedFull = sbranch else {
				return Err(Error::InvalidChildReference(
					b"branch in db should follow extension".to_vec(),
				))
			};
		}

		Ok(result)
	}

	fn access_value<'a>(
		&mut self,
		db: Option<&TrieDB<L>>,
		hash_only: bool,
	) -> Result<bool, Error<TrieHash<L>, CError<L>>> {
		let Some(item) = self.items.last_mut() else { return Ok(false) };
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
					let Some(value) =
						db.expect("non inline").db().get(&hash, self.prefix.as_prefix())
					else {
						return Err(Error::IncompleteProof)
					};
					self.halt |= self.recorder.record_value_node(value, self.prefix.len());
				},
			Value::Inline(_) => (),
		}
		Ok(true)
	}

	fn enter_prefix_iter(&mut self, hash_only: bool) {
		self.iter_prefix = Some((self.items.len(), hash_only));
	}

	fn exit_prefix_iter(&mut self) {
		self.iter_prefix = None
	}
}

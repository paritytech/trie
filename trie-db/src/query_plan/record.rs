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
pub struct Recorder<O: RecorderOutput, L: TrieLayout> {
	output: RecorderStateInner<O>,
	limits: Limits,
	// on restore only record content AFTER this position.
	start_at: Option<usize>,
	_ph: PhantomData<L>,
}

impl<O: RecorderOutput, L: TrieLayout> Recorder<O, L> {
	// TODO rename same as record_inline functio
	fn mark_inline_access(&self) -> bool {
		match &self.output {
			RecorderStateInner::Content { .. } => true,
			_ => false,
		}
	}

	/// Check and update start at record.
	/// When return true, do record.
	/// TODO debug why it is needed.
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
				if flush_compact_content_pop::<O, L>(
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
				let op = Op::<TrieHash<L>, Vec<u8>>::KeyPush(buff.inner().to_vec(), mask);
				let init_len = output.buf_len();
				op.encode_into(output);
				let written = output.buf_len() - init_len;
				res = self.limits.add_node(written, 0, false);
			}
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
				let op = Op::<TrieHash<L>, Vec<u8>>::Value(value);
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
				let op = Op::<TrieHash<L>, &[u8]>::Value(value);
				let init_len = output.buf_len();
				op.encode_into(output);
				let written = output.buf_len() - init_len;
				res = self.limits.add_node(written, 0, false);
			},
		}
		res
	}

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
								Op::<_, Vec<u8>>::HashValue(hash)
							},
							Value::Inline(value) =>
								Op::<TrieHash<L>, Vec<u8>>::Value(value.to_vec()),
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

	#[must_use]
	fn touched_child_hash(&mut self, hash_slice: &[u8], i: u8) -> bool {
		let mut res = false;
		match &mut self.output {
			RecorderStateInner::Content { output, .. } => {
				let mut hash = TrieHash::<L>::default();
				hash.as_mut().copy_from_slice(hash_slice);
				let op = Op::<TrieHash<L>, Vec<u8>>::HashChild(hash, i as u8);
				let init_len = output.buf_len();
				op.encode_into(output);
				let written = output.buf_len() - init_len;
				res = self.limits.add_node(written, 0, false);
			},
			_ => (),
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

	fn finalize(&mut self) {
		let stack = &mut self.stack;
		let items = &stack.items;
		match &mut stack.recorder.output {
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
					let _ = self.record_popped_node(i);
				}
			},
		}
	}

	#[must_use]
	fn record_popped_node(&mut self, at: usize) -> bool {
		let item = self.stack.items.get(at).expect("bounded iter");
		let items = &self.stack.items[..at];
		let mut res = false;
		if !self.stack.recorder.check_start_at(item.depth) {
			return res
		}
		if let RecorderStateInner::Content { .. } = &self.stack.recorder.output {
			// if no value accessed, then we can have push then stack pop.
			if self.stack.recorder.flush_compact_content_pushes(item.depth) {
				res = true;
			}
		}

		let mut process_children = false;
		let mut has_hash_to_write = false;
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
						.expect("TODO error handling, can it actually fail?");
					} // else when restarting record, this is not to be recorded
				},
			RecorderStateInner::Content { .. } => {
				// two case: children to register or all children accessed.
				if let Some(last_item) = items.last() {
					match last_item.node.node_plan() {
						NodePlan::Branch { children, .. } |
						NodePlan::NibbledBranch { children, .. } => {
							process_children = true;
							for i in 0..children.len() {
								if children[i].is_some() && !last_item.accessed_children_node.at(i)
								{
									has_hash_to_write = true;
									break
								}
							}
						},
						_ => (),
					}
				}
			},
		}

		if process_children {
			self.try_stack_content_child().expect("stack inline do not fetch");
		}
		let items = &self.stack.items[..at];
		match &mut self.stack.recorder.output {
			RecorderStateInner::Content { output, stacked_pop, .. } => {
				let item = &self.stack.items.get(at).expect("bounded iter");
				if stacked_pop.is_none() {
					*stacked_pop = Some(item.depth);
				}

				if has_hash_to_write {
					if flush_compact_content_pop::<O, L>(
						output,
						stacked_pop,
						items,
						None,
						&mut self.stack.recorder.limits,
					) {
						res = true;
					}
				}
			},
			_ => (),
		}

		res
	}

	// Add child for content
	fn try_stack_content_child(
		&mut self,
		//upper: u8,
	) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
		let dummy_parent_hash = TrieHash::<L>::default();
		if !self.stack.items.is_empty() {
			for i in 0..NIBBLE_LENGTH as u8 {
				match self.stack.try_stack_child(i, None, dummy_parent_hash, None, true)? {
					// only expect a stacked prefix here
					TryStackChildResult::Stacked => {
						let halt = self.iter_prefix(None, None, false, true, true)?;
						if halt {
							// no halt on inline.
							unreachable!()
						} else {
							self.pop();
						}
					},
					TryStackChildResult::NotStackedBranch => (),
					_ => break,
				}
			}
		}
		self.stack
			.items
			.last_mut()
			.map(|i| i.next_descended_child = NIBBLE_LENGTH as u8);
		Ok(())
	}

	fn pop(&mut self) -> bool {
		if self
			.stack
			.iter_prefix
			.map(|(l, _)| l == self.stack.items.len())
			.unwrap_or(false)
		{
			return false
		}
		let at = self.stack.items.len();
		if at > 0 {
			if self.record_popped_node(at - 1) {
				self.stack.halt = true;
			}
		}
		if let Some(item) = self.stack.items.pop() {
			let depth = self.stack.items.last().map(|i| i.depth).unwrap_or(0);
			self.stack.prefix.drop_lasts(self.stack.prefix.len() - depth);
			if depth == item.depth {
				// Two consecutive identical depth is an extension
				self.pop();
			}
			true
		} else {
			false
		}
	}

	fn iter_prefix(
		&mut self,
		prev_query: Option<&QueryPlanItem>,
		db: Option<&TrieDB<L>>,
		hash_only: bool,
		first_iter: bool,
		inline_iter: bool,
	) -> Result<bool, VerifyError<TrieHash<L>, CError<L>>> {
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

				let child_index = if let Some(mut item) = self.stack.items.last_mut() {
					if item.next_descended_child as usize >= NIBBLE_LENGTH {
						break
					}
					item.next_descended_child += 1;
					item.next_descended_child - 1
				} else {
					break
				};

				match self.stack.try_stack_child(
					child_index,
					db,
					dummy_parent_hash,
					None,
					inline_iter,
				)? {
					TryStackChildResult::Stacked => {
						stacked = true;
					},
					TryStackChildResult::NotStackedBranch => (),
					TryStackChildResult::NotStacked => break,
					TryStackChildResult::StackedDescendIncomplete => {
						unreachable!("no slice query")
					},
					TryStackChildResult::Halted => {
						if let Some(mut item) = self.stack.items.last_mut() {
							item.next_descended_child -= 1;
						}
						self.stack.halt = false;
						self.stack.prefix.push(child_index);
						let dest_from = Some((
							self.stack.prefix.inner().to_vec(),
							(self.stack.prefix.len() % nibble_ops::NIBBLE_PER_BYTE) != 0,
						));
						self.stack.prefix.pop();
						self.finalize();
						self.from = dest_from;
						self.currently_query_item = prev_query.map(|q| q.to_owned());
						return Ok(true)
					},
				}
			}

			// pop
			if !self.pop() {
				break
			}
		}
		self.stack.exit_prefix_iter();
		Ok(false)
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
	from: &mut HaltedStateRecord<O, L>,
) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
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

	let mut prev_query: Option<QueryPlanItem> = None;
	let from_query = from.currently_query_item.take();
	let mut from_query_ref = from_query.as_ref().map(|f| f.as_ref());
	while let Some(query) = from_query_ref.clone().or_else(|| query_plan.items.next()) {
		if stateless {
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
				match from.stack.prefix.len().cmp(&common_nibbles) {
					Ordering::Equal | Ordering::Less => break,
					Ordering::Greater => {
						if query_plan.kind.record_inline() {
							from.try_stack_content_child()?;
						}
						if !from.pop() {
							from.finalize();
							return Ok(())
						}
					},
				}
			}
			common_nibbles
		};
		if let Some((_, hash_only)) = from.stack.iter_prefix.clone() {
			// statefull halted during iteration.
			let halt = from.iter_prefix(Some(&query), Some(db), hash_only, false, false)?;
			if halt {
				return Ok(())
			}
			from_query_ref = None;
			prev_query = Some(query);
			continue
		}
		// descend
		let add = if from.stack.items.len() == 0 { 0 } else { 1 };
		let mut slice_query = NibbleSlice::new_offset(&query.key, from.stack.prefix.len() + add);

		let touched = loop {
			if !from.stack.items.is_empty() {
				if slice_query.is_empty() {
					if query.as_prefix {
						let halt =
							from.iter_prefix(Some(&query), Some(db), query.hash_only, true, false)?;
						if halt {
							return Ok(())
						}
						break false
					} else {
						break true
					}
				} else {
					if from.stack.recorder.record_skip_value(&mut from.stack.items) {
						from.stack.halt = true;
					}
				}
			}

			let child_index = if from.stack.items.is_empty() { 0 } else { slice_query.at(0) };
			/*if query_plan.kind.record_inline() {
				from.try_stack_content_child(child_index)?;
			}*/
			from.stack.items.last_mut().map(|i| {
				// TODO only needed for content but could be better to be always aligned
				i.next_descended_child = child_index + 1;
			});
			match from.stack.try_stack_child(
				child_index,
				Some(db),
				dummy_parent_hash,
				Some(&mut slice_query),
				false,
			)? {
				TryStackChildResult::Stacked => {},
				TryStackChildResult::NotStackedBranch | TryStackChildResult::NotStacked =>
					break false,
				TryStackChildResult::StackedDescendIncomplete => {
					if query.as_prefix {
						let halt =
							from.iter_prefix(Some(&query), Some(db), query.hash_only, true, false)?;
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
					from.finalize();
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
	// TODO loop redundant with finalize??
	loop {
		if query_plan.kind.record_inline() {
			from.try_stack_content_child()?;
		}

		if !from.pop() {
			break
		}
	}
	from.finalize();
	Ok(())
}

impl<O: RecorderOutput, L: TrieLayout> RecordStack<O, L> {
	fn try_stack_child<'a>(
		&mut self,
		child_index: u8,
		db: Option<&TrieDB<L>>,
		parent_hash: TrieHash<L>,
		mut slice_query: Option<&mut NibbleSlice>,
		inline_only: bool, // TODO remove all inline only param and make it db is_none TODO rename
	) -> Result<TryStackChildResult, VerifyError<TrieHash<L>, CError<L>>> {
		let mut is_inline = false;
		let prefix = &mut self.prefix;
		let mut descend_incomplete = false;
		let mut descend_incomplete_stacked = false;
		let mut stack_extension = false;
		let mut from_branch = None;
		let child_handle = if let Some(item) = self.items.last_mut() {
			if inline_only && item.accessed_children_node.at(child_index as usize) {
				return Ok(TryStackChildResult::NotStackedBranch)
			}

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
			NodeHandle::Hash(db.expect("non inline").root().as_ref())
		};
		match &child_handle {
			NodeHandle::Inline(_) => {
				// TODO consider not going into inline for all proof but content.
				// Returning NotStacked here sounds safe, then the is_inline field is not needed.
				is_inline = true;
			},
			NodeHandle::Hash(hash) => {
				if inline_only {
					if self.recorder.touched_child_hash(hash, child_index) {
						self.halt = true;
					}
					if self.recorder.mark_inline_access() {
						if let Some(accessed_children_node) = from_branch {
							accessed_children_node.set(child_index as usize, true);
						}
					}
					return Ok(TryStackChildResult::NotStackedBranch)
				}
				if self.halt && from_branch.is_some() {
					return Ok(TryStackChildResult::Halted)
				}
			},
		}
		if let Some(accessed_children_node) = from_branch {
			if !is_inline || self.recorder.mark_inline_access() {
				accessed_children_node.set(child_index as usize, true);
			}

			slice_query.as_mut().map(|s| s.advance(1));
			prefix.push(child_index);
		}
		// TODO handle cache first
		let child_node = if let Some(db) = db {
			db.get_raw_or_lookup_with_cache(parent_hash, child_handle, prefix.as_prefix(), false)
				.map_err(|_| VerifyError::IncompleteProof)? // actually incomplete db: TODO consider switching error
		} else {
			let NodeHandle::Inline(node_data) = child_handle else {
				unreachable!("call on non inline node when db is None");
			};
			(
				OwnedNode::new::<L::Codec>(node_data.to_vec())
					.map_err(|_| VerifyError::IncompleteProof)?,
				None,
			)
		};

		// }

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
						descend_incomplete_stacked = partial.starts_with(s);
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
		if self.recorder.record_stacked_node(
			&infos,
			self.items.is_empty(),
			child_index,
			&self.items,
		) {
			self.halt = true;
		}
		self.items.push(infos);
		if stack_extension {
			let sbranch = self.try_stack_child(0, db, parent_hash, slice_query, inline_only)?;
			let TryStackChildResult::Stacked = sbranch else {
				return Err(VerifyError::InvalidChildReference(b"branch in db should follow extension".to_vec()));
			};
		}

		if descend_incomplete {
			if descend_incomplete_stacked {
				Ok(TryStackChildResult::StackedDescendIncomplete)
			} else {
				Ok(TryStackChildResult::NotStacked)
			}
		} else {
			Ok(TryStackChildResult::Stacked)
		}
	}

	fn access_value<'a>(
		&mut self,
		db: Option<&TrieDB<L>>,
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
					let Some(value) = db.expect("non inline").db().get(&hash, self.prefix.as_prefix()) else {
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

	fn enter_prefix_iter(&mut self, hash_only: bool) {
		self.iter_prefix = Some((self.items.len(), hash_only));
	}

	fn exit_prefix_iter(&mut self) {
		self.iter_prefix = None
	}
}

#[must_use]
fn flush_compact_content_pop<O: RecorderOutput, L: TrieLayout>(
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
	let op = Op::<TrieHash<L>, Vec<u8>>::KeyPop((from - pop_to) as u16);
	let init_len = out.buf_len();
	op.encode_into(out);
	let written = out.buf_len() - init_len;
	limits.add_node(written, 0, false)
}

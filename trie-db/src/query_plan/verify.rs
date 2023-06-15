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

//! Verify query plan proof.

use super::*;
use core::marker::PhantomData;

use crate::{
	nibble::{nibble_ops, nibble_ops::NIBBLE_LENGTH, NibbleSlice},
	proof::VerifyError,
	rstd::{boxed::Box, result::Result},
	CError, TrieHash, TrieLayout,
};
pub use record::{record_query_plan, HaltedStateRecord, Recorder};

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
		if self.state == ReadProofState::Halted {
			self.state = ReadProofState::Running;
		}
		let mut to_check_slice = self
			.current
			.as_ref()
			.map(|n| NibbleSlice::new_offset(n.key, self.restore_offset));

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

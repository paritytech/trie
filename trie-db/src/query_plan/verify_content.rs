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

//! Verify query plan proof for content proofs.

use super::*;
use core::marker::PhantomData;

use crate::{
	content_proof::Op, nibble::LeftNibbleSlice, proof::VerifyError, rstd::result::Result, CError,
	TrieHash, TrieLayout,
};
pub use record::{record_query_plan, HaltedStateRecord, Recorder};

/// Proof reading iterator.
pub struct ReadProofContentIterator<'a, L, C, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = Option<Op<TrieHash<L>, Vec<u8>>>>,
{
	// always needed, this is option only
	// to avoid unsafe code when halting.
	query_plan: Option<QueryPlan<'a, C>>,
	proof: P,
	expected_root: Option<TrieHash<L>>,
	current: Option<QueryPlanItem<'a>>,
	state: ReadProofState,
	stack: ReadContentStack<L>,
	buf_op: Option<Op<TrieHash<L>, Vec<u8>>>,
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
	P: Iterator<Item = Option<Op<TrieHash<L>, Vec<u8>>>>,
{
	let HaltedStateCheck::Content(state) = state else {
		return Err(VerifyError::IncompleteProof) // TODO not kind as param if keeping CompactContent
	};

	let HaltedStateCheckContent { query_plan, current, stack, state } = state;

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
		buf_op: None,
	})
}

impl<'a, L, C, P> Iterator for ReadProofContentIterator<'a, L, C, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = Option<Op<TrieHash<L>, Vec<u8>>>>,
{
	type Item = Result<ReadProofItem<'a, L, C, Vec<u8>>, VerifyError<TrieHash<L>, CError<L>>>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.state == ReadProofState::Finished {
			return None
		}
		if self.state == ReadProofState::Halted {
			self.state = ReadProofState::Running;
		}
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

					let r = self.stack.pop_until(common_nibbles, false);
					if let Err(e) = r {
						self.state = ReadProofState::Finished;
						return Some(Err(e))
					}
					self.state = ReadProofState::Running;
					self.current = Some(next);
				} else {
					self.state = ReadProofState::PlanConsumed;
					self.current = None;
				}
			};

			// op sequence check
			let mut from_iter = false;
			while let Some(op) = self.buf_op.take().map(Option::Some).or_else(|| {
				from_iter = true;
				self.proof.next()
			}) {
				println!("read: {:?}", op);
				let Some(op) = op else {
					let r = self.stack.stack_pop(None, &self.expected_root);
						self.state = ReadProofState::Finished;
						if let Err(e) = r {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						}
						if let Some(c) = self.current.as_ref() {
						if c.as_prefix {
							// end prefix switch to next
							self.state = ReadProofState::SwitchQueryPlan;
							break;
						} else {
							// missing value
							self.state = ReadProofState::SwitchQueryPlan;
							return Some(Ok(ReadProofItem::NoValue(&c.key)));
						}
					} else {
						return None; // finished
					}
				};
				if from_iter {
					// check ordering logic
					// TODO wrap in an error and put bools in a struct
					match &op {
						Op::KeyPush(..) => {
							if self.stack.is_prev_push_key {
								self.state = ReadProofState::Finished;
								return Some(Err(VerifyError::ExtraneousNode)) // TODO a decode op error
								              // TODO return
								              // Err(CompactDecoderError::ConsecutivePushKeys.
								              // into())
							}
							self.stack.is_prev_push_key = true;
							self.stack.is_prev_pop_key = false;
							self.stack.is_prev_hash_child = None;
							self.stack.first = false;
						},
						Op::KeyPop(..) => {
							if self.stack.is_prev_pop_key {
								self.state = ReadProofState::Finished;
								return Some(Err(VerifyError::ExtraneousNode)) // TODO a decode op error
								              // return Err(CompactDecoderError::ConsecutivePopKeys.
								              // into())
							}
							self.stack.is_prev_push_key = false;
							self.stack.is_prev_pop_key = true;
							self.stack.is_prev_hash_child = None;
							self.stack.first = false;
						},
						Op::HashChild(_, ix) => {
							if let Some(prev_ix) = self.stack.is_prev_hash_child.as_ref() {
								if prev_ix >= ix {
									self.state = ReadProofState::Finished;
									return Some(Err(VerifyError::ExtraneousNode)) // TODO a decode op error
									          // return Err(CompactDecoderError::NotConsecutiveHash.
									          // into())
								}
							}
							// child ix on an existing content would be handle by iter_build.
							self.stack.is_prev_push_key = false;
							self.stack.is_prev_pop_key = false;
							self.stack.is_prev_hash_child = Some(*ix);
						},
						Op::Value(_) => {
							//	| Op::ValueForceInline(_) | Op::ValueForceHashed(_) => {
							if !(self.stack.is_prev_push_key || self.stack.first) {
								self.state = ReadProofState::Finished;
								return Some(Err(VerifyError::ExtraneousNode)) // TODO a decode op error
								              // return Err(CompactDecoderError::ValueNotAfterPush.
								              // into())
							}
							self.stack.is_prev_push_key = false;
							self.stack.is_prev_pop_key = false;
							self.stack.is_prev_hash_child = None;
							self.stack.first = false;
						},
						_ => {
							self.stack.is_prev_push_key = false;
							self.stack.is_prev_pop_key = false;
							self.stack.is_prev_hash_child = None;
							self.stack.first = false;
						},
					}

					// debug TODO make it log and external function
					match &op {
						Op::HashChild(hash, child_ix) => {
							println!(
								"ChildHash {:?}, {:?}, {:?}",
								self.stack.prefix, child_ix, hash
							);
						},
						Op::HashValue(hash) => {
							println!("ValueHash {:?}, {:?}", self.stack.prefix, hash);
						},
						Op::Value(value) => {
							println!("Value {:?}, {:?}", self.stack.prefix, value);
						},
						_ => (),
					}
				}
				from_iter = false;

				// next
				let item = if match &op {
					Op::Value(..) | Op::HashValue(..) => true,
					_ => false,
				} {
					let mut at_value = false;
					let mut next_query = false;
					if let Some(current) = self.current.as_ref() {
						let query_slice = LeftNibbleSlice::new(&current.key);
						match self.stack.prefix.as_leftnibbleslice().cmp(&query_slice) {
							Ordering::Equal =>
								if !self.stack.items.is_empty() {
									at_value = true;
								},
							Ordering::Less => (),
							Ordering::Greater =>
								if current.as_prefix {
									let query_slice = LeftNibbleSlice::new(&current.key);
									if self
										.stack
										.prefix
										.as_leftnibbleslice()
										.starts_with(&query_slice)
									{
										at_value = true;
									} else {
										next_query = true;
									}
								} else {
									next_query = true;
								},
						}
						if next_query {
							self.buf_op = Some(op);
							self.state = ReadProofState::SwitchQueryPlan;
							if current.as_prefix {
								break
							} else {
								return Some(Ok(ReadProofItem::NoValue(&current.key)))
							}
						}
					}

					if at_value {
						match &op {
							Op::Value(value) => {
								// TODO could get content from op with no clone.
								Some(ReadProofItem::Value(
									self.stack.prefix.inner().to_vec().into(),
									value.clone(),
								))
							},
							Op::HashValue(hash) => {
								// TODO could get content from op with no clone.
								Some(ReadProofItem::Hash(
									self.stack.prefix.inner().to_vec().into(),
									hash.clone(),
								))
							},
							_ => unreachable!(),
						}
					} else {
						match &op {
							Op::Value(value) => {
								// hash value here not value
								if L::MAX_INLINE_VALUE
									.map(|max| max as usize <= value.len())
									.unwrap_or(false)
								{
									self.state = ReadProofState::Finished;
									return Some(Err(VerifyError::ExtraneousValue(value.clone())))
								}
							},
							_ => (),
						}
						None
					}
				} else {
					None
				};

				// act
				let r = match op {
					Op::KeyPush(partial, mask) => {
						self.stack
							.prefix
							.append_slice(LeftNibbleSlice::new_with_mask(partial.as_slice(), mask));
						self.stack.stack_empty(self.stack.prefix.len());
						Ok(())
					},
					Op::KeyPop(nb_nibble) => {
						let r = self.stack.stack_pop(Some(nb_nibble as usize), &self.expected_root);
						self.stack.prefix.drop_lasts(nb_nibble.into());
						r
					},
					Op::EndProof => break,
					op => self.stack.set_cache_change(op.into()),
				};
				if let Err(e) = r {
					self.state = ReadProofState::Finished;
					return Some(Err(e))
				}
				if let Some(r) = item {
					if self.current.as_ref().map(|c| !c.as_prefix).unwrap_or(true) {
						self.state = ReadProofState::SwitchQueryPlan; // TODO this is same as content NOne?
					}
					return Some(Ok(r))
				}
			}
			if self.state != ReadProofState::SwitchQueryPlan && self.current.is_some() {
				// TODO return halt instead
				return Some(Err(VerifyError::IncompleteProof))
			}
			self.state = ReadProofState::SwitchQueryPlan;
		}

		/*
		self.state = ReadProofState::Finished;
		if self.proof.next().is_some() {
			return Some(Err(VerifyError::ExtraneousNode))
		} else {
			return None
		}
			*/
	}
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateCheckContent<'a, L: TrieLayout, C> {
	query_plan: QueryPlan<'a, C>,
	current: Option<QueryPlanItem<'a>>,
	stack: ReadContentStack<L>,
	state: ReadProofState,
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
				is_prev_push_key: false,
				is_prev_pop_key: false,
				is_prev_hash_child: None,
				first: true,
				_ph: PhantomData,
			},
			state: ReadProofState::NotStarted,
			current: None,
			query_plan,
		}
	}
}

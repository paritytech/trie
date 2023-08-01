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

/// Result of verify iterator.
type VerifyIteratorResult<'a, L, C, D> =
	Result<ReadProofItem<'a, L, C, D>, VerifyError<TrieHash<L>, CError<L>>>;

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
	current_offset: usize,
	state: ReadProofState,
	stack: Stack<L, D>,
	send_enter_prefix: Option<Vec<u8>>,
	send_exit_prefix: bool,
	buffed_result: Option<Option<VerifyIteratorResult<'a, L, C, D>>>,
}

struct Stack<L: TrieLayout, D: SplitFirst> {
	items: Vec<StackedNodeCheck<L, D>>,
	prefix: NibbleVec,
	// limit and wether we return value and if hash only iteration.
	iter_prefix: Option<InPrefix>,
	start_items: usize,
	is_compact: bool,
	expect_value: bool,
	accessed_root: bool,
	_ph: PhantomData<L>,
}

impl<L: TrieLayout, D: SplitFirst> Clone for Stack<L, D> {
	fn clone(&self) -> Self {
		Stack {
			items: self.items.clone(),
			prefix: self.prefix.clone(),
			start_items: self.start_items.clone(),
			iter_prefix: self.iter_prefix.clone(),
			is_compact: self.is_compact,
			expect_value: self.expect_value,
			accessed_root: self.accessed_root,
			_ph: PhantomData,
		}
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

	Ok(ReadProofIterator {
		query_plan: Some(query_plan),
		proof,
		is_compact: stack.is_compact,
		expected_root,
		current,
		state,
		stack,
		current_offset: restore_offset,
		send_enter_prefix: None,
		send_exit_prefix: false,
		buffed_result: None,
	})
}

impl<'a, L, C, D, P> ReadProofIterator<'a, L, C, D, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = D>,
	D: SplitFirst,
{
	fn halt(&mut self) -> VerifyIteratorResult<'a, L, C, D> {
		if self.is_compact {
			let r = self.stack.pop_until(None, &self.expected_root, true);
			if let Err(e) = r {
				self.state = ReadProofState::Finished;
				return Err(e)
			}
		}
		self.state = ReadProofState::Finished;
		let query_plan = crate::rstd::mem::replace(&mut self.query_plan, None);
		let query_plan = query_plan.expect("Init with state");
		let current = crate::rstd::mem::take(&mut self.current);
		let mut stack = crate::rstd::mem::replace(
			// TODO impl default and use take
			&mut self.stack,
			Stack {
				items: Default::default(),
				start_items: 0,
				prefix: Default::default(),
				is_compact: self.is_compact,
				expect_value: false,
				iter_prefix: None,
				accessed_root: false,
				_ph: PhantomData,
			},
		);
		stack.start_items = stack.items.len();
		Ok(ReadProofItem::Halted(Box::new(HaltedStateCheck {
			query_plan,
			current,
			restore_offset: self.current_offset,
			stack,
			state: ReadProofState::Halted,
		})))
	}

	fn enter_prefix_iter(&mut self, hash_only: bool, key: &[u8]) {
		self.send_enter_prefix = Some(key.to_vec());
		self.stack.iter_prefix =
			Some(InPrefix { start: self.stack.items.len(), send_value: false, hash_only });
	}

	fn exit_prefix_iter(&mut self) {
		self.send_exit_prefix = true;
		self.stack.iter_prefix = None
	}
}

impl<'a, L, C, D, P> Iterator for ReadProofIterator<'a, L, C, D, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = D>,
	D: SplitFirst,
{
	type Item = VerifyIteratorResult<'a, L, C, D>;

	fn next(&mut self) -> Option<Self::Item> {
		debug_assert!(self.send_enter_prefix.is_none());
		debug_assert!(!self.send_exit_prefix);
		if let Some(r) = self.buffed_result.take() {
			return r
		}
		let r = self.next_inner();
		if let Some(k) = self.send_enter_prefix.take() {
			self.buffed_result = Some(r);
			return Some(Ok(ReadProofItem::StartPrefix(k)))
		}
		if self.send_exit_prefix {
			self.buffed_result = Some(r);
			self.send_exit_prefix = false;
			return Some(Ok(ReadProofItem::EndPrefix))
		} else {
			r
		}
	}
}

impl<'a, L, C, D, P> ReadProofIterator<'a, L, C, D, P>
where
	L: TrieLayout,
	C: Iterator<Item = QueryPlanItem<'a>>,
	P: Iterator<Item = D>,
	D: SplitFirst,
{
	fn next_inner(&mut self) -> Option<VerifyIteratorResult<'a, L, C, D>> {
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
			.map(|n| NibbleSlice::new_offset(n.key, self.current_offset));

		// read proof
		loop {
			if self.send_exit_prefix {
				debug_assert!(self.send_enter_prefix.is_none());
				debug_assert!(self.buffed_result.is_none());
				self.send_exit_prefix = false;
				return Some(Ok(ReadProofItem::EndPrefix))
			}
			if self.state == ReadProofState::SwitchQueryPlan ||
				self.state == ReadProofState::SwitchQueryPlanInto ||
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
						self.state = ReadProofState::Finished;
						return Some(Err(VerifyError::UnorderedKey(next.key.to_vec())))
					}

					match self.stack.pop_until(Some(common_nibbles), &self.expected_root, false) {
						Ok(true) => {
							self.current = Some(next);
							let current = self.current.as_ref().expect("current is set");
							return self.missing_switch_next(current.as_prefix, current.key, false)
						},
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
						Ok(false) => (),
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

			while let Some(InPrefix { send_value, hash_only, .. }) = self.stack.iter_prefix.clone()
			{
				// prefix iteration
				if !send_value {
					self.stack.iter_prefix.as_mut().map(|s| {
						s.send_value = true;
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
					) {
						Ok(r) => r,
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
					};
					self.current_offset = to_check_slice.map(|s| s.offset()).unwrap_or(0);
					match r {
						TryStackChildResult::StackedFull => {
							self.stack.iter_prefix.as_mut().map(|p| {
								p.send_value = false;
							});
							break
						},
						TryStackChildResult::StackedAfter | TryStackChildResult::StackedInto => {
							unreachable!("slice query none");
						},
						TryStackChildResult::NotStacked => break,
						TryStackChildResult::NotStackedBranch => (),
						TryStackChildResult::Halted => {
							if let Some(last) = self.stack.items.last_mut() {
								last.next_descended_child -= 1;
							}
							return Some(self.halt())
						},
					}
				}
				if self.stack.iter_prefix.as_ref().map(|p| p.send_value).unwrap_or_default() {
					if !match self.stack.pop(&self.expected_root) {
						Ok(r) => r,
						Err(e) => {
							self.state = ReadProofState::Finished;
							return Some(Err(e))
						},
					} {
						// end iter
						self.exit_prefix_iter();
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
					// two consecutive query in a node that hide them (two miss in a same proof
					// node).
					return self.missing_switch_next(as_prefix, to_check.key, false)
				},
			}

			if at_value {
				if as_prefix {
					self.enter_prefix_iter(
						hash_only,
						&self.current.as_ref().expect("enter prefix").key,
					);
					continue
				}
				self.state = ReadProofState::SwitchQueryPlanInto;
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
			) {
				Ok(r) => r,
				Err(e) => {
					self.state = ReadProofState::Finished;
					return Some(Err(e))
				},
			};
			self.current_offset = to_check_slice.offset();
			match r {
				TryStackChildResult::StackedFull => (),
				TryStackChildResult::StackedInto => {
					if as_prefix {
						self.enter_prefix_iter(
							hash_only,
							&self.current.as_ref().expect("enter prefix").key,
						);
						continue
					}
					self.state = ReadProofState::SwitchQueryPlanInto;
					return Some(Ok(ReadProofItem::NoValue(to_check.key)))
				},
				TryStackChildResult::NotStackedBranch | TryStackChildResult::NotStacked =>
					return self.missing_switch_next(as_prefix, to_check.key, false),
				TryStackChildResult::StackedAfter =>
					return self.missing_switch_next(as_prefix, to_check.key, true),
				TryStackChildResult::Halted => return Some(self.halt()),
			}
		}

		debug_assert!(self.state == ReadProofState::PlanConsumed);
		if self.is_compact {
			let r = self.stack.pop_until(None, &self.expected_root, false);
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

	fn missing_switch_next(
		&mut self,
		as_prefix: bool,
		key: &'a [u8],
		into: bool,
	) -> Option<VerifyIteratorResult<'a, L, C, D>> {
		self.state = if into {
			ReadProofState::SwitchQueryPlanInto
		} else {
			ReadProofState::SwitchQueryPlan
		};
		if as_prefix {
			self.send_enter_prefix = Some(key.to_vec());
			return Some(Ok(ReadProofItem::EndPrefix))
		} else {
			return Some(Ok(ReadProofItem::NoValue(key)))
		}
	}
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateCheck<'a, L: TrieLayout, C, D: SplitFirst> {
	query_plan: QueryPlan<'a, C>,
	current: Option<QueryPlanItem<'a>>,
	stack: Stack<L, D>,
	state: ReadProofState,
	restore_offset: usize,
}

impl<'a, L: TrieLayout, C, D: SplitFirst> From<QueryPlan<'a, C>> for HaltedStateCheck<'a, L, C, D> {
	fn from(query_plan: QueryPlan<'a, C>) -> Self {
		// TODO a method in kind
		let is_compact = match query_plan.kind {
			ProofKind::FullNodes => false,
			ProofKind::CompactNodes => true,
		};

		HaltedStateCheck {
			stack: Stack {
				items: Default::default(),
				start_items: 0,
				prefix: Default::default(),
				is_compact,
				expect_value: false,
				iter_prefix: None,
				accessed_root: false,
				_ph: PhantomData,
			},
			state: ReadProofState::NotStarted,
			current: None,
			restore_offset: 0,
			query_plan,
		}
	}
}

impl<L: TrieLayout, D: SplitFirst> Stack<L, D> {
	fn try_stack_child(
		&mut self,
		child_index: u8,
		proof: &mut impl Iterator<Item = D>,
		expected_root: &Option<TrieHash<L>>,
		mut slice_query: Option<&mut NibbleSlice>,
	) -> Result<TryStackChildResult, VerifyError<TrieHash<L>, CError<L>>> {
		let check_hash = expected_root.is_some();
		let items_len = self.items.len();
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
			if self.accessed_root {
				return Ok(TryStackChildResult::NotStacked)
			}
			if self.is_compact {
				NodeHandle::Inline(&[])
			} else {
				NodeHandle::Hash(expected_root.as_ref().map(AsRef::as_ref).unwrap_or(&[]))
			}
		};
		let mut node: StackedNodeCheck<_, _> = match child_handle {
			NodeHandle::Inline(data) =>
				if self.is_compact && data.len() == 0 {
					// ommitted hash
					let Some(mut encoded_node) = proof.next() else {
						// halt happens with a hash, this is not.
						return Err(VerifyError::IncompleteProof)
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
				let Some(mut encoded_node) = proof.next() else {
					return Ok(TryStackChildResult::Halted)
				};
				if self.is_compact && items_len > self.start_items {
					let mut error_hash = TrieHash::<L>::default();
					error_hash.as_mut().copy_from_slice(hash);
					return Err(VerifyError::ExtraneousHashReference(error_hash))
				}
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
		let mut result = TryStackChildResult::StackedFull;
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
					self.prefix.push(child_index);
				}
				result = if let Some(slice) = slice_query.as_mut() {
					if slice.starts_with(&partial) {
						TryStackChildResult::StackedFull
					} else if partial.starts_with(slice) {
						TryStackChildResult::StackedInto
					} else {
						TryStackChildResult::StackedAfter
					}
				} else {
					TryStackChildResult::StackedFull
				};
				if result != TryStackChildResult::StackedFull {
					// end of query
				} else if let Some(slice) = slice_query.as_mut() {
					slice.advance(partial.len());
				}
				self.prefix.append_partial(partial.right());
			},
		}
		if let NodePlan::Extension { child, .. } = node.node_plan() {
			let node_data = node.data();
			let child = child.build(node_data);
			match child {
				NodeHandle::Hash(hash) => {
					let Some(encoded_branch) = proof.next() else {
						// No halt on extension node (restart over a child index).
						return Err(VerifyError::IncompleteProof)
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
		Ok(result)
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
								return Err(VerifyError::IncompleteProof)
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
							return Err(VerifyError::IncompleteProof)
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
		if self.iter_prefix.as_ref().map(|p| p.start == self.items.len()).unwrap_or(false) {
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
		target: Option<usize>,
		expected_root: &Option<TrieHash<L>>,
		check_only: bool,
	) -> Result<bool, VerifyError<TrieHash<L>, CError<L>>> {
		if self.is_compact && expected_root.is_some() {
			// TODO pop with check only, here unefficient implementation where we just restore

			let mut restore = None;
			if check_only {
				restore = Some(self.clone());
				self.iter_prefix = None;
			}
			// one by one
			while let Some(last) = self.items.last() {
				if let Some(target) = target.as_ref() {
					match last.depth.cmp(&target) {
						Ordering::Greater => (),
						// depth should match.
						Ordering::Less => {
							// skip query plan
							return Ok(true)
						},
						Ordering::Equal => return Ok(false),
					}
				}
				// one by one
				let _ = self.pop(expected_root)?;
				if self.items.len() == self.start_items {
					break
				}
			}

			if let Some(old) = restore.take() {
				*self = old;
				return Ok(false)
			}
		}
		//		let target = target.unwrap_or(0);
		loop {
			if let Some(last) = self.items.last() {
				if let Some(target) = target.as_ref() {
					match last.depth.cmp(&target) {
						Ordering::Greater => (),
						// depth should match.
						Ordering::Less => {
							// skip
							return Ok(true)
						},
						Ordering::Equal => {
							self.prefix.drop_lasts(self.prefix.len() - last.depth);
							return Ok(false)
						},
					}
				}
			} else {
				if target.unwrap_or(0) == 0 {
					return Ok(false)
				} else {
					return Ok(true)
				}
			}
			let _ = self.items.pop();
			if self.items.len() < self.start_items {
				self.start_items = self.items.len();
			}
		}
	}
}

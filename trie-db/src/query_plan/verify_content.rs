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

/// Result of verify iterator.
type VerifyIteratorResult<'a, L, C> = Result<ReadProofItem<'a, L, C, Vec<u8>>, VerifyError<TrieHash<L>, CError<L>>>;

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
	current_offset: usize,
	state: ReadProofState,
	stack: Stack<L>,
	buf_op: Option<Op<TrieHash<L>, Vec<u8>>>,
	send_enter_prefix: Option<Vec<u8>>,
	send_exit_prefix: bool,
	buffed_result: Option<Option<VerifyIteratorResult<'a, L, C>>>,
}

struct Stack<L: TrieLayout> {
	items: Vec<ItemContentStack<L>>,
	prefix: NibbleVec,
	// limit and wether we return value and if hash only iteration.
	iter_prefix: Option<InPrefix>,
	start_items: usize,
	is_prev_hash_child: Option<u8>,
	expect_value: bool,
	is_prev_push_key: bool,
	is_prev_pop_key: bool,
	first: bool,
	_ph: PhantomData<L>,
}

impl<L: TrieLayout> Clone for Stack<L> {
	fn clone(&self) -> Self {
		Stack {
			items: self.items.clone(),
			prefix: self.prefix.clone(),
			start_items: self.start_items.clone(),
			iter_prefix: self.iter_prefix.clone(),
			expect_value: self.expect_value,
			is_prev_push_key: self.is_prev_push_key,
			is_prev_pop_key: self.is_prev_pop_key,
			is_prev_hash_child: self.is_prev_hash_child,
			first: self.first,
			_ph: PhantomData,
		}
	}
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

	let HaltedStateCheckContent { query_plan, current, restore_offset, stack, state } = state;

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
		current_offset: restore_offset,
		state,
		stack,
		buf_op: None,
		send_enter_prefix: None,
		send_exit_prefix: false,
		buffed_result: None,
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
					Op::HashChild(hash, child_ix) => self.stack.set_branch_change(hash, child_ix),
					op => {
						self.stack.set_value_change(op.into());
						Ok(())
					},
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
	restore_offset: usize,
	stack: Stack<L>,
	state: ReadProofState,
}

impl<'a, L: TrieLayout, C> From<QueryPlan<'a, C>> for HaltedStateCheckContent<'a, L, C> {
	fn from(query_plan: QueryPlan<'a, C>) -> Self {
		HaltedStateCheckContent {
			stack: Stack {
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
			restore_offset: 0,
			query_plan,
		}
	}
}

impl<L: TrieLayout> Stack<L> {
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
			ValueSet::None => unreachable!("Not in cache accum"),
		};
		let encoded = L::Codec::leaf_node(pr.right_iter(), pr.len(), value);
		Self::process(encoded, is_root)
	}

	#[inline(always)]
	fn set_value_change(&mut self, change: ValueSet<TrieHash<L>, Vec<u8>>) {
		if self.items.is_empty() {
			self.stack_empty(0);
		}
		let last = self.items.len() - 1;
		let mut item = &mut self.items[last];
		item.value = change;
	}

	#[inline(always)]
	fn set_branch_change(
		&mut self,
		branch_hash: TrieHash<L>,
		branch_index: u8,
	) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
		if self.items.is_empty() {
			self.stack_empty(0);
		}
		let last = self.items.len() - 1;
		let item = &mut self.items[last];
		let i = branch_index as usize;
		if let Some(hash) = item.children[i].as_ref() {
			return Err(VerifyError::ExtraneousHashReference(*hash.disp_hash()))
			//return Err(CompactDecoderError::HashChildNotOmitted.into()) TODO
		}
		item.children[i] = Some(ChildReference::Hash(branch_hash));
		Ok(())
	}
}

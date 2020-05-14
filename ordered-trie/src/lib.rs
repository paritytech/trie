// Copyright 2020 Parity Technologies
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

#![cfg_attr(not(feature = "std"), no_std)]

//! This crate contains implementation of trie/tree based on ordered sequential key only.
//!
//! Current use case is a fixed length tree.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
mod rstd {
	pub use std::{borrow, boxed, cmp, convert, fmt, hash, iter, marker, mem, ops, rc, result, vec};
	pub use std::collections::VecDeque;
	pub use std::collections::BTreeMap;
	pub use std::error::Error;
}

#[cfg(not(feature = "std"))]
mod rstd {
	pub use core::{borrow, convert, cmp, iter, fmt, hash, marker, mem, ops, result};
	pub use alloc::{boxed, rc, vec};
	pub use alloc::collections::VecDeque;
	pub trait Error {}
	impl<T> Error for T {}
}


use crate::rstd::vec::Vec;

use hash_db::{Hasher, HasherHybrid, BinaryHasher};
use crate::rstd::marker::PhantomData;


pub type DBValue = Vec<u8>;

#[derive(PartialEq, Eq, Debug)]
/// A binary trie with guaranties
/// of content being in a fix range
/// of sequential values.
pub struct SequenceBinaryTree<K> {
	// Metadata (needs to be validated)

	/// Nb deleted values at end.
	end: K,
	end_depth: usize,

	// depth of the full tree (maximum depth)
	depth: usize,
	// memmoïze 2^depth
	length: K,

	_ph: PhantomData<K>,
}

impl Default for SequenceBinaryTree<usize> {
	fn default() -> Self {
		SequenceBinaryTree {
			end: 0,
			end_depth: 0,
			depth: 0,
			length: 0,
			_ph: PhantomData,
		}
	}
}

fn depth(nb: usize) -> usize {
	(0usize.leading_zeros() - nb.leading_zeros()) as usize
}

fn right_at(value: usize, index: usize) -> bool {
	value & (1 << index) != 0
}

impl SequenceBinaryTree<usize> {
	pub fn new(number: usize) -> Self {
		let len = number;
		if len == 0 {
			SequenceBinaryTree {
				end: 0,
				end_depth: 0,
				depth: 0,
				length: 0,
				_ph: PhantomData,
			}
		} else {
			let length = len.next_power_of_two();
			let end = length - number;
			let end_depth = depth(end);
			let depth = depth(length - 1);
			SequenceBinaryTree {
				end,
				end_depth,
				depth,
				length,
				_ph: PhantomData,
			}
		}
	}

	fn nb_elements(&self) -> usize {
		self.length - self.end
	}

	#[cfg(test)]
	fn resize_append(&mut self, mut nb: usize) {
		if nb == 0 {
			return;
		}
		if self.length == 0 {
			*self = Self::new(nb);
			return;
		}
		while nb > self.end {
			nb -= self.end;
			self.depth += 1;
			if self.length == 0 {
				self.length += 1;
				self.end = 1;
			} else {
				self.end = self.length;
				self.length *= 2;
			}
		}
		self.end -= nb;
		self.end_depth = depth(self.end);
	}

	fn depth_index(&self, index: usize) -> usize {
		let tmp = (!0usize << (self.depth - self.end_depth)) | (index >> self.end_depth);
		if !tmp == 0 {
			let mut nb_skip = 0;
			for i in 0..self.end_depth {
				// -1 related to redundancy of first level of main depth (depth in number of change of level)
				let ix = self.end_depth - i - 1;
				if self.end & (1 << ix) != 0 {
					// this is a skip
					nb_skip += 1;
				} else {
					// continue only if right (like first if condition)
					if index & (1 << ix) == 0 {
						break;
					}
				}
			}
			self.depth - nb_skip
		} else {
			self.depth
		}
	}

	/// Resolve the tree path for a given index.
	pub fn path_node_key<KN: KeyNode + From<(usize, usize)>>(&self, index: usize) -> KN {
		let tmp = (!0usize << (self.depth - self.end_depth)) | (index >> self.end_depth);
		if !tmp == 0 {
			let mut result: KN = (index, self.depth).into();
			for i in 0..self.end_depth {
				// -1 related to redundancy of first level of main depth (depth in number of change of level)
				let ix = self.end_depth - i - 1;
				if self.end & (1 << ix) != 0 {
					// this is a skip
					let ix = result.depth() - ix - 1;
					result.remove_at(ix);
				} else {
					// continue only if right (like first if condition)
					if index & (1 << ix) == 0 {
						break;
					}
				}
			}
			result
		} else {
			(index, self.depth).into()
		}
	}

	pub fn iter_depth(&self, from: Option<usize>) -> impl Iterator<Item = usize> {
		if let Some(_from) = from {
			unimplemented!();
		}
		let nb_elements = self.nb_elements();
		let mut index = 0;
		let mut depth = self.depth;
		let length = self.length;
		let mut end = UsizeKeyNode::from((self.end, self.end_depth));
		let mut next_skip = length - if end.depth > 0 {
			1usize << end.depth // two time deletion range
		} else {
			0
		};
		crate::rstd::iter::from_fn(move || {
			if index < nb_elements {
				if index == next_skip {
					while end.pop_front() == Some(true) {
						depth -= 1;
					}
					while end.nibble_at(0) == Some(false) {
						end.pop_front();
					}
					if end.depth > 0 {
						next_skip += 1usize << end.depth
					}
				}
				index += 1;
				Some(depth)
			} else {
				None
			}
		})
	}

	pub fn iter_path_node_key<KN>(&self) -> impl Iterator<Item = KN>
		where
			KN: KeyNode + From<(usize, usize)> + Clone,
	{
		let nb_elements = self.nb_elements();
		let mut index = 0;
		let length = self.length;
		let mut end = KN::from((self.end, self.end_depth));
		let mut next_skip = length - if end.depth() > 0 {
			1usize << end.depth() // two time deletion range
		} else {
			0
		};
		let mut key: KN = (0, self.depth).into();
		crate::rstd::iter::from_fn(move || {
			if index < nb_elements {
				if index == next_skip {
					while end.pop_front() == Some(true) {
						let ix = key.depth() - end.depth() - 1;
						key.remove_at(ix);
					}
					while end.nibble_at(0) == Some(false) {
						end.pop_front();
					}
					if end.depth() > 0 {
						next_skip += 1usize << end.depth()
					}
				}
				let result = key.clone();
				key.increment_no_increase();
				index += 1;
				Some(result)
			} else {
				None
			}
		})
	}
}

/// key of node is a sequence of one bit nibbles.
/// This do not implement any key alignment logic,
/// using it for the sequence trie should always
/// use `iter_path_node_key` or `path_node_key`
/// function to instantiate.
pub trait KeyNode {
	fn depth(&self) -> usize;
	// return nibble at depth (bin tree so return bool)
	fn nibble_at(&self, depth: usize) -> Option<bool>;
	// last is leaf
	fn pop_back(&mut self) -> Option<bool>;
	fn push_back(&mut self, nibble: bool);
	fn pop_front(&mut self) -> Option<bool>;
	fn push_front(&mut self, nibble: bool);
	fn remove_at(&mut self, depth: usize);
	fn increment_no_increase(&mut self);
	fn starts_with(&self, other: &Self) -> bool;
	fn common_depth(&self, other: &Self) -> usize;
}

#[cfg(test)]
mod vec_keynode {
	use crate::*;

	#[derive(Clone, Debug)]
	// please do not use, only for test of (usize, K)
	pub(crate) struct VecKeyNode(pub(crate) std::collections::VecDeque<bool>);

	impl KeyNode for VecKeyNode {
		fn increment_no_increase(&mut self) {
			for i in (0..self.0.len()).rev() {
				match self.0.get_mut(i) {
					Some(v) => {
						if !*v {
							*v = true;
							break;
						}
					},
					None => {
						unreachable!("should only be call when guaranties to not increase depth");
					},
				}
			}
		}
		fn depth(&self) -> usize {
			self.0.len()
		}

		fn nibble_at(&self, depth: usize) -> Option<bool> {
			self.0.get(depth).cloned()
		}
		fn pop_back(&mut self) -> Option<bool> {
			self.0.pop_back()
		}
		fn push_back(&mut self, nibble: bool) {
			self.0.push_back(nibble)
		}
		fn pop_front(&mut self) -> Option<bool> {
			self.0.pop_front()
		}
		fn push_front(&mut self, nibble: bool) {
			self.0.push_front(nibble)
		}
		fn remove_at(&mut self, index: usize) {
			self.0.remove(index);
		}
		fn starts_with(&self, other: &Self) -> bool {
			// clone but it is test method only.
			let mut tr = self.0.clone();
			tr.truncate(other.0.len());
			tr == other.0
		}
		fn common_depth(&self, other: &Self) -> usize {
			let bound = rstd::cmp::min(self.0.len(), other.0.len());
			let mut depth = 0;
			for i in 0..bound {
				if self.0[i] == other.0[i] {
					depth += 1;
				} else {
					break;
				}
			}
			depth
		}
	}

	impl From<(usize, usize)> for VecKeyNode {
		fn from((key, depth): (usize, usize)) -> Self {
			if depth == 0 {
				return VecKeyNode(std::collections::VecDeque::new());
			}
			VecKeyNode(
				(1..=depth).map(|i| crate::right_at(key, depth - i)).collect()
			)
		}
	}

	impl Into<usize> for VecKeyNode {
		fn into(self) -> usize {
			let mut result = 0;
			let depth = self.depth();
			self.0.into_iter().enumerate().for_each(|(i, b)| if b {
				result = result | (1 << depth - (i + 1));
			});
			result
		}
	}
}

#[derive(Clone, Copy, Debug)]
pub struct UsizeKeyNode {
	value: usize,
	depth: usize,
}

// first is len, second is key
impl KeyNode for UsizeKeyNode {
	fn depth(&self) -> usize {
		self.depth
	}
	fn increment_no_increase(&mut self) {
		self.value += 1;
	}
	fn nibble_at(&self, depth: usize) -> Option<bool> {
		if depth < self.depth {
			Some(right_at(self.value, self.depth - 1 - depth))
		} else {
			None
		}
	}
	fn pop_back(&mut self) -> Option<bool> {
		if self.depth == 0 {
			return None;
		}
		// TODO is pop returned value of any use:
		// most likely not -> change trait and test
		let result = self.value & 1;
		self.depth -= 1;
		self.value = self.value >> 1;
		Some(result != 0)
	}
	fn push_back(&mut self, nibble: bool) {
		self.value = self.value << 1;
		self.value = self.value | (nibble as usize);
		self.depth +=1;
	}
	fn pop_front(&mut self) -> Option<bool> {
		if self.depth == 0 {
			return None;
		}
		// TODO is pop returned value of any use:
		// most likely not -> change trait and test
		let result = self.value & (1 << (self.depth - 1));
		self.value = self.value & !(1 << (self.depth - 1));
		self.depth -= 1;
		Some(result != 0)
	}
	fn push_front(&mut self, nibble: bool) {
		self.depth += 1;
		self.value = self.value | ((nibble as usize) << (self.depth - 1));
	}

	fn remove_at(&mut self, index: usize) {
		if index >= self.depth {
			return;
		}
		if index == 0 {
			self.pop_front();
			return;
		}
		if index == self.depth - 1 {
			self.pop_back();
			return;
		}
		let right = self.value & !(!0usize << self.depth - index);
		self.value = self.value & (!0usize << self.depth - index);
		self.value = self.value >> 1;
		self.depth -= 1;
		self.value = self.value | right;
	}

	fn starts_with(&self, other: &Self) -> bool {
		if self.depth < other.depth {
			false
		} else {
			self.value >> (self.depth - other.depth) == other.value 
		}
	}
	fn common_depth(&self, other: &Self) -> usize {
/*		let bound = crate::rstd::cmp::min(self.depth, other.depth);
		let mut depth = 0;
		for i in 0..bound {
			if self.nibble_at(i) == other.nibble_at(i) {
				depth += 1;
			} else {
				break;
			}
		}
		depth*/
		let (big, small) = if self.depth < other.depth {
			(other, self)
		} else {
			(self, other)
		};
		// end is not common
		let big_v = big.value >> (big.depth - small.depth);
		let diff = big_v ^ small.value;
		small.depth - (0usize.leading_zeros() - diff.leading_zeros()) as usize
	}
}

impl From<(usize, usize)> for UsizeKeyNode {
	fn from((value, depth): (usize, usize)) -> Self {
		// let value = value & !((!0) << depth);
		UsizeKeyNode { value, depth }
	}
}

impl Into<usize> for UsizeKeyNode {
	fn into(self) -> usize {
		self.value
	}
}

pub trait ProcessNode<HO, KN> {
	/// Callback for an empty trie, return byte representation
	/// of the hash for the empty trie.
	fn process_empty_trie(&mut self) -> &[u8];
	/// Process two child node to produce the parent one.
	fn process(&mut self, key: &KN, child1: &[u8], child2: &[u8]) -> HO;
	/// callback on the calculated root.
	fn register_root(&mut self, root: &HO);
}

pub trait ProcessNodeProof<HO, KN>: ProcessNode<HO, KN> {
	fn register_proof_hash(&mut self, hash: &HO);
}

/// Does only proccess hash on its buffer.
/// Correct buffer size is expected, this is unchecked. 
pub struct HashOnly<'a, H: BinaryHasher>(&'a mut H::Buffer);

impl<'a, H: BinaryHasher> HashOnly<'a, H> {
	pub fn new(buff: &'a mut H::Buffer) -> Self {
		HashOnly(buff)
	}
}

impl<'a, H: BinaryHasher, KN> ProcessNode<H::Out, KN> for HashOnly<'a, H> {
	fn process_empty_trie(&mut self) -> &[u8] {
		H::NULL_HASH
	}
	fn process(&mut self, _key: &KN, child1: &[u8], child2: &[u8]) -> H::Out {
		H::reset_buffer(&mut self.0);
		H::buffer_hash(&mut self.0, child1);
		H::buffer_hash(&mut self.0, child2);
		H::buffer_finalize(&mut self.0)
	}
	fn register_root(&mut self, _root: &H::Out) { }
}

pub struct HashProof<'a, H: BinaryHasher, I, KN> {
	buffer: &'a mut H::Buffer,
	// `I` is a iterator over the depth of every element included in the proof.
	// Can be obtain from `iter_path_node_key` filtered by contained elements.
	to_prove: I,
	state: MultiProofState<KN>,
	additional_hash: Vec<H::Out>,
	// when we do not need to calculate the root but just the additional hashes
	// we can set it to true to avoid useless hashes round.
	additional_hash_only: bool,
}

// We need some read ahead to manage state.
struct MultiProofState<KN> {
	current_key: Option<KN>,
	next_key1: Option<KN>,
	next_key2: Option<KN>,
	// going up a join key means droping current in favor of stack,
	// if stack empty move forward instead.
	join1: Option<usize>,
	join2: Option<usize>,
	stack: smallvec::SmallVec<[(KN, usize);4]>,
	is_empty: bool,
}

enum MultiProofResult {
	RegisterLeft,
	RegisterRight,
	DoNothing,
	DoNothingNoStartWith,
}

impl<KN: KeyNode> MultiProofState<KN> {
	fn new(next_keys: &mut impl Iterator<Item = KN>) -> Self {
		let mut result = MultiProofState {
			current_key: None,
			next_key1: None,
			next_key2: None,
			join1: None,
			join2: None,
			stack: Default::default(),
			is_empty: false,
		};
		result.current_key = next_keys.next();
		if result.current_key.is_none() {
			result.is_empty = true;
		}
		result.next_key1 = next_keys.next();
		result.next_key2 = next_keys.next();
		result.refresh_join1();
		result.refresh_join2();
		result
	}
	fn refresh_join1(&mut self) {
		self.join1 = self.current_key.as_ref()
			.and_then(|c| self.next_key1.as_ref().map(|n| n.common_depth(c)));
	}
	fn refresh_join2(&mut self) {
		self.join2 = self.next_key1.as_ref()
			.and_then(|n1| self.next_key2.as_ref().map(|n2| n2.common_depth(n1)));
	}

	fn new_key(&mut self, key: &KN, next_keys: &mut impl Iterator<Item = KN>) -> MultiProofResult {
		let depth = key.depth();
		let start_with_current = self.current_key.as_ref().map(|c| c.starts_with(key)).unwrap_or(false);
		if start_with_current {
			// join management
			if Some(depth) == self.join1 {
				if let Some(join2) = self.join2 {
					let stack_join = self.stack.last().map(|s| s.1);
					if stack_join.map(|sj| join2 > sj).unwrap_or(true) {
						// move fw, keep current.
						// next_1 is dropped.
						self.next_key1 = self.next_key2.take();
						self.refresh_join1();
						self.next_key2 = next_keys.next();
						self.refresh_join2();
						return MultiProofResult::DoNothing;
					}
				}
				// from stack
				if let Some((stack_hash, _stack_join)) = self.stack.pop() {
					// current is dropped.
					self.current_key = Some(stack_hash);
					// TODO check if stack depth == this new depth (should be?).
					self.refresh_join1();
				} else {
					// fuse last interval
					self.join1 = None;
					self.join2 = None;
					self.next_key1 = None;
					self.next_key2 = None;
				}
				return MultiProofResult::DoNothing;
			} else {
				// no matching join1 depth exclude sibling case.
				if self.current_key.as_ref()
					.expect("start_with_current").nibble_at(key.depth()).expect("starts with") {
					return MultiProofResult::RegisterLeft;
				} else {
					return MultiProofResult::RegisterRight;
				}
			}
		}
		
		let start_with_next = self.next_key1.as_ref().map(|n| n.starts_with(key)).unwrap_or(false);
		// next interval management 
		if start_with_next {
			let mut sibling = false;
			if let Some(join2) = self.join2 {
				if join2 == depth {
					// next is sibling, skip it and do not register.
					// next2 is dropped
					self.next_key2 = next_keys.next();
					self.refresh_join2();
					sibling = true;
				}
			}

			// sibling || is just to skip next nible query as it is unused.
			let right = sibling || self.next_key1.as_ref()
				.expect("start_with_current").nibble_at(key.depth()).expect("starts with");
			if let Some(join1) = self.join1 {
				if let Some(join2) = self.join2 {
					if join2 > join1 {
						// shift and stack
						self.stack.push((self.current_key.take().expect("no next without current"), join1));
						self.current_key = self.next_key1.take();
						self.next_key1 = self.next_key2.take();
						self.next_key2 = next_keys.next();
						self.refresh_join1(); // TODO could also use join2 for join1 would be fastest
						self.refresh_join2();
					} else {
						// keep interval
					}
				} else {
					// no next_key2, keep interval
				}
			} else {
				unreachable!("next is defined (start_with_next)");
			}
			if !sibling {
				if right {
					return MultiProofResult::RegisterLeft;
				} else {
					return MultiProofResult::RegisterRight;
				}
			}
			return MultiProofResult::DoNothing;
		}
		MultiProofResult::DoNothingNoStartWith
	}
}

impl<'a, H: BinaryHasher, KN: KeyNode, I: Iterator<Item = KN>> HashProof<'a, H, I, KN> {
	// TODO write function to build from iter of unchecked usize indexes: map iter
	// with either depth_at or the depth_iterator skipping undesired elements (second
	// seems better as it filters out of range.
	pub fn new(
		buffer: &'a mut H::Buffer,
		mut to_prove: I,
		additional_hash_only: bool,
	) -> Self {
		let state = MultiProofState::new(&mut to_prove);
		HashProof {
			buffer,
			to_prove,
			state,
			additional_hash: Vec::new(),
			additional_hash_only,
		}
	}
	pub fn take_additional_hash(&mut self) -> Vec<H::Out> {
		crate::rstd::mem::replace(&mut self.additional_hash, Vec::new())
	}
}

impl<'a, H: BinaryHasher, KN: KeyNode, I: Iterator<Item = KN>> ProcessNode<H::Out, KN> for HashProof<'a, H, I, KN> {
	fn process_empty_trie(&mut self) -> &[u8] {
		H::NULL_HASH
	}
	fn process(&mut self, key: &KN, child1: &[u8], child2: &[u8]) -> H::Out {
		let mut skip_hashing = false;
		match self.state.new_key(key, &mut self.to_prove) {
			MultiProofResult::DoNothingNoStartWith => (),
			MultiProofResult::DoNothing => {
				skip_hashing = self.additional_hash_only
			},
			MultiProofResult::RegisterLeft => {
				let mut to_push = H::Out::default();
				to_push.as_mut().copy_from_slice(child1);
				self.additional_hash.push(to_push);
				skip_hashing = self.additional_hash_only;
			},
			MultiProofResult::RegisterRight => {
				let mut to_push = H::Out::default();
				to_push.as_mut().copy_from_slice(child2);
				self.additional_hash.push(to_push);
				skip_hashing = self.additional_hash_only;
			},
		}

		if skip_hashing {
			Default::default()
		} else {
			let mut h = HashOnly::<H>::new(self.buffer);
			h.process(key, child1, child2)
		}
	}
	fn register_root(&mut self, root: &H::Out) {
		if self.state.is_empty {
			self.additional_hash.push(root.clone());
		}
	}
}

// This only include hash, for including hashed value or inline node, just map the process over the
// input iterator (note that for inline node we need to attach this inline info to the tree so it
// only make sense for small trie or fix length trie).
/// Returns a calculated hash
pub fn trie_root<HO, KN, I, F>(layout: &SequenceBinaryTree<usize>, input: I, callback: &mut F) -> HO
	where
		HO: Default + AsRef<[u8]> + AsMut<[u8]>,
		KN: KeyNode + Into<usize> + From<(usize, usize)> + Clone,
		I: Iterator<Item = HO>,
		F: ProcessNode<HO, KN>,
{
	let mut iter = input.into_iter().zip(layout.iter_path_node_key::<KN>());
	debug_assert!({
		let (r, s) = iter.size_hint();
		if s == Some(r) {
			layout.nb_elements() == r
		} else {
			true
		}
	});
	let mut depth1 = layout.depth;
	let mut child1 = if let Some((child, key)) = iter.next() {
		debug_assert!(key.depth() == depth1);
		child
	} else {
		debug_assert!(layout.nb_elements() == 0);
		let mut result = HO::default();
		result.as_mut().copy_from_slice(callback.process_empty_trie());
		return result;
	};
	debug_assert!(layout.depth_index(0) == layout.depth);
	// use a stack that match 16 element without allocation, that is 4 element depth
	let mut stack = smallvec::SmallVec::<[(HO, usize);4]>::new();
	let mut key: KN = (0, depth1).into();
	loop {
		let last_stack_depth = stack.last().map(|e|e.1);
		if Some(depth1) == last_stack_depth {
			// process over stack
			let (child2, _depth2) = stack.pop().expect("checked above");
			key.pop_back();
			// stacked on at left
			let parent = callback.process(&key, child2.as_ref(), child1.as_ref());
			depth1 = key.depth();
			child1 = parent;
		} else {
			if let Some((child2, key2)) = iter.next() {
				key = key2;
				if key.depth() == depth1 {
					key.pop_back();
					// iter one at right
					let parent = callback.process(&key, child1.as_ref(), child2.as_ref());
					depth1 = key.depth();
					child1 = parent;
				} else {
					stack.push((child1, depth1));
					child1 = child2;
					depth1 = key.depth();
				}
			} else {
				break;
			}
		}
	}
	debug_assert!(stack.is_empty());
	callback.register_root(&child1);
	child1
}

/// Returns a calculated hash
pub fn trie_root_from_proof<HO, KN, I, I2, F>(
	layout: &SequenceBinaryTree<usize>,
	input: I,
	additional_hash: I2,
	callback: &mut F,
	allow_additionals_hashes: bool,
) -> Option<HO>
	where
		HO: Default + AsRef<[u8]> + AsMut<[u8]>,
		KN: KeyNode + Into<usize> + From<(usize, usize)> + Clone,
		I: IntoIterator<Item = (KN, HO)>,
		I2: IntoIterator<Item = HO>,
		F: ProcessNode<HO, KN>,
{
	if layout.nb_elements() == 0 {
		if !allow_additionals_hashes && additional_hash.into_iter().next().is_some() {
			return None;
		} else {
			let mut result = HO::default();
			result.as_mut().copy_from_slice(callback.process_empty_trie());
			return Some(result);
		}
	}

	let mut items = input.into_iter();
	let mut additional_hash = additional_hash.into_iter();
	let mut current;
	if let Some(c) = items.next() {
		current = c;
	} else {
		// TODO check if we even can produce such proof.
		// no item case root is directly in additional
		if let Some(h) = additional_hash.next() {
			if allow_additionals_hashes || additional_hash.next().is_none() {
				callback.register_root(&h);
				return Some(h);
			}
		}
		return None;
	}
	let mut next = items.next();
	let calc_common_depth = |current: &(KN, HO), next: &Option<(KN, HO)>| {
		next.as_ref().map(|n| current.0.common_depth(&n.0))
	};
	let mut common_depth = calc_common_depth(&current, &next);
	let mut stack = smallvec::SmallVec::<[((KN, HO), usize);4]>::new();

	while let Some(right) = current.0.pop_back() {
		let depth = current.0.depth();
		if Some(depth) == stack.last().as_ref().map(|s| s.1) {
			let ((stack_key, stack_hash), _stack_depth) = stack.pop().expect("tested in condition");
			debug_assert!(right == true);
			debug_assert!(stack_key.starts_with(&current.0) && current.0.starts_with(&stack_key));
			current.1 = callback.process(&current.0, stack_hash.as_ref(), current.1.as_ref());
			continue;
		}
		if Some(depth) == common_depth {
			let (key_next, hash_next) = next.take().expect("common depth is some");
			stack.push((current, depth)); // TODO process sibling without stack? or all on stack
			current = (key_next, hash_next);
			next = items.next();
			common_depth = calc_common_depth(&current, &next);
			continue;
		}
		if let Some(other) = additional_hash.next() {
			if right {
				current.1 = callback.process(&current.0, other.as_ref(), current.1.as_ref());
			} else {
				current.1 = callback.process(&current.0, current.1.as_ref(), other.as_ref());
			}
		} else {
			return None;
		}
	}

	debug_assert!(current.0.depth() == 0);
	if  !allow_additionals_hashes && additional_hash.next().is_some() {
		None
	} else {
		callback.register_root(&current.1);
		Some(current.1)
	}
}

/// Hasher hybrid using an ordered trie
pub struct OrderedTrieHasher<H, HH>(PhantomData<(H, HH)>);

impl<H: BinaryHasher, HH: BinaryHasher<Out = H::Out>> HasherHybrid for OrderedTrieHasher<H, HH> {
	type InnerHasher = HH;

	fn hash_hybrid_proof<
		I: Iterator<Item = Option<<Self as Hasher>::Out>>,
		I2: Iterator<Item = <Self as Hasher>::Out>,
	>(
		header: &[u8],
		nb_children: usize,
		children: I,
		additional_hashes: I2,
		buffer: &mut HH::Buffer,
	) -> Option<H::Out> {
		let seq_trie = SequenceBinaryTree::new(nb_children);

		let mut callback_read_proof = HashOnly::<HH>::new(buffer);
		// proof node, UsizeKeyNode should be big enough for hasher hybrid
		// case.
		let iter_key = seq_trie.iter_path_node_key::<UsizeKeyNode>();
		let iter = children
			.zip(iter_key)
			.filter_map(|(value, key)| if let Some(value) = value {
				Some((key, value))
			} else {
				None
			});
		let hash = if let Some(hash) = crate::trie_root_from_proof(
			&seq_trie,
			iter,
			additional_hashes,
			&mut callback_read_proof,
			false,
		) {
			hash
		} else {
			return None;
		};
		let mut hash_buf2 = <H as BinaryHasher>::init_buffer();
		<H as BinaryHasher>::buffer_hash(&mut hash_buf2, header);
		<H as BinaryHasher>::buffer_hash(&mut hash_buf2, hash.as_ref());
		Some(H::buffer_finalize(&mut hash_buf2))
	}

	fn hash_hybrid<
		I: Iterator<Item = Option<<Self as Hasher>::Out>>,
	>(
		header: &[u8],
		nb_children: usize,
		children: I,
		buffer: &mut HH::Buffer,
	) -> H::Out {
		let seq_trie = SequenceBinaryTree::new(nb_children);

		let mut callback_read_proof = HashOnly::<HH>::new(buffer);
		// full node
		let iter = children.filter_map(|v| v); // TODO assert same number as count
		let hash = crate::trie_root::<_, UsizeKeyNode, _, _>(&seq_trie, iter, &mut callback_read_proof);
		let mut hash_buf2 = <H as BinaryHasher>::init_buffer();
		<H as BinaryHasher>::buffer_hash(&mut hash_buf2, header);
		<H as BinaryHasher>::buffer_hash(&mut hash_buf2, hash.as_ref());
		H::buffer_finalize(&mut hash_buf2)
	}

}

impl<H: BinaryHasher, HH: Send + Sync> BinaryHasher for OrderedTrieHasher<H, HH> {
	const NULL_HASH: &'static [u8] = <H as BinaryHasher>::NULL_HASH;
	type Buffer = <H as BinaryHasher>::Buffer;
	fn init_buffer() -> Self::Buffer {
		<H as BinaryHasher>::init_buffer()
	}
	fn reset_buffer(buf: &mut Self::Buffer) {
		<H as BinaryHasher>::reset_buffer(buf)
	}
	fn buffer_hash(buff: &mut Self::Buffer, x: &[u8]) {
		<H as BinaryHasher>::buffer_hash(buff, x)
	}
	fn buffer_finalize(buff: &mut Self::Buffer) -> Self::Out {
		<H as BinaryHasher>::buffer_finalize(buff)
	}
}

impl<H: Hasher, HH: Send + Sync> Hasher for OrderedTrieHasher<H, HH> {
	type Out = <H as Hasher>::Out;
	type StdHasher = <H as Hasher>::StdHasher;
	const LENGTH: usize = <H as Hasher>::LENGTH;

	#[inline]
	fn hash(x: &[u8]) -> Self::Out {
		<H as Hasher>::hash(x)
	}
}

#[cfg(test)]
mod test {

	use keccak_hasher::KeccakHasher;
	use super::*;
	use crate::vec_keynode::VecKeyNode;

	#[test]
	fn test_depth() {
	/*
				(0, 0),
				(1, 1),
				(2, 2),
				(3, 2),
				(4, 3),
				(5, 3),
				(7, 3),
				(8, 4),
	*/	
		assert_eq!(depth(0), 0);
		assert_eq!(depth(1), 1);
		assert_eq!(depth(2), 2);
		assert_eq!(depth(3), 2);
		assert_eq!(depth(4), 3);
		assert_eq!(depth(7), 3);
		assert_eq!(depth(8), 4);
		assert_eq!(depth(9), 4);
		assert_eq!(depth(u16::max_value() as usize - 1), 16);
		assert_eq!(depth(u16::max_value() as usize), 16);
	}

	#[test]
	fn key_node_test() {
		let test = |start: usize, end: bool| {
			let depth = depth(start);
			let mut v = VecKeyNode::from((start, depth));
			let mut u = UsizeKeyNode::from((start, depth));
			assert_eq!(v.nibble_at(start), u.nibble_at(start));
			if !end {
				assert_eq!(u.push_back(true), v.push_back(true));
			}
			assert_eq!(u.pop_back(), v.pop_back());
			if !end {
				assert_eq!(u.push_back(false), v.push_back(false));
			}
			assert_eq!(u.pop_back(), v.pop_back());
			assert_eq!(u.push_front(true), v.push_front(true));
			assert_eq!(u.pop_front(), v.pop_front());
			assert_eq!(u.push_front(false), v.push_front(false));
			assert_eq!(u.pop_front(), v.pop_front());
			if !end {
				assert_eq!(start, u.into());
				assert_eq!(start, v.clone().into());
			}
			assert_eq!(u.pop_back(), v.pop_back());
			let u: usize = u.into();
			assert_eq!(u, v.into());
		};
		let t: VecKeyNode = (5, 4).into();
		let t: Vec<bool> = t.0.into_iter().collect();
		assert_eq!(t, vec![false, true, false, true]);
		let t: std::collections::VecDeque<bool> = [false, true, false, true].iter().cloned().collect();
		assert_eq!(5usize, VecKeyNode(t).into());
		for i in 0..17 {
			test(i, false);
		}
		test(usize::max_value() - 1, true);
	}

	type Tree = super::SequenceBinaryTree<usize>;

	#[test]
	fn test_max_depth() {
		let values = [
			(0, 0),
			(1, 0),
			(2, 1),
			(3, 2),
			(4, 2),
			(5, 3),
			(8, 3),
			(9, 4),
			(16, 4),
			(17, 5),
			(32, 5),
		];
		let mut tree = Tree::default();
		let mut prev = 0;
		for (nb, depth) in values.iter().cloned() {
			let inc = nb - prev;
			prev = nb;
			tree.resize_append(inc);
			assert_eq!(tree.depth, depth);
			let tree2 = Tree::new(nb);
			assert_eq!(tree2.depth, depth);
			assert_eq!(tree, tree2);
		}
	}

	#[test]
	fn test_depth_index() {
		// 8 trie
		let tree = Tree::new(7);
		assert_eq!(tree.depth_index(3), 3);
		assert_eq!(tree.depth_index(4), 3);
		assert_eq!(tree.depth_index(6), 2);
		let tree = Tree::new(6);
		assert_eq!(tree.depth_index(0), 3);
		assert_eq!(tree.depth_index(3), 3);
		assert_eq!(tree.depth_index(4), 2);
		assert_eq!(tree.depth_index(5), 2);
		let tree = Tree::new(5);
		assert_eq!(tree.depth_index(3), 3);
		assert_eq!(tree.depth_index(4), 1);
		// 16 trie
		let tree = Tree::new(12);
		assert_eq!(tree.depth_index(7), 4);
		assert_eq!(tree.depth_index(8), 3);
		assert_eq!(tree.depth_index(11), 3);
		let tree = Tree::new(11);
		assert_eq!(tree.depth_index(7), 4);
		assert_eq!(tree.depth_index(8), 3);
		assert_eq!(tree.depth_index(9), 3);
		assert_eq!(tree.depth_index(10), 2);
		let tree = Tree::new(10);
		assert_eq!(tree.depth_index(7), 4);
		assert_eq!(tree.depth_index(8), 2);
		assert_eq!(tree.depth_index(9), 2);
		let tree = Tree::new(9);
		assert_eq!(tree.depth_index(7), 4);
		assert_eq!(tree.depth_index(8), 1);
		// 32 trie TODO
	}

	#[test]
	fn test_depth_iter() {
		// cases corresponding to test_depth, TODO add more
//		let cases = [7, 6, 5, 12, 11, 10, 9];
		for nb in 0usize..16 {
			let mut n = 0;
			let tree = Tree::new(nb);
			for (i, (d, k)) in tree.iter_depth(None)
				.zip(tree.iter_path_node_key::<UsizeKeyNode>())
				.enumerate() {
				n += 1;
				assert_eq!(d, tree.depth_index(i));
				assert_eq!(d, k.depth);
				let k2: UsizeKeyNode = tree.path_node_key(i);
				assert_eq!(k.depth, k2.depth);
				assert_eq!(k.value, k2.value);
			}
			assert_eq!(n, nb);
		}
	}

	fn hashes(l: usize) -> Vec<[u8;32]> {
		(0..l).map(|i| {
			let mut hash = <KeccakHasher as Hasher>::Out::default();
			let v = (i as u64).to_be_bytes();
			hash.as_mut()[..8].copy_from_slice(&v[..]);
			hash
		}).collect()
	}

	fn base16_roots() -> Vec<[u8;32]> {
		let hashes = hashes(16);
		let mut result = Vec::<[u8;32]>::new();

		let khash = |a: &[u8], b: &[u8]| {
			let mut v = Vec::new();
			v.extend_from_slice(a);
			v.extend_from_slice(b);
			<KeccakHasher as Hasher>::hash(v.as_ref())
		};
		let mut hash = <KeccakHasher as Hasher>::Out::default();
		hash.as_mut()[..].copy_from_slice(KeccakHasher::NULL_HASH);
		result.push(hash);
		result.push(hashes[0].clone());
		let base2 = khash(hashes[0].as_ref(), hashes[1].as_ref());
		result.push(base2);
		result.push(khash(
			base2.as_ref(),
			hashes[2].as_ref(),
		));
		let base4 = khash(
			base2.as_ref(),
			khash(hashes[2].as_ref(), hashes[3].as_ref()).as_ref(),
		);
		result.push(base4);
		result.push(khash(
			base4.as_ref(),
			hashes[4].as_ref(),
		));
		let base2 = khash(hashes[4].as_ref(), hashes[5].as_ref());
		result.push(khash(
			base4.as_ref(),
			base2.as_ref(),
		));
		result.push(khash(
			base4.as_ref(),
			khash(
				base2.as_ref(),
				hashes[6].as_ref(),
			).as_ref(),
		));
		let base8 = khash(
			base4.as_ref(),
			khash(
				base2.as_ref(),
				khash(hashes[6].as_ref(), hashes[7].as_ref()).as_ref(),
			).as_ref(),
		);
		result.push(base8);
		result.push(khash(
			base8.as_ref(),
			hashes[8].as_ref(),
		));
		let base2 = khash(hashes[8].as_ref(), hashes[9].as_ref());
		result.push(khash(
			base8.as_ref(),
			base2.as_ref(),
		));
		result.push(khash(
			base8.as_ref(),
			khash(
				base2.as_ref(),
				hashes[10].as_ref(),
			).as_ref(),
		));
		let base4 = khash(
			base2.as_ref(),
			khash(hashes[10].as_ref(), hashes[11].as_ref()).as_ref(),
		);
		result.push(khash(
			base8.as_ref(),
			base4.as_ref(),
		));
		result.push(khash(
			base8.as_ref(),
			khash(
				base4.as_ref(),
				hashes[12].as_ref(),
			).as_ref(),
		));
		let base2 = khash(hashes[12].as_ref(), hashes[13].as_ref());
		result.push(khash(
			base8.as_ref(),
			khash(
				base4.as_ref(),
				base2.as_ref(),
			).as_ref(),
		));
		result.push(khash(
			base8.as_ref(),
			khash(
				base4.as_ref(),
				khash(
					base2.as_ref(),
					hashes[14].as_ref(),
				).as_ref(),
			).as_ref(),
		));
		result.push(khash(
			base8.as_ref(),
			khash(
				base4.as_ref(),
				khash(
					base2.as_ref(),
					khash(hashes[14].as_ref(), hashes[15].as_ref()).as_ref(),
				).as_ref(),
			).as_ref(),
		));
		result
	}

	#[test]
	fn test_hash_only() {
		let result = base16_roots();
		for l in 0..17 {
			let tree = Tree::new(l);
			let mut hash_buf = <KeccakHasher as BinaryHasher>::init_buffer();
			let mut callback = HashOnly::<KeccakHasher>::new(&mut hash_buf);
			let hashes: Vec<_> = hashes(l);
			let root = trie_root::<_, UsizeKeyNode, _, _>(&tree, hashes.into_iter(), &mut callback);
			assert_eq!(root.as_ref(), &result[l][..]);
		}
	}

	#[test]
	fn test_one_element_proof() {
		let result = base16_roots();
		for l in 0..17 {
			let tree = Tree::new(l);
			let mut hash_buf = <KeccakHasher as BinaryHasher>::init_buffer();
			let mut hash_buf2 = <KeccakHasher as BinaryHasher>::init_buffer();
			let mut hash_buf3 = <KeccakHasher as BinaryHasher>::init_buffer();
			let mut callback_read_proof = HashOnly::<KeccakHasher>::new(&mut hash_buf2);
			let hashes: Vec<_> = hashes(l);
			for p in 0..l {
				let to_prove = vec![tree.path_node_key::<UsizeKeyNode>(p)];
				let mut callback = HashProof::<KeccakHasher, _, _>::new(&mut hash_buf, to_prove.into_iter(), false);
				let to_prove = vec![tree.path_node_key::<UsizeKeyNode>(p)];
				let root = trie_root::<_, UsizeKeyNode, _, _>(&tree, hashes.clone().into_iter(), &mut callback);
				let mut callback2 = HashProof::<KeccakHasher, _, _>::new(&mut hash_buf3, to_prove.into_iter(), true);
				let _ = trie_root::<_, UsizeKeyNode, _, _>(&tree, hashes.clone().into_iter(), &mut callback2);
				assert_eq!(root.as_ref(), &result[l][..]);
				let additional_hash = callback.take_additional_hash();
				let additional_hash_2 = callback2.take_additional_hash();
				assert_eq!(additional_hash, additional_hash_2);
				let proof_items = vec![(tree.path_node_key::<UsizeKeyNode>(p), hashes[p].clone())];
				let root = trie_root_from_proof::<_, UsizeKeyNode, _, _, _>(
					&tree,
					proof_items,
					additional_hash.into_iter(),
					&mut callback_read_proof,
					false,
				);
				println!("{}, {}", l, p);
				assert!(root.is_some());
				assert_eq!(root.unwrap().as_ref(), &result[l][..]);
			}
		}
	}

	#[test]
	fn test_multiple_elements_proof() {
		let result = base16_roots();
		let tests = [
			(1, &[][..]),
			(1, &[0][..]),
			(4, &[][..]),
			(4, &[1][..]),
			(4, &[1, 2][..]),
			(4, &[1, 2, 3][..]),
			(13, &[1, 2, 3][..]),
			(13, &[2, 3, 4][..]),
			(13, &[2, 5][..]),
			(13, &[2, 5, 11][..]),
			(13, &[2, 11][..]),
			(13, &[11, 12][..]),
			(13, &[10, 12][..]),
			(13, &[2, 11, 12][..]),
		];
		for (l, ps) in tests.iter() {
			let l = *l;
			let ps = *ps;
			let tree = Tree::new(l);
			let mut hash_buf = <KeccakHasher as BinaryHasher>::init_buffer();
			let mut hash_buf2 = <KeccakHasher as BinaryHasher>::init_buffer();
			let mut hash_buf3 = <KeccakHasher as BinaryHasher>::init_buffer();
			let mut callback_read_proof = HashOnly::<KeccakHasher>::new(&mut hash_buf2);
			let hashes: Vec<_> = hashes(l);
			let mut to_prove = Vec::new();
			let mut proof_items = Vec::new();
			for p in ps {
				let p = *p;
				to_prove.push(tree.path_node_key::<UsizeKeyNode>(p));
				proof_items.push((tree.path_node_key::<UsizeKeyNode>(p), hashes[p].clone()));
			}
			let mut callback = HashProof::<KeccakHasher, _, _>::new(&mut hash_buf, to_prove.clone().into_iter(), false);
			let mut callback2 = HashProof::<KeccakHasher, _, _>::new(&mut hash_buf3, to_prove.into_iter(), true);
			let root = trie_root::<_, UsizeKeyNode, _, _>(&tree, hashes.clone().into_iter(), &mut callback);
			let _ = trie_root::<_, UsizeKeyNode, _, _>(&tree, hashes.clone().into_iter(), &mut callback2);
			assert_eq!(root.as_ref(), &result[l][..]);
			let additional_hash = callback.take_additional_hash();
			let additional_hash2 = callback2.take_additional_hash();
			assert_eq!(additional_hash, additional_hash2);
			let root = trie_root_from_proof::<_, UsizeKeyNode, _, _, _>(
				&tree,
				proof_items,
				additional_hash.into_iter(),
				&mut callback_read_proof,
				false,
			);
			println!("{}, {:?}", l, ps);
			assert!(root.is_some());
			assert_eq!(root.unwrap().as_ref(), &result[l][..]);
		}
	}
}

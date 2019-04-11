// Copyright 2017, 2018 Parity Technologies
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

//! An owning, nibble-oriented byte vector.
use elastic_array::ElasticArray36;
use nibbleslice::NibbleSlice;
use nibbleslice::NibbleOps;
use ::core_::marker::PhantomData;

// TODO EMCH change crate layout to give access to nibble vec field to nibble ops and avoid pub(crate)
/// Owning, nibble-oriented byte vector. Counterpart to `NibbleSlice`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NibbleVec<N> {
	pub(crate) inner: ElasticArray36<u8>,
	pub(crate) len: usize,
	marker: PhantomData<N>,
}

impl<N: NibbleOps> Default for NibbleVec<N> {
	fn default() -> Self {
		NibbleVec::<N>::new()
	}
}

impl<N: NibbleOps> NibbleVec<N> {
	/// Make a new `NibbleVec`
	pub fn new() -> Self {
		NibbleVec {
			inner: ElasticArray36::new(),
			len: 0,
			marker: PhantomData,
		}
	}

	/// Length of the `NibbleVec`
	#[inline(always)]
	pub fn len(&self) -> usize { self.len }

	/// Retrurns true if `NibbleVec` has zero length
	pub fn is_empty(&self) -> bool { self.len == 0 }

	/// Try to get the nibble at the given offset.
	#[inline]
	pub fn at(&self, idx: usize) -> u8 {
		N::vec_at(self, idx)
	}

	/// Push a nibble onto the `NibbleVec`. Ignores the high 4 bits.
	pub fn push(&mut self, nibble: u8) {
		N::push(self, nibble)
	}

	/// Try to pop a nibble off the `NibbleVec`. Fails if len == 0.
	pub fn pop(&mut self) -> Option<u8> {
		N::pop(self)
	}

	/// Get the underlying byte slice.
	pub fn inner(&self) -> &[u8] {
		&self.inner[..]
	}
}

impl<'a, N: NibbleOps> From<NibbleSlice<'a, N>> for NibbleVec<N> {
	fn from(s: NibbleSlice<'a, N>) -> Self {
		let mut v = NibbleVec::new();
		for i in 0..s.len() {
			v.push(s.at(i));
		}
		v
	}
}

#[cfg(test)]
mod tests {
	use super::NibbleVec;
	use nibbleslice::{NibblePreHalf, NibblePostHalf, NibbleOps};

	#[test]
	fn push_pop() {
		push_pop_inner::<NibblePreHalf>();
		push_pop_inner::<NibblePostHalf>();
	}
	fn push_pop_inner<N: NibbleOps>() {
		let mut v = NibbleVec::<N>::new();

		for i in 0..16 {
			v.push(i);
			assert_eq!(v.len() - 1, i as usize);
			assert_eq!(v.at(i as usize), i);
		}

		for i in (0..16).rev() {
			assert_eq!(v.pop(), Some(i));
			assert_eq!(v.len(), i as usize);
		}
	}
}

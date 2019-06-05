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
use nibble::NibbleSlice;
use nibble::NibbleOps;
use hash_db::Prefix;
use node_codec::Partial;
use ::core_::marker::PhantomData;
use super::NibbleVec;

impl<N: NibbleOps> Default for NibbleVec<N> {
	fn default() -> Self {
		NibbleVec::<N>::new()
	}
}

impl<N: NibbleOps> NibbleVec<N> {
	/// Make a new `NibbleVec`.
	pub fn new() -> Self {
		NibbleVec {
			inner: ElasticArray36::new(),
			len: 0,
			marker: PhantomData,
		}
	}

	/// Length of the `NibbleVec`.
	#[inline(always)]
	pub fn len(&self) -> usize { self.len }

	/// Retrurns true if `NibbleVec` has zero length.
	pub fn is_empty(&self) -> bool { self.len == 0 }

	/// Try to get the nibble at the given offset.
	#[inline]
	pub fn at(&self, idx: usize) -> u8 {
		let ix = idx / N::NIBBLE_PER_BYTE;
		let pad = idx % N::NIBBLE_PER_BYTE;
		N::at_left(pad as u8, self.inner[ix])
	}

	/// Push a nibble onto the `NibbleVec`. Ignores the high 4 bits.
	pub fn push(&mut self, nibble: u8) {
		let i = self.len % N::NIBBLE_PER_BYTE;

		if i == 0 {
			self.inner.push(N::push_at_left(0, nibble, 0));
		} else {
			let dest = self.inner.last_mut().expect("len != 0 since len % 2 != 0; inner has a last element; qed");
			*dest = N::push_at_left(i as u8, nibble, *dest);
		}
		self.len += 1;
	}
	
	/// Try to pop a nibble off the `NibbleVec`. Fails if len == 0.
	pub fn pop(&mut self) -> Option<u8> {
		if self.is_empty() {
			return None;
		}
		let byte = self.inner.pop().expect("len != 0; inner has last elem; qed");
		self.len -= 1;
		let i_new = self.len % N::NIBBLE_PER_BYTE;
		if i_new != 0 {
			self.inner.push(N::masked_left(i_new as u8, byte));
		}
		Some(N::at_left(i_new as u8, byte))
	}

	/// Remove then n last nibbles in a faster way than popping n times.
	pub fn drop_lasts(&mut self, n: usize) {
		if n == 0 { return; }
		if n >= self.len {
			self.clear();
			return;
		}
		let end = self.len - n;
		let end_ix = end / N::NIBBLE_PER_BYTE
			+ if end % N::NIBBLE_PER_BYTE == 0 { 0 } else { 1 };
		(end_ix..self.inner.len()).for_each(|_|{ self.inner.pop(); });
		self.len = end;
		let pos = self.len % N::NIBBLE_PER_BYTE;
		if pos != 0 {
			let kl = self.inner.len() - 1;
			self.inner[kl] = N::masked_left(pos as u8, self.inner[kl]);
		}
	}

	/// Get `Prefix` representation of this `NibbleVec`.
	pub fn as_prefix(&self) -> Prefix {
		let split = self.len / N::NIBBLE_PER_BYTE;
		let pos = (self.len % N::NIBBLE_PER_BYTE) as u8;
		if pos == 0 {
			(&self.inner[..split], (0,0))
		} else {
			(&self.inner[..split], (pos, N::masked_left(pos, self.inner[split])))
		}
	}

	/// Append another `NibbleVec`. Can be slow (alignement of second vec).
	pub fn append(&mut self, v: &NibbleVec<N>) {

		if v.len == 0 { return; }
		let final_len = self.len + v.len;
		let offset = self.len % N::NIBBLE_PER_BYTE;
		let final_offset = final_len % N::NIBBLE_PER_BYTE;
		let last_ix = self.len / N::NIBBLE_PER_BYTE;
		if offset > 0 {
			let (s1, s2) = N::split_shifts(offset);
			self.inner[last_ix] = N::masked_left(offset as u8, self.inner[last_ix]) | (v.inner[0] >> s2);
			(0..v.inner.len() - 1).for_each(|i|self.inner.push(v.inner[i] << s1 | v.inner[i+1] >> s2));
			if final_offset > 0 {
				self.inner.push(v.inner[v.inner.len() - 1] << s1);
			}
		} else {
			(0..v.inner.len()).for_each(|i|self.inner.push(v.inner[i]));
		}
		self.len += v.len;
	}

	/// Append a `Partial`. Can be slow (alignement of partial).
	pub fn append_partial(&mut self, (o_n, sl): Partial) {
		for i in (1..=o_n.0).rev() {
			let ix = N::NIBBLE_PER_BYTE - i as usize;
			self.push(N::at_left(ix as u8, o_n.1));
		}
		let pad = self.inner.len() * N::NIBBLE_PER_BYTE - self.len;
		if pad == 0 {
			self.inner.append_slice(&sl[..]);
		} else {
			let kend = self.inner.len() - 1;
			if sl.len() > 0 {
				self.inner[kend] = N::masked_left((N::NIBBLE_PER_BYTE - pad) as u8, self.inner[kend]);
				let (s1, s2) = N::split_shifts(pad);
				self.inner[kend] |= sl[0] >> s1;
				(0..sl.len() - 1).for_each(|i|self.inner.push(sl[i] << s2 | sl[i+1] >> s1));
				self.inner.push(sl[sl.len() - 1] << s2);
			}
		}
		self.len += sl.len() * N::NIBBLE_PER_BYTE;
	}

	/// Utility function for chaining two optional appending
  /// of `NibbleSlice` and/or a byte.
  /// Can be slow.
	pub(crate) fn append_slice_nibble(
		&mut self,
		o_sl: Option<&NibbleSlice<N>>,
		o_ix: Option<u8>,
	) -> usize {
		let mut res = 0;
		if let Some(sl) = o_sl { 
			self.append_partial(sl.right());
			res += sl.len();
		}
		if let Some(ix) = o_ix { 
			self.push(ix);
			res += 1;
		}
		res
	}
	/// Utility function for `append_slice_nibble` after a clone.
  /// Can be slow.
	pub(crate) fn clone_append_slice_nibble(
		&self,
		o_sl: Option<&NibbleSlice<N>>,
		o_ix: Option<u8>,
	) -> Self {
		let mut p = self.clone();
		p.append_slice_nibble(o_sl, o_ix);
		p
	}

	/// Get the underlying byte slice.
	pub fn inner(&self) -> &[u8] {
		&self.inner[..]
	}

	/// clear
	pub fn clear(&mut self) {
		self.inner.clear();
		self.len = 0;
	}

	/// Try to treat this `NibbleVec` as a `NibbleSlice`. Works only if there is no padding.
	pub fn as_nibbleslice(&self) -> Option<NibbleSlice<N>> {
		if self.len % N::NIBBLE_PER_BYTE == 0 {
			Some(NibbleSlice::new(self.inner()))
		} else {
			None
		}
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
	use crate::nibble::NibbleVec;
	use crate::nibble::{NibbleHalf, NibbleOps, NibbleQuarter};

	#[test]
	fn push_pop() {
		push_pop_inner::<NibbleHalf>();
		push_pop_inner::<NibbleQuarter>();
	}
	fn push_pop_inner<N: NibbleOps>() {
		let mut v = NibbleVec::<N>::new();

		for i in 0..(N::NIBBLE_PER_BYTE * 3) {
			let iu8 = (i % N::NIBBLE_PER_BYTE) as u8;
			v.push(iu8);
			assert_eq!(v.len() - 1, i);
			assert_eq!(v.at(i), iu8);
		}

		for i in (0..(N::NIBBLE_PER_BYTE * 3)).rev() {
			let iu8 = (i % N::NIBBLE_PER_BYTE) as u8;
			let a = v.pop();
			assert_eq!(a, Some(iu8));
			assert_eq!(v.len(), i);
		}
	}
	#[test]
	fn append_partial() {
		append_partial_inner::<NibbleHalf>(&[1,2,3], &[], ((1,1), &[0x23]));
		append_partial_inner::<NibbleHalf>(&[1,2,3], &[1], ((0,0), &[0x23]));
		append_partial_inner::<NibbleHalf>(&[0,1,2,3], &[0], ((1,1), &[0x23]));
		append_partial_inner::<NibbleQuarter>(&[1, 0, 2, 0, 3], &[], ((1,1), &[0x23]));
		append_partial_inner::<NibbleQuarter>(&[1, 0, 2, 0, 3, 0, 1, 0, 2], &[], ((1,1), &[0x23, 0x12]));
		append_partial_inner::<NibbleQuarter>(&[2, 1, 0, 2, 0, 3, 0, 1, 0, 2], &[], ((2,0b1001), &[0x23, 0x12]));
		append_partial_inner::<NibbleQuarter>(&[3, 2, 1, 0, 2, 0, 3, 0, 1, 0, 2], &[], ((3,0b111001), &[0x23, 0x12]));
		append_partial_inner::<NibbleQuarter>(&[3, 1, 0, 2, 0, 3, 0, 1, 0, 2], &[3], ((1,1), &[0x23, 0x12]));
		append_partial_inner::<NibbleQuarter>(&[3, 2, 3, 1, 0, 2, 0, 3, 0, 1, 0, 2], &[3, 2, 3], ((1,1), &[0x23, 0x12]));
		append_partial_inner::<NibbleQuarter>(&[3, 2, 3, 2, 1, 0, 2, 0, 3, 0, 1, 0, 2], &[3, 2, 3], ((2,0b1001), &[0x23, 0x12]));
		append_partial_inner::<NibbleQuarter>(&[3, 2, 1, 0, 2, 0, 3, 0, 1, 0, 2], &[3, 2], ((1,1), &[0x23, 0x12]));
		append_partial_inner::<NibbleQuarter>(&[3, 2, 3, 2, 1, 0, 2, 0, 3, 0, 1, 0, 2], &[3, 2], ((3,0b111001), &[0x23, 0x12]));
	}

	fn append_partial_inner<N: NibbleOps>(res: &[u8], init: &[u8], partial: ((u8,u8), &[u8])) {
		let mut resv = NibbleVec::<N>::new();
		res.iter().for_each(|r|resv.push(*r));
		let mut initv = NibbleVec::<N>::new();
		init.iter().for_each(|r|initv.push(*r));
		initv.append_partial(partial);
		assert_eq!(resv, initv);
	}

	#[test]
	fn drop_lasts_test() {
		let test_trun = |a: &[u8], b: usize, c: (&[u8], usize)| { 
			let mut k = NibbleVec::<crate::nibble::NibbleHalf>::new();
			for v in a {
				k.push(*v);
			}
			k.drop_lasts(b);
			assert_eq!((&k.inner[..], k.len), c);
		};
		test_trun(&[1,2,3,4], 0, (&[0x12, 0x34], 4));
		test_trun(&[1,2,3,4], 1, (&[0x12, 0x30], 3));
		test_trun(&[1,2,3,4], 2, (&[0x12], 2));
		test_trun(&[1,2,3,4], 3, (&[0x10], 1));
		test_trun(&[1,2,3,4], 4, (&[], 0));
		test_trun(&[1,2,3,4], 5, (&[], 0));
		test_trun(&[1,2,3], 0, (&[0x12, 0x30], 3));
		test_trun(&[1,2,3], 1, (&[0x12], 2));
		test_trun(&[1,2,3], 2, (&[0x10], 1));
		test_trun(&[1,2,3], 3, (&[], 0));
		test_trun(&[1,2,3], 4, (&[], 0));
	}

}

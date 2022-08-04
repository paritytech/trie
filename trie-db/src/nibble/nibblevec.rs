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

use super::NibbleVec;
use crate::{
	nibble::{nibble_ops, BackingByteVec, NibbleSlice},
	node::NodeKey,
	node_codec::Partial,
};
use hash_db::Prefix;

impl Default for NibbleVec {
	fn default() -> Self {
		NibbleVec::new()
	}
}

impl NibbleVec {
	/// Make a new `NibbleVec`.
	pub fn new() -> Self {
		NibbleVec { inner: BackingByteVec::new(), len: 0 }
	}

	/// Length of the `NibbleVec`.
	#[inline(always)]
	pub fn len(&self) -> usize {
		self.len
	}

	/// Returns true if `NibbleVec` has zero length.
	pub fn is_empty(&self) -> bool {
		self.len == 0
	}

	/// Try to get the nibble at the given offset.
	#[inline]
	pub fn at(&self, idx: usize) -> u8 {
		let ix = idx / nibble_ops::NIBBLE_PER_BYTE;
		let pad = idx % nibble_ops::NIBBLE_PER_BYTE;
		nibble_ops::at_left(pad as u8, self.inner[ix])
	}

	/// Push a nibble onto the `NibbleVec`. Ignores the high 4 bits.
	pub fn push(&mut self, nibble: u8) {
		let i = self.len % nibble_ops::NIBBLE_PER_BYTE;

		if i == 0 {
			self.inner.push(nibble_ops::push_at_left(0, nibble, 0));
		} else {
			let output = self
				.inner
				.last_mut()
				.expect("len != 0 since len % 2 != 0; inner has a last element; qed");
			*output = nibble_ops::push_at_left(i as u8, nibble, *output);
		}
		self.len += 1;
	}

	/// Try to pop a nibble off the `NibbleVec`. Fails if len == 0.
	pub fn pop(&mut self) -> Option<u8> {
		if self.is_empty() {
			return None
		}
		let byte = self.inner.pop().expect("len != 0; inner has last elem; qed");
		self.len -= 1;
		let i_new = self.len % nibble_ops::NIBBLE_PER_BYTE;
		if i_new != 0 {
			self.inner.push(nibble_ops::pad_left(byte));
		}
		Some(nibble_ops::at_left(i_new as u8, byte))
	}

	/// Remove then n last nibbles in a faster way than popping n times.
	pub fn drop_lasts(&mut self, n: usize) {
		if n == 0 {
			return
		}
		if n >= self.len {
			self.clear();
			return
		}
		let end = self.len - n;
		let end_index = end / nibble_ops::NIBBLE_PER_BYTE +
			if end % nibble_ops::NIBBLE_PER_BYTE == 0 { 0 } else { 1 };
		(end_index..self.inner.len()).for_each(|_| {
			self.inner.pop();
		});
		self.len = end;
		let pos = self.len % nibble_ops::NIBBLE_PER_BYTE;
		if pos != 0 {
			let kl = self.inner.len() - 1;
			self.inner[kl] = nibble_ops::pad_left(self.inner[kl]);
		}
	}

	/// Get `Prefix` representation of this `NibbleVec`.
	pub fn as_prefix(&self) -> Prefix {
		let split = self.len / nibble_ops::NIBBLE_PER_BYTE;
		let pos = (self.len % nibble_ops::NIBBLE_PER_BYTE) as u8;
		if pos == 0 {
			(&self.inner[..split], None)
		} else {
			(&self.inner[..split], Some(nibble_ops::pad_left(self.inner[split])))
		}
	}

	/// Append another `NibbleVec`. Can be slow (alignement of second vec).
	pub fn append(&mut self, v: &NibbleVec) {
		if v.len == 0 {
			return
		}

		let final_len = self.len + v.len;
		let offset = self.len % nibble_ops::NIBBLE_PER_BYTE;
		let final_offset = final_len % nibble_ops::NIBBLE_PER_BYTE;
		let last_index = self.len / nibble_ops::NIBBLE_PER_BYTE;
		if offset > 0 {
			let (s1, s2) = nibble_ops::SPLIT_SHIFTS;
			self.inner[last_index] =
				nibble_ops::pad_left(self.inner[last_index]) | (v.inner[0] >> s2);
			(0..v.inner.len() - 1)
				.for_each(|i| self.inner.push(v.inner[i] << s1 | v.inner[i + 1] >> s2));
			if final_offset > 0 {
				self.inner.push(v.inner[v.inner.len() - 1] << s1);
			}
		} else {
			(0..v.inner.len()).for_each(|i| self.inner.push(v.inner[i]));
		}
		self.len += v.len;
	}

	/// Append a `Partial`. Can be slow (alignement of partial).
	pub fn append_partial(&mut self, (start_byte, sl): Partial) {
		if start_byte.0 == 1 {
			self.push(nibble_ops::at_left(1, start_byte.1));
		}
		let pad = self.inner.len() * nibble_ops::NIBBLE_PER_BYTE - self.len;
		if pad == 0 {
			self.inner.extend_from_slice(&sl[..]);
		} else {
			let kend = self.inner.len() - 1;
			if sl.len() > 0 {
				self.inner[kend] = nibble_ops::pad_left(self.inner[kend]);
				let (s1, s2) = nibble_ops::SPLIT_SHIFTS;
				self.inner[kend] |= sl[0] >> s1;
				(0..sl.len() - 1).for_each(|i| self.inner.push(sl[i] << s2 | sl[i + 1] >> s1));
				self.inner.push(sl[sl.len() - 1] << s2);
			}
		}
		self.len += sl.len() * nibble_ops::NIBBLE_PER_BYTE;
	}

	/// Utility function for chaining two optional appending
	/// of `NibbleSlice` and/or a byte.
	/// Can be slow.
	pub(crate) fn append_optional_slice_and_nibble(
		&mut self,
		o_slice: Option<&NibbleSlice>,
		o_index: Option<u8>,
	) -> usize {
		let mut res = 0;
		if let Some(slice) = o_slice {
			self.append_partial(slice.right());
			res += slice.len();
		}
		if let Some(ix) = o_index {
			self.push(ix);
			res += 1;
		}
		res
	}

	/// Utility function for `append_optional_slice_and_nibble` after a clone.
	/// Can be slow.
	pub(crate) fn clone_append_optional_slice_and_nibble(
		&self,
		o_slice: Option<&NibbleSlice>,
		o_index: Option<u8>,
	) -> Self {
		let mut p = self.clone();
		p.append_optional_slice_and_nibble(o_slice, o_index);
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
	pub fn as_nibbleslice(&self) -> Option<NibbleSlice> {
		if self.len % nibble_ops::NIBBLE_PER_BYTE == 0 {
			Some(NibbleSlice::new(self.inner()))
		} else {
			None
		}
	}

	/// Do we start with the same nibbles as the whole of `them`?
	pub fn starts_with(&self, other: &Self) -> bool {
		if self.len() < other.len() {
			return false
		}
		let byte_len = other.len() / nibble_ops::NIBBLE_PER_BYTE;
		if &self.inner[..byte_len] != &other.inner[..byte_len] {
			return false
		}
		for pad in 0..(other.len() - byte_len * nibble_ops::NIBBLE_PER_BYTE) {
			let self_nibble = nibble_ops::at_left(pad as u8, self.inner[byte_len]);
			let other_nibble = nibble_ops::at_left(pad as u8, other.inner[byte_len]);
			if self_nibble != other_nibble {
				return false
			}
		}
		true
	}

	/// Return an iterator over `Partial` bytes representation.
	pub fn right_iter<'a>(&'a self) -> impl Iterator<Item = u8> + 'a {
		let require_padding = self.len % nibble_ops::NIBBLE_PER_BYTE != 0;
		let mut ix = 0;
		let inner = &self.inner;

		let (left_s, right_s) = nibble_ops::SPLIT_SHIFTS;

		crate::rstd::iter::from_fn(move || {
			if require_padding && ix < inner.len() {
				if ix == 0 {
					ix += 1;
					Some(inner[ix - 1] >> nibble_ops::BIT_PER_NIBBLE)
				} else {
					ix += 1;

					Some(inner[ix - 2] << left_s | inner[ix - 1] >> right_s)
				}
			} else if ix < inner.len() {
				ix += 1;

				Some(inner[ix - 1])
			} else {
				None
			}
		})
	}
}

impl<'a> From<NibbleSlice<'a>> for NibbleVec {
	fn from(s: NibbleSlice<'a>) -> Self {
		let mut v = NibbleVec::new();
		for i in 0..s.len() {
			v.push(s.at(i));
		}
		v
	}
}

impl From<&NibbleVec> for NodeKey {
	fn from(nibble: &NibbleVec) -> NodeKey {
		if let Some(slice) = nibble.as_nibbleslice() {
			slice.into()
		} else {
			(1, nibble.right_iter().collect())
		}
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::{nibble::nibble_ops, NibbleSlice};

	#[test]
	fn push_pop() {
		let mut v = NibbleVec::new();

		for i in 0..(nibble_ops::NIBBLE_PER_BYTE * 3) {
			let iu8 = (i % nibble_ops::NIBBLE_PER_BYTE) as u8;
			v.push(iu8);
			assert_eq!(v.len() - 1, i);
			assert_eq!(v.at(i), iu8);
		}

		for i in (0..(nibble_ops::NIBBLE_PER_BYTE * 3)).rev() {
			let iu8 = (i % nibble_ops::NIBBLE_PER_BYTE) as u8;
			let a = v.pop();
			assert_eq!(a, Some(iu8));
			assert_eq!(v.len(), i);
		}
	}

	#[test]
	fn append_partial() {
		append_partial_inner(&[1, 2, 3], &[], ((1, 1), &[0x23]));
		append_partial_inner(&[1, 2, 3], &[1], ((0, 0), &[0x23]));
		append_partial_inner(&[0, 1, 2, 3], &[0], ((1, 1), &[0x23]));
	}

	fn append_partial_inner(res: &[u8], init: &[u8], partial: ((u8, u8), &[u8])) {
		let mut resv = NibbleVec::new();
		res.iter().for_each(|r| resv.push(*r));
		let mut initv = NibbleVec::new();
		init.iter().for_each(|r| initv.push(*r));
		initv.append_partial(partial);
		assert_eq!(resv, initv);
	}

	#[test]
	fn drop_lasts_test() {
		let test_trun = |a: &[u8], b: usize, c: (&[u8], usize)| {
			let mut k = NibbleVec::new();
			for v in a {
				k.push(*v);
			}
			k.drop_lasts(b);
			assert_eq!((&k.inner[..], k.len), c);
		};
		test_trun(&[1, 2, 3, 4], 0, (&[0x12, 0x34], 4));
		test_trun(&[1, 2, 3, 4], 1, (&[0x12, 0x30], 3));
		test_trun(&[1, 2, 3, 4], 2, (&[0x12], 2));
		test_trun(&[1, 2, 3, 4], 3, (&[0x10], 1));
		test_trun(&[1, 2, 3, 4], 4, (&[], 0));
		test_trun(&[1, 2, 3, 4], 5, (&[], 0));
		test_trun(&[1, 2, 3], 0, (&[0x12, 0x30], 3));
		test_trun(&[1, 2, 3], 1, (&[0x12], 2));
		test_trun(&[1, 2, 3], 2, (&[0x10], 1));
		test_trun(&[1, 2, 3], 3, (&[], 0));
		test_trun(&[1, 2, 3], 4, (&[], 0));
	}

	#[test]
	fn right_iter_works() {
		let data = vec![1, 2, 3, 4, 5, 234, 78, 99];

		let nibble = NibbleSlice::new(&data);
		let vec = NibbleVec::from(nibble);

		nibble
			.right_iter()
			.zip(vec.right_iter())
			.enumerate()
			.for_each(|(i, (l, r))| assert_eq!(l, r, "Don't match at {}", i));

		// Also try with using an offset.
		let nibble = NibbleSlice::new_offset(&data, 3);
		let vec = NibbleVec::from(nibble);

		nibble
			.right_iter()
			.zip(vec.right_iter())
			.enumerate()
			.for_each(|(i, (l, r))| assert_eq!(l, r, "Don't match at {}", i));
	}
}

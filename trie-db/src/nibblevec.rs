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

/// Owning, nibble-oriented byte vector. Counterpart to `NibbleSlice`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NibbleVec {
	inner: ElasticArray36<u8>,
	len: usize,
}

impl Default for NibbleVec {
	fn default() -> Self {
		NibbleVec::new()
	}
}

impl NibbleVec {
	/// Make a new `NibbleVec`
	pub fn new() -> Self {
		NibbleVec {
			inner: ElasticArray36::new(),
			len: 0
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
		if idx % 2 == 0 {
			self.inner[idx / 2] >> 4
		} else {
			self.inner[idx / 2] & 0x0F
		}
	}

	/// Push a nibble onto the `NibbleVec`. Ignores the high 4 bits.
	pub fn push(&mut self, nibble: u8) {
		let nibble = nibble & 0x0F;

		if self.len % 2 == 0 {
			self.inner.push(nibble << 4);
		} else {
			*self.inner.last_mut().expect("len != 0 since len % 2 != 0; inner has a last element; qed") |= nibble;
		}

		self.len += 1;
	}

	/// Try to pop a nibble off the `NibbleVec`. Fails if len == 0.
	pub fn pop(&mut self) -> Option<u8> {
		if self.is_empty() {
			return None;
		}

		let byte = self.inner.pop().expect("len != 0; inner has last elem; qed");
		let nibble = if self.len % 2 == 0 {
			self.inner.push(byte & 0xF0);
			byte & 0x0F
		} else {
			byte >> 4
		};

		self.len -= 1;
		Some(nibble)
	}

	/// Try to treat this `NibbleVec` as a `NibbleSlice`. Works only if len is even.
	pub fn as_nibbleslice(&self) -> Option<NibbleSlice> {
		if self.len % 2 == 0 {
			Some(NibbleSlice::new(self.inner()))
		} else {
			None
		}
	}

	/// Get the underlying byte slice.
	pub fn inner(&self) -> &[u8] {
		&self.inner[..]
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

#[cfg(test)]
mod tests {
	use super::NibbleVec;

	#[test]
	fn push_pop() {
		let mut v = NibbleVec::new();

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

	#[test]
	fn nibbleslice_conv() {
		let mut v = NibbleVec::new();
		for i in 0..10 {
			v.push(i);
		}

		let v2: NibbleVec = v.as_nibbleslice().unwrap().into();
		assert_eq!(v, v2);
	}
}

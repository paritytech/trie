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
use hash_db::Prefix;
use node_codec::Partial;
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

	/// truncate n last nibbles.
	pub fn truncate(&mut self, mov: usize) {
		if mov == 0 { return; }
		if mov >= self.len {
			self.clear();
			return;
		}
		let nb_rem = if (self.len - mov) % N::NIBBLE_PER_BYTE > 0 {
			mov / N::NIBBLE_PER_BYTE

		} else {
			(mov + 1) / N::NIBBLE_PER_BYTE

		};
		(0..nb_rem).for_each(|_|{ self.inner.pop(); });
    self.len -= mov;
		if self.len % 2 == 1 {
			let kl = self.inner.len() - 1;
			self.inner[kl] &= 255 << 4;
		}
	}

	/// Get prefix from `NibbleVec` (when used as a prefix stack of nibble).
	pub fn as_prefix(&self) -> Prefix {
		let split = self.len / 2;
		if self.len % 2 == 1 {
			(&self.inner[..split], Some(self.inner[split] & (255 << 4)))
		} else {
			(&self.inner[..split], None)
		}
	}

	/// push a full partial.
	pub fn append_partial(&mut self, (o_n, sl): Partial) {
		if let Some(nibble) = o_n {
			self.push(nibble)
		}
    let pad = self.inner.len() * N::NIBBLE_PER_BYTE - self.len;
		if pad == 0 {
			self.inner.append_slice(&sl[..]);
		} else {
			let kend = self.inner.len() - 1;
			if sl.len() > 0 {
				self.inner[kend] &= 255 << 4;
				self.inner[kend] |= sl[0] >> 4;
				(0..sl.len() - 1).for_each(|i|self.inner.push(sl[i] << 4 | sl[i+1]>>4));
				self.inner.push(sl[sl.len() - 1] << 4);
			}
		}
    self.len += sl.len() * N::NIBBLE_PER_BYTE;
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
	use nibbleslice::{NibbleHalf, NibbleOps};

	#[test]
	fn push_pop() {
		push_pop_inner::<NibbleHalf>();
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

	#[test]
	fn truncate_test() {
		let test_trun = |a: &[u8], b: usize, c: (&[u8], usize)| { 
			let mut k = NibbleVec::<crate::nibbleslice::NibbleHalf>::new();
      for v in a {
        k.push(*v);
      }
      k.truncate(b);
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

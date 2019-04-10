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

//! Nibble-orientated view onto byte-slice, allowing nibble-precision offsets.

use ::core_::cmp::*;
use ::core_::fmt;
use elastic_array::ElasticArray36;
use ::core_::marker::PhantomData;
use nibblevec::NibbleVec;

// until const fn for pow
const TWO_EXP: [usize; 9] = [1, 2, 4, 8, 16, 32, 64, 128, 256];

/// Nibble specific variants
pub trait NibbleOps: Default + Clone + PartialEq + Eq + PartialOrd + Ord + Copy {
	/// variant repr 
	const REPR : ByteLayout;
	/// Number of bit per nibble
	const BIT_PER_NIBBLE : usize = TWO_EXP[Self::REPR as usize]; // 2usize.pow(Self::REPR as u32);
	/// Number of nibble per byte
	const NIBBLE_PER_BYTE : usize = 8 / Self::BIT_PER_NIBBLE;
	/// Number of nibble per node (must be power of 2 and under 256)
	const NIBBLE_LEN : usize = TWO_EXP[8 / Self::NIBBLE_PER_BYTE]; //2usize.pow(8 as u32 / Self::NIBBLE_PER_BYTE as u32);
	/// Empty nibble encoded
	const EMPTY_ENCODED: &'static [u8];

	/// Create a new nibble slice from the given HPE encoded data (e.g. output of `encoded()`).
	fn from_encoded(data: &[u8]) -> (NibbleSlice<Self>, bool);

	/// Get the nibble at position `i`.
	fn at(&NibbleSlice<Self>, i: usize) -> u8;

 	/// Encode while nibble slice in prefixed hex notation, noting whether it `is_leaf`.
	#[inline]
	fn encoded(s: &NibbleSlice<Self>, is_leaf: bool) -> ElasticArray36<u8> {
		Self::encoded_leftmost_unchecked(s, s.len(), is_leaf)
	}

	/// Encode only the leftmost `n` bytes of the nibble slice in prefixed hex notation,
	/// noting whether it `is_leaf`.
	fn encoded_leftmost(s: &NibbleSlice<Self>, n: usize, is_leaf: bool) -> ElasticArray36<u8> {
		let l = min(s.len(), n);
		Self::encoded_leftmost_unchecked(s, l, is_leaf)
	}
 
	/// encoded leftmost without checking end bound
	fn encoded_leftmost_unchecked(s: &NibbleSlice<Self>, l: usize, is_leaf: bool) -> ElasticArray36<u8>;

	/// Try to get the nibble at the given offset.
	fn vec_at(s: &NibbleVec<Self>, idx: usize) -> u8;

	/// Push a nibble onto the `NibbleVec`. Ignores the high 4 bits.
	fn push(s: &mut NibbleVec<Self>, nibble: u8);

	/// Try to pop a nibble off the `NibbleVec`. Fails if len == 0.
	fn pop(s: &mut NibbleVec<Self>) -> Option<u8>;

}

/// half byte nibble prepend encoding
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy, Debug)]
pub struct NibblePreHalf;


/// Type of nibble in term of byte size
#[repr(usize)]
pub enum ByteLayout {
	/// nibble of one bit length
	Bit = 0, // 1, 8, 2
	/// nibble of a quarter byte length
	Quarter = 1, // 2, 4, 4
	/// nibble of a half byte length
	Half = 2, // 4, 2, 16
	/// nibble of one byte length
	Full = 3, // 8, 1, 256
}

impl NibbleOps for NibblePreHalf {
	const EMPTY_ENCODED: &'static [u8] = &[0];
	const REPR: ByteLayout = ByteLayout::Half; 

	fn from_encoded(data: &[u8]) -> (NibbleSlice<Self>, bool) {
		if data.is_empty() {
			(NibbleSlice::<Self>::new(&[]), false)
		} else {
			(NibbleSlice::<Self>::new_offset(data, if data[0] & 16 == 16 {1} else {2}), data[0] & 32 == 32)
		}
	}

	#[inline(always)]
	fn at(s: &NibbleSlice<Self>, i: usize) -> u8 {
		let l = s.data.len() * Self::NIBBLE_PER_BYTE - s.offset;
		if i < l {
			if (s.offset + i) & 1 == 1 {
				s.data[(s.offset + i) / Self::NIBBLE_PER_BYTE] & 15u8
			}
			else {
				s.data[(s.offset + i) / Self::NIBBLE_PER_BYTE] >> 4
			}
		} else {
			let i = i - l;
			if (s.offset_encode_suffix + i) & 1 == 1 {
				s.data_encode_suffix[(s.offset_encode_suffix + i) / Self::NIBBLE_PER_BYTE] & 15u8
			}
			else {
				s.data_encode_suffix[(s.offset_encode_suffix + i) / Self::NIBBLE_PER_BYTE] >> 4
			}
		}
	}

	fn encoded_leftmost_unchecked(s: &NibbleSlice<Self>, l: usize, is_leaf: bool) -> ElasticArray36<u8> {
		let mut r = ElasticArray36::new();
		let mut i = l % 2;
		r.push(if i == 1 {NIBBLE_ODD_MASK + Self::at(s, 0)} else {0} 
			+ if is_leaf {NIBBLE_LEAF_MASK} else {NIBBLE_EXT_MASK});
		while i < l {
			r.push(Self::at(s, i) * 16 + Self::at(s, i + 1));
			i += 2;
		}
		r
	}

	#[inline]
	fn vec_at(s: &NibbleVec<Self>, idx: usize) -> u8 {
		if idx % 2 == 0 {
			s.inner[idx / 2] >> 4
		} else {
			s.inner[idx / 2] & 0x0F
		}
	}

	fn push(s: &mut NibbleVec<Self>, nibble: u8) {
		let nibble = nibble & 0x0F;

		if s.len % 2 == 0 {
			s.inner.push(nibble << 4);
		} else {
			*s.inner.last_mut().expect("len != 0 since len % 2 != 0; inner has a last element; qed") |= nibble;
		}

		s.len += 1;
	}

	fn pop(s: &mut NibbleVec<Self>) -> Option<u8> {
		if s.is_empty() {
			return None;
		}

		let byte = s.inner.pop().expect("len != 0; inner has last elem; qed");
		let nibble = if s.len % 2 == 0 {
			s.inner.push(byte & 0xF0);
			byte & 0x0F
		} else {
			byte >> 4
		};

		s.len -= 1;
		Some(nibble)
	}

}

// TODO EMCH NIBBLE api from full key without concat??

pub const EMPTY_ENCODED: &[u8] = &[0];


/// mask for nibble encoded first byte for extension
const NIBBLE_EXT_MASK: u8 = 0x00;

/// mask for nibble encoded first byte for leaf
const NIBBLE_ODD_MASK: u8 = 0x10;

/// mask for nibble encoded first byte for leaf
const NIBBLE_LEAF_MASK: u8 = 0x20;

/// Nibble-orientated view onto byte-slice, allowing nibble-precision offsets.
///
/// This is an immutable struct. No operations actually change it.
///
/// # Example
/// ```snippet
/// use patricia_trie::nibbleslice::NibbleSlice;
/// fn main() {
///   let d1 = &[0x01u8, 0x23, 0x45];
///   let d2 = &[0x34u8, 0x50, 0x12];
///   let d3 = &[0x00u8, 0x12];
///   let n1 = NibbleSlice::new(d1);			// 0,1,2,3,4,5
///   let n2 = NibbleSlice::new(d2);			// 3,4,5,0,1,2
///   let n3 = NibbleSlice::new_offset(d3, 1);	// 0,1,2
///   assert!(n1 > n3);							// 0,1,2,... > 0,1,2
///   assert!(n1 < n2);							// 0,... < 3,...
///   assert!(n2.mid(3) == n3);					// 0,1,2 == 0,1,2
///   assert!(n1.starts_with(&n3));
///   assert_eq!(n1.common_prefix(&n3), 3);
///   assert_eq!(n2.mid(3).common_prefix(&n1), 3);
/// }
/// ```
#[derive(Copy, Clone)]
pub struct NibbleSlice<'a, N> {
	data: &'a [u8],
	offset: usize,
	data_encode_suffix: &'a [u8],
	offset_encode_suffix: usize,
	marker: PhantomData<N>,
}

/// Iterator type for a nibble slice.
pub struct NibbleSliceIterator<'a, N> {
	p: &'a NibbleSlice<'a, N>,
	i: usize,
}

impl<'a, N: NibbleOps> Iterator for NibbleSliceIterator<'a, N> {
	type Item = u8;
	fn next(&mut self) -> Option<u8> {
		self.i += 1;
		match self.i <= self.p.len() {
			true => Some(self.p.at(self.i - 1)),
			false => None,
		}
	}
}

impl<'a, N: NibbleOps> NibbleSlice<'a, N> {
	/// Create a new nibble slice with the given byte-slice.
	pub fn new(data: &'a [u8]) -> Self { NibbleSlice::new_offset(data, 0) }

	/// Create a new nibble slice with the given byte-slice with a nibble offset.
	pub fn new_offset(data: &'a [u8], offset: usize) -> Self {
		NibbleSlice {
			data,
			offset,
			data_encode_suffix: &b""[..],
			offset_encode_suffix: 0,
			marker: PhantomData,
		}
	}

	/// Create a composed nibble slice; one followed by the other.
	pub fn new_composed(a: &Self, b: &Self) -> Self {
		NibbleSlice {
			data: a.data,
			offset: a.offset,
			data_encode_suffix: b.data,
			offset_encode_suffix: b.offset,
			marker: PhantomData,
		}
	}

	/// Get an iterator for the series of nibbles.
	pub fn iter(&'a self) -> NibbleSliceIterator<'a, N> {
		NibbleSliceIterator { p: self, i: 0 }
	}

	/// Create a new nibble slice from the given HPE encoded data (e.g. output of `encoded()`).
	pub fn from_encoded(data: &[u8]) -> (NibbleSlice<N>, bool) {
		N::from_encoded(data)
	}

	/// Is this an empty slice?
	pub fn is_empty(&self) -> bool { self.len() == 0 }

	/// Get the length (in nibbles, naturally) of this slice.
	#[inline]
	pub fn len(&self) -> usize { (self.data.len() + self.data_encode_suffix.len()) * N::NIBBLE_PER_BYTE - self.offset - self.offset_encode_suffix }

	/// Get the nibble at position `i`.
	#[inline(always)]
	pub fn at(&self, i: usize) -> u8 {
		N::at(&self, i)
	}

	/// Return object which represents a view on to this slice (further) offset by `i` nibbles.
	pub fn mid(&self, i: usize) -> NibbleSlice<'a, N> {
		NibbleSlice {
			data: self.data,
			offset: self.offset + i,
			data_encode_suffix: &b""[..],
			offset_encode_suffix: 0,
			marker: PhantomData,
		}
	}

	/// Do we start with the same nibbles as the whole of `them`?
 	pub fn starts_with(&self, them: &Self) -> bool { self.common_prefix(them) == them.len() }

 	/// How many of the same nibbles at the beginning do we match with `them`?
	pub fn common_prefix(&self, them: &Self) -> usize {
		let s = min(self.len(), them.len());
		let mut i = 0usize;
		while i < s {
			if self.at(i) != them.at(i) { break; }
			i += 1;
		}
		i
	}

	/// Encode while nibble slice in prefixed hex notation, noting whether it `is_leaf`.
	#[inline]
	pub fn encoded(&self, is_leaf: bool) -> ElasticArray36<u8> {
		N::encoded(self, is_leaf)
	}

	/// Encode only the leftmost `n` bytes of the nibble slice in prefixed hex notation,
	/// noting whether it `is_leaf`.
	pub fn encoded_leftmost(&self, n: usize, is_leaf: bool) -> ElasticArray36<u8> {
		N::encoded_leftmost(self, n, is_leaf)
	}
}

impl<'a, N: NibbleOps> PartialEq for NibbleSlice<'a, N> {
	fn eq(&self, them: &Self) -> bool {
		self.len() == them.len() && self.starts_with(them)
	}
}

impl<'a, N: NibbleOps> Eq for NibbleSlice<'a, N> { }

impl<'a, N: NibbleOps> PartialOrd for NibbleSlice<'a, N> {
	fn partial_cmp(&self, them: &Self) -> Option<Ordering> {
		Some(self.cmp(them))
	}
}

impl<'a, N: NibbleOps> Ord for NibbleSlice<'a, N> {
	fn cmp(&self, them: &Self) -> Ordering {
		let s = min(self.len(), them.len());
		let mut i = 0usize;
		while i < s {
			match self.at(i).partial_cmp(&them.at(i)).unwrap() {
				Ordering::Less => return Ordering::Less,
				Ordering::Greater => return Ordering::Greater,
				_ => i += 1,
			}
		}
		self.len().cmp(&them.len())
	}
}

impl<'a, N: NibbleOps> fmt::Debug for NibbleSlice<'a, N> {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		for i in 0..self.len() {
			match i {
				0 => write!(f, "{:01x}", self.at(i))?,
				_ => write!(f, "'{:01x}", self.at(i))?,
			}
		}
		Ok(())
	}
}

/// Join two encoded nibble slices.
pub fn combine_encoded<N: NibbleOps>(prefix: &[u8], extension: &[u8]) -> ElasticArray36<u8> {
	let slice = NibbleSlice::<N>::new_composed(&NibbleSlice::from_encoded(&prefix).0, &NibbleSlice::from_encoded(extension).0);
	slice.encoded(false)
}

#[cfg(test)]
mod tests {
	use super::NibbleSlice;
	use super::NibblePreHalf;
	use elastic_array::ElasticArray36;
	static D: &'static [u8;3] = &[0x01u8, 0x23, 0x45];

	#[test]
	fn basics() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		assert_eq!(n.len(), 6);
		assert!(!n.is_empty());

		let n = NibbleSlice::<NibblePreHalf>::new_offset(D, 6);
		assert!(n.is_empty());

		let n = NibbleSlice::<NibblePreHalf>::new_offset(D, 3);
		assert_eq!(n.len(), 3);
		for i in 0..3 {
			assert_eq!(n.at(i), i as u8 + 3);
		}
	}

	#[test]
	fn iterator() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		let mut nibbles: Vec<u8> = vec![];
		nibbles.extend(n.iter());
		assert_eq!(nibbles, (0u8..6).collect::<Vec<_>>())
	}

	#[test]
	fn mid() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		let m = n.mid(2);
		for i in 0..4 {
			assert_eq!(m.at(i), i as u8 + 2);
		}
		let m = n.mid(3);
		for i in 0..3 {
			assert_eq!(m.at(i), i as u8 + 3);
		}
	}

	#[test]
	fn encoded() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		assert_eq!(n.encoded(false), ElasticArray36::from_slice(&[0x00, 0x01, 0x23, 0x45]));
		assert_eq!(n.encoded(true), ElasticArray36::from_slice(&[0x20, 0x01, 0x23, 0x45]));
		assert_eq!(n.mid(1).encoded(false), ElasticArray36::from_slice(&[0x11, 0x23, 0x45]));
		assert_eq!(n.mid(1).encoded(true), ElasticArray36::from_slice(&[0x31, 0x23, 0x45]));
	}

	#[test]
	fn from_encoded() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		assert_eq!((n, false), NibbleSlice::from_encoded(&[0x00, 0x01, 0x23, 0x45]));
		assert_eq!((n, true), NibbleSlice::from_encoded(&[0x20, 0x01, 0x23, 0x45]));
		assert_eq!((n.mid(1), false), NibbleSlice::from_encoded(&[0x11, 0x23, 0x45]));
		assert_eq!((n.mid(1), true), NibbleSlice::from_encoded(&[0x31, 0x23, 0x45]));
	}

	#[test]
	fn shared() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);

		let other = &[0x01u8, 0x23, 0x01, 0x23, 0x45, 0x67];
		let m = NibbleSlice::new(other);

		assert_eq!(n.common_prefix(&m), 4);
		assert_eq!(m.common_prefix(&n), 4);
		assert_eq!(n.mid(1).common_prefix(&m.mid(1)), 3);
		assert_eq!(n.mid(1).common_prefix(&m.mid(2)), 0);
		assert_eq!(n.common_prefix(&m.mid(4)), 6);
		assert!(!n.starts_with(&m.mid(4)));
		assert!(m.mid(4).starts_with(&n));
	}

	#[test]
	fn compare() {
		let other = &[0x01u8, 0x23, 0x01, 0x23, 0x45];
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		let m = NibbleSlice::new(other);

		assert!(n != m);
		assert!(n > m);
		assert!(m < n);

		assert!(n == m.mid(4));
		assert!(n >= m.mid(4));
		assert!(n <= m.mid(4));
	}
}

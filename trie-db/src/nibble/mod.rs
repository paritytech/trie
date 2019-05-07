// Copyright 2019 Parity Technologies
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

//! Nibble oriented methods

mod nibblevec;
mod nibbleslice;
use ::core_::cmp::*;
use ::core_::marker::PhantomData;
use elastic_array::ElasticArray36;
use crate::node::NodeKey;

pub const EMPTY_NIBBLE: (&'static [u8], (u8, u8)) = (&[], (0, 0));
// until const fn for pow
const TWO_EXP: [usize; 9] = [1, 2, 4, 8, 16, 32, 64, 128, 256];
/// Nibble specific variants
/// Note that some function are defined here but ideally it should just be a set of
/// constant (with function handling all constant case).
pub trait NibbleOps: Default + Clone + PartialEq + Eq + PartialOrd + Ord + Copy + super::MaybeDebug {
	/// variant repr 
	const REPR : ByteLayout;
	/// Number of bit per nibble
	const BIT_PER_NIBBLE : usize = TWO_EXP[Self::REPR as usize]; // 2usize.pow(Self::REPR as u32);
	/// Number of nibble per byte
	const NIBBLE_PER_BYTE : usize = 8 / Self::BIT_PER_NIBBLE;
	/// Number of nibble per node (must be power of 2 and under 256)
	const NIBBLE_LEN : usize = TWO_EXP[8 / Self::NIBBLE_PER_BYTE]; //2usize.pow(8 as u32 / Self::NIBBLE_PER_BYTE as u32);
	/// padding bitmasks (could be calculated with a constant function).
	/// First is bit mask to apply, second is right shift needed.
	const PADDING_BITMASK: &'static [(u8, usize)];
	/// las ix for nible
	const LAST_N_IX: usize = Self::NIBBLE_PER_BYTE - 1;
	/// las ix for nible as a u8 (for pattern matching)
	const LAST_N_IX_U8: u8 = Self::LAST_N_IX as u8;

	/// Buff for slice index store (we do not include
	/// directly slice in it to avoid lifetime in
	/// trait
	type ChildSliceIx: ChildSliceIx;

	/// mask a byte from a ix > 0 (ix being content)
	#[inline(always)]
	fn masked_left(ix: u8, b: u8) -> u8 {
		debug_assert!(ix > 0);
		b & !Self::PADDING_BITMASK[ix as usize].0
	}
	/// mask a byte from a ix > 0 (ix being padding)
	#[inline(always)]
	fn masked_right(ix: u8, b: u8) -> u8 {
		debug_assert!(ix > 0);
		b & Self::PADDING_BITMASK[ix as usize].0
	}
	/// get value at ix from a right first byte
	#[inline(always)]
	fn at_left(ix: u8, b: u8) -> u8 {
		(b & Self::PADDING_BITMASK[ix as usize].0)
			>> Self::PADDING_BITMASK[ix as usize].1
	}

	/// get nibble for left aligned array
	#[inline(always)]
	fn left_nibble_at(v1: &[u8], ix: usize) -> u8 {
		Self::at_left(
			(ix % Self::NIBBLE_PER_BYTE) as u8,
			v1[ix / Self::NIBBLE_PER_BYTE]
		)
	}

	/// push u8 nib value at ix into a existing byte 
	#[inline(always)]
	fn push_at_left(ix: u8, v: u8, into: u8) -> u8 {
		into | (v << Self::PADDING_BITMASK[ix as usize].1)
	}

	/// Get the nibble at position `i`.
	#[inline(always)]
	fn at(s: &NibbleSlice<Self>, i: usize) -> u8 {
		let ix = (s.offset + i) / Self::NIBBLE_PER_BYTE;
		let pad = (s.offset + i) % Self::NIBBLE_PER_BYTE;
		Self::at_left(pad as u8, s.data[ix])
	}

	#[inline]
	/// Number of padding needed for a length `i`.
	fn nb_padding(i: usize) -> usize {
		(Self::NIBBLE_PER_BYTE - (i % Self::NIBBLE_PER_BYTE)) % Self::NIBBLE_PER_BYTE
	}

	/// split shifts for a given unaligned padding (pad != 0)
	#[inline(always)]
	fn split_shifts(pad: usize) -> (usize, usize) {
		debug_assert!(pad > 0);
		let s1 = Self::PADDING_BITMASK[pad - 1].1;
		let s2 = 8 - s1;
		(s1, s2)
	}

	/// get biggest common depth between two left aligned packed nibble arrays
	fn biggest_depth(v1: &[u8], v2: &[u8]) -> usize {
		// sorted assertion preventing out of bound
		for a in 0..v1.len() {
			if v1[a] == v2[a] {
			} else {
				return a * Self::NIBBLE_PER_BYTE + Self::left_common(v1[a], v2[a]);
			}
		}
		return v1.len() * Self::NIBBLE_PER_BYTE;
	}

	/// number of common bit between two left pad byte
	#[inline(always)]
	fn left_common(a: u8, b: u8) -> usize {
		let mut i = 0;
		while i < Self::NIBBLE_PER_BYTE {
			if (a >> Self::PADDING_BITMASK[i].1)
				!= (b >> Self::PADDING_BITMASK[i].1) {
				break;
			}
			i += 1;
		}
		return i;
	}

	/// shift key (right) alignment to match a given left offset, possibly leaving
	/// wrong end of Nodekey (eg to combine two keys)
	fn shift_key(key: &mut NodeKey, ofset: usize) -> bool {
		let old_offset = key.0;
		key.0 = ofset;
		if old_offset > ofset {
			// shift left
			let shift = old_offset - ofset;
			let (s1, s2) = Self::split_shifts(shift);
			let kl = key.1.len();
			(0..kl - 1).for_each(|i|key.1[i] = key.1[i] << s2 | key.1[i+1] >> s1);
			key.1[kl - 1] = key.1[kl - 1] << s2;
			true
		} else if old_offset < ofset {
			// shift right
			let shift = ofset - old_offset;
			let (s1, s2) = Self::split_shifts(shift);
			key.1.push(0);
			(1..key.1.len()).rev().for_each(|i|key.1[i] = key.1[i - 1] << s1 | key.1[i] >> s2);
			key.1[0] = key.1[0] >> s2;
			true
		} else {
			false
		}
	}
}

/// half byte nibble prepend encoding
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy, Debug)]
pub struct NibbleHalf;


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

impl NibbleOps for NibbleHalf {
	const REPR: ByteLayout = ByteLayout::Half; 
	const PADDING_BITMASK: &'static [(u8, usize)] = &[(0xFF, 4), (0x0F, 0)];
	type ChildSliceIx = ChildSliceIx16;
}

#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy, Debug)]
pub struct NibbleQuarter;

// new_padded_end merged
impl NibbleOps for NibbleQuarter {
	const REPR: ByteLayout = ByteLayout::Quarter; 
	const PADDING_BITMASK: &'static [(u8, usize)] = &[
		(0b1111_1111, 6),
		(0b0011_1111, 4),
		(0b0000_1111, 2),
		(0b0000_0011, 0),
	];
	type ChildSliceIx = ChildSliceIx4;
}


/// Owning, nibble-oriented byte vector. Counterpart to `NibbleSlice`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NibbleVec<N> {
	inner: ElasticArray36<u8>,
	len: usize,
	marker: PhantomData<N>,
}

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
pub struct NibbleSlice<'a, N: NibbleOps> {
	data: &'a [u8],
	offset: usize,
	marker: PhantomData<N>,
}

/// Iterator type for a nibble slice.
pub struct NibbleSliceIterator<'a, N: NibbleOps> {
	p: &'a NibbleSlice<'a, N>,
	i: usize,
}

/// trait only here to avoid lifetime when storing slice
/// This would be useless with https://github.com/rust-lang/rust/issues/43408
pub trait ChildSliceIx: AsRef<[usize]>
	+ AsMut<[usize]> + Default + Eq + PartialEq + crate::MaybeDebug
	+ Clone {

	/// nb nibble in slice
	const NIBBLE_LEN : usize;
	/// bit to skip between slice
	const CONTENT_HEADER_SIZE: usize;

	/// get an optional slice
	fn slice_at<'a>(&self, ix: usize, data: &'a [u8]) -> Option<&'a[u8]> {
		let b = (self.as_ref().get(ix), self.as_ref().get(ix + 1));
		if let (Some(s), Some(e)) = b {
			let s = s + Self::CONTENT_HEADER_SIZE;
			if s < *e {
				Some(&data[s..*e])
			} else {
				None
			}
		} else {
			None
		}
	}
	fn iter<'a>(&'a self, data: &'a [u8]) -> IterChildSliceIx<'a, Self> {
		IterChildSliceIx(self, 0, data)
	}
}

/// iterator over `ChildSliceIx` trait
pub struct IterChildSliceIx<'a, CS>(&'a CS, usize, &'a[u8]);

impl<'a, CS: ChildSliceIx> Iterator for IterChildSliceIx<'a, CS> {
	type Item = Option<&'a[u8]>;
	fn next(&mut self) -> Option<Self::Item> {
		if self.1 == CS::NIBBLE_LEN {
			return None;
		}
		self.1 += 1;
		Some(self.0.slice_at(self.1 - 1, self.2))
	}
}

macro_rules! child_slice_ix {
	($me: ident, $size: expr, $pre: expr) => {
		#[derive(Default, Eq, PartialEq, Debug, Clone)]
		/// child slice ix for radix $size
		pub struct $me([usize; $size + 1]);

		impl AsRef<[usize]> for $me {
			fn as_ref(&self) -> &[usize] {
				&self.0[..]
			}
		}

		impl AsMut<[usize]> for $me {
			fn as_mut(&mut self) -> &mut [usize] {
				&mut self.0[..]
			}
		}

		impl ChildSliceIx for $me {
			const CONTENT_HEADER_SIZE: usize = $pre;
			const NIBBLE_LEN: usize = $size;
		}
	}
}
child_slice_ix!(ChildSliceIx16, 16, 1);
child_slice_ix!(ChildSliceIx4, 4, 1);

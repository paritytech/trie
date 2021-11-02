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

//! Nibble oriented methods.

use crate::node::NodeKey;
use crate::rstd::cmp;

pub use self::leftnibbleslice::LeftNibbleSlice;

mod nibblevec;
mod nibbleslice;
mod leftnibbleslice;

/// Utility methods to work on radix 16 nibble.
pub mod nibble_ops {
	use super::*;

	/// Single nibble length in bit.
	pub const BIT_PER_NIBBLE : usize = 4;
	/// Number of nibble per byte.
	pub const NIBBLE_PER_BYTE : usize = 2;
	/// Number of child for a branch (trie radix).
	pub const NIBBLE_LENGTH : usize = 16;
	/// Nibble (half a byte).
	pub const PADDING_BITMASK: u8 = 0x0F;
	/// Size of header.
	pub const CONTENT_HEADER_SIZE: u8 = 1;

	/// Mask a byte, keeping left nibble.
	#[inline(always)]
	pub fn pad_left(b: u8) -> u8 {
		b & !PADDING_BITMASK
	}

	/// Mask a byte, keeping right byte.
	#[inline(always)]
	pub fn pad_right(b: u8) -> u8 {
		b & PADDING_BITMASK
	}

	/// Get u8 nibble value at a given index of a byte.
	#[inline(always)]
	pub fn at_left(ix: u8, b: u8) -> u8 {
		if ix == 1 {
			b & PADDING_BITMASK
		} else {
			b >> BIT_PER_NIBBLE
		}
	}

	/// Get u8 nibble value at a given index in a left aligned array.
	#[inline(always)]
	pub fn left_nibble_at(v1: &[u8], ix: usize) -> u8 {
		at_left(
			(ix % NIBBLE_PER_BYTE) as u8,
			v1[ix / NIBBLE_PER_BYTE]
		)
	}

	/// Get u8 nibble value at a given index in a `NibbleSlice`.
	#[inline(always)]
	pub fn at(s: &NibbleSlice, i: usize) -> u8 {
		let ix = (s.offset + i) / NIBBLE_PER_BYTE;
		let pad = (s.offset + i) % NIBBLE_PER_BYTE;
		at_left(pad as u8, s.data[ix])
	}

	/// Push u8 nibble value at a given index into an existing byte.
	#[inline(always)]
	pub fn push_at_left(ix: u8, v: u8, into: u8) -> u8 {
		into | if ix == 1 {
			v
		} else {
			v << BIT_PER_NIBBLE
		}
	}

	#[inline]
	/// Calculate the number of needed padding a array of nibble length `i`.
	pub fn number_padding(i: usize) -> usize {
		i % NIBBLE_PER_BYTE
	}

	/// The nibble shifts needed to align.
	/// We use two value, one is a left shift and
	/// the other is a right shift.
	pub const SPLIT_SHIFTS: (usize, usize) = (4, 4);

	/// Count the biggest common depth between two left aligned packed nibble slice.
	pub fn biggest_depth(v1: &[u8], v2: &[u8]) -> usize {
		let upper_bound = cmp::min(v1.len(), v2.len());
		for a in 0 .. upper_bound {
			if v1[a] != v2[a] {
				return a * NIBBLE_PER_BYTE + left_common(v1[a], v2[a]);
			}
		}
		upper_bound * NIBBLE_PER_BYTE
	}

	/// Calculate the number of common nibble between two left aligned bytes.
	#[inline(always)]
	pub fn left_common(a: u8, b: u8) -> usize {
		if a == b {
			2
		} else if pad_left(a) == pad_left(b) {
			1
		} else {
			0
		}
	}

	/// Shifts right aligned key to add a given left offset.
	/// Resulting in possibly padding at both left and right
	/// (example usage when combining two keys).
	pub fn shift_key(key: &mut NodeKey, offset: usize) -> bool {
		let old_offset = key.0;
		key.0 = offset;
		if old_offset > offset {
			// shift left
			let (s1, s2) = nibble_ops::SPLIT_SHIFTS;
			let kl = key.1.len();
			(0..kl - 1).for_each(|i| key.1[i] = key.1[i] << s2 | key.1[i+1] >> s1);
			key.1[kl - 1] = key.1[kl - 1] << s2;
			true
		} else if old_offset < offset {
			// shift right
			let (s1, s2) = nibble_ops::SPLIT_SHIFTS;
			key.1.push(0);
			(1..key.1.len()).rev().for_each(|i| key.1[i] = key.1[i - 1] << s1 | key.1[i] >> s2);
			key.1[0] = key.1[0] >> s2;
			true
		} else {
			false
		}
	}

}

/// Backing storage for `NibbleVec`s.
pub(crate) type BackingByteVec = smallvec::SmallVec<[u8; 36]>;

/// Owning, nibble-oriented byte vector. Counterpart to `NibbleSlice`.
/// Nibbles are always left aligned, so making a `NibbleVec` from
/// a `NibbleSlice` can get costy.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, PartialEq, Eq)]
pub struct NibbleVec {
	inner: BackingByteVec,
	len: usize,
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
pub struct NibbleSlice<'a> {
	data: &'a [u8],
	offset: usize,
}

/// Iterator type for a nibble slice.
pub struct NibbleSliceIterator<'a> {
	p: &'a NibbleSlice<'a>,
	i: usize,
}

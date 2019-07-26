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

mod nibblevec;
mod nibbleslice;
use ::core_::cmp::*;
use ::core_::marker::PhantomData;
use elastic_array::ElasticArray36;
use crate::node::NodeKey;
use super::MaybeDebug;

// Workaround no constant function for pow.
const TWO_EXP: [usize; 9] = [1, 2, 4, 8, 16, 32, 64, 128, 256];

/// This trait contain Trie nibble specific definitions.
/// This trait is mostly a collection of associated constant and some generic
/// methods.
/// Generic methods should not need redefinition except for optimization
/// purpose.
pub trait NibbleOps: Default + Clone + PartialEq + Eq + PartialOrd + Ord + Copy + MaybeDebug {
	/// See [`ByteLayout`].
	const REPR : ByteLayout;
	/// Single nibble length in bit.
	const BIT_PER_NIBBLE : usize = TWO_EXP[Self::REPR as usize];
	/// Number of nibble per byte.
	const NIBBLE_PER_BYTE : usize = 8 / Self::BIT_PER_NIBBLE;
	/// Number of child for a branch (trie radix).
	const NIBBLE_LENGTH : usize = TWO_EXP[Self::BIT_PER_NIBBLE];
	/// Padding bitmasks, internally use for working on padding byte.
	/// Length of this array is `Self::BIT_PER_NIBBLE`.
	/// The first element of each pair is a bit mask to apply,
	/// the second element is a right shift to apply in some case.
	///	const PADDING_BITMASK: &'static [(u8, usize)] = &[
	/// Similar to following const function.
	/// ```rust
	/// const BIT_PER_NIBBLE: usize = 4;
	/// const fn padding_bitmask(ix: usize) -> (u8, usize) {
	///   //assert!(ix < 8 / BIT_PER_NIBBLE);
	///   let offset = BIT_PER_NIBBLE * ix;
	///   (1u8 >> offset, 8 - offset)
	/// }
	/// ```
	const PADDING_BITMASK: &'static [(u8, usize)];
	/// Last nibble index as u8, a convenience constant for iteration on all nibble.
	const LAST_NIBBLE_INDEX: u8 = (Self::NIBBLE_PER_BYTE - 1) as u8;

	/// Buffer type for slice index store (we do not include
	/// directly slice in it to avoid lifetime in
	/// trait
	type ChildSliceIndex: ChildSliceIndex;

	/// Mask a byte from a `ix` > 0 (ix being content).
	/// Result is a byte containing `ix` nibble of left aligned content and padded with 0.
	#[inline(always)]
	fn masked_left(ix: u8, b: u8) -> u8 {
		debug_assert!(ix > 0);
		b & !Self::PADDING_BITMASK[ix as usize].0
	}

	/// Mask a byte from a ix > 0 (ix being content)
	/// Result is a byte containing `ix` nibble of right aligned content and padded with 0.
	#[inline(always)]
	fn masked_right(ix: u8, b: u8) -> u8 {
		if ix > 0 {
			b & Self::PADDING_BITMASK[Self::NIBBLE_PER_BYTE - ix as usize].0
		} else {
			b
		}
	}

	/// Get u8 nibble value at a given index of a byte.
	#[inline(always)]
	fn at_left(ix: u8, b: u8) -> u8 {
		(b & Self::PADDING_BITMASK[ix as usize].0)
			>> Self::PADDING_BITMASK[ix as usize].1
	}

	/// Get u8 nibble value at a given index in a left aligned array.
	#[inline(always)]
	fn left_nibble_at(v1: &[u8], ix: usize) -> u8 {
		Self::at_left(
			(ix % Self::NIBBLE_PER_BYTE) as u8,
			v1[ix / Self::NIBBLE_PER_BYTE]
		)
	}

	/// Get u8 nibble value at a given index in a `NibbleSlice`.
	#[inline(always)]
	fn at(s: &NibbleSlice<Self>, i: usize) -> u8 {
		let ix = (s.offset + i) / Self::NIBBLE_PER_BYTE;
		let pad = (s.offset + i) % Self::NIBBLE_PER_BYTE;
		Self::at_left(pad as u8, s.data[ix])
	}

	/// Push u8 nibble value at a given index into an existing byte.
	#[inline(always)]
	fn push_at_left(ix: u8, v: u8, into: u8) -> u8 {
		into | (v << Self::PADDING_BITMASK[ix as usize].1)
	}

	#[inline]
	/// Calculate the number of needed padding a array of nibble length `i`.
	fn number_padding(i: usize) -> usize {
		(Self::NIBBLE_PER_BYTE - (i % Self::NIBBLE_PER_BYTE)) % Self::NIBBLE_PER_BYTE
	}

	/// Calculate the array nibble shifts needed
	/// for alignment a given unaligned padding (pad != 0).
	#[inline(always)]
	fn split_shifts(pad: usize) -> (usize, usize) {
		debug_assert!(pad > 0);
		let s1 = Self::PADDING_BITMASK[pad - 1].1;
		let s2 = 8 - s1;
		(s1, s2)
	}

	/// Count the biggest common depth between two left aligned packed nibble slice.
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

	/// Calculate the number of common nibble between two left aligned bytes.
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

	/// Shifts right aligned key to add a given left offset.
	/// Resulting in possibly padding at both left and right
	/// (example usage when combining two keys).
	fn shift_key(key: &mut NodeKey, ofset: usize) -> bool {
		let old_offset = key.0;
		key.0 = ofset;
		if old_offset > ofset {
			// shift left
			let shift = old_offset - ofset;
			let (s1, s2) = Self::split_shifts(shift);
			let kl = key.1.len();
			(0..kl - 1).for_each(|i| key.1[i] = key.1[i] << s2 | key.1[i+1] >> s1);
			key.1[kl - 1] = key.1[kl - 1] << s2;
			true
		} else if old_offset < ofset {
			// shift right
			let shift = ofset - old_offset;
			let (s1, s2) = Self::split_shifts(shift);
			key.1.push(0);
			(1..key.1.len()).rev().for_each(|i| key.1[i] = key.1[i - 1] << s1 | key.1[i] >> s2);
			key.1[0] = key.1[0] >> s2;
			true
		} else {
			false
		}
	}

}

/// Radix 16 `NibbleOps` definition.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub struct NibbleHalf;

/// Ordered enumeration of the different possible number of nibble in
/// a byte.
#[repr(usize)]
pub enum ByteLayout {
	/// Radix 2 trie. Eight nibble per byte.
	Bit = 0, // 1, 8, 2
	/// Radix 4 trie. Four nibble per byte.
	Quarter = 1, // 2, 4, 4
	/// Radix 16 trie. Two nibble per byte.
	Half = 2, // 4, 2, 16
	/// Radix 256 trie. One nibble per byte.
	Full = 3, // 8, 1, 256
}

impl NibbleOps for NibbleHalf {
	const REPR: ByteLayout = ByteLayout::Half;
	const PADDING_BITMASK: &'static [(u8, usize)] = &[(0xFF, 4), (0x0F, 0)];
	type ChildSliceIndex = ChildSliceIndex16;
}

/// Radix 4 `NibbleOps` definition.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
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
	type ChildSliceIndex = ChildSliceIndex4;
}

/// Owning, nibble-oriented byte vector. Counterpart to `NibbleSlice`.
/// Nibbles are always left aligned, so making a `NibbleVec` from
/// a `NibbleSlice` can get costy.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, PartialEq, Eq)]
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

/// Technical trait only to access child slice from an encoded
/// representation of a branch.
/// This is use instead of `&[&[u8]]` to allow associated type
/// with a constant lenght.
pub trait ChildSliceIndex: AsRef<[usize]>
	+ AsMut<[usize]> + Default + Eq + PartialEq + crate::MaybeDebug
	+ Clone {

	/// Constant length for the number of children.
	const NIBBLE_LENGTH : usize;
	/// Constant size of header
	/// Should only be use for inner implementation.
	const CONTENT_HEADER_SIZE: usize;

	/// Access a children slice at a given index.
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
	/// Iterator over the children slice.
	fn iter<'a>(&'a self, data: &'a [u8]) -> IterChildSliceIndex<'a, Self> {
		IterChildSliceIndex(self, 0, data)
	}
}

/// Iterator over `ChildSliceIndex` trait.
pub struct IterChildSliceIndex<'a, CS>(&'a CS, usize, &'a[u8]);

impl<'a, CS: ChildSliceIndex> Iterator for IterChildSliceIndex<'a, CS> {
	type Item = Option<&'a[u8]>;
	fn next(&mut self) -> Option<Self::Item> {
		if self.1 == CS::NIBBLE_LENGTH {
			return None;
		}
		self.1 += 1;
		Some(self.0.slice_at(self.1 - 1, self.2))
	}
}

macro_rules! child_slice_index {
	($me: ident, $size: expr, $pre: expr) => {
		#[cfg_attr(feature = "std", derive(Debug))]
		#[derive(Default, Eq, PartialEq, Clone)]
		/// Child slice indexes for radix $size.
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

		impl ChildSliceIndex for $me {
			const CONTENT_HEADER_SIZE: usize = $pre;
			const NIBBLE_LENGTH: usize = $size;
		}
	}
}
child_slice_index!(ChildSliceIndex16, 16, 1);
child_slice_index!(ChildSliceIndex4, 4, 1);

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

use crate::node::{NodeKey, NodeHandlePlan};
use crate::rstd::cmp;
use hash_db::MaybeDebug;
use crate::rstd::vec::Vec;
pub use self::leftnibbleslice::LeftNibbleSlice;

mod nibblevec;
mod nibbleslice;
mod leftnibbleslice;

// Work-around absence of constant function for math pow.
const TWO_EXP: [usize; 9] = [1, 2, 4, 8, 16, 32, 64, 128, 256];

/// Ordered enumeration of the different possible number of nibble in
/// a byte.
#[repr(usize)] // TODO EMCH remove repr ??
pub enum ByteLayout { // TODO EMCH rename to Layout
	// TODO EMCH rename to Radix2 (all other variant too)
	/// Radix 2 trie. Eight nibble per byte.
	Bit = 0, // 1, 8, 2
	/// Radix 4 trie. Four nibble per byte.
	Quarter = 1, // 2, 4, 4
	/// Radix 16 trie. Two nibble per byte.
	Half = 2, // 4, 2, 16
	/// Radix 256 trie. One nibble per byte.
	Full = 3, // 8, 1, 256
}

/// This trait contain Trie nibble specific definitions.
/// This trait is mostly a collection of associated constant and some generic
/// methods.
/// Generic methods should not need redefinition except for optimization
/// purpose.
pub trait NibbleOps: Default + Clone + PartialEq + Eq + PartialOrd + Ord + Copy + MaybeDebug {
	/// See [`ByteLayout`].
	const LAYOUT : ByteLayout;
	/// Single nibble length in bit.
	const BIT_PER_NIBBLE : usize = TWO_EXP[Self::LAYOUT as usize];
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
	const PADDING_BITMASK: &'static [(u8, usize)]; // TODO EMCH rewrite to remove this const (does not help readability).
	/// Last nibble index as u8, a convenience constant for iteration on all nibble.
	const LAST_NIBBLE_INDEX: u8 = (Self::NIBBLE_PER_BYTE - 1) as u8;

	/// Buffer type for child slice index array. TODO EMCH this associated type looks useless!! (a
	/// codec thing -> can move ChildSliceIndex to codec code)
	type ChildSliceIndex: ChildSliceIndex;

	/// Pad left aligned representation for a given number of element.
	/// Mask a byte from a `ix` > 0 (ix being content).
	/// Result is a byte containing `ix` nibble of left aligned content and padded with 0.
	#[inline(always)]
	fn pad_left(ix: u8, b: u8) -> u8 {
		debug_assert!(ix > 0); // 0 does not pad anything TODO EMCH allow 0
		b & !Self::PADDING_BITMASK[ix as usize].0
		//b & !(1u8 >> (Self::BIT_PER_NIBBLE * ix)) // TODO EMCH compare perf with that
	}

	/// Pad right aligned representation for a given number of element.
	/// Mask a byte from a ix > 0 (ix being content).
	/// Result is a byte containing `ix` nibble of right aligned content and padded with 0.
	#[inline(always)]
	fn pad_right(ix: u8, b: u8) -> u8 {
		b & !(1u8 << (Self::BIT_PER_NIBBLE * (ix as usize)))
/*		if ix > 0 {
			b & Self::PADDING_BITMASK[Self::NIBBLE_PER_BYTE - ix as usize].0
		} else {
			b
		}*/
	}

	/// Get u8 nibble value at a given index of a byte.
	#[inline(always)]
	fn at_left(ix: u8, b: u8) -> u8 {
		// TODO EMCH compare perf without padding bitmask
		(b & Self::PADDING_BITMASK[ix as usize].0)
			>> Self::PADDING_BITMASK[ix as usize].1
	}

	/// Get u8 nibble value at a given index in a left aligned array.
	#[inline(always)]
	fn left_nibble_at(v1: &[u8], mut ix: usize) -> u8 {
		let pad = ix % Self::NIBBLE_PER_BYTE;
		ix =  ix / Self::NIBBLE_PER_BYTE;
		Self::at_left(pad as u8, v1[ix])
	}

	/// Get u8 nibble value at a given index in a `NibbleSlice`.
	#[inline(always)]
	fn at(s: &NibbleSlice, ix: usize) -> u8 {
		// same as left with offset
		Self::left_nibble_at(&s.data[..], s.offset + ix)
	}

	/// Push u8 nibble value at a given index into an existing byte.
	/// Note that existing value must be null (padded with 0).
	#[inline(always)]
	fn push_at_left(ix: u8, v: u8, into: u8) -> u8 {
		//into | (v << (8 - (BIT_PER_NIBBLE * ix)))
		into | (v << Self::PADDING_BITMASK[ix as usize].1)
	}

	#[inline]
	/// Calculate the number of needed padding for an array of nibble length `i`.
	fn number_padding(i: usize) -> usize {
		(Self::NIBBLE_PER_BYTE - (i % Self::NIBBLE_PER_BYTE)) % Self::NIBBLE_PER_BYTE
	}

	/// Count the biggest common depth between two left aligned packed nibble slice.
	fn biggest_depth(v1: &[u8], v2: &[u8]) -> usize {
		let upper_bound = cmp::min(v1.len(), v2.len());
		for a in 0 .. upper_bound {
			if v1[a] != v2[a] {
				return a * Self::NIBBLE_PER_BYTE + Self::left_common(v1[a], v2[a]);
			}
		}
		upper_bound * Self::NIBBLE_PER_BYTE
	}

	/// Calculate the number of common nibble between two left aligned bytes.
	#[inline(always)]
	fn left_common(a: u8, b: u8) -> usize {
		((a ^ b).leading_zeros() as usize) / Self::BIT_PER_NIBBLE
/*		let mut i = 0;
		while i < Self::NIBBLE_PER_BYTE {
			//if (a >> Self::PADDING_BITMASK[i].1)
			//	!= (b >> Self::PADDING_BITMASK[i].1) {
			let offset = i * Self::BIT_PER_NIBBLE;
			if (a >> offset) != (b >> offset) {
				break;
			}
			i += 1;
		}
		return i;*/
	}

	/// The nibble shifts needed to align.
	/// We use two value, one is a left shift and
	/// the other is a right shift.
	#[inline(always)]
	fn split_shifts(pad: usize) -> (usize, usize) {
		debug_assert!(pad > 0);
		let s1 = Self::PADDING_BITMASK[pad - 1].1;
		let s2 = 8 - s1;
		(s1, s2)
	}

	/// Shifts right aligned key to add a given left offset.
	/// Resulting in possibly padding at both left and right
	/// (used when combining two keys).
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
		((a ^ b).leading_zeros() as usize) / BIT_PER_NIBBLE
		/*if a == b {
			2
		} else if pad_left(a) == pad_left(b) {
			1
		} else {
			0
		}*/
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

/// Radix 16 `NibbleOps` definition.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub struct NibbleHalf; // TODO rename Radix16

impl NibbleOps for NibbleHalf {
	const LAYOUT: ByteLayout = ByteLayout::Half;
	const PADDING_BITMASK: &'static [(u8, usize)] = &[(0xFF, 4), (0x0F, 0)];
	type ChildSliceIndex = ChildSliceIndex16;

	#[inline]
	fn number_padding(i: usize) -> usize {
		i % Self::NIBBLE_PER_BYTE
	}

	#[inline]
	fn split_shifts(pad: usize) -> (usize, usize) {
		debug_assert!(pad > 0);
		(4, 4)
	}
}

/// Radix 4 `NibbleOps` definition.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub struct NibbleQuarter; // TODO rename Radix4

// new_padded_end merged
impl NibbleOps for NibbleQuarter {
	const LAYOUT: ByteLayout = ByteLayout::Quarter;
	const PADDING_BITMASK: &'static [(u8, usize)] = &[
		(0b1111_1111, 6),
		(0b0011_1111, 4),
		(0b0000_1111, 2),
		(0b0000_0011, 0),
	];
	type ChildSliceIndex = ChildSliceIndex4;
}

/// Radix 2 `NibbleOps` definition.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub struct NibbleBit; // TODO rename Radix2

impl NibbleOps for NibbleBit {
	const LAYOUT: ByteLayout = ByteLayout::Bit;
	const PADDING_BITMASK: &'static [(u8, usize)] = &[
		(0b1111_1111, 7),
		(0b0111_1111, 6),
		(0b0011_1111, 5),
		(0b0001_1111, 4),
		(0b0000_1111, 3),
		(0b0000_0111, 2),
		(0b0000_0011, 1),
		(0b0000_0001, 0),
	];
	type ChildSliceIndex = ChildSliceIndex2;
}

/// Radix 256 `NibbleOps` definition.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Default, Clone, PartialEq, Eq, PartialOrd, Ord, Copy)]
pub struct NibbleFull; // TODO rename Radix256

impl NibbleOps for NibbleFull {
	const LAYOUT: ByteLayout = ByteLayout::Full;
	const PADDING_BITMASK: &'static [(u8, usize)] = &[
		(1, 0),
	];
	type ChildSliceIndex = ChildSliceIndex256;

	#[inline]
	fn split_shifts(_pad: usize) -> (usize, usize) {
		unreachable!("pad > 0");
	}

	#[inline]
	fn left_common(_a: u8, _b: u8) -> usize {
		0
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

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Eq, PartialEq, Clone, Copy)]
#[repr(u8)]
/// indicate if the slice is inline or a hash 
pub enum ChildSliceType {
	Inline,
	Hash,
}

impl Default for ChildSliceType {
	fn default() -> Self {
		ChildSliceType::Hash
	}
}

/// Technical trait only to access child slice from an encoded
/// representation of a branch.
/// This is use instead of `&[&[u8]]` to allow associated type
/// with a constant length.
/// TODO EMCH this is probably not a good trait, putting directly
/// AsRef<[NodeHandlePlan]> &AsMut is WAY better.
pub trait ChildSliceIndex: AsRef<[(usize, ChildSliceType)]>
	+ AsMut<[(usize, ChildSliceType)]> + Default + Eq + PartialEq + crate::MaybeDebug
	+ Clone {

	/// Constant length for the number of children.
	const NIBBLE_LENGTH : usize;

	/// Constant size of header for each child index.
	/// This is only needed for default implementation.
	/// TODO EMCH not sure this is really usefull
	const CONTENT_HEADER_SIZE: usize;

	#[inline]
	fn range_at(&self, ix: usize) -> (usize, ChildSliceType, usize) {
		let (start, child_type) = self.as_ref()[ix];
		(start + Self::CONTENT_HEADER_SIZE, child_type, self.as_ref()[ix + 1].0)
	}

	#[inline]
	fn from_node_plan(nodes: impl Iterator<Item = Option<NodeHandlePlan>>) -> Self {
		let mut index = Self::default();
		let mut prev = 0;
		let mut first = true;
		for (i, node) in nodes.enumerate() {
			match node {
				Some(NodeHandlePlan::Hash(range)) => {
					// TODO EMCH awkward: change proto or use simple index
					if first {
						let mut n = range.start;
						for i in (0..i).rev() {
							n -= Self::CONTENT_HEADER_SIZE;
							index.as_mut()[i].0 = n;
						}
					}
					index.as_mut()[i] = (range.start - Self::CONTENT_HEADER_SIZE, ChildSliceType::Hash);
					prev = range.end;
					first = false;
				},
				Some(NodeHandlePlan::Inline(range)) => {
					if first {
						let mut n = range.start;
						for i in (0..i).rev() {
							n -= Self::CONTENT_HEADER_SIZE;
							index.as_mut()[i].0 = n;
						}
					}
					index.as_mut()[i] = (range.start - Self::CONTENT_HEADER_SIZE, ChildSliceType::Inline);
					prev = range.end;
					first = false;
				},
				None => {
					if !first {
						index.as_mut()[i] = (prev, Default::default());
						prev += Self::CONTENT_HEADER_SIZE;
					}
				},
			}
		}
		let len = index.as_ref().len();
		index.as_mut()[len - 1] = (prev, Default::default());
		index
	}

	/// The default implemenatation only works if the encoding of child
	/// slice is the slice value with a fix size header of length
	/// `CONTENT_HEADER_SIZE`.
	fn slice_at<'a>(&self, ix: usize, data: &'a [u8]) -> Option<(&'a[u8], ChildSliceType)> {
		let (s, t, e) = self.range_at(ix);
		if s < e {
			Some((&data[s..e], t))
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
	type Item = Option<(&'a[u8], ChildSliceType)>;
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
		pub struct $me([(usize, ChildSliceType); $size + 1]);

		impl AsRef<[(usize, ChildSliceType)]> for $me {
			fn as_ref(&self) -> &[(usize, ChildSliceType)] {
				&self.0[..]
			}
		}

		impl AsMut<[(usize, ChildSliceType)]> for $me {
			fn as_mut(&mut self) -> &mut [(usize, ChildSliceType)] {
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
child_slice_index!(ChildSliceIndex2, 2, 1);

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Eq, PartialEq, Clone)]
/// Child slice indexes for radix 256.
///
/// TODO EMCH no default impl for array of len 257,
/// but could use bench to see if worth implementing
/// (probably sparse vec implementation is better:
/// need to remove asref and asmut bound).
pub struct ChildSliceIndex256(Vec<(usize, ChildSliceType)>);

impl Default for ChildSliceIndex256 {
	fn default() -> Self {
		ChildSliceIndex256(vec![(0, Default::default()); 257])
	}
}

impl AsRef<[(usize, ChildSliceType)]> for ChildSliceIndex256 {
	fn as_ref(&self) -> &[(usize, ChildSliceType)] {
			&self.0[..]
	}
}

impl AsMut<[(usize, ChildSliceType)]> for ChildSliceIndex256 {
	fn as_mut(&mut self) -> &mut [(usize, ChildSliceType)] {
		&mut self.0[..]
	}
}

impl ChildSliceIndex for ChildSliceIndex256 {
	const CONTENT_HEADER_SIZE: usize = 1;
	const NIBBLE_LENGTH: usize = 256;
}

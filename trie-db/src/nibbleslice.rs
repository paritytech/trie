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
use ::core_::marker::PhantomData;
use nibblevec::NibbleVec;
use elastic_array::ElasticArray36;
use node::NodeKey;
use node_codec::Partial;

pub const EMPTY_ENCODED: (&'static [u8], Option<u8>) = (&[], None);
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
	/// padding value to apply (default to 0)
	const PADDING_VALUE: u8 = 0;
	/// padding bitmasks (could be calculated with a constant function).
	const PADDING_BITMASK: &'static [u8];

	#[inline]
	/// Number of padding needed for a length `i`.
	fn nb_padding(i: usize) -> usize {
		// TODO bench something faster
		(Self::NIBBLE_PER_BYTE - (i % Self::NIBBLE_PER_BYTE)) % Self::NIBBLE_PER_BYTE
	}
	/// Get the nibble at position `i`.
	fn at(&NibbleSlice<Self>, i: usize) -> u8;

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

/// `()` with a conversion to 0
#[derive(Clone, Default, Copy, PartialEq, Eq, Debug)]
pub struct Empty;

impl Into<usize> for Empty {
	fn into(self) -> usize { 0 }
}

// TODO EMCH some method can be fuse with post half (see bug solving: eg new_offset and
// new_padded_end merged
impl NibbleOps for NibblePreHalf {
	const REPR: ByteLayout = ByteLayout::Half; 
	const PADDING_BITMASK: &'static [u8] = &[0x0f];

	#[inline(always)]
	fn at(s: &NibbleSlice<Self>, i: usize) -> u8 {
		if (s.offset + i) & 1 == 1 {
			s.data[(s.offset + i) / Self::NIBBLE_PER_BYTE] & 15u8
		} else {
			s.data[(s.offset + i) / Self::NIBBLE_PER_BYTE] >> 4
		}
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
	pub fn new(data: &'a [u8]) -> Self { NibbleSlice::new_slice(data, 0) }

	/// Create a new nibble slice with the given byte-slice with a nibble offset.
	pub fn new_offset(data: &'a [u8], offset: usize) -> Self {
		Self::new_slice(data, offset)
	}

	fn new_slice(data: &'a [u8], offset: usize) -> Self {
		NibbleSlice {
			data,
			offset,
			marker: PhantomData,
		}
	}

	/// Get an iterator for the series of nibbles.
	pub fn iter(&'a self) -> NibbleSliceIterator<'a, N> {
		NibbleSliceIterator { p: self, i: 0 }
	}
/*
	/// Create a new nibble slice from the given encoded data, applying start padding.
	pub fn from_encoded(data: &[u8], nibble_len: usize) -> NibbleSlice<N> {
		// TODO EMCH better expression or specialization for len
		let start_padding = (N::NIBBLE_PER_BYTE - data.len() % N::NIBBLE_PER_BYTE) % N::NIBBLE_PER_BYTE;
		NibbleSlice::<N>::new_offset(data, start_padding)
	}*/
	/// helper function for getting slice from `NodeKey` stored in nodes
	pub fn from_stored(i: &(usize,ElasticArray36<u8>)) -> NibbleSlice<N> {
		NibbleSlice::<N>::new_offset(&i.1[..], i.0)
	}
	/// helper function to get `NodeKey` stored in nodes
	pub fn to_stored(&self) -> (usize,ElasticArray36<u8>) {
		let split = self.offset / N::NIBBLE_PER_BYTE;
		let offset = N::nb_padding(self.len());
		(offset, self.data[split..].into())
	}

	/// helper function to get `NodeKey` stored in nodes, warning slow
	pub fn to_stored_range(&self, nb: usize) -> (usize,ElasticArray36<u8>) {
		if nb == self.len() { return self.to_stored() }
/* TODO EMCH (commented thing is shit)		if nb % N::NIBBLE_PER_BYTE == 0 {
			let split = self.offset / 2;
			let end	= self.data.len() - (self.len() - (nb / N::NIBBLE_PER_BYTE)); 
			return (self.len(), self.data[split..end].into())
		}*/
		let mut ea = ElasticArray36::new();
		let iter = self.range_iter(nb);
		for i in iter {
			ea.push(i);
		}
 
		(N::nb_padding(nb), ea)
	}

	/// Is this an empty slice?
	pub fn is_empty(&self) -> bool { self.len() == 0 }

	/// Get the length (in nibbles, naturally) of this slice.
	#[inline]
	pub fn len(&self) -> usize { self.data.len() * N::NIBBLE_PER_BYTE - self.offset }

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
			marker: PhantomData,
		}
	}
	/// Return object to an offset position
	pub fn back(&self, i: usize) -> NibbleSlice<'a, N> {
		NibbleSlice {
			data: self.data,
			offset: i,
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

	/// return first encoded byte and following slice
	pub fn right(&'a self) -> (Option<u8>, &'a [u8]) {
		let split = self.offset / 2;
		if self.data.len() % 2 == 1 {
			(Some(self.data[split] & (255 << 4)), &self.data[split + 1 ..])
		} else {
			(None, &self.data[split..])
		}
	}

	/// return left of key nibble
	pub fn left(&'a self) -> (&'a [u8], Option<u8>) {
		let split = self.offset / 2;
		if self.len() % 2 == 1 {
			(&self.data[..split], Some(self.data[split] & (255 >> 4)))
		} else {
			(&self.data[..split], None)
		}
	}

	/// get iterator over slice, slow
	/// TODO switch to padded access as in right padded eg with a move end function that return self
	/// and a padding len
	pub fn range_iter(&'a self, to: usize) -> impl Iterator<Item = u8> + 'a {
		let mut first = to % 2;
		let aligned_i = (self.offset + to) % 2;
		let aligned = aligned_i == 0;
		let mut ix = self.offset / 2;
		let ix_lim = (self.offset + to) / 2;
		::std::iter::from_fn( move || {
			if aligned {
				if first > 0 {
					first = 0;
					ix += 1;
					Some(self.data[ix - 1] & (255 >> 4))
				} else if ix < ix_lim {
					ix += 1;
					Some(self.data[ix - 1])
				} else {
					None
				}
			} else {
				// unaligned
				if first > 0 {
					first = 0;
					Some((self.data[ix] & (255 << 4)) >> 4)
				} else if ix < ix_lim {
					ix += 1;
					let b1 = (self.data[ix - 1] & (255 >> 4)) << 4;
					let b2 = (self.data[ix] & (255 << 4)) >> 4;
					Some(b1 | b2)
				} else {
					None
				}
			}

		})
	}
}

// TODO EMCH not generic (not that partial type does not support nothing else than 4 byte)
impl<'a, N: NibbleOps> Into<NodeKey> for NibbleSlice<'a, N> {
	fn into(self) -> NodeKey {
		(self.offset, self.data.into())
	}
}

// TODO rename or enhanch
pub fn into_part(inp: &NodeKey) -> Partial {
	if inp.0 / 2 == 1 {
		(Some(inp.1[0]),
			&inp.1[1..]) 
	} else {
		(None, &inp.1[..])
	}
}


/*
// TODO EMCH use in prev into fn
impl<'a, N: NibbleOps> Into<(Option<u8>, &'a[u8])> for NibbleSlice<'a, N> {
	fn into(self) -> (Option<u8>, &'a[u8]) {
		if self.len() / 2 == 1 {
			(Some(self.data[self.offset/2] & (255 >> 4)),
				&self.data[self.offset/2 + 1..]) 
		} else {
			(None,
				&self.data[self.offset/2..])
		}
	}
}
*/

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

#[cfg(test)]
mod tests {
	use super::NibbleSlice;
	use super::NibblePreHalf;
	use super::NibbleOps;
	use elastic_array::ElasticArray36;
	static D: &'static [u8;3] = &[0x01u8, 0x23, 0x45];

	#[test]
	fn basics() {
		basics_inner::<NibblePreHalf>();
	}
	fn basics_inner<N: NibbleOps>() {
		let n = NibbleSlice::<N>::new(D);
		assert_eq!(n.len(), 6);
		assert!(!n.is_empty());

		let n = NibbleSlice::<N>::new_offset(D, 6);
		assert!(n.is_empty());

		let n = NibbleSlice::<N>::new_offset(D, 3);
		assert_eq!(n.len(), 3);
		for i in 0..3 {
			assert_eq!(n.at(i), i as u8 + 3);
		}
	}

	#[test]
	fn iterator() {
		iterator_inner::<NibblePreHalf>();
	}
	fn iterator_inner<N: NibbleOps>() {
		let n = NibbleSlice::<N>::new(D);
		let mut nibbles: Vec<u8> = vec![];
		nibbles.extend(n.iter());
		assert_eq!(nibbles, (0u8..6).collect::<Vec<_>>())
	}

	#[test]
	fn mid() {
		mid_inner::<NibblePreHalf>();
	}
	fn mid_inner<N: NibbleOps>() {
		let n = NibbleSlice::<N>::new(D);
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
	fn encoded_pre() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		let len = D.len() * NibblePreHalf::NIBBLE_PER_BYTE;
		assert_eq!(n.to_stored(), (0, ElasticArray36::from_slice(&[0x01, 0x23, 0x45])));
		assert_eq!(n.mid(1).to_stored(), (1, ElasticArray36::from_slice(&[0x01, 0x23, 0x45])));
		assert_eq!(n.mid(2).to_stored(), (0, ElasticArray36::from_slice(&[0x23, 0x45])));
		assert_eq!(n.mid(3).to_stored(), (1, ElasticArray36::from_slice(&[0x23, 0x45])));
	}
/*
	#[test]
	fn encoded_post() {
		let n = NibbleSlice::<NibblePostHalf>::new(D);
		assert_eq!(n.encoded(false), ElasticArray36::from_slice(&[0x01, 0x23, 0x45, 0x00]));
		assert_eq!(n.encoded(true), ElasticArray36::from_slice(&[0x01, 0x23, 0x45, 0x02]));
		assert_eq!(n.mid(1).encoded(false), ElasticArray36::from_slice(&[0x12, 0x34, 0x51]));
		assert_eq!(n.mid(1).encoded(true), ElasticArray36::from_slice(&[0x12, 0x34, 0x53]));
		let n = NibbleSlice::<NibblePostHalf>::from_encoded(&[0x12, 0x34, 0x51]).0; // unaligned end
		assert_eq!(n.encoded(false), ElasticArray36::from_slice(&[0x12, 0x34, 0x51]));
		assert_eq!(n.encoded(true), ElasticArray36::from_slice(&[0x12, 0x34, 0x53]));
		assert_eq!(n.mid(1).encoded(false), ElasticArray36::from_slice(&[0x23, 0x45, 0x00]));
		assert_eq!(n.mid(1).encoded(true), ElasticArray36::from_slice(&[0x23, 0x45, 0x02]));
	}
*/

	#[test]
	fn from_encoded_pre() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		let len = D.len() * NibblePreHalf::NIBBLE_PER_BYTE;
		let stored: ElasticArray36<u8> = [0x01, 0x23, 0x45][..].into();
		assert_eq!(n, NibbleSlice::from_stored(&(0, stored.clone())));
		assert_eq!(n.mid(1), NibbleSlice::from_stored(&(1, stored)));
	}
	#[test]
	fn range_iter() {
		let n = NibbleSlice::<NibblePreHalf>::new(D);
		let len = D.len() * NibblePreHalf::NIBBLE_PER_BYTE;
		for i in [
			vec![],
			vec![0x00],
			vec![0x01],
			vec![0x00, 0x12],
			vec![0x01, 0x23],
			vec![0x00, 0x12, 0x34],
			vec![0x01, 0x23, 0x45],
		].iter().enumerate() {
			range_iter_test(n, i.0, None, &i.1[..]);
		}
		for i in [
			vec![],
			vec![0x01],
			vec![0x12],
			vec![0x01, 0x23],
			vec![0x12, 0x34],
			vec![0x01, 0x23, 0x45],
		].iter().enumerate() {
			range_iter_test(n, i.0, Some(1), &i.1[..]);
		}
		for i in [
			vec![],
			vec![0x02],
			vec![0x23],
			vec![0x02, 0x34],
			vec![0x23, 0x45],
		].iter().enumerate() {
			range_iter_test(n, i.0, Some(2), &i.1[..]);
		}
		for i in [
			vec![],
			vec![0x03],
			vec![0x34],
			vec![0x03, 0x45],
		].iter().enumerate() {
			range_iter_test(n, i.0, Some(3), &i.1[..]);
		}


	}

	fn range_iter_test(n: NibbleSlice<NibblePreHalf>, nb: usize, mid: Option<usize>, res: &[u8]) {
		let n = if let Some(i) = mid {
			n.mid(i)
		} else { n };
		assert_eq!(&n.range_iter(nb).collect::<Vec<_>>()[..], res);
	}

/*	#[test]
	fn from_encoded_post() {
		let n = NibbleSlice::<NibblePostHalf>::new(D);
		assert_eq!((n, false), NibbleSlice::from_encoded(&[0x01, 0x23, 0x45, 0x00]));
		assert_eq!((n, true), NibbleSlice::from_encoded(&[0x01, 0x23, 0x45, 0x02]));
		assert_eq!((n.mid(1), false), NibbleSlice::from_encoded(&[0x12, 0x34, 0x51]));
		assert_eq!((n.mid(1), true), NibbleSlice::from_encoded(&[0x12, 0x34, 0x53]));
	}*/


	#[test]
	fn shared() {
		shared_inner::<NibblePreHalf>();
	}
	fn shared_inner<N: NibbleOps>() {
		let n = NibbleSlice::<N>::new(D);

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
		compare_inner::<NibblePreHalf>();
	}
	fn compare_inner<N: NibbleOps>() {
		let other = &[0x01u8, 0x23, 0x01, 0x23, 0x45];
		let n = NibbleSlice::<N>::new(D);
		let m = NibbleSlice::new(other);

		assert!(n != m);
		assert!(n > m);
		assert!(m < n);

		assert!(n == m.mid(4));
		assert!(n >= m.mid(4));
		assert!(n <= m.mid(4));
	}
}

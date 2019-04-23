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
use hash_db::Prefix;

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
  /// padding bitmasks (could be calculated with a constant function).
  /// First is bit mask to apply, second is right shift needed.
  /// TODO EMCH check that array act as constant
  const PADDING_BITMASK: &'static [(u8, usize)];

  /// Try to get the nibble at the given offset.
	#[inline]
	fn vec_at(s: &NibbleVec<Self>, idx: usize) -> u8 {
    let ix = idx / Self::NIBBLE_PER_BYTE;
    let pad = idx % Self::NIBBLE_PER_BYTE;
		(s.inner[ix] & Self::PADDING_BITMASK[pad].0)
      >> Self::PADDING_BITMASK[pad].1
	}

  /// Get the nibble at position `i`.
	#[inline(always)]
	fn at(s: &NibbleSlice<Self>, i: usize) -> u8 {
    let ix = (s.offset + i) / Self::NIBBLE_PER_BYTE;
    let pad = (s.offset + i) % Self::NIBBLE_PER_BYTE;
		(s.data[ix] & Self::PADDING_BITMASK[pad].0)
      >> Self::PADDING_BITMASK[pad].1
	}

  #[inline]
  /// Number of padding needed for a length `i`.
  fn nb_padding(i: usize) -> usize {
    // TODO bench something faster
    (Self::NIBBLE_PER_BYTE - (i % Self::NIBBLE_PER_BYTE)) % Self::NIBBLE_PER_BYTE
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

/// `()` with a conversion to 0
#[derive(Clone, Default, Copy, PartialEq, Eq, Debug)]
pub struct Empty;

impl Into<usize> for Empty {
  fn into(self) -> usize { 0 }
}

impl NibbleOps for NibbleHalf {
  const REPR: ByteLayout = ByteLayout::Half; 
  const PADDING_BITMASK: &'static [(u8, usize)] = &[(0xFF, 4), (0x0F, 0)];
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
	/// helper function for getting slice from `NodeKey` stored in nodes
	pub fn from_stored(i: &(usize,ElasticArray36<u8>)) -> NibbleSlice<N> {
		NibbleSlice::<N>::new_offset(&i.1[..], i.0)
	}
	/// helper function to get `NodeKey` stored in nodes
	pub fn to_stored(&self) -> NodeKey {
		let split = self.offset / N::NIBBLE_PER_BYTE;
		let offset = N::nb_padding(self.len());
		(offset, self.data[split..].into())
	}

	/// helper function to get `NodeKey` stored in nodes, warning slow
	pub fn to_stored_range(&self, nb: usize) -> NodeKey {
		if nb >= self.len() { return self.to_stored() }
		if (self.offset + nb) % N::NIBBLE_PER_BYTE == 0 {
			// aligned
			let start = self.offset / N::NIBBLE_PER_BYTE;
			let end = self.offset + nb / N::NIBBLE_PER_BYTE;
			(N::nb_padding(nb), ElasticArray36::from_slice(&self.data[start..end]))
		} else {
			let start = self.offset / N::NIBBLE_PER_BYTE;
			let end = (self.offset + nb) / N::NIBBLE_PER_BYTE;
			let ea = ElasticArray36::from_slice(&self.data[start..=end]);
      let n_offset = N::nb_padding(nb);
      if n_offset == 1 {
        let mut result = (0, ea);
        super::triedbmut::shift_key::<N>(&mut result, 1);
        result.1.pop();
        result
      } else {
        let mut result = (1, ea);
        super::triedbmut::shift_key::<N>(&mut result, 0);
        result.1.pop();
        result
      }
		}
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
  /// Advance the view on the slice by `i` nibbles
	pub fn advance(&mut self, i: usize) {
		debug_assert!(self.len() >= i);
    self.offset += i;
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
	pub fn right(&'a self) -> Partial {
		let split = self.offset / 2;
		if self.len() % 2 == 1 {
			(Some(self.data[split] & (255 >> 4)), &self.data[split + 1 ..])
		} else {
			(None, &self.data[split..])
		}
	}

	/// return encoded value as an iterator
	pub fn right_iter(&'a self) -> impl Iterator<Item = u8> + 'a {
		let (mut first, sl) = self.right();
		let mut ix = 0;
		::core_::iter::from_fn( move || {
			if first.is_some() {
				first.take()
			} else {
				if ix < sl.len() {
					ix += 1;
					Some(sl[ix - 1])
				} else {
					None
				}
			}
		})
	}

	/// return left of key nibble
	pub fn left(&'a self) -> Prefix {
		let split = self.offset / 2;
		if self.len() % 2 == 1 {
			(&self.data[..split], Some(self.data[split] & (255 << 4)))
		} else {
			(&self.data[..split], None)
		}
	}
	pub fn left_owned(&'a self) -> (ElasticArray36<u8>, Option<u8>) {
		let (a, b) = self.left();
		(a.into(), b)
	}


	/// get iterator over slice, slow
	pub fn right_range_iter(&'a self, to: usize) -> impl Iterator<Item = u8> + 'a {
		let mut first = to % 2;
		let aligned_i = (self.offset + to) % 2;
		let aligned = aligned_i == 0;
		let mut ix = self.offset / 2;
		let ix_lim = (self.offset + to) / 2;
		::core_::iter::from_fn( move || {
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

// TODO EMCH rename or enhanch + generalize (in NibbleOps) + use in a single place (cast from
// leaf)
pub fn into_part(inp: &NodeKey) -> Partial {
	let start = inp.0 / 2;
	if inp.0 % 2 > 0 {
		(Some(inp.1[start]),
			&inp.1[start + 1..]) 
	} else {
		(None, &inp.1[start..])
	}
}

#[test]
fn into_part_test() {
	let v = [
		((0, [0x12, 0x34][..].into()),
			(None, &vec![0x12, 0x34][..])),
		((1, [0x12, 0x34][..].into()),
			(Some(0x12), &vec![0x34][..])),
		((2, [0x12, 0x34][..].into()),
			(None, &vec![0x34][..])),
		((3, [0x12, 0x34][..].into()),
			(Some(0x34), &vec![][..])),
	];
	for nk in v.iter() {
		assert_eq!(into_part(&nk.0), nk.1);
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
	use super::NibbleHalf;
	use super::NibbleOps;
	use elastic_array::ElasticArray36;
	static D: &'static [u8;3] = &[0x01u8, 0x23, 0x45];

	#[test]
	fn basics() {
		basics_inner::<NibbleHalf>();
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
		iterator_inner::<NibbleHalf>();
	}
	fn iterator_inner<N: NibbleOps>() {
		let n = NibbleSlice::<N>::new(D);
		let mut nibbles: Vec<u8> = vec![];
		nibbles.extend(n.iter());
		assert_eq!(nibbles, (0u8..6).collect::<Vec<_>>())
	}

	#[test]
	fn mid() {
		mid_inner::<NibbleHalf>();
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
		let n = NibbleSlice::<NibbleHalf>::new(D);
		let len = D.len() * NibbleHalf::NIBBLE_PER_BYTE;
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
		let n = NibbleSlice::<NibbleHalf>::new(D);
		let len = D.len() * NibbleHalf::NIBBLE_PER_BYTE;
		let stored: ElasticArray36<u8> = [0x01, 0x23, 0x45][..].into();
		assert_eq!(n, NibbleSlice::from_stored(&(0, stored.clone())));
		assert_eq!(n.mid(1), NibbleSlice::from_stored(&(1, stored)));
	}
	#[test]
	fn range_iter() {
		let n = NibbleSlice::<NibbleHalf>::new(D);
		let len = D.len() * NibbleHalf::NIBBLE_PER_BYTE;
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

	fn range_iter_test(n: NibbleSlice<NibbleHalf>, nb: usize, mid: Option<usize>, res: &[u8]) {
		let n = if let Some(i) = mid {
			n.mid(i)
		} else { n };
		assert_eq!(&n.right_range_iter(nb).collect::<Vec<_>>()[..], res);
	}

	#[test]
	fn shared() {
		shared_inner::<NibbleHalf>();
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
		compare_inner::<NibbleHalf>();
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

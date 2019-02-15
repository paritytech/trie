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

use std::cmp::*;
use std::fmt;
use elastic_array::ElasticArray36;

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
#[derive(Copy, Clone, Eq, Ord)]
pub struct NibbleSlice<'a> {
	data: &'a [u8],
	offset: usize,
	data_encode_suffix: &'a [u8],
	offset_encode_suffix: usize,
}

/// Iterator type for a nibble slice.
pub struct NibbleSliceIterator<'a> {
	p: &'a NibbleSlice<'a>,
	i: usize,
}

impl<'a> Iterator for NibbleSliceIterator<'a> {
	type Item = u8;
	fn next(&mut self) -> Option<u8> {
		self.i += 1;
		match self.i <= self.p.len() {
			true => Some(self.p.at(self.i - 1)),
			false => None,
		}
	}
}

impl<'a> NibbleSlice<'a> {
	/// Create a new nibble slice with the given byte-slice.
	pub fn new(data: &'a [u8]) -> Self { NibbleSlice::new_offset(data, 0) }

	/// Create a new nibble slice with the given byte-slice with a nibble offset.
	pub fn new_offset(data: &'a [u8], offset: usize) -> Self {
		NibbleSlice {
			data,
			offset,
			data_encode_suffix: &b""[..],
			offset_encode_suffix: 0
		}
	}

	/// Create a composed nibble slice; one followed by the other.
	pub fn new_composed(a: &NibbleSlice<'a>, b: &NibbleSlice<'a>) -> Self {
		if a.len() != 0 {
		NibbleSlice {
			data: a.data,
			offset: a.offset,
			data_encode_suffix: b.data,
			offset_encode_suffix: b.offset
		}
		} else {
		NibbleSlice {
			data: b.data,
			offset: b.offset,
			data_encode_suffix: &b""[..],
			offset_encode_suffix: 0
		}
		}
	}

	/// Get an iterator for the series of nibbles.
	pub fn iter(&'a self) -> NibbleSliceIterator<'a> {
		NibbleSliceIterator { p: self, i: 0 }
	}

	/// Create a new nibble slice from the given HPE encoded data (e.g. output of `encoded()`).
	pub fn from_encoded(data: &'a [u8]) -> (NibbleSlice, bool) {
		(Self::new_offset(data, if data[0] & 16 == 16 {1} else {2}), data[0] & 32 == 32)
	}

	/// Is this an empty slice?
	pub fn is_empty(&self) -> bool { self.len() == 0 }

	/// Get the length (in nibbles, naturally) of this slice.
	#[inline]
	pub fn len(&self) -> usize { (self.data.len() + self.data_encode_suffix.len()) * 2 - self.offset - self.offset_encode_suffix }

	/// Get the nibble at position `i`.
	#[inline(always)]
	pub fn at(&self, i: usize) -> u8 {
		let l = self.data.len() * 2 - self.offset;
		if i < l {
			if (self.offset + i) & 1 == 1 {
				self.data[(self.offset + i) / 2] & 15u8
			}
			else {
				self.data[(self.offset + i) / 2] >> 4
			}
		}
		else {
			let i = i - l;
			if (self.offset_encode_suffix + i) & 1 == 1 {
				self.data_encode_suffix[(self.offset_encode_suffix + i) / 2] & 15u8
			}
			else {
				self.data_encode_suffix[(self.offset_encode_suffix + i) / 2] >> 4
			}
		}
	}

	/// Return object which represents a view on to this slice (further) offset by `i` nibbles.
	pub fn mid(&self, i: usize) -> NibbleSlice<'a> {
		NibbleSlice {
			data: self.data,
			offset: self.offset + i,
			data_encode_suffix: &b""[..],
			offset_encode_suffix: 0
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
	#[inline]
	pub fn encoded_old(&self, is_leaf: bool) -> ElasticArray36<u8> {
		let l = self.len();
		let mut r = ElasticArray36::new();
		let mut i = l % 2;
		r.push(if i == 1 {0x10 + self.at(0)} else {0} + if is_leaf {0x20} else {0});
		while i < l {
			r.push(self.at(i) * 16 + self.at(i + 1));
			i += 2;
		}
		r
	}


	/// Encode while nibble slice in prefixed hex notation, noting whether it `is_leaf`.
	/// TODO this is probably brokenfor self.data empty (TODO check that it compose correctly(replace
	/// first by second).
	#[inline]
	pub fn encoded(&self, is_leaf: bool) -> ElasticArray36<u8> {
		let mut dest = ElasticArray36::new();
		let l = self.len();
		let mut i = l % 2;

		dest.push(if i == 1 {
			0x10 + if self.offset % 2 == 1 {
				self.data[self.offset / 2] & 15u8
			} else {
				self.data[self.offset / 2] >> 4
			}
		} else {0} + if is_leaf {0x20} else {0});

		let mut next : u8 = 255;
		if self.data.len() > 0 {
			let i1 = i == 0;
			let i2 = self.offset % 2 == 0;
			if i1 == i2 {
				// aligned
				for i in self.offset / 2 + i..self.data.len() {
					dest.push(self.data[i])
				}
			} else {
				// unaligned
				if self.data.len() > 1 {
					for i in self.offset / 2 + 1..self.data.len() {
						dest.push((self.data[i - 1] << 4) | (self.data[i] >> 4));
					}
				}
				next = self.data[self.data.len()-1] & 15u8;
			}
		}
		if self.data_encode_suffix.len() > 0 {
			let i1 = next > 15;
			let i = if i1 { 0 } else { 1 };
			let i2 = self.offset_encode_suffix % 2 == 0;
			if i1 == i2 {
				if !i2 {
					let a = self.data_encode_suffix[self.offset_encode_suffix / 2];
					dest.push((next << 4) | (self.data_encode_suffix[self.offset_encode_suffix / 2] & 15u8));
				}
				for i in self.offset_encode_suffix / 2 + i..self.data_encode_suffix.len() {
					dest.push(self.data_encode_suffix[i])
				}
			} else {
				if i1 {
					dest.push((next << 4) | (self.data_encode_suffix[0] >> 4));
				}
				if self.data_encode_suffix.len() > 1 {
					for i in self.offset_encode_suffix / 2 + 1..self.data_encode_suffix.len() {
						dest.push((self.data_encode_suffix[i - 1] << 4) | (self.data_encode_suffix[i] >> 4));
					}
				}
			}
		}
		dest
	}

	/// Encode only the leftmost `n` bytes of the nibble slice in prefixed hex notation,
	/// noting whether it `is_leaf`.
	pub fn encoded_leftmost(&self, n: usize, is_leaf: bool) -> ElasticArray36<u8> {
		let l = min(self.len(), n);
		let mut r = ElasticArray36::new();
		let mut i = l % 2;
		r.push(if i == 1 {0x10 + self.at(0)} else {0} + if is_leaf {0x20} else {0});
		while i < l {
			r.push(self.at(i) * 16 + self.at(i + 1));
			i += 2;
		}
		r
	}

}

impl<'a> PartialEq for NibbleSlice<'a> {
	fn eq(&self, them: &Self) -> bool {
		self.len() == them.len() && self.starts_with(them)
	}
}

impl<'a> PartialOrd for NibbleSlice<'a> {
	fn partial_cmp(&self, them: &Self) -> Option<Ordering> {
		let s = min(self.len(), them.len());
		let mut i = 0usize;
		while i < s {
			match self.at(i).partial_cmp(&them.at(i)).unwrap() {
				Ordering::Less => return Some(Ordering::Less),
				Ordering::Greater => return Some(Ordering::Greater),
				_ => i += 1,
			}
		}
		self.len().partial_cmp(&them.len())
	}
}

impl<'a> fmt::Debug for NibbleSlice<'a> {
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
	use elastic_array::ElasticArray36;
	static D: &'static [u8;3] = &[0x01u8, 0x23, 0x45];

	#[test]
	fn basics() {
		let n = NibbleSlice::new(D);
		assert_eq!(n.len(), 6);
		assert!(!n.is_empty());

		let n = NibbleSlice::new_offset(D, 6);
		assert!(n.is_empty());

		let n = NibbleSlice::new_offset(D, 3);
		assert_eq!(n.len(), 3);
		for i in 0..3 {
			assert_eq!(n.at(i), i as u8 + 3);
		}
	}

	#[test]
	fn iterator() {
		let n = NibbleSlice::new(D);
		let mut nibbles: Vec<u8> = vec![];
		nibbles.extend(n.iter());
		assert_eq!(nibbles, (0u8..6).collect::<Vec<_>>())
	}

	#[test]
	fn mid() {
		let n = NibbleSlice::new(D);
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
		let n = NibbleSlice::new(D);
		assert_eq!(n.encoded(false), ElasticArray36::from_slice(&[0x00, 0x01, 0x23, 0x45]));
		assert_eq!(n.encoded(true), ElasticArray36::from_slice(&[0x20, 0x01, 0x23, 0x45]));
		assert_eq!(n.mid(1).encoded(false), ElasticArray36::from_slice(&[0x11, 0x23, 0x45]));
		assert_eq!(n.mid(1).encoded(true), ElasticArray36::from_slice(&[0x31, 0x23, 0x45]));
	}

	#[test]
	fn encoded2() {
		let n = NibbleSlice::new(D);
		assert_eq!(n.encoded(false), ElasticArray36::from_slice(&[0x00, 0x01, 0x23, 0x45]));
		assert_eq!(n.encoded(true), ElasticArray36::from_slice(&[0x20, 0x01, 0x23, 0x45]));
		assert_eq!(n.mid(1).encoded(false), ElasticArray36::from_slice(&[0x11, 0x23, 0x45]));
		assert_eq!(n.mid(1).encoded(true), ElasticArray36::from_slice(&[0x31, 0x23, 0x45]));
		assert_eq!(n.mid(2).encoded(false), ElasticArray36::from_slice(&[0x00, 0x23, 0x45]));
		assert_eq!(n.mid(3).encoded(false), ElasticArray36::from_slice(&[0x13, 0x45]));
		assert_eq!(n.mid(4).encoded(false), ElasticArray36::from_slice(&[0x00, 0x45]));
		assert_eq!(n.mid(5).encoded(false), ElasticArray36::from_slice(&[0x15]));
		assert_eq!(n.mid(6).encoded(false), ElasticArray36::from_slice(&[0x00]));

		let n2 = NibbleSlice::new(&D[..1]);
		assert_eq!(n2.encoded(false), ElasticArray36::from_slice(&[0x00, 0x01]));
		assert_eq!(NibbleSlice::new_composed(&n.mid(4),&n2).encoded(false),
		ElasticArray36::from_slice(&[0x00, 0x45,0x01]));
		assert_eq!(NibbleSlice::new_composed(&n.mid(5),&n2).encoded(false),
		ElasticArray36::from_slice(&[0x15, 0x01]));
		assert_eq!(NibbleSlice::new_composed(&n.mid(4),&n2.mid(1)).encoded(false),
		ElasticArray36::from_slice(&[0x14,0x51]));
		assert_eq!(NibbleSlice::new_composed(&n.mid(5),&n2.mid(1)).encoded(false),
		ElasticArray36::from_slice(&[0x0, 0x51]));
	
	}


	#[test]
	fn from_encoded() {
		let n = NibbleSlice::new(D);
		assert_eq!((n, false), NibbleSlice::from_encoded(&[0x00, 0x01, 0x23, 0x45]));
		assert_eq!((n, true), NibbleSlice::from_encoded(&[0x20, 0x01, 0x23, 0x45]));
		assert_eq!((n.mid(1), false), NibbleSlice::from_encoded(&[0x11, 0x23, 0x45]));
		assert_eq!((n.mid(1), true), NibbleSlice::from_encoded(&[0x31, 0x23, 0x45]));
	}

	#[test]
	fn shared() {
		let n = NibbleSlice::new(D);

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
		let n = NibbleSlice::new(D);
		let m = NibbleSlice::new(other);

		assert!(n != m);
		assert!(n > m);
		assert!(m < n);

		assert!(n == m.mid(4));
		assert!(n >= m.mid(4));
		assert!(n <= m.mid(4));
	}
}

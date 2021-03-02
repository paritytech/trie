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

use crate::rstd::{cmp::*, fmt};
use super::{nibble_ops, NibbleSlice, NibbleSliceIterator, BackingByteVec};
use crate::node::NodeKey;
use crate::node_codec::Partial;
use hash_db::Prefix;

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
	pub fn new(data: &'a [u8]) -> Self { NibbleSlice::new_slice(data, 0) }

	/// Create a new nibble slice with the given byte-slice with a nibble offset.
	pub fn new_offset(data: &'a [u8], offset: usize) -> Self {
		Self::new_slice(data, offset)
	}

	fn new_slice(data: &'a [u8], offset: usize) -> Self {
		NibbleSlice {
			data,
			offset,
		}
	}

	/// Get an iterator for the series of nibbles.
	pub fn iter(&'a self) -> NibbleSliceIterator<'a> {
		NibbleSliceIterator { p: self, i: 0 }
	}

	/// Get nibble slice from a `NodeKey`.
	pub fn from_stored(i: &NodeKey) -> NibbleSlice {
		NibbleSlice::new_offset(&i.1[..], i.0)
	}

	/// Helper function to create a owned `NodeKey` from this `NibbleSlice`.
	pub fn to_stored(&self) -> NodeKey {
		let split = self.offset / nibble_ops::NIBBLE_PER_BYTE;
		let offset = self.offset % nibble_ops::NIBBLE_PER_BYTE;
		(offset, self.data[split..].into())
	}

	/// Helper function to create a owned `NodeKey` from this `NibbleSlice`,
	/// and for a given number of nibble.
	/// Warning this method can be slow (number of nibble does not align the
	/// original padding).
	pub fn to_stored_range(&self, nb: usize) -> NodeKey {
		if nb >= self.len() { return self.to_stored() }
		if (self.offset + nb) % nibble_ops::NIBBLE_PER_BYTE == 0 {
			// aligned
			let start = self.offset / nibble_ops::NIBBLE_PER_BYTE;
			let end = (self.offset + nb) / nibble_ops::NIBBLE_PER_BYTE;
			(
				self.offset % nibble_ops::NIBBLE_PER_BYTE,
				BackingByteVec::from_slice(&self.data[start..end]),
			)
		} else {
			// unaligned
			let start = self.offset / nibble_ops::NIBBLE_PER_BYTE;
			let end = (self.offset + nb) / nibble_ops::NIBBLE_PER_BYTE;
			let ea = BackingByteVec::from_slice(&self.data[start..=end]);
			let ea_offset = self.offset % nibble_ops::NIBBLE_PER_BYTE;
			let n_offset = nibble_ops::number_padding(nb);
			let mut result = (ea_offset, ea);
			nibble_ops::shift_key(&mut result, n_offset);
			result.1.pop();
			result
		}
	}

	/// Return true if the slice contains no nibbles.
	pub fn is_empty(&self) -> bool { self.len() == 0 }

	/// Get the length (in nibbles, naturally) of this slice.
	#[inline]
	pub fn len(&self) -> usize { self.data.len() * nibble_ops::NIBBLE_PER_BYTE - self.offset }

	/// Get the nibble at position `i`.
	#[inline(always)]
	pub fn at(&self, i: usize) -> u8 {
		nibble_ops::at(&self, i)
	}

	/// Return object which represents a view on to this slice (further) offset by `i` nibbles.
	pub fn mid(&self, i: usize) -> NibbleSlice<'a> {
		NibbleSlice {
			data: self.data,
			offset: self.offset + i,
		}
	}

	/// Advance the view on the slice by `i` nibbles.
	pub fn advance(&mut self, i: usize) {
		debug_assert!(self.len() >= i);
		self.offset += i;
	}

	/// Move back to a previously valid fix offset position.
	pub fn back(&self, i: usize) -> NibbleSlice<'a> {
		NibbleSlice {
			data: self.data,
			offset: i,
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

	/// Return `Partial` representation of this slice:
	/// first encoded byte and following slice.
	pub fn right(&'a self) -> Partial {
		let split = self.offset / nibble_ops::NIBBLE_PER_BYTE;
		let nb = (self.len() % nibble_ops::NIBBLE_PER_BYTE) as u8;
		if nb > 0 {
			((nb, nibble_ops::pad_right(self.data[split])), &self.data[split + 1 ..])
		} else {
			((0, 0), &self.data[split..])
		}
	}

	/// Return an iterator over `Partial` bytes representation.
	pub fn right_iter(&'a self) -> impl Iterator<Item = u8> + 'a {
		let (mut first, sl) = self.right();
		let mut ix = 0;
		crate::rstd::iter::from_fn(move || {
			if first.0 > 0 {
				first.0 = 0;
				Some(nibble_ops::pad_right(first.1))
			} else if ix < sl.len() {
				ix += 1;
				Some(sl[ix - 1])
			} else {
				None
			}
		})
	}

	/// Return `Partial` bytes iterator over a range of byte..
	/// Warning can be slow when unaligned (similar to `to_stored_range`).
	pub fn right_range_iter(&'a self, to: usize) -> impl Iterator<Item = u8> + 'a {
		let mut nib_res = to % nibble_ops::NIBBLE_PER_BYTE;
		let aligned_i = (self.offset + to) % nibble_ops::NIBBLE_PER_BYTE;
		let aligned = aligned_i == 0;
		let mut ix = self.offset / nibble_ops::NIBBLE_PER_BYTE;
		let ix_lim = (self.offset + to) / nibble_ops::NIBBLE_PER_BYTE;
		crate::rstd::iter::from_fn( move || {
			if aligned {
				if nib_res > 0 {
					let v = nibble_ops::pad_right(self.data[ix]);
					nib_res = 0;
					ix += 1;
					Some(v)
				} else if ix < ix_lim {
					ix += 1;
					Some(self.data[ix - 1])
				} else {
					None
				}
			} else {
				let (s1, s2) = nibble_ops::SPLIT_SHIFTS;
				// unaligned
				if nib_res > 0 {
					let v = self.data[ix] >> s1;
					let v = nibble_ops::pad_right(v);
					nib_res = 0;
					Some(v)
				} else if ix < ix_lim {
					ix += 1;
					let b1 = self.data[ix - 1] << s2;
					let b2 = self.data[ix] >> s1;
					Some(b1 | b2)
				} else {
					None
				}
			}
		})
	}

	/// Return left portion of `NibbleSlice`, if the slice
	/// originates from a full key it will be the `Prefix of
	/// the node`.
	pub fn left(&'a self) -> Prefix {
		let split = self.offset / nibble_ops::NIBBLE_PER_BYTE;
		let ix = (self.offset % nibble_ops::NIBBLE_PER_BYTE) as u8;
		if ix == 0 {
			(&self.data[..split], None)
		} else {
			(&self.data[..split], Some(nibble_ops::pad_left(self.data[split])))
		}
	}

	/// Owned version of a `Prefix` from a `left` method call.
	pub fn left_owned(&'a self) -> (BackingByteVec, Option<u8>) {
		let (a, b) = self.left();
		(a.into(), b)
	}
}

impl<'a> Into<NodeKey> for NibbleSlice<'a> {
	fn into(self) -> NodeKey {
		(self.offset, self.data.into())
	}
}

impl<'a> PartialEq for NibbleSlice<'a> {
	fn eq(&self, them: &Self) -> bool {
		self.len() == them.len() && self.starts_with(them)
	}
}

impl<'a> Eq for NibbleSlice<'a> { }

impl<'a> PartialOrd for NibbleSlice<'a> {
	fn partial_cmp(&self, them: &Self) -> Option<Ordering> {
		Some(self.cmp(them))
	}
}

impl<'a> Ord for NibbleSlice<'a> {
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

#[cfg(feature = "std")]
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
	use crate::nibble::{NibbleSlice, BackingByteVec};
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
	fn encoded_pre() {
		let n = NibbleSlice::new(D);
		assert_eq!(n.to_stored(), (0, BackingByteVec::from_slice(&[0x01, 0x23, 0x45])));
		assert_eq!(n.mid(1).to_stored(), (1, BackingByteVec::from_slice(&[0x01, 0x23, 0x45])));
		assert_eq!(n.mid(2).to_stored(), (0, BackingByteVec::from_slice(&[0x23, 0x45])));
		assert_eq!(n.mid(3).to_stored(), (1, BackingByteVec::from_slice(&[0x23, 0x45])));
	}

	#[test]
	fn from_encoded_pre() {
		let n = NibbleSlice::new(D);
		let stored: BackingByteVec = [0x01, 0x23, 0x45][..].into();
		assert_eq!(n, NibbleSlice::from_stored(&(0, stored.clone())));
		assert_eq!(n.mid(1), NibbleSlice::from_stored(&(1, stored)));
	}

	#[test]
	fn range_iter() {
		let n = NibbleSlice::new(D);
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

	fn range_iter_test(n: NibbleSlice, nb: usize, mid: Option<usize>, res: &[u8]) {
		let n = if let Some(i) = mid {
			n.mid(i)
		} else { n };
		assert_eq!(&n.right_range_iter(nb).collect::<Vec<_>>()[..], res);
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

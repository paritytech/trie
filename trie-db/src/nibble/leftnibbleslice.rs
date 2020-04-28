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

use crate::rstd::cmp::{self, Ordering};
use crate::rstd::marker::PhantomData;

use crate::nibble::{NibbleOps, NibbleSlice};

/// A representation of a nibble slice which is left-aligned. The regular `NibbleSlice` is
/// right-aligned, meaning it does not support efficient truncation from the right side.
///
/// This is an immutable struct. No operations actually change it.
pub struct LeftNibbleSlice<'a, N> {
	bytes: &'a [u8],
	len: usize,
	_marker: PhantomData<N>,
}

impl<'a, N: NibbleOps> LeftNibbleSlice<'a, N> {
	/// Constructs a byte-aligned nibble slice from a byte slice.
	pub fn new(bytes: &'a [u8]) -> Self {
		LeftNibbleSlice {
			bytes,
			len: bytes.len() * N::NIBBLE_PER_BYTE,
			_marker: PhantomData,
		}
	}

	/// Returns the length of the slice in nibbles.
	pub fn len(&self) -> usize {
		self.len
	}

	/// Get the nibble at a nibble index padding with a 0 nibble. Returns None if the index is
	/// out of bounds.
	pub fn at(&self, index: usize) -> Option<u8> {
		if index < self.len() {
			Some(N::left_nibble_at(self.bytes, index))
		} else {
			None
		}
	}

	/// Returns a new slice truncated from the right side to the given length. If the given length
	/// is greater than that of this slice, the function just returns a copy.
	pub fn truncate(&self, len: usize) -> Self {
		LeftNibbleSlice {
			bytes: self.bytes,
			len: cmp::min(len, self.len),
			_marker: PhantomData,
		}
	}

	/// Returns whether the given slice is a prefix of this one.
	pub fn starts_with(&self, prefix: &LeftNibbleSlice<'a, N>) -> bool {
		self.truncate(prefix.len()) == *prefix
	}

	/// Returns whether another regular (right-aligned) nibble slice is contained in this one at
	/// the given offset.
	pub fn contains(&self, partial: &NibbleSlice<N>, offset: usize) -> bool {
		(0..partial.len()).all(|i| self.at(offset + i) == Some(partial.at(i)))
	}

	fn cmp(&self, other: &Self) -> Ordering {
		let common_len = cmp::min(self.len(), other.len());
		let common_byte_len = common_len / N::NIBBLE_PER_BYTE;

		// Quickly compare the common prefix of the byte slices.
		match self.bytes[..common_byte_len].cmp(&other.bytes[..common_byte_len]) {
			Ordering::Equal => {}
			ordering => return ordering,
		}

		// Compare nibble-by-nibble (either 0 or 1 nibbles) any after the common byte prefix.
		for i in (common_byte_len * N::NIBBLE_PER_BYTE)..common_len {
			let a = self.at(i).expect("i < len; len == self.len() qed");
			let b = other.at(i).expect("i < len; len == other.len(); qed");
			match a.cmp(&b) {
				Ordering::Equal => {}
				ordering => return ordering,
			}
		}

		// If common nibble prefix is the same, finally compare lengths.
		self.len().cmp(&other.len())
	}
}

impl<'a, N: NibbleOps> PartialEq for LeftNibbleSlice<'a, N> {
	fn eq(&self, other: &Self) -> bool {
		let len = self.len();
		if other.len() != len {
			return false;
		}

		// Quickly compare the common prefix of the byte slices.
		let byte_len = len / N::NIBBLE_PER_BYTE;
		if self.bytes[..byte_len] != other.bytes[..byte_len] {
			return false;
		}

		// Compare nibble-by-nibble (either 0 or 1 nibbles) any after the common byte prefix.
		for i in (byte_len * N::NIBBLE_PER_BYTE)..len {
			let a = self.at(i).expect("i < len; len == self.len() qed");
			let b = other.at(i).expect("i < len; len == other.len(); qed");
			if a != b {
				return false
			}
		}

		true
	}
}

impl<'a, N: NibbleOps> Eq for LeftNibbleSlice<'a, N> {}

impl<'a, N: NibbleOps> PartialOrd for LeftNibbleSlice<'a, N> {
	fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
		Some(self.cmp(other))
	}
}

impl<'a, N: NibbleOps> Ord for LeftNibbleSlice<'a, N> {
	fn cmp(&self, other: &Self) -> Ordering {
		self.cmp(other)
	}
}

#[cfg(feature = "std")]
impl<'a, N: NibbleOps> std::fmt::Debug for LeftNibbleSlice<'a, N> {
	fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
		for i in 0..self.len() {
			let nibble = self.at(i).expect("i < self.len(); qed");
			match i {
				0 => write!(f, "{:01x}", nibble)?,
				_ => write!(f, "'{:01x}", nibble)?,
			}
		}
		Ok(())
	}
}

#[cfg(test)]
mod tests {
	use super::*;
	use crate::nibble::Radix16;

	#[test]
	fn test_len() {
		assert_eq!(LeftNibbleSlice::<Radix16>::new(&[]).len(), 0);
		assert_eq!(LeftNibbleSlice::<Radix16>::new(&b"hello"[..]).len(), 10);
		assert_eq!(LeftNibbleSlice::<Radix16>::new(&b"hello"[..]).truncate(7).len(), 7);
	}

	#[test]
	fn test_at() {
		let slice = LeftNibbleSlice::<Radix16>::new(&b"\x01\x23\x45\x67"[..]).truncate(7);
		assert_eq!(slice.at(0), Some(0));
		assert_eq!(slice.at(6), Some(6));
		assert_eq!(slice.at(7), None);
		assert_eq!(slice.at(8), None);
	}

	#[test]
	fn test_starts_with() {
		assert!(
			LeftNibbleSlice::<Radix16>::new(b"hello").starts_with(&LeftNibbleSlice::<Radix16>::new(b"heli").truncate(7))
		);
		assert!(
			!LeftNibbleSlice::<Radix16>::new(b"hello").starts_with(&LeftNibbleSlice::<Radix16>::new(b"heli").truncate(8))
		);
	}

	#[test]
	fn test_contains() {
		assert!(
			LeftNibbleSlice::<Radix16>::new(b"hello").contains(&NibbleSlice::new_offset(b"ello", 0), 2)
		);
		assert!(
			LeftNibbleSlice::<Radix16>::new(b"hello").contains(&NibbleSlice::new_offset(b"ello", 1), 3)
		);
		assert!(
			!LeftNibbleSlice::<Radix16>::new(b"hello").contains(&NibbleSlice::new_offset(b"allo", 1), 3)
		);
		assert!(
			!LeftNibbleSlice::<Radix16>::new(b"hello").contains(&NibbleSlice::new_offset(b"ello!", 1), 3)
		);
	}

	#[test]
	fn test_cmp() {
		assert!(LeftNibbleSlice::<Radix16>::new(b"hallo") < LeftNibbleSlice::<Radix16>::new(b"hello"));
		assert!(LeftNibbleSlice::<Radix16>::new(b"hello") > LeftNibbleSlice::<Radix16>::new(b"hallo"));
		assert_eq!(
			LeftNibbleSlice::<Radix16>::new(b"hello").cmp(&LeftNibbleSlice::<Radix16>::new(b"hello")),
			Ordering::Equal
		);

		assert!(
			LeftNibbleSlice::<Radix16>::new(b"hello\x10")
				< LeftNibbleSlice::<Radix16>::new(b"hello\x20").truncate(11)
		);
		assert!(
			LeftNibbleSlice::<Radix16>::new(b"hello\x20").truncate(11)
				> LeftNibbleSlice::<Radix16>::new(b"hello\x10")
		);

		assert!(
			LeftNibbleSlice::<Radix16>::new(b"hello\x10").truncate(11)
				< LeftNibbleSlice::<Radix16>::new(b"hello\x10")
		);
		assert!(
			LeftNibbleSlice::<Radix16>::new(b"hello\x10")
				> LeftNibbleSlice::<Radix16>::new(b"hello\x10").truncate(11)
		);
		assert_eq!(
			LeftNibbleSlice::<Radix16>::new(b"hello\x10").truncate(11)
				.cmp(&LeftNibbleSlice::<Radix16>::new(b"hello\x10").truncate(11)),
			Ordering::Equal
		);
	}
}

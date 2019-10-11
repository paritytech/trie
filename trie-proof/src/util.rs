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

use trie_db::{NibbleSlice, nibble_ops::{self, NIBBLE_PER_BYTE}};

use crate::std::{fmt, cmp::{self, Ordering}};

/// A representation of a nibble slice which is left-aligned. The regular `trie_db::NibbleSlice` is
/// right-aligned meaning it does not support efficient truncation from the right side.
pub struct LeftAlignedNibbleSlice<'a> {
    bytes: &'a [u8],
    len: usize,
}

impl<'a> LeftAlignedNibbleSlice<'a> {
    pub fn new(bytes: &'a [u8]) -> Self {
        LeftAlignedNibbleSlice {
            bytes,
            len: bytes.len() * NIBBLE_PER_BYTE,
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
            Some(nibble_ops::left_nibble_at(self.bytes, index))
        } else {
            None
        }
    }

    /// Returns a new slice truncated from the right side to the given length. If the given length
    /// is greater than that of this slice, the function just returns a copy.
    pub fn truncate(&self, len: usize) -> Self {
        LeftAlignedNibbleSlice {
            bytes: self.bytes,
            len: cmp::min(len, self.len),
        }
    }

    /// Returns whether the given slice is a prefix of this one.
    pub fn starts_with(&self, prefix: &LeftAlignedNibbleSlice<'a>) -> bool {
        self.truncate(prefix.len()) == *prefix
    }

    /// Returns whether another regular (right-aligned) nibble slice is contained in this one at
    /// the given offset.
    pub fn contains(&self, partial: NibbleSlice, offset: usize) -> bool {
        (0..partial.len()).all(|i| self.at(offset + i) == Some(partial.at(i)))
    }
}

impl<'a> PartialEq for LeftAlignedNibbleSlice<'a> {
    fn eq(&self, other: &Self) -> bool {
        let len = self.len();
        if other.len() != len {
            return false;
        }

        // Quickly compare the common prefix of the byte slices.
        let byte_len = len / NIBBLE_PER_BYTE;
        if self.bytes[..byte_len] != other.bytes[..byte_len] {
            return false;
        }

        // Compare nibble-by-nibble (either 0 or 1 nibbles) any after the common byte prefix.
        for i in (byte_len * NIBBLE_PER_BYTE)..len {
            let a = self.at(i).expect("i < len; len == self.len() qed");
            let b = other.at(i).expect("i < len; len == other.len(); qed");
            if a != b {
                return false
            }
        }

        true
    }
}

impl<'a> Eq for LeftAlignedNibbleSlice<'a> {}

#[cfg(feature = "std")]
impl<'a> fmt::Debug for LeftAlignedNibbleSlice<'a> {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
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

/// A comparator function for keys in post-order traversal order in a trie. This is similar to
/// the regular lexographic order except that if one byte slice is a prefix of another, the longer
/// one comes first in the ordering.
pub fn post_order_compare(a: &[u8], b: &[u8]) -> Ordering {
    let common_len = cmp::min(a.len(), b.len());
    match a[..common_len].cmp(&b[..common_len]) {
        // If one is a prefix of the other, the longer string is lesser.
        Ordering::Equal => b.len().cmp(&a.len()),
        ordering => ordering,
    }
}

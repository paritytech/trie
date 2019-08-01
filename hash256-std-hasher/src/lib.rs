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

#![cfg_attr(not(feature = "std"), no_std)]

#[macro_use]
extern crate crunchy;

#[cfg(feature = "std")]
use std::hash;

#[cfg(not(feature = "std"))]
use core::hash;

/// Hasher that just takes 8 bytes of the provided value.
/// May only be used for keys which are 32 bytes.
#[derive(Default)]
pub struct Hash256StdHasher {
	prefix: u64,
}

impl hash::Hasher for Hash256StdHasher {
	#[inline]
	fn finish(&self) -> u64 {
		self.prefix
	}

	#[inline]
	#[allow(unused_assignments)]
	fn write(&mut self, bytes: &[u8]) {
		// we get a length written first as 8 bytes (possibly 4 on 32-bit platforms?). this
		// keeps it safe.
		debug_assert!(bytes.len() == 4 || bytes.len() == 8 || bytes.len() == 32);
		if bytes.len() < 32 { return }

		let mut bytes_ptr = bytes.as_ptr();
		let mut prefix_ptr = &mut self.prefix as *mut u64 as *mut u8;

		unroll! {
			for _i in 0..8 {
				unsafe {
					*prefix_ptr ^= (*bytes_ptr ^ *bytes_ptr.offset(8)) ^ (*bytes_ptr.offset(16) ^ *bytes_ptr.offset(24));
					bytes_ptr = bytes_ptr.offset(1);
					prefix_ptr = prefix_ptr.offset(1);
				}
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use hash::Hasher;
	use super::Hash256StdHasher;

	#[test]
	fn it_works() {
		let mut bytes = [32u8; 32];
		bytes[0] = 15;
		let mut hasher = Hash256StdHasher::default();
		hasher.write(&bytes);
		assert_eq!(hasher.prefix, 47);
	}
}

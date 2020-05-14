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

//! Hasher implementation for the Keccak-256 hash

use hash_db::{Hasher, BinaryHasher};
//use hash_db::FixHash;
use tiny_keccak::Keccak;
use hash256_std_hasher::Hash256StdHasher;

/// Concrete `Hasher` impl for the Keccak-256 hash
#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeccakHasher;
impl Hasher for KeccakHasher {
	type Out = [u8; 32];

	type StdHasher = Hash256StdHasher;

	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		let mut out = [0u8; 32];
		Keccak::keccak256(x, &mut out);
		out
	}
}

impl BinaryHasher for KeccakHasher {
	const NULL_HASH: &'static [u8] = &[197, 210, 70, 1, 134, 247, 35, 60, 146,
		126, 125, 178, 220, 199, 3, 192, 229, 0, 182, 83, 202, 130, 39, 59, 123,
		250, 216, 4, 93, 133, 164, 112];
	type Buffer = Keccak;

	fn init_buffer() -> Self::Buffer {
		Keccak::new_keccak256()
	}

	fn reset_buffer(buff: &mut Self::Buffer) {
		let _ = core::mem::replace(buff, Self::init_buffer());
	}

	fn buffer_hash(buff: &mut Self::Buffer, x: &[u8]) {
		buff.update(&x[..])
	}

	fn buffer_finalize(buff: &mut Self::Buffer) -> Self::Out {
		let mut res: [u8; 32] = [0; 32];
		let k = core::mem::replace(buff, Self::init_buffer());
		k.finalize(&mut res);
		res
	}
}

#[test]
fn test_keccack_hasher() {
	hash_db::test_binary_hasher::<KeccakHasher>()
}

#[cfg(test)]
mod tests {
	use super::*;
	use std::collections::HashMap;

	#[test]
	fn hash256_std_hasher_works() {
		let hello_bytes = b"Hello world!";
		let hello_key = KeccakHasher::hash(hello_bytes);

		let mut h: HashMap<<KeccakHasher as Hasher>::Out, Vec<u8>> = Default::default();
		h.insert(hello_key, hello_bytes.to_vec());
		h.remove(&hello_key);

		let mut h: HashMap<<KeccakHasher as Hasher>::Out, Vec<u8>, std::hash::BuildHasherDefault<Hash256StdHasher>> = Default::default();
		h.insert(hello_key, hello_bytes.to_vec());
		h.remove(&hello_key);
	}
}

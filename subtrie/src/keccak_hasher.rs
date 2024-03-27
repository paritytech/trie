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

use crate::node_db::Hasher;
use hash256_std_hasher::Hash256StdHasher;
use tiny_keccak::{Hasher as _, Keccak};

/// The `Keccak` hash output type.
pub type KeccakHash = [u8; 32];

/// Concrete `Hasher` impl for the Keccak-256 hash
#[derive(Default, Debug, Clone, PartialEq)]
pub struct KeccakHasher;
impl Hasher for KeccakHasher {
	type Out = KeccakHash;

	type StdHasher = Hash256StdHasher;

	const LENGTH: usize = 32;

	fn hash(x: &[u8]) -> Self::Out {
		let mut keccak = Keccak::v256();
		keccak.update(x);
		let mut out = [0u8; 32];
		keccak.finalize(&mut out);
		out
	}
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

		let mut h: HashMap<
			<KeccakHasher as Hasher>::Out,
			Vec<u8>,
			std::hash::BuildHasherDefault<Hash256StdHasher>,
		> = Default::default();
		h.insert(hello_key, hello_bytes.to_vec());
		h.remove(&hello_key);
	}
}

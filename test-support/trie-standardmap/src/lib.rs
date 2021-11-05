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

//! Key-value datastore with a modified Merkle tree.

use hash_db::Hasher;
use keccak_hasher::KeccakHasher;

type H256 = <KeccakHasher as hash_db::Hasher>::Out;

/// Alphabet to use when creating words for insertion into tries.
pub enum Alphabet {
	/// All values are allowed in each bytes of the key.
	All,
	/// Only a 6 values ('a' - 'f') are chosen to compose the key.
	Low,
	/// Quite a few values (around 32) are chosen to compose the key.
	Mid,
	/// A set of bytes given is used to compose the key.
	Custom(Vec<u8>),
}

/// Means of determining the value.
pub enum ValueMode {
	/// Same as the key.
	Mirror,
	/// Randomly (50:50) 1 or 32 byte randomly string.
	Random,
	/// RLP-encoded index.
	Index,
}

/// Standard test map for profiling tries.
pub struct StandardMap {
	/// The alphabet to use for keys.
	pub alphabet: Alphabet,
	/// Minimum size of key.
	pub min_key: usize,
	/// Delta size of key.
	pub journal_key: usize,
	/// Mode of value generation.
	pub value_mode: ValueMode,
	/// Number of keys.
	pub count: u32,
}

impl StandardMap {
	/// Get a bunch of random bytes, at least `min_count` bytes, at most `min_count` +
	/// `journal_count` bytes. `seed` is mutated pseudoramdonly and used.
	fn random_bytes(min_count: usize, journal_count: usize, seed: &mut H256) -> Vec<u8> {
		assert!(min_count + journal_count <= 32);
		*seed = KeccakHasher::hash(&seed[..]);
		let r = min_count + (seed[31] as usize % (journal_count + 1));
		seed[0..r].to_vec()
	}

	/// Get a random value. Equal chance of being 1 byte as of 32. `seed` is mutated pseudoramdonly
	/// and used.
	fn random_value(seed: &mut H256) -> Vec<u8> {
		*seed = KeccakHasher::hash(&seed[..]);
		match seed[0] % 2 {
			1 => vec![seed[31]; 1],
			_ => seed.to_vec(),
		}
	}

	/// Get a random word of, at least `min_count` bytes, at most `min_count` + `journal_count`
	/// bytes. Each byte is an item from `alphabet`. `seed` is mutated pseudoramdonly and used.
	fn random_word(
		alphabet: &[u8],
		min_count: usize,
		journal_count: usize,
		seed: &mut H256,
	) -> Vec<u8> {
		assert!(min_count + journal_count <= 32);
		*seed = KeccakHasher::hash(&seed[..]);
		let r = min_count + (seed[31] as usize % (journal_count + 1));
		let mut ret: Vec<u8> = Vec::with_capacity(r);
		for i in 0..r {
			ret.push(alphabet[seed[i] as usize % alphabet.len()]);
		}
		ret
	}

	/// Create the standard map (set of keys and values) for the object's fields.
	pub fn make(&self) -> Vec<(Vec<u8>, Vec<u8>)> {
		self.make_with(&mut H256::default())
	}

	/// Create the standard map (set of keys and values) for the object's fields, using the given
	/// seed.
	pub fn make_with(&self, seed: &mut H256) -> Vec<(Vec<u8>, Vec<u8>)> {
		let low = b"abcdef";
		let mid = b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_";

		let mut d: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
		for index in 0..self.count {
			let k = match self.alphabet {
				Alphabet::All => Self::random_bytes(self.min_key, self.journal_key, seed),
				Alphabet::Low => Self::random_word(low, self.min_key, self.journal_key, seed),
				Alphabet::Mid => Self::random_word(mid, self.min_key, self.journal_key, seed),
				Alphabet::Custom(ref a) =>
					Self::random_word(a, self.min_key, self.journal_key, seed),
			};
			let v = match self.value_mode {
				ValueMode::Mirror => k.clone(),
				ValueMode::Random => Self::random_value(seed),
				ValueMode::Index =>
					vec![index as u8, (index >> 8) as u8, (index >> 16) as u8, (index >> 24) as u8],
			};
			d.push((k, v))
		}
		d
	}
}

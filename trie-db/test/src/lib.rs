// Copyright 2020 Parity Technologies
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

//! Tests for trie-db crate.

#[cfg(test)]
mod fatdb;
#[cfg(test)]
mod fatdbmut;
pub mod fuzz;
#[cfg(test)]
mod iter_build;
#[cfg(test)]
mod iterator;
#[cfg(test)]
mod proof;
mod query_plan;
#[cfg(test)]
mod recorder;
#[cfg(test)]
mod sectriedb;
#[cfg(test)]
mod sectriedbmut;
#[cfg(test)]
mod trie_codec;
#[cfg(test)]
mod triedb;
#[cfg(test)]
mod triedbmut;

use trie_db::{DBValue, TrieLayout};

/// Testing memory db type.
pub type MemoryDB<T> = memory_db::MemoryDB<
	<T as TrieLayout>::Hash,
	memory_db::HashKey<<T as TrieLayout>::Hash>,
	DBValue,
>;

/// Set of entries for base testing.
pub fn test_entries() -> Vec<(&'static [u8], &'static [u8])> {
	vec![
		// "alfa" is at a hash-referenced leaf node.
		(b"alfa", &[0; 32]),
		// "bravo" is at an inline leaf node.
		(b"bravo", b"bravo"),
		// "do" is at a hash-referenced branch node.
		(b"do", b"verb"),
		// "dog" is at a hash-referenced branch node.
		(b"dog", b"puppy"),
		// "doge" is at a hash-referenced leaf node.
		(b"doge", &[0; 32]),
		// extension node "o" (plus nibble) to next branch.
		(b"horse", b"stallion"),
		(b"house", b"building"),
	]
}

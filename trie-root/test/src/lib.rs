// Copyright 2017, 2020 Parity Technologies
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

//! Test for trie-root crate.

#[cfg(test)]
mod test {
	use hex_literal::hex;
	use trie_root::{sec_trie_root, trie_root};
	use keccak_hasher::KeccakHasher;
	use reference_trie::ReferenceTrieStream;

	#[test]
	fn previous_doc_test_1() {
		let v = vec![
			("doe", "reindeer"),
			("dog", "puppy"),
			("dogglesworth", "cat"),
		];

		let root = hex!["d6e02b2bd48aa04fd2ad87cfac1144a29ca7f7dc60f4526c7b7040763abe3d43"];
		assert_eq!(sec_trie_root::<KeccakHasher, ReferenceTrieStream, _, _, _>(v), root);
	}

	#[test]
	fn previous_doc_test_2() {
		let v = vec![
				("doe", "reindeer"),
				("dog", "puppy"),
				("dogglesworth", "cat"),
		];

		let root = hex!["0807d5393ae7f349481063ebb5dbaf6bda58db282a385ca97f37dccba717cb79"];
		assert_eq!(trie_root::<KeccakHasher, ReferenceTrieStream, _, _, _>(v), root);
	}
}

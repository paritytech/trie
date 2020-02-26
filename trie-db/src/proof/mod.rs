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

//! Generation and verification of compact proofs for Merkle-Patricia tries.
//!
//! Using this module, it is possible to generate a logarithmic-space proof of inclusion or
//! non-inclusion of certain key-value pairs in a trie with a known root. The proof contains
//! information so that the verifier can reconstruct the subset of nodes in the trie required to
//! lookup the keys. The trie nodes are not included in their entirety as data which the verifier
//! can compute for themself is omitted. In particular, the values of included keys and and hashes
//! of other trie nodes in the proof are omitted.
//!
//! The proof is a sequence of the subset of nodes in the trie traversed while performing lookups
//! on all keys. The trie nodes are listed in pre-order traversal order with some values and
//! internal hashes omitted. In particular, values on leaf nodes, child references on extension
//! nodes, values on branch nodes corresponding to a key in the statement, and child references on
//! branch nodes corresponding to another node in the proof are all omitted. The proof is verified
//! by iteratively reconstructing the trie nodes using the values proving as part of the statement
//! and the hashes of other reconstructed nodes. Since the nodes in the proof are arranged in
//! pre-order traversal order, the construction can be done efficiently using a stack.

pub use self::generate::generate_proof;
pub use self::verify::{Error as VerifyError, verify_proof};

mod generate;
mod verify;

#[cfg(test)]
mod tests {
	use hash_db::Hasher;
	use reference_trie::{
		ExtensionLayout, NoExtensionLayout,
		proof::{generate_proof, verify_proof, VerifyError}, Trie, TrieDB, TrieDBMut, TrieLayout,
		TrieMut,
	};

	use crate::DBValue;

	type MemoryDB<H> = memory_db::MemoryDB<H, memory_db::HashKey<H>, DBValue>;

	fn test_entries() -> Vec<(&'static [u8], &'static [u8])> {
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

	fn test_generate_proof<L: TrieLayout>(
		entries: Vec<(&'static [u8], &'static [u8])>,
		keys: Vec<&'static [u8]>,
	) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(&'static [u8], Option<DBValue>)>)
	{
		// Populate DB with full trie from entries.
		let (db, root) = {
			let mut db = <MemoryDB<L::Hash>>::default();
			let mut root = Default::default();
			{
				let mut trie = <TrieDBMut<L>>::new(&mut db, &mut root);
				for (key, value) in entries.iter() {
					trie.insert(key, value).unwrap();
				}
			}
			(db, root)
		};

		// Generate proof for the given keys..
		let trie = <TrieDB<L>>::new(&db, &root).unwrap();
		let proof = generate_proof::<_, L, _, _>(&trie, keys.iter()).unwrap();
		let items = keys.into_iter()
			.map(|key| (key, trie.get(key).unwrap()))
			.collect();

		(root, proof, items)
	}

	#[test]
	fn trie_proof_works_with_ext() {
		let (root, proof, items) = test_generate_proof::<ExtensionLayout>(
			test_entries(),
			vec![
				b"do",
				b"dog",
				b"doge",
				b"bravo",
				b"alfabet", // None, not found under leaf node
				b"d", // None, witness is extension node with omitted child
				b"do\x10", // None, empty branch child
				b"halp", // None, witness is extension node with non-omitted child
			],
		);

		verify_proof::<ExtensionLayout, _, _, _>(&root, &proof, items.iter()).unwrap();
	}

	#[test]
	fn trie_proof_works_without_ext() {
		let (root, proof, items) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![
				b"do",
				b"dog",
				b"doge",
				b"bravo",
				b"alfabet", // None, not found under leaf node
				b"d", // None, witness is extension node with omitted child
				b"do\x10", // None, empty branch child
				b"halp", // None, witness is extension node with non-omitted child
			],
		);

		verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()).unwrap();
	}

	#[test]
	fn trie_proof_works_for_empty_trie() {
		let (root, proof, items) = test_generate_proof::<NoExtensionLayout>(
			vec![],
			vec![
				b"alpha",
				b"bravo",
				b"\x42\x42",
			],
		);

		verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()).unwrap();
	}

	#[test]
	fn test_verify_duplicate_keys() {
		let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"bravo"],
		);

		let items = vec![
			(b"bravo", Some(b"bravo")),
			(b"bravo", Some(b"bravo")),
		];
		assert_eq!(
			verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()),
			Err(VerifyError::DuplicateKey(b"bravo".to_vec()))
		);
	}

	#[test]
	fn test_verify_extraneous_node() {
		let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"bravo", b"do"],
		);

		let items = vec![
			(b"bravo", Some(b"bravo")),
		];
		assert_eq!(
			verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()),
			Err(VerifyError::ExtraneousNode)
		);
	}

	#[test]
	fn test_verify_extraneous_value() {
		let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"doge"],
		);

		let items = vec![
			(&b"do"[..], Some(&b"verb"[..])),
			(&b"doge"[..], Some(&[0; 32][..])),
		];
		assert_eq!(
			verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()),
			Err(VerifyError::ExtraneousValue(b"do".to_vec()))
		);
	}

	// #[test] TODO this does not work for complex hash, restore
	// when two test case.
	// Reason it does not work is that the hash not in root are
	// skipped so there is no extranous hash, error could be better
	// still, but produce in advance children
	fn test_verify_extraneous_hash_reference() {
		let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"do"],
		);

		let items = vec![
			(&b"alfa"[..], Some(&[0; 32][..])),
			(&b"do"[..], Some(&b"verb"[..])),
		];
		match verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()) {
			Err(VerifyError::ExtraneousHashReference(_)) => {}
			result => panic!("expected VerifyError::ExtraneousHashReference, got {:?}", result),
		}
	}

	#[test]
	fn test_verify_invalid_child_reference() {
		let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"bravo"],
		);

		// InvalidChildReference because "bravo" is in an inline leaf node and a 32-byte value cannot
		// fit in an inline leaf.
		let items = vec![
			(b"bravo", Some([0; 32])),
		];
		match verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()) {
			Err(VerifyError::InvalidChildReference(_)) => {}
			result => panic!("expected VerifyError::InvalidChildReference, got {:?}", result),
		}
	}

	#[test]
	fn test_verify_value_mismatch_some_to_none() {
		let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"horse"],
		);

		let items = vec![
			(&b"horse"[..], Some(&b"stallion"[..])),
			(&b"halp"[..], Some(&b"plz"[..])),
		];
		assert_eq!(
			verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()),
			Err(VerifyError::ValueMismatch(b"halp".to_vec()))
		);
	}

	#[test]
	fn test_verify_value_mismatch_none_to_some() {
		let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"alfa", b"bravo"],
		);

		let items = vec![
			(&b"alfa"[..], Some(&[0; 32][..])),
			(&b"bravo"[..], None),
		];
		assert_eq!(
			verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()),
			Err(VerifyError::ValueMismatch(b"bravo".to_vec()))
		);
	}

	#[test]
	fn test_verify_incomplete_proof() {
		let (root, mut proof, items) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"alfa"],
		);

		proof.pop();
		assert_eq!(
			verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()),
			Err(VerifyError::IncompleteProof)
		);
	}

	#[test]
	fn test_verify_root_mismatch() {
		let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"bravo"],
		);

		let items = vec![
			(b"bravo", Some("incorrect")),
		];
		match verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()) {
			Err(VerifyError::RootMismatch(_)) => {}
			result => panic!("expected VerifyError::RootMismatch, got {:?}", result),
		}
	}

	#[test]
	fn test_verify_decode_error() {
		let (root, mut proof, items) = test_generate_proof::<NoExtensionLayout>(
			test_entries(),
			vec![b"bravo"],
		);

		proof.insert(0, b"this is not a trie node".to_vec());
		match verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()) {
			Err(VerifyError::DecodeError(_)) => {}
			result => panic!("expected VerifyError::DecodeError, got {:?}", result),
		}
	}
}

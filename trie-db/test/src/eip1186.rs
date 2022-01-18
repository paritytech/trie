// Copyright 2019, 2020 Parity Technologies
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

use hash_db::Hasher;
use reference_trie::test_layouts;

use trie_db::{
	proof::eip1186::{generate_proof, verify_proof, VerifyError},
	DBValue, TrieDB, TrieDBMut, TrieLayout, TrieMut,
};

type MemoryDB<T> = memory_db::MemoryDB<
	<T as TrieLayout>::Hash,
	memory_db::HashKey<<T as TrieLayout>::Hash>,
	DBValue,
>;

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
	key: &[u8],
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Option<Vec<u8>>) {
	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L>>::default();
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
	let proof = generate_proof::<_, L>(&trie, key).unwrap();
	(root, proof.0, proof.1)
}

test_layouts!(trie_proof_works2, trie_proof_works_internal2);
fn trie_proof_works_internal2<T: TrieLayout>() {
	let (root, proof, item) = test_generate_proof::<T>(
		vec![
			// "do" is at a hash-referenced branch node.
			(b"do", b"verb"),
			// "dog" is at a hash-referenced branch node.
			(b"dog", b"puppy"),
		],
		b"do",
	);
	assert_eq!(Some(b"verb".as_ref()), item.as_deref(), "verb is the item");
	assert!(verify_proof::<T>(&root, &proof, b"do", Some(b"verb")).is_ok(), "verifying do");

	let (root, proof, item) = test_generate_proof::<T>(
		vec![
			// "do" is at a hash-referenced branch node.
			(b"do", b"verb"),
			// "dog" is at a hash-referenced branch node.
			(b"dog", b"puppy"),
		],
		b"dog",
	);
	assert_eq!(Some(b"puppy".as_ref()), item.as_deref(), "puppy is the item");
	assert!(verify_proof::<T>(&root, &proof, b"dog", Some(b"puppy")).is_ok(), "verifying dog");
}

test_layouts!(trie_proof_works, trie_proof_works_internal);
fn trie_proof_works_internal<T: TrieLayout>() {
	let (root, proof, item) = test_generate_proof::<T>(test_entries(), b"do");
	assert_eq!(Some(b"verb".as_ref()), item.as_deref(), "verb is the item");
	assert!(verify_proof::<T>(&root, &proof, b"do", Some(b"verb")).is_ok(), "verifying do");

	let (root, proof, item) = test_generate_proof::<T>(test_entries(), b"dog");
	assert_eq!(Some(b"puppy".as_ref()), item.as_deref(), "puppy is the item");
	assert!(verify_proof::<T>(&root, &proof, b"dog", Some(b"puppy")).is_ok(), "verifying dog");

	let (root, proof, item) = test_generate_proof::<T>(test_entries(), b"doge");
	assert_eq!(Some([0; 32].as_ref()), item.as_deref(), "[0;32] is the item");
	assert!(verify_proof::<T>(&root, &proof, b"doge", Some(&[0; 32])).is_ok(), "verifying doge");

	let (root, proof, item) = test_generate_proof::<T>(test_entries(), b"bravo");
	assert_eq!(Some(b"bravo".as_ref()), item.as_deref(), "bravo is the item");
	assert!(verify_proof::<T>(&root, &proof, b"bravo", Some(b"bravo")).is_ok(), "verifying bravo");

	let (root, proof, item) = test_generate_proof::<T>(test_entries(), b"alfabet");
	assert!(item.is_none(), "item not found");
	assert!(verify_proof::<T>(&root, &proof, b"alfabet", None).is_ok(), "verifying alfabet");

	let (root, proof, item) = test_generate_proof::<T>(test_entries(), b"d");
	assert!(item.is_none(), "item not found");
	assert!(verify_proof::<T>(&root, &proof, b"d", None).is_ok(), "verifying d");

	let (root, proof, item) = test_generate_proof::<T>(test_entries(), b"do\x10");
	assert!(item.is_none(), "item not found");
	assert!(verify_proof::<T>(&root, &proof, b"do\x10", None).is_ok(), "verifying do\x10");

	let (root, proof, item) = test_generate_proof::<T>(test_entries(), b"halp");
	assert!(item.is_none(), "item not found");
	assert!(verify_proof::<T>(&root, &proof, b"halp", None).is_ok(), "verifying halp");
}

test_layouts!(trie_proof_works_for_empty_trie, trie_proof_works_for_empty_trie_internal);
fn trie_proof_works_for_empty_trie_internal<T: TrieLayout>() {
	let (root, proof, item) = test_generate_proof::<T>(vec![], b"alpha");
	assert!(item.is_none(), "item not found");
	assert!(verify_proof::<T>(&root, &proof, b"alpha", None).is_ok(), "verifying alpha");
	let (root, proof, item) = test_generate_proof::<T>(vec![], b"bravo");
	assert!(item.is_none(), "item not found");
	assert!(verify_proof::<T>(&root, &proof, b"bravo", None).is_ok(), "verifying bravo");
	let (root, proof, item) = test_generate_proof::<T>(vec![], b"\x42\x42");
	assert!(item.is_none(), "item not found");
	assert!(verify_proof::<T>(&root, &proof, b"\x42\x42", None).is_ok(), "verifying \x42\x42");
}

test_layouts!(
	test_verify_value_mismatch_some_to_none,
	test_verify_value_mismatch_some_to_none_internal
);
fn test_verify_value_mismatch_some_to_none_internal<T: TrieLayout>() {
	let (root, proof, _) = test_generate_proof::<T>(test_entries(), b"horse");
	let res = verify_proof::<T>(&root, &proof, b"horse", Some(b"stallion"));
	assert!(res.is_ok(), "verifying horse");

	let res = verify_proof::<T>(&root, &proof, b"halp", Some(b"plz"));
	assert!(res.is_err(), "verifying halp");
	assert!(matches!(res.err().unwrap(), VerifyError::NonExistingValue(_)));

	let res = verify_proof::<T>(&root, &proof, b"horse", Some(b"rocinante"));
	assert!(res.is_err(), "verifying horse");
	//checking for two variants as it depends on the TrieLayout which one occurs
	let is_ok = match res {
		Err(VerifyError::HashMismatch(_)) | Err(VerifyError::ValueMismatch(_)) => true,
		_ => false,
	};
	assert!(is_ok);
}

test_layouts!(test_verify_incomplete_proof, test_verify_incomplete_proof_internal);
fn test_verify_incomplete_proof_internal<T: TrieLayout>() {
	let (root, mut proof, item) = test_generate_proof::<T>(test_entries(), b"alfa");

	proof.pop();
	let res = verify_proof::<T>(&root, &proof, b"alfa", item.as_deref());
	assert!(matches!(res, Err(VerifyError::IncompleteProof)));
}

test_layouts!(test_verify_decode_error, test_verify_decode_error_internal);
fn test_verify_decode_error_internal<T: TrieLayout>() {
	let (_, mut proof, item) = test_generate_proof::<T>(test_entries(), b"bravo");

	let fake_node = b"this is not a trie node";
	proof.insert(0, fake_node.to_vec());
	let fake_root = T::Hash::hash(fake_node);
	let res = verify_proof::<T>(&fake_root, &proof, b"bravo", item.as_deref());
	assert!(matches!(res, Err(VerifyError::DecodeError(_))));
}

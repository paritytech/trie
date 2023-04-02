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
use reference_trie::{test_layouts, NoExtensionLayout};

use std::collections::BTreeMap;
use trie_db::{
	proof::{generate_proof, verify_proof, VerifyError},
	query_plan::HaltedStateRecord,
	DBValue, Trie, TrieDBBuilder, TrieDBMutBuilder, TrieLayout, TrieMut,
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
	keys: Vec<&'static [u8]>,
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(&'static [u8], Option<DBValue>)>) {
	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L>>::default();
		let mut root = Default::default();
		{
			let mut trie = <TrieDBMutBuilder<L>>::new(&mut db, &mut root).build();
			for (key, value) in entries.iter() {
				trie.insert(key, value).unwrap();
			}
		}
		(db, root)
	};

	// Generate proof for the given keys..
	let proof = generate_proof::<_, L, _, _>(&db, &root, keys.iter()).unwrap();
	let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
	let items = keys.into_iter().map(|key| (key, trie.get(key).unwrap())).collect();

	(root, proof, items)
}

test_layouts!(trie_proof_works2, trie_proof_works_internal2);
fn trie_proof_works_internal2<T: TrieLayout>() {
	let (root, proof, items) = test_generate_proof::<T>(
		vec![
			// "do" is at a hash-referenced branch node.
			(&b"do"[..], b"verb"),
			// "dog" is at a hash-referenced branch node.
			(b"dog", b"puppy"),
		],
		vec![b"do", b"dog"],
	);

	verify_proof::<T, _, _, _>(&root, &proof, items.iter()).unwrap();
}

test_layouts!(trie_proof_works, trie_proof_works_internal);
fn trie_proof_works_internal<T: TrieLayout>() {
	let (root, proof, items) = test_generate_proof::<T>(
		test_entries(),
		vec![
			b"do", b"dog", b"doge", b"bravo", b"alfabet", // None, not found under leaf node
			b"d",       // None, witness is extension node with omitted child
			b"do\x10",  // None, empty branch child
			b"halp",    // None, witness is extension node with non-omitted child
		],
	);

	verify_proof::<T, _, _, _>(&root, &proof, items.iter()).unwrap();
}

test_layouts!(trie_proof_works_for_empty_trie, trie_proof_works_for_empty_trie_internal);
fn trie_proof_works_for_empty_trie_internal<T: TrieLayout>() {
	let (root, proof, items) =
		test_generate_proof::<T>(vec![], vec![b"alpha", b"bravo", b"\x42\x42"]);

	verify_proof::<T, _, _, _>(&root, &proof, items.iter()).unwrap();
}

test_layouts!(test_verify_duplicate_keys, test_verify_duplicate_keys_internal);
fn test_verify_duplicate_keys_internal<T: TrieLayout>() {
	let (root, proof, _) = test_generate_proof::<T>(test_entries(), vec![b"bravo"]);

	let items = vec![(b"bravo", Some(b"bravo")), (b"bravo", Some(b"bravo"))];
	assert!(if let Err(VerifyError::DuplicateKey(key)) =
		verify_proof::<T, _, _, _>(&root, &proof, items.iter(),)
	{
		key == b"bravo".to_vec()
	} else {
		false
	});
}

test_layouts!(test_verify_extraneaous_node, test_verify_extraneaous_node_internal);
fn test_verify_extraneaous_node_internal<T: TrieLayout>() {
	let (root, proof, _) = test_generate_proof::<T>(test_entries(), vec![b"bravo", b"do"]);

	let items = vec![(b"bravo", Some(b"bravo"))];
	assert!(matches!(
		verify_proof::<T, _, _, _>(&root, &proof, items.iter()),
		Err(VerifyError::ExtraneousNode)
	));
}

test_layouts!(test_verify_extraneaous_value, test_verify_extraneaous_value_internal);
fn test_verify_extraneaous_value_internal<T: TrieLayout>() {
	let (root, proof, _) = test_generate_proof::<T>(test_entries(), vec![b"doge"]);

	let items = vec![(&b"do"[..], Some(&b"verb"[..])), (&b"doge"[..], Some(&[0; 32][..]))];
	assert!(if let Err(VerifyError::ExtraneousValue(val)) =
		verify_proof::<T, _, _, _>(&root, &proof, items.iter(),)
	{
		val == b"do".to_vec()
	} else {
		false
	});
}

#[test]
fn test_verify_extraneous_hash_reference() {
	let (root, proof, _) = test_generate_proof::<NoExtensionLayout>(test_entries(), vec![b"do"]);

	let items = vec![(&b"alfa"[..], Some(&[0; 32][..])), (&b"do"[..], Some(&b"verb"[..]))];
	match verify_proof::<NoExtensionLayout, _, _, _>(&root, &proof, items.iter()) {
		Err(VerifyError::ExtraneousHashReference(_)) => {},
		result => panic!("expected VerifyError::ExtraneousHashReference, got {:?}", result),
	}
}

test_layouts!(test_verify_invalid_child_reference, test_verify_invalid_child_reference_internal);
fn test_verify_invalid_child_reference_internal<T: TrieLayout>() {
	let (root, proof, _) = test_generate_proof::<T>(test_entries(), vec![b"bravo"]);

	if T::MAX_INLINE_VALUE.map_or(false, |t| t as usize <= b"bravo".len()) {
		// node will not be inline: ignore test
		return
	}
	// InvalidChildReference because "bravo" is in an inline leaf node and a 32-byte value cannot
	// fit in an inline leaf.
	let items = vec![(b"bravo", Some([0; 32]))];
	match verify_proof::<T, _, _, _>(&root, &proof, items.iter()) {
		Err(VerifyError::InvalidChildReference(_)) => {},
		result => panic!("expected VerifyError::InvalidChildReference, got {:?}", result),
	}
}

test_layouts!(
	test_verify_value_mismatch_some_to_none,
	test_verify_value_mismatch_some_to_none_internal
);
fn test_verify_value_mismatch_some_to_none_internal<T: TrieLayout>() {
	let (root, proof, _) = test_generate_proof::<T>(test_entries(), vec![b"horse"]);

	let items = vec![(&b"horse"[..], Some(&b"stallion"[..])), (&b"halp"[..], Some(&b"plz"[..]))];
	assert!(if let Err(VerifyError::ValueMismatch(val)) =
		verify_proof::<T, _, _, _>(&root, &proof, items.iter(),)
	{
		val == b"halp".to_vec()
	} else {
		false
	});
}

test_layouts!(
	test_verify_value_mismatch_none_to_some,
	test_verify_value_mismatch_none_to_some_internal
);
fn test_verify_value_mismatch_none_to_some_internal<T: TrieLayout>() {
	let (root, proof, _) = test_generate_proof::<T>(test_entries(), vec![b"alfa", b"bravo"]);

	let items = vec![(&b"alfa"[..], Some(&[0; 32][..])), (&b"bravo"[..], None)];
	assert!(if let Err(VerifyError::ValueMismatch(val)) =
		verify_proof::<T, _, _, _>(&root, &proof, items.iter(),)
	{
		val == b"bravo".to_vec()
	} else {
		false
	});
}

test_layouts!(test_verify_incomplete_proof, test_verify_incomplete_proof_internal);
fn test_verify_incomplete_proof_internal<T: TrieLayout>() {
	let (root, mut proof, items) = test_generate_proof::<T>(test_entries(), vec![b"alfa"]);

	proof.pop();
	assert!(matches!(
		verify_proof::<T, _, _, _>(&root, &proof, items.iter()),
		Err(VerifyError::IncompleteProof)
	));
}

test_layouts!(test_verify_root_mismatch, test_verify_root_mismatch_internal);
fn test_verify_root_mismatch_internal<T: TrieLayout>() {
	let (root, proof, _) = test_generate_proof::<T>(test_entries(), vec![b"bravo"]);

	let items = vec![(b"bravo", Some("incorrect"))];
	match verify_proof::<T, _, _, _>(&root, &proof, items.iter()) {
		Err(VerifyError::RootMismatch(_)) => {},
		result => panic!("expected VerifyError::RootMismatch, got {:?}", result),
	}
}

test_layouts!(test_verify_decode_error, test_verify_decode_error_internal);
fn test_verify_decode_error_internal<T: TrieLayout>() {
	let (root, mut proof, items) = test_generate_proof::<T>(test_entries(), vec![b"bravo"]);

	proof.insert(0, b"this is not a trie node".to_vec());
	match verify_proof::<T, _, _, _>(&root, &proof, items.iter()) {
		Err(VerifyError::DecodeError(_)) => {},
		result => panic!("expected VerifyError::DecodeError, got {:?}", result),
	}
}

test_layouts!(test_query_plan, test_query_plan_internal);
fn test_query_plan_internal<L: TrieLayout>() {
	use trie_db::query_plan::{
		record_query_plan, verify_query_plan_iter, InMemQueryPlan, InMemQueryPlanItem,
		InMemoryRecorder, ProofKind, ReadProofItem, Recorder,
	};
	let set = test_entries();
	let (db, root) = {
		let mut db = <MemoryDB<L>>::default();
		let mut root = Default::default();
		{
			let mut trie = <TrieDBMutBuilder<L>>::new(&mut db, &mut root).build();
			for (key, value) in set.iter() {
				trie.insert(key, value).unwrap();
			}
		}
		(db, root)
	};
	// TODO add a cache
	let db = <TrieDBBuilder<L>>::new(&db, &root).build();

	let query_plans = [
		InMemQueryPlan {
			items: vec![
				InMemQueryPlanItem::new(b"bravo".to_vec(), false),
				InMemQueryPlanItem::new(b"doge".to_vec(), false),
				InMemQueryPlanItem::new(b"horsey".to_vec(), false),
			],
			ignore_unordered: false,
		},
		InMemQueryPlan {
			items: vec![
				InMemQueryPlanItem::new(b"bravo".to_vec(), false),
				InMemQueryPlanItem::new(b"do".to_vec(), true),
			],
			ignore_unordered: false,
		},
		InMemQueryPlan {
			items: vec![InMemQueryPlanItem::new(b"".to_vec(), true)],
			ignore_unordered: false,
		},
	];
	for query_plan in query_plans {
		let kind = ProofKind::FullNodes;
		for limit_conf in [(0, false), (1, false), (1, true), (2, false), (2, true), (3, true)] {
			let limit = limit_conf.0;
			let limit = (limit != 0).then(|| limit);
			let recorder = Recorder::new(kind, InMemoryRecorder::default(), limit, None);
			let mut from = HaltedStateRecord::from_start(recorder);
			// no limit
			let mut proof: Vec<Vec<u8>> = Default::default();
			let mut query_plan_iter = query_plan.as_ref();
			loop {
				from = record_query_plan::<L, _, _>(&db, &mut query_plan_iter, from).unwrap();

				if limit.is_none() {
					assert!(from.is_finished());
				}
				if from.is_finished() {
					proof.append(&mut from.finish().output().nodes);
					break
				}
				let rec = if limit_conf.1 {
					query_plan_iter = query_plan.as_ref();
					from.stateless(Recorder::new(kind, InMemoryRecorder::default(), limit, None))
				} else {
					from.statefull(Recorder::new(kind, InMemoryRecorder::default(), limit, None))
				};
				proof.append(&mut rec.output().nodes);
			}

			let query_plan_iter = query_plan.as_ref();
			let verify_iter = verify_query_plan_iter::<L, _, _, _>(
				query_plan_iter,
				proof.into_iter(),
				None,
				kind,
				Some(root.clone()),
			)
			.unwrap();
			let content: BTreeMap<_, _> = set.iter().cloned().collect();
			let mut in_prefix = false;
			for item in verify_iter {
				match item.unwrap() {
					ReadProofItem::Value(key, value) => {
						assert_eq!(content.get(&*key), Some(&value.as_ref()));
					},
					ReadProofItem::NoValue(key) => {
						assert_eq!(content.get(key), None);
					},
					ReadProofItem::StartPrefix(_prefix) => {
						in_prefix = true;
					},
					ReadProofItem::EndPrefix => {
						assert!(in_prefix);
						in_prefix = false;
					},
					ReadProofItem::Halted(_) => {
						unreachable!("full proof");
					},
				}
			}
		}

		// TODO limit 1, 2, 3 and restarts
	}
}

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
use reference_trie::{test_layouts, NoExtensionLayout, TestTrieCache};

use std::collections::BTreeMap;
use trie_db::{
	proof::{generate_proof, verify_proof, VerifyError},
	query_plan::{HaltedStateCheck, HaltedStateRecord},
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
		record_query_plan, verify_query_plan_iter, HaltedStateCheck, InMemQueryPlan,
		InMemQueryPlanItem, InMemoryRecorder, ProofKind, QueryPlan, ReadProofItem, Recorder,
	};
	let set = test_entries();

	let mut cache = TestTrieCache::<L>::default();

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
	let db = <TrieDBBuilder<L>>::new(&db, &root).with_cache(&mut cache).build();

	for (hash_only, kind) in [
		(false, ProofKind::CompactContent),
		(false, ProofKind::FullNodes),
		(true, ProofKind::FullNodes),
		(false, ProofKind::CompactNodes),
		(true, ProofKind::CompactNodes),
	] {
		if (kind == ProofKind::CompactContent || kind == ProofKind::CompactNodes) &&
			L::USE_EXTENSION
		{
			// Compact proofs are not supported with extensions.
			// Requires changing the way extension are handled
			// when decoding (putting on stack).
			// Not implemented for `CompactContent`, would need
			// to not append 0 after pushing an extension node.
			continue
		}
		let query_plans = [
			InMemQueryPlan {
				items: vec![InMemQueryPlanItem::new(b"".to_vec(), hash_only, true)],
				ignore_unordered: false,
				kind,
			},
			InMemQueryPlan {
				items: vec![
					InMemQueryPlanItem::new(b"bravo".to_vec(), hash_only, false),
					InMemQueryPlanItem::new(b"do".to_vec(), hash_only, true),
				],
				ignore_unordered: false,
				kind,
			},
			InMemQueryPlan {
				items: vec![
					InMemQueryPlanItem::new(b"bravo".to_vec(), hash_only, false),
					InMemQueryPlanItem::new(b"doge".to_vec(), hash_only, false),
					InMemQueryPlanItem::new(b"horsey".to_vec(), hash_only, false),
				],
				ignore_unordered: false,
				kind,
			},
		];
		for (nb_plan, query_plan) in query_plans.iter().enumerate() {
			/*
			// TODO rem
			if nb_plan < 1 {
				continue
			}
			*/
			for limit_conf in [(0, false), (1, false), (1, true), (2, false), (2, true), (3, true)]
			{
				let limit = limit_conf.0;
				let limit = (limit != 0).then(|| limit);
				let recorder = Recorder::new(kind, InMemoryRecorder::default(), limit, None);
				let mut from = HaltedStateRecord::from_start(recorder);
				// no limit
				let mut proofs: Vec<Vec<Vec<u8>>> = Default::default();
				let mut query_plan_iter = query_plan.as_ref();
				loop {
					from = record_query_plan::<L, _, _>(&db, &mut query_plan_iter, from).unwrap();

					if limit.is_none() {
						assert!(from.is_finished());
					}
					if from.is_finished() {
						if kind == ProofKind::CompactContent {
							proofs.push(vec![from.finish().output().buffer]);
						} else {
							proofs.push(from.finish().output().nodes);
						}
						break
					}
					let rec = if limit_conf.1 {
						query_plan_iter = query_plan.as_ref();
						from.stateless(Recorder::new(
							kind,
							InMemoryRecorder::default(),
							limit,
							None,
						))
					} else {
						from.statefull(Recorder::new(
							kind,
							InMemoryRecorder::default(),
							limit,
							None,
						))
					};
					if kind == ProofKind::CompactContent {
						proofs.push(vec![rec.output().buffer]);
					} else {
						proofs.push(rec.output().nodes);
					}
				}

				let mut full_proof: Vec<Vec<u8>> = Default::default();
				proofs.reverse();

				fn shifted(bytes: &[u8], aligned: bool) -> Vec<u8> {
					let mut shifted: Vec<u8> = vec![];
					let last = bytes.len();
					bytes.iter().enumerate().for_each(|(i, b)| {
						shifted.last_mut().map(|l| {
							*l |= *b >> 4;
						});
						if !(i == last - 1 && aligned) {
							shifted.push(*b << 4);
						}
					});
					shifted
				}

				if kind == ProofKind::CompactContent {
					let all = match L::MAX_INLINE_VALUE {
						Some(1) => true,
						Some(33) => false,
						_ => continue,
					};
					use trie_db::query_plan::compact_content_proof::{Encode, Op};
					// hard coded check
					if limit == None {
						// full on iter all
						assert_eq!(proofs.len(), 1);
						assert_eq!(proofs[0].len(), 1);

						let refs: Vec<Op<trie_db::TrieHash<L>, Vec<u8>>> = match nb_plan {
							0 => vec![
								Op::KeyPush(b"alfa".to_vec(), 0xff),
								Op::Value([0; 32].to_vec()),
								Op::KeyPop(7),
								Op::KeyPush(shifted(b"bravo", false), 0xf0),
								Op::Value(b"bravo".to_vec()),
								Op::KeyPop(9),
								Op::KeyPush(shifted(b"do", false), 0xf0),
								Op::Value(b"verb".to_vec()),
								Op::KeyPush(b"g".to_vec(), 0xff),
								Op::Value(b"puppy".to_vec()),
								Op::KeyPush(b"e".to_vec(), 0xff),
								Op::Value([0; 32].to_vec()),
								Op::KeyPop(7),
								Op::KeyPush(shifted(b"horse", false), 0xf0),
								Op::Value(b"stallion".to_vec()),
								Op::KeyPop(5),
								Op::KeyPush(shifted(b"use", false), 0xf0),
								Op::Value(b"building".to_vec()),
							],
							1 =>
								if all {
									vec![
										Op::KeyPush(b"bravo".to_vec(), 0xff),
										Op::Value(b"bravo".to_vec()),
										Op::KeyPop(9),
										Op::KeyPush(shifted(b"do", false), 0xf0),
										Op::Value(b"verb".to_vec()),
										Op::KeyPush(b"g".to_vec(), 0xff),
										Op::Value(b"puppy".to_vec()),
										Op::KeyPush(b"e".to_vec(), 0xff),
										Op::Value([0; 32].to_vec()),
										Op::KeyPop(7),
										Op::HashChild(
											(&[
												44, 27, 209, 105, 69, 70, 73, 254, 82, 36, 236, 20,
												32, 247, 110, 189, 213, 140, 86, 162, 229, 70, 86,
												163, 223, 26, 52, 253, 176, 201, 65, 248,
											][..])
												.into(),
											1,
										),
										Op::HashChild(
											(&[
												31, 82, 102, 128, 24, 85, 151, 92, 70, 18, 78, 14,
												161, 91, 109, 136, 84, 6, 128, 190, 201, 49, 142,
												21, 154, 250, 246, 133, 0, 199, 138, 49,
											][..])
												.into(),
											8,
										),
									]
								} else {
									vec![
										Op::KeyPush(b"bravo".to_vec(), 0xff),
										Op::Value(b"bravo".to_vec()),
										Op::KeyPop(9),
										Op::KeyPush(shifted(b"do", false), 0xf0),
										Op::Value(b"verb".to_vec()),
										Op::KeyPush(b"g".to_vec(), 0xff),
										Op::Value(b"puppy".to_vec()),
										Op::KeyPush(b"e".to_vec(), 0xff),
										Op::Value([0; 32].to_vec()),
										Op::KeyPop(7),
										// inline ix 8
										Op::KeyPush(shifted(b"horse", false), 0xf0),
										Op::Value(b"stallion".to_vec()),
										Op::KeyPop(5),
										Op::KeyPush(shifted(b"use", false), 0xf0),
										Op::Value(b"building".to_vec()),
										Op::KeyPop(9),
										Op::HashChild(
											(&[
												225, 211, 100, 128, 231, 82, 240, 112, 33, 165,
												225, 30, 244, 128, 56, 45, 17, 21, 138, 87, 3, 211,
												231, 109, 244, 137, 208, 244, 12, 65, 196, 119,
											][..])
												.into(),
											1,
										),
									]
								},
							_ => continue,
						};
						let mut encoded = Vec::new();
						for r in refs {
							r.encode_to(&mut encoded);
						}
						assert_eq!(proofs[0][0], encoded);
					}
					// Decode not written
					continue
				}

				let mut query_plan_iter: QueryPlan<_> = query_plan.as_ref();
				let mut run_state: Option<HaltedStateCheck<_, _, _>> = Some(query_plan_iter.into());
				let mut has_run_full = false;
				while let Some(state) = run_state.take() {
					let proof = if let Some(proof) = proofs.pop() {
						full_proof.extend_from_slice(&proof);
						proof
					} else {
						if full_proof.is_empty() {
							break
						}
						proofs.clear();
						std::mem::take(&mut full_proof)
					};
					let verify_iter = verify_query_plan_iter::<L, _, _, _>(
						state,
						proof.into_iter(),
						Some(root.clone()),
					)
					.unwrap();
					let content: BTreeMap<_, _> = set.iter().cloned().collect();
					let mut in_prefix = false;
					let mut halted = false;
					for item in verify_iter {
						match item.unwrap() {
							ReadProofItem::Hash(key, hash) => {
								assert!(hash_only);
								assert_eq!(
									content.get(&*key).map(|v| L::Hash::hash(&v.as_ref())),
									Some(hash)
								);
							},
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
							ReadProofItem::Halted(resume) => {
								run_state = Some(*resume);
								break
							},
						}
					}
					if run_state.is_none() && !has_run_full {
						has_run_full = true;
						query_plan_iter = query_plan.as_ref();
						run_state = Some(query_plan_iter.into());
					}
				}
				if !has_run_full {
					panic!("did not run full proof")
				}
			}
		}
	}
}

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

//! Query plan tests.

use crate::proof::{test_entries, MemoryDB};
use hash_db::Hasher;
use reference_trie::{test_layouts, TestTrieCache};

use std::collections::BTreeMap;
use trie_db::{
	content_proof::IterOpProof,
	query_plan::{
		record_query_plan, verify_query_plan_iter, verify_query_plan_iter_content,
		HaltedStateCheck, HaltedStateRecord, InMemQueryPlan, InMemQueryPlanItem, InMemoryRecorder,
		ProofKind, QueryPlan, QueryPlanItem, ReadProofItem, Recorder,
	},
	TrieDBBuilder, TrieDBMutBuilder, TrieHash, TrieLayout, TrieMut,
};

test_layouts!(test_query_plan_full, test_query_plan_full_internal);
fn test_query_plan_full_internal<L: TrieLayout>() {
	test_query_plan_internal::<L>(ProofKind::FullNodes, false);
	test_query_plan_internal::<L>(ProofKind::FullNodes, true);
}

test_layouts!(test_query_plan_compact, test_query_plan_compact_internal);
fn test_query_plan_compact_internal<L: TrieLayout>() {
	test_query_plan_internal::<L>(ProofKind::CompactNodes, false);
	test_query_plan_internal::<L>(ProofKind::CompactNodes, true);
}

test_layouts!(test_query_plan_content, test_query_plan_content_internal);
fn test_query_plan_content_internal<L: TrieLayout>() {
	test_query_plan_internal::<L>(ProofKind::CompactContent, false);
	test_query_plan_internal::<L>(ProofKind::CompactContent, true);
}

fn test_query_plan_internal<L: TrieLayout>(kind: ProofKind, hash_only: bool) {
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

	if (kind == ProofKind::CompactContent || kind == ProofKind::CompactNodes) && L::USE_EXTENSION {
		// Compact proofs are not supported with extensions.
		// Requires changing the way extension are handled
		// when decoding (putting on stack).
		// Not implemented for `CompactContent`, would need
		// to not append 0 after pushing an extension node.
		return
	}
	let query_plans = [
		InMemQueryPlan {
			items: vec![InMemQueryPlanItem::new(b"".to_vec(), hash_only, true)],
			ignore_unordered: false,
			kind,
		},
		/*
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
		},*/
	];
	for (_nb_plan, query_plan) in query_plans.iter().enumerate() {
		for limit_conf in [
			(1, false), /* TODO uncomment	(0, false), (1, false), (1, true), (2, false), (2,
			             * true), (3, true) */
		] {
			let limit = limit_conf.0;
			let limit = (limit != 0).then(|| limit);
			let recorder = Recorder::new(kind, InMemoryRecorder::default(), limit, None);
			let mut from = HaltedStateRecord::from_start(recorder);
			// no limit
			let mut proofs: Vec<Vec<Vec<u8>>> = Default::default();
			let mut query_plan_iter = query_plan.as_ref();
			loop {
				record_query_plan::<L, _, _>(&db, &mut query_plan_iter, &mut from).unwrap();

				if limit.is_none() {
					assert!(!from.is_halted());
				}
				if !from.is_halted() {
					if kind == ProofKind::CompactContent {
						proofs.push(vec![from.finish().buffer]);
						for proof in proofs.iter() {
							let mut p = &proof[0][..];
							println!("proof start");
							while let Some((op, read)) =
								trie_db::content_proof::Op::<TrieHash<L>, _>::decode(p).ok()
							{
								println!("{:?}", op);
								p = &p[read..];
							}
							println!("proof end\n");
						}
					} else {
						proofs.push(from.finish().nodes);
					}
					break
				}
				let rec = if limit_conf.1 {
					query_plan_iter = query_plan.as_ref();
					from.stateless(Recorder::new(kind, InMemoryRecorder::default(), limit, None))
				} else {
					from.statefull(Recorder::new(kind, InMemoryRecorder::default(), limit, None))
				};
				if kind == ProofKind::CompactContent {
					proofs.push(vec![rec.buffer]);
				} else {
					proofs.push(rec.nodes);
				}
			}
			let content: BTreeMap<_, _> =
				set.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
			check_proofs::<L>(proofs, query_plan, kind, root, &content, hash_only);

			/* TODO this static check keep it somehow ??
				if kind == ProofKind::CompactContent {
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

					fn hash<H: AsMut<[u8]> + Default>(b: &[u8]) -> H {
						let mut hash = H::default();
						hash.as_mut().copy_from_slice(&b[..]);
						hash
					}

					let all = match L::MAX_INLINE_VALUE {
						Some(1) => true,
						Some(33) => false,
						_ => continue,
					};
					let mut nb = 0;
					let mut proofs = proofs.clone();
					while let Some(proof) = proofs.pop() {
						use trie_db::content_proof::Op;
						// full on iter all
						//						assert_eq!(proofs.len(), 1);
						assert_eq!(proof.len(), 1);

						let refs: Vec<Op<trie_db::TrieHash<L>, Vec<u8>>> =
							match (limit.unwrap_or(0), nb_plan, nb) {
								(0, 0, 0) => vec![
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
								(0, 1, 0) =>
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
												hash(
													&[
														44, 27, 209, 105, 69, 70, 73, 254, 82, 36, 236,
														20, 32, 247, 110, 189, 213, 140, 86, 162, 229,
														70, 86, 163, 223, 26, 52, 253, 176, 201, 65,
														248,
													][..],
												),
												1,
											),
											Op::HashChild(
												hash(
													&[
														31, 82, 102, 128, 24, 85, 151, 92, 70, 18, 78,
														14, 161, 91, 109, 136, 84, 6, 128, 190, 201,
														49, 142, 21, 154, 250, 246, 133, 0, 199, 138,
														49,
													][..],
												),
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
												hash(
													&[
														225, 211, 100, 128, 231, 82, 240, 112, 33, 165,
														225, 30, 244, 128, 56, 45, 17, 21, 138, 87, 3,
														211, 231, 109, 244, 137, 208, 244, 12, 65, 196,
														119,
													][..],
												),
												1,
											),
										]
									},
								(0, 2, 0) =>
								// bravo, doge, horsey
									if all {
										vec![
											Op::KeyPush(b"bravo".to_vec(), 0xff),
											Op::Value(b"bravo".to_vec()),
											Op::KeyPop(9),
											Op::KeyPush(shifted(b"do", false), 0xf0),
											// hash value here is not really good (could only be
											// with child hashes when no hash query).
											Op::HashValue(hash(
												&[
													48, 51, 75, 77, 6, 75, 210, 124, 205, 63, 59, 165,
													81, 140, 222, 237, 196, 168, 203, 206, 105, 245,
													15, 154, 233, 147, 189, 123, 194, 243, 179, 137,
												][..],
											)),
											Op::KeyPush(b"g".to_vec(), 0xff),
											Op::HashValue(hash(
												&[
													104, 225, 103, 23, 160, 148, 143, 214, 98, 64, 250,
													245, 134, 99, 233, 36, 28, 150, 26, 205, 25, 165,
													122, 211, 170, 180, 45, 82, 143, 71, 191, 19,
												][..],
											)),
											Op::KeyPush(b"e".to_vec(), 0xff),
											Op::Value([0; 32].to_vec()),
											Op::KeyPop(7),
											Op::KeyPush(shifted(b"horse", false), 0xf0),
											Op::HashValue(hash(
												&[
													170, 195, 61, 227, 244, 86, 86, 205, 233, 84, 40,
													116, 166, 25, 158, 33, 18, 236, 208, 172, 115, 246,
													158, 34, 158, 170, 197, 139, 219, 254, 124, 136,
												][..],
											)),
											Op::KeyPop(5),
											Op::HashChild(
												hash(
													&[
														115, 96, 173, 184, 157, 30, 165, 173, 98, 91,
														45, 97, 173, 249, 2, 240, 133, 247, 131, 7,
														128, 195, 235, 114, 210, 152, 24, 22, 105, 232,
														147, 171,
													][..],
												),
												5,
											),
											Op::KeyPop(4),
											Op::HashChild(
												hash(
													&[
														44, 27, 209, 105, 69, 70, 73, 254, 82, 36, 236,
														20, 32, 247, 110, 189, 213, 140, 86, 162, 229,
														70, 86, 163, 223, 26, 52, 253, 176, 201, 65,
														248,
													][..],
												),
												1,
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
											Op::KeyPush(shifted(b"horse", false), 0xf0),
											Op::Value(b"stallion".to_vec()),
											Op::KeyPop(5),
											Op::KeyPush(shifted(b"use", false), 0xf0),
											Op::Value(b"building".to_vec()),
											Op::KeyPop(9),
											Op::HashChild(
												hash(
													&[
														225, 211, 100, 128, 231, 82, 240, 112, 33, 165,
														225, 30, 244, 128, 56, 45, 17, 21, 138, 87, 3,
														211, 231, 109, 244, 137, 208, 244, 12, 65, 196,
														119,
													][..],
												),
												1,
											),
										]
									},
								(1, 2, 0) =>
								// bravo, doge, horsey
									if all {
										vec![
											Op::KeyPush(b"bravo".to_vec(), 0xff),
											Op::Value(b"bravo".to_vec()),
											Op::KeyPop(9),
											Op::HashChild(
												hash(
													&[
														44, 27, 209, 105, 69, 70, 73, 254, 82, 36, 236,
														20, 32, 247, 110, 189, 213, 140, 86, 162, 229,
														70, 86, 163, 223, 26, 52, 253, 176, 201, 65,
														248,
													][..],
												),
												1,
											),
											Op::HashChild(
												hash(
													&[
														223, 91, 16, 28, 134, 71, 144, 93, 127, 153,
														131, 180, 101, 103, 252, 121, 200, 66, 33, 188,
														58, 187, 247, 197, 65, 169, 112, 46, 241, 22,
														96, 196,
													][..],
												),
												4,
											),
											Op::HashChild(
												hash(
													&[
														31, 82, 102, 128, 24, 85, 151, 92, 70, 18, 78,
														14, 161, 91, 109, 136, 84, 6, 128, 190, 201,
														49, 142, 21, 154, 250, 246, 133, 0, 199, 138,
														49,
													][..],
												),
												8,
											),
										]
									} else {
										break
										/*
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
											Op::KeyPush(shifted(b"horse", false), 0xf0),
											Op::Value(b"stallion".to_vec()),
											Op::KeyPop(5),
											Op::KeyPush(shifted(b"use", false), 0xf0),
											Op::Value(b"building".to_vec()),
											Op::KeyPop(9),
											Op::HashChild(
												(&[
													225, 211, 100, 128, 231, 82, 240, 112, 33, 165,
													225, 30, 244, 128, 56, 45, 17, 21, 138, 87, 3,
													211, 231, 109, 244, 137, 208, 244, 12, 65, 196,
													119,
												][..])
													.into(),
												1,
											),
										]
										*/
									},

								_ => break,
							};
						let mut encoded = InMemoryRecorder::default();
						for r in refs {
							r.encode_into(&mut encoded);
						}
						assert_eq!(proof[0], encoded.buffer);
						nb += 1;
					}
					// continue
			*/
		}
	}
}

/// Proof checking.
pub fn check_proofs<L: TrieLayout>(
	mut proofs: Vec<Vec<Vec<u8>>>,
	query_plan_in_mem: &InMemQueryPlan,
	kind: ProofKind,
	root: TrieHash<L>,
	content: &BTreeMap<Vec<u8>, Vec<u8>>,
	hash_only: bool,
) {
	let mut full_proof: Vec<Vec<u8>> = Default::default();
	proofs.reverse();

	let is_content_proof = kind == ProofKind::CompactContent;
	let query_plan: QueryPlan<_> = query_plan_in_mem.as_ref();
	let mut run_state: Option<HaltedStateCheck<_, _, _>> = Some(if is_content_proof {
		HaltedStateCheck::Content(query_plan.into())
	} else {
		HaltedStateCheck::Node(query_plan.into())
	});
	let mut query_plan_iter: QueryPlan<_> = query_plan_in_mem.as_ref();
	let mut current_plan = query_plan_iter.items.next();
	let mut has_run_full = false;
	let mut in_prefix = false;
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
		let (mut verify_iter, mut verify_iter_content) = if is_content_proof {
			let proof_iter: IterOpProof<_, _> = (&proof[0]).into();
			(
				None,
				Some(
					verify_query_plan_iter_content::<L, _, IterOpProof<_, _>>(
						state,
						proof_iter,
						Some(root.clone()),
					)
					.unwrap(),
				),
			)
		} else {
			(
				Some(
					verify_query_plan_iter::<L, _, _, _>(
						state,
						proof.into_iter(),
						Some(root.clone()),
					)
					.unwrap(),
				),
				None,
			)
		};
		let mut next_item = || {
			if let Some(verify_iter) = verify_iter.as_mut() {
				verify_iter.next()
			} else if let Some(verify_iter_content) = verify_iter_content.as_mut() {
				verify_iter_content.next()
			} else {
				None
			}
		};

		while let Some(item) = next_item() {
			match item.unwrap() {
				ReadProofItem::Hash(key, hash) => {
					assert!(hash_only);
					assert_eq!(content.get(&*key).map(|v| L::Hash::hash(&v.as_ref())), Some(hash));
					if in_prefix {
						assert!(current_plan
							.as_ref()
							.map(|item| key.starts_with(item.key) &&
								item.hash_only && item.as_prefix)
							.unwrap_or(false));
					} else {
						assert_eq!(
							current_plan.as_ref(),
							Some(&QueryPlanItem { key: &key, hash_only: true, as_prefix: false })
						);
						current_plan = query_plan_iter.items.next();
					}
				},
				ReadProofItem::Value(key, value) => {
					assert_eq!(content.get(&*key), Some(value.as_ref()));
					if in_prefix {
						assert!(current_plan
							.as_ref()
							.map(|item| key.starts_with(item.key) &&
								!item.hash_only && item.as_prefix)
							.unwrap_or(false));
					} else {
						assert_eq!(
							current_plan.as_ref(),
							Some(&QueryPlanItem { key: &key, hash_only: false, as_prefix: false })
						);
						current_plan = query_plan_iter.items.next();
					}
				},
				ReadProofItem::NoValue(key) => {
					assert_eq!(content.get(key), None);
					assert!(!in_prefix);
					if hash_only {
						assert_eq!(
							current_plan.as_ref(),
							Some(&QueryPlanItem { key: &key, hash_only: true, as_prefix: false })
						);
					} else {
						assert_eq!(
							current_plan.as_ref(),
							Some(&QueryPlanItem { key: &key, hash_only: false, as_prefix: false })
						);
					}
					current_plan = query_plan_iter.items.next();
				},
				ReadProofItem::StartPrefix(prefix) => {
					in_prefix = true;
					if hash_only {
						assert_eq!(
							current_plan.as_ref(),
							Some(&QueryPlanItem { key: &prefix, hash_only: true, as_prefix: true })
						);
					} else {
						assert_eq!(
							current_plan.as_ref(),
							Some(&QueryPlanItem {
								key: &prefix,
								hash_only: false,
								as_prefix: true
							})
						);
					}
				},
				ReadProofItem::EndPrefix => {
					assert!(in_prefix);
					in_prefix = false;
					assert!(current_plan.as_ref().map(|item| item.as_prefix).unwrap_or(false));
					current_plan = query_plan_iter.items.next();
				},
				ReadProofItem::Halted(resume) => {
					run_state = Some(*resume);
					break
				},
			}
		}
		if run_state.is_none() {
			assert_eq!(current_plan.as_ref(), None)
		}
		if kind == ProofKind::FullNodes {
			if run_state.is_none() && !has_run_full {
				has_run_full = true;
				query_plan_iter = query_plan_in_mem.as_ref();
				current_plan = query_plan_iter.items.next();

				let query_plan_iter_2 = query_plan_in_mem.as_ref();
				run_state = Some(if is_content_proof {
					HaltedStateCheck::Content(query_plan_iter_2.into())
				} else {
					HaltedStateCheck::Node(query_plan_iter_2.into())
				});
			}
		} else {
			has_run_full = true;
		}
	}
	if !has_run_full {
		panic!("did not run full proof")
	}
	assert!(!in_prefix);
}

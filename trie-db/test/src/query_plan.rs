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

use hash_db::Hasher;
use reference_trie::test_layouts;

use std::collections::BTreeMap;
use trie_db::{
	query_plan::{
		verify_query_plan_iter, HaltedStateCheck,
		InMemQueryPlan, ProofKind, QueryPlan, QueryPlanItem, ReadProofItem,
	},
	TrieHash, TrieLayout,
};

test_layouts!(test_query_plan_full, test_query_plan_full_internal);
#[cfg(test)]
fn test_query_plan_full_internal<L: TrieLayout>() {
	test_query_plan_internal::<L>(ProofKind::FullNodes, false);
	test_query_plan_internal::<L>(ProofKind::FullNodes, true);
}

test_layouts!(test_query_plan_compact, test_query_plan_compact_internal);
#[cfg(test)]
fn test_query_plan_compact_internal<L: TrieLayout>() {
	test_query_plan_internal::<L>(ProofKind::CompactNodes, false);
	test_query_plan_internal::<L>(ProofKind::CompactNodes, true);
}

#[cfg(test)]
fn test_query_plan_internal<L: TrieLayout>(kind: ProofKind, hash_only: bool) {
	use trie_db::query_plan::{Recorder, InMemQueryPlanItem};
	use trie_db::{TrieDBBuilder, TrieDBMutBuilder,  TrieMut};
	let set = crate::test_entries();

	let mut cache = reference_trie::TestTrieCache::<L>::default();

	let (db, root) = {
		let mut db = <crate::MemoryDB<L>>::default();
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

	if kind == ProofKind::CompactNodes && L::USE_EXTENSION {
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
			kind,
		},
		InMemQueryPlan {
			items: vec![
				InMemQueryPlanItem::new(b"bravo".to_vec(), hash_only, false),
				InMemQueryPlanItem::new(b"do".to_vec(), hash_only, true),
			],
			kind,
		},
		InMemQueryPlan {
			items: vec![
				InMemQueryPlanItem::new(b"bravo".to_vec(), hash_only, false),
				InMemQueryPlanItem::new(b"doge".to_vec(), hash_only, false),
				InMemQueryPlanItem::new(b"horsey".to_vec(), hash_only, false),
			],
			kind,
		},
	];
	for (_nb_plan, query_plan) in query_plans.iter().enumerate() {
		for limit_conf in [
			(0, false), /* TODO uncomment	(0, false), (1, false), (1, true), (2, false), (2,
			             * true), (3, true) */
		] {
			let limit = limit_conf.0;
			let limit = (limit != 0).then(|| limit);
			let recorder = Recorder::new(kind, Default::default(), limit, None);
			let mut from = trie_db::query_plan::HaltedStateRecord::from_start(recorder);
			// no limit
			let mut proofs: Vec<Vec<Vec<u8>>> = Default::default();
			let mut query_plan_iter = query_plan.as_ref();
			loop {
				trie_db::query_plan::record_query_plan::<L, _>(&db, &mut query_plan_iter, &mut from).unwrap();

				if limit.is_none() {
					assert!(!from.is_halted());
				}
				if !from.is_halted() {
					proofs.push(from.finish());
					break
				}
				let rec = if limit_conf.1 {
					query_plan_iter = query_plan.as_ref();
					from.stateless(Recorder::new(kind, Default::default(), limit, None))
				} else {
					from.statefull(Recorder::new(kind, Default::default(), limit, None))
				};
				proofs.push(rec);
			}
			let content: BTreeMap<_, _> =
				set.iter().map(|(k, v)| (k.to_vec(), v.to_vec())).collect();
			check_proofs::<L>(proofs, query_plan, kind, root, &content, hash_only);
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

	let query_plan: QueryPlan<_> = query_plan_in_mem.as_ref();
	let mut run_state: Option<HaltedStateCheck<_, _, _>> = Some(query_plan.into());
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
		let mut verify_iter =
			verify_query_plan_iter::<L, _, _, _>(state, proof.into_iter(), Some(root.clone()))
				.unwrap();
		while let Some(item) = verify_iter.next() {
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
					assert!(!in_prefix);
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
				run_state = Some(query_plan_iter_2.into());
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

// Copyright 2026 Parity Technologies
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

//! `AppendOnlyTrieDBMut`, as used to estimate the proof size of a block's storage deletions
//! incrementally: deletes are applied over several sessions (detached in between) and runtime
//! transactions roll them back, yet the recorded nodes must match one real `storage_root`.

use std::{
	collections::BTreeMap,
	panic::{catch_unwind, AssertUnwindSafe},
};

use hash_db::{HashDBRef, Hasher, Prefix};
use memory_db::{MemoryDB, PrefixedKey};
use rand::{rngs::SmallRng, Rng, SeedableRng};
use reference_trie::test_layouts;
use trie_db::{
	AppendOnlyTrieDBMut, AppendOnlyTrieDBMutBuilder, DBValue, DetachedTrieDBMut, InvalidSnapshot,
	Recorder, TrieDBMutBuilder, TrieDBMutSnapshot, TrieHash, TrieLayout, TrieMut,
};

type PrefixedMemoryDB<T> =
	MemoryDB<<T as TrieLayout>::Hash, PrefixedKey<<T as TrieLayout>::Hash>, DBValue>;
type Nodes<T> = BTreeMap<<<T as TrieLayout>::Hash as Hasher>::Out, Vec<u8>>;

// Trie shape (nibble paths), the root being a wide branch:
//
//   root ─5─ A ─0─ B ─0─ L1 (K1)
//            │       └1─ L2 (K2)
//            └1─ L3 (K3)
//
// Removing K1 and K2 together collapses B and then A, which loads L3; removing either one alone
// never loads L3.
const K1: &[u8] = &[0x50, 0x00, 0xAA, 0xAA];
const K2: &[u8] = &[0x50, 0x10, 0xBB, 0xBB];
const K3: &[u8] = &[0x51, 0x00, 0xCC, 0xCC];

fn build_trie<T: TrieLayout>(
	entries: &[(Vec<u8>, Vec<u8>)],
) -> (PrefixedMemoryDB<T>, TrieHash<T>, Vec<Vec<u8>>) {
	let mut db = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut trie = TrieDBMutBuilder::<T>::new(&mut db, &mut root).build();
		for (key, value) in entries {
			trie.insert(key, value).unwrap();
		}
	}
	(db, root, entries.iter().map(|(key, _)| key.clone()).collect())
}

fn block_start_trie<T: TrieLayout>() -> (PrefixedMemoryDB<T>, TrieHash<T>, Vec<Vec<u8>>) {
	let fillers = [0x0u8, 0x1, 0x2, 0x3, 0xA, 0xB, 0xC, 0xD]
		.map(|nibble| (vec![nibble << 4, 0x11, 0x22, 0x33], vec![nibble; 64]));
	let collapsing =
		[(K1, 1u8), (K2, 2), (K3, 3)].map(|(key, byte)| (key.to_vec(), vec![byte; 64]));
	build_trie::<T>(&[&fillers[..], &collapsing[..]].concat())
}

fn read_keys<T: TrieLayout>(
	trie: &AppendOnlyTrieDBMut<T>,
	keys: &[Vec<u8>],
) -> Vec<Option<DBValue>> {
	keys.iter().map(|key| trie.get(key).unwrap()).collect()
}

fn drain<T: TrieLayout>(mut recorder: Recorder<T>) -> Nodes<T> {
	recorder.drain().into_iter().map(|record| (record.hash, record.data)).collect()
}

/// What a real `storage_root` does: removes `removed` in one committing session. Returns the
/// recorded nodes and the resulting values of `probed`.
fn real_session<T: TrieLayout, K: AsRef<[u8]>>(
	db: &PrefixedMemoryDB<T>,
	root: TrieHash<T>,
	removed: &[K],
	probed: &[Vec<u8>],
) -> (Nodes<T>, Vec<Option<DBValue>>) {
	let mut scratch = db.clone();
	let mut root = root;
	let mut recorder = Recorder::<T>::new();
	{
		let mut trie = TrieDBMutBuilder::<T>::from_existing(&mut scratch, &mut root)
			.with_recorder(&mut recorder)
			.build();
		for key in removed {
			trie.remove(key.as_ref()).unwrap();
		}
	}
	let trie = TrieDBMutBuilder::<T>::from_existing(&mut scratch, &mut root).build();
	let contents = probed.iter().map(|key| trie.get(key).unwrap()).collect();
	(drain(recorder), contents)
}

/// One append-only session over `detached`, with a fresh recorder like the PoV estimator takes
/// on every size estimation call. Returns the nodes recorded in it.
fn session<T: TrieLayout>(
	detached: &mut DetachedTrieDBMut<T>,
	db: &dyn HashDBRef<T::Hash, DBValue>,
	operations: impl FnOnce(&mut AppendOnlyTrieDBMut<T>),
) -> Nodes<T> {
	let mut recorder = Recorder::<T>::new();
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(db, detached)
		.with_recorder(&mut recorder)
		.build();
	operations(&mut trie);
	drop(trie);
	drain(recorder)
}

fn contents<T: TrieLayout>(
	detached: &mut DetachedTrieDBMut<T>,
	db: &PrefixedMemoryDB<T>,
	probed: &[Vec<u8>],
) -> Vec<Option<DBValue>> {
	let mut values = Vec::new();
	session::<T>(detached, db, |trie| values = read_keys(trie, probed));
	values
}

test_layouts!(joint_collapse_across_sessions_is_recorded, joint_collapse_across_sessions_internal);
/// The bug this mode fixes: when each delete is replayed from the pristine root, a collapse that
/// only happens because of an earlier delete (here A collapsing into L3) is never recorded and the
/// proof size is under-estimated.
fn joint_collapse_across_sessions_internal<T: TrieLayout>() {
	for order in [[K1, K2], [K2, K1]] {
		let (db, root, _) = block_start_trie::<T>();
		let (real, _) = real_session::<T, _>(&db, root, &order, &[]);

		let mut detached = DetachedTrieDBMut::<T>::new(root);
		let mut recorded = Nodes::<T>::new();
		for key in order {
			recorded.extend(session::<T>(&mut detached, &db, |trie| {
				trie.remove(key).unwrap();
			}));
		}

		assert_eq!(recorded, real);
	}
}

test_layouts!(rollback_then_redo_matches_real_session, rollback_then_redo_internal);
/// A rolled back transaction must leave the trie as if its deletes never happened, so a later
/// redo of the same delete loads exactly what a real session would.
fn rollback_then_redo_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (real, real_contents) = real_session::<T, _>(&db, root, &[K1, K2], &keys);
	let (_, only_k1_removed) = real_session::<T, _>(&db, root, &[K1], &keys);

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut recorded = session::<T>(&mut detached, &db, |trie| {
		trie.remove(K1).unwrap();
		let snapshot = trie.snapshot();
		trie.remove(K2).unwrap();
		trie.rollback_to(&snapshot).unwrap();
	});
	let values = contents::<T>(&mut detached, &db, &keys);
	assert_eq!(values[keys.iter().position(|key| key == K2).unwrap()], Some(vec![2u8; 64]));
	assert_eq!(values, only_k1_removed);

	recorded.extend(session::<T>(&mut detached, &db, |trie| {
		trie.remove(K2).unwrap();
	}));
	assert_eq!(recorded, real);
	assert_eq!(contents::<T>(&mut detached, &db, &keys), real_contents);
}

test_layouts!(nested_rollbacks_restore_pristine_trie, nested_rollbacks_internal);
/// Nested runtime transactions roll back innermost first; after both, the trie must be pristine
/// and the nodes loaded inside them must be loaded (and recorded) again when needed.
fn nested_rollbacks_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, pristine_contents) = real_session::<T, &[u8]>(&db, root, &[], &keys);
	let (real_k1, _) = real_session::<T, _>(&db, root, &[K1], &keys);

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	session::<T>(&mut detached, &db, |trie| {
		let outer = trie.snapshot();
		trie.remove(K1).unwrap();
		let inner = trie.snapshot();
		trie.remove(K2).unwrap();
		trie.rollback_to(&inner).unwrap();
		trie.rollback_to(&outer).unwrap();
	});
	assert_eq!(contents::<T>(&mut detached, &db, &keys), pristine_contents);

	let recorded = session::<T>(&mut detached, &db, |trie| {
		trie.remove(K1).unwrap();
	});
	assert_eq!(recorded, real_k1);
}

test_layouts!(rollback_to_initial_snapshot, rollback_to_initial_snapshot_internal);
/// A transaction may start before the first delete of the block, while the root is still only a
/// hash; rolling back to it must work whether or not anything was loaded since, including after
/// the trie was emptied entirely.
fn rollback_to_initial_snapshot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, pristine_contents) = real_session::<T, &[u8]>(&db, root, &[], &keys);
	let (real_k1, _) = real_session::<T, _>(&db, root, &[K1], &keys);

	let mut never_mutated = DetachedTrieDBMut::<T>::new(root);
	let initial = never_mutated.snapshot();
	never_mutated.rollback_to(&initial).unwrap();
	assert_eq!(contents::<T>(&mut never_mutated, &db, &keys), pristine_contents);

	let mut emptied = DetachedTrieDBMut::<T>::new(root);
	let initial = emptied.snapshot();
	session::<T>(&mut emptied, &db, |trie| {
		for key in &keys {
			trie.remove(key).unwrap();
		}
		assert!(trie.is_empty());
	});
	emptied.rollback_to(&initial).unwrap();
	assert_eq!(contents::<T>(&mut emptied, &db, &keys), pristine_contents);
	let recorded = session::<T>(&mut emptied, &db, |trie| {
		trie.remove(K1).unwrap();
	});
	assert_eq!(recorded, real_k1);
}

test_layouts!(detached_snapshot_spans_sessions, detached_snapshot_spans_sessions_internal);
/// Transactions start and roll back between sessions, when only the detached state exists.
fn detached_snapshot_spans_sessions_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, only_k1_removed) = real_session::<T, _>(&db, root, &[K1], &keys);
	let (_, k1_and_k3_removed) = real_session::<T, _>(&db, root, &[K1, K3], &keys);

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	session::<T>(&mut detached, &db, |trie| {
		trie.remove(K1).unwrap();
	});
	let snapshot = detached.snapshot();
	session::<T>(&mut detached, &db, |trie| {
		trie.remove(K2).unwrap();
		trie.remove(K3).unwrap();
	});
	detached.rollback_to(&snapshot).unwrap();
	assert_eq!(contents::<T>(&mut detached, &db, &keys), only_k1_removed);

	session::<T>(&mut detached, &db, |trie| {
		trie.remove(K3).unwrap();
	});
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k1_and_k3_removed);
}

test_layouts!(removing_missing_key_is_harmless, removing_missing_key_internal);
/// Extrinsics may delete keys that do not exist; that must not corrupt the trie.
fn removing_missing_key_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, pristine_contents) = real_session::<T, &[u8]>(&db, root, &[], &keys);

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	session::<T>(&mut detached, &db, |trie| {
		assert!(trie.remove(&[0x50, 0x00, 0xAA, 0xAB]).unwrap().is_none());
		assert!(trie.remove(&[0x50, 0x20]).unwrap().is_none());
	});
	assert_eq!(contents::<T>(&mut detached, &db, &keys), pristine_contents);
}

/// Checks the append-only state against a real session removing only the deletes that survived
/// every rollback: same contents, and the same recorded nodes.
fn assert_matches_real<T: TrieLayout>(
	db: &PrefixedMemoryDB<T>,
	root: TrieHash<T>,
	detached: &mut DetachedTrieDBMut<T>,
	keys: &[Vec<u8>],
	surviving_deletes: &[Vec<u8>],
	recorded: &Nodes<T>,
) {
	let (real, real_contents) = real_session::<T, _>(db, root, surviving_deletes, keys);
	assert_eq!(recorded, &real);
	assert_eq!(contents::<T>(detached, db, keys), real_contents);
}

test_layouts!(random_deletes_and_rollbacks_match_real_session, random_internal);
/// Random interleavings of deletes, transactions and rollbacks across sessions, as a block
/// produces them.
fn random_internal<T: TrieLayout>() {
	for seed in 0..8 {
		random_run::<T>(seed);
	}
}

fn random_run<T: TrieLayout>(seed: u64) {
	let mut rng = SmallRng::seed_from_u64(seed);
	// Short keys over a small alphabet, so deletes share paths and collapse into each other.
	let entries: BTreeMap<Vec<u8>, Vec<u8>> = (0..200)
		.map(|_| {
			let key = (0..rng.gen_range(2..=3)).map(|_| rng.gen_range(0..8u8) * 0x11).collect();
			let value = vec![rng.gen(); rng.gen_range(1..=40)];
			(key, value)
		})
		.collect();
	let (db, root, keys) = build_trie::<T>(&entries.into_iter().collect::<Vec<_>>());

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut surviving_deletes: Vec<Vec<u8>> = Vec::new();
	// The production recorder is transactional too, so a rollback also forgets what was recorded.
	let mut recorded = Nodes::<T>::new();
	let mut snapshots: Vec<(TrieDBMutSnapshot<T>, usize, Nodes<T>)> = Vec::new();

	for _ in 0..80 {
		match rng.gen_range(0..6) {
			0 => snapshots.push((detached.snapshot(), surviving_deletes.len(), recorded.clone())),
			1 if !snapshots.is_empty() => {
				let index = rng.gen_range(0..snapshots.len());
				snapshots.truncate(index + 1);
				let (snapshot, deletes, nodes) = &snapshots[index];
				detached.rollback_to(snapshot).unwrap();
				surviving_deletes.truncate(*deletes);
				recorded = nodes.clone();
				assert_matches_real(&db, root, &mut detached, &keys, &surviving_deletes, &recorded);
			},
			_ => {
				let live: Vec<_> =
					keys.iter().filter(|key| !surviving_deletes.contains(key)).cloned().collect();
				let batch: Vec<_> = (0..rng.gen_range(1..=3))
					.filter_map(|_| live.get(rng.gen_range(0..live.len().max(1))).cloned())
					.collect();
				recorded.extend(session::<T>(&mut detached, &db, |trie| {
					for key in &batch {
						trie.remove(key).unwrap();
					}
				}));
				surviving_deletes.extend(batch);
			},
		}
	}
	assert_matches_real(&db, root, &mut detached, &keys, &surviving_deletes, &recorded);
}

test_layouts!(
	rollback_last_delete_preserves_external_root,
	rollback_last_delete_preserves_external_root_internal
);
/// Rolling back the deletion of the final key must restore the in-memory view. The caller's
/// root is not even borrowed, so it cannot be touched.
fn rollback_last_delete_preserves_external_root_internal<T: TrieLayout>() {
	let value = vec![1u8; 64];
	let (db, root, _) = build_trie::<T>(&[(K1.to_vec(), value.clone())]);
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let snapshot = trie.snapshot();
	trie.remove(K1).unwrap();
	assert!(trie.is_empty());
	trie.rollback_to(&snapshot).unwrap();
	assert_eq!(trie.get(K1).unwrap(), Some(value));
}

test_layouts!(rollback_below_a_snapshot_invalidates_it, rollback_below_a_snapshot_internal);
/// A snapshot describes the arena up to its mark. Rolling back below that mark and working on
/// replaces those nodes, so the snapshot would install a root that is not its own; using it must
/// be refused. Rolling back to the same snapshot again is fine.
fn rollback_below_a_snapshot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();

	let outer = trie.snapshot();
	trie.remove(K1).unwrap();
	let inner = trie.snapshot();

	trie.rollback_to(&outer).unwrap();
	trie.rollback_to(&outer).unwrap();
	for key in &keys {
		trie.remove(key).unwrap();
	}

	assert_eq!(trie.rollback_to(&inner), Err(InvalidSnapshot));
	assert_eq!(trie.get(K1).unwrap(), None, "a refused rollback leaves the trie as it is");
}

test_layouts!(inserts_are_visible_and_roll_back, inserts_internal);
/// The other tests only remove. Inserting drives `insert_at` over a storage whose `destroy` hands
/// out a copy of the node instead of taking it out, and a rollback must drop the inserts too.
fn inserts_internal<T: TrieLayout>() {
	const NEW_SIBLING: &[u8] = &[0x50, 0x20, 0xDD, 0xDD];
	const NEW_BRANCH: &[u8] = &[0x60, 0x00, 0xEE, 0xEE];
	let (db, root, keys) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let before = read_keys(&trie, &keys);

	assert_eq!(trie.insert(NEW_SIBLING, &[1; 40]).unwrap(), None);
	let snapshot = trie.snapshot();
	assert_eq!(trie.insert(NEW_BRANCH, &[2; 40]).unwrap(), None);
	assert_eq!(trie.get(NEW_SIBLING).unwrap(), Some(vec![1; 40]));
	assert_eq!(trie.get(NEW_BRANCH).unwrap(), Some(vec![2; 40]));
	assert_eq!(read_keys(&trie, &keys), before);

	trie.rollback_to(&snapshot).unwrap();
	assert_eq!(trie.get(NEW_SIBLING).unwrap(), Some(vec![1; 40]));
	assert_eq!(trie.get(NEW_BRANCH).unwrap(), None);
	assert_eq!(read_keys(&trie, &keys), before);
}

/// Keys on the path to K1 that are not in the trie.
fn absent_keys_under_k1() -> Vec<Vec<u8>> {
	(0..50u8).map(|byte| vec![0x50, 0x00, 0xAA, byte]).collect()
}

/// Removes every key in `absent_keys` and checks that only the first removal grew the arena.
fn assert_absent_removals_reuse_slots<T: TrieLayout>(
	trie: &mut AppendOnlyTrieDBMut<T>,
	absent_keys: &[Vec<u8>],
) {
	assert!(trie.remove(&absent_keys[0]).unwrap().is_none());
	let after_first = trie.arena_len();
	for key in &absent_keys[1..] {
		assert!(trie.remove(key).unwrap().is_none());
	}
	assert_eq!(trie.arena_len(), after_first);
}

test_layouts!(absent_key_removals_keep_arena_bounded, absent_key_removals_internal);
/// The estimation trie lives for a whole block, and a block may remove tens of thousands of keys,
/// many of them absent. Outside of a snapshot nothing needs the replaced nodes, so a removal must
/// reuse their slots: an arena growing by a path copy per removal exhausts the runtime's memory.
fn absent_key_removals_internal<T: TrieLayout>() {
	let (db, root, _) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	assert_absent_removals_reuse_slots(&mut trie, &absent_keys_under_k1());
}

test_layouts!(rollback_after_slot_reuse, rollback_after_slot_reuse_internal);
/// The second delete along a path overwrites the slots the first one freed. A rollback must still
/// restore the trie of the snapshot, and the slots handed out afterwards must not be ones the
/// rollback discarded, so a redo loads and records exactly what a real session does.
fn rollback_after_slot_reuse_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, k3_removed) = real_session::<T, _>(&db, root, &[K3], &keys);
	let (real, all_removed) = real_session::<T, _>(&db, root, &[K3, K1, K2], &keys);

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut recorded = session::<T>(&mut detached, &db, |trie| {
		trie.remove(K3).unwrap();
		let snapshot = trie.snapshot();
		trie.remove(K1).unwrap();
		trie.remove(K2).unwrap();
		trie.rollback_to(&snapshot).unwrap();
	});
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_removed);

	recorded.extend(session::<T>(&mut detached, &db, |trie| {
		trie.remove(K1).unwrap();
		trie.remove(K2).unwrap();
	}));
	assert_eq!(recorded, real);
	assert_eq!(contents::<T>(&mut detached, &db, &keys), all_removed);
}

test_layouts!(nested_rollbacks_after_slot_reuse, nested_rollbacks_after_slot_reuse_internal);
/// A snapshot protects every node written before it, so deletes inside a nested transaction may
/// only reuse slots written after the inner snapshot, and both rollbacks must restore their own
/// trie. Once rolled back past the outer snapshot, nothing protects the nodes written since it,
/// so removals must reuse their slots again instead of growing the arena.
fn nested_rollbacks_after_slot_reuse_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, pristine_contents) = real_session::<T, &[u8]>(&db, root, &[], &keys);
	let (_, k1_and_k2_removed) = real_session::<T, _>(&db, root, &[K1, K2], &keys);
	// Enough nodes that the inner snapshot protects more slots than the absent-key removals at
	// the end use, so those would not be reused if the protection stayed at the inner snapshot.
	let inserted: Vec<Vec<u8>> = (0..32u8).map(|byte| vec![0xE0, byte, 0x55]).collect();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();

	let outer = trie.snapshot();
	for key in &inserted {
		trie.insert(key, &[7; 40]).unwrap();
	}
	let inner = trie.snapshot();
	trie.remove(K1).unwrap();
	trie.remove(K2).unwrap();
	assert_eq!(read_keys(&trie, &keys), k1_and_k2_removed);

	trie.rollback_to(&inner).unwrap();
	assert_eq!(read_keys(&trie, &keys), pristine_contents);
	assert!(read_keys(&trie, &inserted).iter().all(|value| *value == Some(vec![7; 40])));
	trie.rollback_to(&outer).unwrap();
	assert_eq!(read_keys(&trie, &keys), pristine_contents);
	assert!(read_keys(&trie, &inserted).iter().all(Option::is_none));

	assert_absent_removals_reuse_slots(&mut trie, &absent_keys_under_k1());
}

test_layouts!(
	reused_arena_indices_do_not_revive_snapshots,
	reused_arena_indices_do_not_revive_snapshots_internal
);
/// Repeating the same edits after a rollback reuses the same arena indices. A snapshot from
/// the discarded branch must still be rejected, without disturbing the current branch.
fn reused_arena_indices_do_not_revive_snapshots_internal<T: TrieLayout>() {
	const NEW_KEY: &[u8] = &[0x60, 0x00, 0xEE, 0xEE];
	const LATER_KEY: &[u8] = &[0x70, 0x00, 0xFF, 0xFF];
	let (db, root, keys) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let original_values = read_keys(&trie, &keys);
	let initial = trie.snapshot();

	trie.insert(NEW_KEY, &[1; 40]).unwrap();
	let stale = trie.snapshot();
	drop(trie);
	detached.rollback_to(&initial).unwrap();

	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	// The same insertion allocates the same number of nodes at the same indices.
	trie.insert(NEW_KEY, &[2; 40]).unwrap();
	let current = trie.snapshot();
	assert_eq!(trie.rollback_to(&stale), Err(InvalidSnapshot));
	assert_eq!(trie.get(NEW_KEY).unwrap(), Some(vec![2; 40]));

	// The rejected rollback must not discard nodes allocated after the stale snapshot's mark.
	trie.insert(LATER_KEY, &[3; 40]).unwrap();
	assert_eq!(trie.rollback_to(&stale), Err(InvalidSnapshot));
	assert_eq!(trie.get(LATER_KEY).unwrap(), Some(vec![3; 40]));

	trie.rollback_to(&current).unwrap();
	trie.rollback_to(&current).unwrap();
	assert_eq!(trie.get(NEW_KEY).unwrap(), Some(vec![2; 40]));
	assert_eq!(trie.get(LATER_KEY).unwrap(), None);
	trie.rollback_to(&initial).unwrap();
	trie.rollback_to(&initial).unwrap();
	assert_eq!(trie.get(NEW_KEY).unwrap(), None);
	assert_eq!(read_keys(&trie, &keys), original_values);
}

/// An empty trie with `K1` inserted in memory, so that removing `K1` empties the trie again.
fn trie_holding_only_k1<'a, T: TrieLayout>(
	detached: &'a mut DetachedTrieDBMut<T>,
	db: &'a PrefixedMemoryDB<T>,
) -> AppendOnlyTrieDBMut<'a, T> {
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(db, detached).build();
	trie.insert(K1, &[1; 64]).unwrap();
	trie
}

test_layouts!(removing_the_last_key_does_not_revive_snapshots, removing_the_last_key_internal);
/// Removing the last key empties the trie without writing a node, so the snapshots before and
/// after it stand at the same arena length. A rollback to the earlier one must still invalidate
/// the later one, or the trie would lose `K1` again.
fn removing_the_last_key_internal<T: TrieLayout>() {
	let (db, root, _) = build_trie::<T>(&[]);
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = trie_holding_only_k1(&mut detached, &db);
	let before_removal = trie.snapshot();
	trie.remove(K1).unwrap();
	let emptied = trie.snapshot();

	trie.rollback_to(&before_removal).unwrap();
	assert_eq!(trie.rollback_to(&emptied), Err(InvalidSnapshot));
	assert_eq!(trie.get(K1).unwrap(), Some(vec![1; 64]));
}

test_layouts!(
	stale_snapshots_at_a_shared_length_are_refused,
	stale_snapshots_at_a_shared_length_internal
);
/// Once one stale snapshot at a shared arena length were accepted, every snapshot at that length
/// would look valid too. Each must be judged on its own: a refused rollback keeps later snapshots
/// valid, and a rollback below a snapshot invalidates it even when it holds the current trie.
fn stale_snapshots_at_a_shared_length_internal<T: TrieLayout>() {
	let (db, root, _) = build_trie::<T>(&[]);
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = trie_holding_only_k1(&mut detached, &db);
	let holding_k1 = trie.snapshot();
	trie.remove(K1).unwrap();
	let emptied = trie.snapshot();
	trie.rollback_to(&holding_k1).unwrap();
	let after_rollback = trie.snapshot();

	assert_eq!(trie.rollback_to(&emptied), Err(InvalidSnapshot));
	assert_eq!(trie.get(K1).unwrap(), Some(vec![1; 64]));
	trie.remove(K1).unwrap();
	trie.rollback_to(&after_rollback).unwrap();
	assert_eq!(trie.get(K1).unwrap(), Some(vec![1; 64]));

	trie.rollback_to(&holding_k1).unwrap();
	trie.remove(K1).unwrap();
	assert_eq!(trie.rollback_to(&after_rollback), Err(InvalidSnapshot));
	assert!(trie.is_empty());
}

test_layouts!(
	snapshot_after_rollback_does_not_revive_older_ones,
	snapshot_after_rollback_does_not_revive_older_ones_internal
);
/// Snapshots follow nested transactions, so the valid ones are not a contiguous range: after
/// `s1`, `s2`, a rollback to `s1` and `s3`, only `s1` and `s3` are valid. Taking `s3` must not
/// make `s2` valid again.
fn snapshot_after_rollback_does_not_revive_older_ones_internal<T: TrieLayout>() {
	let (db, root, _) = build_trie::<T>(&[]);
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = trie_holding_only_k1(&mut detached, &db);
	let s1 = trie.snapshot();
	trie.insert(K2, &[2; 64]).unwrap();
	let s2 = trie.snapshot();
	trie.rollback_to(&s1).unwrap();
	trie.insert(K3, &[3; 64]).unwrap();
	let s3 = trie.snapshot();
	let holding =
		|trie: &AppendOnlyTrieDBMut<T>| [K1, K2, K3].map(|key| trie.get(key).unwrap().is_some());

	assert_eq!(trie.rollback_to(&s2), Err(InvalidSnapshot));
	assert_eq!(holding(&trie), [true, false, true]);
	trie.rollback_to(&s3).unwrap();
	assert_eq!(holding(&trie), [true, false, true]);
	trie.rollback_to(&s1).unwrap();
	assert_eq!(holding(&trie), [true, false, false]);
}

test_layouts!(snapshot_of_another_trie_is_refused, snapshot_of_another_trie_internal);
/// A snapshot only describes the trie it was taken from. Used on another trie it would install
/// that trie's root over unrelated nodes, so it must be refused and leave the trie as it is.
fn snapshot_of_another_trie_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let foreign = DetachedTrieDBMut::<T>::new(Default::default()).snapshot();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let before = read_keys(&trie, &keys);
	let initial = trie.snapshot();

	trie.remove(K1).unwrap();
	assert_eq!(trie.rollback_to(&foreign), Err(InvalidSnapshot));
	assert_eq!(trie.get(K1).unwrap(), None);

	trie.rollback_to(&initial).unwrap();
	assert_eq!(read_keys(&trie, &keys), before);
}

/// Arena length after each of 50 extrinsics. Each removes an absent key under a snapshot of its
/// own, then `end` gets the trie, that snapshot and the extrinsic's number.
fn arena_per_extrinsic<T: TrieLayout>(
	trie: &mut AppendOnlyTrieDBMut<T>,
	mut end: impl FnMut(&mut AppendOnlyTrieDBMut<T>, &TrieDBMutSnapshot<T>, usize),
) -> Vec<usize> {
	absent_keys_under_k1()
		.iter()
		.enumerate()
		.map(|(number, key)| {
			let extrinsic = trie.snapshot();
			assert!(trie.remove(key).unwrap().is_none());
			end(trie, &extrinsic, number);
			trie.arena_len()
		})
		.collect()
}

/// The first two extrinsics may load the path and copy it; after that the arena must not grow.
fn assert_stays_flat(lengths: &[usize]) {
	assert!(lengths[2..].iter().all(|len| *len == lengths[1]), "{:?}", lengths);
}

test_layouts!(discarded_snapshots_keep_arena_flat, discarded_snapshots_keep_arena_flat_internal);
/// A block takes a snapshot per extrinsic. It discards the snapshot when the extrinsic commits,
/// and rolls back to it and then discards it when the extrinsic fails. The nodes only that
/// snapshot kept alive must then be reused, or the arena grows by a path copy per extrinsic for
/// the whole block.
fn discarded_snapshots_keep_arena_flat_internal<T: TrieLayout>() {
	let (db, root, _) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let block = trie.snapshot();
	let commit =
		|trie: &mut AppendOnlyTrieDBMut<T>, extrinsic: &_, _| trie.discard_from(extrinsic).unwrap();
	assert_stays_flat(&arena_per_extrinsic(&mut trie, commit));
	assert_absent_removals_reuse_slots(&mut trie, &absent_keys_under_k1());
	assert_stays_flat(&arena_per_extrinsic(&mut trie, |trie, extrinsic, number| {
		if number % 2 == 1 {
			trie.rollback_to(extrinsic).unwrap();
		}
		trie.discard_from(extrinsic).unwrap()
	}));
	trie.discard_from(&block).unwrap();
	assert_stays_flat(&arena_per_extrinsic(&mut trie, commit));

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let kept = arena_per_extrinsic(&mut trie, |_, _, _| {});
	assert!(kept.windows(2).all(|pair| pair[1] > pair[0]), "{:?}", kept);
}

test_layouts!(ended_blocks_keep_arena_flat, ended_blocks_keep_arena_flat_internal);
/// An extrinsic commits inside a block snapshot, then the block commits or fails. Once the block
/// ends, the nodes only its snapshot kept alive must be reused, or the arena grows by a path copy
/// per block.
fn ended_blocks_keep_arena_flat_internal<T: TrieLayout>() {
	let (db, root, _) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let arena_per_block: Vec<usize> = absent_keys_under_k1()
		.iter()
		.enumerate()
		.map(|(number, key)| {
			let block = trie.snapshot();
			let extrinsic = trie.snapshot();
			assert!(trie.remove(key).unwrap().is_none());
			trie.discard_from(&extrinsic).unwrap();
			let arena_len = trie.arena_len();
			if number % 2 == 1 {
				trie.rollback_to(&block).unwrap();
			}
			trie.discard_from(&block).unwrap();
			arena_len
		})
		.collect();
	assert_stays_flat(&arena_per_block);
}

test_layouts!(commits_under_a_block_snapshot_keep_arena_flat, commits_under_a_block_internal);
/// Extrinsics commit one after another under a block snapshot that already kept nodes alive. Each
/// commit must free exactly the slots its extrinsic emptied above the block's freeze line, or the
/// arena grows per extrinsic. The nodes the block keeps must stay, or its rollback loses them.
fn commits_under_a_block_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, k3_removed) = real_session::<T, _>(&db, root, &[K3], &keys);
	let (_, k3_and_k2_removed) = real_session::<T, _>(&db, root, &[K3, K2], &keys);
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	trie.remove(K3).unwrap();
	let block = trie.snapshot();
	trie.remove(K2).unwrap();

	let commit =
		|trie: &mut AppendOnlyTrieDBMut<T>, extrinsic: &_, _| trie.discard_from(extrinsic).unwrap();
	assert_stays_flat(&arena_per_extrinsic(&mut trie, commit));
	assert_eq!(read_keys(&trie, &keys), k3_and_k2_removed);
	trie.rollback_to(&block).unwrap();
	assert_eq!(read_keys(&trie, &keys), k3_removed);
}

/// A trie as `block_start_trie` whose arena has free slots: leaves inserted under empty nibbles of
/// the root and removed again.
fn trie_with_free_slots<'a, T: TrieLayout>(
	detached: &'a mut DetachedTrieDBMut<T>,
	db: &'a PrefixedMemoryDB<T>,
) -> AppendOnlyTrieDBMut<'a, T> {
	let leaves = [0x60u8, 0x70, 0x80, 0x90].map(|byte| vec![byte, 0x77]);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(db, detached).build();
	let mut insert_and_remove = |trie: &mut AppendOnlyTrieDBMut<T>| {
		for leaf in &leaves {
			trie.insert(leaf, &[5; 40]).unwrap();
		}
		let holding_leaves = trie.arena_len();
		for leaf in &leaves {
			trie.remove(leaf).unwrap();
		}
		holding_leaves
	};
	let first = insert_and_remove(&mut trie);
	// The trie holds the leaves again without a larger arena, so they went to freed slots.
	assert_eq!(insert_and_remove(&mut trie), first);
	trie
}

test_layouts!(free_slot_under_the_freeze_is_reused_again, free_slot_under_the_freeze_internal);
/// A slot that was free when the newest snapshot was taken is in no snapshot. A change after the
/// snapshot may write it, and once a later change empties it again it must be reused, or every
/// snapshot costs the arena each free slot under it.
fn free_slot_under_the_freeze_internal<T: TrieLayout>() {
	let (db, root, _) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = trie_with_free_slots(&mut detached, &db);
	let _snapshot = trie.snapshot();
	assert_absent_removals_reuse_slots(&mut trie, &absent_keys_under_k1());
}

test_layouts!(
	rollback_after_repeated_reuse_frees_each_slot_once,
	rollback_after_repeated_reuse_frees_each_slot_once_internal
);
/// Every change after the snapshot writes and empties the same free slots again. A rollback must
/// free each of them once: a slot freed twice is handed to two nodes, which then overwrite each
/// other.
fn rollback_after_repeated_reuse_frees_each_slot_once_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	// More nodes than the rollback frees, so that every freed slot is written again.
	let inserted: Vec<Vec<u8>> = (0..8u8).map(|byte| vec![0xE0, byte, 0x55]).collect();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = trie_with_free_slots(&mut detached, &db);
	let before = read_keys(&trie, &keys);
	let snapshot = trie.snapshot();
	for key in &absent_keys_under_k1()[..5] {
		assert!(trie.remove(key).unwrap().is_none());
	}

	trie.rollback_to(&snapshot).unwrap();
	for key in &inserted {
		trie.insert(key, &[4; 40]).unwrap();
	}
	assert_eq!(read_keys(&trie, &keys), before);
	assert!(read_keys(&trie, &inserted).iter().all(|value| *value == Some(vec![4; 40])));
	for key in keys.iter().chain(&inserted) {
		trie.remove(key).unwrap();
	}
	assert!(trie.is_empty());
}

test_layouts!(
	reused_slots_emptied_out_of_order_are_freed,
	reused_slots_emptied_out_of_order_are_freed_internal
);
/// Changes after a snapshot write free slots and empty them again in any order, not only the
/// newest first. Each emptied slot must be freed once, so that the arena does not grow and no
/// slot is handed to two nodes, and the rollback must restore the trie of the snapshot.
fn reused_slots_emptied_out_of_order_are_freed_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let leaves = [0x60u8, 0x70, 0x80].map(|byte| vec![byte, 0x77]);
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = trie_with_free_slots(&mut detached, &db);
	let before = read_keys(&trie, &keys);
	let snapshot = trie.snapshot();
	for leaf in &leaves {
		trie.insert(leaf, &[6; 40]).unwrap();
	}
	let holding_leaves = trie.arena_len();
	for leaf in [&leaves[1], &leaves[2], &leaves[0]] {
		trie.remove(leaf).unwrap();
	}

	for leaf in &leaves {
		trie.insert(leaf, &[7; 40]).unwrap();
	}
	assert_eq!(trie.arena_len(), holding_leaves);
	assert_eq!(read_keys(&trie, &keys), before);
	assert!(read_keys(&trie, &leaves).iter().all(|value| *value == Some(vec![7; 40])));
	trie.rollback_to(&snapshot).unwrap();
	assert_eq!(read_keys(&trie, &keys), before);
	assert!(read_keys(&trie, &leaves).iter().all(Option::is_none));
}

test_layouts!(discard_keeps_the_parent_snapshot, discard_keeps_the_parent_snapshot_internal);
/// Committing a nested transaction discards its snapshot while the outer one may still roll
/// back. The discard must keep the nodes the outer snapshot needs, even once later changes reuse
/// the freed slots.
fn discard_keeps_the_parent_snapshot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, k3_removed) = real_session::<T, _>(&db, root, &[K3], &keys);
	let (_, k3_and_k1_removed) = real_session::<T, _>(&db, root, &[K3, K1], &keys);
	// More nodes than the discard frees, so that every freed slot is written again.
	let inserted: Vec<Vec<u8>> = (0..8u8).map(|byte| vec![0xE0, byte, 0x55]).collect();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	trie.remove(K3).unwrap();
	let parent = trie.snapshot();
	let child = trie.snapshot();
	trie.remove(K1).unwrap();

	trie.discard_from(&child).unwrap();
	assert_eq!(read_keys(&trie, &keys), k3_and_k1_removed);
	for key in &inserted {
		trie.insert(key, &[4; 40]).unwrap();
	}
	assert_eq!(trie.rollback_to(&child), Err(InvalidSnapshot));
	trie.rollback_to(&parent).unwrap();
	assert_eq!(read_keys(&trie, &keys), k3_removed);
	assert!(read_keys(&trie, &inserted).iter().all(Option::is_none));
}

test_layouts!(discard_after_a_rollback_keeps_the_trie, discard_after_a_rollback_internal);
/// A failed nested transaction rolls back and discards its snapshot, then the outer one commits.
/// The nodes the rolled back changes took out are part of the trie again, so the discards must
/// not reuse their slots.
fn discard_after_a_rollback_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, k3_removed) = real_session::<T, _>(&db, root, &[K3], &keys);
	let inserted: Vec<Vec<u8>> = (0..8u8).map(|byte| vec![0xE0, byte, 0x55]).collect();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let outer = trie.snapshot();
	trie.remove(K3).unwrap();
	let nested = trie.snapshot();
	trie.remove(K1).unwrap();
	trie.rollback_to(&nested).unwrap();

	trie.discard_from(&nested).unwrap();
	trie.discard_from(&outer).unwrap();
	for key in &inserted {
		trie.insert(key, &[4; 40]).unwrap();
	}
	assert_eq!(read_keys(&trie, &keys), k3_removed);
	assert!(read_keys(&trie, &inserted).iter().all(|value| *value == Some(vec![4; 40])));
}

test_layouts!(
	discard_after_a_rollback_restores_the_nesting,
	discard_after_a_rollback_restores_the_nesting_internal
);
/// A rollback keeps its snapshot, so a failed extrinsic rolls back and then discards it. That
/// must leave only the enclosing snapshots: the extrinsic's snapshot is refused, the block's
/// still rolls back, and failed extrinsics do not grow the arena.
fn discard_after_a_rollback_restores_the_nesting_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let before = read_keys(&trie, &keys);
	let block = trie.snapshot();
	trie.remove(K1).unwrap();

	assert_stays_flat(&arena_per_extrinsic(&mut trie, |trie, extrinsic, _| {
		trie.rollback_to(extrinsic).unwrap();
		trie.discard_from(extrinsic).unwrap();
		assert_eq!(trie.rollback_to(extrinsic), Err(InvalidSnapshot));
	}));
	trie.rollback_to(&block).unwrap();
	assert_eq!(read_keys(&trie, &keys), before);
}

test_layouts!(
	discard_from_the_oldest_drops_every_snapshot,
	discard_from_the_oldest_drops_every_snapshot_internal
);
/// Between transactions nothing can be rolled back, so every snapshot is discarded. The trie
/// must stay as it is, refuse the discarded snapshots and support new ones.
fn discard_from_the_oldest_drops_every_snapshot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, k3_and_k1_removed) = real_session::<T, _>(&db, root, &[K3, K1], &keys);
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let initial = detached.snapshot();
	session::<T>(&mut detached, &db, |trie| {
		trie.remove(K3).unwrap();
	});
	let after_k3 = detached.snapshot();
	session::<T>(&mut detached, &db, |trie| {
		trie.remove(K1).unwrap();
	});

	detached.discard_from(&initial).unwrap();
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_and_k1_removed);
	assert_eq!(detached.rollback_to(&initial), Err(InvalidSnapshot));
	assert_eq!(detached.rollback_to(&after_k3), Err(InvalidSnapshot));
	assert_eq!(detached.discard_from(&after_k3), Err(InvalidSnapshot));
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_and_k1_removed);

	let fresh = detached.snapshot();
	session::<T>(&mut detached, &db, |trie| {
		trie.remove(K2).unwrap();
	});
	detached.rollback_to(&fresh).unwrap();
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_and_k1_removed);
}

test_layouts!(discard_of_an_invalid_snapshot_is_refused, discard_of_an_invalid_snapshot_internal);
/// Discarding a snapshot that is already dropped, or one of another trie, must be refused
/// without discarding anything: the live snapshots must still restore their own trie.
fn discard_of_an_invalid_snapshot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, k2_removed) = real_session::<T, _>(&db, root, &[K2], &keys);
	let (_, k2_and_k3_removed) = real_session::<T, _>(&db, root, &[K2, K3], &keys);
	let foreign = DetachedTrieDBMut::<T>::new(Default::default()).snapshot();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(&db, &mut detached).build();
	let outer = trie.snapshot();
	trie.remove(K1).unwrap();
	let rolled_back = trie.snapshot();
	trie.rollback_to(&outer).unwrap();
	trie.remove(K2).unwrap();
	let inner = trie.snapshot();
	trie.remove(K3).unwrap();
	let discarded = trie.snapshot();
	trie.discard_from(&discarded).unwrap();

	assert_eq!(trie.discard_from(&rolled_back), Err(InvalidSnapshot));
	assert_eq!(trie.discard_from(&discarded), Err(InvalidSnapshot));
	assert_eq!(trie.discard_from(&foreign), Err(InvalidSnapshot));
	assert_eq!(read_keys(&trie, &keys), k2_and_k3_removed);
	trie.remove(K1).unwrap();
	trie.rollback_to(&inner).unwrap();
	assert_eq!(read_keys(&trie, &keys), k2_removed);
}

const FIRST: &[u8] = &[0xF0, 0x33];
const SECOND: &[u8] = &[0x40, 0x33];

/// A trie with a block snapshot and an extrinsic snapshot, and free slots between their freeze
/// lines. Returns the trie and the extrinsic snapshot.
fn extrinsic_over_free_slots<'a, T: TrieLayout>(
	detached: &'a mut DetachedTrieDBMut<T>,
	db: &'a PrefixedMemoryDB<T>,
) -> (AppendOnlyTrieDBMut<'a, T>, TrieDBMutSnapshot<T>) {
	session::<T>(detached, db, |trie| {
		trie.remove(K3).unwrap();
	});
	let _block = detached.snapshot();
	let mut trie = trie_with_free_slots(detached, db);
	let extrinsic = trie.snapshot();
	(trie, extrinsic)
}

/// Takes a snapshot, inserts new keys, removes `FIRST` and inserts `SECOND` into the freed slots.
/// The trie must hold exactly these changes, and a rollback must restore the trie of the snapshot.
fn assert_removal_of_first_rolls_back<T: TrieLayout>(
	trie: &mut AppendOnlyTrieDBMut<T>,
	keys: &[Vec<u8>],
) {
	let inserted: Vec<Vec<u8>> = (0..8u8).map(|byte| vec![0xE0, byte, 0x55]).collect();
	let before = read_keys(trie, keys);
	let snapshot = trie.snapshot();
	for key in &inserted {
		trie.insert(key, &[4; 40]).unwrap();
	}
	trie.remove(FIRST).unwrap();
	trie.insert(SECOND, &[2; 40]).unwrap();
	assert_eq!(read_keys(trie, keys), before);
	assert!(read_keys(trie, &inserted).iter().all(|value| *value == Some(vec![4; 40])));
	assert_eq!(trie.get(FIRST).unwrap(), None);
	assert_eq!(trie.get(SECOND).unwrap(), Some(vec![2; 40]));

	trie.rollback_to(&snapshot).unwrap();
	assert_eq!(read_keys(trie, keys), before);
	assert!(read_keys(trie, &inserted).iter().all(Option::is_none));
	assert_eq!(trie.get(FIRST).unwrap(), Some(vec![1; 40]));
	assert_eq!(trie.get(SECOND).unwrap(), None);
}

test_layouts!(
	discarded_reuse_does_not_free_a_protected_slot,
	discarded_reuse_does_not_free_a_protected_slot_internal
);
/// An extrinsic writes `FIRST` to free slots between the block's freeze line and its own, then
/// commits. The block's snapshot never saw those slots, so the discard forgets that they were
/// reused, but `FIRST` stays in the trie. The next snapshot needs its nodes: removing `FIRST`
/// after it must keep them, or their slots are handed out again and the rollback loses `FIRST`.
fn discarded_reuse_does_not_free_a_protected_slot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let (mut trie, extrinsic) = extrinsic_over_free_slots(&mut detached, &db);
	trie.insert(FIRST, &[1; 40]).unwrap();
	trie.discard_from(&extrinsic).unwrap();
	assert_removal_of_first_rolls_back(&mut trie, &keys);
}

test_layouts!(
	rolled_back_reuse_does_not_free_a_protected_slot,
	rolled_back_reuse_does_not_free_a_protected_slot_internal
);
/// A failed extrinsic writes `FIRST` to free slots between the block's freeze line and its own,
/// then rolls back and discards its snapshot. The rollback frees those slots and forgets that
/// they were reused. Above the block's freeze line, writing `FIRST` again takes them without a
/// record. The next snapshot needs its nodes: removing `FIRST` after it must keep them, or their
/// slots are handed out again and the rollback loses `FIRST`.
fn rolled_back_reuse_does_not_free_a_protected_slot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let (mut trie, extrinsic) = extrinsic_over_free_slots(&mut detached, &db);
	trie.insert(FIRST, &[1; 40]).unwrap();
	trie.rollback_to(&extrinsic).unwrap();
	trie.discard_from(&extrinsic).unwrap();
	trie.insert(FIRST, &[1; 40]).unwrap();
	assert_removal_of_first_rolls_back(&mut trie, &keys);
}

/// A database that lost some nodes, so that a removal fails half way with a trie error.
struct MissingNodes<'a, T: TrieLayout> {
	db: &'a PrefixedMemoryDB<T>,
	missing: Vec<TrieHash<T>>,
}

impl<T: TrieLayout> HashDBRef<T::Hash, DBValue> for MissingNodes<'_, T> {
	fn get(&self, key: &TrieHash<T>, prefix: Prefix) -> Option<DBValue> {
		if self.missing.contains(key) {
			return None
		}
		HashDBRef::get(self.db, key, prefix)
	}

	fn contains(&self, key: &TrieHash<T>, prefix: Prefix) -> bool {
		self.get(key, prefix).is_some()
	}
}

test_layouts!(failed_removal_keeps_trie_in_slot, failed_removal_keeps_trie_in_slot_internal);
/// The PoV estimator keeps the trie in a slot across transactions. A removal failing half way
/// must leave the trie in that slot, so that rolling the transaction back restores it and later
/// estimations load and record what they would have without the failed one.
fn failed_removal_keeps_trie_in_slot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (real_k3, k3_removed) = real_session::<T, _>(&db, root, &[K3], &keys);
	let (real_k1, _) = real_session::<T, _>(&db, root, &[K1], &keys);
	let (real_k3_k1, k3_and_k1_removed) = real_session::<T, _>(&db, root, &[K3, K1], &keys);
	let missing_on_k1_path: Vec<_> =
		real_k1.keys().filter(|hash| !real_k3.contains_key(*hash)).copied().collect();
	assert!(!missing_on_k1_path.is_empty());
	let corrupt = MissingNodes::<T> { db: &db, missing: missing_on_k1_path };

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	let mut recorded = session::<T>(&mut detached, &db, |trie| {
		trie.remove(K3).unwrap();
	});
	let before_failure = detached.snapshot();
	session::<T>(&mut detached, &corrupt, |trie| {
		assert!(trie.remove(K1).is_err());
	});

	detached.rollback_to(&before_failure).unwrap();
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_removed);
	recorded.extend(session::<T>(&mut detached, &db, |trie| {
		trie.remove(K1).unwrap();
	}));
	assert_eq!(recorded, real_k3_k1);
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_and_k1_removed);
}

test_layouts!(panicking_session_keeps_trie_in_slot, panicking_session_keeps_trie_in_slot_internal);
/// A panic unwinding through a session must leave the trie in its slot as the panic found it,
/// changes made before the panic included, so that a rollback can restore it.
fn panicking_session_keeps_trie_in_slot_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, k3_removed) = real_session::<T, _>(&db, root, &[K3], &keys);
	let (_, k3_and_k1_removed) = real_session::<T, _>(&db, root, &[K3, K1], &keys);

	let mut detached = DetachedTrieDBMut::<T>::new(root);
	session::<T>(&mut detached, &db, |trie| {
		trie.remove(K3).unwrap();
	});
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_removed);

	let snapshot = detached.snapshot();
	let unwound = catch_unwind(AssertUnwindSafe(|| {
		session::<T>(&mut detached, &db, |trie| {
			trie.remove(K1).unwrap();
			panic!("panic after a removal");
		})
	}));
	assert!(unwound.is_err());
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_and_k1_removed);

	detached.rollback_to(&snapshot).unwrap();
	assert_eq!(contents::<T>(&mut detached, &db, &keys), k3_removed);
}

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

use std::collections::BTreeMap;

use hash_db::Hasher;
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

fn pristine<T: TrieLayout>(db: &PrefixedMemoryDB<T>, root: TrieHash<T>) -> DetachedTrieDBMut<T> {
	AppendOnlyTrieDBMutBuilder::<T>::from_existing(db, root).build().detach()
}

/// One append-only session over `detached`, with a fresh recorder like the PoV estimator takes
/// on every size estimation call. Returns the detached state and the nodes recorded in it.
fn session<T: TrieLayout>(
	detached: DetachedTrieDBMut<T>,
	db: &PrefixedMemoryDB<T>,
	operations: impl FnOnce(&mut AppendOnlyTrieDBMut<T>),
) -> (DetachedTrieDBMut<T>, Nodes<T>) {
	let mut recorder = Recorder::<T>::new();
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_detached(db, detached)
		.with_recorder(&mut recorder)
		.build();
	operations(&mut trie);
	let detached = trie.detach();
	(detached, drain(recorder))
}

fn contents<T: TrieLayout>(
	detached: DetachedTrieDBMut<T>,
	db: &PrefixedMemoryDB<T>,
	probed: &[Vec<u8>],
) -> (DetachedTrieDBMut<T>, Vec<Option<DBValue>>) {
	let mut values = Vec::new();
	let (detached, _) = session::<T>(detached, db, |trie| values = read_keys(trie, probed));
	(detached, values)
}

test_layouts!(joint_collapse_across_sessions_is_recorded, joint_collapse_across_sessions_internal);
/// The bug this mode fixes: when each delete is replayed from the pristine root, a collapse that
/// only happens because of an earlier delete (here A collapsing into L3) is never recorded and the
/// proof size is under-estimated.
fn joint_collapse_across_sessions_internal<T: TrieLayout>() {
	for order in [[K1, K2], [K2, K1]] {
		let (db, root, _) = block_start_trie::<T>();
		let (real, _) = real_session::<T, _>(&db, root, &order, &[]);

		let mut detached = pristine::<T>(&db, root);
		let mut recorded = Nodes::<T>::new();
		for key in order {
			let (next, nodes) = session::<T>(detached, &db, |trie| {
				trie.remove(key).unwrap();
			});
			detached = next;
			recorded.extend(nodes);
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

	let (detached, mut recorded) = session::<T>(pristine::<T>(&db, root), &db, |trie| {
		trie.remove(K1).unwrap();
		let snapshot = trie.snapshot();
		trie.remove(K2).unwrap();
		trie.rollback_to(&snapshot).unwrap();
	});
	let (detached, values) = contents::<T>(detached, &db, &keys);
	assert_eq!(values[keys.iter().position(|key| key == K2).unwrap()], Some(vec![2u8; 64]));
	assert_eq!(values, only_k1_removed);

	let (detached, nodes) = session::<T>(detached, &db, |trie| {
		trie.remove(K2).unwrap();
	});
	recorded.extend(nodes);
	assert_eq!(recorded, real);
	assert_eq!(contents::<T>(detached, &db, &keys).1, real_contents);
}

test_layouts!(nested_rollbacks_restore_pristine_trie, nested_rollbacks_internal);
/// Nested runtime transactions roll back innermost first; after both, the trie must be pristine
/// and the nodes loaded inside them must be loaded (and recorded) again when needed.
fn nested_rollbacks_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, pristine_contents) = real_session::<T, &[u8]>(&db, root, &[], &keys);
	let (real_k1, _) = real_session::<T, _>(&db, root, &[K1], &keys);

	let (detached, _) = session::<T>(pristine::<T>(&db, root), &db, |trie| {
		let outer = trie.snapshot();
		trie.remove(K1).unwrap();
		let inner = trie.snapshot();
		trie.remove(K2).unwrap();
		trie.rollback_to(&inner).unwrap();
		trie.rollback_to(&outer).unwrap();
	});
	let (detached, values) = contents::<T>(detached, &db, &keys);
	assert_eq!(values, pristine_contents);

	let (_, recorded) = session::<T>(detached, &db, |trie| {
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

	let mut never_mutated = pristine::<T>(&db, root);
	let initial = never_mutated.snapshot();
	never_mutated.rollback_to(&initial).unwrap();
	assert_eq!(contents::<T>(never_mutated, &db, &keys).1, pristine_contents);

	let (mut emptied, _) = session::<T>(pristine::<T>(&db, root), &db, |trie| {
		for key in &keys {
			trie.remove(key).unwrap();
		}
		assert!(trie.is_empty());
	});
	emptied.rollback_to(&initial).unwrap();
	let (emptied, values) = contents::<T>(emptied, &db, &keys);
	assert_eq!(values, pristine_contents);
	let (_, recorded) = session::<T>(emptied, &db, |trie| {
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

	let (mut detached, _) = session::<T>(pristine::<T>(&db, root), &db, |trie| {
		trie.remove(K1).unwrap();
	});
	let snapshot = detached.snapshot();
	let (mut detached, _) = session::<T>(detached, &db, |trie| {
		trie.remove(K2).unwrap();
		trie.remove(K3).unwrap();
	});
	detached.rollback_to(&snapshot).unwrap();
	let (detached, values) = contents::<T>(detached, &db, &keys);
	assert_eq!(values, only_k1_removed);

	let (detached, _) = session::<T>(detached, &db, |trie| {
		trie.remove(K3).unwrap();
	});
	assert_eq!(contents::<T>(detached, &db, &keys).1, k1_and_k3_removed);
}

test_layouts!(removing_missing_key_is_harmless, removing_missing_key_internal);
/// Extrinsics may delete keys that do not exist; that must not corrupt the trie.
fn removing_missing_key_internal<T: TrieLayout>() {
	let (db, root, keys) = block_start_trie::<T>();
	let (_, pristine_contents) = real_session::<T, &[u8]>(&db, root, &[], &keys);

	let (detached, _) = session::<T>(pristine::<T>(&db, root), &db, |trie| {
		assert!(trie.remove(&[0x50, 0x00, 0xAA, 0xAB]).unwrap().is_none());
		assert!(trie.remove(&[0x50, 0x20]).unwrap().is_none());
	});
	assert_eq!(contents::<T>(detached, &db, &keys).1, pristine_contents);
}

/// Checks the append-only state against a real session removing only the deletes that survived
/// every rollback: same contents, and the same recorded nodes.
fn assert_matches_real<T: TrieLayout>(
	db: &PrefixedMemoryDB<T>,
	root: TrieHash<T>,
	detached: DetachedTrieDBMut<T>,
	keys: &[Vec<u8>],
	surviving_deletes: &[Vec<u8>],
	recorded: &Nodes<T>,
) -> DetachedTrieDBMut<T> {
	let (real, real_contents) = real_session::<T, _>(db, root, surviving_deletes, keys);
	assert_eq!(recorded, &real);
	let (detached, values) = contents::<T>(detached, db, keys);
	assert_eq!(values, real_contents);
	detached
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

	let mut detached = pristine::<T>(&db, root);
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
				detached =
					assert_matches_real(&db, root, detached, &keys, &surviving_deletes, &recorded);
			},
			_ => {
				let live: Vec<_> =
					keys.iter().filter(|key| !surviving_deletes.contains(key)).cloned().collect();
				let batch: Vec<_> = (0..rng.gen_range(1..=3))
					.filter_map(|_| live.get(rng.gen_range(0..live.len().max(1))).cloned())
					.collect();
				let (next, nodes) = session::<T>(detached, &db, |trie| {
					for key in &batch {
						trie.remove(key).unwrap();
					}
				});
				detached = next;
				recorded.extend(nodes);
				surviving_deletes.extend(batch);
			},
		}
	}
	assert_matches_real(&db, root, detached, &keys, &surviving_deletes, &recorded);
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
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_existing(&db, root).build();
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
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_existing(&db, root).build();

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
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_existing(&db, root).build();
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
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_existing(&db, root).build();
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

	let (detached, mut recorded) = session::<T>(pristine::<T>(&db, root), &db, |trie| {
		trie.remove(K3).unwrap();
		let snapshot = trie.snapshot();
		trie.remove(K1).unwrap();
		trie.remove(K2).unwrap();
		trie.rollback_to(&snapshot).unwrap();
	});
	let (detached, values) = contents::<T>(detached, &db, &keys);
	assert_eq!(values, k3_removed);

	let (detached, nodes) = session::<T>(detached, &db, |trie| {
		trie.remove(K1).unwrap();
		trie.remove(K2).unwrap();
	});
	recorded.extend(nodes);
	assert_eq!(recorded, real);
	assert_eq!(contents::<T>(detached, &db, &keys).1, all_removed);
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
	let mut trie = AppendOnlyTrieDBMutBuilder::<T>::from_existing(&db, root).build();

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

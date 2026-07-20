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

use hash_db::{HashDB, HashDBRef, Hasher, EMPTY_PREFIX};
use reference_trie::{test_layouts, ExtensionLayout};
use std::collections::{BTreeMap, BTreeSet};
use trie_db::{
	decode_compact, decode_compact_from_iter_with_known_items, encode_compact,
	encode_compact_skip_duplicates, DBValue, NodeCodec, Recorder, Trie, TrieDBBuilder,
	TrieDBMutBuilder, TrieError, TrieLayout, TrieMut,
};

type MemoryDB<T> = memory_db::MemoryDB<
	<T as TrieLayout>::Hash,
	memory_db::HashKey<<T as TrieLayout>::Hash>,
	DBValue,
>;

type PrefixedMemoryDB<T> = memory_db::MemoryDB<
	<T as TrieLayout>::Hash,
	memory_db::PrefixedKey<<T as TrieLayout>::Hash>,
	DBValue,
>;

fn test_encode_compact<L: TrieLayout>(
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

	// Lookup items in trie while recording traversed nodes.
	let mut recorder = Recorder::<L>::new();
	let items = {
		let mut items = Vec::with_capacity(keys.len());
		let trie = <TrieDBBuilder<L>>::new(&db, &root).with_recorder(&mut recorder).build();
		for key in keys {
			let value = trie.get(key).unwrap();
			items.push((key, value));
		}
		items
	};

	// Populate a partial trie DB with recorded nodes.
	let mut partial_db = MemoryDB::<L>::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	// Compactly encode the partial trie DB.
	let compact_trie = {
		let trie = <TrieDBBuilder<L>>::new(&partial_db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};

	(root, compact_trie, items)
}

fn test_decode_compact<L: TrieLayout>(
	mut db: impl HashDB<L::Hash, DBValue> + HashDBRef<L::Hash, DBValue>,
	encoded: &[Vec<u8>],
	items: &[(&'static [u8], Option<DBValue>)],
	expected_root: <L::Hash as Hasher>::Out,
	expected_used: usize,
) {
	// Reconstruct the partial DB from the compact encoding.
	let (root, used) = decode_compact::<L, _>(&mut db, encoded).unwrap();
	assert_eq!(root, expected_root);
	assert_eq!(used, expected_used);

	// Check that lookups for all items succeed.
	let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
	for (key, expected_value) in items {
		assert_eq!(&trie.get(key).unwrap(), expected_value);
	}
}

test_layouts!(trie_compact_encoding_works, trie_compact_encoding_works_internal);
fn trie_compact_encoding_works_internal<T: TrieLayout>() {
	let (root, mut encoded, items) = test_encode_compact::<T>(
		vec![
			// "alfa" is at a hash-referenced leaf node.
			(b"alfa", &[0; 32]),
			// "bravo" is at an inline leaf node.
			(b"bravo", b"bravo"),
			// "do" is at a hash-referenced branch node.
			(b"do", b"verb"),
			// "dog" is at an inline leaf node.
			(b"dog", b"puppy"),
			// "doge" is at a hash-referenced leaf node.
			(b"doge", &[0; 32]),
			// extension node "o" (plus nibble) to next branch.
			(b"horse", b"stallion"),
			(b"house", b"building"),
		],
		vec![
			b"do", b"dog", b"doge", b"bravo",
			b"d",      // None, witness is extension node with omitted child
			b"do\x10", // None, empty branch child
			b"halp",   // None, witness is extension node with non-omitted child
		],
	);

	encoded.push(Vec::new()); // Add an extra item to ensure it is not read.
	test_decode_compact::<T>(MemoryDB::<T>::default(), &encoded, &items, root, encoded.len() - 1);
	test_decode_compact::<T>(
		PrefixedMemoryDB::<T>::default(),
		&encoded,
		&items,
		root,
		encoded.len() - 1,
	);
}

test_layouts!(
	trie_decoding_fails_with_incomplete_database,
	trie_decoding_fails_with_incomplete_database_internal
);
fn trie_decoding_fails_with_incomplete_database_internal<T: TrieLayout>() {
	let (_, encoded, _) =
		test_encode_compact::<T>(vec![(b"alfa", &[0; 32]), (b"bravo", b"bravo")], vec![b"alfa"]);

	assert!(encoded.len() > 1);

	// Reconstruct the partial DB from the compact encoding.
	let mut db = MemoryDB::<T>::default();
	match decode_compact::<T, _>(&mut db, &encoded[..encoded.len() - 1]) {
		Err(err) => match *err {
			TrieError::IncompleteDatabase(_) => {},
			_ => panic!("got unexpected TrieError"),
		},
		_ => panic!("decode was unexpectedly successful"),
	}
}

/// A value above every tested layout threshold — including the substrate-like threshold of 33 —
/// stored as a shared, hash-addressed value node.
const SHARED_VALUE: &[u8] = &[4; 33];

/// Whether the layout stores [`SHARED_VALUE`] as a separate value node.
fn has_value_nodes<T: TrieLayout>() -> bool {
	T::MAX_INLINE_VALUE.map_or(false, |threshold| threshold as usize <= SHARED_VALUE.len())
}

/// Count the encoded items that consist of exactly the shared value, i.e. its detached copies.
fn count_shared_value_items(encoded: &[Vec<u8>]) -> usize {
	encoded.iter().filter(|item| item.as_slice() == SHARED_VALUE).count()
}

/// Entries where five nodes (one branch with value, four leaves) reference the shared value.
fn shared_value_entries() -> Vec<(&'static [u8], &'static [u8])> {
	vec![
		// "key" is at a branch node carrying the shared value.
		(b"key", SHARED_VALUE),
		(b"key1", SHARED_VALUE),
		(b"key2", SHARED_VALUE),
		(b"key3", SHARED_VALUE),
		// A distinct value node, must not be affected by deduplication.
		(b"key4", &[5; 32]),
		// A leaf in an unrelated part of the trie, referencing the shared value.
		(b"other", SHARED_VALUE),
	]
}

fn build_trie<T: TrieLayout>(
	entries: &[(&'static [u8], &'static [u8])],
) -> (MemoryDB<T>, <T::Hash as Hasher>::Out) {
	let mut db = <MemoryDB<T>>::default();
	let mut root = Default::default();
	{
		let mut trie = <TrieDBMutBuilder<T>>::new(&mut db, &mut root).build();
		for (key, value) in entries.iter() {
			trie.insert(key, value).unwrap();
		}
	}
	(db, root)
}

fn assert_entries_match<T: TrieLayout>(
	db: &(impl HashDB<T::Hash, DBValue> + HashDBRef<T::Hash, DBValue>),
	root: <T::Hash as Hasher>::Out,
	entries: &[(&'static [u8], &'static [u8])],
) {
	let trie = <TrieDBBuilder<T>>::new(db, &root).build();
	for (key, value) in entries.iter() {
		assert_eq!(trie.get(key).unwrap().as_deref(), Some(*value));
	}
}

test_layouts!(
	skip_duplicate_values_emits_shared_values_once,
	skip_duplicate_values_emits_shared_values_once_internal
);
fn skip_duplicate_values_emits_shared_values_once_internal<T: TrieLayout>() {
	let entries = shared_value_entries();
	let (db, root) = build_trie::<T>(&entries);

	let trie = <TrieDBBuilder<T>>::new(&db, &root).build();
	let encoded = encode_compact::<T>(&trie).unwrap();
	let deduplicated = encode_compact_skip_duplicates::<T>(&trie, &mut Default::default()).unwrap();

	if has_value_nodes::<T>() {
		// One detached copy per referencing node without deduplication...
		assert_eq!(count_shared_value_items(&encoded), 5);
		// ...exactly one with it.
		assert_eq!(count_shared_value_items(&deduplicated), 1);
		// Four duplicate value copies are skipped, and the leaves of "key2" and "key3" — encoded
		// identically to the "key1" leaf (same partial, same value hash) — are deduplicated at
		// the node level.
		assert_eq!(deduplicated.len(), encoded.len() - 4 - 2);
	} else {
		// Without value nodes there are no detached values to deduplicate, but the identical
		// leaves of "key2" and "key3" still are.
		assert_eq!(count_shared_value_items(&encoded), 0);
		assert_eq!(deduplicated.len(), encoded.len() - 2);
	}

	// The deduplicated encoding reconstructs a fully readable trie in a hash-keyed database...
	let mut hash_keyed_db = MemoryDB::<T>::default();
	let (decoded_root, used) = decode_compact::<T, _>(&mut hash_keyed_db, &deduplicated).unwrap();
	assert_eq!(decoded_root, root);
	assert_eq!(used, deduplicated.len());
	assert_entries_match::<T>(&hash_keyed_db, root, &entries);

	// ...and, via value re-insertion, in a position-keyed (prefixed) database as well.
	let mut prefixed_db = PrefixedMemoryDB::<T>::default();
	let (decoded_root, _) = decode_compact::<T, _>(&mut prefixed_db, &deduplicated).unwrap();
	assert_eq!(decoded_root, root);
	assert_entries_match::<T>(&prefixed_db, root, &entries);

	// Both encodings reconstruct identical databases: same entries, same reference counts.
	let mut expected_hash_keyed_db = MemoryDB::<T>::default();
	decode_compact::<T, _>(&mut expected_hash_keyed_db, &encoded).unwrap();
	assert!(hash_keyed_db == expected_hash_keyed_db && expected_hash_keyed_db == hash_keyed_db);
	let mut expected_prefixed_db = PrefixedMemoryDB::<T>::default();
	decode_compact::<T, _>(&mut expected_prefixed_db, &encoded).unwrap();
	assert!(prefixed_db == expected_prefixed_db && expected_prefixed_db == prefixed_db);
}

test_layouts!(
	skip_duplicate_values_handles_missing_value_nodes,
	skip_duplicate_values_handles_missing_value_nodes_internal
);
fn skip_duplicate_values_handles_missing_value_nodes_internal<T: TrieLayout>() {
	let entries = shared_value_entries();
	let (db, root) = build_trie::<T>(&entries);

	// Record all keys, but leave the shared value node out of the partial trie.
	let mut recorder = Recorder::<T>::new();
	{
		let trie = <TrieDBBuilder<T>>::new(&db, &root).with_recorder(&mut recorder).build();
		for (key, _) in entries.iter() {
			trie.get(key).unwrap();
		}
	}
	let mut partial_db = MemoryDB::<T>::default();
	for record in recorder.drain() {
		if record.data != SHARED_VALUE {
			partial_db.insert(EMPTY_PREFIX, &record.data);
		}
	}

	let trie = <TrieDBBuilder<T>>::new(&partial_db, &root).build();
	let encoded = encode_compact::<T>(&trie).unwrap();
	let deduplicated = encode_compact_skip_duplicates::<T>(&trie, &mut Default::default()).unwrap();

	// With no fetchable shared value there is nothing to detach: no encoded item is a standalone
	// value and the referencing nodes are emitted unmodified. The leaves of "key2" and "key3" —
	// encoded identically to the "key1" leaf — are still deduplicated at the node level.
	assert_eq!(count_shared_value_items(&encoded), 0);
	assert_eq!(count_shared_value_items(&deduplicated), 0);
	assert_eq!(deduplicated.len(), encoded.len() - 2);

	let mut decoded_db = MemoryDB::<T>::default();
	let (decoded_root, _) = decode_compact::<T, _>(&mut decoded_db, &deduplicated).unwrap();
	assert_eq!(decoded_root, root);

	// Node-level deduplication must not change the reconstructed database.
	let mut expected_db = MemoryDB::<T>::default();
	decode_compact::<T, _>(&mut expected_db, &encoded).unwrap();
	assert!(decoded_db == expected_db && expected_db == decoded_db);

	let trie = <TrieDBBuilder<T>>::new(&decoded_db, &root).build();
	// The distinct value is present either way.
	assert_eq!(trie.get(b"key4").unwrap().as_deref(), Some(&[5u8; 32][..]));
	if has_value_nodes::<T>() {
		// The shared value node is missing, so lookups must fail with an incomplete
		// database error.
		match trie.get(b"key1") {
			Err(err) => match *err {
				TrieError::IncompleteDatabase(_) => {},
				_ => panic!("got unexpected TrieError"),
			},
			_ => panic!("lookup was unexpectedly successful"),
		}
	} else {
		// Values are inline; filtering the standalone value node removed nothing.
		assert_entries_match::<T>(&decoded_db, root, &entries);
	}
}

#[test]
fn decode_compact_counts_attached_value_items() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	// A single entry: the encoding is exactly the escaped root leaf followed by its detached
	// value. The returned item count must include the value item.
	let (db, root) = build_trie::<L>(&[(b"key", SHARED_VALUE)]);
	let encoded = {
		let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};
	assert_eq!(encoded.len(), 2);
	assert_eq!(encoded[1].as_slice(), SHARED_VALUE);

	let mut decoded_db = MemoryDB::<L>::default();
	let (decoded_root, used) = decode_compact::<L, _>(&mut decoded_db, &encoded).unwrap();
	assert_eq!(decoded_root, root);
	assert_eq!(used, encoded.len());
}

#[test]
fn skip_duplicate_values_across_concatenated_encodings() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	// Two independent tries (think: a top trie and a child trie) sharing a value.
	let entries_a: Vec<(&'static [u8], &'static [u8])> =
		vec![(b"alpha1", SHARED_VALUE), (b"alpha2", SHARED_VALUE), (b"alpha3", &[7; 32])];
	let entries_b: Vec<(&'static [u8], &'static [u8])> =
		vec![(b"beta1", SHARED_VALUE), (b"beta2", SHARED_VALUE), (b"beta9", &[9; 32])];
	let (db_a, root_a) = build_trie::<L>(&entries_a);
	let (db_b, root_b) = build_trie::<L>(&entries_b);

	// Thread one seen-set through both encodings: the second references the shared value
	// without re-emitting it.
	let mut seen_hashes = BTreeSet::new();
	let encoded_a = {
		let trie = <TrieDBBuilder<L>>::new(&db_a, &root_a).build();
		encode_compact_skip_duplicates::<L>(&trie, &mut seen_hashes).unwrap()
	};
	let encoded_b = {
		let trie = <TrieDBBuilder<L>>::new(&db_b, &root_b).build();
		encode_compact_skip_duplicates::<L>(&trie, &mut seen_hashes).unwrap()
	};
	assert_eq!(count_shared_value_items(&encoded_a), 1);
	assert_eq!(count_shared_value_items(&encoded_b), 0);

	// Decode both with a threaded known-values map into one prefixed database.
	let mut prefixed_db = PrefixedMemoryDB::<L>::default();
	let mut known_items = BTreeMap::new();
	let (decoded_root_a, _) = decode_compact_from_iter_with_known_items::<L, _, _>(
		&mut prefixed_db,
		encoded_a.iter().map(Vec::as_slice),
		&mut known_items,
	)
	.unwrap();
	let (decoded_root_b, _) = decode_compact_from_iter_with_known_items::<L, _, _>(
		&mut prefixed_db,
		encoded_b.iter().map(Vec::as_slice),
		&mut known_items,
	)
	.unwrap();
	assert_eq!(decoded_root_a, root_a);
	assert_eq!(decoded_root_b, root_b);
	assert_entries_match::<L>(&prefixed_db, root_a, &entries_a);
	assert_entries_match::<L>(&prefixed_db, root_b, &entries_b);
}

/// Entries forming two identical subtrees below the root.
///
/// The mirrored keys diverge at their first nibble and share all following nibbles and values, so
/// the two subtrees below the root branch consist of identically encoded nodes: one branch
/// carrying two leaves (plus value nodes, for layouts detaching values; plus an extension node,
/// for layouts using them).
fn shared_subtree_entries() -> Vec<(&'static [u8], &'static [u8])> {
	vec![
		(b"\x00AAAA", SHARED_VALUE),
		(b"\x00AAAB", &[6; 32]),
		(b"\x10AAAA", SHARED_VALUE),
		(b"\x10AAAB", &[6; 32]),
		// An unrelated entry so the root is a branch with a third, distinct child.
		(b"\xf0ZZZZ", &[7; 32]),
	]
}

test_layouts!(
	skip_duplicates_emits_shared_subtrees_once,
	skip_duplicates_emits_shared_subtrees_once_internal
);
fn skip_duplicates_emits_shared_subtrees_once_internal<T: TrieLayout>() {
	let entries = shared_subtree_entries();
	let (db, root) = build_trie::<T>(&entries);

	let trie = <TrieDBBuilder<T>>::new(&db, &root).build();
	let encoded = encode_compact::<T>(&trie).unwrap();
	let deduplicated = encode_compact_skip_duplicates::<T>(&trie, &mut Default::default()).unwrap();

	// The mirrored subtree (and everything below it) is emitted only once; its second occurrence
	// stays a plain hash reference in the root node. This holds for every layout: node-level
	// deduplication does not depend on values being stored in separate value nodes.
	assert!(deduplicated.len() < encoded.len());

	// The deduplicated encoding reconstructs a fully readable trie in a hash-keyed database...
	let mut hash_keyed_db = MemoryDB::<T>::default();
	let (decoded_root, used) = decode_compact::<T, _>(&mut hash_keyed_db, &deduplicated).unwrap();
	assert_eq!(decoded_root, root);
	assert_eq!(used, deduplicated.len());
	assert_entries_match::<T>(&hash_keyed_db, root, &entries);

	// ...and, via subtree re-insertion, in a position-keyed (prefixed) database as well.
	let mut prefixed_db = PrefixedMemoryDB::<T>::default();
	let (decoded_root, _) = decode_compact::<T, _>(&mut prefixed_db, &deduplicated).unwrap();
	assert_eq!(decoded_root, root);
	assert_entries_match::<T>(&prefixed_db, root, &entries);

	// Both encodings reconstruct identical databases: same entries, same reference counts.
	let mut expected_hash_keyed_db = MemoryDB::<T>::default();
	decode_compact::<T, _>(&mut expected_hash_keyed_db, &encoded).unwrap();
	assert!(hash_keyed_db == expected_hash_keyed_db && expected_hash_keyed_db == hash_keyed_db);
	let mut expected_prefixed_db = PrefixedMemoryDB::<T>::default();
	decode_compact::<T, _>(&mut expected_prefixed_db, &encoded).unwrap();
	assert!(prefixed_db == expected_prefixed_db && expected_prefixed_db == prefixed_db);
}

#[test]
fn skip_duplicates_shares_subtrees_across_concatenated_encodings() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	// Two independent tries containing an identically encoded subtree: in both tries the
	// mirrored keys share all nibbles below the diverging first nibble.
	let entries_a: Vec<(&'static [u8], &'static [u8])> =
		vec![(b"\x00AAAA", SHARED_VALUE), (b"\x00AAAB", &[6; 32]), (b"\xf0ZZZZ", &[7; 32])];
	let entries_b: Vec<(&'static [u8], &'static [u8])> =
		vec![(b"\x10AAAA", SHARED_VALUE), (b"\x10AAAB", &[6; 32]), (b"\xe0YYYY", &[8; 32])];
	let (db_a, root_a) = build_trie::<L>(&entries_a);
	let (db_b, root_b) = build_trie::<L>(&entries_b);
	let trie_a = <TrieDBBuilder<L>>::new(&db_a, &root_a).build();
	let trie_b = <TrieDBBuilder<L>>::new(&db_b, &root_b).build();

	// Thread one seen-set through both encodings: the second references the shared subtree
	// without re-emitting it.
	let mut seen_hashes = BTreeSet::new();
	let encoded_a = encode_compact_skip_duplicates::<L>(&trie_a, &mut seen_hashes).unwrap();
	let encoded_b = encode_compact_skip_duplicates::<L>(&trie_b, &mut seen_hashes).unwrap();
	let standalone_b =
		encode_compact_skip_duplicates::<L>(&trie_b, &mut Default::default()).unwrap();
	assert!(encoded_b.len() < standalone_b.len());

	// Decode both with a threaded known-items map into one prefixed database.
	let mut prefixed_db = PrefixedMemoryDB::<L>::default();
	let mut known_items = BTreeMap::new();
	let (decoded_root_a, _) = decode_compact_from_iter_with_known_items::<L, _, _>(
		&mut prefixed_db,
		encoded_a.iter().map(Vec::as_slice),
		&mut known_items,
	)
	.unwrap();
	let (decoded_root_b, _) = decode_compact_from_iter_with_known_items::<L, _, _>(
		&mut prefixed_db,
		encoded_b.iter().map(Vec::as_slice),
		&mut known_items,
	)
	.unwrap();
	assert_eq!(decoded_root_a, root_a);
	assert_eq!(decoded_root_b, root_b);
	assert_entries_match::<L>(&prefixed_db, root_a, &entries_a);
	assert_entries_match::<L>(&prefixed_db, root_b, &entries_b);

	// Both encodings prove the shared subtree to the same depth, so this reproduces the plain
	// database exactly. In general the cross-encoding reconstruction is only a reference-count
	// superset of it (see `decode_compact_from_iter_with_known_items`).
	let mut expected_db = PrefixedMemoryDB::<L>::default();
	let plain_a = encode_compact::<L>(&trie_a).unwrap();
	let plain_b = encode_compact::<L>(&trie_b).unwrap();
	decode_compact::<L, _>(&mut expected_db, &plain_a).unwrap();
	decode_compact::<L, _>(&mut expected_db, &plain_b).unwrap();
	assert!(prefixed_db == expected_db && expected_db == prefixed_db);
}

#[test]
fn skip_duplicates_always_emits_the_root() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	let entries = shared_subtree_entries();
	let (db, root) = build_trie::<L>(&entries);
	let trie = <TrieDBBuilder<L>>::new(&db, &root).build();

	// Encode the same trie twice with one threaded seen-set. Everything is known when the second
	// encoding starts, but the root must still be emitted so the encoding stays individually
	// decodable; all its children collapse to plain hash references.
	let mut seen_hashes = BTreeSet::new();
	let first = encode_compact_skip_duplicates::<L>(&trie, &mut seen_hashes).unwrap();
	let second = encode_compact_skip_duplicates::<L>(&trie, &mut seen_hashes).unwrap();
	assert!(first.len() > 1);
	assert_eq!(second.len(), 1);

	// With a threaded known-items map, decoding the second encoding reconstructs the full
	// database below the root, exactly like decoding the first encoding twice would.
	let mut prefixed_db = PrefixedMemoryDB::<L>::default();
	let mut known_items = BTreeMap::new();
	let (decoded_root, _) = decode_compact_from_iter_with_known_items::<L, _, _>(
		&mut prefixed_db,
		first.iter().map(Vec::as_slice),
		&mut known_items,
	)
	.unwrap();
	assert_eq!(decoded_root, root);
	let (decoded_root, used) = decode_compact_from_iter_with_known_items::<L, _, _>(
		&mut prefixed_db,
		second.iter().map(Vec::as_slice),
		&mut known_items,
	)
	.unwrap();
	assert_eq!(decoded_root, root);
	assert_eq!(used, 1);
	assert_entries_match::<L>(&prefixed_db, root, &entries);

	let mut expected_db = PrefixedMemoryDB::<L>::default();
	decode_compact::<L, _>(&mut expected_db, &first).unwrap();
	decode_compact::<L, _>(&mut expected_db, &first).unwrap();
	assert!(prefixed_db == expected_db && expected_db == prefixed_db);
}

#[test]
fn encoding_node_owned_and_decoding_node_works() {
	let entries: Vec<(&[u8], &[u8])> = vec![
		// "alfa" is at a hash-referenced leaf node.
		(b"alfa", &[0; 32]),
		// "bravo" is at an inline leaf node.
		(b"bravo", b"bravo"),
		// "do" is at a hash-referenced branch node.
		(b"do", b"verb"),
		// "dog" is at an inline leaf node.
		(b"dog", b"puppy"),
		// "doge" is at a hash-referenced leaf node.
		(b"doge", &[0; 32]),
		// extension node "o" (plus nibble) to next branch.
		(b"horse", b"stallion"),
		(b"house", b"building"),
	];

	// Populate DB with full trie from entries.
	let mut recorder = {
		let mut db = <MemoryDB<ExtensionLayout>>::default();
		let mut root = Default::default();
		let mut recorder = Recorder::<ExtensionLayout>::new();
		{
			let mut trie = <TrieDBMutBuilder<ExtensionLayout>>::new(&mut db, &mut root).build();
			for (key, value) in entries.iter() {
				trie.insert(key, value).unwrap();
			}
		}

		let trie = TrieDBBuilder::<ExtensionLayout>::new(&db, &root)
			.with_recorder(&mut recorder)
			.build();
		for (key, _) in entries.iter() {
			trie.get(key).unwrap();
		}

		recorder
	};

	for record in recorder.drain() {
		let node =
			<<ExtensionLayout as TrieLayout>::Codec as NodeCodec>::decode(&record.data).unwrap();
		let node_owned = node.to_owned_node::<ExtensionLayout>().unwrap();

		assert_eq!(record.data, node_owned.to_encoded::<<ExtensionLayout as TrieLayout>::Codec>());
	}
}

#[test]
fn deduplicated_encoding_decodes_with_released_0_31_decoder() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	let entries = shared_value_entries();
	let (db, root) = build_trie::<L>(&entries);
	let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
	let encoded = encode_compact::<L>(&trie).unwrap();
	let deduplicated = encode_compact_skip_duplicates::<L>(&trie, &mut Default::default()).unwrap();
	assert_eq!(count_shared_value_items(&deduplicated), 1);

	// Baseline: the released decoder handles the unmodified encoding.
	let mut baseline_db = MemoryDB::<L>::default();
	let (decoded_root, _) =
		reference_trie::trie_db_0_31_decoder::decode_compact_from_iter::<L, _, _>(
			&mut baseline_db,
			encoded.iter().map(Vec::as_slice),
		)
		.unwrap();
	assert_eq!(decoded_root, root);

	// The deduplicated encoding decodes with the released decoder into a readable hash-keyed
	// database: the value node is present from its first, still-attached occurrence.
	// (Prefixed databases are out of scope: 0.31.0 inserts attached values under an incomplete
	// prefix, fixed by #227.)
	let mut hash_keyed_db = MemoryDB::<L>::default();
	let (decoded_root, _) =
		reference_trie::trie_db_0_31_decoder::decode_compact_from_iter::<L, _, _>(
			&mut hash_keyed_db,
			deduplicated.iter().map(Vec::as_slice),
		)
		.unwrap();
	assert_eq!(decoded_root, root);
	assert_entries_match::<L>(&hash_keyed_db, root, &entries);
}

#[test]
fn subtree_deduplicated_encoding_decodes_with_released_0_31_decoder() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	let entries = shared_subtree_entries();
	let (db, root) = build_trie::<L>(&entries);
	let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
	let encoded = encode_compact::<L>(&trie).unwrap();
	let deduplicated = encode_compact_skip_duplicates::<L>(&trie, &mut Default::default()).unwrap();
	assert!(deduplicated.len() < encoded.len());

	// A deduplicated subtree occurrence is indistinguishable from a node outside the partial
	// trie, so the released decoder handles it: the subtree is present in a hash-keyed database
	// from its first, still-emitted occurrence.
	let mut hash_keyed_db = MemoryDB::<L>::default();
	let (decoded_root, _) =
		reference_trie::trie_db_0_31_decoder::decode_compact_from_iter::<L, _, _>(
			&mut hash_keyed_db,
			deduplicated.iter().map(Vec::as_slice),
		)
		.unwrap();
	assert_eq!(decoded_root, root);
	assert_entries_match::<L>(&hash_keyed_db, root, &entries);
}

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


use trie_db::{
	DBValue, encode_compact_skip_values, decode_compact_with_skipped_values,
	Trie, TrieMut, TrieDB, TrieError, TrieDBMut, TrieLayout, Recorder,
	decode_compact,
};
use hash_db::{HashDB, Hasher, EMPTY_PREFIX};
use reference_trie::{
	ExtensionLayout, NoExtensionLayout,
};
use std::collections::{BTreeSet, BTreeMap};

type MemoryDB<H> = memory_db::MemoryDB<H, memory_db::HashKey<H>, DBValue>;

fn test_encode_compact<L: TrieLayout>(
	entries: Vec<(&'static [u8], &'static [u8])>,
	keys: Vec<&'static [u8]>,
	skip_keys: &BTreeSet<&'static [u8]>,
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

	// Lookup items in trie while recording traversed nodes.
	let mut recorder = Recorder::new();
	let items = {
		let mut items = Vec::with_capacity(keys.len());
		let trie = <TrieDB<L>>::new(&db, &root).unwrap();
		for key in keys {
			let value = trie.get_with(key, &mut recorder).unwrap();
			items.push((key, value));
		}
		items
	};

	// Populate a partial trie DB with recorded nodes.
	let mut partial_db = MemoryDB::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	// Compactly encode the partial trie DB.
	let compact_trie = {
		let trie = <TrieDB<L>>::new(&partial_db, &root).unwrap();
		encode_compact_skip_values::<L, _>(&trie, skip_keys.iter().map(|k| *k)).unwrap()
	};

	(root, compact_trie, items)
}

fn test_decode_compact<L: TrieLayout>(
	encoded: &[Vec<u8>],
	items: Vec<(&'static [u8], Option<DBValue>)>,
	expected_root: <L::Hash as Hasher>::Out,
	expected_used: usize,
	skipped_values: &BTreeMap<&'static [u8], &'static [u8]>,
) {
	// Reconstruct the partial DB from the compact encoding.
	let mut db = MemoryDB::default();
	let (root, used) = decode_compact_with_skipped_values::<L, _, _, _, _, _>(
		&mut db,
		encoded.iter().map(Vec::as_slice),
		skipped_values,
		skipped_values.keys().map(|k| *k),
	).unwrap();
	assert_eq!(root, expected_root);
	assert_eq!(used, expected_used);

	// Check that lookups for all items succeed.
	let trie = <TrieDB<L>>::new(&db, &root).unwrap();
	for (key, expected_value) in items {
		assert_eq!(trie.get(key).unwrap(), expected_value);
	}
}

fn test_set() -> Vec<(&'static [u8], &'static [u8])> {
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
	]
}

#[test]
fn trie_compact_encoding_works_with_ext() {
	let (root, mut encoded, items) = test_encode_compact::<ExtensionLayout>(
		test_set(),
		vec![
			b"do",
			b"dog",
			b"doge",
			b"bravo",
			b"d", // None, witness is extension node with omitted child
			b"do\x10", // None, empty branch child
			b"halp", // None, witness is extension node with non-omitted child
		],
		&BTreeSet::new(),
	);

	encoded.push(Vec::new()); // Add an extra item to ensure it is not read.
	test_decode_compact::<ExtensionLayout>(&encoded, items, root, encoded.len() - 1, &BTreeMap::new());
}

#[test]
fn trie_compact_encoding_works_without_ext() {
	let (root, mut encoded, items) = test_encode_compact::<NoExtensionLayout>(
		test_set(),
		vec![
			b"do",
			b"dog",
			b"doge",
			b"bravo",
			b"d", // None, witness is a branch partial
			b"do\x10", // None, witness is empty branch child
			b"halp", // None, witness is branch partial
		],
		&BTreeSet::new(),
	);

	encoded.push(Vec::new()); // Add an extra item to ensure it is not read.
	test_decode_compact::<NoExtensionLayout>(&encoded, items, root, encoded.len() - 1, &BTreeMap::new());
}

#[test]
fn trie_compact_encoding_skip_values() {
	let mut to_skip = BTreeSet::new();
	to_skip.extend(&[&b"doge"[..], &b"aaaaaa"[..], &b"do"[..], &b"b"[..]]); 
	// doge and do will be skip (32 + 4 bytes)
	let skip_len = 36;
	let (root_no_skip, encoded_no_skip, items_no_skip) = test_encode_compact::<NoExtensionLayout>(
		test_set(),
		vec![
			b"do",
			b"dog",
			b"doge",
			b"bravo",
			b"d", // None, witness is a branch partial
			b"do\x10", // None, witness is empty branch child
			b"halp", // None, witness is branch partial
		],
		&BTreeSet::new(),
	);
	let (root, encoded, items) = test_encode_compact::<NoExtensionLayout>(
		test_set(),
		vec![
			b"do",
			b"dog",
			b"doge",
			b"bravo",
			b"d", // None, witness is a branch partial
			b"do\x10", // None, witness is empty branch child
			b"halp", // None, witness is branch partial
		],
		&to_skip,
	);
	assert_eq!(root_no_skip, root);
	assert_eq!(items_no_skip, items);
	assert_eq!(
		encoded_no_skip.iter().map(|e| e.len()).sum::<usize>(),
		encoded.iter().map(|e| e.len()).sum::<usize>() + skip_len,
	);
	let mut encoded = encoded;
	encoded.push(Vec::new()); // Add an extra item to ensure it is not read.
	let mut skipped_values = BTreeMap::new();
	skipped_values.extend(vec![
		(&b"doge"[..], &[0; 32][..]),
		(&b"do"[..], &b"verb"[..]),
		(&b"aaaa"[..], &b"dummy"[..]),
		(&b"b"[..], &b"dummy"[..]),
	]);
	test_decode_compact::<NoExtensionLayout>(
		&encoded,
		items,
		root,
		encoded.len() - 1,
		&skipped_values,
	);
}

#[test]
fn trie_compact_encoding_skip_all_values() {
	let mut values = BTreeMap::new();
	values.extend(test_set());
}

#[test]
fn trie_decoding_fails_with_incomplete_database() {
	let (_, encoded, _) = test_encode_compact::<ExtensionLayout>(
		test_set(),
		vec![
			b"alfa",
		],
		&BTreeSet::new(),
	);

	assert!(encoded.len() > 1);

	// Reconstruct the partial DB from the compact encoding.
	let mut db = MemoryDB::default();
	match decode_compact::<ExtensionLayout, _, _>(&mut db, &encoded[..encoded.len() - 1]) {
		Err(err) => match *err {
			TrieError::IncompleteDatabase(_) => {}
			_ => panic!("got unexpected TrieError"),
		}
		_ => panic!("decode was unexpectedly successful"),
	}
}

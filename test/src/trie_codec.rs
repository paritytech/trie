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

use reference_trie::{test_layouts, ExtensionLayout};
use trie_db::{
	decode_compact, encode_compact,
	node_db::{Hasher, EMPTY_PREFIX},
	DBValue, NodeCodec, Recorder, Trie, TrieDBBuilder, TrieDBMutBuilder, TrieError, TrieLayout,
};

use crate::TestDB;

type MemoryDB<T> = trie_db::memory_db::MemoryDB<
	<T as TrieLayout>::Hash,
	trie_db::memory_db::HashKey<<T as TrieLayout>::Hash>,
	DBValue,
>;

fn test_encode_compact<L: TrieLayout, DB: TestDB<L>>(
	entries: Vec<(&'static [u8], &'static [u8])>,
	keys: Vec<&'static [u8]>,
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(&'static [u8], Option<DBValue>)>) {
	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = DB::default();
		let mut trie = <TrieDBMutBuilder<L>>::new(&mut db).build();
		for (key, value) in entries.iter() {
			trie.insert(key, value).unwrap();
		}
		let commit = trie.commit();
		let root = db.commit(commit);
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
	encoded: &[Vec<u8>],
	items: Vec<(&'static [u8], Option<DBValue>)>,
	expected_root: <L::Hash as Hasher>::Out,
	expected_used: usize,
) {
	// Reconstruct the partial DB from the compact encoding.
	let mut db = MemoryDB::<L>::default();
	let (root, used) = decode_compact::<L>(&mut db, encoded).unwrap();
	assert_eq!(root, expected_root);
	assert_eq!(used, expected_used);

	// Check that lookups for all items succeed.
	let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
	for (key, expected_value) in items {
		assert_eq!(trie.get(key).unwrap(), expected_value);
	}
}

test_layouts!(trie_compact_encoding_works, trie_compact_encoding_works_internal);
fn trie_compact_encoding_works_internal<T: TrieLayout, DB: TestDB<T>>() {
	let (root, mut encoded, items) = test_encode_compact::<T, DB>(
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
	test_decode_compact::<T>(&encoded, items, root, encoded.len() - 1);
}

test_layouts!(
	trie_decoding_fails_with_incomplete_database,
	trie_decoding_fails_with_incomplete_database_internal
);
fn trie_decoding_fails_with_incomplete_database_internal<T: TrieLayout, DB: TestDB<T>>() {
	let (_, encoded, _) = test_encode_compact::<T, DB>(
		vec![(b"alfa", &[0; 32]), (b"bravo", b"bravo")],
		vec![b"alfa"],
	);

	assert!(encoded.len() > 1);

	// Reconstruct the partial DB from the compact encoding.
	let mut db = MemoryDB::<T>::default();
	match decode_compact::<T>(&mut db, &encoded[..encoded.len() - 1]) {
		Err(err) => match *err {
			TrieError::IncompleteDatabase(_) => {},
			_ => panic!("got unexpected TrieError"),
		},
		_ => panic!("decode was unexpectedly successful"),
	}
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
		let mut recorder = Recorder::<ExtensionLayout>::new();
		let mut trie = <TrieDBMutBuilder<ExtensionLayout>>::new(&mut db).build();
		for (key, value) in entries.iter() {
			trie.insert(key, value).unwrap();
		}
		let commit = trie.commit();
		commit.apply_to(&mut db);
		let root = commit.root_hash();

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
			<<ExtensionLayout as TrieLayout>::Codec as NodeCodec>::decode(&record.data, &[(); 0])
				.unwrap();
		let node_owned = node.to_owned_node::<ExtensionLayout>().unwrap();

		assert_eq!(record.data, node_owned.to_encoded::<<ExtensionLayout as TrieLayout>::Codec>());
	}
}

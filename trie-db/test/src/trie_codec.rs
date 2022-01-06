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

use hash_db::{HashDB, Hasher, EMPTY_PREFIX};
use reference_trie::{ExtensionLayout, NoExtensionLayout};
use trie_db::{
    decode_compact, encode_compact, DBValue, NodeCodec, Recorder, Trie, TrieDBBuilder,
    TrieDBMutBuilder, TrieError, TrieLayout, TrieMut,
};

type MemoryDB<H> = memory_db::MemoryDB<H, memory_db::HashKey<H>, DBValue>;

fn test_encode_compact<L: TrieLayout>(
    entries: Vec<(&'static [u8], &'static [u8])>,
    keys: Vec<&'static [u8]>,
) -> (
    <L::Hash as Hasher>::Out,
    Vec<Vec<u8>>,
    Vec<(&'static [u8], Option<DBValue>)>,
) {
    // Populate DB with full trie from entries.
    let (db, root) = {
        let mut db = <MemoryDB<L::Hash>>::default();
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
        let trie = <TrieDBBuilder<L>>::new_unchecked(&db, &root)
            .with_recorder(&mut recorder)
            .build();
        for key in keys {
            let value = trie.get(key).unwrap();
            items.push((key, value));
        }
        items
    };

    // Populate a partial trie DB with recorded nodes.
    let mut partial_db = MemoryDB::default();
    for record in recorder.drain(&db, &root).unwrap() {
        partial_db.insert(EMPTY_PREFIX, &record.1);
    }

    // Compactly encode the partial trie DB.
    let compact_trie = {
        let trie = <TrieDBBuilder<L>>::new_unchecked(&partial_db, &root).build();
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
    let mut db = MemoryDB::default();
    let (root, used) = decode_compact::<L, _, _>(&mut db, encoded).unwrap();
    assert_eq!(root, expected_root);
    assert_eq!(used, expected_used);

    // Check that lookups for all items succeed.
    let trie = <TrieDBBuilder<L>>::new_unchecked(&db, &root).build();
    for (key, expected_value) in items {
        assert_eq!(trie.get(key).unwrap(), expected_value);
    }
}

#[test]
fn trie_compact_encoding_works_with_ext() {
    let (root, mut encoded, items) = test_encode_compact::<ExtensionLayout>(
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
    test_decode_compact::<ExtensionLayout>(&encoded, items, root, encoded.len() - 1);
}

#[test]
fn trie_compact_encoding_works_without_ext() {
    let (root, mut encoded, items) = test_encode_compact::<NoExtensionLayout>(
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
            b"do", b"dog", b"doge", b"bravo", b"d",      // None, witness is a branch partial
            b"do\x10", // None, witness is empty branch child
            b"halp",   // None, witness is branch partial
        ],
    );

    encoded.push(Vec::new()); // Add an extra item to ensure it is not read.
    test_decode_compact::<NoExtensionLayout>(&encoded, items, root, encoded.len() - 1);
}

#[test]
fn trie_decoding_fails_with_incomplete_database() {
    let (_, encoded, _) = test_encode_compact::<ExtensionLayout>(
        vec![(b"alfa", &[0; 32]), (b"bravo", b"bravo")],
        vec![b"alfa"],
    );

    assert!(encoded.len() > 1);

    // Reconstruct the partial DB from the compact encoding.
    let mut db = MemoryDB::default();
    match decode_compact::<ExtensionLayout, _, _>(&mut db, &encoded[..encoded.len() - 1]) {
        Err(err) => match *err {
            TrieError::IncompleteDatabase(_) => {}
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
    let (mut recorder, db, root) = {
        let mut db = <MemoryDB<<ExtensionLayout as TrieLayout>::Hash>>::default();
        let mut root = Default::default();
        let mut recorder = Recorder::<ExtensionLayout>::new();
        {
            let mut trie = <TrieDBMutBuilder<ExtensionLayout>>::new(&mut db, &mut root).build();
            for (key, value) in entries.iter() {
                trie.insert(key, value).unwrap();
            }
        }

        let trie = TrieDBBuilder::<ExtensionLayout>::new_unchecked(&db, &root)
            .with_recorder(&mut recorder)
            .build();
        for (key, _) in entries.iter() {
            trie.get(key).unwrap();
        }

        (recorder, db, root)
    };

    for record in recorder.drain(&db, &root).unwrap() {
        let node =
            <<ExtensionLayout as TrieLayout>::Codec as NodeCodec>::decode(&record.1).unwrap();
        let node_owned = node.to_owned_node::<ExtensionLayout>().unwrap();

        assert_eq!(
            record.1,
            node_owned.to_encoded::<<ExtensionLayout as TrieLayout>::Codec>()
        );
    }
}

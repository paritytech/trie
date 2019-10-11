// Copyright 2019 Parity Technologies
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
use trie_db::{DBValue, TrieMut};
use keccak_hasher::KeccakHasher;
use reference_trie::{
    ExtensionLayout, NoExtensionLayout, RefTrieDB, RefTrieDBNoExt, RefTrieDBMut, RefTrieDBMutNoExt,
};

use crate::reference_codec::{ReferenceProofNodeCodecWithExt, ReferenceProofNodeCodecWithoutExt};
use crate::{generate_proof, verify_proof};

type MemoryDB<H> = memory_db::MemoryDB<H, memory_db::HashKey<H>, DBValue>;

fn test_entries() -> Vec<(&'static [u8], &'static [u8])> {
    vec![
        (b"alfa", b"val alpha"),
        (b"bravo", b"val bravo"),
        (b"do", b"verb"),
        (b"dog", b"puppy"),
        (b"doge", b"coin"),
        (b"horse", b"stallion"),
    ]
}

#[test]
fn trie_proofs_with_ext() {
    let (db, root) = {
        let mut root = <KeccakHasher as Hasher>::Out::default();
        let mut db = MemoryDB::default();
        {
            let mut trie = RefTrieDBMut::new(&mut db, &mut root);
            for (key, value) in test_entries() {
                trie.insert(key, value).unwrap();
            }
        }
        (db, root)
    };
    let trie = RefTrieDB::new(&db, &root).unwrap();

    let items = vec![
        (&b"dog"[..], Some(&b"puppy"[..])),
        (&b"doge"[..], Some(&b"coin"[..])),
        (&b"bravo"[..], Some(&b"val bravo"[..])),
        (&b"do"[..], Some(&b"verb"[..])),
        (&b"dag"[..], None),
    ];
    let proof = generate_proof::<_, ExtensionLayout, ReferenceProofNodeCodecWithExt, _, _,>(
        &trie, items.iter().map(|(k, _)| k)
    ).unwrap();

    verify_proof::<ExtensionLayout, ReferenceProofNodeCodecWithExt, _, _, _>(
        &root, proof, items.iter()
    ).unwrap();
}

#[test]
fn trie_proofs_without_ext() {
    let (db, root) = {
        let mut root = <KeccakHasher as Hasher>::Out::default();
        let mut db = MemoryDB::default();
        {
            let mut trie = RefTrieDBMutNoExt::new(&mut db, &mut root);
            for (key, value) in test_entries() {
                trie.insert(key, value).unwrap();
            }
        }
        (db, root)
    };
    let trie = RefTrieDBNoExt::new(&db, &root).unwrap();

    let items = vec![
        (&b"dog"[..], Some(&b"puppy"[..])),
        (&b"doge"[..], Some(&b"coin"[..])),
        (&b"bravo"[..], Some(&b"val bravo"[..])),
        (&b"do"[..], Some(&b"verb"[..])),
        (&b"dag"[..], None),
    ];
    let proof = generate_proof::<_, NoExtensionLayout, ReferenceProofNodeCodecWithoutExt, _, _,>(
        &trie, items.iter().map(|(k, _)| k)
    ).unwrap();

    verify_proof::<NoExtensionLayout, ReferenceProofNodeCodecWithoutExt, _, _, _>(
        &root, proof, items.iter()
    ).unwrap();
}

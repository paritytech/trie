// Copyright 2017, 2020 Parity Technologies
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

use hash_db::{EMPTY_PREFIX, HashDB};
use memory_db::{MemoryDB, PrefixedKey, HashKey};
use keccak_hasher::KeccakHasher;
use trie_db::{DBValue, Trie, NibbleSlice, TrieMut, Recorder, TrieCache as _};
use reference_trie::{RefLookup, RefTrieDBBuilder, RefTrieDBNoExtBuilder, RefTrieDBMutBuilder, RefTrieDBMutNoExtBuilder, RefTrieDBCacheNoExt, NoExtensionLayout};
use hex_literal::hex;

#[test]
fn iterator_works() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutBuilder::new(&mut memdb, &mut root).build();
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let trie = RefTrieDBBuilder::new_unchecked(&memdb, &root).build();

	let iter = trie.iter().unwrap();
	let mut iter_pairs = Vec::new();
	for pair in iter {
		let (key, value) = pair.unwrap();
		iter_pairs.push((key, value.to_vec()));
	}

	assert_eq!(pairs, iter_pairs);
}

#[test]
fn iterator_works_without_extension() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExtBuilder::new(&mut memdb, &mut root).build();
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let trie = RefTrieDBNoExtBuilder::new_unchecked(&memdb, &root).build();

	let iter = trie.iter().unwrap();
	let mut iter_pairs = Vec::new();
	for pair in iter {
		let (key, value) = pair.unwrap();
		iter_pairs.push((key, value.to_vec()));
	}

	assert_eq!(pairs, iter_pairs);
}

#[test]
fn iterator_seek_works() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutBuilder::new(&mut memdb, &mut root).build();
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let t = RefTrieDBBuilder::new_unchecked(&memdb, &root).build();

	let mut iter = t.iter().unwrap();
	assert_eq!(
		iter.next().unwrap().unwrap(),
		(
			hex!("0103000000000000000464").to_vec(),
			hex!("fffffffffe").to_vec(),
		)
	);
	iter.seek(&hex!("00")[..]).unwrap();
	assert_eq!(
		pairs,
		iter.map(|x| x.unwrap())
			.map(|(k, v)| (k, v[..].to_vec()))
			.collect::<Vec<_>>()
	);
	let mut iter = t.iter().unwrap();
	iter.seek(&hex!("0103000000000000000465")[..]).unwrap();
	assert_eq!(
		&pairs[1..],
		&iter.map(|x| x.unwrap())
			.map(|(k, v)| (k, v[..].to_vec()))
			.collect::<Vec<_>>()[..]
	);
}

#[test]
fn iterator_seek_works_without_extension() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExtBuilder::new(&mut memdb, &mut root).build();
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let t = RefTrieDBNoExtBuilder::new_unchecked(&memdb, &root).build();

	let mut iter = t.iter().unwrap();
	assert_eq!(
		iter.next().unwrap().unwrap(),
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec())
	);
	iter.seek(&hex!("00")[..]).unwrap();
	assert_eq!(
		pairs,
		iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>(),
	);
	let mut iter = t.iter().unwrap();
	iter.seek(&hex!("0103000000000000000465")[..]).unwrap();
	assert_eq!(
		&pairs[1..],
		&iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>()[..],
	);
}

#[test]
fn iterator() {
	let d = vec![
		b"A".to_vec(),
		b"AA".to_vec(),
		b"AB".to_vec(),
		b"B".to_vec(),
	];

	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutBuilder::new(&mut memdb, &mut root).build();
		for x in &d {
			t.insert(x, x).unwrap();
		}
	}

	let t = RefTrieDBBuilder::new_unchecked(&memdb, &root).build();
	assert_eq!(
		d.iter()
			.map(|i| i.clone())
			.collect::<Vec<_>>(),
		t.iter()
			.unwrap()
			.map(|x| x.unwrap().0)
			.collect::<Vec<_>>()
	);
	assert_eq!(d, t.iter().unwrap().map(|x| x.unwrap().1).collect::<Vec<_>>());
}

#[test]
fn iterator_without_extension() {
	let d = vec![
		b"A".to_vec(),
		b"AA".to_vec(),
		b"AB".to_vec(),
		b"B".to_vec(),
	];

	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExtBuilder::new(&mut memdb, &mut root).build();
		for x in &d {
			t.insert(x, x).unwrap();
		}
	}

	let t = RefTrieDBNoExtBuilder::new_unchecked(&memdb, &root).build();
	assert_eq!(
		d.iter().map(|i| i.clone()).collect::<Vec<_>>(),
		t.iter().unwrap().map(|x| x.unwrap().0).collect::<Vec<_>>(),
	);
	assert_eq!(d, t.iter().unwrap().map(|x| x.unwrap().1).collect::<Vec<_>>());
}

#[test]
fn iterator_seek() {
	let d = vec![
		b"A".to_vec(),
		b"AA".to_vec(),
		b"AB".to_vec(),
		b"B".to_vec(),
	];
	let vals = vec![
		vec![0; 32],
		vec![1; 32],
		vec![2; 32],
		vec![3; 32],
	];

	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExtBuilder::new(&mut memdb, &mut root).build();
		for (k, val) in d.iter().zip(vals.iter()) {
			t.insert(k, val.as_slice()).unwrap();
		}
	}

	let t = RefTrieDBNoExtBuilder::new_unchecked(&memdb, &root).build();
	let mut iter = t.iter().unwrap();
	assert_eq!(iter.next().unwrap().unwrap(), (b"A".to_vec(), vals[0].clone()));
	iter.seek(b"!").unwrap();
	assert_eq!(vals, iter.map(|x| x.unwrap().1).collect::<Vec<_>>());
	let mut iter = t.iter().unwrap();
	iter.seek(b"A").unwrap();
	assert_eq!(vals, &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AA").unwrap();
	assert_eq!(&vals[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed(&t, b"aaaaa").unwrap();
	assert_eq!(&vals[..0], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed(&t, b"A").unwrap();
	assert_eq!(&vals[..3], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AA").unwrap();
	assert_eq!(&vals[1..3], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AB").unwrap();
	assert_eq!(&vals[2..3], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"", b"AB").unwrap();
	assert_eq!(&vals[2..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"A!").unwrap();
	assert_eq!(&vals[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AB").unwrap();
	assert_eq!(&vals[2..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AB!").unwrap();
	assert_eq!(&vals[3..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"B").unwrap();
	assert_eq!(&vals[3..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"C").unwrap();
	assert_eq!(&vals[4..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
}

#[test]
fn get_length_with_extension() {
	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutBuilder::new(&mut memdb, &mut root).build();
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
	}

	let t = RefTrieDBBuilder::new_unchecked(&memdb, &root).build();
	assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
	assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(32));
	assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
}

#[test]
fn get_length_without_extension() {
	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExtBuilder::new(&mut memdb, &mut root).build();
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBA").unwrap();
	}

	let t = RefTrieDBNoExtBuilder::new_unchecked(&memdb, &root).build();
	assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
	assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(5));
	assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
}

#[test]
fn debug_output_supports_pretty_print() {
	let d = vec![
		b"A".to_vec(),
		b"AA".to_vec(),
		b"AB".to_vec(),
		b"B".to_vec(),
	];

	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let root = {
		let mut t = RefTrieDBMutBuilder::new(&mut memdb, &mut root).build();
		for x in &d {
			t.insert(x, x).unwrap();
		}
		t.root().clone()
	};
	let t = RefTrieDBBuilder::new_unchecked(&memdb, &root).build();

	assert_eq!(format!("{:#?}", t),
"TrieDB {
    hash_count: 0,
    root: Node::Extension {
        slice: 4,
        item: Node::Branch {
            nodes: [
                Node::Branch {
                    index: 1,
                    nodes: [
                        Node::Branch {
                            index: 4,
                            nodes: [
                                Node::Leaf {
                                    index: 1,
                                    slice: ,
                                    value: [
                                        65,
                                        65,
                                    ],
                                },
                                Node::Leaf {
                                    index: 2,
                                    slice: ,
                                    value: [
                                        65,
                                        66,
                                    ],
                                },
                            ],
                            value: None,
                        },
                    ],
                    value: Some(
                        [
                            65,
                        ],
                    ),
                },
                Node::Leaf {
                    index: 2,
                    slice: ,
                    value: [
                        66,
                    ],
                },
            ],
            value: None,
        },
    },
}");

}

#[test]
fn test_lookup_with_corrupt_data_returns_decoder_error() {
	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutBuilder::new(&mut memdb, &mut root).build();
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBA").unwrap();
	}

	let t = RefTrieDBBuilder::new_unchecked(&memdb, &root).build();

	// query for an invalid data type to trigger an error
	let q = |x: &[u8]| x.len() < 64;
	let lookup = RefLookup { db: t.db(), query: q, hash: root, cache: None, recorder: None };
	let query_result = lookup.look_up(&b"A"[..], NibbleSlice::new(b"A"));
	assert_eq!(query_result.unwrap().unwrap(), true);
}

#[test]
fn test_recorder() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 64]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut memdb = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutBuilder::new(&mut memdb, &mut root).build();
		for (key, value) in &key_value {
			t.insert(key, value).unwrap();
		}
	}

	let mut recorder = Recorder::<NoExtensionLayout>::new();
	{
		let trie = RefTrieDBBuilder::new_unchecked(&memdb, &root).with_recorder(&mut recorder).build();

		for (key, value) in key_value.iter().take(3) {
			assert_eq!(*value, trie.get(key).unwrap().unwrap());
		}
	}

	let mut partial_db = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
	for record in recorder.drain(&memdb, &root).unwrap() {
		partial_db.insert(EMPTY_PREFIX, &record.1);
	}

	{
		let trie = RefTrieDBBuilder::new_unchecked(&partial_db, &root).build();

		for (key, value) in key_value.iter().take(3) {
			assert_eq!(*value, trie.get(key).unwrap().unwrap());
		}
		assert!(trie.get(&key_value[3].0).is_err());
	}
}

#[test]
fn test_recorder_with_cache() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 64]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut memdb = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
	let mut root = Default::default();

	{
		let mut t = RefTrieDBMutNoExtBuilder::new(&mut memdb, &mut root).build();
		for (key, value) in &key_value {
			t.insert(key, value).unwrap();
		}
	}

	let mut cache = RefTrieDBCacheNoExt::default();

	{
		let trie = RefTrieDBNoExtBuilder::new_unchecked(&memdb, &root).with_cache(&mut cache).build();

		// Only read one entry.
		assert_eq!(key_value[1].1, trie.get(&key_value[1].0).unwrap().unwrap());
	}

	// Root should now be cached.
	assert!(cache.get_node(&root).is_some());
	// Also the data should be cached.
	assert!(cache.lookup_data_for_key(&key_value[1].0).is_some());
	// And the rest not
	assert!(cache.lookup_data_for_key(&key_value[0].0).is_none());
	assert!(cache.lookup_data_for_key(&key_value[2].0).is_none());
	assert!(cache.lookup_data_for_key(&key_value[3].0).is_none());

	let mut recorder = Recorder::<NoExtensionLayout>::new();
	{
		let trie = RefTrieDBNoExtBuilder::new_unchecked(&memdb, &root).with_cache(&mut cache).with_recorder(&mut recorder).build();

		for (key, value) in key_value.iter().take(3) {
			assert_eq!(*value, trie.get(key).unwrap().unwrap());
		}
	}

	let mut partial_db = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
	for record in recorder.drain(&memdb, &root).unwrap() {
		partial_db.insert(EMPTY_PREFIX, &record.1);
	}

	{
		let trie = RefTrieDBNoExtBuilder::new_unchecked(&partial_db, &root).build();

		for (key, value) in key_value.iter().take(3) {
			assert_eq!(*value, trie.get(key).unwrap().unwrap());
		}

		assert!(trie.get(&key_value[3].0).is_err());
	}
}

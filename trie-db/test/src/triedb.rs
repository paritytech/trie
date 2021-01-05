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

use memory_db::{MemoryDB, PrefixedKey};
use keccak_hasher::KeccakHasher;
use trie_db::{DBValue, Trie, TrieMut, NibbleSlice};
use reference_trie::{RefTrieDB, RefTrieDBMut, RefLookup};
use reference_trie::{RefTrieDBNoExt, RefTrieDBMutNoExt};
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
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let trie = RefTrieDB::new(&memdb, &root).unwrap();

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
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let trie = RefTrieDBNoExt::new(&memdb, &root).unwrap();

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
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let t = RefTrieDB::new(&memdb, &root).unwrap();

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
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let t = RefTrieDBNoExt::new(&memdb, &root).unwrap();

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
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for x in &d {
			t.insert(x, x).unwrap();
		}
	}

	let t = RefTrieDB::new(&memdb, &root).unwrap();
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
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for x in &d {
			t.insert(x, x).unwrap();
		}
	}

	let t = RefTrieDBNoExt::new(&memdb, &root).unwrap();
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

	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for x in &d {
			t.insert(x, x).unwrap();
		}
	}

	let t = RefTrieDBNoExt::new(&memdb, &root).unwrap();
	let mut iter = t.iter().unwrap();
	assert_eq!(iter.next().unwrap().unwrap(), (b"A".to_vec(), b"A".to_vec()));
	iter.seek(b"!").unwrap();
	assert_eq!(d, iter.map(|x| x.unwrap().1).collect::<Vec<_>>());
	let mut iter = t.iter().unwrap();
	iter.seek(b"A").unwrap();
	assert_eq!(d, &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AA").unwrap();
	assert_eq!(&d[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"A!").unwrap();
	assert_eq!(&d[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AB").unwrap();
	assert_eq!(&d[2..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AB!").unwrap();
	assert_eq!(&d[3..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"B").unwrap();
	assert_eq!(&d[3..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"C").unwrap();
	assert_eq!(&d[4..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
}

#[test]
fn get_length_with_extension() {
	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
	}

	let t = RefTrieDB::new(&memdb, &root).unwrap();
	assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
	assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(32));
	assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
}

#[test]
fn get_length_without_extension() {
	let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBA").unwrap();
	}

	let t = RefTrieDBNoExt::new(&memdb, &root).unwrap();
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
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for x in &d {
			t.insert(x, x).unwrap();
		}
		t.root().clone()
	};
	let t = RefTrieDB::new(&memdb, &root).unwrap();

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
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBA").unwrap();
	}

	let t = RefTrieDB::new(&memdb, &root).unwrap();

	// query for an invalid data type to trigger an error
	let q = |x: &[u8]| x.len() < 64;
	let lookup = RefLookup { db: t.db(), query: q, hash: root };
	let query_result = lookup.look_up(NibbleSlice::new(b"A"));
	assert_eq!(query_result.unwrap().unwrap(), true);
}

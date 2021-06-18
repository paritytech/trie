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
use trie_db::{TrieDB, TrieDBMut, Lookup, Trie, TrieMut, NibbleSlice, TrieLayout,
	DBValue};
use reference_trie::test_layouts;
use hex_literal::hex;

type PrefixedMemoryDB<T> = MemoryDB::<
	<T as TrieLayout>::Hash,
	PrefixedKey<<T as TrieLayout>::Hash>,
	DBValue,
>;

test_layouts!(iterator_works, iterator_works_internal);
fn iterator_works_internal<T: TrieLayout>() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let trie = TrieDB::<T>::new(&memdb, &root).unwrap();

	let iter = trie.iter().unwrap();
	let mut iter_pairs = Vec::new();
	for pair in iter {
		let (key, value) = pair.unwrap();
		iter_pairs.push((key, value.to_vec()));
	}

	assert_eq!(pairs, iter_pairs);
}

test_layouts!(iterator_seek_works, iterator_seek_works_internal);
fn iterator_seek_works_internal<T: TrieLayout>() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let t = TrieDB::<T>::new(&memdb, &root).unwrap();

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

test_layouts!(iterator, iterator_internal);
fn iterator_internal<T: TrieLayout>() {
	let d = vec![
		b"A".to_vec(),
		b"AA".to_vec(),
		b"AB".to_vec(),
		b"B".to_vec(),
	];

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		for x in &d {
			t.insert(x, x).unwrap();
		}
	}

	let t = TrieDB::<T>::new(&memdb, &root).unwrap();
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

test_layouts!(iterator_seek, iterator_seek_internal);
fn iterator_seek_internal<T: TrieLayout>() {
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

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		for (k, val) in d.iter().zip(vals.iter()) {
			t.insert(k, val.as_slice()).unwrap();
		}
	}

	let t = TrieDB::<T>::new(&memdb, &root).unwrap();
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

test_layouts!(get_length_with_extension, get_length_with_extension_internal);
fn get_length_with_extension_internal<T: TrieLayout>() {
	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
	}

	let t = TrieDB::<T>::new(&memdb, &root).unwrap();
	assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
	assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(32));
	assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
}

test_layouts!(debug_output_supports_pretty_print, debug_output_supports_pretty_print_internal);
fn debug_output_supports_pretty_print_internal<T: TrieLayout>() {
	let d = vec![
		b"A".to_vec(),
		b"AA".to_vec(),
		b"AB".to_vec(),
		b"B".to_vec(),
	];

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	let root = {
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		for x in &d {
			t.insert(x, x).unwrap();
		}
		t.root().clone()
	};
	let t = TrieDB::<T>::new(&memdb, &root).unwrap();

	if T::USE_EXTENSION {
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
                                    value: Value(
                                        [
                                            65,
                                            65,
                                        ],
                                    ),
                                },
                                Node::Leaf {
                                    index: 2,
                                    slice: ,
                                    value: Value(
                                        [
                                            65,
                                            66,
                                        ],
                                    ),
                                },
                            ],
                            value: NoValue,
                        },
                    ],
                    value: Value(
                        [
                            65,
                        ],
                    ),
                },
                Node::Leaf {
                    index: 2,
                    slice: ,
                    value: Value(
                        [
                            66,
                        ],
                    ),
                },
            ],
            value: NoValue,
        },
    },
}")
	} else {
		// untested without extension
	};
}

test_layouts!(test_lookup_with_corrupt_data_returns_decoder_error, test_lookup_with_corrupt_data_returns_decoder_error_internal);
fn test_lookup_with_corrupt_data_returns_decoder_error_internal<T: TrieLayout>() {

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBA").unwrap();
	}

	let t = TrieDB::<T>::new(&memdb, &root).unwrap();

	// query for an invalid data type to trigger an error
	let q = |x: &[u8]| x.len() < 64;
	let lookup = Lookup::<T, _> { db: t.db(), query: q, hash: root, layout: t.layout() };
	let query_result = lookup.look_up(NibbleSlice::new(b"A"));
	assert_eq!(query_result.unwrap().unwrap(), true);
}

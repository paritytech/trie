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

use std::ops::Deref;

use hash_db::{HashDB, Hasher, EMPTY_PREFIX};
use hex_literal::hex;
use memory_db::{HashKey, MemoryDB, PrefixedKey};
use reference_trie::{test_layouts, TestTrieCache};
use trie_db::{
	CachedValue, DBValue, Lookup, NibbleSlice, Recorder, Trie, TrieCache, TrieDBBuilder,
	TrieDBMutBuilder, TrieLayout, TrieMut,
};

type PrefixedMemoryDB<T> =
	MemoryDB<<T as TrieLayout>::Hash, PrefixedKey<<T as TrieLayout>::Hash>, DBValue>;
type MemoryDBProof<T> =
	MemoryDB<<T as TrieLayout>::Hash, HashKey<<T as TrieLayout>::Hash>, DBValue>;

test_layouts!(iterator_works, iterator_works_internal);
fn iterator_works_internal<T: TrieLayout>() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000010000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();

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
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (x, y) in &pairs {
			t.insert(x, y).unwrap();
		}
	}

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();

	let mut iter = t.iter().unwrap();
	assert_eq!(
		iter.next().unwrap().unwrap(),
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec(),)
	);
	iter.seek(&hex!("00")[..]).unwrap();
	assert_eq!(
		pairs,
		iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>()
	);
	let mut iter = t.iter().unwrap();
	iter.seek(&hex!("0103000000000000000465")[..]).unwrap();
	assert_eq!(
		&pairs[1..],
		&iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>()[..]
	);
}

test_layouts!(iterator, iterator_internal);
fn iterator_internal<T: TrieLayout>() {
	let d = vec![b"A".to_vec(), b"AA".to_vec(), b"AB".to_vec(), b"B".to_vec()];

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for x in &d {
			t.insert(x, x).unwrap();
		}
	}

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();
	assert_eq!(
		d.iter().map(|i| i.clone()).collect::<Vec<_>>(),
		t.iter().unwrap().map(|x| x.unwrap().0).collect::<Vec<_>>()
	);
	assert_eq!(d, t.iter().unwrap().map(|x| x.unwrap().1).collect::<Vec<_>>());
}

test_layouts!(iterator_seek, iterator_seek_internal);
fn iterator_seek_internal<T: TrieLayout>() {
	let d = vec![b"A".to_vec(), b"AA".to_vec(), b"AB".to_vec(), b"AS".to_vec(), b"B".to_vec()];
	let vals = vec![vec![0; 32], vec![1; 32], vec![2; 32], vec![4; 32], vec![3; 32]];

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (k, val) in d.iter().zip(vals.iter()) {
			t.insert(k, val.as_slice()).unwrap();
		}
	}

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();
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
	assert_eq!(&vals[..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AA").unwrap();
	assert_eq!(&vals[1..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AR").unwrap();
	assert_eq!(&vals[3..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AS").unwrap();
	assert_eq!(&vals[3..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AB").unwrap();
	assert_eq!(&vals[2..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
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
	assert_eq!(&vals[4..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"C").unwrap();
	assert_eq!(&vals[5..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
}

test_layouts!(get_length_with_extension, get_length_with_extension_internal);
fn get_length_with_extension_internal<T: TrieLayout>() {
	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
	}

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();
	assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
	assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(32));
	assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
}

test_layouts!(debug_output_supports_pretty_print, debug_output_supports_pretty_print_internal);
fn debug_output_supports_pretty_print_internal<T: TrieLayout>() {
	let d = vec![b"A".to_vec(), b"AA".to_vec(), b"AB".to_vec(), b"B".to_vec()];

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	let root = {
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for x in &d {
			t.insert(x, x).unwrap();
		}
		t.root().clone()
	};
	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();

	if T::USE_EXTENSION {
		assert_eq!(
			format!("{:#?}", t),
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
                                    value: Inline(
                                        [
                                            65,
                                            65,
                                        ],
                                    ),
                                },
                                Node::Leaf {
                                    index: 2,
                                    slice: ,
                                    value: Inline(
                                        [
                                            65,
                                            66,
                                        ],
                                    ),
                                },
                            ],
                            value: None,
                        },
                    ],
                    value: Some(
                        Inline(
                            [
                                65,
                            ],
                        ),
                    ),
                },
                Node::Leaf {
                    index: 2,
                    slice: ,
                    value: Inline(
                        [
                            66,
                        ],
                    ),
                },
            ],
            value: None,
        },
    },
}"
		)
	} else {
		// untested without extension
	};
}

test_layouts!(
	test_lookup_with_corrupt_data_returns_decoder_error,
	test_lookup_with_corrupt_data_returns_decoder_error_internal
);
fn test_lookup_with_corrupt_data_returns_decoder_error_internal<T: TrieLayout>() {
	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		t.insert(b"A", b"ABC").unwrap();
		t.insert(b"B", b"ABCBA").unwrap();
	}

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();

	// query for an invalid data type to trigger an error
	let q = |x: &[u8]| x.len() < 64;
	let lookup = Lookup::<T, _> { db: t.db(), query: q, hash: root, cache: None, recorder: None };
	let query_result = lookup.look_up(&b"A"[..], NibbleSlice::new(b"A"));
	assert_eq!(query_result.unwrap().unwrap(), true);
}

test_layouts!(test_recorder, test_recorder_internal);
fn test_recorder_internal<T: TrieLayout>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut memdb = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (key, value) in &key_value {
			t.insert(key, value).unwrap();
		}
	}

	let mut recorder = Recorder::<T>::new();
	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).with_recorder(&mut recorder).build();

		for (key, value) in key_value.iter().take(3) {
			assert_eq!(*value, trie.get(key).unwrap().unwrap());
		}
	}

	let mut partial_db = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	{
		let trie = TrieDBBuilder::<T>::new(&partial_db, &root).build();

		for (key, value) in key_value.iter().take(3) {
			assert_eq!(*value, trie.get(key).unwrap().unwrap());
		}
		assert!(trie.get(&key_value[3].0).is_err());
	}
}

test_layouts!(test_recorder_with_cache, test_recorder_with_cache_internal);
fn test_recorder_with_cache_internal<T: TrieLayout>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut memdb = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
	let mut root = Default::default();

	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (key, value) in &key_value {
			t.insert(key, value).unwrap();
		}
	}

	let mut cache = TestTrieCache::<T>::default();

	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).with_cache(&mut cache).build();

		// Only read one entry.
		assert_eq!(key_value[1].1, trie.get(&key_value[1].0).unwrap().unwrap());
	}

	// Root should now be cached.
	assert!(cache.get_node(&root).is_some());
	// Also the data should be cached.
	let value = cache.lookup_value_for_key(&key_value[1].0).unwrap();

	assert_eq!(key_value[1].1, value.data().unwrap().unwrap().deref());
	assert_eq!(T::Hash::hash(&key_value[1].1), value.hash().unwrap());

	// And the rest not
	assert!(cache.lookup_value_for_key(&key_value[0].0).is_none());
	assert!(cache.lookup_value_for_key(&key_value[2].0).is_none());
	assert!(cache.lookup_value_for_key(&key_value[3].0).is_none());

	// Run this multiple times to ensure that the cache is not interfering the recording.
	for i in 0..6 {
		eprintln!("Round: {}", i);

		// Ensure that it works with a filled value/node cache and without it.
		if i < 2 {
			cache.clear_value_cache();
		} else if i < 4 {
			cache.clear_node_cache();
		}

		let mut recorder = Recorder::<T>::new();
		{
			let trie = TrieDBBuilder::<T>::new(&memdb, &root)
				.with_cache(&mut cache)
				.with_recorder(&mut recorder)
				.build();

			for (key, value) in key_value.iter().take(2) {
				assert_eq!(*value, trie.get(key).unwrap().unwrap());
			}

			assert_eq!(
				T::Hash::hash(&key_value[2].1),
				trie.get_hash(&key_value[2].0).unwrap().unwrap()
			);
			assert_eq!(key_value[2].1, trie.get(&key_value[2].0).unwrap().unwrap());
		}

		let mut partial_db = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
		for record in recorder.drain() {
			partial_db.insert(EMPTY_PREFIX, &record.data);
		}

		{
			let trie = TrieDBBuilder::<T>::new(&partial_db, &root).build();

			for (key, value) in key_value.iter().take(3) {
				assert_eq!(*value, trie.get(key).unwrap().unwrap());
			}

			assert!(trie.get(&key_value[3].0).is_err());
		}
	}
}

test_layouts!(test_recorder_with_cache_get_hash, test_recorder_with_cache_get_hash_internal);
fn test_recorder_with_cache_get_hash_internal<T: TrieLayout>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut memdb = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
	let mut root = Default::default();

	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (key, value) in &key_value {
			t.insert(key, value).unwrap();
		}
	}

	let mut cache = TestTrieCache::<T>::default();

	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).with_cache(&mut cache).build();

		// Only read one entry.
		assert_eq!(
			T::Hash::hash(&key_value[1].1),
			trie.get_hash(&key_value[1].0).unwrap().unwrap()
		);
	}

	// Root should now be cached.
	assert!(cache.get_node(&root).is_some());
	// Also the data should be cached.

	if T::MAX_INLINE_VALUE.map_or(true, |l| l as usize >= key_value[1].1.len()) {
		assert!(matches!(
			cache.lookup_value_for_key(&key_value[1].0).unwrap(),
			CachedValue::Existing { hash, .. } if *hash == T::Hash::hash(&key_value[1].1)
		));
	} else {
		assert!(matches!(
			cache.lookup_value_for_key(&key_value[1].0).unwrap(),
			CachedValue::ExistingHash(hash) if *hash == T::Hash::hash(&key_value[1].1)
		));
	}

	// Run this multiple times to ensure that the cache is not interfering the recording.
	for i in 0..6 {
		// Ensure that it works with a filled value/node cache and without it.
		if i < 2 {
			cache.clear_value_cache();
		} else if i < 4 {
			cache.clear_node_cache();
		}

		let mut recorder = Recorder::<T>::new();
		{
			let trie = TrieDBBuilder::<T>::new(&memdb, &root)
				.with_cache(&mut cache)
				.with_recorder(&mut recorder)
				.build();

			assert_eq!(
				T::Hash::hash(&key_value[2].1),
				trie.get_hash(&key_value[2].0).unwrap().unwrap()
			);
			assert_eq!(
				T::Hash::hash(&key_value[1].1),
				trie.get_hash(&key_value[1].0).unwrap().unwrap()
			);
		}

		let mut partial_db = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
		for record in recorder.drain() {
			partial_db.insert(EMPTY_PREFIX, &record.data);
		}

		{
			let trie = TrieDBBuilder::<T>::new(&partial_db, &root).build();

			assert_eq!(
				T::Hash::hash(&key_value[2].1),
				trie.get_hash(&key_value[2].0).unwrap().unwrap()
			);
			assert_eq!(
				T::Hash::hash(&key_value[1].1),
				trie.get_hash(&key_value[1].0).unwrap().unwrap()
			);

			// Check if the values are part of the proof or not, based on the layout.
			if T::MAX_INLINE_VALUE.map_or(true, |l| l as usize >= key_value[2].1.len()) {
				assert_eq!(key_value[2].1, trie.get(&key_value[2].0).unwrap().unwrap());
			} else {
				assert!(trie.get(&key_value[2].0).is_err());
			}

			if T::MAX_INLINE_VALUE.map_or(true, |l| l as usize >= key_value[1].1.len()) {
				assert_eq!(key_value[1].1, trie.get(&key_value[1].0).unwrap().unwrap());
			} else {
				assert!(trie.get(&key_value[1].0).is_err());
			}
		}
	}
}

test_layouts!(iterator_seek_with_recorder, iterator_seek_with_recorder_internal);
fn iterator_seek_with_recorder_internal<T: TrieLayout>() {
	let d = vec![b"A".to_vec(), b"AA".to_vec(), b"AB".to_vec(), b"B".to_vec()];
	let vals = vec![vec![0; 64], vec![1; 64], vec![2; 64], vec![3; 64]];

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (k, val) in d.iter().zip(vals.iter()) {
			t.insert(k, val.as_slice()).unwrap();
		}
	}

	let mut recorder = Recorder::<T>::new();
	{
		let t = TrieDBBuilder::<T>::new(&memdb, &root).with_recorder(&mut recorder).build();
		let mut iter = t.iter().unwrap();
		iter.seek(b"AA").unwrap();
		assert_eq!(&vals[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	}

	let mut partial_db = MemoryDBProof::<T>::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	// Replay with from the proof.
	{
		let trie = TrieDBBuilder::<T>::new(&partial_db, &root).build();

		let mut iter = trie.iter().unwrap();
		iter.seek(b"AA").unwrap();
		assert_eq!(&vals[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	}
}

test_layouts!(test_cache, test_cache_internal);
fn test_cache_internal<T: TrieLayout>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
		(b"BC".to_vec(), vec![4; 64]),
	];

	let mut memdb = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut cache = TestTrieCache::<T>::default();

	{
		let mut t =
			TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).with_cache(&mut cache).build();
		for (key, value) in &key_value {
			t.insert(key, value).unwrap();
		}
	}

	// Ensure that when we cache the same value multiple times under different keys,
	// the first cached key is still working.
	assert_eq!(
		cache.lookup_value_for_key(&b"B"[..]).unwrap().data().flatten().unwrap(),
		vec![4u8; 64]
	);
	assert_eq!(
		cache.lookup_value_for_key(&b"BC"[..]).unwrap().data().flatten().unwrap(),
		vec![4u8; 64]
	);

	// Ensure that we don't insert the same node multiple times, which would result in invalidating
	// cached values.
	let cached_value = cache.lookup_value_for_key(&b"AB"[..]).unwrap().clone();
	assert_eq!(cached_value.data().flatten().unwrap(), vec![3u8; 4]);

	{
		let mut t =
			TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).with_cache(&mut cache).build();
		for (key, value) in &key_value {
			t.insert(key, value).unwrap();
		}
	}

	assert_eq!(
		cache.lookup_value_for_key(&b"AB"[..]).unwrap().data().flatten().unwrap(),
		vec![3u8; 4]
	);
	assert_eq!(cached_value.data().flatten().unwrap(), vec![3u8; 4]);

	// Clear all nodes and ensure that the value cache works flawlessly.
	cache.clear_node_cache();

	{
		let t = TrieDBBuilder::<T>::new(&mut memdb, &mut root).with_cache(&mut cache).build();
		for (key, value) in &key_value {
			assert_eq!(*value, t.get(key).unwrap().unwrap());
		}
	}

	// Ensure `get_hash` is also working properly
	cache.clear_node_cache();

	{
		let t = TrieDBBuilder::<T>::new(&mut memdb, &mut root).with_cache(&mut cache).build();
		for (key, value) in &key_value {
			assert_eq!(T::Hash::hash(value), t.get_hash(key).unwrap().unwrap());
		}
	}
}

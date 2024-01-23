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

use arbitrary::Arbitrary;
use reference_trie::{
	calc_root, compare_insert_remove, reference_trie_root_iter_build as reference_trie_root,
};
use std::{convert::TryInto, fmt::Debug};
use trie_db::{
	memory_db::{HashKey, MemoryDB, PrefixedKey},
	node_db::Hasher,
	proof::{generate_proof, verify_proof},
	DBValue, Trie, TrieDBBuilder, TrieDBIterator, TrieDBMutBuilder, TrieLayout,
};

fn fuzz_to_data(input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut result = Vec::new();
	// enc = (minkeylen, maxkeylen (min max up to 32), datas)
	// fix data len 2 bytes
	let mut minkeylen = if let Some(v) = input.get(0) {
		let mut v = *v & 31u8;
		v = v + 1;
		v
	} else {
		return result
	};
	let mut maxkeylen = if let Some(v) = input.get(1) {
		let mut v = *v & 31u8;
		v = v + 1;
		v
	} else {
		return result
	};

	if maxkeylen < minkeylen {
		let v = minkeylen;
		minkeylen = maxkeylen;
		maxkeylen = v;
	}
	let mut ix = 2;
	loop {
		let keylen = if let Some(v) = input.get(ix) {
			let mut v = *v & 31u8;
			v = v + 1;
			v = std::cmp::max(minkeylen, v);
			v = std::cmp::min(maxkeylen, v);
			v as usize
		} else {
			break
		};
		let key = if input.len() > ix + keylen { input[ix..ix + keylen].to_vec() } else { break };
		ix += keylen;
		let val = if input.len() > ix + 2 { input[ix..ix + 2].to_vec() } else { break };
		result.push((key, val));
	}
	result
}

fn fuzz_removal(data: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(bool, Vec<u8>, Vec<u8>)> {
	let mut res = Vec::new();
	let mut torem = None;
	for (a, d) in data.into_iter().enumerate() {
		if a % 7 == 6 {
			// a random removal some time
			res.push((true, d.0, d.1));
		} else {
			if a % 5 == 0 {
				torem = Some((true, d.0.clone(), d.1.clone()));
			}
			res.push((false, d.0, d.1));
			if a % 5 == 4 {
				if let Some(v) = torem.take() {
					res.push(v);
				}
			}
		}
	}
	res
}

pub fn fuzz_that_reference_trie_root<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	let memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(t.commit().root_hash(), reference_trie_root::<T, _, _, _>(data));
}

pub fn fuzz_that_reference_trie_root_fix_length<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));
	let memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(t.commit().root_hash(), reference_trie_root::<T, _, _, _>(data));
}

fn fuzz_to_data_fix_length(input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut result = Vec::new();
	let mut ix = 0;
	loop {
		let keylen = 32;
		let key = if input.len() > ix + keylen { input[ix..ix + keylen].to_vec() } else { break };
		ix += keylen;
		let val = if input.len() > ix + 2 { input[ix..ix + 2].to_vec() } else { break };
		result.push((key, val));
	}
	result
}

fn data_sorted_unique(input: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut m = std::collections::BTreeMap::new();
	for (k, v) in input.into_iter() {
		let _ = m.insert(k, v); // latest value for uniqueness
	}
	m.into_iter().collect()
}

pub fn fuzz_that_compare_implementations<T: TrieLayout>(input: &[u8])
	where T::Location: Debug,
{
	let data = data_sorted_unique(fuzz_to_data(input));
	reference_trie::compare_implementations::<T, PrefixedKey<_>>(data);
}

pub fn fuzz_that_no_extension_insert<T: TrieLayout>(input: &[u8]) {
	let data = fuzz_to_data(input);
	//println!("data{:?}", data);
	let memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	// we are testing the RefTrie code here so we do not sort or check uniqueness
	// before.
	let data = data_sorted_unique(fuzz_to_data(input));
	//println!("data{:?}", data);
	assert_eq!(t.commit().root_hash(), calc_root::<T, _, _, _>(data));
}

pub fn fuzz_that_no_extension_insert_remove<T: TrieLayout>(input: &[u8]) {
	let data = fuzz_to_data(input);
	let data = fuzz_removal(data);

	compare_insert_remove::<T, PrefixedKey<_>>(data);
}

pub fn fuzz_seek_iter<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));

	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	let root = t.commit().apply_to(&mut memdb);

	// fuzzing around a fix prefix of 6 nibble.
	let prefix = &b"012"[..];

	let mut iter_res2 = Vec::new();
	for a in data {
		if a.0.starts_with(prefix) {
			iter_res2.push(a.0);
		}
	}

	let mut iter_res = Vec::new();
	let mut error = 0;
	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();
		let mut iter = trie.iter().unwrap();
		if let Ok(_) = iter.seek(prefix) {
		} else {
			error += 1;
		}

		for x in iter {
			if let Ok((key, _)) = x {
				if key.starts_with(prefix) {
					iter_res.push(key);
				} else {
					break
				}
			} else {
				error += 1;
			}
		}
	}

	assert_eq!(iter_res, iter_res2);
	assert_eq!(error, 0);
}

pub fn fuzz_prefix_iter<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));

	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	let root = t.commit().apply_to(&mut memdb);

	// fuzzing around a fix prefix of 6 nibble.
	let prefix = &b"012"[..];

	let mut iter_res2 = Vec::new();
	for a in data {
		if a.0.starts_with(prefix) {
			iter_res2.push(a.0);
		}
	}

	let mut iter_res = Vec::new();
	let mut error = 0;
	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();
		let iter = TrieDBIterator::new_prefixed(&trie, prefix).unwrap();

		for x in iter {
			if let Ok((key, _)) = x {
				if key.starts_with(prefix) {
					iter_res.push(key);
				} else {
					println!("error out of range");
					error += 1;
				}
			} else {
				error += 1;
			}
		}
	}

	assert_eq!(iter_res, iter_res2);
	assert_eq!(error, 0);
}

#[derive(Debug, Arbitrary)]
pub struct PrefixSeekTestInput {
	keys: Vec<Vec<u8>>,
	prefix_key: Vec<u8>,
	seek_key: Vec<u8>,
}

fn printable_keys<T: AsRef<[u8]>>(iter: impl IntoIterator<Item = T>) -> String {
	iter.into_iter()
		.map(|key| format!("\"{}\"", array_bytes::bytes2hex("", key)))
		.collect::<Vec<_>>()
		.join(", ")
}

pub fn fuzz_prefix_seek_iter<T: TrieLayout>(mut input: PrefixSeekTestInput) {
	type PrefixedMemoryDB<T> =
		MemoryDB<<T as TrieLayout>::Hash, PrefixedKey<<T as TrieLayout>::Hash>, DBValue>;

	input.keys.retain_mut(|key| !key.is_empty());

	input.keys.sort_unstable();
	input.keys.dedup();

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for (index, key) in input.keys.iter().enumerate() {
		t.insert(&key, &[index as u8]).unwrap();
	}
	let root = t.commit().apply_to(&mut memdb);

	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();
	let iter =
		trie_db::TrieDBIterator::new_prefixed_then_seek(&trie, &input.prefix_key, &input.seek_key)
			.unwrap();
	let output_keys: Vec<_> = iter.map(|item| item.unwrap().0).collect();

	let input_keys = input.keys;
	let seek_key = input.seek_key;
	let prefix_key = input.prefix_key;
	let expected_keys: Vec<_> = input_keys
		.iter()
		.filter(|key| key.starts_with(&prefix_key) && **key >= seek_key)
		.cloned()
		.collect();

	if output_keys != expected_keys {
		panic!(
			"Test failed!\nresult = [{result}]\nexpected = [{expected}]\nprefix_key = \"{prefix_key}\"\nseek_key = \"{seek_key}\"\nkeys = [{input_keys}]",
			result = printable_keys(output_keys),
			expected = printable_keys(expected_keys),
			prefix_key = array_bytes::bytes2hex("", prefix_key),
			seek_key = array_bytes::bytes2hex("", seek_key),
			input_keys = printable_keys(input_keys)
		);
	}
}

pub fn fuzz_that_verify_accepts_valid_proofs<T: TrieLayout>(input: &[u8]) {
	let mut data = fuzz_to_data(input);
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	let (root, proof, items) = test_generate_proof::<T>(data, keys);
	assert!(verify_proof::<T, _, _, _>(&root, &proof, items.iter()).is_ok());
}

pub fn fuzz_that_trie_codec_proofs<T: TrieLayout>(input: &[u8]) {
	let mut data = fuzz_to_data(input);
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	test_trie_codec_proof::<T>(data, keys);
}

pub fn fuzz_that_verify_rejects_invalid_proofs<T: TrieLayout>(input: &[u8]) {
	if input.len() < 4 {
		return
	}

	let random_int = u32::from_le_bytes(input[0..4].try_into().expect("slice is 4 bytes")) as usize;

	let mut data = fuzz_to_data(&input[4..]);
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	if keys.is_empty() {
		return
	}

	let (root, proof, mut items) = test_generate_proof::<T>(data, keys);

	// Make one item at random incorrect.
	let items_idx = random_int % items.len();
	match &mut items[items_idx] {
		(_, Some(value)) if random_int % 2 == 0 => value.push(0),
		(_, value) if value.is_some() => *value = None,
		(_, value) => *value = Some(DBValue::new()),
	}
	assert!(verify_proof::<T, _, _, _>(&root, &proof, items.iter()).is_err());
}

fn test_generate_proof<L: TrieLayout>(
	entries: Vec<(Vec<u8>, Vec<u8>)>,
	keys: Vec<Vec<u8>>,
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(Vec<u8>, Option<DBValue>)>) {
	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
		let mut trie = TrieDBMutBuilder::<L>::new(&mut db).build();
		for (key, value) in entries {
			trie.insert(&key, &value).unwrap();
		}
		let root = trie.commit().apply_to(&mut db);
		(db, root)
	};

	// Generate proof for the given keys..
	let proof = generate_proof::<_, L, _, _>(&db, &root, keys.iter()).unwrap();
	let trie = TrieDBBuilder::<L>::new(&db, &root).build();
	let items = keys
		.into_iter()
		.map(|key| {
			let value = trie.get(&key).unwrap();
			(key, value)
		})
		.collect();

	(root, proof, items)
}

fn test_trie_codec_proof<L: TrieLayout>(entries: Vec<(Vec<u8>, Vec<u8>)>, keys: Vec<Vec<u8>>) {
	use trie_db::{node_db::EMPTY_PREFIX, decode_compact, encode_compact, Recorder};

	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
		let mut trie = TrieDBMutBuilder::<L>::new(&db).build();
		for (key, value) in entries {
			trie.insert(&key, &value).unwrap();
		}
		let root = trie.commit().apply_to(&mut db);
		(db, root)
	};
	let expected_root = root;
	// Lookup items in trie while recording traversed nodes.
	let mut recorder = Recorder::<L>::new();
	let items = {
		let mut items = Vec::with_capacity(keys.len());
		let trie = TrieDBBuilder::<L>::new(&db, &root).with_recorder(&mut recorder).build();
		for key in keys {
			let value = trie.get(key.as_slice()).unwrap();
			items.push((key, value));
		}
		items
	};

	// Populate a partial trie DB with recorded nodes.
	let mut partial_db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
	for record in recorder.drain() {
		partial_db.emplace(record.hash, EMPTY_PREFIX, record.data);
	}

	// Compactly encode the partial trie DB.
	let compact_trie = {
		let trie = TrieDBBuilder::<L>::new(&partial_db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};

	let expected_used = compact_trie.len();
	// Reconstruct the partial DB from the compact encoding.
	let mut db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
	let (root, used) = decode_compact::<L>(&mut db, &compact_trie).unwrap();
	assert_eq!(root, expected_root);
	assert_eq!(used, expected_used);

	// Check that lookups for all items succeed.
	let trie = TrieDBBuilder::<L>::new(&db, &root).build();
	for (key, expected_value) in items {
		assert_eq!(trie.get(key.as_slice()).unwrap(), expected_value);
	}
}

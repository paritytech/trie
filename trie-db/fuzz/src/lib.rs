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
use keccak_hasher::KeccakHasher;
use memory_db::{HashKey, MemoryDB, PrefixedKey};
use reference_trie::{
	calc_root_no_extension,
	compare_no_extension_insert_remove,
	ExtensionLayout,
	NoExtensionLayout, batch_update, InputAction,
	proof::{generate_proof, verify_proof},
	reference_trie_root,
	RefTrieDBMut,
	RefTrieDBMutNoExt,
	RefTrieDBNoExt,
	TrieDBIterator,
};
use std::convert::TryInto;
use trie_db::{DBValue, Trie, TrieDB, TrieDBMut, TrieLayout, TrieMut};

fn fuzz_to_data(input: &[u8]) -> Vec<(Vec<u8>,Vec<u8>)> {
	let mut result = Vec::new();
	// enc = (minkeylen, maxkeylen (min max up to 32), datas)
	// fix data len 2 bytes
	let mut minkeylen = if let Some(v) = input.get(0) {
		let mut v = *v & 31u8;
		v = v + 1;
		v
	} else { return result; };
	let mut maxkeylen = if let Some(v) = input.get(1) {
		let mut v = *v & 31u8;
		v = v + 1;
		v
	} else { return result; };

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
		} else { break };
		let key = if input.len() > ix + keylen {
			input[ix..ix+keylen].to_vec()
		} else { break };
		ix += keylen;
		let val = if input.len() > ix + 2 {
			input[ix..ix+2].to_vec()
		} else { break };
		result.push((key,val));
	}
	result
}

fn fuzz_removal(data: Vec<(Vec<u8>,Vec<u8>)>) -> Vec<(bool, Vec<u8>, Vec<u8>)> {
	let mut res = Vec::new();
	let mut torem = None;
	for (a, d) in data.into_iter().enumerate() {
		if a % 7 == 6	{
			// a random removal some time
			res.push((true, d.0, d.1));
		} else {
			if a % 5 == 0	{
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

pub fn fuzz_that_reference_trie_root(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(*t.root(), reference_trie_root(data));
}

pub fn fuzz_that_reference_trie_root_fix_length(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(*t.root(), reference_trie_root(data));
}

fn fuzz_to_data_fix_length(input: &[u8]) -> Vec<(Vec<u8>,Vec<u8>)> {
	let mut result = Vec::new();
	let mut ix = 0;
	loop {
		let keylen = 32;
		let key = if input.len() > ix + keylen {
			input[ix..ix+keylen].to_vec()
		} else { break };
		ix += keylen;
		let val = if input.len() > ix + 2 {
			input[ix..ix+2].to_vec()
		} else { break };
		result.push((key,val));
	}
	result
}

fn data_sorted_unique(input: Vec<(Vec<u8>,Vec<u8>)>) -> Vec<(Vec<u8>,Vec<u8>)> {
	let mut m = std::collections::BTreeMap::new();
	for (k,v) in input.into_iter() {
		let _ = m.insert(k,v); // latest value for uniqueness
	}
	m.into_iter().collect()
}

pub fn fuzz_that_compare_implementations(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	//println!("data:{:?}", &data);
	let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	let hashdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	reference_trie::compare_implementations(data, memdb, hashdb);
}

pub fn fuzz_that_unhashed_no_extension(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	reference_trie::compare_unhashed_no_extension(data);
}

pub fn fuzz_that_no_extension_insert(input: &[u8]) {
	let data = fuzz_to_data(input);
	//println!("data{:?}", data);
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	// we are testing the RefTrie code here so we do not sort or check uniqueness
	// before.
	let data = data_sorted_unique(fuzz_to_data(input));
	//println!("data{:?}", data);
	assert_eq!(*t.root(), calc_root_no_extension(data));
}

pub fn fuzz_that_no_extension_insert_remove(input: &[u8]) {
	let data = fuzz_to_data(input);
	let data = fuzz_removal(data);

	let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	compare_no_extension_insert_remove(data, memdb);
}

pub fn fuzz_seek_iter(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));

	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for a in 0..data.len() {
			t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
		}
	}

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
			let trie = RefTrieDBNoExt::new(&memdb, &root).unwrap();
			let mut iter =  trie.iter().unwrap();
			if let Ok(_) = iter.seek(prefix) {
			} else {
				error += 1;
			}

			for x in iter {
				if let Ok((key, _)) = x {
				if key.starts_with(prefix) {
					iter_res.push(key);
				} else {
					break;
				}
				} else {
					error +=1;
				}
			}
	}

	assert_eq!(iter_res, iter_res2);
	assert_eq!(error, 0);
}

pub fn fuzz_prefix_iter(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));

	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for a in 0..data.len() {
			t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
		}
	}

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
			let trie = RefTrieDBNoExt::new(&memdb, &root).unwrap();
			let iter = TrieDBIterator::new_prefixed(&trie, prefix).unwrap();

			for x in iter {
				if let Ok((key, _)) = x {
				if key.starts_with(prefix) {
					iter_res.push(key);
				} else {
					println!("error out of range");
					error +=1;
				}
				} else {
					error +=1;
				}
			}
	}

	assert_eq!(iter_res, iter_res2);
	assert_eq!(error, 0);
}

pub fn fuzz_that_verify_accepts_valid_proofs(input: &[u8]) {
	let mut data = fuzz_to_data(input);
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..]
		.iter()
		.map(|(key, _)| key.clone())
		.collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	let (root, proof, items) = test_generate_proof::<ExtensionLayout>(data, keys);
	assert!(verify_proof::<ExtensionLayout, _, _, _>(&root, &proof, items.iter()).is_ok());
}

pub fn fuzz_that_verify_rejects_invalid_proofs(input: &[u8]) {
	if input.len() < 4 {
		return;
	}

	let random_int = u32::from_le_bytes(
		input[0..4].try_into().expect("slice is 4 bytes")
	) as usize;

	let mut data = fuzz_to_data(&input[4..]);
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..]
		.iter()
		.map(|(key, _)| key.clone())
		.collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	if keys.is_empty() {
		return;
	}

	let (root, proof, mut items) = test_generate_proof::<ExtensionLayout>(data, keys);

	// Make one item at random incorrect.
	let items_idx = random_int % items.len();
	match &mut items[items_idx] {
		(_, Some(value)) if random_int % 2 == 0 => value.push(0),
		(_, value) if value.is_some() => *value = None,
		(_, value) => *value = Some(DBValue::new()),
	}
	assert!(verify_proof::<ExtensionLayout, _, _, _>(&root, &proof, items.iter()).is_err());
}

fn test_generate_proof<L: TrieLayout>(
	entries: Vec<(Vec<u8>, Vec<u8>)>,
	keys: Vec<Vec<u8>>,
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(Vec<u8>, Option<DBValue>)>)
{
	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
		let mut root = Default::default();
		{
			let mut trie = <TrieDBMut<L>>::new(&mut db, &mut root);
			for (key, value) in entries {
				trie.insert(&key, &value).unwrap();
			}
		}
		(db, root)
	};

	// Generate proof for the given keys..
	let trie = <TrieDB<L>>::new(&db, &root).unwrap();
	let proof = generate_proof::<_, L, _, _>(&trie, keys.iter()).unwrap();
	let items = keys.into_iter()
		.map(|key| {
			let value = trie.get(&key).unwrap();
			(key,value)
		})
		.collect();

	(root, proof, items)
}

pub fn fuzz_batch_update(input: &[u8], build_val: fn(&mut Vec<u8>), compare_db: bool) {
	let data = fuzz_to_data(input);
	let mut data = fuzz_removal(data);
	for i in data.iter_mut() {
		build_val(&mut i.2);
	}
	let data = data;
//println!("{}: {:?}", data.len(), data);
	let mut db = memory_db::MemoryDB::<_, PrefixedKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = reference_trie::RefTrieDBMutNoExt::new(&mut db, &mut root);
		for i in 0..data.len() / 2 {
			let key: &[u8]= &data[i].1;
			let val: &[u8] = &data[i].2;
			t.insert(key, val).unwrap();
		}
	}

	let initial_root = root.clone();
	let mut initial_db = db.clone();

	let mut sorted_data = std::collections::BTreeMap::new();
	{
		let mut t = reference_trie::RefTrieDBMutNoExt::from_existing(&mut db, &mut root)
			.unwrap();
		for i in data.len() / 2..data.len() {
			let key: &[u8]= &data[i].1;
			let val: &[u8] = &data[i].2;
			if !data[i].0 {
				sorted_data.insert(key, Some(val));
				t.insert(key, val).unwrap();
			} else {
				sorted_data.insert(key, None);
				// remove overwrite insert from fuzz_removal ordering,
				// that is important
				t.remove(key).unwrap();
			}
		}
	}
//println!("{:?}", sorted_data);
	let (calc_root, payload, _detached) = reference_trie::trie_traverse_key_no_extension_build(
		&mut initial_db,
		&initial_root,
		sorted_data.into_iter(),
	);
	assert!(calc_root == root);

	if compare_db {
		for (p, h, v) in payload {
			use hash_db::HashDB;
			if let Some(v) = v {
				let prefix = (p.0.as_ref(), p.1);
				initial_db.emplace(h, prefix, v[..].into());
			} else {
				let prefix = (p.0.as_ref(), p.1);
				initial_db.remove(&h, prefix);
			}
		}

		assert!(initial_db == db);
	}
}

pub fn fuzz_detach_attach(input: &[u8], build_val: fn(&mut Vec<u8>), compare_db: bool) {
	//x: &[(Vec<u8>, Vec<u8>)],
	//d: &Vec<u8>,
	let mut data = fuzz_to_data(input);
	if data.len() == 0 {
		return;
	}
	for i in data.iter_mut() {
		build_val(&mut i.1);
	}
	let x = &data[1..];
	let d = &data[0].0;
	//println!("{:?}\n d {:?}", x, d);
	let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = reference_trie::RefTrieDBMutNoExt::new(&mut db, &mut root);
		for i in 1..x.len() {
			let key: &[u8]= &x[i].0;
			let val: &[u8] = &x[i].1;
			t.insert(key, val).unwrap();
		}
	}
	let initial_root = root.clone();
	let initial_db = db.clone();
	// reference
	{
		let mut t = RefTrieDBMutNoExt::from_existing(&mut db, &mut root).unwrap();
		for i in 1..x.len() {
			if x[i].0.starts_with(d) {
				let key: &[u8]= &x[i].0;
				t.remove(key).unwrap();
			}
		}
	}
	let elements = Some(d.clone()).into_iter().map(|k| (k, InputAction::<Vec<u8>, _>::Detach));
	let (calc_root, payload, payload_det, detached_root) = batch_update::<NoExtensionLayout, _, _, _, _>(
		&initial_db,
		&initial_root,
		elements,
	).unwrap();

	assert_eq!(calc_root, root);

	let mut batch_delta = initial_db.clone();
	for (p, h, v) in payload.into_iter().chain(payload_det) {
		use hash_db::HashDB;
		if let Some(v) = v {
			let prefix = (p.0.as_ref(), p.1);
			batch_delta.emplace(h, prefix, v[..].into());
		} else {
			let prefix = (p.0.as_ref(), p.1);
			batch_delta.remove(&h, prefix);
		}
	}

	// attach back
	let elements = detached_root.into_iter().map(|(k, _prefix, root)| (k, InputAction::<Vec<u8>, _>::Attach(root)));
	let (calc_root, payload, payload_det, detached_root) = batch_update::<NoExtensionLayout, _, _, _, _>(
		&batch_delta,
		&calc_root,
		elements,
	).unwrap();
	if detached_root.is_empty() {
		if compare_db {
			for (p, h, v) in payload.into_iter().chain(payload_det) {
				use hash_db::HashDB;
				if let Some(v) = v {
					let prefix = (p.0.as_ref(), p.1);
					batch_delta.emplace(h, prefix, v[..].into());
				} else {
					let prefix = (p.0.as_ref(), p.1);
					batch_delta.remove(&h, prefix);
				}
			}
			batch_delta.purge();
			assert!(initial_db == batch_delta);
		}
		assert!(calc_root == initial_root);
	} else {
		// case where there was a node fuse due to dettach
		// we could inject manually detached node and compare
	}
}


#[test]
fn test() {
	let tests = [
		vec![0x1,0x0,0x0,0x0,0x8,0xc,0x8,0x8,0x8,0x0,0x3d,0x0,0x9d,0x4,0x4e],
		vec![0x1,0x0,0x0,0x0,0x8,0x8,0x8,0x8,0x8,0x0,0x80,0x0,0x9d,0x4,0x4e],
		vec![0x0,0x80,0xd4,0xd4,0xd4,0xd4,0x3a,0x3a,0x3f,0x0,0x3f,0x0],
		vec![0x0,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x9,0x1,0x8d,0x2c,0xd4,0x0,0x0,0x33,0x8a,0x20,0x80,0x9a,0x2c,0xd4,0x0,0x0,0x33,0x8a,0xff,0x8],
		vec![0xff,0xd1,0x0,0x90,0x40,0xd4,0x8d,0x1,0x0,0x0,0xff,0x90,0x40,0xd4,0x8d,0x1,0x0,0x8d,0xce,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xd0,0xd0,0xd0,0xd0,0xd0,0xd0,0xd0,0xd0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x80,0x6,0x8,0x15,0x1,0x4,0x0,0x8d,0x87,0xcf,0x0,0x3f,0xcb,0xd8,0xb9,0xa2,0x4d,0x9a,0xd6,0xd2,0x0,0x0,0x0,0x0,0x80,0x0,0x6,0x8,0x15,0x1,0x4,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x23,0xc7,0xd7,0xd7,0xfb,0x7f,0x83,0x3,0x37,0x37,0x37,0xb2,0xa8,0xb,0xf5,0x5a,0x50,0xb6,0x0,0xff,0x17,0x21,0x0],
		vec![0x43,0x19,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x3,0x0,0x0,0x6,0x0,0x0,0x0,0x0,0xaa,0x0,0x0,0x49,0x0,0x0,0xc7,0x8d,0x0,0x5b,0x2d,0xbd,0x20,0x0,0x0,0x0,0x0,0xc7,0x8d,0x0,0x5b,0x2d,0xbd,0x20,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xaa,0x0,0x0,0x49,0x1,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0xc,0x0,0x80,0x0,0x0,0x0,0x0,0x0,0x0,0x4,0x40,0x2,0x4,0x0,0x0,0xc7,0x8d,0x0,0x0,0xe0],
		vec![0x7f,0x2b,0x4,0x3a,0x89,0xfb,0x0,0x2e,0x70,0x0,0x0,0x2e,0x2,0x0,0x0,0x0,0x41,0xd1,0x2e,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x0,0x80,0xff,0xcd,0x72,0xfb,0x7f,0xc3,0x0,0x9a,0xff,0xff,0xff,0x72,0xfb,0x7f,0xff,0x0,0x0,0x0,0x0,0x0,0x82,0x82,0x81,0x81,0x29,0x8f,0x7d,0x42,0x12,0xf7,0xb4,0x77,0xd6,0x65,0x91,0xff,0x96,0xa9,0xe0,0x64,0xbc,0xc9,0x8a,0x70,0xc,0x4,0x0,0x0,0xc3,0x0,0x0,0x0,0x0,0x0,0x0],
		vec![0x0,0x84,0xff,0xfb,0x7f,0xff,0xff,0xff,0xff,0x7f,0x70,0xff,0xff,0x7f,0x72,0xfd,0xc3,0x0,0x4,0xfb,0xff,0x10,0x10,0x10,0x10,0x10,0x9a,0x4],
		vec![0x0,0x80,0xd4,0x0,0x1,0xc,0x0,0xc,0xd,0x2,0x9,0xd4,0xd4,0x0,0x8,0x8,0x8,0x1,0x0,0x0,0x0,0x0],
		vec![0x0,0x80,0x0,0xd1,0x0,0x0,0x9a,0x4,0x4,0x0,0x0,0xc],
		vec![0x0,0x0,0xff,0xff,0x0,0x0,0x4,0x8d,0x87,0xd1],
		vec![0x0,0x0,0x0,0x0,0x4,0x0,0xff,0xd1,0x0,0x0,0xfe,0x0],
		vec![0x0,0x0,0xfe,0x0,0xff,0xff,0xd1,0xd1,0x27,0x0],
		vec![0x0,0xfe,0x41,0x0,0x0,0x80,0x0,0x0,0xff],
		vec![0x0,0x0,0x0,0x4,0x20,0x1a,0x0,0x0],
		vec![0x0,0x0,0x0,0x0,0xfe,0xff,0xff,0xd1,0x27],
		vec![0x0,0x0,0x0,0xb7,0x4,0xf8,0x0,0x0,0x0],
		vec![0xa,0x0,0x0,0x0,0x0,0x4,0x0,0x0],
		vec![0x0,0x0,0x0,0x0,0x8d,0x4],
		vec![0x0,0x0,0x4,0x8d,0x8d,0x4],
	];
	for v in tests.iter() {
		fuzz_batch_update(&v[..], |_v| (), false);
		fuzz_batch_update(&v[..], |v| v.extend(&[4u8; 32]), true);
	}
}

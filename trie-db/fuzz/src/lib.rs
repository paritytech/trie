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



use memory_db::{MemoryDB, HashKey, PrefixedKey};
use reference_trie::{
	RefTrieDBMutNoExt,
	RefTrieDBMut,
	reference_trie_root,
	calc_root_no_extension,
	compare_no_extension_insert_remove,
};
use trie_db::{TrieMut, DBValue};
use keccak_hasher::KeccakHasher;



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

fn fuzz_removal(data: Vec<(Vec<u8>,Vec<u8>)>) -> Vec<(bool, Vec<u8>,Vec<u8>)> {
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

pub fn fuzz_batch_update(input: &[u8], build_val: fn(&mut Vec<u8>)) {
	let data = fuzz_to_data(input);
	let mut data = fuzz_removal(data);
	for i in data.iter_mut() {
		build_val(&mut i.2);
	}
	let data = data;
println!("{}: {:?}", data.len(), data);
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
	let mut batch_update = reference_trie::BatchUpdate(
		Default::default(),
		initial_root.clone(),
		None,
	);
println!("{:?}", sorted_data);
	reference_trie::trie_traverse_key_no_extension_build(
		&mut initial_db,
		&initial_root, sorted_data.into_iter(), &mut batch_update);
//	println!("{:?}", batch_update.1);
//	println!("{:?}", root);
	assert!(batch_update.1 == root);
}

#[test]
fn test() {
	let tests = [
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
		fuzz_batch_update(&v[..], |_v| ());
		fuzz_batch_update(&v[..], |v| v.extend(&[4u8; 32]));
	}
}

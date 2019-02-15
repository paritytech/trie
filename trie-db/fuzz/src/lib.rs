

use memory_db::MemoryDB;
use reference_trie::{
  RefTrieDBMutNoExt,
  RefTrieDBMut,
  ref_trie_root,
  calc_root_no_ext,
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


pub fn fuzz_that_ref_trie_root(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	let mut memdb = MemoryDB::default();
	let mut root = Default::default();
	let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(*t.root(), ref_trie_root(data));
}

pub fn fuzz_that_ref_trie_root_fix_len(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_len(input));
	let mut memdb = MemoryDB::default();
	let mut root = Default::default();
	let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(*t.root(), ref_trie_root(data));
}

fn fuzz_to_data_fix_len(input: &[u8]) -> Vec<(Vec<u8>,Vec<u8>)> {
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


pub fn fuzz_that_compare_impl(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	let memdb = MemoryDB::default();
	let hashdb = MemoryDB::<KeccakHasher, DBValue>::default();
	reference_trie::compare_impl(data, memdb, hashdb);
}

pub fn fuzz_that_no_ext_insert(input: &[u8]) {
  let data = fuzz_to_data(input);
  //println!("data{:?}", data);
	let mut memdb = MemoryDB::default();
	let mut root = Default::default();
	let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
  // we are testing the RefTrie code here so we do not sort or check uniqueness
  // before.
	let data = data_sorted_unique(fuzz_to_data(input));
  //println!("data{:?}", data);
	assert_eq!(*t.root(), calc_root_no_ext(data));
}

pub fn fuzz_that_no_ext_insert_remove(input: &[u8]) {
  let data = fuzz_to_data(input);
	let mut data2 = std::collections::BTreeMap::new();
	let mut memdb = MemoryDB::default();
	let mut root = Default::default();
	let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
  let mut torem = None;
//  println!("data{:?}", data);
	for a in 0..data.len() {
    if a % 7 == 6  {
//  println!("remrand{:?}", a);
      // a random removal some time
		  t.remove(&data[a].0[..]).unwrap();
		  data2.remove(&data[a].0[..]);
    } else {
      if a % 5 == 0  {
//  println!("rem{:?}", a);
        torem = Some(data[a].0.to_vec());
      }
      t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
      data2.insert(&data[a].0[..], &data[a].1[..]);
      if a % 5 == 4 {
        if let Some(v) = torem.take() {
//  println!("remdoneaft {:?}", a);
          t.remove(&v[..]);
          data2.remove(&v[..]);
        }
      }
    }
	}
  // we are testing the RefTrie code here so we do not sort or check uniqueness
  // before.
  //println!("data{:?}", data);
	assert_eq!(*t.root(), calc_root_no_ext(data2));
}

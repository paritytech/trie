// Copyright 2020 Parity Technologies
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

use trie_standardmap::{Alphabet, StandardMap, ValueMode};
use hash_db::{
	HashDB,
	EMPTY_PREFIX,
};
use memory_db::{
	MemoryDB,
	PrefixedKey,
	HashKey,
};
use reference_trie::{
	ExtensionLayoutHybrid,
	ExtensionLayout,
	TrieDBMut,
	TrieMut,
	TrieDB,
	Trie,
	TrieLayout,
	Recorder,
	encode_compact,
	decode_compact,
};
use parity_scale_codec::{Encode, Compact};

type DBValue = Vec<u8>;

fn main() {
	let trie_size = [100, 1000, 10_000, 100_000];
	let number_key = [1, 10, 100, 1000, 10_000];
	let size_value = 32;
	for s in trie_size.iter() {
		compare(*s, &number_key[..], size_value, true)
	}
}

fn compare(trie_size: u32, number_key: &[usize], size_value: usize, check_proof: bool) {

	let mut seed = Default::default();
	let x = StandardMap {
		alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
		min_key: size_value,
		journal_key: 0,
		value_mode: ValueMode::Index,
		count: trie_size,
	}.make_with(&mut seed);
	let mut memdb = MemoryDB::<<ExtensionLayout as TrieLayout>::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<ExtensionLayout>::new(&mut memdb, &mut root);
		for i in 0..x.len() {
			let key: &[u8]= &x[i].0;
			let val: &[u8] = &x[i].1;
			t.insert(key, val).unwrap();
		}
		t.commit();
	}
	let trie = <TrieDB<ExtensionLayout>>::new(&memdb, &root).unwrap();
	for n in number_key {
		if *n < trie_size as usize {
			// we test only existing key, missing key should have better overall compression(could try with pure random)
			compare_inner(&trie, trie_size, &x[..*n], "standard", check_proof)
		}
	}

	let mut memdb = MemoryDB::<<ExtensionLayoutHybrid as TrieLayout>::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut thyb = TrieDBMut::<ExtensionLayoutHybrid>::new(&mut memdb, &mut root);
		for i in 0..x.len() {
			let key: &[u8]= &x[i].0;
			let val: &[u8] = &x[i].1;
			thyb.insert(key, val).unwrap();
		}
		thyb.commit();
	}
	let trie = <TrieDB<ExtensionLayoutHybrid>>::new(&memdb, &root).unwrap();
	for n in number_key {
		if *n < trie_size as usize {
			compare_inner(&trie, trie_size, &x[..*n], "hybrid", check_proof)
		}
	}
}


fn compare_inner<L: TrieLayout>(trie: &TrieDB<L>, trie_size: u32, keys: &[(Vec<u8>, Vec<u8>)], lay: &str, check_proof: bool) {
	let mut recorder = Recorder::new();
	for (key, _) in keys {
		let _ = trie.get_with(key.as_slice(), &mut recorder).unwrap();
	}

	let mut std_proof_len = 0;
	let mut partial_db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
	let mut nb_elt = 0;
	for record in recorder.drain() {
		std_proof_len += compact_size(record.data.len());
		std_proof_len += record.data.len();
		partial_db.emplace(record.hash, EMPTY_PREFIX, record.data);
		nb_elt += 1;
	}
	std_proof_len += compact_size(nb_elt);
	let compact_trie = {
		let partial_trie = <TrieDB<L>>::new(&partial_db, &trie.root()).unwrap();
		encode_compact::<L>(&partial_trie).unwrap()
	};

	if check_proof {
		let mut memdb = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
		let (root, nbs) = decode_compact::<L, _, _>(&mut memdb, &compact_trie).unwrap();
		println!("nb node in proof {}", nbs);
		let trie = <TrieDB<L>>::new(&memdb, &root).unwrap();
		for (key, value) in keys {
			let v = trie.get(key).unwrap();
			assert_eq!(v.as_ref(), Some(value));
		}
	}
	let mut compact_proof_len = compact_size(compact_trie.len());
	for node in compact_trie.iter() {
		compact_proof_len += compact_size(node.len());
		compact_proof_len += node.len();
	}

	let ratio: f64 = compact_proof_len as f64 / std_proof_len as f64;
	println!(
		"On {} {} size trie, {} proof, non compact: {} compact: {} ratio: {}",
		lay,
		trie_size,
		keys.len(),
		std_proof_len,
		compact_proof_len,
		ratio,
	);
}

fn compact_size(len: usize) -> usize {
	// TODO switch to range, this is slow
	Compact::<u64>(len as u64).encode().len()
}

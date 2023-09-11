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
use hash_db::Hasher;
use memory_db::{HashKey, MemoryDB, PrefixedKey};
use reference_trie::{
	calc_root, compare_insert_remove, reference_trie_root_iter_build as reference_trie_root,
};
use std::convert::TryInto;
use trie_db::{
	proof::{generate_proof, verify_proof},
	DBValue, Trie, TrieDBBuilder, TrieDBIterator, TrieDBMutBuilder, TrieLayout, TrieMut,
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
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(data));
}

pub fn fuzz_that_reference_trie_root_fix_length<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(data));
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

pub fn fuzz_that_compare_implementations<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	//println!("data:{:?}", &data);
	let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	let hashdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	reference_trie::compare_implementations::<T, _>(data, memdb, hashdb);
}

pub fn fuzz_that_no_extension_insert<T: TrieLayout>(input: &[u8]) {
	let data = fuzz_to_data(input);
	//println!("data{:?}", data);
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	// we are testing the RefTrie code here so we do not sort or check uniqueness
	// before.
	let data = data_sorted_unique(fuzz_to_data(input));
	//println!("data{:?}", data);
	assert_eq!(*t.root(), calc_root::<T, _, _, _>(data));
}

pub fn fuzz_that_no_extension_insert_remove<T: TrieLayout>(input: &[u8]) {
	let data = fuzz_to_data(input);
	let data = fuzz_removal(data);

	let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	compare_insert_remove::<T, _>(data, memdb);
}

pub fn fuzz_seek_iter<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));

	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
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
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
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
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (index, key) in input.keys.iter().enumerate() {
			t.insert(&key, &[index as u8]).unwrap();
		}
	}

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
		let mut root = Default::default();
		{
			let mut trie = TrieDBMutBuilder::<L>::new(&mut db, &mut root).build();
			for (key, value) in entries {
				trie.insert(&key, &value).unwrap();
			}
		}
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
	use hash_db::{HashDB, EMPTY_PREFIX};
	use trie_db::{decode_compact, encode_compact, Recorder};

	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
		let mut root = Default::default();
		{
			let mut trie = TrieDBMutBuilder::<L>::new(&mut db, &mut root).build();
			for (key, value) in entries {
				trie.insert(&key, &value).unwrap();
			}
		}
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
	let (root, used) = decode_compact::<L, _>(&mut db, &compact_trie).unwrap();
	assert_eq!(root, expected_root);
	assert_eq!(used, expected_used);

	// Check that lookups for all items succeed.
	let trie = TrieDBBuilder::<L>::new(&db, &root).build();
	for (key, expected_value) in items {
		assert_eq!(trie.get(key.as_slice()).unwrap(), expected_value);
	}
}

/// Query plan proof fuzzing.
pub mod query_plan {
	use super::*;
	use crate::{test_entries, MemoryDB};
	use arbitrary::Arbitrary;
	use rand::{rngs::SmallRng, RngCore, SeedableRng};
	use reference_trie::TestTrieCache;
	use std::collections::{BTreeMap, BTreeSet};
	use trie_db::{
		query_plan::{
			record_query_plan, HaltedStateRecord, InMemQueryPlan, ProofKind, QueryPlanItem,
			Recorder,
		},
		TrieHash, TrieLayout,
	};

	const KEY_SIZES: [usize; 7] = [1, 2, 3, 4, 5, 29, 300];

	// deterministic generator.
	type Rng = SmallRng;

	/// Config for fuzzing.
	#[derive(Debug, Clone, Copy, PartialEq, Eq)]
	pub struct Conf {
		/// Seed.
		pub seed: u64,
		/// proof kind.
		pub kind: ProofKind,
		/// number of items in state.
		pub nb_key_value: usize,
		/// number of different small value.
		pub nb_small_value_set: usize,
		/// number of different small value.
		pub nb_big_value_set: usize,
		/// Test querying hash only
		pub hash_only: bool,
		/// Limit the number of non inline value per proof
		/// TODO could be arbitrary.
		pub limit: usize,
		/// Do we create proof on same memory.
		pub proof_spawn_with_persistence: bool,
		/*
		/// number of query existing.
		pub nb_existing_value_query: usize,
		/// number of query existing.
		pub nb_missing_value_query: usize,
		/// prefix query (can reduce `nb_existing_value_query`).
		pub nb_prefix_query: usize,
		*/
	}

	#[derive(Clone)]
	pub struct FuzzContext<L: TrieLayout> {
		pub reference: BTreeMap<Vec<u8>, Vec<u8>>,
		pub db: MemoryDB<L>,
		pub root: TrieHash<L>,
		pub conf: Conf,
		pub small_values: BTreeSet<Vec<u8>>,
		pub big_values: BTreeSet<Vec<u8>>,
		pub values: Vec<Vec<u8>>,
	}

	fn bytes_set(
		rng: &mut Rng,
		nb: usize,
		sizes: &[usize],
		max_byte_value: Option<usize>,
	) -> BTreeSet<Vec<u8>> {
		if let Some(max_byte_value) = max_byte_value {
			let max_nb_value = sizes.len() * max_byte_value;
			if nb > (max_nb_value / 2) {
				panic!("too many value {}, max is {}", nb, max_nb_value / 2);
			}
		}
		let mut set = BTreeSet::new();
		let mut buff = vec![0u8; nb * 2];
		while set.len() < nb {
			rng.fill_bytes(&mut buff);
			for i in 0..buff.len() / 2 {
				let size = buff[i * 2] as usize % sizes.len();
				let value = if let Some(max_byte_value) = max_byte_value {
					let byte = buff[(i * 2) + 1] % max_byte_value as u8;
					vec![byte; sizes[size]]
				} else {
					let mut value = vec![0u8; sizes[size]];
					rng.fill_bytes(&mut value);
					value
				};
				set.insert(value);
			}
		}
		set
	}

	fn small_value_set(rng: &mut Rng, nb: usize) -> BTreeSet<Vec<u8>> {
		let sizes = [1, 2, 30, 31, 32];
		let max_byte_value = 4; // avoid to many different values.
		bytes_set(rng, nb, &sizes, Some(max_byte_value))
	}

	fn big_value_set(rng: &mut Rng, nb: usize) -> BTreeSet<Vec<u8>> {
		let sizes = [33, 34, 301, 302];
		let max_byte_value = 4; // avoid to many different values.
		bytes_set(rng, nb, &sizes, Some(max_byte_value))
	}

	fn key_set(rng: &mut Rng, nb: usize) -> BTreeSet<Vec<u8>> {
		bytes_set(rng, nb, &KEY_SIZES[..], None)
	}

	/// State building (out of fuzzing loop).
	pub fn build_state<L: TrieLayout>(conf: Conf) -> FuzzContext<L> {
		let mut rng = Rng::seed_from_u64(conf.seed);
		let mut reference = BTreeMap::<Vec<u8>, Vec<u8>>::new();
		let small_values = small_value_set(&mut rng, conf.nb_small_value_set);
		let big_values = big_value_set(&mut rng, conf.nb_big_value_set);
		let mut values: Vec<Vec<u8>> = small_values.iter().cloned().collect();
		values.extend(big_values.iter().cloned());
		let values = values;
		let keys = key_set(&mut rng, conf.nb_key_value);
		for k in keys.into_iter() {
			let value_index = rng.next_u32() as usize % values.len();
			reference.insert(k, values[value_index].clone());
		}

		// add the test entries
		for (key, value) in test_entries() {
			reference.insert(key.to_vec(), value.to_vec());
		}

		let (db, root) = {
			let mut db = <MemoryDB<L>>::default();
			let mut root = Default::default();
			{
				let mut trie = <TrieDBMutBuilder<L>>::new(&mut db, &mut root).build();
				for (key, value) in reference.iter() {
					trie.insert(key, value).unwrap();
				}
			}
			(db, root)
		};
		FuzzContext { reference, db, root, conf, small_values, big_values, values }
	}

	#[derive(Arbitrary, Clone, Debug)]
	enum ArbitraryKey {
		Indexed(usize),
		Random(Vec<u8>),
	}

	/// Base arbitrary for fuzzing.
	#[derive(Arbitrary, Clone, Debug)]
	pub struct ArbitraryQueryPlan(Vec<(bool, ArbitraryKey)>);

	fn arbitrary_query_plan<L: TrieLayout>(
		context: &FuzzContext<L>,
		plan: ArbitraryQueryPlan,
	) -> InMemQueryPlan {
		let conf = &context.conf;
		let mut set = BTreeSet::new();
		for (prefix, k) in plan.0.iter() {
			// TODO Rc to avoid clone
			match k {
				ArbitraryKey::Indexed(at) => {
					set.insert((context.values[at % context.values.len()].clone(), !prefix));
				},
				ArbitraryKey::Random(k) => {
					set.insert((k.clone(), !prefix));
				},
			}
		}
		let mut prev_pref: Option<Vec<u8>> = None;
		let mut query_plan =
			InMemQueryPlan { items: Vec::with_capacity(set.len()), kind: conf.kind };
		for (key, not_prefix) in set.into_iter() {
			if let Some(pref) = prev_pref.as_ref() {
				if key.starts_with(pref) {
					continue
				}
				prev_pref = None;
			}

			if !not_prefix {
				prev_pref = Some(key.clone());
			}

			query_plan.items.push(QueryPlanItem::new(key, conf.hash_only, !not_prefix));
		}
		query_plan
	}

	/// Main entry point for query plan fuzzing.
	pub fn fuzz_query_plan<L: TrieLayout>(context: &FuzzContext<L>, plan: ArbitraryQueryPlan) {
		let conf = context.conf.clone();
		fuzz_query_plan_conf(context, conf, plan);
	}

	/// Main entry point for query plan fuzzing.
	pub fn fuzz_query_plan_conf<L: TrieLayout>(
		context: &FuzzContext<L>,
		conf: Conf,
		plan: ArbitraryQueryPlan,
	) {
		let query_plan = arbitrary_query_plan(context, plan);

		let kind = conf.kind;
		let limit = conf.limit;
		let limit = (limit != 0).then(|| limit);
		let recorder = Recorder::new(conf.kind, Default::default(), limit, None);
		let mut from = HaltedStateRecord::from_start(recorder);
		let mut proofs: Vec<Vec<Vec<u8>>> = Default::default();
		let mut query_plan_iter = query_plan.as_ref();
		let mut cache = TestTrieCache::<L>::default();
		let db = <TrieDBBuilder<L>>::new(&context.db, &context.root)
			.with_cache(&mut cache)
			.build();
		loop {
			record_query_plan::<L, _>(&db, &mut query_plan_iter, &mut from).unwrap();

			if limit.is_none() {
				assert!(!from.is_halted());
			}
			if !from.is_halted() {
				proofs.push(from.finish());
				break
			}
			let rec = if conf.proof_spawn_with_persistence {
				from.statefull(Recorder::new(kind, Default::default(), limit, None))
			} else {
				query_plan_iter = query_plan.as_ref();
				from.stateless(Recorder::new(kind, Default::default(), limit, None))
			};
			proofs.push(rec);
		}

		crate::query_plan::check_proofs::<L>(
			proofs,
			&query_plan,
			conf.kind,
			context.root,
			&context.reference,
			conf.hash_only,
		);
	}

	/// Fuzzing conf 1.
	pub const CONF1: Conf = Conf {
		seed: 0u64,
		kind: ProofKind::FullNodes,
		nb_key_value: 300,
		nb_small_value_set: 5,
		nb_big_value_set: 5,
		hash_only: false,
		limit: 0, // no limit
		proof_spawn_with_persistence: false,
	};

	/// Fuzzing conf 2.
	pub const CONF2: Conf = Conf {
		seed: 0u64,
		kind: ProofKind::CompactNodes,
		nb_key_value: 300,
		nb_small_value_set: 5,
		nb_big_value_set: 5,
		hash_only: false,
		limit: 0, // no limit
		proof_spawn_with_persistence: false,
	};

	#[test]
	fn fuzz_query_plan_1() {
		use reference_trie::{RefHasher, SubstrateV1};
		let plans = [
			ArbitraryQueryPlan(vec![
				(false, ArbitraryKey::Indexed(9137484785696899328)),
				(false, ArbitraryKey::Indexed(393082)),
			]),
			ArbitraryQueryPlan(vec![
				(false, ArbitraryKey::Indexed(17942346408707227648)),
				(false, ArbitraryKey::Indexed(37833)),
			]),
			ArbitraryQueryPlan(vec![
				(true, ArbitraryKey::Random(vec![131, 1, 11, 234, 137, 233, 233, 233, 180])),
				(false, ArbitraryKey::Random(vec![137])),
			]),
			ArbitraryQueryPlan(vec![
				(true, ArbitraryKey::Random(vec![76])),
				(true, ArbitraryKey::Random(vec![198, 198, 234, 35, 76, 76, 1])),
			]),
			ArbitraryQueryPlan(vec![
				(false, ArbitraryKey::Random(vec![225])),
				(true, ArbitraryKey::Random(vec![225, 225, 225, 142])),
			]),
			ArbitraryQueryPlan(vec![
				(false, ArbitraryKey::Indexed(18446475631341993995)),
				(true, ArbitraryKey::Indexed(254)),
			]),
			ArbitraryQueryPlan(vec![(
				true,
				ArbitraryKey::Random(vec![252, 63, 149, 166, 164, 38]),
			)]),
			ArbitraryQueryPlan(vec![(false, ArbitraryKey::Indexed(459829968682))]),
			ArbitraryQueryPlan(vec![(true, ArbitraryKey::Indexed(43218140957))]),
			ArbitraryQueryPlan(vec![]),
		];
		let context: FuzzContext<SubstrateV1<RefHasher>> = build_state(CONF1);
		for plan in plans {
			fuzz_query_plan::<SubstrateV1<RefHasher>>(&context, plan.clone());
		}
	}

	#[test]
	fn fuzz_query_plan_2() {
		use reference_trie::{RefHasher, SubstrateV1};
		let plans = [
			ArbitraryQueryPlan(vec![
				(false, ArbitraryKey::Indexed(18446475631341993995)),
				(true, ArbitraryKey::Indexed(254)),
			]),
			ArbitraryQueryPlan(vec![(
				true,
				ArbitraryKey::Random(vec![252, 63, 149, 166, 164, 38]),
			)]),
			ArbitraryQueryPlan(vec![(false, ArbitraryKey::Indexed(459829968682))]),
			ArbitraryQueryPlan(vec![
				(false, ArbitraryKey::Indexed(17942346408707227648)),
				(false, ArbitraryKey::Indexed(37833)),
			]),
			ArbitraryQueryPlan(vec![(true, ArbitraryKey::Indexed(43218140957))]),
			ArbitraryQueryPlan(vec![]),
		];
		let mut conf = CONF1.clone();
		let context: FuzzContext<SubstrateV1<RefHasher>> = build_state(CONF1);
		for plan in plans {
			conf.limit = 2;
			conf.proof_spawn_with_persistence = true;
			fuzz_query_plan_conf::<SubstrateV1<RefHasher>>(&context, conf, plan.clone());
		}
	}

	#[test]
	fn fuzz_query_plan_3() {
		use reference_trie::{RefHasher, SubstrateV1};
		let plans = [ArbitraryQueryPlan(vec![])];
		let context: FuzzContext<SubstrateV1<RefHasher>> = build_state(CONF2);
		for plan in plans {
			fuzz_query_plan::<SubstrateV1<RefHasher>>(&context, plan.clone());
		}
	}

	#[test]
	fn fuzz_query_plan_4() {
		use reference_trie::{RefHasher, SubstrateV1};
		let plans = [(
			ArbitraryQueryPlan(vec![
				(true, ArbitraryKey::Random(vec![86])),
				(false, ArbitraryKey::Random(vec![232])),
			]),
			3,
			true, // TODO false
		)];
		[(ArbitraryQueryPlan(vec![(false, ArbitraryKey::Random(vec![115]))]), 1, false)];
		let mut conf = CONF2.clone();
		let context: FuzzContext<SubstrateV1<RefHasher>> = build_state(CONF2);
		for (plan, nb, statefull) in plans {
			conf.limit = nb;
			conf.proof_spawn_with_persistence = statefull;
			fuzz_query_plan_conf::<SubstrateV1<RefHasher>>(&context, conf, plan.clone());
		}
	}
}

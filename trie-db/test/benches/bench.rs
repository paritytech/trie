// Copyright 2017, 2018 Parity Technologies
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

use criterion::{criterion_group, criterion_main, Bencher, black_box, Criterion};

use trie_db::{NibbleSlice, proof::{generate_proof, verify_proof}, TrieLayout};
use trie_standardmap::{Alphabet, StandardMap, ValueMode};
use reference_trie::ExtensionLayout as Layout;

criterion_group!(benches,
	root_old,
	root_new,
	root_a_big_v,
	root_b_big_v,
	root_a_small_v,
	root_b_small_v,
	trie_mut_ref_root_a,
	trie_mut_ref_root_b,
	trie_mut_root_a,
	trie_mut_root_b,
	trie_mut_a,
	trie_mut_b,
	trie_mut_build_a,
	trie_mut_build_b,
	trie_iteration,
	nibble_common_prefix,
	trie_proof_verification,
	proof_build_dataset_standard,
	proof_build_dataset_hybrid,
	proof_build_compacting_standard,
	proof_build_compacting_hybrid,
	proof_build_change_standard,
	proof_build_change_hybrid,
);
criterion_main!(benches);

fn nibble_common_prefix(b: &mut Criterion) {
	let st = StandardMap {
		alphabet: Alphabet::Custom(b"abcd".to_vec()),
		min_key: 32,
		journal_key: 0,
		value_mode: ValueMode::Mirror,
		count: 255,
	};
	let (keys, values): (Vec<_>, Vec<_>) = st.make().into_iter().unzip();
	b.bench_function("nibble_common_prefix", move |b| {
		let mixed: Vec<_> = keys.iter().zip(values.iter().rev()).map(|pair| {
			(NibbleSlice::new(pair.0), NibbleSlice::new(pair.1))
		}).collect();

		b.iter(&mut || {
			for (left, right) in mixed.iter() {
				let _ = black_box(left.common_prefix(&right));
			}
		})
	});
}

fn root_a_big_v(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input2(29, 204800 / 2, 512 * 2),
	];

	c.bench_function_over_inputs("root_a_big_v", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone();
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v|(&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();


			reference_trie::calc_root::<Layout, _, _, _>(inputc);
		}),
		data,
	);
}

fn root_b_big_v(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input2(29, 204800, 512),
	];

	c.bench_function_over_inputs("root_b_big_v", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone();
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();


			reference_trie::calc_root::<Layout, _, _, _>(inputc);
		}),
		data,
	);
}


fn root_a_small_v(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input2(29, 204800, 32),
	];

	c.bench_function_over_inputs("root_a_small_v", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone();
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();


			reference_trie::calc_root::<Layout, _, _, _>(inputc);
		}),
		data,
	);
}

fn root_b_small_v(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input2(29, 204800 / 2, 32 * 2),
	];

	c.bench_function_over_inputs("root_b_small_v", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone();
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();


			reference_trie::calc_root::<Layout, _, _, _>(inputc);
		}),
		data,
	);
}

fn root_old(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input(1, 5120),
		input(41, 10240),
		input(18, 102400),
		input(29, 204800),
	];

	c.bench_function_over_inputs("root_old", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone();
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1));

			reference_trie::reference_trie_root::<Layout, _, _, _>(inputc);
		}),
		data,
	);
}


fn root_new(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input(1, 5120),
		input(41, 10240),
		input(18, 102400),
		input(29, 204800),
	];

	c.bench_function_over_inputs("root_new", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone();
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();


			reference_trie::calc_root::<Layout, _, _, _>(inputc);
		}),
		data,
	);
}

fn fuzz_to_data(input: Vec<u8>) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut result = Vec::new();
	// enc = (minkeylen, maxkeylen (min max up to 32), datas)
	// fix data len 2 bytes
	let minkeylen = 1;
	let maxkeylen = 32;
	let mut ix = 0;
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
			input[ix..ix + 2].to_vec()
		} else { break };
		ix += 2;
		result.push((key, val));
	}
	result
}

fn fuzz_to_data2(input: Vec<u8>, vl: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut result = Vec::new();
	let mut ix = 0;
	loop {
		let keylen = 32;
		let key = if input.len() > ix + keylen {
			input[ix..ix+keylen].to_vec()
		} else { break };
		ix += keylen;
		let val = vec![input[ix];vl];
		result.push((key, val));
	}
	result
}


fn data_sorted_unique(input: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut m = std::collections::BTreeMap::new();
	for (k, v) in input.into_iter() {
		let _	= m.insert(k, v); // latest value for uniqueness
	}
	m.into_iter().collect()
}

fn input(seed: u64, len: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
	use rand::SeedableRng;
	use rand::RngCore;
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	let mut data = vec![0u8; len];
	rng.fill_bytes(&mut data[..]);
	let data = data_sorted_unique(fuzz_to_data(data));
	data
}

fn input2(seed: u64, len: usize, value_length: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
	use rand::SeedableRng;
	use rand::RngCore;
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	let mut data = vec![0u8; len];
	rng.fill_bytes(&mut data[..]);
	let data = data_sorted_unique(fuzz_to_data2(data, value_length));
	data
}

fn input_unsorted(seed: u64, len: usize, value_length: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
	use rand::SeedableRng;
	use rand::RngCore;
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	let mut data = vec![0u8; len];
	rng.fill_bytes(&mut data[..]);
	fuzz_to_data2(data, value_length)
}

fn trie_mut_root_a(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input_unsorted(29, 204800 / 2, 512 * 2),
	];

	c.bench_function_over_inputs("trie_mut_root_a", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data_sorted_unique(data.clone());
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v|(&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();


			reference_trie::calc_root::<Layout, _, _, _>(inputc);
		}),
		data);
}

fn trie_mut_root_b(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input_unsorted(29, 204800, 32),
	];

	c.bench_function_over_inputs("trie_mut_root_b", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data_sorted_unique(data.clone());
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();

			reference_trie::calc_root::<Layout, _, _, _>(inputc);
		}),
		data);
}

fn trie_mut_ref_root_a(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input_unsorted(29, 204800 / 2, 512 * 2),
	];

	c.bench_function_over_inputs("trie_mut_ref_root_a", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone(); // no need to sort for trie_root, see implementation

			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();

			reference_trie::reference_trie_root_iter_build::<Layout, _, _, _>(inputc);
		}),
		data);
}

fn trie_mut_ref_root_b(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		//input_unsorted(29, 204800, 512),
		input_unsorted(29, 204800, 32),
	];

	c.bench_function_over_inputs("trie_mut_ref_root_b", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone(); // no need to sort for trie_root, see implementation
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();

			reference_trie::reference_trie_root_iter_build::<Layout, _, _, _>(inputc);
		}),
		data);
}



fn trie_mut_a(c: &mut Criterion) {
	use trie_db::TrieMut;
	use memory_db::HashKey;
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input_unsorted(29, 204800 / 2, 512 * 2),
	];

	c.bench_function_over_inputs("trie_mut_a", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone();

			let mut root = Default::default();
			let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
			let mut trie = trie_db::TrieDBMut::<Layout>::new(&mut mdb, &mut root);
			for (key, value) in datac {
				trie.insert(&key, &value)
					.expect("changes trie: insertion to trie is not allowed to fail within runtime");
			}

		}),
		data);
}

fn trie_mut_b(c: &mut Criterion) {
	use trie_db::TrieMut;
	use memory_db::HashKey;
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		//input_unsorted(29, 204800, 512),
		input_unsorted(29, 204800, 32),
	];

	c.bench_function_over_inputs("trie_mut_b", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data.clone();

			let mut root = Default::default();
			let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
			let mut trie = trie_db::TrieDBMut::<Layout>::new(&mut mdb, &mut root);
			for (key, value) in datac {
				trie.insert(&key, &value)
					.expect("changes trie: insertion to trie is not allowed to fail within runtime");
			}

		}),
		data);
}

fn trie_mut_build_a(c: &mut Criterion) {
	use memory_db::HashKey;
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		input_unsorted(29, 204800 / 2, 512 * 2),
	];

	c.bench_function_over_inputs("trie_mut_build_a", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data_sorted_unique(data.clone());
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();

			let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
			reference_trie::calc_root_build::<Layout, _, _, _, _>(inputc, &mut mdb);
		}),
		data);
}

fn trie_mut_build_b(c: &mut Criterion) {
	use memory_db::HashKey;
	let data : Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		//input_unsorted(29, 204800, 512),
		input_unsorted(29, 204800, 32),
	];

	c.bench_function_over_inputs("trie_mut_build_b", |b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>|
		b.iter(|| {
			let datac:Vec<(Vec<u8>, Vec<u8>)> = data_sorted_unique(data.clone());
			// this is in `reference_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v| (&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();

			let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
			reference_trie::calc_root_build::<Layout, _, _, _, _>(inputc, &mut mdb);
		}),
		data);
}

fn trie_iteration(c: &mut Criterion) {
	use memory_db::HashKey;

	let input = input2(29, 204800, 32);

	let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
	let root = reference_trie::calc_root_build::<Layout, _, _, _, _>(input, &mut mdb);

	c.bench_function("trie_iteration", move |b: &mut Bencher|
		b.iter(|| {
			let trie = trie_db::TrieDB::<Layout>::new(&mdb, &root).unwrap();
			let mut iter = trie_db::TrieDBNodeIterator::new(&trie).unwrap();
			assert!(iter.all(|result| result.is_ok()));
		})
	);
}

fn trie_proof_verification(c: &mut Criterion) {
	use memory_db::HashKey;
	use trie_db::Trie;

	let mut data = input_unsorted(29, 204800, 32);
	let mut keys = data[(data.len() / 3)..]
		.iter()
		.map(|(key, _)| key.clone())
		.collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
	let root = reference_trie::calc_root_build::<Layout, _, _, _, _>(data, &mut mdb);

	let trie = trie_db::TrieDB::<Layout>::new(&mdb, &root).unwrap();
	let proof = generate_proof(&trie, keys.iter()).unwrap();
	let items = keys.into_iter()
		.map(|key| {
			let value = trie.get(&key).unwrap();
			(key, value)
		})
		.collect::<Vec<_>>();

	c.bench_function("trie_proof_verification", move |b: &mut Bencher|
		b.iter(|| {
			verify_proof::<Layout, _, _, _>(
				&root,
				&proof,
				items.iter()
			).unwrap();
		})
	);
}

// bench build triedbmut as in proof size main from reference trie
// parameters are hadcoded.
fn proof_build_dataset<L: TrieLayout>(c: &mut Criterion, trie_size: u32, size_value: usize) {
	use memory_db::PrefixedKey;
	use trie_db::TrieMut;

	let mut seed = Default::default();
	let x = StandardMap {
		alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
		min_key: size_value,
		journal_key: 0,
		value_mode: ValueMode::Index,
		count: trie_size,
	}.make_with(&mut seed);
	let mut memdb = memory_db::MemoryDB::<<L as TrieLayout>::Hash, PrefixedKey<_>, Vec<u8>>::default();
	let mut root = Default::default();

	c.bench_function("proof_build_dataset", move |b: &mut Bencher|
		b.iter(|| {
			let mut t = trie_db::TrieDBMut::<L>::new(&mut memdb, &mut root);
			for i in 0..x.len() {
				let key: &[u8]= &x[i].0;
				let val: &[u8] = &x[i].1;
				t.insert(key, val).unwrap();
			}
			t.commit();
		})
	);
}

fn proof_build_dataset_standard(c: &mut Criterion) {
	let trie_size = 1000;
	let values_size = 32;
	proof_build_dataset::<reference_trie::NoExtensionLayout>(c, trie_size, values_size)
}

fn proof_build_dataset_hybrid(c: &mut Criterion) {
	let trie_size = 1000;
	let values_size = 32;
	proof_build_dataset::<reference_trie::NoExtensionLayoutHybrid>(c, trie_size, values_size)
}

fn proof_build_compacting<L: TrieLayout>(c: &mut Criterion, trie_size: u32, size_value: usize, number_key: usize) {
	use memory_db::{PrefixedKey, HashKey};
	use trie_db::TrieMut;

	let mut seed = Default::default();
	let x = StandardMap {
		alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
		min_key: size_value,
		journal_key: 0,
		value_mode: ValueMode::Index,
		count: trie_size,
	}.make_with(&mut seed);
	let mut memdb = memory_db::MemoryDB::<<L as TrieLayout>::Hash, PrefixedKey<_>, Vec<u8>>::default();
	let mut root = Default::default();
	{
		let mut t = trie_db::TrieDBMut::<L>::new(&mut memdb, &mut root);
		for i in 0..x.len() {
			let key: &[u8]= &x[i].0;
			let val: &[u8] = &x[i].1;
			t.insert(key, val).unwrap();
		}
		t.commit();
	}

	use trie_db::{Trie, TrieDB};
	use hash_db::{EMPTY_PREFIX, HashDB};

	let keys = &x[..number_key];
	let trie = <TrieDB<L>>::new(&memdb, &root).unwrap();
	let mut recorder = trie_db::Recorder::new();
	for (key, _) in keys {
		let _ = trie.get_with(key.as_slice(), &mut recorder).unwrap();
	}

	let mut partial_db = <memory_db::MemoryDB<L::Hash, HashKey<_>, _>>::default();
	for record in recorder.drain() {
		partial_db.emplace(record.hash, EMPTY_PREFIX, record.data);
	}
	let partial_trie = <TrieDB<L>>::new(&partial_db, &trie.root()).unwrap();

	c.bench_function("proof_build_compacting", move |b: &mut Bencher|
		b.iter(|| {
			trie_db::encode_compact::<L>(&partial_trie).unwrap()
		})
	);
}

fn proof_build_compacting_standard(c: &mut Criterion) {
	let trie_size = 1000;
	let proof_keys = 10;
	let values_size = 32;
	proof_build_compacting::<reference_trie::NoExtensionLayout>(c, trie_size, values_size, proof_keys)
}

fn proof_build_compacting_hybrid(c: &mut Criterion) {
	let trie_size = 1000;
	let proof_keys = 10;
	let values_size = 32;
	proof_build_compacting::<reference_trie::NoExtensionLayoutHybrid>(c, trie_size, values_size, proof_keys)
}

fn proof_build_change<L: TrieLayout>(c: &mut Criterion, trie_size: u32, size_value: usize, number_key: usize) {
	use memory_db::PrefixedKey;
	use trie_db::TrieMut;

	let mut seed = Default::default();
	let x = StandardMap {
		alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
		min_key: size_value,
		journal_key: 0,
		value_mode: ValueMode::Index,
		count: trie_size,
	}.make_with(&mut seed);
	let mut memdb = memory_db::MemoryDB::<<L as TrieLayout>::Hash, PrefixedKey<_>, Vec<u8>>::default();
	let mut root = Default::default();
	{
		let mut t = trie_db::TrieDBMut::<L>::new(&mut memdb, &mut root);
		for i in 0..x.len() {
			let key: &[u8]= &x[i].0;
			let val: &[u8] = &x[i].1;
			t.insert(key, val).unwrap();
		}
		t.commit();
	}

	let keys = &x[..number_key];
	let value = vec![213u8; size_value];

	c.bench_function("proof_build_change", move |b: &mut Bencher|
		b.iter(|| {
			let mut memdb = memdb.clone();
			let mut root = root.clone();
			let mut t = trie_db::TrieDBMut::<L>::from_existing(&mut memdb, &mut root).unwrap();
			for i in 0..keys.len() {
				let key: &[u8]= &keys[i].0;
				let val: &[u8] = &value[..];
				t.insert(key, val).unwrap();
			}
			t.commit();
		})
	);
}

fn proof_build_change_standard(c: &mut Criterion) {
	let trie_size = 1000;
	let change_keys = 10;
	let values_size = 32;
	proof_build_change::<reference_trie::NoExtensionLayout>(c, trie_size, values_size, change_keys)
}

fn proof_build_change_hybrid(c: &mut Criterion) {
	let trie_size = 1000;
	let change_keys = 10;
	let values_size = 32;
	proof_build_change::<reference_trie::NoExtensionLayoutHybrid>(c, trie_size, values_size, change_keys)
}

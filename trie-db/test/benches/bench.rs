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

use criterion::{black_box, criterion_group, criterion_main, Bencher, Criterion};

use reference_trie::ExtensionLayout as Layout;
use trie_db::{
	proof::{generate_proof, verify_proof},
	NibbleSlice, Trie,
};
use trie_standardmap::{Alphabet, StandardMap, ValueMode};

criterion_group!(
	benches,
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
		let mixed: Vec<_> = keys
			.iter()
			.zip(values.iter().rev())
			.map(|pair| (NibbleSlice::new(pair.0), NibbleSlice::new(pair.1)))
			.collect();

		b.iter(&mut || {
			for (left, right) in mixed.iter() {
				let _ = black_box(left.common_prefix(&right));
			}
		})
	});
}

fn root_a_big_v(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input2(29, 204800 / 2, 512 * 2)];

	c.bench_function_over_inputs(
		"root_a_big_v",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone();
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::calc_root::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn root_b_big_v(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input2(29, 204800, 512)];

	c.bench_function_over_inputs(
		"root_b_big_v",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone();
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::calc_root::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn root_a_small_v(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input2(29, 204800, 32)];

	c.bench_function_over_inputs(
		"root_a_small_v",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone();
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::calc_root::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn root_b_small_v(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input2(29, 204800 / 2, 32 * 2)];

	c.bench_function_over_inputs(
		"root_b_small_v",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone();
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::calc_root::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn root_old(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> =
		vec![input(1, 5120), input(41, 10240), input(18, 102400), input(29, 204800)];

	c.bench_function_over_inputs(
		"root_old",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone();
				let inputc = datac.iter().map(|v| (&v.0, &v.1));

				reference_trie::reference_trie_root::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn root_new(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> =
		vec![input(1, 5120), input(41, 10240), input(18, 102400), input(29, 204800)];

	c.bench_function_over_inputs(
		"root_new",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone();
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::calc_root::<Layout, _, _, _>(inputc);
			})
		},
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
		} else {
			break
		};
		let key = if input.len() > ix + keylen { input[ix..ix + keylen].to_vec() } else { break };
		ix += keylen;
		let val = if input.len() > ix + 2 { input[ix..ix + 2].to_vec() } else { break };
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
		let key = if input.len() > ix + keylen { input[ix..ix + keylen].to_vec() } else { break };
		ix += keylen;
		let val = vec![input[ix]; vl];
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

fn input(seed: u64, len: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
	use rand::{RngCore, SeedableRng};
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	let mut data = vec![0u8; len];
	rng.fill_bytes(&mut data[..]);
	let data = data_sorted_unique(fuzz_to_data(data));
	data
}

fn input2(seed: u64, len: usize, value_length: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
	use rand::{RngCore, SeedableRng};
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	let mut data = vec![0u8; len];
	rng.fill_bytes(&mut data[..]);
	let data = data_sorted_unique(fuzz_to_data2(data, value_length));
	data
}

fn input_unsorted(seed: u64, len: usize, value_length: usize) -> Vec<(Vec<u8>, Vec<u8>)> {
	use rand::{RngCore, SeedableRng};
	let mut rng = rand::rngs::SmallRng::seed_from_u64(seed);
	let mut data = vec![0u8; len];
	rng.fill_bytes(&mut data[..]);
	fuzz_to_data2(data, value_length)
}

fn trie_mut_root_a(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input_unsorted(29, 204800 / 2, 512 * 2)];

	c.bench_function_over_inputs(
		"trie_mut_root_a",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data_sorted_unique(data.clone());
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::calc_root::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn trie_mut_root_b(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input_unsorted(29, 204800, 32)];

	c.bench_function_over_inputs(
		"trie_mut_root_b",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data_sorted_unique(data.clone());
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::calc_root::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn trie_mut_ref_root_a(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input_unsorted(29, 204800 / 2, 512 * 2)];

	c.bench_function_over_inputs(
		"trie_mut_ref_root_a",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone(); // no need to sort for trie_root, see implementation

				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::reference_trie_root_iter_build::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn trie_mut_ref_root_b(c: &mut Criterion) {
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		//input_unsorted(29, 204800, 512),
		input_unsorted(29, 204800, 32),
	];

	c.bench_function_over_inputs(
		"trie_mut_ref_root_b",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone(); // no need to sort for trie_root, see implementation
												   // this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				reference_trie::reference_trie_root_iter_build::<Layout, _, _, _>(inputc);
			})
		},
		data,
	);
}

fn trie_mut_a(c: &mut Criterion) {
	use memory_db::HashKey;
	use trie_db::TrieMut;
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input_unsorted(29, 204800 / 2, 512 * 2)];

	c.bench_function_over_inputs(
		"trie_mut_a",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone();

				let mut root = Default::default();
				let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
				let mut trie =
					trie_db::TrieDBMutBuilder::<Layout>::new(&mut mdb, &mut root).build();
				for (key, value) in datac {
					trie.insert(&key, &value).expect(
						"changes trie: insertion to trie is not allowed to fail within runtime",
					);
				}
			})
		},
		data,
	);
}

fn trie_mut_b(c: &mut Criterion) {
	use memory_db::HashKey;
	use trie_db::TrieMut;
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		//input_unsorted(29, 204800, 512),
		input_unsorted(29, 204800, 32),
	];

	c.bench_function_over_inputs(
		"trie_mut_b",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data.clone();

				let mut root = Default::default();
				let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
				let mut trie =
					trie_db::TrieDBMutBuilder::<Layout>::new(&mut mdb, &mut root).build();
				for (key, value) in datac {
					trie.insert(&key, &value).expect(
						"changes trie: insertion to trie is not allowed to fail within runtime",
					);
				}
			})
		},
		data,
	);
}

fn trie_mut_build_a(c: &mut Criterion) {
	use memory_db::HashKey;
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![input_unsorted(29, 204800 / 2, 512 * 2)];

	c.bench_function_over_inputs(
		"trie_mut_build_a",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data_sorted_unique(data.clone());
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
				reference_trie::calc_root_build::<Layout, _, _, _, _>(inputc, &mut mdb);
			})
		},
		data,
	);
}

fn trie_mut_build_b(c: &mut Criterion) {
	use memory_db::HashKey;
	let data: Vec<Vec<(Vec<u8>, Vec<u8>)>> = vec![
		//input_unsorted(29, 204800, 512),
		input_unsorted(29, 204800, 32),
	];

	c.bench_function_over_inputs(
		"trie_mut_build_b",
		|b: &mut Bencher, data: &Vec<(Vec<u8>, Vec<u8>)>| {
			b.iter(|| {
				let datac: Vec<(Vec<u8>, Vec<u8>)> = data_sorted_unique(data.clone());
				// this is in `reference_trie_root` added here to make things comparable
				let inputc = datac
					.iter()
					.map(|v| (&v.0, &v.1))
					.collect::<std::collections::BTreeMap<_, _>>();

				let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
				reference_trie::calc_root_build::<Layout, _, _, _, _>(inputc, &mut mdb);
			})
		},
		data,
	);
}

fn trie_iteration(c: &mut Criterion) {
	use memory_db::HashKey;

	let input = input2(29, 204800, 32);

	let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
	let root = reference_trie::calc_root_build::<Layout, _, _, _, _>(input, &mut mdb);

	c.bench_function("trie_iteration", move |b: &mut Bencher| {
		b.iter(|| {
			let trie = trie_db::TrieDBBuilder::<Layout>::new(&mdb, &root).build();
			let mut iter = trie_db::TrieDBNodeIterator::new(&trie).unwrap();
			assert!(iter.all(|result| result.is_ok()));
		})
	});
}

fn trie_proof_verification(c: &mut Criterion) {
	use memory_db::HashKey;

	let mut data = input_unsorted(29, 204800, 32);
	let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	let mut mdb = memory_db::MemoryDB::<_, HashKey<_>, _>::default();
	let root = reference_trie::calc_root_build::<Layout, _, _, _, _>(data, &mut mdb);

	let proof = generate_proof::<_, Layout, _, _>(&mdb, &root, keys.iter()).unwrap();
	let trie = trie_db::TrieDBBuilder::<Layout>::new(&mdb, &root).build();
	let items = keys
		.into_iter()
		.map(|key| {
			let value = trie.get(&key).unwrap();
			(key, value)
		})
		.collect::<Vec<_>>();

	c.bench_function("trie_proof_verification", move |b: &mut Bencher| {
		b.iter(|| {
			verify_proof::<Layout, _, _, _>(&root, &proof, items.iter()).unwrap();
		})
	});
}

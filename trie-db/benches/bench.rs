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

#[macro_use]
extern crate criterion;
use criterion::{Criterion, black_box, Bencher};
criterion_group!(benches,
	nibble_common_prefix,
	root_old,
	root_new,
);
criterion_main!(benches);

extern crate trie_standardmap;
extern crate trie_db;
use std::io::Read;
use trie_standardmap::{Alphabet, StandardMap, ValueMode};
use trie_db::NibbleSlice;

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

		b.iter(&mut ||{
			for (left, right) in mixed.iter() {
				let _ = black_box(left.common_prefix(&right));
			}
		})
	});
}

fn root_old(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>,Vec<u8>)>> = vec![
		input("./testset0"), // 286 vals
		input("./testset1"), // 571 vals
		input("./testset2"), // 5649 vals
		input("./testset3"), // 11376 vals
	];

	c.bench_function_over_inputs("root_old",|b: &mut Bencher, data: &Vec<(Vec<u8>,Vec<u8>)>|
		b.iter(||{
			let datac:Vec<(Vec<u8>,Vec<u8>)> = data.clone();
			let inputc = datac
				.iter()
				.map(|v|(&v.0, &v.1));

			reference_trie::ref_trie_root(inputc);
		})
	,data);
}


fn root_new(c: &mut Criterion) {
	let data : Vec<Vec<(Vec<u8>,Vec<u8>)>> = vec![
		input("./testset0"),
		input("./testset1"),
		input("./testset2"),
		input("./testset3"),
	];

	c.bench_function_over_inputs("root_new",|b: &mut Bencher, data: &Vec<(Vec<u8>,Vec<u8>)>|
		b.iter(||{
			let datac:Vec<(Vec<u8>,Vec<u8>)> = data.clone();
			// this is in `ref_trie_root` added here to make things comparable
			let inputc = datac
				.iter()
				.map(|v|(&v.0, &v.1))
				.collect::<std::collections::BTreeMap<_, _>>();


			reference_trie::calc_root(inputc);
		})
	,data);
}

fn fuzz_to_data(fp: &std::path::Path) -> Vec<(Vec<u8>,Vec<u8>)> {
	let mut file = std::fs::File::open(fp).unwrap();
	let mut input = Vec::new();
	file.read_to_end(&mut input).unwrap();
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
				input[ix..ix + 2].to_vec()
			} else { break };
			ix += 2;
			result.push((key,val));
		}
		result
}

fn data_sorted_unique(input: Vec<(Vec<u8>,Vec<u8>)>) -> Vec<(Vec<u8>,Vec<u8>)> {
	let mut m = std::collections::BTreeMap::new();
	for (k,v) in input.into_iter() {
		let _	= m.insert(k,v); // latest value for uniqueness
	}
	m.into_iter().collect()
}

fn input(file: &str) -> Vec<(Vec<u8>,Vec<u8>)> {
	let pb = std::path::PathBuf::from(file);
	let data = data_sorted_unique(fuzz_to_data(&pb));
	data
}

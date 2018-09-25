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
use criterion::{Criterion, black_box};
criterion_group!(benches, nibble_common_prefix);
criterion_main!(benches);

extern crate trie_standardmap;
extern crate trie_db;

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
	let (keys, values): (Vec<_>, Vec<_>) = st.make().iter().cloned().unzip();
	let mixed: Vec<_> = keys.iter().zip(values.iter().rev()).map(|pair| {
		(NibbleSlice::new(pair.0), NibbleSlice::new(pair.1))
	}).collect();
	b.bench_function("nibble_common_prefix", |b| b.iter(&mut ||{
		for (left, right) in mixed.iter() {
			let _ = black_box(left.common_prefix(&right));
		}
	}));
}

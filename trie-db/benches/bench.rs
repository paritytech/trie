// Copyright 2015-2018 Parity Technologies (UK) Ltd.
// This file is part of Parity.

// Parity is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Parity is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Parity.  If not, see <http://www.gnu.org/licenses/>.

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

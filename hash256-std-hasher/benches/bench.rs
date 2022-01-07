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
use criterion::{black_box, Criterion};
criterion_group!(benches, write_hash256_std_hasher, write_default_hasher);
criterion_main!(benches);

extern crate hash256_std_hasher;

use hash256_std_hasher::Hash256StdHasher;
use std::{collections::hash_map::DefaultHasher, hash::Hasher};

fn write_hash256_std_hasher(b: &mut Criterion) {
	b.bench_function("write_hash256_std_hasher", |b| {
		b.iter(|| {
			let n: u8 = black_box(100);
			(0..n).fold(Hash256StdHasher::default(), |mut old, new| {
				let bb = black_box([new; 32]);
				old.write(&bb as &[u8]);
				old
			});
		})
	});
}

fn write_default_hasher(b: &mut Criterion) {
	b.bench_function("write_default_hasher", |b| {
		b.iter(|| {
			let n: u8 = black_box(100);
			(0..n).fold(DefaultHasher::default(), |mut old, new| {
				let bb = black_box([new; 32]);
				old.write(&bb as &[u8]);
				old
			});
		})
	});
}

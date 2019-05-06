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
use criterion::Criterion;
criterion_group!(benches, benchmark);
criterion_main!(benches);

extern crate keccak_hasher;
extern crate reference_trie;
extern crate trie_bench;

fn benchmark(c: &mut Criterion) {
	trie_bench::standard_benchmark::<
		reference_trie::LayoutOri,
		reference_trie::ReferenceTrieStream,
	>(c, "ref");
}

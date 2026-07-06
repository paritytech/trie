// Copyright 2026 Parity Technologies
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

//! Deterministic smoke runs of the fuzz harnesses, so their assertions are exercised in CI
//! without a libFuzzer setup.

use reference_trie::HashedValueNoExtThreshold;
use trie_db_fuzz::{fuzz_that_trie_codec_proofs, fuzz_that_trie_codec_proofs_with_shared_values};

fn xorshift(state: &mut u64) -> u64 {
	*state ^= *state << 13;
	*state ^= *state >> 7;
	*state ^= *state << 17;
	*state
}

#[test]
fn trie_codec_proof_dedup_smoke() {
	let mut state = 0x0123_4567_89ab_cdefu64;
	for len in (0..2048usize).step_by(37) {
		let input: Vec<u8> = (0..len).map(|_| xorshift(&mut state) as u8).collect();
		// A layout storing every non-empty value as a separate, hash-addressed value node, so
		// that compact-proof value detachment and deduplication are exercised.
		fuzz_that_trie_codec_proofs::<HashedValueNoExtThreshold<1>>(&input);
		fuzz_that_trie_codec_proofs_with_shared_values::<HashedValueNoExtThreshold<1>>(&input);
	}
}

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

use arbitrary::{Arbitrary, Unstructured};
use reference_trie::HashedValueNoExtThreshold;
use trie_db_fuzz::{
	fuzz_dedup_scenario, fuzz_that_trie_codec_proofs,
	fuzz_that_trie_codec_proofs_with_shared_subtrees,
	fuzz_that_trie_codec_proofs_with_shared_values, DedupScenario,
};

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
		// Hashed-value layout, so value detachment and deduplication are exercised.
		fuzz_that_trie_codec_proofs::<HashedValueNoExtThreshold<1>>(&input);
		fuzz_that_trie_codec_proofs_with_shared_values::<HashedValueNoExtThreshold<1>>(&input);
		fuzz_that_trie_codec_proofs_with_shared_subtrees::<HashedValueNoExtThreshold<1>>(&input);
	}
}

#[test]
fn trie_codec_proof_dedup_guided_smoke() {
	let mut state = 0xdead_beef_cafe_f00du64;
	for len in (0..4096usize).step_by(29) {
		let input: Vec<u8> = (0..len).map(|_| xorshift(&mut state) as u8).collect();
		// Structure-aware scenario built the same way libFuzzer builds it, via `arbitrary`.
		let mut unstructured = Unstructured::new(&input);
		if let Ok(scenario) = DedupScenario::arbitrary(&mut unstructured) {
			fuzz_dedup_scenario::<HashedValueNoExtThreshold<1>>(scenario);
		}
	}
}

/// Fuzzer-found inputs, replayed byte-for-byte the way libFuzzer feeds them.
#[test]
fn fuzzer_found_scenarios() {
	const INPUTS: &[&str] = &[
		// crash-bf782723…: shared subtrees deduplicated across threaded encodings; historically
		// pinned the reference-count semantics of the (since removed) re-inserting decoder, kept
		// as a regression scenario for the node-set invariant of `fuzz_dedup_scenario`.
		"3fff413f20b5b5b5b54185018601ff00858b01028681ff96fffffffaffff41fa96ffffa1a1ff96ffffe2ffb1b524fafafbfa962c01",
		// crash-ef90b66d…: proofs covering a shared subtree to different depths; dropped a node
		// when the harness encoded from per-trie recorded sets instead of their union (the
		// fixed-backing-set precondition of `encode_compact_skip_duplicates`).
		"c901cd01002b2b0b0100000081402b2b2b2b0b0011ab3105d2ffffff01b000d2f90660cf2b",
	];
	for input in INPUTS {
		let bytes = array_bytes::hex2bytes(*input).unwrap();
		let scenario = DedupScenario::arbitrary_take_rest(Unstructured::new(&bytes)).unwrap();
		fuzz_dedup_scenario::<HashedValueNoExtThreshold<1>>(scenario);
	}
}

/// Violating the precondition of `encode_compact_skip_duplicates` — threading `seen_hashes`
/// across encodings from per-proof recorded sets whose coverage of a shared node diverges —
/// silently drops nodes. This pins the failure mode; if the encoder is ever hardened against
/// it, update this test (and the harness doc) accordingly.
#[test]
fn divergent_coverage_drops_nodes() {
	use hash_db::{HashDB, EMPTY_PREFIX};
	use memory_db::{HashKey, MemoryDB};
	use trie_db::{
		decode_compact_from_iter, encode_compact_skip_duplicates, DBValue, Recorder, SeenHashes,
		Trie, TrieDBBuilder, TrieDBMutBuilder, TrieError, TrieLayout, TrieMut,
	};
	type L = HashedValueNoExtThreshold<1>;
	type H = <L as TrieLayout>::Hash;

	let entries: Vec<(Vec<u8>, Vec<u8>)> = vec![
		(vec![0x11, 0x00], vec![0]),
		(vec![0x11, 0x11], vec![1; 32]),
		(vec![0x22, 0x22], vec![0]),
	];
	let mut db = MemoryDB::<H, HashKey<H>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut trie = TrieDBMutBuilder::<L>::new(&mut db, &mut root).build();
		for (key, value) in &entries {
			trie.insert(key, value).unwrap();
		}
	}

	// Two proofs of the same trie, each recorded independently, so the branch above the two
	// 0x11… leaves is a boundary node of proof 0 and covered deeper by proof 1.
	let mut seen = SeenHashes::default();
	let mut reconstructed = MemoryDB::<H, HashKey<H>, DBValue>::default();
	let queried: [&[u8]; 2] = [&[0x11, 0x00], &[0x11, 0x11]];
	for (proof, key) in queried.iter().enumerate() {
		let mut recorder = Recorder::<L>::new();
		{
			let trie = TrieDBBuilder::<L>::new(&db, &root).with_recorder(&mut recorder).build();
			trie.get(key).unwrap().unwrap();
		}
		let mut partial = MemoryDB::<H, HashKey<H>, DBValue>::default();
		for record in recorder.drain() {
			partial.emplace(record.hash, EMPTY_PREFIX, record.data);
		}
		let encoded = {
			let trie = TrieDBBuilder::<L>::new(&partial, &root).build();
			encode_compact_skip_duplicates::<L>(&trie, &mut seen).unwrap()
		};
		decode_compact_from_iter::<L, _, _>(&mut reconstructed, encoded.iter().map(Vec::as_slice))
			.unwrap();

		let trie = TrieDBBuilder::<L>::new(&reconstructed, &root).build();
		let result = trie.get(key);
		if proof == 0 {
			assert!(result.unwrap().is_some(), "proof 0 must be readable");
		} else {
			// Proof 1's encoding skipped the seen boundary branch, dropping the leaf that only
			// proof 1 covers — the node exists in no encoding at all.
			assert!(
				matches!(*result.unwrap_err(), TrieError::IncompleteDatabase(_)),
				"expected the documented node drop under divergent coverage"
			);
		}
	}
}

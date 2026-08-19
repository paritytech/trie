#![no_main]

use libfuzzer_sys::fuzz_target;
use trie_db_fuzz::{fuzz_dedup_scenario, DedupScenario};

// Structure-aware, differential harness for deduplicated compact proofs. `DedupScenario` is built
// via `arbitrary`, so libFuzzer mutates the trie/value structure directly instead of a raw byte
// stream fed through `fuzz_to_data`.
fuzz_target!(|scenario: DedupScenario| {
	// Hashed-value layout: values are detachable value nodes, so value- and subtree-level
	// deduplication are both exercised.
	fuzz_dedup_scenario::<reference_trie::HashedValueNoExtThreshold<1>>(scenario);
});

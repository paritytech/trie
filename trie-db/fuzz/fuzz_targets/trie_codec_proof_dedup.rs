#![no_main]

use libfuzzer_sys::fuzz_target;
use trie_db_fuzz::{fuzz_that_trie_codec_proofs, fuzz_that_trie_codec_proofs_with_shared_values};

fuzz_target!(|data: &[u8]| {
	// A layout storing every non-empty value as a separate, hash-addressed value node, so that
	// compact-proof value detachment and deduplication are exercised.
	fuzz_that_trie_codec_proofs::<reference_trie::HashedValueNoExtThreshold<1>>(data);
	fuzz_that_trie_codec_proofs_with_shared_values::<reference_trie::HashedValueNoExtThreshold<1>>(
		data,
	);
});

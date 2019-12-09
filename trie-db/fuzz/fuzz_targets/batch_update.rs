#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
	// fuzzed code goes here
	trie_db_fuzz::fuzz_batch_update(data);
});

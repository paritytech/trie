#![no_main]

use libfuzzer_sys::fuzz_target;
use trie_db_test::fuzz::fuzz_that_compare_implementations;

fuzz_target!(|data: &[u8]| {
	// fuzzed code goes here
	fuzz_that_compare_implementations::<reference_trie::NoExtensionLayout>(data);
});

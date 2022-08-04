#![no_main]

use libfuzzer_sys::fuzz_target;
use trie_db_fuzz::fuzz_that_no_extension_insert;

fuzz_target!(|data: &[u8]| {
	// fuzzed code goes here
	fuzz_that_no_extension_insert::<reference_trie::NoExtensionLayout>(data);
});

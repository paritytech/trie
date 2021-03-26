#![no_main]

use trie_db_fuzz::fuzz_that_no_extension_insert_remove;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
	// fuzzed code goes here
	fuzz_that_no_extension_insert_remove::<reference_trie::NoExtensionLayout>(data);
});

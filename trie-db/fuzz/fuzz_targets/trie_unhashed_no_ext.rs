
#![no_main]

use trie_db_fuzz::fuzz_that_unhashed_no_extension;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
	// fuzzed code goes here
	fuzz_that_unhashed_no_extension(data);
});

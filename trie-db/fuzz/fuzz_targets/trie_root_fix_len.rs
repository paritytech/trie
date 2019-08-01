
#![no_main]

use trie_db_fuzz::fuzz_that_reference_trie_root_fix_length;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
	fuzz_that_reference_trie_root_fix_length(data);
});

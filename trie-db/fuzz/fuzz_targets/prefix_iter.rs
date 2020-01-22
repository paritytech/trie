#![no_main]

use trie_db_fuzz::fuzz_prefix_iter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
	fuzz_prefix_iter(data);
});

#![no_main]

use trie_db_fuzz::fuzz_seek_iter;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
	fuzz_seek_iter(data);
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use trie_db_fuzz::fuzz_seek_iter;

fuzz_target!(|data: &[u8]| {
	fuzz_seek_iter::<reference_trie::NoExtensionLayout>(data);
});

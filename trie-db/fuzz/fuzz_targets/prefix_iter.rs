#![no_main]

use libfuzzer_sys::fuzz_target;
use trie_db_test::fuzz::fuzz_prefix_iter;

fuzz_target!(|data: &[u8]| {
	fuzz_prefix_iter::<reference_trie::NoExtensionLayout>(data);
});

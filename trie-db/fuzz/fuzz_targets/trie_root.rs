
#![no_main]

use trie_db_fuzz::fuzz_that_reference_trie_root;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
	fuzz_that_reference_trie_root::<reference_trie::NoExtensionLayout>(data);
});

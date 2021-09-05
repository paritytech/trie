#![no_main]

use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
	// use next line to favor complex structure and inline data
	trie_db_fuzz::fuzz_batch_update(data, |_v| (), false);
	// use next line to favor db prefix verification
	//trie_db_fuzz::fuzz_batch_update(data, |v| v.extend(&[4u8; 32]), true);
});

#![no_main]

use libfuzzer_sys::fuzz_target;
use trie_db_test::fuzz::{fuzz_prefix_seek_iter, PrefixSeekTestInput};

fuzz_target!(|data: PrefixSeekTestInput| {
	fuzz_prefix_seek_iter::<reference_trie::SubstrateV1<reference_trie::RefHasher>>(data);
});

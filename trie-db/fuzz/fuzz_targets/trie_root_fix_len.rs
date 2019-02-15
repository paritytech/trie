
#![no_main]

use trie_db_fuzz::fuzz_that_ref_trie_root_fix_len;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
  fuzz_that_ref_trie_root_fix_len(data);
});

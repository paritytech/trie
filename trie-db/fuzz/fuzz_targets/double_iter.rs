#![no_main]

use libfuzzer_sys::fuzz_target;
use memory_db::{MemoryDB, PrefixedKey};
use trie_db::{DBValue, TrieLayout};
use trie_db_fuzz::fuzz_double_iter;

type T = reference_trie::NoExtensionLayout;
type DB = MemoryDB<<T as TrieLayout>::Hash, PrefixedKey<<T as TrieLayout>::Hash>, DBValue>;

fuzz_target!(|data: &[u8]| {
	fuzz_double_iter::<T, DB>(data, false);
	fuzz_double_iter::<T, DB>(data, true);
});

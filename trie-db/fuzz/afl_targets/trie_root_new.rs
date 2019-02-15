
// TODO this is currently borked behind linker sanitizer issues (unordered without gold or multiple
// definition with it).

use afl::fuzz;

use trie_db_fuzz::fuzz_that_compare_impl;

fn main() {
	fuzz_target!(|data: &[u8]| {
		// fuzzed code goes here
		fuzz_that_compare_impl(data);
	});
}


use honggfuzz::fuzz;
use trie_db_fuzz::fuzz_that_compare_impl;

fn main() {
  loop {
    fuzz!(|data: &[u8]| {
      // fuzzed code goes here
      fuzz_that_compare_impl(data);
    });
  }
}

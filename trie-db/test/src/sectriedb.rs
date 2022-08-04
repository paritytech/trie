// Copyright 2017, 2020 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

use hash_db::Hasher;
use memory_db::{HashKey, MemoryDB};
use reference_trie::{RefHasher, RefSecTrieDB, RefTrieDBMutBuilder};
use trie_db::{DBValue, Trie, TrieMut};

#[test]
fn trie_to_sectrie() {
	let mut db = MemoryDB::<RefHasher, HashKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutBuilder::new(&mut db, &mut root).build();
		t.insert(&RefHasher::hash(&[0x01u8, 0x23]), &[0x01u8, 0x23]).unwrap();
	}
	let t = RefSecTrieDB::new(&db, &root);
	assert_eq!(t.get(&[0x01u8, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
}

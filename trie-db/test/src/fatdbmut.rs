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

use hash_db::{Hasher, EMPTY_PREFIX};
use memory_db::{HashKey, MemoryDB};
use reference_trie::{RefFatDBMut, RefHasher, RefTrieDB};
use trie_db::{Trie, TrieMut};

#[test]
fn fatdbmut_to_trie() {
	let mut memdb = MemoryDB::<RefHasher, HashKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = RefFatDBMut::new(&mut memdb, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	}
	let t = RefTrieDB::new(&memdb, &root).unwrap();
	assert_eq!(t.get(&RefHasher::hash(&[0x01u8, 0x23])), Ok(Some(vec![0x01u8, 0x23])),);
}

#[test]
fn fatdbmut_insert_remove_key_mapping() {
	let mut memdb = MemoryDB::<RefHasher, HashKey<_>, _>::default();
	let mut root = Default::default();
	let key = [0x01u8, 0x23];
	let val = [0x01u8, 0x24];
	let key_hash = RefHasher::hash(&key);
	let aux_hash = RefHasher::hash(&key_hash);
	let mut t = RefFatDBMut::new(&mut memdb, &mut root);
	t.insert(&key, &val).unwrap();
	assert_eq!(t.get(&key), Ok(Some(val.to_vec())));
	assert_eq!(t.db().get(&aux_hash, EMPTY_PREFIX), Some(key.to_vec()));
	t.remove(&key).unwrap();
	assert_eq!(t.db().get(&aux_hash, EMPTY_PREFIX), None);
}

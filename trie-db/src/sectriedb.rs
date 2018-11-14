// Copyright 2017, 2018 Parity Technologies
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

use hash_db::{HashDBRef, Hasher};
use super::triedb::TrieDB;
use super::{Result, DBValue, Trie, TrieItem, TrieIterator, Query};
use node_codec::NodeCodec;

/// A `Trie` implementation which hashes keys and uses a generic `HashDB` backing database.
///
/// Use it as a `Trie` trait object. You can use `raw()` to get the backing `TrieDB` object.
pub struct SecTrieDB<'db, H, C>
where
	H: Hasher + 'db,
	C: NodeCodec<H>
{
	raw: TrieDB<'db, H, C>
}

impl<'db, H, C> SecTrieDB<'db, H, C>
where
	H: Hasher,
	C: NodeCodec<H>
{
	/// Create a new trie with the backing database `db` and empty `root`
	///
	/// Initialise to the state entailed by the genesis block.
	/// This guarantees the trie is built correctly.
	/// Returns an error if root does not exist.
	pub fn new(db: &'db HashDBRef<H, DBValue>, root: &'db H::Out) -> Result<Self, H::Out, C::Error> {
		Ok(SecTrieDB { raw: TrieDB::new(db, root)? })
	}

	/// Get a reference to the underlying raw `TrieDB` struct.
	pub fn raw(&self) -> &TrieDB<H, C> {
		&self.raw
	}

	/// Get a mutable reference to the underlying raw `TrieDB` struct.
	pub fn raw_mut(&mut self) -> &mut TrieDB<'db, H, C> {
		&mut self.raw
	}
}

impl<'db, H, C> Trie<H, C> for SecTrieDB<'db, H, C>
where
	H: Hasher,
	C: NodeCodec<H>
{
	fn root(&self) -> &H::Out { self.raw.root() }

	fn contains(&self, key: &[u8]) -> Result<bool, H::Out, C::Error> {
		self.raw.contains(H::hash(key).as_ref())
	}

	fn get_with<'a, 'key, Q: Query<H>>(&'a self, key: &'key [u8], query: Q) -> Result<Option<Q::Item>, H::Out, C::Error>
		where 'a: 'key
	{
		self.raw.get_with(H::hash(key).as_ref(), query)
	}

	fn iter<'a>(&'a self) -> Result<Box<TrieIterator<H, C, Item = TrieItem<H::Out, C::Error>> + 'a>, H::Out, C::Error> {
		TrieDB::iter(&self.raw)
	}
}

#[cfg(test)]
mod test {
	use memory_db::MemoryDB;
	use hash_db::Hasher;
	use keccak_hasher::KeccakHasher;
	use reference_trie::{RefTrieDBMut, RefSecTrieDB, Trie, TrieMut};
	use DBValue;

	#[test]
	fn trie_to_sectrie() {
		let mut db = MemoryDB::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut db, &mut root);
			t.insert(&KeccakHasher::hash(&[0x01u8, 0x23]), &[0x01u8, 0x23]).unwrap();
		}
		let t = RefSecTrieDB::new(&db, &root).unwrap();
		assert_eq!(t.get(&[0x01u8, 0x23]).unwrap().unwrap(), DBValue::from_slice(&[0x01u8, 0x23]));
	}
}

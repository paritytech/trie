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

use hash_db::{Hasher};
use crate::node_codec::HashDBComplexDyn as HashDB;
use super::{Result, DBValue, TrieMut, TrieDBMut, TrieLayout, TrieHash, CError};

/// A mutable `Trie` implementation which hashes keys and uses a generic `HashDB` backing database.
///
/// Use it as a `Trie` or `TrieMut` trait object. You can use `raw()` to get the backing `TrieDBMut`
/// object.
pub struct SecTrieDBMut<'db, L>
where
	L: TrieLayout
{
	raw: TrieDBMut<'db, L>
}

impl<'db, L> SecTrieDBMut<'db, L>
where
	L: TrieLayout
{
	/// Create a new trie with the backing database `db` and empty `root`
	/// Initialise to the state entailed by the genesis block.
	/// This guarantees the trie is built correctly.
	pub fn new(db: &'db mut dyn HashDB<L::Hash, DBValue>, root: &'db mut TrieHash<L>) -> Self {
		SecTrieDBMut { raw: TrieDBMut::new(db, root) }
	}

	/// Create a new trie with the backing database `db` and `root`.
	///
	/// Returns an error if root does not exist.
	pub fn from_existing(
		db: &'db mut dyn HashDB<L::Hash, DBValue>,
		root: &'db mut TrieHash<L>,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(SecTrieDBMut { raw: TrieDBMut::from_existing(db, root)? })
	}

	/// Get the backing database.
	pub fn db(&self) -> &dyn HashDB<L::Hash, DBValue> { self.raw.db() }

	/// Get the backing database.
	pub fn db_mut(&mut self) -> &mut dyn HashDB<L::Hash, DBValue> { self.raw.db_mut() }
}

impl<'db, L> TrieMut<L> for SecTrieDBMut<'db, L>
where
	L: TrieLayout,
{
	fn root(&mut self) -> &TrieHash<L> {
		self.raw.root()
	}

	fn is_empty(&self) -> bool {
		self.raw.is_empty()
	}

	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.raw.contains(&L::Hash::hash(key).as_ref())
	}

	fn get<'a, 'key>(&'a self, key: &'key [u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>>
		where 'a: 'key
	{
		self.raw.get(&L::Hash::hash(key).as_ref())
	}

	fn insert(
		&mut self, key: &[u8],
		value: &[u8],
	) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		self.raw.insert(&L::Hash::hash(key).as_ref(), value)
	}

	 fn remove(&mut self, key: &[u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		self.raw.remove(&L::Hash::hash(key).as_ref())
	}
}

#[cfg(test)]
mod test {
	use memory_db::{MemoryDB, HashKey};
	use hash_db::Hasher;
	use keccak_hasher::KeccakHasher;
	use reference_trie::{RefTrieDB, RefSecTrieDBMut, Trie, TrieMut};
	use crate::DBValue;

	#[test]
	fn sectrie_to_trie() {
		let mut memdb = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefSecTrieDBMut::new(&mut memdb, &mut root);
			t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		}
		let t = RefTrieDB::new(&memdb, &root).unwrap();
		assert_eq!(
			t.get(&KeccakHasher::hash(&[0x01u8, 0x23])).unwrap().unwrap(),
			vec![0x01u8, 0x23],
		);
	}
}

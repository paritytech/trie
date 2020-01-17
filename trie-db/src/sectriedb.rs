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
use crate::rstd::boxed::Box;
use super::triedb::TrieDB;
use super::{Result, DBValue, Trie, TrieItem, TrieIterator, Query, TrieLayout, CError, TrieHash};

/// A `Trie` implementation which hashes keys and uses a generic `HashDB` backing database.
///
/// Use it as a `Trie` trait object. You can use `raw()` to get the backing `TrieDB` object.
pub struct SecTrieDB<'db, L>
where
	L: TrieLayout,
{
	raw: TrieDB<'db, L>
}

impl<'db, L> SecTrieDB<'db, L>
where
	L: TrieLayout,
{
	/// Create a new trie with the backing database `db` and empty `root`
	///
	/// Initialise to the state entailed by the genesis block.
	/// This guarantees the trie is built correctly.
	/// Returns an error if root does not exist.
	pub fn new(
		db: &'db dyn HashDBRef<L::Hash, DBValue>,
		root: &'db TrieHash<L>,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(SecTrieDB { raw: TrieDB::new(db, root)? })
	}

	/// Get a reference to the underlying raw `TrieDB` struct.
	pub fn raw(&self) -> &TrieDB<L> {
		&self.raw
	}

	/// Get a mutable reference to the underlying raw `TrieDB` struct.
	pub fn raw_mut(&mut self) -> &mut TrieDB<'db, L> {
		&mut self.raw
	}
}

impl<'db, L> Trie<L> for SecTrieDB<'db, L>
where
	L: TrieLayout,
{
	fn root(&self) -> &TrieHash<L> { self.raw.root() }

	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.raw.contains(L::Hash::hash(key).as_ref())
	}

	fn get_with<'a, 'key, Q: Query<L::Hash>>(
		&'a self,
		key: &'key [u8],
		query: Q,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>>
		where 'a: 'key
	{
		self.raw.get_with(L::Hash::hash(key).as_ref(), query)
	}

	fn iter<'a>(&'a self) -> Result<
		Box<dyn TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>
	> {
		TrieDB::iter(&self.raw)
	}
}

#[cfg(test)]
mod test {
	use memory_db::{MemoryDB, HashKey};
	use hash_db::Hasher;
	use keccak_hasher::KeccakHasher;
	use reference_trie::{RefTrieDBMut, RefSecTrieDB, Trie, TrieMut};
	use crate::DBValue;

	#[test]
	fn trie_to_sectrie() {
		let mut db = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut db, &mut root);
			t.insert(&KeccakHasher::hash(&[0x01u8, 0x23]), &[0x01u8, 0x23]).unwrap();
		}
		let t = RefSecTrieDB::new(&db, &root).unwrap();
		assert_eq!(t.get(&[0x01u8, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
	}
}

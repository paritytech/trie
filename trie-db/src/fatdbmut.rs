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

use hash_db::{HashDB, Hasher, EMPTY_PREFIX};
use super::{Result, DBValue, TrieDBMut, TrieMut, TrieLayout, TrieHash, CError,
	Value};

/// A mutable `Trie` implementation which hashes keys and uses a generic `HashDB` backing database.
/// Additionaly it stores inserted hash-key mappings for later retrieval.
///
/// Use it as a `Trie` or `TrieMut` trait object.
pub struct FatDBMut<'db, L>
where
	L: TrieLayout,
{
	raw: TrieDBMut<'db, L>,
}

impl<'db, L> FatDBMut<'db, L>
where
	L: TrieLayout,
{
	/// Create a new trie with the backing database `db` and empty `root`
	/// Initialise to the state entailed by the genesis block.
	/// This guarantees the trie is built correctly.
	pub fn new(db: &'db mut dyn HashDB<L::Hash, DBValue>, root: &'db mut TrieHash<L>) -> Self {
		FatDBMut { raw: TrieDBMut::new(db, root) }
	}

	/// Create a new trie with the backing database `db` and `root`.
	///
	/// Returns an error if root does not exist.
	pub fn from_existing(
		db: &'db mut dyn HashDB<L::Hash, DBValue>,
		root: &'db mut TrieHash<L>
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(FatDBMut { raw: TrieDBMut::from_existing(db, root)? })
	}

	/// Get the backing database.
	pub fn db(&self) -> &dyn HashDB<L::Hash, DBValue> {
		self.raw.db()
	}

	/// Get the backing database.
	pub fn db_mut(&mut self) -> &mut dyn HashDB<L::Hash, DBValue> {
		self.raw.db_mut()
	}
}

impl<'db, L> TrieMut<L> for FatDBMut<'db, L>
where
	L: TrieLayout,
{
	fn root(&mut self) -> &TrieHash<L> { self.raw.root() }

	fn is_empty(&self) -> bool { self.raw.is_empty() }

	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.raw.contains(L::Hash::hash(key).as_ref())
	}

	fn get<'a, 'key>(&'a self, key: &'key [u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>>
		where 'a: 'key
	{
		self.raw.get(L::Hash::hash(key).as_ref())
	}

	fn insert(
		&mut self,
		key: &[u8],
		value: &[u8],
	) -> Result<Value, TrieHash<L>, CError<L>> {
		let hash = L::Hash::hash(key);
		let out = self.raw.insert(hash.as_ref(), value)?;
		let db = self.raw.db_mut();

		// insert if it doesn't exist.
		if let Value::NoValue = &out {
			let aux_hash = L::Hash::hash(hash.as_ref());
			db.emplace(aux_hash, EMPTY_PREFIX, key.to_vec());
		}
		Ok(out)
	}

	fn remove(&mut self, key: &[u8]) -> Result<Value, TrieHash<L>, CError<L>> {
		let hash = L::Hash::hash(key);
		let out = self.raw.remove(hash.as_ref())?;

		// remove if it already exists.
		match &out {
			Value::NoValue => (),
			_ => {
				let aux_hash = L::Hash::hash(hash.as_ref());
				self.raw.db_mut().remove(&aux_hash, EMPTY_PREFIX);
			},
		}

		Ok(out)
	}
}

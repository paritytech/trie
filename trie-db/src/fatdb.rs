// Copyright 2017, 2021 Parity Technologies
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

use super::{
	CError, DBValue, Query, Result, Trie, TrieDB, TrieDBIterator, TrieDBKeyIterator, TrieHash,
	TrieItem, TrieIterator, TrieKeyItem, TrieLayout,
};
use hash_db::{HashDBRef, Hasher};

use crate::rstd::boxed::Box;

/// A `Trie` implementation which hashes keys and uses a generic `HashDB` backing database.
/// Additionaly it stores inserted hash-key mappings for later retrieval.
///
/// Use it as a `Trie` or `TrieMut` trait object.
pub struct FatDB<'db, L>
where
	L: TrieLayout,
{
	raw: TrieDB<'db, L>,
}

impl<'db, L> FatDB<'db, L>
where
	L: TrieLayout,
{
	/// Create a new trie with the backing database `db` and empty `root`
	/// Initialise to the state entailed by the genesis block.
	/// This guarantees the trie is built correctly.
	pub fn new(
		db: &'db dyn HashDBRef<L::Hash, DBValue>,
		root: &'db TrieHash<L>,
	) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(FatDB { raw: TrieDB::new(db, root)? })
	}

	/// Get the backing database.
	pub fn db(&self) -> &dyn HashDBRef<L::Hash, DBValue> {
		self.raw.db()
	}
}

impl<'db, L> Trie<L> for FatDB<'db, L>
where
	L: TrieLayout,
{
	fn root(&self) -> &TrieHash<L> {
		self.raw.root()
	}

	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.raw.contains(L::Hash::hash(key).as_ref())
	}

	fn get_with<'a, 'key, Q: Query<L::Hash>>(
		&'a self,
		key: &'key [u8],
		query: Q,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>>
	where
		'a: 'key,
	{
		self.raw.get_with(L::Hash::hash(key).as_ref(), query)
	}

	fn iter<'a>(
		&'a self,
	) -> Result<
		Box<dyn TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		FatDBIterator::<L>::new(&self.raw).map(|iter| Box::new(iter) as Box<_>)
	}

	fn key_iter<'a>(
		&'a self,
	) -> Result<
		Box<dyn TrieIterator<L, Item = TrieKeyItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		FatDBKeyIterator::<L>::new(&self.raw).map(|iter| Box::new(iter) as Box<_>)
	}
}

/// Iterator over inserted pairs of key values.
pub struct FatDBIterator<'db, L>
where
	L: TrieLayout,
{
	trie_iterator: TrieDBIterator<'db, L>,
	trie: &'db TrieDB<'db, L>,
}

impl<'db, L> FatDBIterator<'db, L>
where
	L: TrieLayout,
{
	/// Creates new iterator.
	pub fn new(trie: &'db TrieDB<L>) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(FatDBIterator { trie_iterator: TrieDBIterator::new(trie)?, trie })
	}
}

impl<'db, L> TrieIterator<L> for FatDBIterator<'db, L>
where
	L: TrieLayout,
{
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		let hashed_key = L::Hash::hash(key);
		self.trie_iterator.seek(hashed_key.as_ref())
	}
}

impl<'db, L> Iterator for FatDBIterator<'db, L>
where
	L: TrieLayout,
{
	type Item = TrieItem<'db, TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.trie_iterator.next().map(|res| {
			res.map(|(hash, value)| {
				let aux_hash = L::Hash::hash(&hash);
				(
					self.trie.db().get(&aux_hash, Default::default()).expect("Missing fatdb hash"),
					value,
				)
			})
		})
	}
}

/// Iterator over inserted keys.
pub struct FatDBKeyIterator<'db, L>
where
	L: TrieLayout,
{
	trie_iterator: TrieDBKeyIterator<'db, L>,
	trie: &'db TrieDB<'db, L>,
}

impl<'db, L> FatDBKeyIterator<'db, L>
where
	L: TrieLayout,
{
	/// Creates new iterator.
	pub fn new(trie: &'db TrieDB<L>) -> Result<Self, TrieHash<L>, CError<L>> {
		Ok(FatDBKeyIterator { trie_iterator: TrieDBKeyIterator::new(trie)?, trie })
	}
}

impl<'db, L> TrieIterator<L> for FatDBKeyIterator<'db, L>
where
	L: TrieLayout,
{
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		let hashed_key = L::Hash::hash(key);
		self.trie_iterator.seek(hashed_key.as_ref())
	}
}

impl<'db, L> Iterator for FatDBKeyIterator<'db, L>
where
	L: TrieLayout,
{
	type Item = TrieKeyItem<'db, TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		self.trie_iterator.next().map(|res| {
			res.map(|hash| {
				let aux_hash = L::Hash::hash(&hash);
				self.trie.db().get(&aux_hash, Default::default()).expect("Missing fatdb hash")
			})
		})
	}
}

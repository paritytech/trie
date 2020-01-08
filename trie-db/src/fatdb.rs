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
use super::{Result, DBValue, TrieDB, Trie, TrieDBIterator, TrieItem, TrieIterator, Query,
	TrieLayout, CError, TrieHash};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

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
	pub fn db(&self) -> &dyn HashDBRef<L::Hash, DBValue> { self.raw.db() }
}

impl<'db, L> Trie<L> for FatDB<'db, L>
where
	L: TrieLayout,
{
	fn root(&self) -> &TrieHash<L> { self.raw.root() }

	fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.raw.contains(L::Hash::hash(key).as_ref())
	}

	fn get_with<'a, 'key, Q: Query<L::Hash>>(&'a self, key: &'key [u8], query: Q)
		-> Result<Option<Q::Item>, TrieHash<L>, CError<L>>
		where 'a: 'key
	{
		self.raw.get_with(L::Hash::hash(key).as_ref(), query)
	}

	fn iter<'a>(&'a self) -> Result<
		Box<dyn TrieIterator<L, Item = TrieItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		FatDBIterator::<L>::new(&self.raw).map(|iter| Box::new(iter) as Box<_>)
	}
}

/// Itarator over inserted pairs of key values.
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
		Ok(FatDBIterator {
			trie_iterator: TrieDBIterator::new(trie)?,
			trie: trie,
		})
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
		self.trie_iterator.next()
			.map(|res| {
				res.map(|(hash, value)| {
					let aux_hash = L::Hash::hash(&hash);
					(
						self.trie.db().get(&aux_hash, Default::default())
							.expect("Missing fatdb hash"),
						value,
					)
				})
			})
	}
}

#[cfg(test)]
mod test {
	use memory_db::{MemoryDB, HashKey};
	use crate::DBValue;
	use keccak_hasher::KeccakHasher;
	use reference_trie::{RefFatDBMut, RefFatDB, Trie, TrieMut};

	#[test]
	fn fatdb_to_trie() {
		let mut memdb = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefFatDBMut::new(&mut memdb, &mut root);
			t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
		}
		let t = RefFatDB::new(&memdb, &root).unwrap();
		assert_eq!(t.get(&[0x01u8, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
		assert_eq!(
			t.iter().unwrap().map(Result::unwrap).collect::<Vec<_>>(),
			vec![(vec![0x01u8, 0x23], vec![0x01u8, 0x23])]
		);
	}
}

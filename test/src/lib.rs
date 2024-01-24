// Copyright 2020 Parity Technologies
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

//! Tests for trie-db crate.

use trie_db::memory_db::{KeyFunction, MemoryDB};

#[cfg(test)]
mod double_ended_iterator;
#[cfg(test)]
mod iter_build;
#[cfg(test)]
mod iterator;
#[cfg(test)]
mod proof;
#[cfg(test)]
mod recorder;
#[cfg(test)]
mod trie_codec;
#[cfg(test)]
mod trie_root;
#[cfg(test)]
mod triedb;
#[cfg(test)]
mod triedbmut;

use trie_db::{
	mem_tree_db::{Location, MemTreeDB},
	node_db::{self, Hasher, Prefix},
	Changeset, DBValue, TrieHash, TrieLayout,
};

trait TestDB<T: TrieLayout>: node_db::NodeDB<T::Hash, DBValue, T::Location> + Clone + Default {
	fn commit(
		&mut self,
		commit: trie_db::Changeset<<<T as TrieLayout>::Hash as Hasher>::Out, T::Location>,
	) -> TrieHash<T>;
	fn remove(&mut self, hash: &<T::Hash as Hasher>::Out, prefix: Prefix);
	fn is_empty(&self) -> bool;
	fn support_location() -> bool {
		false
	}
}

impl<T: TrieLayout<Hash = H>, H, KF> TestDB<T> for MemoryDB<H, KF, DBValue>
where
	H: Hasher,
	KF: KeyFunction<H> + Send + Sync,
{
	fn commit(
		&mut self,
		commit: trie_db::Changeset<H::Out, <T as TrieLayout>::Location>,
	) -> H::Out {
		commit.apply_to(self)
	}

	fn remove(&mut self, hash: &<T::Hash as Hasher>::Out, prefix: Prefix) {
		MemoryDB::remove(self, hash, prefix);
	}

	fn is_empty(&self) -> bool {
		self.keys().is_empty()
	}
}

impl<T: TrieLayout<Hash = H, Location = Location>, H> TestDB<T> for MemTreeDB<H>
where
	H: Hasher + Clone,
{
	fn commit(&mut self, commit: trie_db::Changeset<H::Out, Location>) -> H::Out {
		let root = commit.root_hash();
		self.apply_commit(commit);
		root
	}

	fn remove(&mut self, hash: &H::Out, _prefix: Prefix) {
		MemTreeDB::test_remove_node(self, hash);
	}

	fn is_empty(&self) -> bool {
		MemTreeDB::is_empty(self)
	}

	fn support_location() -> bool {
		true
	}
}

trait TestCommit<T: TrieLayout> {
	fn commit_to<DB: TestDB<T>>(self, db: &mut DB) -> TrieHash<T>;
}

impl<H, DL, T: TrieLayout<Location = DL>> TestCommit<T> for Changeset<H, DL>
where
	T::Hash: Hasher<Out = H>,
{
	fn commit_to<DB: TestDB<T>>(self, db: &mut DB) -> TrieHash<T> {
		db.commit(self)
	}
}

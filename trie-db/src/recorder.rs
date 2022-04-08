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

//! Trie query recorder.

use crate::{
	rstd::vec::Vec, CError, DBValue, TrieAccess, TrieCache, TrieDBBuilder, TrieHash, TrieLayout,
	TrieRecorder,
};
use hash_db::HashDBRef;
use hashbrown::HashSet;

/// Records trie nodes as they pass it.
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Recorder<L: TrieLayout> {
	nodes: Vec<(TrieHash<L>, Vec<u8>)>,
	keys: HashSet<Vec<u8>>,
}

impl<L: TrieLayout> Default for Recorder<L> {
	fn default() -> Self {
		Recorder::new()
	}
}

impl<L: TrieLayout> Recorder<L> {
	/// Create a new `Recorder` which records all given nodes.
	pub fn new() -> Self {
		Self { nodes: Default::default(), keys: Default::default() }
	}

	/// Drain all visited records.
	pub fn drain(
		&mut self,
		db: &dyn HashDBRef<L::Hash, DBValue>,
		root: &TrieHash<L>,
		cache: Option<&mut dyn TrieCache<L::Codec>>,
	) -> crate::Result<Vec<(TrieHash<L>, Vec<u8>)>, TrieHash<L>, CError<L>> {
		let keys = crate::rstd::mem::take(&mut self.keys);

		{
			let builder = TrieDBBuilder::<L>::new(db, root).with_recorder(self);

			let trie = if let Some(cache) = cache {
				builder.with_cache(cache).build()
			} else {
				builder.build()
			};

			for key in keys {
				trie.traverse_to(&key)?;
			}
		}

		Ok(crate::rstd::mem::take(&mut self.nodes))
	}
}

impl<L: TrieLayout> TrieRecorder<TrieHash<L>> for Recorder<L> {
	fn record<'a>(&mut self, access: TrieAccess<'a, TrieHash<L>>) {
		match access {
			TrieAccess::EncodedNode { hash, encoded_node, .. } => {
				self.nodes.push((hash, encoded_node.to_vec()));
			},
			TrieAccess::NodeOwned { hash, node_owned, .. } => {
				self.nodes.push((hash, node_owned.to_encoded::<L::Codec>()));
			},
			TrieAccess::Key { key, .. } => {
				self.keys.insert(key.to_vec());
			},
			TrieAccess::Value { hash, value, .. } => {
				self.nodes.push((hash, value.to_vec()));
			},
		}
	}
}

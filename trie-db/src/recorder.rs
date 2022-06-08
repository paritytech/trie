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

use crate::{rstd::vec::Vec, RecordedForKey, TrieAccess, TrieHash, TrieLayout, TrieRecorder};
use hashbrown::HashMap;

/// Records trie nodes as they pass it.
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Recorder<L: TrieLayout> {
	nodes: Vec<(TrieHash<L>, Vec<u8>)>,
	recorded_keys: HashMap<Vec<u8>, RecordedForKey>,
}

impl<L: TrieLayout> Default for Recorder<L> {
	fn default() -> Self {
		Recorder::new()
	}
}

impl<L: TrieLayout> Recorder<L> {
	/// Create a new `Recorder` which records all given nodes.
	pub fn new() -> Self {
		Self { nodes: Default::default(), recorded_keys: Default::default() }
	}

	/// Drain all visited records.
	pub fn drain(&mut self) -> Vec<(TrieHash<L>, Vec<u8>)> {
		self.recorded_keys.clear();
		crate::rstd::mem::take(&mut self.nodes)
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
			TrieAccess::Value { hash, value, full_key } => {
				self.nodes.push((hash, value.to_vec()));
				self.recorded_keys.entry(full_key.to_vec()).insert(RecordedForKey::Value);
			},
			TrieAccess::Hash { full_key } => {
				self.recorded_keys.entry(full_key.to_vec()).or_insert(RecordedForKey::Hash);
			},
		}
	}

	fn trie_nodes_recorded_for_key(&self, key: &[u8]) -> RecordedForKey {
		self.recorded_keys.get(key).copied().unwrap_or(RecordedForKey::Nothing)
	}
}

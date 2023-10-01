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
	rstd::{vec::Vec, BTreeMap},
	RecordedForKey, TrieAccess, TrieHash, TrieLayout, TrieRecorder,
};

/// The record of a visited node.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq, Clone)]
pub struct Record<HO> {
	/// The hash of the node.
	pub hash: HO,
	/// The data representing the node.
	pub data: Vec<u8>,
}

/// Records trie nodes as they pass it.
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Recorder<L: TrieLayout> {
	nodes: Vec<Record<TrieHash<L>>>,
	recorded_keys: BTreeMap<Vec<u8>, RecordedForKey>,
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
	pub fn drain(&mut self) -> Vec<Record<TrieHash<L>>> {
		self.recorded_keys.clear();
		crate::rstd::mem::take(&mut self.nodes)
	}
}

impl<L: TrieLayout> TrieRecorder<TrieHash<L>> for Recorder<L> {
	fn record<'a>(&mut self, access: TrieAccess<'a, TrieHash<L>>) {
		match access {
			TrieAccess::EncodedNode { hash, encoded_node, .. } => {
				self.nodes.push(Record { hash, data: encoded_node.to_vec() });
			},
			TrieAccess::NodeOwned { hash, node_owned, .. } => {
				self.nodes.push(Record { hash, data: node_owned.to_encoded::<L::Codec>() });
			},
			TrieAccess::Value { hash, value, full_key } => {
				self.nodes.push(Record { hash, data: value.to_vec() });
				self.recorded_keys.insert(full_key.to_vec(), RecordedForKey::Value);
			},
			TrieAccess::Hash { full_key } => {
				self.recorded_keys.entry(full_key.to_vec()).or_insert(RecordedForKey::Hash);
			},
			TrieAccess::NonExisting { full_key } => {
				// We handle the non existing value/hash like having recorded the value.
				self.recorded_keys.insert(full_key.to_vec(), RecordedForKey::Value);
			},
			TrieAccess::InlineValue { full_key } => {
				self.recorded_keys.insert(full_key.to_vec(), RecordedForKey::Value);
			},
		}
	}

	fn trie_nodes_recorded_for_key(&self, key: &[u8]) -> RecordedForKey {
		self.recorded_keys.get(key).copied().unwrap_or(RecordedForKey::None)
	}
}

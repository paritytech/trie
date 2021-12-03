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

//! Trie query recorder.

use crate::{TrieAccess, TrieRecorder, rstd::vec::Vec};

/// A record of a visited node.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq, Clone)]
pub struct Record<HO> {
	/// The raw data of the node.
	pub data: Vec<u8>,

	/// The hash of the data.
	pub hash: HO,
}

/// Records trie nodes as they pass it.
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Recorder<HO> {
	nodes: Vec<Record<HO>>,
}

impl<HO: Copy> Default for Recorder<HO> {
	fn default() -> Self {
		Recorder::new()
	}
}

impl<HO: Copy> Recorder<HO> {
	/// Create a new `Recorder` which records all given nodes.
	pub fn new() -> Self {
		Self {
			nodes: Vec::new(),
		}
	}

	/// Drain all visited records.
	pub fn drain(&mut self) -> Vec<Record<HO>> {
		crate::rstd::mem::take(&mut self.nodes)
	}
}

impl<H: Copy> TrieRecorder<H> for Recorder<H> {
	fn record<'a>(&mut self, access: TrieAccess<'a, H>) {
		match access {
			TrieAccess::EncodedNode { hash, encoded_node } => self.nodes.push(Record { data: encoded_node.to_vec(), hash }),
			_ => unimplemented!(),
		}
	}
}

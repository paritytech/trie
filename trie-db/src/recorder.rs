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

use crate::rstd::vec::Vec;

/// A record of a visited node.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq, Clone)]
pub struct Record<HO> {
	/// The depth of this node.
	pub depth: u32,

	/// The raw data of the node.
	pub data: Vec<u8>,

	/// The hash of the data.
	pub hash: HO,
}

/// Records trie nodes as they pass it.
#[cfg_attr(feature = "std", derive(Debug))]
pub struct Recorder<HO> {
	nodes: Vec<Record<HO>>,
	min_depth: u32,
}

impl<HO: Copy> Default for Recorder<HO> {
	fn default() -> Self {
		Recorder::new()
	}
}

impl<HO: Copy> Recorder<HO> {
	/// Create a new `Recorder` which records all given nodes.
	#[inline]
	pub fn new() -> Self {
		Recorder::with_depth(0)
	}

	/// Create a `Recorder` which only records nodes beyond a given depth.
	pub fn with_depth(depth: u32) -> Self {
		Recorder {
			nodes: Vec::new(),
			min_depth: depth,
		}
	}

	/// Record a visited node, given its hash, data, and depth.
	pub fn record(&mut self, hash: &HO, data: &[u8], depth: u32) {
		if depth >= self.min_depth {
			self.nodes.push(Record {
				depth,
				data: data.into(),
				hash: *hash,
			})
		}
	}

	/// Drain all visited records.
	pub fn drain(&mut self) -> Vec<Record<HO>> {
		crate::rstd::mem::replace(&mut self.nodes, Vec::new())
	}
}

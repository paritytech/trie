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

use elastic_array::ElasticArray36;
use hash_db::Hasher;
use nibble::NibbleSlice;
use nibble::nibble_ops;
use node_codec::NodeCodec;

use core_::ops::Range;
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Partial node key type: offset and owned value of a nibbleslice.
/// Offset is applied on first byte of array (bytes are right aligned).
pub type NodeKey = (usize, ElasticArray36<u8>);

/// Type of node in the trie and essential information thereof.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Node<'a> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleSlice<'a>, &'a [u8]),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleSlice<'a>, &'a [u8]),
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch([Option<&'a [u8]>; nibble_ops::NIBBLE_LENGTH], Option<&'a [u8]>),
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch(NibbleSlice<'a>, [Option<&'a [u8]>; nibble_ops::NIBBLE_LENGTH], Option<&'a [u8]>),
}

/// Type of node in the trie and essential information thereof.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum NodePlan {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf {
		partial: Range<usize>,
		partial_padding: usize,
		value: Range<usize>,
	},
	/// Extension node; has key slice and node data. Data may not be null.
	Extension {
		partial: Range<usize>,
		partial_padding: usize,
		child_data: Range<usize>,
	},
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch {
		value: Option<Range<usize>>,
		children: [Option<Range<usize>>; nibble_ops::NIBBLE_LENGTH],
	},
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch {
		partial: Range<usize>,
		partial_padding: usize,
		value: Option<Range<usize>>,
		children: [Option<Range<usize>>; nibble_ops::NIBBLE_LENGTH],
	},
}

impl NodePlan {
	pub fn build_node(self, data: &[u8]) -> Option<Node> {
		let node = match self {
			NodePlan::Empty => Node::Empty,
			NodePlan::Leaf { partial, partial_padding, value } => {
				let partial_slice = NibbleSlice::new_offset(data.get(partial)?, partial_padding);
				Node::Leaf(partial_slice, data.get(value.clone())?)
			},
			NodePlan::Extension { partial, partial_padding, child_data } => {
				let partial_slice = NibbleSlice::new_offset(data.get(partial)?, partial_padding);
				Node::Extension(partial_slice, data.get(child_data.clone())?)
			},
			NodePlan::Branch { value, children } => {
				let mut child_slices = [None; nibble_ops::NIBBLE_LENGTH];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if let Some(range) = children[i].clone() {
						child_slices[i] = Some(data.get(range)?);
					}
				}
				let value_slice = match value {
					Some(range) => Some(data.get(range)?),
					None => None,
				};
				Node::Branch(child_slices, value_slice)
			},
			NodePlan::NibbledBranch { partial, partial_padding, value, children } => {
				let partial_slice = NibbleSlice::new_offset(data.get(partial)?, partial_padding);
				let mut child_slices = [None; nibble_ops::NIBBLE_LENGTH];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if let Some(range) = children[i].clone() {
						child_slices[i] = Some(data.get(range)?);
					}
				}
				let value_slice = match value {
					Some(range) => Some(data.get(range)?),
					None => None,
				};
				Node::NibbledBranch(partial_slice, child_slices, value_slice)
			},
		};
		Some(node)
	}
}

/// An owning node type. Useful for trie iterators.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq)]
pub struct OwnedNode<D: AsRef<[u8]>> {
	data: D,
	plan: NodePlan,
}

impl<D: AsRef<[u8]>> OwnedNode<D> {
	pub fn new<H: Hasher, C: NodeCodec<H>>(data: D) -> Result<Self, C::Error> {
		let plan = C::decode_plan(data.as_ref())?;
		Ok(OwnedNode { data, plan })
	}

	pub fn node(&self) -> Node {
		self.plan.clone().build_node(self.data.as_ref())
			.expect("plan is constructed on the same data so cannot reference out-of-range data; qed")
	}
}

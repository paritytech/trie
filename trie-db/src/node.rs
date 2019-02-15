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
use nibbleslice::NibbleSlice;
use nibblevec::NibbleVec;
use super::DBValue;

/// Partial node key type.
pub type NodeKey = ElasticArray36<u8>;

/// Type of node in the trie and essential information thereof.
#[derive(Eq, PartialEq, Debug, Clone)]
pub enum Node<'a> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleSlice<'a>, &'a [u8]),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleSlice<'a>, &'a [u8]),
	/// Branch node; has array of 16 child nodes (each possibly null) and an optional immediate node data.
	Branch([Option<&'a [u8]>; 16], Option<&'a [u8]>),
	/// Branch node with support for a nibble (to avoid extension node)
	NibbledBranch(NibbleSlice<'a>, [Option<&'a [u8]>; 16], Option<&'a [u8]>),
}

/// A Sparse (non mutable) owned vector struct to hold branch keys and value
#[derive(Eq, PartialEq, Debug, Clone)]
pub struct Branch {
	data: Vec<u8>,
	ubounds: [usize; 18],
	has_value: bool,
}

impl Branch {
	fn new(children: [Option<&[u8]>; 16], maybe_value: Option<&[u8]>) -> Self {
		let mut data = Vec::with_capacity(children.iter()
			.filter_map(|n| n.clone())
			.map(|child| child.len())
			.sum()
		);
		let mut ubounds = [0; 18];
		for (maybe_child, ub) in children.iter().zip(ubounds.iter_mut().skip(1)) {
			if let Some(child) = maybe_child {
				data.extend_from_slice(child);
			}
			*ub = data.len();
		}
		if let Some(value) = maybe_value {
			data.extend_from_slice(value);
			ubounds[17] = data.len();
		}
		Branch { data, ubounds, has_value: maybe_value.is_some() }
	}

	/// Get the node value, if any
	pub fn get_value(&self) -> Option<&[u8]> {
		if self.has_value {
			Some(&self.data[self.ubounds[16]..self.ubounds[17]])
		} else {
			None
		}
	}

	/// Test if the node has a value
	pub fn has_value(&self) -> bool {
		self.has_value
	}

	pub fn index(&self, index: usize) -> Option<&[u8]> {
		assert!(index < 16);
		if self.ubounds[index] == self.ubounds[index + 1] {
			None
		} else {
			Some(&self.data[self.ubounds[index]..self.ubounds[index + 1]])
		}
	}
}

/// An owning node type. Useful for trie iterators.
#[derive(Debug, PartialEq, Eq)]
pub enum OwnedNode {
	/// Empty trie node.
	Empty,
	/// Leaf node: partial key and value.
	Leaf(NibbleVec, DBValue),
	/// Extension node: partial key and child node.
	Extension(NibbleVec, DBValue),
	/// Branch node: 16 children and an optional value.
	Branch(Branch),
	/// Branch node: 16 children and an optional value.
	NibbledBranch(NibbleVec, Branch),
}

impl<'a> From<Node<'a>> for OwnedNode {
	fn from(node: Node<'a>) -> Self {
		match node {
			Node::Empty => OwnedNode::Empty,
			Node::Leaf(k, v) => OwnedNode::Leaf(k.into(), DBValue::from_slice(v)),
			Node::Extension(k, child) => OwnedNode::Extension(k.into(), DBValue::from_slice(child)),
			Node::Branch(c, val) => OwnedNode::Branch(Branch::new(c, val)),
			Node::NibbledBranch(k, c, val) => OwnedNode::NibbledBranch(k.into(), Branch::new(c, val)),
		}
	}
}

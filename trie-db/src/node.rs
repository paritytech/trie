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
use nibble::NibbleSlice;
use nibble::{NibbleOps, ChildSliceIx};
use nibble::NibbleVec;
use super::DBValue;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Partial node key type: offset and owned value of a nibbleslice.
/// Offset is applied on first byte of array.
pub type NodeKey = (usize, ElasticArray36<u8>);

/// alias to branch children slice
pub type BranchChildrenSlice<'a, N> = (<N as NibbleOps>::ChildSliceIx, &'a[u8]); 

/// Type of node in the trie and essential information thereof.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Node<'a, N: NibbleOps> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleSlice<'a, N>, &'a [u8]),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleSlice<'a, N>, &'a [u8]),
	// TODO EMCH var length for children array is stuck behind https://github.com/rust-lang/rust/issues/43408
	// So we should also put it as associated type of N, but generic_associated_types will be needed
	// for lifetime, so we should ultimately use something similar to struct `Branch` it decodes from
	// a slice that is already aligned (need 2* bound in case there is some headers).
	/// Branch node; has array of 16 child nodes (each possibly null) and an optional immediate node data.
	Branch(BranchChildrenSlice<'a, N>, Option<&'a [u8]>),
	/// Branch node with support for a nibble (to avoid extension node)
	NibbledBranch(NibbleSlice<'a, N>, BranchChildrenSlice<'a, N>, Option<&'a [u8]>),
}
/// A Sparse (non mutable) owned vector struct to hold branch keys and value
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Eq, PartialEq, Clone)]
pub struct Branch {
	data: Vec<u8>,
	data_ix: usize,
	ubounds_ix: usize,
	child_head: usize,
}

impl Branch {
	fn new<N: NibbleOps>(children_slice: &BranchChildrenSlice<N>, maybe_value: Option<&[u8]>) -> Self {
		let mut data: Vec<u8> = children_slice.1.into();
		let data_ix = data.len();
		let ubounds_ix = data_ix + maybe_value.map(|v|{
			data.extend_from_slice(v);
			v.len()
		}).unwrap_or(0);
		let mut i = 0;
		while let Some(ix) = children_slice.0.as_ref().get(i) {
			i += 1;
			data.extend_from_slice(&ix.to_ne_bytes()[..]);
		}
		Branch { data, data_ix, ubounds_ix, child_head: N::ChildSliceIx::CONTENT_HEADER_SIZE }
	}

	/// Get the node value, if any
	pub fn get_value(&self) -> Option<&[u8]> {
		if self.has_value() {
			Some(&self.data[self.data_ix..self.ubounds_ix])
		} else {
			None
		}
	}

	/// Test if the node has a value
	pub fn has_value(&self) -> bool {
		self.data_ix < self.ubounds_ix
	}

	fn index_bound(&self, index: usize) -> Option<usize> {
		use core_::convert::TryInto;
		use core_::mem;
		let usize_len = mem::size_of::<usize>(); 
		let s = self.ubounds_ix + index * usize_len;
		let e = s + usize_len;
		if self.data.len() < e {
			None
		} else {
			self.data[s..e].try_into().ok().map(usize::from_ne_bytes)
		}
	}
	pub fn index(&self, index: usize) -> Option<&[u8]> {
		let b = (self.index_bound(index), self.index_bound(index + 1));
		if let (Some(s), Some(e)) = b {
			let s = s + self.child_head;
			if s < e {
				return Some(&self.data[s..e])
			}
		}
		None
	}
}

/// An owning node type. Useful for trie iterators.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq)]
pub enum OwnedNode<N> {
	/// Empty trie node.
	Empty,
	/// Leaf node: partial key and value.
	Leaf(NibbleVec<N>, DBValue),
	/// Extension node: partial key and child node.
	Extension(NibbleVec<N>, DBValue),
	/// Branch node: 16 children and an optional value.
	Branch(Branch),
	/// Branch node: 16 children and an optional value.
	/// TODO can put nibble vec into branch data vec
	NibbledBranch(NibbleVec<N>, Branch),
}

impl<'a, N: NibbleOps> From<Node<'a, N>> for OwnedNode<N> {
	fn from(node: Node<'a, N>) -> Self {
		match node {
			Node::Empty => OwnedNode::Empty,
			Node::Leaf(k, v) => OwnedNode::Leaf(k.into(), DBValue::from_slice(v)),
			Node::Extension(k, child) => OwnedNode::Extension(k.into(), DBValue::from_slice(child)),
			Node::Branch(c, val) => OwnedNode::Branch(Branch::new::<N>(&c, val)),
			Node::NibbledBranch(k, c, val) => OwnedNode::NibbledBranch(k.into(), Branch::new::<N>(&c, val)),
		}
	}
}

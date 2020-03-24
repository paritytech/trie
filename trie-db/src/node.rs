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

use hash_db::Hasher;
use crate::nibble::{self, NibbleSlice};
use crate::nibble::NibbleOps;
use crate::node_codec::NodeCodec;

use crate::nibble::nibble_ops;
use crate::nibble::{ChildSliceIndex, ChildSliceType};

use crate::rstd::{borrow::Borrow, ops::Range};

/// Partial node key type: offset and owned value of a nibbleslice.
/// Offset is applied on first byte of array (bytes are right aligned).
pub type NodeKey = (usize, nibble::BackingByteVec);

#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
/// Alias to branch children slice, it is equivalent to '&[&[u8]]'.
/// Reason for using it is https://github.com/rust-lang/rust/issues/43408.
pub struct BranchChildrenSlice<'a, I> {
	index: I,
	data: &'a[u8],
}

impl<'a, I: ChildSliceIndex> BranchChildrenSlice<'a, I> {
	/// Similar to `Index` but returns a copied value.
	pub fn at(&self, index: usize) -> Option<NodeHandle<'a>> {
		if index < I::NIBBLE_LENGTH {
			let (start, child_type, end) = self.index.range_at(index);
			if end > start {
				return Some(match child_type {
					ChildSliceType::Hash => NodeHandle::Hash(&self.data[start..end]),
					ChildSliceType::Inline => NodeHandle::Inline(&self.data[start..end]),
				});
			}
		}
		None
	}

	/// Iterator over children node handles.
	pub fn iter(&'a self) -> impl Iterator<Item=Option<NodeHandle<'a>>> {
		self.index.iter(self.data).map(|o_slice| o_slice.map(|(slice, child_type)| match child_type {
			ChildSliceType::Hash => NodeHandle::Hash(slice),
			ChildSliceType::Inline => NodeHandle::Inline(slice),
		}))
	}
}

/// A reference to a trie node which may be stored within another trie node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeHandle<'a> {
	Hash(&'a [u8]),
	Inline(&'a [u8]),
}

/// Read a hash from a slice into a Hasher output. Returns None if the slice is the wrong length.
pub fn decode_hash<H: Hasher>(data: &[u8]) -> Option<H::Out> {
	if data.len() != H::LENGTH {
		return None;
	}
	let mut hash = H::Out::default();
	hash.as_mut().copy_from_slice(data);
	Some(hash)
}

/// Type of node in the trie and essential information thereof.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Node<'a, I> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleSlice<'a>, &'a [u8]),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleSlice<'a>, NodeHandle<'a>),
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch(BranchChildrenSlice<'a, I>, Option<&'a [u8]>),
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch(NibbleSlice<'a>, BranchChildrenSlice<'a, I>, Option<&'a [u8]>),
}

/// A `NodeHandlePlan` is a decoding plan for constructing a `NodeHandle` from an encoded trie
/// node. This is used as a substructure of `NodePlan`. See `NodePlan` for details.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NodeHandlePlan {
	Hash(Range<usize>),
	Inline(Range<usize>),
}

impl NodeHandlePlan {
	/// Build a node handle by decoding a byte slice according to the node handle plan. It is the
	/// responsibility of the caller to ensure that the node plan was created for the argument
	/// data, otherwise the call may decode incorrectly or panic.
	pub fn build<'a, 'b>(&'a self, data: &'b [u8]) -> NodeHandle<'b> {
		match self {
			NodeHandlePlan::Hash(range) => NodeHandle::Hash(&data[range.clone()]),
			NodeHandlePlan::Inline(range) => NodeHandle::Inline(&data[range.clone()]),
		}
	}
}

/// A `NibbleSlicePlan` is a blueprint for decoding a nibble slice from a byte slice. The
/// `NibbleSlicePlan` is created by parsing a byte slice and can be reused multiple times.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct NibbleSlicePlan {
	bytes: Range<usize>,
	offset: usize,
}

impl NibbleSlicePlan {
	/// Construct a nibble slice decode plan.
	pub fn new(bytes: Range<usize>, offset: usize) -> Self {
		NibbleSlicePlan {
			bytes,
			offset
		}
	}

	/// Returns the nibble length of the slice.
	pub fn len(&self) -> usize {
		(self.bytes.end - self.bytes.start) * nibble_ops::NIBBLE_PER_BYTE - self.offset
	}

	/// Build a nibble slice by decoding a byte slice according to the plan. It is the
	/// responsibility of the caller to ensure that the node plan was created for the argument
	/// data, otherwise the call may decode incorrectly or panic.
	pub fn build<'a, 'b>(&'a self, data: &'b [u8]) -> NibbleSlice<'b> {
		NibbleSlice::new_offset(&data[self.bytes.clone()], self.offset)
	}
}

/// TODO try non public
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct BranchChildrenNodePlan<I> {
	index: I,
}

impl<I: ChildSliceIndex> BranchChildrenNodePlan<I> {
	/// Similar to `Index` but return a copied value.
	pub fn at(&self, index: usize) -> Option<NodeHandlePlan> {
		if index < I::NIBBLE_LENGTH {
			let (start, child_type, end) = self.index.range_at(index);
			if end > start {
				return Some(match child_type {
					ChildSliceType::Hash => NodeHandlePlan::Hash(start..end),
					ChildSliceType::Inline => NodeHandlePlan::Inline(start..end),
				});
			}
		}
		None
	}

	/// Build from sequence of content.
	pub fn new(nodes: impl Iterator<Item = Option<NodeHandlePlan>>) -> Self {
		let index = ChildSliceIndex::from_node_plan(nodes);
		BranchChildrenNodePlan { index }
	}
}

/// A `NodePlan` is a blueprint for decoding a node from a byte slice. The `NodePlan` is created
/// by parsing an encoded node and can be reused multiple times. This is useful as a `Node` borrows
/// from a byte slice and this struct does not.
///
/// The enum values mirror those of `Node` except that instead of byte slices, this struct stores
/// ranges that can be used to index into a large byte slice.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum NodePlan<I> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has a partial key plan and value.
	Leaf {
		partial: NibbleSlicePlan,
		value: Range<usize>,
	},
	/// Extension node; has a partial key plan and child data.
	Extension {
		partial: NibbleSlicePlan,
		child: NodeHandlePlan,
	},
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch {
		value: Option<Range<usize>>,
		children: BranchChildrenNodePlan<I>,
	},
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch {
		partial: NibbleSlicePlan,
		value: Option<Range<usize>>,
		children: BranchChildrenNodePlan<I>,
	},
}

impl<I: ChildSliceIndex> NodePlan<I> {
	/// Build a node by decoding a byte slice according to the node plan. It is the responsibility
	/// of the caller to ensure that the node plan was created for the argument data, otherwise the
	/// call may decode incorrectly or panic.
	pub fn build<'a, 'b>(&'a self, data: &'b [u8]) -> Node<'b, I> {
		match self {
			NodePlan::Empty => Node::Empty,
			NodePlan::Leaf { partial, value } =>
				Node::Leaf(partial.build(data), &data[value.clone()]),
			NodePlan::Extension { partial, child } =>
				Node::Extension(partial.build(data), child.build(data)),
			NodePlan::Branch { value, children } => {
				let child_slices = BranchChildrenSlice {
					index: children.index.clone(),
					data,
				};
				let value_slice = value.clone().map(|value| &data[value]);
				Node::Branch(child_slices, value_slice)
			},
			NodePlan::NibbledBranch { partial, value, children } => {
				let child_slices = BranchChildrenSlice {
					index: children.index.clone(),
					data,
				};
				let value_slice = value.clone().map(|value| &data[value]);
				Node::NibbledBranch(partial.build(data), child_slices, value_slice)
			},
		}
	}
}

/// An `OwnedNode` is an owned type from which a `Node` can be constructed which borrows data from
/// the `OwnedNode`. This is useful for trie iterators.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq)]
pub struct OwnedNode<D: Borrow<[u8]>, I> {
	data: D,
	plan: NodePlan<I>,
}

impl<D: Borrow<[u8]>, I: ChildSliceIndex> OwnedNode<D, I> {
	/// Construct an `OwnedNode` by decoding an owned data source according to some codec.
	pub fn new<C: NodeCodec<ChildIndex = I>>(data: D) -> Result<Self, C::Error>	{
		let plan = C::decode_plan(data.borrow())?;
		Ok(OwnedNode { data, plan })
	}

	/// Returns a reference to the backing data.
	pub fn data(&self) -> &[u8] {
		self.data.borrow()
	}

	/// Returns a reference to the node decode plan.
	pub fn node_plan(&self) -> &NodePlan<I> {
		&self.plan
	}

	/// Construct a `Node` by borrowing data from this struct.
	pub fn node(&self) -> Node<I> {
		self.plan.build(self.data.borrow())
	}
}

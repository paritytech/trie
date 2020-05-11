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
use crate::nibble::nibble_ops;
use crate::node_codec::NodeCodec;
use crate::rstd::{borrow::Borrow, ops::Range, boxed::Box, vec::Vec};


/// This was only implemented for trie without extension, it could
/// be implemented for trie and extension in the future but is not
/// at this point.
const NO_EXTENSION_ONLY: &str = "trie without extension implemented only";

/// Owned handle to a node, to use when there is no caching.
pub type StorageHandle = Vec<u8>;

type TNode<H> = crate::triedbmut::NodeMut<H, StorageHandle>;

type TNodeHandle<H> = crate::triedbmut::NodeHandleMut<H, StorageHandle>;

/// Partial node key type: offset and owned value of a nibbleslice.
/// Offset is applied on first byte of array (bytes are right aligned).
pub type NodeKey = (usize, nibble::BackingByteVec);

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
pub enum Node<'a> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleSlice<'a>, &'a [u8]),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleSlice<'a>, NodeHandle<'a>),
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch([Option<NodeHandle<'a>>; nibble_ops::NIBBLE_LENGTH], Option<&'a [u8]>),
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch(NibbleSlice<'a>, [Option<NodeHandle<'a>>; nibble_ops::NIBBLE_LENGTH], Option<&'a [u8]>),
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

	fn build_owned_handle<H: AsMut<[u8]> + Default>(&self, data: &[u8]) -> TNodeHandle<H> {
		match self {
			NodeHandlePlan::Hash(range) => {
				let mut hash = H::default();
				hash.as_mut().copy_from_slice(&data[range.clone()]);
				TNodeHandle::Hash(hash)
			},
			NodeHandlePlan::Inline(range) => TNodeHandle::InMemory((&data[range.clone()]).into()),
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

/// A `NodePlan` is a blueprint for decoding a node from a byte slice. The `NodePlan` is created
/// by parsing an encoded node and can be reused multiple times. This is useful as a `Node` borrows
/// from a byte slice and this struct does not.
///
/// The enum values mirror those of `Node` except that instead of byte slices, this struct stores
/// ranges that can be used to index into a large byte slice.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum NodePlan {
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
		children: [Option<NodeHandlePlan>; nibble_ops::NIBBLE_LENGTH],
	},
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch {
		partial: NibbleSlicePlan,
		value: Option<Range<usize>>,
		children: [Option<NodeHandlePlan>; nibble_ops::NIBBLE_LENGTH],
	},
}

impl NodePlan {
	/// Build a node by decoding a byte slice according to the node plan. It is the responsibility
	/// of the caller to ensure that the node plan was created for the argument data, otherwise the
	/// call may decode incorrectly or panic.
	pub fn build<'a, 'b>(&'a self, data: &'b [u8]) -> Node<'b> {
		match self {
			NodePlan::Empty => Node::Empty,
			NodePlan::Leaf { partial, value } =>
				Node::Leaf(partial.build(data), &data[value.clone()]),
			NodePlan::Extension { partial, child } =>
				Node::Extension(partial.build(data), child.build(data)),
			NodePlan::Branch { value, children } => {
				let mut child_slices = [None; nibble_ops::NIBBLE_LENGTH];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					child_slices[i] = children[i].as_ref().map(|child| child.build(data));
				}
				let value_slice = value.clone().map(|value| &data[value]);
				Node::Branch(child_slices, value_slice)
			},
			NodePlan::NibbledBranch { partial, value, children } => {
				let mut child_slices = [None; nibble_ops::NIBBLE_LENGTH];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					child_slices[i] = children[i].as_ref().map(|child| child.build(data));
				}
				let value_slice = value.clone().map(|value| &data[value]);
				Node::NibbledBranch(partial.build(data), child_slices, value_slice)
			},
		}
	}
}

/// An `OwnedNode` is an owned type from which a `Node` can be constructed which borrows data from
/// the `OwnedNode`. This is useful for trie iterators.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, PartialEq, Eq)]
pub struct OwnedNode<D: Borrow<[u8]>> {
	data: D,
	plan: NodePlan,
}

impl<D: Borrow<[u8]>> OwnedNode<D> {
	/// Construct an `OwnedNode` by decoding an owned data source according to some codec.
	pub fn new<C: NodeCodec>(data: D) -> Result<Self, C::Error> {
		let plan = C::decode_plan(data.borrow())?;
		Ok(OwnedNode { data, plan })
	}

	/// Returns a reference to the backing data.
	pub fn data(&self) -> &[u8] {
		self.data.borrow()
	}

	/// Returns a reference to the node decode plan.
	pub fn node_plan(&self) -> &NodePlan {
		&self.plan
	}

	/// Construct a `Node` by borrowing data from this struct.
	pub fn node(&self) -> Node {
		self.plan.build(self.data.borrow())
	}

	/// Get extension part of the node (partial) if any.
	pub fn partial(&self) -> Option<NibbleSlice> {
		match &self.plan {
			NodePlan::Branch { .. }
			| NodePlan::Empty => None,
			NodePlan::Leaf { partial, .. }
			| NodePlan::NibbledBranch { partial, .. }
			| NodePlan::Extension { partial, .. } =>
				Some(partial.build(self.data.borrow())),
		}
	}

	/// Tell if there is a value defined at this node position.
	pub fn has_value(&self) -> bool {
		match &self.plan {
			NodePlan::Extension { .. }
			| NodePlan::Empty => false,
			NodePlan::Leaf { .. }	=> true,
			NodePlan::Branch { value, .. }
			| NodePlan::NibbledBranch { value, .. }	=> value.is_some(),
		}
	}


	/// Get value part of the node (partial) if any.
	pub fn value(&self) -> Option<super::DBValue> {
		let data = &self.data.borrow();
		match &self.plan {
			NodePlan::Branch { .. }
			| NodePlan::Extension { .. }
			| NodePlan::Empty => None,
			NodePlan::Leaf { value, .. }
				=> Some(data[value.clone()].into()),
			| NodePlan::NibbledBranch { value, .. }
				=> value.as_ref().map(|v| data[v.clone()].into()),
		}
	}

	/// Try to access child.
	pub fn child(&self, ix: u8) -> Option<NodeHandle> {
		match &self.plan {
			NodePlan::Leaf { .. }
			| NodePlan::Extension { .. }
			| NodePlan::Empty => None,
			NodePlan::NibbledBranch { children, .. }
			| NodePlan::Branch { children, .. } =>
				children[ix as usize].as_ref().map(|child| child.build(self.data.borrow())),
		}
	}

	/// Tell if it is the empty node.
	pub fn is_empty(&self) -> bool {
		if let NodePlan::Empty = &self.plan {
			true
		} else {
			false
		}
	}

	/// Return number of children for this node.
	pub fn number_child(&self) -> usize {
		match &self.plan {
			NodePlan::Leaf { .. }
			| NodePlan::Empty => 0,
			NodePlan::Extension { .. } => 1,
			NodePlan::NibbledBranch { children, .. }
			| NodePlan::Branch { children, .. } => children.len(),
		}
	}
}

impl<B: Borrow<[u8]>> OwnedNode<B> {


	fn init_child_slice<H: AsMut<[u8]> + Default>(
		data: &[u8],
		children: &[Option<NodeHandlePlan>; nibble_ops::NIBBLE_LENGTH],
		skip_index: Option<usize>,
	) -> Box<[Option<TNodeHandle<H>>; 16]> {
		let mut child_slices = Box::new([
			None, None, None, None,
			None, None, None, None,
			None, None, None, None,
			None, None, None, None,
		]);
		if let Some(skip) = skip_index {
			for i in 0..nibble_ops::NIBBLE_LENGTH {
				if i != skip {
					child_slices[i] = children[i].as_ref().map(|child| child.build_owned_handle(data));
				}
			}
		} else {
			for i in 0..nibble_ops::NIBBLE_LENGTH {
				child_slices[i] = children[i].as_ref().map(|child| child.build_owned_handle(data));
			}
		}
		child_slices
	}

	/// Remove n first byte from the existing partial, return updated node if updated.
	pub(crate) fn advance_partial<H: AsMut<[u8]> + Default>(&mut self, nb: usize) -> Option<TNode<H>> {
		if nb == 0 {
			return None;
		}
		let data = &self.data.borrow();
		match &self.plan {
			NodePlan::Leaf { partial, value } => {
				let mut partial = partial.build(data);
				partial.advance(nb);
				Some(TNode::Leaf(
					partial.into(),
					data[value.clone()].into(),
				))
			},
			NodePlan::Extension { .. } => unimplemented!("{}", NO_EXTENSION_ONLY),
			NodePlan::Branch { .. }
			| NodePlan::Empty => None,
			NodePlan::NibbledBranch { partial, value, children } => {
				let mut partial = partial.build(data);
				partial.advance(nb);

				Some(TNode::NibbledBranch(
					partial.into(),
					Self::init_child_slice(data, children, None),
					value.as_ref().map(|value| data[value.clone()].into()),
				))
			},
		}
	}

	/// Set a partial and return new node if changed.
	pub(crate) fn set_partial<H: AsMut<[u8]> + Default>(&mut self, new_partial: NodeKey) -> Option<TNode<H>> {
		let data = &self.data.borrow();
		match &self.plan {
			NodePlan::Leaf { value, partial } => {
				let partial = partial.build(data);
				if partial == NibbleSlice::from_stored(&new_partial) {
					return None;
				}
				Some(TNode::Leaf(
					new_partial,
					data[value.clone()].into(),
				))
			},
			NodePlan::Extension { .. } => unimplemented!("{}", NO_EXTENSION_ONLY),
			NodePlan::Branch { .. }
			| NodePlan::Empty => None,
			NodePlan::NibbledBranch { value, children, partial } => {
				let partial = partial.build(data);
				if partial == NibbleSlice::from_stored(&new_partial) {
					return None;
				}
				Some(TNode::NibbledBranch(
					new_partial,
					Self::init_child_slice(data, children, None),
					value.as_ref().map(|value| data[value.clone()].into()),
				))
			},
		}
	}

	/// Set a value and return new node if changed.
	pub(crate) fn set_value<H: AsMut<[u8]> + Default>(&mut self, new_value: &[u8]) -> Option<TNode<H>> {
		let data = &self.data.borrow();
		match &self.plan {
			NodePlan::Empty => {
				Some(TNode::Leaf(
					Default::default(),
					new_value.into(),
				))
			},
			NodePlan::Leaf { partial, value } => {
				if &data[value.clone()] == new_value {
					return None;
				}
				Some(TNode::Leaf(
					partial.build(data).into(),
					new_value.into(),
				))
			},
			NodePlan::Extension { .. } => None,
			NodePlan::Branch { .. } => unimplemented!("{}", NO_EXTENSION_ONLY),
			NodePlan::NibbledBranch { partial, value, children } => {
				if let Some(value) = value {
					if &data[value.clone()] == new_value {
						return None;
					}
				}

				Some(TNode::NibbledBranch(
					partial.build(data).into(),
					Self::init_child_slice(data, children, None),
					Some(new_value.into()),
				))
			},
		}
	}

	/// Remove a value, return the change if something did change either node deleted or new value
	/// for node.
	/// Note that we are allowed to return a branch with no value and a single child (would need to
	/// be fix depending on calling context (there could be some appending afterward)).
	pub(crate) fn remove_value<H: AsMut<[u8]> + Default>(&mut self) -> Option<Option<TNode<H>>> {
		let data = &self.data.borrow();
		match &self.plan {
			NodePlan::Leaf { .. } => Some(None),
			NodePlan::Branch { .. } => unimplemented!("{}", NO_EXTENSION_ONLY),
			NodePlan::Extension { .. }
			| NodePlan::Empty => None,
			NodePlan::NibbledBranch { partial, value, children } => {
				if value.is_none() {
					return None;
				}

				Some(Some(TNode::NibbledBranch(
					partial.build(data).into(),
					Self::init_child_slice(data, children, None),
					None,
				)))
			},
		}
	}

	/// Set a handle to a child node or remove it if handle is none.
	/// Return possibly updated node.
	pub(crate) fn set_handle<H: AsMut<[u8]> + Default>(&mut self, handle: Option<TNodeHandle<H>>, index: u8)
		-> Option<TNode<H>> {

		let index = index as usize;
		let data = &self.data.borrow();
		match &mut self.plan {
			NodePlan::Empty => unreachable!("Do not add handle to empty but replace the node instead"),
			NodePlan::Extension { .. }
			| NodePlan::Branch { .. } => unimplemented!("{}", NO_EXTENSION_ONLY),
			NodePlan::Leaf { partial, value } => {
				if handle.is_some() {
					let mut child_slices = Box::new([
						None, None, None, None,
						None, None, None, None,
						None, None, None, None,
						None, None, None, None,
					]);
					child_slices[index] = handle;

					Some(TNode::NibbledBranch(
						partial.build(data).into(),
						child_slices,
						Some(data[value.clone()].into())),
					)
				} else {
					None
				}
			},
			NodePlan::NibbledBranch { partial, value, children } => {
				if handle.is_none() && children[index].is_none() {
					None
				} else {
					let value = if let Some(value) = value.clone() {
						Some(data[value.clone()].into())
					} else {
						None
					};
					let mut child_slices = Self::init_child_slice(data, children, Some(index));
					child_slices[index] = handle;

					Some(TNode::NibbledBranch(
						partial.build(data).into(),
						child_slices,
						value,
					))
				}
			},
		}
	}
}

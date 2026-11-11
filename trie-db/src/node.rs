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

use crate::{
	nibble::{self, nibble_ops, NibbleSlice, NibbleVec},
	node_codec::NodeCodec,
	Bytes, CError, ChildReference, Result, TrieError, TrieHash, TrieLayout,
};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};
use hash_db::Hasher;

use crate::rstd::{borrow::Borrow, mem, ops::Range};

/// Partial node key type: offset and owned value of a nibbleslice.
/// Offset is applied on first byte of array (bytes are right aligned).
pub type NodeKey = (usize, nibble::BackingByteVec);

/// A reference to a trie node which may be stored within another trie node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeHandle<'a> {
	Hash(&'a [u8]),
	Inline(&'a [u8]),
}

impl NodeHandle<'_> {
	/// Converts this node handle into a [`NodeHandleOwned`].
	pub fn to_owned_handle<L: TrieLayout>(
		&self,
	) -> Result<NodeHandleOwned<TrieHash<L>>, TrieHash<L>, CError<L>> {
		match self {
			Self::Hash(h) => decode_hash::<L::Hash>(h)
				.ok_or_else(|| Box::new(TrieError::InvalidHash(Default::default(), h.to_vec())))
				.map(NodeHandleOwned::Hash),
			Self::Inline(i) => match L::Codec::decode(i) {
				Ok(node) => Ok(NodeHandleOwned::Inline(Box::new(node.to_owned_node::<L>()?))),
				Err(e) => Err(Box::new(TrieError::DecoderError(Default::default(), e))),
			},
		}
	}
}

/// Owned version of [`NodeHandleOwned`].
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum NodeHandleOwned<H> {
	Hash(H),
	Inline(Box<NodeOwned<H>>),
}

impl<H> NodeHandleOwned<H>
where
	H: Default + AsRef<[u8]> + AsMut<[u8]> + Copy,
{
	/// Returns `self` as a [`ChildReference`].
	///
	/// # Panic
	///
	/// This function panics if `self == Self::Inline(_)` and the inline node encoded length is
	/// greater then the length of the hash.
	fn as_child_reference<C: NodeCodec<HashOut = H>>(&self) -> ChildReference<H> {
		match self {
			NodeHandleOwned::Hash(h) => ChildReference::Hash(*h),
			NodeHandleOwned::Inline(n) => {
				let encoded = n.to_encoded::<C>();
				let mut store = H::default();
				assert!(store.as_ref().len() > encoded.len(), "Invalid inline node handle");

				store.as_mut()[..encoded.len()].copy_from_slice(&encoded);
				ChildReference::Inline(store, encoded.len())
			},
		}
	}
}

impl<H> NodeHandleOwned<H> {
	/// Returns `self` as inline node.
	pub fn as_inline(&self) -> Option<&NodeOwned<H>> {
		match self {
			Self::Hash(_) => None,
			Self::Inline(node) => Some(&*node),
		}
	}
}

/// Read a hash from a slice into a Hasher output. Returns None if the slice is the wrong length.
pub fn decode_hash<H: Hasher>(data: &[u8]) -> Option<H::Out> {
	if data.len() != H::LENGTH {
		return None
	}
	let mut hash = H::Out::default();
	hash.as_mut().copy_from_slice(data);
	Some(hash)
}

/// Value representation in `Node`.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Value<'a> {
	/// Value byte slice as stored in a trie node.
	Inline(&'a [u8]),
	/// Hash byte slice as stored in a trie node.
	Node(&'a [u8]),
}

impl<'a> Value<'a> {
	pub(crate) fn new_inline(value: &'a [u8], threshold: Option<u32>) -> Option<Self> {
		if let Some(threshold) = threshold {
			if value.len() >= threshold as usize {
				return None
			} else {
				Some(Value::Inline(value))
			}
		} else {
			Some(Value::Inline(value))
		}
	}

	pub fn to_owned_value<L: TrieLayout>(&self) -> ValueOwned<TrieHash<L>> {
		match self {
			Self::Inline(data) => ValueOwned::Inline(Bytes::from(*data), L::Hash::hash(data)),
			Self::Node(hash) => {
				let mut res = TrieHash::<L>::default();
				res.as_mut().copy_from_slice(hash);

				ValueOwned::Node(res)
			},
		}
	}
}

/// Owned value representation in `Node`.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ValueOwned<H> {
	/// Value bytes as stored in a trie node and its hash.
	Inline(Bytes, H),
	/// Hash byte slice as stored in a trie node.
	Node(H),
}

impl<H: AsRef<[u8]> + Copy> ValueOwned<H> {
	/// Returns self as [`Value`].
	pub fn as_value(&self) -> Value<'_> {
		match self {
			Self::Inline(data, _) => Value::Inline(&data),
			Self::Node(hash) => Value::Node(hash.as_ref()),
		}
	}

	/// Returns the hash of the data stored in self.
	pub fn data_hash(&self) -> Option<H> {
		match self {
			Self::Inline(_, hash) => Some(*hash),
			Self::Node(hash) => Some(*hash),
		}
	}
}

impl<H> ValueOwned<H> {
	/// Returns the data stored in self.
	pub fn data(&self) -> Option<&Bytes> {
		match self {
			Self::Inline(data, _) => Some(data),
			Self::Node(_) => None,
		}
	}
}

/// Type of node in the trie and essential information thereof.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Node<'a> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleSlice<'a>, Value<'a>),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleSlice<'a>, NodeHandle<'a>),
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch([Option<NodeHandle<'a>>; nibble_ops::NIBBLE_LENGTH], Option<Value<'a>>),
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch(
		NibbleSlice<'a>,
		[Option<NodeHandle<'a>>; nibble_ops::NIBBLE_LENGTH],
		Option<Value<'a>>,
	),
}

impl Node<'_> {
	/// Converts this node into a [`NodeOwned`].
	pub fn to_owned_node<L: TrieLayout>(
		&self,
	) -> Result<NodeOwned<TrieHash<L>>, TrieHash<L>, CError<L>> {
		match self {
			Self::Empty => Ok(NodeOwned::Empty),
			Self::Leaf(n, d) => Ok(NodeOwned::Leaf((*n).into(), d.to_owned_value::<L>())),
			Self::Extension(n, h) =>
				Ok(NodeOwned::Extension((*n).into(), h.to_owned_handle::<L>()?)),
			Self::Branch(childs, data) => Ok(NodeOwned::Branch(
				ChildrenNodesOwned::from_handles::<L>(childs)?,
				data.as_ref().map(|d| d.to_owned_value::<L>()),
			)),
			Self::NibbledBranch(n, childs, data) => Ok(NodeOwned::NibbledBranch(
				(*n).into(),
				ChildrenNodesOwned::from_handles::<L>(childs)?,
				data.as_ref().map(|d| d.to_owned_value::<L>()),
			)),
		}
	}
}

/// Owned version of [`Node`].
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum NodeOwned<H> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleVec, ValueOwned<H>),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleVec, NodeHandleOwned<H>),
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch(ChildrenNodesOwned<H>, Option<ValueOwned<H>>),
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch(NibbleVec, ChildrenNodesOwned<H>, Option<ValueOwned<H>>),
	/// Node that represents a value.
	///
	/// This variant is only constructed when working with a [`crate::TrieCache`]. It is only
	/// used to cache a raw value.
	Value(Bytes, H),
}

/// Owned children of a node.
///
/// Only the existing children are stored, in nibble order; `slots` maps a nibble to its child.
/// A branch with children at nibbles 0 and 15 pays for two slots, not sixteen, which is what
/// keeps sparse branches cheap in the `TrieCache`.
///
/// The fields stay private so that every access goes through the nibble-indexed API.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub struct ChildrenNodesOwned<H> {
	/// The existing children, by ascending nibble. Every slot is `Some`: the `Option` costs no
	/// space (niche) and lets [`Self::iter`] hand out `&Option<_>`.
	///
	/// A boxed slice rather than a `Vec`: no spare capacity, so [`Self::heap_size`] is exact.
	present: Box<[Option<NodeHandleOwned<H>>]>,
	/// Four bits per nibble: the position in `present` of that nibble's child, [`NO_CHILD`] if
	/// it has none.
	///
	/// `NO_CHILD` needs no flag of its own: it is only stored when a child is missing, and
	/// `present` is then too short for it to be a position. A lookup is thus a shift and a
	/// bounds-checked read, with no population count (slow on baseline x86-64).
	slots: u64,
}

/// The [`ChildrenNodesOwned::slots`] entry of a nibble without a child.
const NO_CHILD: u64 = 0xf;
/// Width in bits of a [`ChildrenNodesOwned::slots`] entry.
const SLOT_BITS: usize = 4;

// `slots` holds one entry per nibble, and `NO_CHILD` is the last position of a full branch.
const _: () = assert!(nibble_ops::NIBBLE_LENGTH * SLOT_BITS == u64::BITS as usize);
const _: () = assert!(NO_CHILD as usize == nibble_ops::NIBBLE_LENGTH - 1);

impl<H> ChildrenNodesOwned<H> {
	/// Converts the children of a [`Node`] into their owned version.
	fn from_handles<L>(
		childs: &[Option<NodeHandle<'_>>; nibble_ops::NIBBLE_LENGTH],
	) -> Result<Self, H, CError<L>>
	where
		L: TrieLayout,
		L::Hash: Hasher<Out = H>,
	{
		let mut slots = u64::MAX;
		let mut position = 0;
		let mut present = Vec::with_capacity(childs.iter().flatten().count());
		for (nibble, child) in childs.iter().enumerate() {
			if let Some(child) = child {
				// Clears the bits `NO_CHILD` and `position` differ in.
				slots ^= (NO_CHILD ^ position) << (nibble * SLOT_BITS);
				position += 1;
				present.push(Some(child.to_owned_handle::<L>()?));
			}
		}
		Ok(Self { present: present.into_boxed_slice(), slots })
	}

	/// The slot of the child at nibble `index`, if it exists.
	fn slot(&self, index: usize) -> Option<&Option<NodeHandleOwned<H>>> {
		if index >= nibble_ops::NIBBLE_LENGTH {
			return None
		}
		// At most 15: lossless.
		let position = ((self.slots >> (index * SLOT_BITS)) & NO_CHILD) as usize;
		self.present.get(position)
	}

	/// Returns the child at the given index.
	pub fn get(&self, index: usize) -> Option<&NodeHandleOwned<H>> {
		self.slot(index).and_then(Option::as_ref)
	}

	/// Returns an iterator over all children.
	///
	/// The size of the iterator is always constant goes up to `nibble_ops::NIBBLE_LENGTH`, with
	/// None representing the missing children.
	pub fn iter(&self) -> impl Iterator<Item = &Option<NodeHandleOwned<H>>> {
		(0..nibble_ops::NIBBLE_LENGTH).map(move |index| self.slot(index).unwrap_or(&None))
	}

	/// Returns one past the index of the last existing child: [`Self::get`] is `None` from here
	/// on.
	pub fn allocated_len(&self) -> usize {
		let last = (0..nibble_ops::NIBBLE_LENGTH).rev().find(|i| self.slot(*i).is_some());
		last.map_or(0, |i| i + 1)
	}

	/// Returns the existing children with their nibble, by ascending nibble.
	fn existing(&self) -> impl Iterator<Item = (u8, &NodeHandleOwned<H>)> {
		(0u8..).zip(self.iter()).filter_map(|(i, child)| Some((i, child.as_ref()?)))
	}

	/// Returns the bytes this holds on the heap, inline child nodes included.
	fn heap_size(&self) -> usize {
		// A child that isn't an inline node lives entirely in its slot.
		let inline = self.present.iter().flatten().filter_map(NodeHandleOwned::as_inline);
		mem::size_of_val(&*self.present) + inline.map(NodeOwned::size_in_bytes).sum::<usize>()
	}
}

impl<H> NodeOwned<H>
where
	H: Default + AsRef<[u8]> + AsMut<[u8]> + Copy,
{
	/// Convert to its encoded format.
	pub fn to_encoded<C>(&self) -> Vec<u8>
	where
		C: NodeCodec<HashOut = H>,
	{
		match self {
			Self::Empty => C::empty_node().to_vec(),
			Self::Leaf(partial, value) =>
				C::leaf_node(partial.right_iter(), partial.len(), value.as_value()),
			Self::Extension(partial, child) => C::extension_node(
				partial.right_iter(),
				partial.len(),
				child.as_child_reference::<C>(),
			),
			Self::Branch(children, value) => C::branch_node(
				children.iter().map(|child| child.as_ref().map(|c| c.as_child_reference::<C>())),
				value.as_ref().map(|v| v.as_value()),
			),
			Self::NibbledBranch(partial, children, value) => C::branch_node_nibbled(
				partial.right_iter(),
				partial.len(),
				children.iter().map(|child| child.as_ref().map(|c| c.as_child_reference::<C>())),
				value.as_ref().map(|v| v.as_value()),
			),
			Self::Value(data, _) => data.to_vec(),
		}
	}

	/// Returns an iterator over all existing children with their optional nibble.
	pub fn child_iter(&self) -> impl Iterator<Item = (Option<u8>, &NodeHandleOwned<H>)> {
		let (single, children) = match self {
			Self::Leaf(_, _) | Self::Empty | Self::Value(_, _) => (None, None),
			Self::Extension(_, child) => (Some(child), None),
			Self::Branch(children, _) | Self::NibbledBranch(_, children, _) =>
				(None, Some(children)),
		};
		let single = single.into_iter().map(|child| (None, child));
		let children = children.into_iter().flat_map(ChildrenNodesOwned::existing);
		single.chain(children.map(|(nibble, child)| (Some(nibble), child)))
	}

	/// Returns the hash of the data attached to this node.
	pub fn data_hash(&self) -> Option<H> {
		match &self {
			Self::Empty => None,
			Self::Leaf(_, value) => value.data_hash(),
			Self::Extension(_, _) => None,
			Self::Branch(_, value) => value.as_ref().and_then(|v| v.data_hash()),
			Self::NibbledBranch(_, _, value) => value.as_ref().and_then(|v| v.data_hash()),
			Self::Value(_, hash) => Some(*hash),
		}
	}
}

impl<H> NodeOwned<H> {
	/// Returns the data attached to this node.
	pub fn data(&self) -> Option<&Bytes> {
		match &self {
			Self::Empty => None,
			Self::Leaf(_, value) => value.data(),
			Self::Extension(_, _) => None,
			Self::Branch(_, value) => value.as_ref().and_then(|v| v.data()),
			Self::NibbledBranch(_, _, value) => value.as_ref().and_then(|v| v.data()),
			Self::Value(data, _) => Some(data),
		}
	}

	/// Returns the partial key of this node.
	pub fn partial_key(&self) -> Option<&NibbleVec> {
		match self {
			Self::Branch(_, _) | Self::Value(_, _) | Self::Empty => None,
			Self::Extension(partial, _) |
			Self::Leaf(partial, _) |
			Self::NibbledBranch(partial, _, _) => Some(partial),
		}
	}

	/// Returns the size in bytes of this node in memory.
	///
	/// This also includes the size of any inline child nodes.
	pub fn size_in_bytes(&self) -> usize {
		let self_size = mem::size_of::<Self>();

		// As `self_size` only represents the static size of `Self`, we also need
		// to add the size of any dynamically allocated data.
		let dynamic_size = match self {
			Self::Empty => 0,
			Self::Leaf(nibbles, value) =>
				nibbles.inner().len() + value.data().map_or(0, |b| b.len()),
			Self::Value(bytes, _) => bytes.len(),
			Self::Extension(nibbles, child) => {
				// If the `child` isn't an inline node, its size is already taken account for by
				// `self_size`.
				nibbles.inner().len() + child.as_inline().map_or(0, |n| n.size_in_bytes())
			},
			Self::Branch(childs, value) =>
				childs.heap_size() + value.as_ref().and_then(|v| v.data()).map_or(0, |b| b.len()),
			Self::NibbledBranch(nibbles, childs, value) =>
				nibbles.inner().len() +
					childs.heap_size() +
					value.as_ref().and_then(|v| v.data()).map_or(0, |b| b.len()),
		};

		self_size + dynamic_size
	}
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
		NibbleSlicePlan { bytes, offset }
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

/// Plan for value representation in `NodePlan`.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ValuePlan {
	/// Range for byte representation in encoded node.
	Inline(Range<usize>),
	/// Range for hash in encoded node and original
	/// value size.
	Node(Range<usize>),
}

impl ValuePlan {
	/// Build a value slice by decoding a byte slice according to the plan.
	pub fn build<'a, 'b>(&'a self, data: &'b [u8]) -> Value<'b> {
		match self {
			ValuePlan::Inline(range) => Value::Inline(&data[range.clone()]),
			ValuePlan::Node(range) => Value::Node(&data[range.clone()]),
		}
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
	Leaf { partial: NibbleSlicePlan, value: ValuePlan },
	/// Extension node; has a partial key plan and child data.
	Extension { partial: NibbleSlicePlan, child: NodeHandlePlan },
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch {
		value: Option<ValuePlan>,
		children: [Option<NodeHandlePlan>; nibble_ops::NIBBLE_LENGTH],
	},
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch {
		partial: NibbleSlicePlan,
		value: Option<ValuePlan>,
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
			NodePlan::Leaf { partial, value } => Node::Leaf(partial.build(data), value.build(data)),
			NodePlan::Extension { partial, child } =>
				Node::Extension(partial.build(data), child.build(data)),
			NodePlan::Branch { value, children } => {
				let mut child_slices = [None; nibble_ops::NIBBLE_LENGTH];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					child_slices[i] = children[i].as_ref().map(|child| child.build(data));
				}
				Node::Branch(child_slices, value.as_ref().map(|v| v.build(data)))
			},
			NodePlan::NibbledBranch { partial, value, children } => {
				let mut child_slices = [None; nibble_ops::NIBBLE_LENGTH];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					child_slices[i] = children[i].as_ref().map(|child| child.build(data));
				}
				Node::NibbledBranch(
					partial.build(data),
					child_slices,
					value.as_ref().map(|v| v.build(data)),
				)
			},
		}
	}

	/// Access value plan from node plan, return `None` for
	/// node that cannot contain a `ValuePlan`.
	pub fn value_plan(&self) -> Option<&ValuePlan> {
		match self {
			NodePlan::Extension { .. } | NodePlan::Empty => None,
			NodePlan::Leaf { value, .. } => Some(value),
			NodePlan::Branch { value, .. } | NodePlan::NibbledBranch { value, .. } =>
				value.as_ref(),
		}
	}

	/// Mutable ccess value plan from node plan, return `None` for
	/// node that cannot contain a `ValuePlan`.
	pub fn value_plan_mut(&mut self) -> Option<&mut ValuePlan> {
		match self {
			NodePlan::Extension { .. } | NodePlan::Empty => None,
			NodePlan::Leaf { value, .. } => Some(value),
			NodePlan::Branch { value, .. } | NodePlan::NibbledBranch { value, .. } =>
				value.as_mut(),
		}
	}
}

/// An `OwnedNode` is an owned type from which a `Node` can be constructed which borrows data from
/// the `OwnedNode`. This is useful for trie iterators.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq)]
pub struct OwnedNode<D: Borrow<[u8]>> {
	data: D,
	plan: NodePlan,
}

impl<D: Borrow<[u8]>> OwnedNode<D> {
	/// Construct an `OwnedNode` by decoding an owned data source according to some codec.
	pub fn new<C: NodeCodec>(data: D) -> core::result::Result<Self, C::Error> {
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

	/// Returns a mutable reference to the node decode plan.
	pub fn node_plan_mut(&mut self) -> &mut NodePlan {
		&mut self.plan
	}

	/// Construct a `Node` by borrowing data from this struct.
	pub fn node(&self) -> Node<'_> {
		self.plan.build(self.data.borrow())
	}
}

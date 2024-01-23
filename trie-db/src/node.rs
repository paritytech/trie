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
	node_db::Hasher,
	Bytes, CError, ChildReference, Result, TrieError, TrieHash, TrieLayout,
};
#[cfg(not(feature = "std"))]
use alloc::{boxed::Box, vec::Vec};

use crate::rstd::{borrow::Borrow, mem, ops::Range};

/// Partial node key type: offset and owned value of a nibbleslice.
/// Offset is applied on first byte of array (bytes are right aligned).
pub type NodeKey = (usize, nibble::BackingByteVec);

/// A reference to a trie node which may be stored within another trie node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NodeHandle<'a, L> {
	Hash(&'a [u8], L),
	Inline(&'a [u8]),
}

impl<'a, L: Copy + Default> NodeHandle<'a, L> {
	/// Converts this node handle into a [`NodeHandleOwned`].
	pub fn to_owned_handle<TL: TrieLayout>(
		&self,
	) -> Result<NodeHandleOwned<TrieHash<TL>, TL::Location>, TrieHash<TL>, CError<TL>>
	where
		TL::Location: From<L>,
	{
		match self {
			Self::Hash(h, l) => decode_hash::<TL::Hash>(h)
				.ok_or_else(|| Box::new(TrieError::InvalidHash(Default::default(), h.to_vec())))
				.map(|h| NodeHandleOwned::Hash(h, (*l).into())),
			Self::Inline(i) => match TL::Codec::decode(i, &[] as &[L]) {
				Ok(node) => Ok(NodeHandleOwned::Inline(Box::new(node.to_owned_node::<TL>()?))),
				Err(e) => Err(Box::new(TrieError::DecoderError(Default::default(), e))),
			},
		}
	}
}

/// Owned version of [`NodeHandleOwned`].
#[derive(Clone, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum NodeHandleOwned<H, L> {
	Hash(H, L),
	Inline(Box<NodeOwned<H, L>>),
}

impl<H, L> NodeHandleOwned<H, L>
where
	H: Default + AsRef<[u8]> + AsMut<[u8]> + Copy,
	L: Default + Copy,
{
	/// Returns `self` as a [`ChildReference`].
	///
	/// # Panic
	///
	/// This function panics if `self == Self::Inline(_)` and the inline node encoded length is
	/// greater then the length of the hash.
	fn as_child_reference<C: NodeCodec<HashOut = H>>(&self) -> ChildReference<H, L> {
		match self {
			NodeHandleOwned::Hash(h, l) => ChildReference::Hash(*h, *l),
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

impl<H, L> NodeHandleOwned<H, L> {
	/// Returns `self` as inline node.
	pub fn as_inline(&self) -> Option<&NodeOwned<H, L>> {
		match self {
			Self::Hash(_, _) => None,
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
pub enum Value<'a, L> {
	/// Value byte slice as stored in a trie node.
	Inline(&'a [u8]),
	/// Hash byte slice as stored in a trie node.
	Node(&'a [u8], L),
}

impl<'a, L: Copy + Default> Value<'a, L> {
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

	pub fn to_owned_value<TL: TrieLayout>(&self) -> ValueOwned<TrieHash<TL>, TL::Location>
	where
		TL::Location: From<L>,
	{
		match self {
			Self::Inline(data) => ValueOwned::Inline(Bytes::from(*data), TL::Hash::hash(data)),
			Self::Node(hash, l) => {
				let mut res = TrieHash::<TL>::default();
				res.as_mut().copy_from_slice(hash);

				ValueOwned::Node(res, (*l).into())
			},
		}
	}
}

/// Owned value representation in `Node`.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ValueOwned<H, L> {
	/// Value bytes as stored in a trie node and its hash.
	Inline(Bytes, H),
	/// Hash byte slice as stored in a trie node.
	Node(H, L),
}

impl<H: AsRef<[u8]> + Copy, L: Copy + Default> ValueOwned<H, L> {
	/// Returns self as [`Value`].
	pub fn as_value(&self) -> Value<L> {
		match self {
			Self::Inline(data, _) => Value::Inline(&data),
			Self::Node(hash, location) => Value::Node(hash.as_ref(), *location),
		}
	}

	/// Returns the hash of the data stored in self.
	pub fn data_hash(&self) -> Option<H> {
		match self {
			Self::Inline(_, hash) => Some(*hash),
			Self::Node(hash, _) => Some(*hash),
		}
	}
}

impl<H, L> ValueOwned<H, L> {
	/// Returns the data stored in self.
	pub fn data(&self) -> Option<&Bytes> {
		match self {
			Self::Inline(data, _) => Some(data),
			Self::Node(_, _) => None,
		}
	}
}

/// Type of node in the trie and essential information thereof.
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Node<'a, L> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleSlice<'a>, Value<'a, L>),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleSlice<'a>, NodeHandle<'a, L>),
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch([Option<NodeHandle<'a, L>>; nibble_ops::NIBBLE_LENGTH], Option<Value<'a, L>>),
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch(
		NibbleSlice<'a>,
		[Option<NodeHandle<'a, L>>; nibble_ops::NIBBLE_LENGTH],
		Option<Value<'a, L>>,
	),
}

impl<Location> Node<'_, Location> {
	/// Converts this node into a [`NodeOwned`].
	pub fn to_owned_node<L: TrieLayout>(
		&self,
	) -> Result<NodeOwned<TrieHash<L>, L::Location>, TrieHash<L>, CError<L>>
	where
		L::Location: From<Location>,
		Location: Copy + Default,
	{
		match self {
			Self::Empty => Ok(NodeOwned::Empty),
			Self::Leaf(n, d) => Ok(NodeOwned::Leaf((*n).into(), d.to_owned_value::<L>())),
			Self::Extension(n, h) =>
				Ok(NodeOwned::Extension((*n).into(), h.to_owned_handle::<L>()?)),
			Self::Branch(childs, data) => {
				let mut childs_owned = [(); nibble_ops::NIBBLE_LENGTH].map(|_| None);
				childs
					.iter()
					.enumerate()
					.map(|(i, c)| {
						childs_owned[i] =
							c.as_ref().map(|c| c.to_owned_handle::<L>()).transpose()?;
						Ok(())
					})
					.collect::<Result<_, _, _>>()?;

				Ok(NodeOwned::Branch(childs_owned, data.as_ref().map(|d| d.to_owned_value::<L>())))
			},
			Self::NibbledBranch(n, childs, data) => {
				let mut childs_owned = [(); nibble_ops::NIBBLE_LENGTH].map(|_| None);
				childs
					.iter()
					.enumerate()
					.map(|(i, c)| {
						childs_owned[i] =
							c.as_ref().map(|c| c.to_owned_handle::<L>()).transpose()?;
						Ok(())
					})
					.collect::<Result<_, _, _>>()?;

				Ok(NodeOwned::NibbledBranch(
					(*n).into(),
					childs_owned,
					data.as_ref().map(|d| d.to_owned_value::<L>()),
				))
			},
		}
	}
}

/// Owned version of [`Node`].
#[derive(Eq, PartialEq, Clone)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum NodeOwned<H, L> {
	/// Null trie node; could be an empty root or an empty branch entry.
	Empty,
	/// Leaf node; has key slice and value. Value may not be empty.
	Leaf(NibbleVec, ValueOwned<H, L>),
	/// Extension node; has key slice and node data. Data may not be null.
	Extension(NibbleVec, NodeHandleOwned<H, L>),
	/// Branch node; has slice of child nodes (each possibly null)
	/// and an optional immediate node data.
	Branch([Option<NodeHandleOwned<H, L>>; nibble_ops::NIBBLE_LENGTH], Option<ValueOwned<H, L>>),
	/// Branch node with support for a nibble (when extension nodes are not used).
	NibbledBranch(
		NibbleVec,
		[Option<NodeHandleOwned<H, L>>; nibble_ops::NIBBLE_LENGTH],
		Option<ValueOwned<H, L>>,
	),
	/// Node that represents a value.
	///
	/// This variant is only constructed when working with a [`crate::TrieCache`]. It is only
	/// used to cache a raw value.
	Value(Bytes, H),
}

impl<H, L: Copy + Default> NodeOwned<H, L>
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
	pub fn child_iter(&self) -> impl Iterator<Item = (Option<u8>, &NodeHandleOwned<H, L>)> {
		enum ChildIter<'a, H, L> {
			Empty,
			Single(&'a NodeHandleOwned<H, L>, bool),
			Array(&'a [Option<NodeHandleOwned<H, L>>; nibble_ops::NIBBLE_LENGTH], usize),
		}

		impl<'a, H, L> Iterator for ChildIter<'a, H, L> {
			type Item = (Option<u8>, &'a NodeHandleOwned<H, L>);

			fn next(&mut self) -> Option<Self::Item> {
				loop {
					match self {
						Self::Empty => break None,
						Self::Single(child, returned) =>
							break if *returned {
								None
							} else {
								*returned = true;
								Some((None, child))
							},
						Self::Array(childs, index) =>
							if *index >= childs.len() {
								break None
							} else {
								*index += 1;

								// Ignore non-existing childs.
								if let Some(ref child) = childs[*index - 1] {
									break Some((Some(*index as u8 - 1), child))
								}
							},
					}
				}
			}
		}

		match self {
			Self::Leaf(_, _) | Self::Empty | Self::Value(_, _) => ChildIter::Empty,
			Self::Extension(_, child) => ChildIter::Single(child, false),
			Self::Branch(children, _) | Self::NibbledBranch(_, children, _) =>
				ChildIter::Array(children, 0),
		}
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

impl<H, L> NodeOwned<H, L> {
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

		fn childs_size<'a, H: 'a, L: 'a>(
			childs: impl Iterator<Item = &'a Option<NodeHandleOwned<H, L>>>,
		) -> usize {
			// If a `child` isn't an inline node, its size is already taken account for by
			// `self_size`.
			childs
				.filter_map(|c| c.as_ref())
				.map(|c| c.as_inline().map_or(0, |n| n.size_in_bytes()))
				.sum()
		}

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
				childs_size(childs.iter()) +
					value.as_ref().and_then(|v| v.data()).map_or(0, |b| b.len()),
			Self::NibbledBranch(nibbles, childs, value) =>
				nibbles.inner().len() +
					childs_size(childs.iter()) +
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
	pub fn build<'a, 'b, L>(&'a self, data: &'b [u8], location: L) -> NodeHandle<'b, L> {
		match self {
			NodeHandlePlan::Hash(range) => NodeHandle::Hash(&data[range.clone()], location),
			NodeHandlePlan::Inline(range) => NodeHandle::Inline(&data[range.clone()]),
		}
	}

	/// Check if the node is innline.
	pub fn is_inline(&self) -> bool {
		match self {
			NodeHandlePlan::Hash(_) => false,
			NodeHandlePlan::Inline(_) => true,
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
	pub fn build<'a, 'b, L>(&'a self, data: &'b [u8], location: L) -> Value<'b, L> {
		match self {
			ValuePlan::Inline(range) => Value::Inline(&data[range.clone()]),
			ValuePlan::Node(range) => Value::Node(&data[range.clone()], location),
		}
	}

	/// Check if the value is inline.
	pub fn is_inline(&self) -> bool {
		match self {
			ValuePlan::Inline(_) => true,
			ValuePlan::Node(_) => false,
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
	/// Build a node by decoding a byte slice according to the node plan and attaching location
	/// dats. It is the responsibility of the caller to ensure that the node plan was created for
	/// the argument data, otherwise the call may decode incorrectly or panic.
	pub fn build<'a, 'b, L: Copy + Default>(
		&'a self,
		data: &'b [u8],
		locations: &[L],
	) -> Node<'b, L> {
		match self {
			NodePlan::Empty => Node::Empty,
			NodePlan::Leaf { partial, value } => Node::Leaf(
				partial.build(data),
				value.build(data, locations.first().copied().unwrap_or_default()),
			),
			NodePlan::Extension { partial, child } => Node::Extension(
				partial.build(data),
				child.build(data, locations.first().copied().unwrap_or_default()),
			),
			NodePlan::Branch { value, children } => {
				let (value, child_slices) =
					Self::build_value_and_children(value.as_ref(), children, data, locations);
				Node::Branch(child_slices, value)
			},
			NodePlan::NibbledBranch { partial, value, children } => {
				let (value, child_slices) =
					Self::build_value_and_children(value.as_ref(), children, data, locations);
				Node::NibbledBranch(partial.build(data), child_slices, value)
			},
		}
	}

	pub(crate) fn build_value_and_children<'a, 'b, L: Copy + Default>(
		value: Option<&'a ValuePlan>,
		children: &'a [Option<NodeHandlePlan>; nibble_ops::NIBBLE_LENGTH],
		data: &'b [u8],
		locations: &[L],
	) -> (Option<Value<'b, L>>, [Option<NodeHandle<'b, L>>; nibble_ops::NIBBLE_LENGTH]) {
		let mut child_slices = [None; nibble_ops::NIBBLE_LENGTH];
		let mut nc = 0;
		let value = if let Some(v) = value {
			if v.is_inline() {
				Some(v.build(data, Default::default()))
			} else {
				nc += 1;
				Some(v.build(data, locations.first().copied().unwrap_or_default()))
			}
		} else {
			None
		};
		for i in 0..nibble_ops::NIBBLE_LENGTH {
			if let Some(child) = &children[i] {
				let location = if child.is_inline() {
					Default::default()
				} else {
					let l = locations.get(nc).copied().unwrap_or_default();
					nc += 1;
					l
				};
				child_slices[i] = Some(child.build(data, location));
			}
		}
		(value, child_slices)
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

	/// Check if the node has a location for value.
	pub fn has_location_for_value(&self) -> bool {
		self.value_plan().map(|v| !v.is_inline()).unwrap_or(false)
	}

	/// Check how many children location value node has.
	pub fn num_children_locations(&self) -> usize {
		match self {
			NodePlan::Extension { child: NodeHandlePlan::Hash(_), .. } => 1,
			NodePlan::Branch { children, .. } | NodePlan::NibbledBranch { children, .. } => {
				let mut count = 0;
				for child in children {
					if let Some(NodeHandlePlan::Hash(_)) = child {
						count += 1;
					}
				}
				count
			},
			_ => 0,
		}
	}

	pub fn additional_ref_location<L: Copy + Default>(&self, locations: &[L]) -> Option<L> {
		let offset =
			if self.has_location_for_value() { 1 } else { 0 } + self.num_children_locations();
		if locations.len() > offset {
			// only one additional location expected with current code.
			debug_assert!(locations.len() == offset + 1);
			Some(locations[offset])
		} else {
			None
		}
	}
}

/// An `OwnedNode` is an owned type from which a `Node` can be constructed which borrows data from
/// the `OwnedNode`. This is useful for trie iterators.
#[cfg_attr(feature = "std", derive(Debug))]
#[derive(PartialEq, Eq)]
pub struct OwnedNode<D: Borrow<[u8]>, L> {
	data: D,
	plan: NodePlan,
	locations: Vec<L>,
}

impl<D: Borrow<[u8]>, L: Default + Copy> OwnedNode<D, L> {
	/// Construct an `OwnedNode` by decoding an owned data source according to some codec.
	pub fn new<C: NodeCodec>(data: D, locations: Vec<L>) -> core::result::Result<Self, C::Error> {
		let plan = C::decode_plan(data.borrow())?;
		Ok(OwnedNode { data, plan, locations })
	}

	/// Returns a reference to the backing data.
	pub fn data(&self) -> &[u8] {
		self.data.borrow()
	}

	/// Returns a reference to children locations.
	pub fn locations(&self) -> &[L] {
		&self.locations
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
	pub fn node(&self) -> Node<L> {
		self.plan.build(self.data.borrow(), &self.locations)
	}
}

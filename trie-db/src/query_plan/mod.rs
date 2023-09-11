// Copyright 2023, 2023 Parity Technologies
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

//! Iterate on multiple values following a specific query plan.
//! Can be use on a trie db to register a proof, or
//! be use on a proof directly.
//! When use on a proof, process can be interrupted, checked and
//! restore (at the cost of additional hashes in proof).
//!
//! Because nodes are guaranted to be accessed only once and recorded
//! in proof, we do not use a cache (or only the node caching part).

use core::marker::PhantomData;

use crate::{
	nibble::{nibble_ops, nibble_ops::NIBBLE_LENGTH, LeftNibbleSlice, NibbleSlice},
	node::{NodeHandle, NodePlan, OwnedNode, Value},
	node_codec::NodeCodec,
	rstd::{
		borrow::{Borrow, Cow},
		boxed::Box,
		cmp::*,
		convert::{TryFrom, TryInto},
		result::Result,
		vec,
		vec::Vec,
	},
	CError, ChildReference, DBValue, NibbleVec, Trie, TrieDB, TrieHash, TrieLayout,
};
use hash_db::Hasher;
pub use record::{record_query_plan, HaltedStateRecord, Recorder};
pub use verify::{verify_query_plan_iter, HaltedStateCheck};

mod record;
mod verify;

/// Errors that may occur during proof verification. Most of the errors types simply indicate that
/// the proof is invalid with respect to the statement being verified, and the exact error type can
/// be used for debugging.
#[derive(PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Error<HO, CE> {
	/// The statement being verified contains multiple key-value pairs with the same key. The
	/// parameter is the duplicated key.
	DuplicateKey(Vec<u8>),
	/// The statement being verified contains key not ordered properly.
	UnorderedKey(Vec<u8>),
	/// The proof contains at least one extraneous node.
	ExtraneousNode,
	/// The proof contains at least one extraneous value which should have been omitted from the
	/// proof.
	ExtraneousValue(Vec<u8>),
	/// The proof contains at least one extraneous hash reference the should have been omitted.
	ExtraneousHashReference(HO),
	/// The proof contains an invalid child reference that exceeds the hash length.
	/// TODO extension only?
	InvalidChildReference(Vec<u8>),
	/// The proof is missing trie nodes required to verify.
	IncompleteProof,
	/// Item missing in backend when recording.
	IncompleteDB(HO),
	/// The root hash computed from the proof is incorrect.
	RootMismatch(HO),
	/// The hash computed from a node is incorrect.
	HashMismatch(HO),
	/// One of the proof nodes could not be decoded.
	DecodeError(CE),
	/// Node does not match existing handle.
	/// This should not happen.
	InvalidNodeHandle(Vec<u8>),
	/// Node type in proof inconsistent with node ordering.
	UnexpectedNodeType,
}

#[cfg(feature = "std")]
impl<HO: std::fmt::Debug, CE: std::error::Error> std::fmt::Display for Error<HO, CE> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		match self {
			Error::DuplicateKey(key) =>
				write!(f, "Duplicate key in input statement: key={:?}", key),
			Error::UnorderedKey(key) =>
				write!(f, "Unordered key in input statement: key={:?}", key),
			Error::ExtraneousNode => write!(f, "Extraneous node found in proof"),
			Error::ExtraneousValue(key) =>
				write!(f, "Extraneous value found in proof should have been omitted: key={:?}", key),
			Error::ExtraneousHashReference(hash) => write!(
				f,
				"Extraneous hash reference found in proof should have been omitted: hash={:?}",
				hash
			),
			Error::InvalidChildReference(data) =>
				write!(f, "Invalid child reference exceeds hash length: {:?}", data),
			Error::IncompleteProof => write!(f, "Proof is incomplete -- expected more nodes"),
			Error::IncompleteDB(hash) => write!(f, "Missing node in db: {:?}", hash),
			Error::RootMismatch(hash) => write!(f, "Computed incorrect root {:?} from proof", hash),
			Error::HashMismatch(hash) => write!(f, "Computed incorrect hash {:?} from node", hash),
			Error::DecodeError(err) => write!(f, "Unable to decode proof node: {}", err),
			Error::InvalidNodeHandle(node) => write!(f, "Invalid node handle: {:?}", node),
			Error::UnexpectedNodeType =>
				write!(f, "Node type in proof inconsistent with node ordering."),
		}
	}
}

#[cfg(feature = "std")]
impl<HO: std::fmt::Debug, CE: std::error::Error + 'static> std::error::Error for Error<HO, CE> {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Error::DecodeError(err) => Some(err),
			_ => None,
		}
	}
}

/// Item to query, in memory.
#[derive(Default, Clone, Debug)]
pub struct QueryPlanItem {
	key: Vec<u8>,
	hash_only: bool,
	as_prefix: bool,
}

impl QueryPlanItem {
	/// Create new item.
	pub fn new(key: Vec<u8>, hash_only: bool, as_prefix: bool) -> Self {
		Self { key, hash_only, as_prefix }
	}
	/// Get ref.
	pub fn as_ref(&self) -> QueryPlanItemRef {
		QueryPlanItemRef { key: &self.key, hash_only: self.hash_only, as_prefix: self.as_prefix }
	}
}

/// Item to query.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct QueryPlanItemRef<'a> {
	pub key: &'a [u8],
	pub hash_only: bool,
	pub as_prefix: bool,
}

impl<'a> QueryPlanItemRef<'a> {
	fn before(&self, other: &Self) -> (bool, usize) {
		let (common_depth, ordering) = nibble_ops::biggest_depth_and_order(&self.key, &other.key);

		(
			match ordering {
				Ordering::Less => {
					if self.as_prefix {
						// do not allow querying content inside a prefix
						!other.key.starts_with(self.key)
					} else {
						true
					}
				},
				Ordering::Greater | Ordering::Equal => false,
			},
			common_depth,
		)
	}

	fn to_owned(&self) -> QueryPlanItem {
		QueryPlanItem {
			key: self.key.to_vec(),
			hash_only: self.hash_only,
			as_prefix: self.as_prefix,
		}
	}
}

/// Query plan in memory.
#[derive(Clone, Debug)]
pub struct InMemQueryPlan {
	pub items: Vec<QueryPlanItem>,
	pub kind: ProofKind,
}

/// Iterator as type of mapped slice iter is very noisy.
pub struct QueryPlanItemIter<'a>(&'a Vec<QueryPlanItem>, usize);

impl<'a> Iterator for QueryPlanItemIter<'a> {
	type Item = QueryPlanItemRef<'a>;

	fn next(&mut self) -> Option<Self::Item> {
		if self.1 >= self.0.len() {
			return None
		}
		self.1 += 1;
		Some(self.0[self.1 - 1].as_ref())
	}
}

impl InMemQueryPlan {
	/// Get ref.
	pub fn as_ref(&self) -> QueryPlan<QueryPlanItemIter> {
		QueryPlan { items: QueryPlanItemIter(&self.items, 0), kind: self.kind, _ph: PhantomData }
	}
}

/// Query plan.
pub struct QueryPlan<'a, I> {
	pub items: I,
	pub kind: ProofKind,
	pub _ph: PhantomData<&'a ()>,
}

/// Different proof support.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum ProofKind {
	/// Proof is a sequence of fully encoded node, this is not
	/// size efficient but allows streaming a proof better, since
	/// the consumer can halt at the first invalid node.
	FullNodes,

	/// Proof got its accessed hash and value removed (same scheme
	/// as in trie_codec.rs ordering is same as full node, from
	/// root and in lexicographic order).
	///
	/// Checking this proof requires to read it fully. When stopping
	/// recording, the partial proof stays valid, but it will
	/// contains hashes that would not be needed if creating the
	/// proof at once.
	CompactNodes,
}

impl ProofKind {
	/// Check if compact variant of proof.
	pub fn is_compact(self) -> bool {
		matches!(self, ProofKind::CompactNodes)
	}
}

#[derive(Default, Clone, Copy)]
struct Bitmap(u16);

pub(crate) trait BitmapAccess: Copy {
	fn at(&self, i: usize) -> bool;
}

impl BitmapAccess for Bitmap {
	fn at(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}
}

impl<'a> BitmapAccess for &'a [bool] {
	fn at(&self, i: usize) -> bool {
		self[i]
	}
}

impl Bitmap {
	fn set(&mut self, i: usize, v: bool) {
		if v {
			self.0 |= 1u16 << i
		} else {
			self.0 &= !(1u16 << i)
		}
	}
}

#[derive(Clone)]
struct StackedNodeRecord {
	/// Node in memory content.
	node: OwnedNode<DBValue>,
	/// Flags indicating whether each child is omitted (accessed) in the encoded node.
	/// For some encoding, it also record if the child has already been written.
	accessed_children_node: Bitmap,
	/// Skip value if value node is after.
	accessed_value_node: bool,
	/// Depth of node in nibbles (actual depth of an attached value (post partial)).
	depth: usize,
	/// Next descended child, can also be use to get node position in parent
	/// (this minus one).
	next_descended_child: u8,
	/// Is the node inline.
	is_inline: bool,
}

/// Limits to size proof to record.
struct Limits {
	remaining_node: Option<usize>,
	remaining_size: Option<usize>,
	kind: ProofKind,
}

impl Limits {
	#[must_use]
	fn add_node(&mut self, size: usize, hash_size: usize, is_root: bool) -> bool {
		let mut res = false;
		match self.kind {
			ProofKind::CompactNodes | ProofKind::FullNodes => {
				if let Some(rem_size) = self.remaining_size.as_mut() {
					if let ProofKind::CompactNodes = self.kind {
						if !is_root {
							// remove a parent hash
							*rem_size += hash_size;
						}
					}
					if *rem_size >= size {
						*rem_size -= size;
					} else {
						*rem_size = 0;
						res = true;
					}
				}
				if let Some(rem_node) = self.remaining_node.as_mut() {
					if *rem_node > 1 {
						*rem_node -= 1;
					} else {
						*rem_node = 0;
						res = true;
					}
				}
			},
		}
		res
	}

	#[must_use]
	fn add_value(&mut self, size: usize, hash_size: usize) -> bool {
		let mut res = false;
		match self.kind {
			ProofKind::CompactNodes | ProofKind::FullNodes => {
				if let Some(rem_size) = self.remaining_size.as_mut() {
					if let ProofKind::CompactNodes = self.kind {
						// remove a parent value hash
						*rem_size += hash_size;
					}
					if *rem_size >= size {
						*rem_size -= size;
					} else {
						*rem_size = 0;
						res = true;
					}
				}
				if let Some(rem_node) = self.remaining_node.as_mut() {
					if *rem_node > 1 {
						*rem_node -= 1;
					} else {
						*rem_node = 0;
						res = true;
					}
				}
			},
		}
		res
	}
}

#[derive(Eq, PartialEq)]
enum TryStackChildResult {
	/// If there is no child to stack.
	NotStacked,
	/// Same indicating it is a branch so in case of iteration
	/// we will attempt next child.
	NotStackedBranch,
	/// Nothing stacked, this is a next child attempt that allows
	/// suspending proof registering of proof check iteration.
	Halted,
	/// Child stacked and matched of the full partial key.
	StackedFull,
	/// Child stacked but part of partial key is into.
	/// If prefix query plan item, this is part of the prefix.
	StackedInto,
	/// Child stacked but part of partial key is after.
	/// Indicate that the query plan item need to be switched.
	/// Next query plan item could still be using this stacked node (as any stacked variant).
	StackedAfter,
}

#[derive(Eq, PartialEq)]
enum ReadProofState {
	/// Iteration not started.
	NotStarted,
	/// Iterating.
	Running,
	/// Switch next item.
	SwitchQueryPlan,
	/// Proof read.
	PlanConsumed,
	/// Proof read.
	Halted,
	/// Iteration finished.
	Finished,
}

struct StackedNodeCheck<L: TrieLayout, D: SplitFirst> {
	node: ItemStackNode<D>,
	children: Vec<Option<ChildReference<TrieHash<L>>>>,
	attached_value_hash: Option<TrieHash<L>>,
	depth: usize,
	next_descended_child: u8,
}

impl<L: TrieLayout, D: SplitFirst> Clone for StackedNodeCheck<L, D> {
	fn clone(&self) -> Self {
		StackedNodeCheck {
			node: self.node.clone(),
			children: self.children.clone(),
			attached_value_hash: self.attached_value_hash,
			depth: self.depth,
			next_descended_child: self.next_descended_child,
		}
	}
}

#[derive(Clone)]
enum ItemStackNode<D: SplitFirst> {
	Inline(OwnedNode<Vec<u8>>),
	Node(OwnedNode<D>),
}

impl<L: TrieLayout, D: SplitFirst> TryFrom<(ItemStackNode<D>, ProofKind)>
	for StackedNodeCheck<L, D>
{
	type Error = Error<TrieHash<L>, CError<L>>;

	fn try_from(
		(node, kind): (ItemStackNode<D>, ProofKind),
	) -> crate::rstd::result::Result<Self, Self::Error> {
		let children = if !kind.is_compact() {
			Vec::new()
		} else {
			match &node {
				ItemStackNode::Inline(_) => Vec::new(),
				ItemStackNode::Node(node) => match node.node_plan() {
					NodePlan::Empty | NodePlan::Leaf { .. } => Vec::new(),
					NodePlan::Extension { child, .. } => {
						let mut result: Vec<Option<ChildReference<TrieHash<L>>>> = vec![None; 1];
						let node_data = node.data();
						match child.build(node_data) {
							NodeHandle::Inline(data) if data.is_empty() => (),
							child => {
								let child_ref =
									child.try_into().map_err(|d| Error::InvalidNodeHandle(d))?;
								result[0] = Some(child_ref);
							},
						}
						result
					},
					NodePlan::Branch { children, .. } |
					NodePlan::NibbledBranch { children, .. } => {
						let mut i = 0;
						let mut result: Vec<Option<ChildReference<TrieHash<L>>>> =
							vec![None; NIBBLE_LENGTH];
						let node_data = node.data();
						while i < NIBBLE_LENGTH {
							match children[i].as_ref().map(|c| c.build(node_data)) {
								Some(NodeHandle::Inline(data)) if data.is_empty() => (),
								Some(child) => {
									let child_ref = child
										.try_into()
										.map_err(|d| Error::InvalidNodeHandle(d))?;

									result[i] = Some(child_ref);
								},
								None => {},
							}
							i += 1;
						}
						result
					},
				},
			}
		};

		Ok(StackedNodeCheck {
			node,
			depth: 0,
			next_descended_child: 0,
			children,
			attached_value_hash: None,
		})
	}
}

impl<L: TrieLayout, D: SplitFirst> StackedNodeCheck<L, D> {
	fn data(&self) -> &[u8] {
		match &self.node {
			ItemStackNode::Inline(n) => n.data(),
			ItemStackNode::Node(n) => n.data(),
		}
	}

	fn node_plan(&self) -> &NodePlan {
		match &self.node {
			ItemStackNode::Inline(n) => n.node_plan(),
			ItemStackNode::Node(n) => n.node_plan(),
		}
	}
}

fn verify_hash<L: TrieLayout>(
	data: &[u8],
	expected: &[u8],
) -> Result<(), Error<TrieHash<L>, CError<L>>> {
	let checked_hash = L::Hash::hash(data);
	if checked_hash.as_ref() != expected {
		let mut error_hash = TrieHash::<L>::default();
		error_hash.as_mut().copy_from_slice(expected);
		Err(Error::HashMismatch(error_hash))
	} else {
		Ok(())
	}
}

/// Byte array where we can remove first item.
/// This is only needed for the ESCAPE_HEADER of COMPACT which
/// itself is not strictly needed (we can know if escaped from
/// query plan).
pub trait SplitFirst: Borrow<[u8]> + Clone {
	fn split_first(&mut self);
}

impl SplitFirst for Vec<u8> {
	fn split_first(&mut self) {
		*self = self.split_off(1);
	}
}

impl<'a> SplitFirst for &'a [u8] {
	fn split_first(&mut self) {
		*self = &self[1..];
	}
}

/// Content return on success when reading proof.
pub enum ReadProofItem<'a, L: TrieLayout, C, D: SplitFirst> {
	/// Successfull read of proof, not all content read.
	Halted(Box<HaltedStateCheck<'a, L, C, D>>),
	/// Seen value and key in proof.
	/// We only return content matching the query plan.
	Value(Cow<'a, [u8]>, Vec<u8>),
	/// Seen hash of value and key in proof.
	/// We only return content matching the query plan.
	Hash(Cow<'a, [u8]>, TrieHash<L>),
	/// No value seen for a key in the input query plan.
	NoValue(&'a [u8]),
	/// Seen fully covered prefix in proof, this is only
	/// return when we read the proof with the query input (otherwhise
	/// we would need to indicate every child without a hash as a prefix).
	StartPrefix(Vec<u8>),
	/// End of a previously start prefix.
	EndPrefix,
}

#[derive(Clone)]
struct InPrefix {
	start: usize,
	send_value: bool,
	hash_only: bool,
}

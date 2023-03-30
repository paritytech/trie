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
	nibble::{nibble_ops, LeftNibbleSlice, NibbleSlice},
	node::{NodeHandle, NodePlan, OwnedNode},
	proof::VerifyError,
	rstd::{cmp::*, result::Result},
	CError, DBValue, NibbleVec, Trie, TrieDB, TrieError, TrieHash, TrieLayout,
};

/// Item to query, in memory.
pub struct InMemQueryPlanItem {
	key: Vec<u8>,
	as_prefix: bool,
}

impl InMemQueryPlanItem {
	/// Create new item.
	pub fn new(key: Vec<u8>, as_prefix: bool) -> Self {
		Self { key, as_prefix }
	}
	/// Get ref.
	pub fn as_ref(&self) -> QueryPlanItem {
		QueryPlanItem { key: &self.key, as_prefix: self.as_prefix }
	}
}

/// Item to query.
pub struct QueryPlanItem<'a> {
	key: &'a [u8],
	as_prefix: bool,
}

impl<'a> QueryPlanItem<'a> {
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
}

/// Query plan in memory.
pub struct InMemQueryPlan {
	pub items: Vec<InMemQueryPlanItem>,
	pub current: Option<InMemQueryPlanItem>,
	pub ignore_unordered: bool,
}

/// Iterator as type of mapped slice iter is very noisy.
pub struct QueryPlanItemIter<'a>(&'a Vec<InMemQueryPlanItem>, usize);

impl<'a> Iterator for QueryPlanItemIter<'a> {
	type Item = QueryPlanItem<'a>;

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
		QueryPlan {
			items: QueryPlanItemIter(&self.items, 0),
			current: self.current.as_ref().map(|i| i.as_ref()),
			ignore_unordered: self.ignore_unordered,
		}
	}
}

/// Query plan.
pub struct QueryPlan<'a, I>
where
	I: Iterator<Item = QueryPlanItem<'a>>,
{
	items: I,
	current: Option<QueryPlanItem<'a>>,
	ignore_unordered: bool,
}

/// Different proof support.
#[derive(Clone, Copy, PartialEq, Eq)]
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

	/// Content oriented proof, no nodes are written, just a
	/// sequence of accessed by lexicographical order as described
	/// in compact_content_proof::Op.
	/// As with compact node, checking validity of proof need to
	/// load the full proof or up to the halt point.
	CompactContent,
}

#[derive(Default, Clone, Copy)]
struct Bitmap(u16);

impl Bitmap {
	fn at(&self, i: usize) -> bool {
		self.0 & (1u16 << i) != 0
	}

	fn set(&mut self, i: usize, v: bool) {
		if v {
			self.0 |= 1u16 << i
		} else {
			self.0 &= !(1u16 << i)
		}
	}
}

// TODO rename
struct CompactEncodingInfos {
	/// Node in memory content.
	node: OwnedNode<DBValue>,
	/// Flags indicating whether each child is omitted in the encoded node.
	accessed_children: Bitmap,
	/// Skip value if value node is after.
	accessed_value: bool,
	/// Depth of node in nible.
	depth: usize,
	/// Next descended child, this is only really needed when iterating on
	/// prefix.
	next_descended_child: u8,
}

/* likely compact encoding is enough
struct ContentEncodingInfos {
	/// Node in memory content.
	node: OwnedNode<Vec<u8>>,
	/// Flags indicating whether each child is omitted in the encoded node.
	omit_children: Bitmap,
	/// Skip value if value node is after.
	omit_value: bool,
}
*/

/// Simplified recorder.
pub struct RecorderState<O: codec::Output>(RecorderStateInner<O>);

// TODO may be useless
enum RecorderStateInner<O: codec::Output> {
	/// For FullNodes proofs, just send node to this stream.
	Stream(O),
	/// For FullNodes proofs, just send node to this stream.
	Compact(O, Vec<CompactEncodingInfos>),
	/// For FullNodes proofs, just send node to this stream.
	Content(O, Vec<CompactEncodingInfos>),
	/// Restore from next node prefix to descend into
	/// (skipping all query plan before this definition).
	/// (prefix is key and a boolean to indicate if padded).
	Stateless(O, Vec<u8>, bool),
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateRecord<O: codec::Output> {
	recorder: RecorderState<O>,
	currently_query_item: Option<InMemQueryPlanItem>,
}

/// When process is halted keep execution state
/// to restore later.
pub struct HaltedStateCheck {
	stack: (),
	stack_content: (),
	currently_query_item: Option<InMemQueryPlanItem>,
}

#[derive(Default)]
struct RecordStack {
	items: Vec<CompactEncodingInfos>,
	prefix: NibbleVec,
	iter_prefix: Option<usize>,
}

/// Run query plan on a full db and record it.
///
/// TODO output and restart are mutually exclusive. -> enum
/// or remove output from halted state.
pub fn record_query_plan<
	'a,
	L: TrieLayout,
	I: Iterator<Item = QueryPlanItem<'a>>,
	//	O: codec::Output,
>(
	db: &TrieDB<L>,
	mut query_plan: QueryPlan<'a, I>,
	//	output: Option<O>,
	restart: Option<()>,
	//	restart: Option<HaltedStateRecord<O>>, // TODO restore
	//) -> Result<Option<HaltedStateRecord<O>>, VerifyError<TrieHash<L>, CError<L>>> { // TODO
	//) restore
) -> Result<Option<()>, VerifyError<TrieHash<L>, CError<L>>> {
	let dummy_parent_hash = TrieHash::<L>::default();
	let mut stack = RecordStack::default();

	let prev_query: Option<QueryPlanItem> = None;
	while let Some(query) = query_plan.items.next() {
		let (ordered, common_nibbles) =
			prev_query.as_ref().map(|p| p.before(&query)).unwrap_or((true, 0));
		if !ordered {
			if query_plan.ignore_unordered {
				continue
			} else {
				return Err(VerifyError::UnorderedKey(query.key.to_vec())) // TODO not kind as param if keeping
				                                          // CompactContent
			}
		}
		loop {
			match stack.prefix.len().cmp(&common_nibbles) {
				Ordering::Equal | Ordering::Less => break,
				Ordering::Greater =>
					if !stack.pop() {
						return Ok(None)
					},
			}
		}

		// descend
		let mut slice_query = NibbleSlice::new_offset(&query.key, common_nibbles);
		let mut touched = false;
		loop {
			if slice_query.is_empty() {
				if query.as_prefix {
					stack.enter_prefix_iter();
				} else {
					touched = true;
				}
				break
			}

			let child_index = slice_query.at(0);
			match stack.try_stack_child(
				child_index,
				db,
				dummy_parent_hash,
				Some(&mut slice_query),
			)? {
				TryStackChildResult::Stacked => {},
				TryStackChildResult::NotStackedBranch | TryStackChildResult::NotStacked => break,
				TryStackChildResult::StackedDescendIncomplete => {
					if query.as_prefix {
						stack.enter_prefix_iter();
					}
					break
				},
			}
		}

		if touched {
			// try access value
			stack.access_value(db)?;
		}
		if let Some(prefix_stack_depth) = stack.iter_prefix.clone() {
			// run prefix iteration
			loop {
				// descend
				let mut stacked = true;
				loop {
					if stacked {
						// try access value in next node
						stack.access_value(db)?;
						stacked = false;
					}

					let child_index = if let Some(mut item) = stack.items.last_mut() {
						if item.next_descended_child as usize >= crate::nibble_ops::NIBBLE_LENGTH {
							continue
						}
						item.next_descended_child += 1;
						item.next_descended_child - 1
					} else {
						break
					};
					match stack.try_stack_child(child_index, db, dummy_parent_hash, None)? {
						TryStackChildResult::Stacked => {
							stacked = true;
						},
						TryStackChildResult::NotStackedBranch => (),
						TryStackChildResult::NotStacked => break,
						TryStackChildResult::StackedDescendIncomplete => {
							unreachable!("no slice query")
						},
					}
				}

				// pop

				if !stack.pop() {
					break
				}
			}
			stack.exit_prefix_iter();
		}
	}

	Ok(None)
}

enum TryStackChildResult {
	Stacked,
	NotStackedBranch,
	NotStacked,
	StackedDescendIncomplete,
}

impl RecordStack {
	fn try_stack_child<'a, L: TrieLayout>(
		&mut self,
		child_index: u8,
		db: &TrieDB<L>,
		parent_hash: TrieHash<L>,
		mut slice_query: Option<&mut NibbleSlice>,
	) -> Result<TryStackChildResult, VerifyError<TrieHash<L>, CError<L>>> {
		let prefix = &mut self.prefix;
		let stack = &mut self.items;
		let mut descend_incomplete = false;
		let mut stack_extension = false;
		let child_handle = if let Some(item) = stack.last_mut() {
			// TODO this could be reuse from iterator, but it seems simple
			// enough here too.
			let node_data = item.node.data();

			match item.node.node_plan() {
				NodePlan::Empty | NodePlan::Leaf { .. } =>
					return Ok(TryStackChildResult::NotStacked),
				NodePlan::Extension { child, .. } => {
					stack_extension = true;
					child.build(node_data)
				},
				NodePlan::NibbledBranch { children, .. } | NodePlan::Branch { children, .. } =>
					if let Some(child) = &children[child_index as usize] {
						slice_query.as_mut().map(|s| s.advance(1));
						prefix.push(child_index);
						item.accessed_children.set(child_index as usize, true);
						child.build(node_data)
					} else {
						return Ok(TryStackChildResult::NotStackedBranch)
					},
			}
		} else {
			NodeHandle::Hash(db.root().as_ref())
		};
		// TODO handle cache first
		let child_node = db
			.get_raw_or_lookup(parent_hash, child_handle, prefix.as_prefix(), false)
			.map_err(|_| VerifyError::IncompleteProof)?; // actually incomplete db: TODO consider switching error

		// TODO put in proof (only if Hash or inline for content one)

		let node_data = child_node.0.data();

		match child_node.0.node_plan() {
			NodePlan::Branch { .. } => (),
			| NodePlan::Empty => (),
			NodePlan::Leaf { partial, .. } |
			NodePlan::NibbledBranch { partial, .. } |
			NodePlan::Extension { partial, .. } => {
				let partial = partial.build(node_data);
				prefix.append_partial(partial.right());
				if let Some(s) = slice_query.as_mut() {
					if s.starts_with(&partial) {
						s.advance(partial.len());
					} else {
						descend_incomplete = true;
					}
				}
			},
		}
		if stack_extension {
			// rec call to stack branch
			let sbranch = self.try_stack_child(child_index, db, parent_hash, slice_query)?;
			let TryStackChildResult::Stacked = sbranch else {
				return Err(VerifyError::InvalidChildReference(b"branch in db should follow extension".to_vec()));
			};
		} else {
			stack.push(CompactEncodingInfos {
				node: child_node.0,
				accessed_children: Default::default(),
				accessed_value: false,
				depth: prefix.len(),
				next_descended_child: child_index + 1,
			});
		}

		if descend_incomplete {
			Ok(TryStackChildResult::StackedDescendIncomplete)
		} else {
			Ok(TryStackChildResult::Stacked)
		}
	}

	fn access_value<'a, L: TrieLayout>(
		&mut self,
		db: &TrieDB<L>,
	) -> Result<bool, VerifyError<TrieHash<L>, CError<L>>> {
		let Some(item)= self.items.last_mut() else {
		return Ok(false)
	};
		// TODO this could be reuse from iterator, but it seems simple
		// enough here too.
		let node_data = item.node.data();

		let value = match item.node.node_plan() {
			NodePlan::Leaf { value, .. } => value.build(node_data),
			NodePlan::Branch { value, .. } | NodePlan::NibbledBranch { value, .. } => {
				if let Some(value) = value {
					value.build(node_data)
				} else {
					return Ok(false)
				}
			},
			_ => return Ok(false),
		};

		item.accessed_value = true;
		// TODO register access to key and value

		Ok(true)
	}

	fn pop(&mut self) -> bool {
		if self.iter_prefix == Some(self.items.len()) {
			return false
		}
		if let Some(_item) = self.items.pop() {
			let depth = self.items.last().map(|i| i.depth).unwrap_or(0);
			self.prefix.drop_lasts(self.prefix.len() - depth);
			true
		} else {
			false
		}
	}

	fn enter_prefix_iter(&mut self) {
		self.iter_prefix = Some(self.items.len());
	}

	fn exit_prefix_iter(&mut self) {
		self.iter_prefix = None
	}
}

/// Proof reading iterator.
pub struct ReadProofIterator<'a, L: TrieLayout> {
	_ph: PhantomData<&'a L>,
}

/// Content return on success when reading proof.
pub enum ReadProofItem<'a> {
	/// Successfull read of proof, not all content read.
	Halted(HaltedStateCheck),
	/// Seen value and key in proof.
	/// When we set the query plan, we only return content
	/// matching the query plan.
	Value(&'a [u8], Vec<u8>),
	/// No value seen for a key in the input query plan.
	NoValue(&'a [u8]),
	/// Seen fully covered prefix in proof, this is only
	/// return when we read the proof with the query input (otherwhise
	/// we would need to indicate every child without a hash as a prefix).
	CoveredPrefix(&'a [u8]),
}

impl<'a, L: TrieLayout> Iterator for ReadProofIterator<'a, L> {
	type Item = Result<ReadProofItem<'a>, VerifyError<TrieHash<L>, CError<L>>>;

	fn next(&mut self) -> Option<Self::Item> {
		unimplemented!()
	}
}

/// Read the proof.
pub fn prove_query_plan_iter<'a, L: TrieLayout>(
	content_iter: Option<QueryPlanItemIter<'a>>,
	proof: impl Iterator<Item = &'a [u8]>,
	restart: Option<HaltedStateCheck>,
	kind: ProofKind,
	skip_hash_validation: bool,
) -> Result<(), VerifyError<TrieHash<L>, CError<L>>> {
	if kind == ProofKind::CompactContent {
		return Err(VerifyError::IncompleteProof) // TODO not kind as param if keeping CompactContent
	}

	Ok(())
}

mod compact_content_proof {

	use codec::{Decode, Encode};

	/// Representation of each encoded action
	/// for building the proof.
	/// TODO ref variant for encoding ??
	#[derive(Encode, Decode, Debug)]
	pub(crate) enum Op<H, V> {
		// key content followed by a mask for last byte.
		// If mask erase some content the content need to
		// be set at 0 (or error).
		// Two consecutive `KeyPush` are invalid.
		KeyPush(Vec<u8>, u8), /* TODO could use BackingByteVec (but Vec for new as it scale
		                       * encode) */
		// Last call to pop is implicit (up to root), defining
		// one will result in an error.
		// Two consecutive `KeyPush` are invalid.
		// TODO should be compact encoding of number.
		KeyPop(u16),
		// u8 is child index, shorthand for key push one nibble followed by key pop.
		HashChild(Enc<H>, u8),
		// All value variant are only after a `KeyPush` or at first position.
		HashValue(Enc<H>),
		Value(V),
		// This is not strictly necessary, only if the proof is not sized, otherwhise if we know
		// the stream will end it can be skipped.
		EndProof,
	}

	#[derive(Debug)]
	#[repr(transparent)]
	pub struct Enc<H>(pub H);

	impl<H: AsRef<[u8]>> Encode for Enc<H> {
		fn size_hint(&self) -> usize {
			self.0.as_ref().len()
		}

		fn encoded_size(&self) -> usize {
			self.0.as_ref().len()
		}

		fn encode_to<T: codec::Output + ?Sized>(&self, dest: &mut T) {
			dest.write(self.0.as_ref())
		}
	}

	impl<H: AsMut<[u8]> + Default> Decode for Enc<H> {
		fn decode<I: codec::Input>(input: &mut I) -> core::result::Result<Self, codec::Error> {
			let mut dest = H::default();
			input.read(dest.as_mut())?;
			Ok(Enc(dest))
		}
	}
}

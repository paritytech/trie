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
struct InMemQueryPlan {
	items: Vec<InMemQueryPlanItem>,
	current: Option<InMemQueryPlanItem>,
	ensure_ordered: bool,
	ignore_unordered: bool,
	allow_under_prefix: bool,
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
	fn as_ref(&self) -> QueryPlan<QueryPlanItemIter> {
		QueryPlan {
			items: QueryPlanItemIter(&self.items, 0),
			current: self.current.as_ref().map(|i| i.as_ref()),
			ensure_ordered: self.ensure_ordered,
			ignore_unordered: self.ignore_unordered,
			allow_under_prefix: self.allow_under_prefix,
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
	ensure_ordered: bool,
	ignore_unordered: bool,
	allow_under_prefix: bool,
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
	/// Last descended child, this is only really needed when iterating on
	/// prefix.
	last_descended_child: u8,
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

/// Run query plan on a full db and record it.
///
/// TODO output and restart are mutually exclusive. -> enum
/// or remove output from halted state.
pub fn record_query_plan<'a, L: TrieLayout, I: Iterator<Item = QueryPlanItem<'a>>, O: codec::Output>(
	db: &TrieDB<L>,
	mut query_plan: QueryPlan<'a, I>,
	output: Option<O>,
	restart: Option<HaltedStateRecord<O>>,
) -> Result<Option<HaltedStateRecord<O>>, VerifyError<TrieHash<L>, CError<L>>> {
	let dummy_parent_hash = TrieHash::<L>::default();
	let mut prefix = NibbleVec::new();
	let mut stack: Vec<CompactEncodingInfos> = Vec::new();

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
			match prefix.len().cmp(&common_nibbles) {
				Ordering::Equal | Ordering::Less => break,
				Ordering::Greater =>
					if let Some(item) = stack.pop() {
						let depth = stack.last().map(|i| i.depth).unwrap_or(0);
						prefix.drop_lasts(prefix.len() - depth);
					} else {
						return Ok(None)
					},
			}
		}

		// descend
		let mut slice_query = NibbleSlice::new_offset(&query.key, common_nibbles);
		let mut touched = false;
		let mut iter_prefix = false;
		let mut child_index = 0;
		loop {
			let child_handle = if let Some(mut item) = stack.last_mut() {
				if slice_query.is_empty() {
					if query.as_prefix {
						touched = true;
						iter_prefix = true;
					} else {
						touched = true;
					}
					break
				}
				child_index = slice_query.at(0);

				// TODO this could be reuse from iterator, but it seems simple
				// enough here too.
				let node_data = item.node.data();

				match item.node.node_plan() {
					NodePlan::Empty | NodePlan::Leaf { .. } => break,
					NodePlan::Extension { child, .. } => child.build(node_data),
					NodePlan::NibbledBranch { children, .. } |
					NodePlan::Branch { children, .. } =>
						if let Some(child) = &children[child_index as usize] {
							slice_query.advance(1);
							prefix.push(child_index);
							item.accessed_children.set(child_index as usize, true);

							child.build(node_data)
						} else {
							break
						},
				}
			} else {
				NodeHandle::Hash(db.root().as_ref())
			};

			// TODO handle cache first
			let child_node = db
				.get_raw_or_lookup(dummy_parent_hash, child_handle, prefix.as_prefix(), false)
				.map_err(|_| VerifyError::IncompleteProof)?; // actually incomplete db: TODO consider switching error

			// TODO put in proof (only if Hash or inline for content one)

			// descend in node
			let mut node_depth = 0;
			let mut descend_incomplete = false;

			// TODO
			//
			let node_data = child_node.0.data();

			match child_node.0.node_plan() {
				NodePlan::Branch { .. } => (),
				| NodePlan::Empty => (),
				NodePlan::Leaf { partial, .. } |
				NodePlan::NibbledBranch { partial, .. } |
				NodePlan::Extension { partial, .. } => {
					let partial = partial.build(node_data);
					node_depth = partial.len();
					prefix.append_partial(partial.right());

					if slice_query.starts_with(&partial) {
						slice_query.advance(partial.len());
					} else {
						descend_incomplete = true;
					}
				},
			}

			stack.push(CompactEncodingInfos {
				node: child_node.0,
				accessed_children: Default::default(),
				accessed_value: false,
				depth: prefix.len() + node_depth,
				last_descended_child: child_index,
			});

			if descend_incomplete {
				if query.as_prefix {
					iter_prefix = true;
				}
				break
			}
		}

		if touched {
			// try access value
		}
		if iter_prefix {
			// run prefix iteration
		}
	}

	Ok(None)
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

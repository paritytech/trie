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
	node::OwnedNode, proof::VerifyError, rstd::result::Result, CError, TrieError, TrieHash,
	TrieLayout, TrieDB,
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
struct QueryPlan<'a, I>
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

struct CompactEncodingInfos {
	/// Node in memory content.
	node: OwnedNode<Vec<u8>>,
	/// Flags indicating whether each child is omitted in the encoded node.
	omit_children: Bitmap,
	/// Skip value if value node is after.
	omit_value: bool,
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

enum RecorderStateInner<O: codec::Output> {
	/// For FullNodes proofs, just send node to this stream.
	Stream(O),
	/// For FullNodes proofs, just send node to this stream.
	Compact(O, Vec<CompactEncodingInfos>),
	/// For FullNodes proofs, just send node to this stream.
	Content(O, Vec<CompactEncodingInfos>),
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
pub fn record_query_plan<'a, L: TrieLayout, O: codec::Output>(
	db: &TrieDB<L>,
	content_iter: QueryPlanItemIter<'a>,
	output: Option<O>,
	restart: Option<HaltedStateRecord<O>>,
	size_limit: Option<usize>,
	node_limit: Option<usize>,
) -> Result<Option<HaltedStateRecord<O>>, VerifyError<TrieHash<L>, CError<L>>> {
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

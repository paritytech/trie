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

//! Codec and layout configuration similar to upstream default substrate one.

use super::{CodecError as Error, NodeCodec as NodeCodecT, *};
use trie_db::node::Value;

/// No extension trie with no hashed value.
pub struct HashedValueNoExt;

/// No extension trie which stores value above a static size
/// as external node.
pub struct HashedValueNoExtThreshold<const C: u32>;

impl TrieLayout for HashedValueNoExt {
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = false;
	const MAX_INLINE_VALUE: Option<u32> = None;

	type Hash = RefHasher;
	type Codec = ReferenceNodeCodecNoExtMeta<RefHasher>;
}

impl<const C: u32> TrieLayout for HashedValueNoExtThreshold<C> {
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = false;
	const MAX_INLINE_VALUE: Option<u32> = Some(C);

	type Hash = RefHasher;
	type Codec = ReferenceNodeCodecNoExtMeta<RefHasher>;
}

/// Constants specific to encoding with external value node support.
pub mod trie_constants {
	const FIRST_PREFIX: u8 = 0b_00 << 6;
	pub const NIBBLE_SIZE_BOUND: usize = u16::max_value() as usize;
	pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
	pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
	pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
	pub const EMPTY_TRIE: u8 = FIRST_PREFIX | (0b_00 << 4);
	pub const ALT_HASHING_LEAF_PREFIX_MASK: u8 = FIRST_PREFIX | (0b_1 << 5);
	pub const ALT_HASHING_BRANCH_WITH_MASK: u8 = FIRST_PREFIX | (0b_01 << 4);
	pub const ESCAPE_COMPACT_HEADER: u8 = EMPTY_TRIE | 0b_00_01;
}

#[derive(Default, Clone)]
pub struct NodeCodec<H>(PhantomData<H>);

impl<H: Hasher> NodeCodec<H> {
	fn decode_plan_inner_hashed(data: &[u8]) -> Result<NodePlan, Error> {
		let mut input = ByteSliceInput::new(data);

		let header = NodeHeader::decode(&mut input)?;
		let contains_hash = header.contains_hash_of_value();

		let branch_has_value = if let NodeHeader::Branch(has_value, _) = &header {
			*has_value
		} else {
			// alt_hash_branch
			true
		};

		match header {
			NodeHeader::Null => Ok(NodePlan::Empty),
			NodeHeader::HashedValueBranch(nibble_count) | NodeHeader::Branch(_, nibble_count) => {
				let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
				// check that the padding is valid (if any)
				if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
					return Err(CodecError::from("Bad format"))
				}
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) /
						nibble_ops::NIBBLE_PER_BYTE,
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let bitmap_range = input.take(BITMAP_LENGTH)?;
				let bitmap = Bitmap::decode(&data[bitmap_range])?;
				let value = if branch_has_value {
					Some(if contains_hash {
						ValuePlan::Node(input.take(H::LENGTH)?)
					} else {
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						ValuePlan::Inline(input.take(count)?)
					})
				} else {
					None
				};
				let mut children = [
					None, None, None, None, None, None, None, None, None, None, None, None, None,
					None, None, None,
				];
				for i in 0..nibble_ops::NIBBLE_LENGTH {
					if bitmap.value_at(i) {
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						let range = input.take(count)?;
						children[i] = Some(if count == H::LENGTH {
							NodeHandlePlan::Hash(range)
						} else {
							NodeHandlePlan::Inline(range)
						});
					}
				}
				Ok(NodePlan::NibbledBranch {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value,
					children,
				})
			},
			NodeHeader::HashedValueLeaf(nibble_count) | NodeHeader::Leaf(nibble_count) => {
				let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
				// check that the padding is valid (if any)
				if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
					return Err(CodecError::from("Bad format"))
				}
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) /
						nibble_ops::NIBBLE_PER_BYTE,
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let value = if contains_hash {
					ValuePlan::Node(input.take(H::LENGTH)?)
				} else {
					let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
					ValuePlan::Inline(input.take(count)?)
				};

				Ok(NodePlan::Leaf {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value,
				})
			},
		}
	}
}

impl<H> NodeCodecT for NodeCodec<H>
where
	H: Hasher,
{
	const ESCAPE_HEADER: Option<u8> = Some(trie_constants::ESCAPE_COMPACT_HEADER);
	type Error = Error;
	type HashOut = H::Out;

	fn hashed_null_node() -> <H as Hasher>::Out {
		H::hash(<Self as NodeCodecT>::empty_node())
	}

	fn decode_plan(data: &[u8]) -> Result<NodePlan, Self::Error> {
		Self::decode_plan_inner_hashed(data)
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodecT>::empty_node()
	}

	fn empty_node() -> &'static [u8] {
		&[trie_constants::EMPTY_TRIE]
	}

	fn leaf_node(partial: impl Iterator<Item = u8>, number_nibble: usize, value: Value) -> Vec<u8> {
		let contains_hash = matches!(&value, Value::Node(..));
		let mut output = if contains_hash {
			partial_from_iterator_encode(partial, number_nibble, NodeKind::HashedValueLeaf)
		} else {
			partial_from_iterator_encode(partial, number_nibble, NodeKind::Leaf)
		};
		match value {
			Value::Inline(value) => {
				Compact(value.len() as u32).encode_to(&mut output);
				output.extend_from_slice(value);
			},
			Value::Node(hash) => {
				debug_assert!(hash.len() == H::LENGTH);
				output.extend_from_slice(hash);
			},
		}
		output
	}

	fn extension_node(
		_partial: impl Iterator<Item = u8>,
		_nbnibble: usize,
		_child: ChildReference<<H as Hasher>::Out>,
	) -> Vec<u8> {
		unreachable!("Codec without extension.")
	}

	fn branch_node(
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
		_maybe_value: Option<Value>,
	) -> Vec<u8> {
		unreachable!("Codec without extension.")
	}

	fn branch_node_nibbled(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
		value: Option<Value>,
	) -> Vec<u8> {
		let contains_hash = matches!(&value, Some(Value::Node(..)));
		let mut output = match (&value, contains_hash) {
			(&None, _) =>
				partial_from_iterator_encode(partial, number_nibble, NodeKind::BranchNoValue),
			(_, false) =>
				partial_from_iterator_encode(partial, number_nibble, NodeKind::BranchWithValue),
			(_, true) =>
				partial_from_iterator_encode(partial, number_nibble, NodeKind::HashedValueBranch),
		};

		let bitmap_index = output.len();
		let mut bitmap: [u8; BITMAP_LENGTH] = [0; BITMAP_LENGTH];
		(0..BITMAP_LENGTH).for_each(|_| output.push(0));
		match value {
			Some(Value::Inline(value)) => {
				Compact(value.len() as u32).encode_to(&mut output);
				output.extend_from_slice(value);
			},
			Some(Value::Node(hash)) => {
				debug_assert!(hash.len() == H::LENGTH);
				output.extend_from_slice(hash);
			},
			None => (),
		}
		Bitmap::encode(
			children.map(|maybe_child| match maybe_child.borrow() {
				Some(ChildReference::Hash(h)) => {
					h.as_ref().encode_to(&mut output);
					true
				},
				&Some(ChildReference::Inline(inline_data, len)) => {
					inline_data.as_ref()[..len].encode_to(&mut output);
					true
				},
				None => false,
			}),
			bitmap.as_mut(),
		);
		output[bitmap_index..bitmap_index + BITMAP_LENGTH]
			.copy_from_slice(&bitmap[..BITMAP_LENGTH]);
		output
	}
}

// utils

/// Encode and allocate node type header (type and size), and partial value.
/// It uses an iterator over encoded partial bytes as input.
fn partial_from_iterator_encode<I: Iterator<Item = u8>>(
	partial: I,
	nibble_count: usize,
	node_kind: NodeKind,
) -> Vec<u8> {
	let nibble_count = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, nibble_count);

	let mut output = Vec::with_capacity(4 + (nibble_count / nibble_ops::NIBBLE_PER_BYTE));
	match node_kind {
		NodeKind::Leaf => NodeHeader::Leaf(nibble_count).encode_to(&mut output),
		NodeKind::BranchWithValue => NodeHeader::Branch(true, nibble_count).encode_to(&mut output),
		NodeKind::BranchNoValue => NodeHeader::Branch(false, nibble_count).encode_to(&mut output),
		NodeKind::HashedValueLeaf =>
			NodeHeader::HashedValueLeaf(nibble_count).encode_to(&mut output),
		NodeKind::HashedValueBranch =>
			NodeHeader::HashedValueBranch(nibble_count).encode_to(&mut output),
	};
	output.extend(partial);
	output
}

/// A node header.
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum NodeHeader {
	Null,
	// contains wether there is a value and nibble count
	Branch(bool, usize),
	// contains nibble count
	Leaf(usize),
	// contains nibble count.
	HashedValueBranch(usize),
	// contains nibble count.
	HashedValueLeaf(usize),
}

impl NodeHeader {
	fn contains_hash_of_value(&self) -> bool {
		match self {
			NodeHeader::HashedValueBranch(_) | NodeHeader::HashedValueLeaf(_) => true,
			_ => false,
		}
	}
}

/// NodeHeader without content
pub(crate) enum NodeKind {
	Leaf,
	BranchNoValue,
	BranchWithValue,
	HashedValueLeaf,
	HashedValueBranch,
}

impl Encode for NodeHeader {
	fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
		match self {
			NodeHeader::Null => output.push_byte(trie_constants::EMPTY_TRIE),
			NodeHeader::Branch(true, nibble_count) =>
				encode_size_and_prefix(*nibble_count, trie_constants::BRANCH_WITH_MASK, 2, output),
			NodeHeader::Branch(false, nibble_count) => encode_size_and_prefix(
				*nibble_count,
				trie_constants::BRANCH_WITHOUT_MASK,
				2,
				output,
			),
			NodeHeader::Leaf(nibble_count) =>
				encode_size_and_prefix(*nibble_count, trie_constants::LEAF_PREFIX_MASK, 2, output),
			NodeHeader::HashedValueBranch(nibble_count) => encode_size_and_prefix(
				*nibble_count,
				trie_constants::ALT_HASHING_BRANCH_WITH_MASK,
				4,
				output,
			),
			NodeHeader::HashedValueLeaf(nibble_count) => encode_size_and_prefix(
				*nibble_count,
				trie_constants::ALT_HASHING_LEAF_PREFIX_MASK,
				3,
				output,
			),
		}
	}
}

impl parity_scale_codec::EncodeLike for NodeHeader {}

impl Decode for NodeHeader {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		let i = input.read_byte()?;
		if i == trie_constants::EMPTY_TRIE {
			return Ok(NodeHeader::Null)
		}
		match i & (0b11 << 6) {
			trie_constants::LEAF_PREFIX_MASK => Ok(NodeHeader::Leaf(decode_size(i, input, 2)?)),
			trie_constants::BRANCH_WITH_MASK =>
				Ok(NodeHeader::Branch(true, decode_size(i, input, 2)?)),
			trie_constants::BRANCH_WITHOUT_MASK =>
				Ok(NodeHeader::Branch(false, decode_size(i, input, 2)?)),
			trie_constants::EMPTY_TRIE => {
				if i & (0b111 << 5) == trie_constants::ALT_HASHING_LEAF_PREFIX_MASK {
					Ok(NodeHeader::HashedValueLeaf(decode_size(i, input, 3)?))
				} else if i & (0b1111 << 4) == trie_constants::ALT_HASHING_BRANCH_WITH_MASK {
					Ok(NodeHeader::HashedValueBranch(decode_size(i, input, 4)?))
				} else {
					// do not allow any special encoding
					Err("Unallowed encoding".into())
				}
			},
			_ => unreachable!(),
		}
	}
}

/// Returns an iterator over encoded bytes for node header and size.
/// Size encoding allows unlimited, length inefficient, representation, but
/// is bounded to 16 bit maximum value to avoid possible DOS.
pub(crate) fn size_and_prefix_iterator(
	size: usize,
	prefix: u8,
	prefix_mask: usize,
) -> impl Iterator<Item = u8> {
	let size = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, size);

	let max_value = 255u8 >> prefix_mask;
	let l1 = std::cmp::min(max_value as usize - 1, size);
	let (first_byte, mut rem) = if size == l1 {
		(once(prefix + l1 as u8), 0)
	} else {
		(once(prefix + max_value as u8), size - l1)
	};
	let next_bytes = move || {
		if rem > 0 {
			if rem < 256 {
				let result = rem - 1;
				rem = 0;
				Some(result as u8)
			} else {
				rem = rem.saturating_sub(255);
				Some(255)
			}
		} else {
			None
		}
	};
	first_byte.chain(std::iter::from_fn(next_bytes))
}

/// Encodes size and prefix to a stream output (prefix on 2 first bit only).
fn encode_size_and_prefix<W>(size: usize, prefix: u8, prefix_mask: usize, out: &mut W)
where
	W: Output + ?Sized,
{
	for b in size_and_prefix_iterator(size, prefix, prefix_mask) {
		out.push_byte(b)
	}
}

/// Decode size only from stream input and header byte.
fn decode_size(first: u8, input: &mut impl Input, prefix_mask: usize) -> Result<usize, Error> {
	let max_value = 255u8 >> prefix_mask;
	let mut result = (first & max_value) as usize;
	if result < max_value as usize {
		return Ok(result)
	}
	result -= 1;
	while result <= trie_constants::NIBBLE_SIZE_BOUND {
		let n = input.read_byte()? as usize;
		if n < 255 {
			return Ok(result + n + 1)
		}
		result += 255;
	}
	Ok(trie_constants::NIBBLE_SIZE_BOUND)
}

/// Reference implementation of a `TrieStream` without extension.
#[derive(Default, Clone)]
pub struct ReferenceTrieStreamNoExt {
	/// Current node buffer.
	buffer: Vec<u8>,
}

/// Create a leaf/branch node, encoding a number of nibbles.
fn fuse_nibbles_node<'a>(nibbles: &'a [u8], kind: NodeKind) -> impl Iterator<Item = u8> + 'a {
	let size = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, nibbles.len());

	let iter_start = match kind {
		NodeKind::Leaf => size_and_prefix_iterator(size, trie_constants::LEAF_PREFIX_MASK, 2),
		NodeKind::BranchNoValue =>
			size_and_prefix_iterator(size, trie_constants::BRANCH_WITHOUT_MASK, 2),
		NodeKind::BranchWithValue =>
			size_and_prefix_iterator(size, trie_constants::BRANCH_WITH_MASK, 2),
		NodeKind::HashedValueLeaf =>
			size_and_prefix_iterator(size, trie_constants::ALT_HASHING_LEAF_PREFIX_MASK, 3),
		NodeKind::HashedValueBranch =>
			size_and_prefix_iterator(size, trie_constants::ALT_HASHING_BRANCH_WITH_MASK, 4),
	};
	iter_start
		.chain(if nibbles.len() % 2 == 1 { Some(nibbles[0]) } else { None })
		.chain(nibbles[nibbles.len() % 2..].chunks(2).map(|ch| ch[0] << 4 | ch[1]))
}

use trie_root::Value as TrieStreamValue;
impl TrieStream for ReferenceTrieStreamNoExt {
	fn new() -> Self {
		Self { buffer: Vec::new() }
	}

	fn append_empty_data(&mut self) {
		self.buffer.push(trie_constants::EMPTY_TRIE);
	}

	fn append_leaf(&mut self, key: &[u8], value: TrieStreamValue) {
		let kind = match &value {
			TrieStreamValue::Inline(..) => NodeKind::Leaf,
			TrieStreamValue::Node(..) => NodeKind::HashedValueLeaf,
		};
		self.buffer.extend(fuse_nibbles_node(key, kind));
		match &value {
			TrieStreamValue::Inline(value) => {
				Compact(value.len() as u32).encode_to(&mut self.buffer);
				self.buffer.extend_from_slice(value);
			},
			TrieStreamValue::Node(hash) => {
				self.buffer.extend_from_slice(hash.as_slice());
			},
		};
	}

	fn begin_branch(
		&mut self,
		maybe_partial: Option<&[u8]>,
		maybe_value: Option<TrieStreamValue>,
		has_children: impl Iterator<Item = bool>,
	) {
		if let Some(partial) = maybe_partial {
			let kind = match &maybe_value {
				None => NodeKind::BranchNoValue,
				Some(TrieStreamValue::Inline(..)) => NodeKind::BranchWithValue,
				Some(TrieStreamValue::Node(..)) => NodeKind::HashedValueBranch,
			};

			self.buffer.extend(fuse_nibbles_node(partial, kind));
			let bm = branch_node_bit_mask(has_children);
			self.buffer.extend([bm.0, bm.1].iter());
		} else {
			unreachable!("trie stream codec only for no extension trie");
		}
		match maybe_value {
			None => (),
			Some(TrieStreamValue::Inline(value)) => {
				Compact(value.len() as u32).encode_to(&mut self.buffer);
				self.buffer.extend_from_slice(value);
			},
			Some(TrieStreamValue::Node(hash)) => {
				self.buffer.extend_from_slice(hash.as_slice());
			},
		}
	}

	fn append_extension(&mut self, _key: &[u8]) {
		unreachable!("trie stream codec only for no extension trie");
	}

	fn append_substream<H: Hasher>(&mut self, other: Self) {
		let data = other.out();
		match data.len() {
			0..=31 => data.encode_to(&mut self.buffer),
			_ => H::hash(&data).as_ref().encode_to(&mut self.buffer),
		}
	}

	fn out(self) -> Vec<u8> {
		self.buffer
	}
}

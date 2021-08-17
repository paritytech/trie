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

use super::*;
use super::CodecError as Error;
use super::NodeCodec as NodeCodecT;

/// Contains threshold for applying alt_hashing.
#[derive(Default, Clone, Debug)]
pub struct AltHashNoExt(pub Option<u32>);

impl TrieLayout for AltHashNoExt {
	const USE_EXTENSION: bool = false;
	const ALLOW_EMPTY: bool = false;
	const USE_META: bool = true;

	type Hash = RefHasher;
	type Codec = ReferenceNodeCodecNoExtMeta<RefHasher>;

	fn alt_threshold(&self) -> Option<u32> {
		self.0
	}
}

/// Switch to hashed value variant.
pub	fn to_hashed_variant<H: Hasher>(value: &[u8], meta: &mut Meta, used_value: bool) -> Option<DBValue> {
	if !meta.contain_hash && meta.apply_inner_hashing && !used_value && meta.range.is_some() {
		let mut stored = Vec::with_capacity(value.len() + 1);
		// Warning this assumes that encoded value cannot start by this,
		// so it is tightly coupled with the header type of the codec.
		stored.push(trie_constants::DEAD_HEADER_META_HASHED_VALUE);
		let range = meta.range.as_ref().expect("Tested in condition");
		// store hash instead of value.
		let value = inner_hashed_value::<H>(value, Some((range.start, range.end)));
		stored.extend_from_slice(value.as_slice());
		meta.contain_hash = true;
		return Some(stored);
	}
	None
}


/// Constants specific to encoding with alt hashing.
pub mod trie_constants {
	const FIRST_PREFIX: u8 = 0b_00 << 6;
	/// In proof this header is used when only hashed value is stored.
	pub const DEAD_HEADER_META_HASHED_VALUE: u8 = EMPTY_TRIE | 0b_00_01;
	pub const NIBBLE_SIZE_BOUND: usize = u16::max_value() as usize;
	pub const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
	pub const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
	pub const BRANCH_WITH_MASK: u8 = 0b_11 << 6;
	pub const EMPTY_TRIE: u8 = FIRST_PREFIX | (0b_00 << 4);
	pub const ALT_HASHING_LEAF_PREFIX_MASK: u8 = FIRST_PREFIX | (0b_1 << 5);
	pub const ALT_HASHING_BRANCH_WITH_MASK: u8 = FIRST_PREFIX | (0b_01 << 4);
}

#[derive(Default, Clone)]
pub struct NodeCodec<H>(PhantomData<H>);

impl<H: Hasher> NodeCodec<H> {
	fn decode_plan_inner_hashed(
		data: &[u8],
		meta: &mut Meta,
	) -> Result<NodePlan, Error> {
		let mut input = ByteSliceInput::new(data);

		let header = NodeHeader::decode(&mut input)?;
		let contains_hash = header.contains_hash_of_value();
		let alt_hashing = header.alt_hashing();
		meta.apply_inner_hashing = alt_hashing;

		let branch_has_value = if let NodeHeader::Branch(has_value, _) = &header {
			*has_value
		} else {
			// alt_hash_branch
			true
		};

		match header {
			NodeHeader::Null => Ok(NodePlan::Empty),
			NodeHeader::AltHashBranch(nibble_count, _)
			| NodeHeader::Branch(_, nibble_count) => {
				let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
				// check that the padding is valid (if any)
				if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
					return Err(CodecError::from("Bad format"));
				}
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE,
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let bitmap_range = input.take(BITMAP_LENGTH)?;
				let bitmap = Bitmap::decode(&data[bitmap_range])?;
				let value = if branch_has_value {
					if alt_hashing && contains_hash {
						ValuePlan::HashedValue(input.take(H::LENGTH)?)
					} else {
						let with_len = input.offset;
						let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
						ValuePlan::Value(input.take(count)?, with_len)
					}
				} else {
					ValuePlan::NoValue
				};
				let mut children = [
					None, None, None, None, None, None, None, None,
					None, None, None, None, None, None, None, None,
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
			NodeHeader::AltHashLeaf(nibble_count, _)
			| NodeHeader::Leaf(nibble_count) => {
				let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
				// check that the padding is valid (if any)
				if padding && nibble_ops::pad_left(data[input.offset]) != 0 {
					return Err(CodecError::from("Bad format"));
				}
				let partial = input.take(
					(nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE,
				)?;
				let partial_padding = nibble_ops::number_padding(nibble_count);
				let value = if alt_hashing && contains_hash {
					ValuePlan::HashedValue(input.take(H::LENGTH)?)
				} else {
					let with_len = input.offset;
					let count = <Compact<u32>>::decode(&mut input)?.0 as usize;
					ValuePlan::Value(input.take(count)?, with_len)
				};

				Ok(NodePlan::Leaf {
					partial: NibbleSlicePlan::new(partial, partial_padding),
					value,
				})
			}
		}
	}
}

impl<H> NodeCodecT for NodeCodec<H>
	where
		H: Hasher,
{
	const OFFSET_IF_CONTAINS_HASH: usize = 1;
	type Error = Error;
	type HashOut = H::Out;

	fn hashed_null_node() -> <H as Hasher>::Out {
		H::hash(<Self as NodeCodecT>::empty_node())
	}

	fn decode_plan(data: &[u8], meta: &mut Meta) -> Result<NodePlan, Self::Error> {
		Self::decode_plan_inner_hashed(data, meta).map(|plan| {
			meta.decoded_callback(&plan);
			plan
		})
	}

	fn decode_plan_inner(_data: &[u8]) -> Result<NodePlan, Self::Error> {
		unreachable!("decode_plan is implemented")
	}

	fn is_empty_node(data: &[u8]) -> bool {
		data == <Self as NodeCodecT>::empty_node()
	}

	fn empty_node() -> &'static [u8] {
		&[trie_constants::EMPTY_TRIE]
	}

	fn leaf_node(partial: Partial, value: Value, meta: &mut Meta) -> Vec<u8> {
		let contains_hash = matches!(&value, Value::HashedValue(..));
		// Note that we use AltHash type only if inner hashing will occur,
		// this way we allow changing hash threshold.
		// With fix inner hashing alt hash can be use with all node, but
		// that is not better (encoding can use an additional nibble byte
		// sometime).
		let mut output = if meta.try_inner_hashing.as_ref().map(|threshold|
			value_do_hash(&value, threshold)
		).unwrap_or(meta.apply_inner_hashing) {
			if contains_hash {
				partial_encode(partial, NodeKind::AltHashLeafHash)
			} else {
				partial_encode(partial, NodeKind::AltHashLeaf)
			}
		} else {
			partial_encode(partial, NodeKind::Leaf)
		};
		match value {
			Value::Value(value) => {
				let with_len = output.len();
				Compact(value.len() as u32).encode_to(&mut output);
				let start = output.len();
				output.extend_from_slice(value);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::Value(start..end, with_len));
			},
			Value::HashedValue(hash) => {
				debug_assert!(hash.len() == H::LENGTH);
				let start = output.len();
				output.extend_from_slice(hash);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::HashedValue(start..end));
			},
			Value::NoValue => unimplemented!("No support for incomplete nodes"),
		}
		output
	}

	fn extension_node(
		_partial: impl Iterator<Item = u8>,
		_nbnibble: usize,
		_child: ChildReference<<H as Hasher>::Out>,
		_meta: &mut Meta,
	) -> Vec<u8> {
		unreachable!()
	}

	fn branch_node(
		_children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
		_maybe_value: Value,
		_meta: &mut Meta,
	) -> Vec<u8> {
		unreachable!()
	}

	fn branch_node_nibbled(
		partial: impl Iterator<Item = u8>,
		number_nibble: usize,
		children: impl Iterator<Item = impl Borrow<Option<ChildReference<<H as Hasher>::Out>>>>,
		value: Value,
		meta: &mut Meta,
	) -> Vec<u8> {
		let contains_hash = matches!(&value, Value::HashedValue(..));
		let mut output = match (&value,  meta.try_inner_hashing.as_ref().map(|threshold|
			value_do_hash(&value, threshold)
		).unwrap_or(meta.apply_inner_hashing)) {
			(&Value::NoValue, _) => {
				partial_from_iterator_encode(partial, number_nibble, NodeKind::BranchNoValue)
			},
			(_, false) => {
				partial_from_iterator_encode(partial, number_nibble, NodeKind::BranchWithValue)
			},
			(_, true) => {
				if contains_hash {
					partial_from_iterator_encode(partial, number_nibble, NodeKind::AltHashBranchWithValueHash)
				} else {
					partial_from_iterator_encode(partial, number_nibble, NodeKind::AltHashBranchWithValue)
				}
			},
		};

		let bitmap_index = output.len();
		let mut bitmap: [u8; BITMAP_LENGTH] = [0; BITMAP_LENGTH];
		(0..BITMAP_LENGTH).for_each(|_|output.push(0));
		match value {
			Value::Value(value) => {
				let with_len = output.len();
				Compact(value.len() as u32).encode_to(&mut output);
				let start = output.len();
				output.extend_from_slice(value);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::Value(start..end, with_len));
			},
			Value::HashedValue(hash) => {
				debug_assert!(hash.len() == H::LENGTH);
				let start = output.len();
				output.extend_from_slice(hash);
				let end = output.len();
				meta.encoded_value_callback(ValuePlan::HashedValue(start..end));
			},
			Value::NoValue => (),
		}
		Bitmap::encode(children.map(|maybe_child| match maybe_child.borrow() {
			Some(ChildReference::Hash(h)) => {
				h.as_ref().encode_to(&mut output);
				true
			}
			&Some(ChildReference::Inline(inline_data, len)) => {
				inline_data.as_ref()[..len].encode_to(&mut output);
				true
			}
			None => false,
		}), bitmap.as_mut());
		output[bitmap_index..bitmap_index + BITMAP_LENGTH]
			.copy_from_slice(&bitmap[..BITMAP_LENGTH]);
		output
	}
}

// utils

fn value_do_hash(val: &Value, threshold: &u32) -> bool {
	match val {
		Value::Value(val) => {
			val.encoded_size() >= *threshold as usize
		},
		Value::HashedValue(..) => true, // can only keep hashed
		Value::NoValue => {
			false
		},
	}
}

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
		NodeKind::AltHashLeaf => NodeHeader::AltHashLeaf(nibble_count, false).encode_to(&mut output),
		NodeKind::AltHashBranchWithValue => NodeHeader::AltHashBranch(nibble_count, false)
			.encode_to(&mut output),
		NodeKind::AltHashLeafHash => NodeHeader::AltHashLeaf(nibble_count, true).encode_to(&mut output),
		NodeKind::AltHashBranchWithValueHash => NodeHeader::AltHashBranch(nibble_count, true)
			.encode_to(&mut output),

	};
	output.extend(partial);
	output
}

/// Encode and allocate node type header (type and size), and partial value.
/// Same as `partial_from_iterator_encode` but uses non encoded `Partial` as input.
fn partial_encode(partial: Partial, node_kind: NodeKind) -> Vec<u8> {
	let number_nibble_encoded = (partial.0).0 as usize;
	let nibble_count = partial.1.len() * nibble_ops::NIBBLE_PER_BYTE + number_nibble_encoded;

	let nibble_count = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, nibble_count);

	let mut output = Vec::with_capacity(3 + partial.1.len());
	match node_kind {
		NodeKind::Leaf => NodeHeader::Leaf(nibble_count).encode_to(&mut output),
		NodeKind::BranchWithValue => NodeHeader::Branch(true, nibble_count).encode_to(&mut output),
		NodeKind::BranchNoValue => NodeHeader::Branch(false, nibble_count).encode_to(&mut output),
		NodeKind::AltHashLeaf => NodeHeader::AltHashLeaf(nibble_count, false).encode_to(&mut output),
		NodeKind::AltHashBranchWithValue => NodeHeader::AltHashBranch(nibble_count, false)
			.encode_to(&mut output),
		NodeKind::AltHashLeafHash => NodeHeader::AltHashLeaf(nibble_count, true).encode_to(&mut output),
		NodeKind::AltHashBranchWithValueHash => NodeHeader::AltHashBranch(nibble_count, true)
			.encode_to(&mut output),

	};
	if number_nibble_encoded > 0 {
		output.push(nibble_ops::pad_right((partial.0).1));
	}
	output.extend_from_slice(&partial.1[..]);
	output
}

/// A node header
#[derive(Copy, Clone, PartialEq, Eq, Debug)]
pub(crate) enum NodeHeader {
	Null,
	// contains wether there is a value and nibble count
	Branch(bool, usize),
	// contains nibble count
	Leaf(usize),
	// contains nibble count and wether the value is a hash.
	AltHashBranch(usize, bool),
	// contains nibble count and wether the value is a hash.
	AltHashLeaf(usize, bool),
}

impl NodeHeader {
	fn contains_hash_of_value(&self) -> bool {
		match self {
			NodeHeader::AltHashBranch(_, true)
			| NodeHeader::AltHashLeaf(_, true) => true,
			_ => false,
		}
	}
}

/// NodeHeader without content
pub(crate) enum NodeKind {
	Leaf,
	BranchNoValue,
	BranchWithValue,
	AltHashLeaf,
	AltHashBranchWithValue,
	AltHashLeafHash,
	AltHashBranchWithValueHash,
}

impl Encode for NodeHeader {
	fn encode_to<T: Output + ?Sized>(&self, output: &mut T) {
		if self.contains_hash_of_value() {
			output.write(&[trie_constants::DEAD_HEADER_META_HASHED_VALUE]);
		}
		match self {
			NodeHeader::Null => output.push_byte(trie_constants::EMPTY_TRIE),
			NodeHeader::Branch(true, nibble_count)	=>
				encode_size_and_prefix(*nibble_count, trie_constants::BRANCH_WITH_MASK, 2, output),
			NodeHeader::Branch(false, nibble_count) =>
				encode_size_and_prefix(*nibble_count, trie_constants::BRANCH_WITHOUT_MASK, 2, output),
			NodeHeader::Leaf(nibble_count) =>
				encode_size_and_prefix(*nibble_count, trie_constants::LEAF_PREFIX_MASK, 2, output),
			NodeHeader::AltHashBranch(nibble_count, _)	=>
				encode_size_and_prefix(*nibble_count, trie_constants::ALT_HASHING_BRANCH_WITH_MASK, 4, output),
			NodeHeader::AltHashLeaf(nibble_count, _)	=>
				encode_size_and_prefix(*nibble_count, trie_constants::ALT_HASHING_LEAF_PREFIX_MASK, 3, output),
		}
	}
}

impl NodeHeader {
	/// Is this header using alternate hashing scheme.
	pub(crate) fn alt_hashing(&self) -> bool {
		match self {
			NodeHeader::Null
			| NodeHeader::Leaf(..)
			| NodeHeader::Branch(..) => false,
			NodeHeader::AltHashBranch(..)
			| NodeHeader::AltHashLeaf(..) => true,
		}
	}
}

impl parity_scale_codec::EncodeLike for NodeHeader {}

impl Decode for NodeHeader {
	fn decode<I: Input>(input: &mut I) -> Result<Self, Error> {
		let mut i = input.read_byte()?;
		if i == trie_constants::EMPTY_TRIE {
			return Ok(NodeHeader::Null);
		}
		let contain_hash = if trie_constants::DEAD_HEADER_META_HASHED_VALUE == i {
			i = input.read_byte()?;
			true
		} else {
			false
		};
		match i & (0b11 << 6) {
			trie_constants::LEAF_PREFIX_MASK => Ok(NodeHeader::Leaf(decode_size(i, input, 2)?)),
			trie_constants::BRANCH_WITH_MASK => Ok(NodeHeader::Branch(true, decode_size(i, input, 2)?)),
			trie_constants::BRANCH_WITHOUT_MASK => Ok(NodeHeader::Branch(false, decode_size(i, input, 2)?)),
			trie_constants::EMPTY_TRIE => {
				if i & (0b111 << 5) == trie_constants::ALT_HASHING_LEAF_PREFIX_MASK {
					Ok(NodeHeader::AltHashLeaf(decode_size(i, input, 3)?, contain_hash))
				} else if i & (0b1111 << 4) == trie_constants::ALT_HASHING_BRANCH_WITH_MASK {
					Ok(NodeHeader::AltHashBranch(decode_size(i, input, 4)?, contain_hash))
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
	where W: Output + ?Sized,
{
	for b in size_and_prefix_iterator(size, prefix, prefix_mask) {
		out.push_byte(b)
	}
}

/// Decode size only from stream input and header byte.
fn decode_size(
	first: u8,
	input: &mut impl Input,
	prefix_mask: usize,
) -> Result<usize, Error> {
	let max_value = 255u8 >> prefix_mask;
	let mut result = (first & max_value) as usize;
	if result < max_value as usize {
		return Ok(result);
	}
	result -= 1;
	while result <= trie_constants::NIBBLE_SIZE_BOUND {
		let n = input.read_byte()? as usize;
		if n < 255 {
			return Ok(result + n + 1);
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
	/// Global trie alt hashing activation.
	inner_value_hashing: Option<u32>,
	/// For current node, do we use alt hashing.
	apply_inner_hashing: bool,
	/// Keep trace of position of encoded value.
	current_value_range: Option<Range<usize>>,
}

/// Create a leaf/branch node, encoding a number of nibbles.
fn fuse_nibbles_node<'a>(nibbles: &'a [u8], kind: NodeKind) -> impl Iterator<Item = u8> + 'a {
	let size = std::cmp::min(trie_constants::NIBBLE_SIZE_BOUND, nibbles.len());

	let iter_start = match kind {
		NodeKind::Leaf => size_and_prefix_iterator(size, trie_constants::LEAF_PREFIX_MASK, 2),
		NodeKind::BranchNoValue => size_and_prefix_iterator(size, trie_constants::BRANCH_WITHOUT_MASK, 2),
		NodeKind::BranchWithValue => size_and_prefix_iterator(size, trie_constants::BRANCH_WITH_MASK, 2),
		NodeKind::AltHashLeaf =>
			size_and_prefix_iterator(size, trie_constants::ALT_HASHING_LEAF_PREFIX_MASK, 3),
		NodeKind::AltHashBranchWithValue =>
			size_and_prefix_iterator(size, trie_constants::ALT_HASHING_BRANCH_WITH_MASK, 4),
		NodeKind::AltHashBranchWithValueHash
		| NodeKind::AltHashLeafHash => unreachable!("only added value that do not contain hash"),
	};
	iter_start
		.chain(if nibbles.len() % 2 == 1 { Some(nibbles[0]) } else { None })
		.chain(nibbles[nibbles.len() % 2..].chunks(2).map(|ch| ch[0] << 4 | ch[1]))
}
fn value_do_hash_stream(val: &[u8], threshold: &u32) -> bool {
	val.encoded_size() >= *threshold as usize
}
impl TrieStream for ReferenceTrieStreamNoExt {
	fn new(meta: Option<u32>) -> Self {
		Self {
			buffer: Vec::new(),
			inner_value_hashing: meta,
			apply_inner_hashing: false,
			current_value_range: None,
		}
	}

	fn append_empty_data(&mut self) {
		self.buffer.push(trie_constants::EMPTY_TRIE);
	}

	fn append_leaf(&mut self, key: &[u8], value: &[u8]) {
		self.apply_inner_hashing = self.inner_value_hashing.as_ref().map(|threshold|
			value_do_hash_stream(value, threshold)
		).unwrap_or(false);
		let kind = if self.apply_inner_hashing {
			NodeKind::AltHashLeaf
		} else {
			NodeKind::Leaf
		};
		self.buffer.extend(fuse_nibbles_node(key, kind));
		let start = self.buffer.len();
		Compact(value.len() as u32).encode_to(&mut self.buffer);
		self.buffer.extend_from_slice(value);
		self.current_value_range = Some(start..self.buffer.len());
	}

	fn begin_branch(
		&mut self,
		maybe_partial: Option<&[u8]>,
		maybe_value: Option<&[u8]>,
		has_children: impl Iterator<Item = bool>,
	) {
		if let Some(partial) = maybe_partial {
			if let Some(value) = maybe_value {
				self.apply_inner_hashing = self.inner_value_hashing.as_ref().map(|threshold|
					value_do_hash_stream(value, threshold)
				).unwrap_or(false);
				let kind = if self.apply_inner_hashing {
					NodeKind::AltHashBranchWithValue
				} else {
					NodeKind::BranchWithValue
				};
				self.buffer.extend(fuse_nibbles_node(partial, kind));
			} else {
				self.buffer.extend(fuse_nibbles_node(partial, NodeKind::BranchNoValue));
			}
			let bm = branch_node_bit_mask(has_children);
			self.buffer.extend([bm.0,bm.1].iter());
		} else {
			debug_assert!(false, "trie stream codec only for no extension trie");
			self.buffer.extend(&branch_node(maybe_value.is_some(), has_children));
		}
		if let Some(value) = maybe_value {
			let start = self.buffer.len();
			Compact(value.len() as u32).encode_to(&mut self.buffer);
			self.buffer.extend_from_slice(value);
			self.current_value_range = Some(start..self.buffer.len());
		}
	}

	fn append_extension(&mut self, _key: &[u8]) {
		debug_assert!(false, "trie stream codec only for no extension trie");
	}

	fn append_substream<H: Hasher>(&mut self, other: Self) {
		let apply_inner_hashing = other.apply_inner_hashing;
		let range = other.current_value_range.clone();
		let data = other.out();
		match data.len() {
			0..=31 => data.encode_to(&mut self.buffer),
			_ => {
				if apply_inner_hashing {
					hash_db::AltHashing {
						encoded_offset: 0,
						value_range: range.map(|r| (r.start, r.end)),
					}.alt_hash::<H>(&data).as_ref()
						.encode_to(&mut self.buffer);
				} else {
					H::hash(&data).as_ref().encode_to(&mut self.buffer);
				}
			},
		}
	}

	fn hash_root<H: Hasher>(self) -> H::Out {
		let apply_inner_hashing = self.apply_inner_hashing;
		let range = self.current_value_range;
		let data = self.buffer;

		if apply_inner_hashing {
			hash_db::AltHashing {
				encoded_offset: 0,
				value_range: range.map(|r| (r.start, r.end)),
			}.alt_hash::<H>(&data)
		} else {
			H::hash(&data)
		}
	}

	fn out(self) -> Vec<u8> { self.buffer }
}

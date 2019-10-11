// Copyright 2019 Parity Technologies
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
use parity_scale_codec::{Decode, Input, Output, Encode, Error as CodecError};
use trie_db::{NibbleSlice, nibble_ops};

use crate::node::{ProofBranchChild, ProofBranchValue, ProofNode, ProofNodeCodec};
use crate::std::{cmp, iter, result::Result, vec::Vec};
use crate::reference_codec::util::{
    decode_branch_value, decode_branch_children, encode_branch_value, encode_branch_children, take,
};

const EMPTY_TRIE: u8 = 0;
const NIBBLE_SIZE_BOUND: usize = u16::max_value() as usize;
const LEAF_PREFIX_MASK: u8 = 0b_01 << 6;
const BRANCH_WITHOUT_MASK: u8 = 0b_10 << 6;
const BRANCH_WITH_MASK: u8 = 0b_11 << 6;

/// A `ProofNodeCodec` implementation for without extension and where branch nodes include partial
/// keys. The codec is compatible with any `Hasher`.
#[derive(Default, Clone)]
pub struct ReferenceProofNodeCodec;

impl<H: Hasher> ProofNodeCodec<H> for ReferenceProofNodeCodec {
    type Error = CodecError;

    fn decode(data: &[u8]) -> Result<ProofNode, Self::Error> {
        let input = &mut &*data;
        match NodeHeader::decode(input)? {
            NodeHeader::Null => Ok(ProofNode::Empty),
            NodeHeader::Leaf(nibble_count) => {
                let partial_key = decode_partial(input, nibble_count)?;
                Ok(ProofNode::Leaf { partial_key })
            }
            NodeHeader::Branch(has_value, nibble_count) => {
                let partial_key = decode_partial(input, nibble_count)?;
                let value = decode_branch_value(input, has_value)?;
                let children = decode_branch_children(input)?;
                Ok(ProofNode::NibbledBranch { partial_key, children, value })
            }
        }
    }

    fn try_decode_hash(data: &[u8]) -> Option<<H as Hasher>::Out> {
        if data.len() == H::LENGTH {
            let mut r = <H as Hasher>::Out::default();
            r.as_mut().copy_from_slice(data);
            Some(r)
        } else {
            None
        }
    }

    fn empty_node() -> &'static[u8] {
        &[EMPTY_TRIE]
    }

    fn leaf_node(partial: impl Iterator<Item = u8>, number_nibble: usize) -> Vec<u8> {
        assert!(number_nibble < NIBBLE_SIZE_BOUND as usize);

        let mut output = Vec::with_capacity(3 + (number_nibble / nibble_ops::NIBBLE_PER_BYTE));
        NodeHeader::Leaf(number_nibble).encode_to(&mut output);
        output.extend(partial);
        output
    }

    fn extension_node(_partial: impl Iterator<Item = u8>, _number_nibble: usize) -> Vec<u8> {
        unreachable!()
    }

    fn branch_node<'a>(
        _children: &'a [ProofBranchChild<'a>; nibble_ops::NIBBLE_LENGTH],
        _value: &ProofBranchValue<'a>,
    ) -> Vec<u8>
    {
        unreachable!()
    }

    fn branch_node_nibbled<'a>(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
        children: &'a [ProofBranchChild<'a>; nibble_ops::NIBBLE_LENGTH],
        value: &ProofBranchValue<'a>,
    ) -> Vec<u8>
    {
        assert!(number_nibble < NIBBLE_SIZE_BOUND as usize);

        let has_value = *value != ProofBranchValue::Empty;
        let mut output = NodeHeader::Branch(has_value, number_nibble).encode();
        output.extend(partial);
        encode_branch_value(&mut output, value);
        encode_branch_children(&mut output, children);
        output
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum NodeHeader {
    Null,
    Leaf(usize),
    Branch(bool, usize),
}

impl Encode for NodeHeader {
    fn encode_to<T: Output>(&self, output: &mut T) {
        match self {
            NodeHeader::Null => output.push_byte(EMPTY_TRIE),
            NodeHeader::Leaf(nibble_count) =>
                encode_size_and_prefix(*nibble_count, LEAF_PREFIX_MASK, output),
            NodeHeader::Branch(true, nibble_count) =>
                encode_size_and_prefix(*nibble_count, BRANCH_WITH_MASK, output),
            NodeHeader::Branch(false, nibble_count) =>
                encode_size_and_prefix(*nibble_count, BRANCH_WITHOUT_MASK, output),
        }
    }
}

impl Decode for NodeHeader {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let i = input.read_byte()?;
        if i == EMPTY_TRIE {
            return Ok(NodeHeader::Null);
        }
        match i & (0b11 << 6) {
            LEAF_PREFIX_MASK =>
                Ok(NodeHeader::Leaf(decode_size(i, input)?)),
            BRANCH_WITHOUT_MASK =>
                Ok(NodeHeader::Branch(false, decode_size(i, input)?)),
            BRANCH_WITH_MASK =>
                Ok(NodeHeader::Branch(true, decode_size(i, input)?)),
            // do not allow any special encoding
            _ => Err("Unknown type of node".into()),
        }
    }
}

/// Encode and allocate node type header (type and size), and partial value.
/// It uses an iterator over encoded partial bytes as input.
fn size_and_prefix_iterator(size: usize, prefix: u8) -> impl Iterator<Item = u8> {
    let size = cmp::min(NIBBLE_SIZE_BOUND, size);

    let l1 = cmp::min(62, size);
    let (first_byte, mut rem) = if size == l1 {
        (iter::once(prefix + l1 as u8), 0)
    } else {
        (iter::once(prefix + 63), size - l1)
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
    first_byte.chain(iter::from_fn(next_bytes))
}

fn encode_size_and_prefix(size: usize, prefix: u8, out: &mut impl Output) {
    for b in size_and_prefix_iterator(size, prefix) {
        out.push_byte(b)
    }
}

fn decode_size<I: Input>(first: u8, input: &mut I) -> Result<usize, CodecError> {
    let mut result = (first & 255u8 >> 2) as usize;
    if result < 63 {
        return Ok(result);
    }
    result -= 1;
    while result <= NIBBLE_SIZE_BOUND {
        let n = input.read_byte()? as usize;
        if n < 255 {
            return Ok(result + n + 1);
        }
        result += 255;
    }
    Err("Size limit reached for a nibble slice".into())
}

fn decode_partial<'a>(input: &mut &'a [u8], nibble_count: usize)
    -> Result<NibbleSlice<'a>, CodecError>
{
    let padding = nibble_count % nibble_ops::NIBBLE_PER_BYTE != 0;
    // check that the padding is valid (if any)
    if padding && nibble_ops::pad_left(input[0]) != 0 {
        return Err(CodecError::from("Bad format"));
    }
    let nibble_data = take(
        input,
        (nibble_count + (nibble_ops::NIBBLE_PER_BYTE - 1)) / nibble_ops::NIBBLE_PER_BYTE,
    ).ok_or(CodecError::from("Bad format"))?;
    let nibble_slice = NibbleSlice::new_offset(
        nibble_data,
        nibble_ops::number_padding(nibble_count),
    );
    Ok(nibble_slice)
}

#[cfg(test)]
mod tests {
    use super::*;
    use keccak_hasher::KeccakHasher;

    #[test]
    fn empty_encode_decode() {
        let encoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::empty_node();
        let decoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::decode(encoded).unwrap();
        assert_eq!(decoded, ProofNode::Empty);
    }

    #[test]
    fn leaf_encode_decode() {
        let partial_key = NibbleSlice::new(b"tralala");
        let encoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::leaf_node(partial_key.right_iter(), partial_key.len());
        let decoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::decode(&encoded).unwrap();
        assert_eq!(decoded, ProofNode::Leaf { partial_key });

        let partial_key = NibbleSlice::new_offset(b"tralala", 1);
        let encoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::leaf_node(partial_key.right_iter(), partial_key.len());
        let decoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::decode(&encoded).unwrap();
        assert_eq!(decoded, ProofNode::Leaf { partial_key });
    }

    #[test]
    fn branch_encode_decode() {
        let mut children = [ProofBranchChild::Empty; nibble_ops::NIBBLE_LENGTH];
        children[2] = ProofBranchChild::Omitted;
        children[3] = ProofBranchChild::Included(b"value 3");
        children[7] = ProofBranchChild::Included(b"value 7");
        children[12] = ProofBranchChild::Omitted;

        let partial_keys = [
            NibbleSlice::new_offset(b"tralala", 0),
            NibbleSlice::new_offset(b"tralala", 1),
        ];
        let values = [
            ProofBranchValue::Empty,
            ProofBranchValue::Omitted,
            ProofBranchValue::Included(b"value"),
        ];
        for partial_key in partial_keys.iter() {
            for value in values.iter() {
                let encoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
                    ::branch_node_nibbled(
                        partial_key.right_iter(),
                        partial_key.len(),
                        &children,
                        &value,
                    );
                let decoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
                    ::decode(&encoded).unwrap();
                assert_eq!(
                    decoded,
                    ProofNode::NibbledBranch { partial_key: *partial_key, children, value: *value }
                );
            }
        }
    }
}
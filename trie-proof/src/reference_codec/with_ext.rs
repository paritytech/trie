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
use crate::std::{result::Result, vec::Vec};
use crate::reference_codec::util::{
    decode_branch_value, decode_branch_children, encode_branch_children, encode_branch_value, take,
};

const EMPTY_TRIE: u8 = 0;
const LEAF_NODE_OFFSET: u8 = 1;
const EXTENSION_NODE_OFFSET: u8 = 128;
const BRANCH_NODE_NO_VALUE: u8 = 254;
const BRANCH_NODE_WITH_VALUE: u8 = 255;
const LEAF_NODE_OVER: u8 = EXTENSION_NODE_OFFSET - LEAF_NODE_OFFSET;
const EXTENSION_NODE_OVER: u8 = BRANCH_NODE_NO_VALUE - EXTENSION_NODE_OFFSET;
const LEAF_NODE_LAST: u8 = EXTENSION_NODE_OFFSET - 1;
const EXTENSION_NODE_LAST: u8 = BRANCH_NODE_NO_VALUE - 1;

/// A `ProofNodeCodec` implementation for with extension and where branch nodes do not include
/// partial keys. The codec is compatible with any `Hasher`.
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
            NodeHeader::Extension(nibble_count) => {
                let partial_key = decode_partial(input, nibble_count)?;
                Ok(ProofNode::Extension { partial_key })
            }
            NodeHeader::Branch(has_value) => {
                let value = decode_branch_value(input, has_value)?;
                let children = decode_branch_children(input)?;
                Ok(ProofNode::Branch { children, value })
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
        assert!(number_nibble < LEAF_NODE_OVER as usize);

        let mut output = Vec::with_capacity(1 + (number_nibble / nibble_ops::NIBBLE_PER_BYTE));
        NodeHeader::Leaf(number_nibble).encode_to(&mut output);
        output.extend(partial);
        output
    }

    fn extension_node(partial: impl Iterator<Item = u8>, number_nibble: usize) -> Vec<u8> {
        assert!(number_nibble < EXTENSION_NODE_OVER as usize);

        let mut output = Vec::with_capacity(1 + (number_nibble / nibble_ops::NIBBLE_PER_BYTE));
        NodeHeader::Extension(number_nibble).encode_to(&mut output);
        output.extend(partial);
        output
    }

    fn branch_node<'a>(
        children: &'a [ProofBranchChild<'a>; nibble_ops::NIBBLE_LENGTH],
        value: &ProofBranchValue<'a>,
    ) -> Vec<u8>
    {
        let has_value = *value != ProofBranchValue::Empty;
        let mut output = NodeHeader::Branch(has_value).encode();
        encode_branch_value(&mut output, value);
        encode_branch_children(&mut output, children);
        output
    }

    fn branch_node_nibbled<'a>(
        _partial: impl Iterator<Item = u8>,
        _number_nibble: usize,
        _children: &'a [ProofBranchChild<'a>; nibble_ops::NIBBLE_LENGTH],
        _value: &ProofBranchValue<'a>,
    ) -> Vec<u8>
    {
        unreachable!();
    }
}

#[derive(Copy, Clone, PartialEq, Eq, Debug)]
enum NodeHeader {
    Null,
    Leaf(usize),
    Extension(usize),
    Branch(bool),
}

impl Encode for NodeHeader {
    fn encode_to<T: Output>(&self, output: &mut T) {
        match self {
            NodeHeader::Null => output.push_byte(EMPTY_TRIE),
            NodeHeader::Leaf(nibble_count) =>
                output.push_byte(LEAF_NODE_OFFSET + *nibble_count as u8),
            NodeHeader::Extension(nibble_count) =>
                output.push_byte(EXTENSION_NODE_OFFSET + *nibble_count as u8),
            NodeHeader::Branch(true) => output.push_byte(BRANCH_NODE_WITH_VALUE),
            NodeHeader::Branch(false) => output.push_byte(BRANCH_NODE_NO_VALUE),
        }
    }
}

impl Decode for NodeHeader {
    fn decode<I: Input>(input: &mut I) -> Result<Self, CodecError> {
        let byte = input.read_byte()?;
        Ok(match byte {
            EMPTY_TRIE => NodeHeader::Null,
            LEAF_NODE_OFFSET..=LEAF_NODE_LAST =>
                NodeHeader::Leaf((byte - LEAF_NODE_OFFSET) as usize),
            EXTENSION_NODE_OFFSET ..= EXTENSION_NODE_LAST =>
                NodeHeader::Extension((byte - EXTENSION_NODE_OFFSET) as usize),
            BRANCH_NODE_NO_VALUE => NodeHeader::Branch(false),
            BRANCH_NODE_WITH_VALUE => NodeHeader::Branch(true),
        })
    }
}

fn decode_partial<'a>(input: &mut &'a [u8], nibble_count: usize)
    -> Result<NibbleSlice<'a>, CodecError>
{
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
    fn extension_encode_decode() {
        let partial_key = NibbleSlice::new(b"tralala");
        let encoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::extension_node(partial_key.right_iter(), partial_key.len());
        let decoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::decode(&encoded).unwrap();
        assert_eq!(decoded, ProofNode::Extension { partial_key });

        let partial_key = NibbleSlice::new_offset(b"tralala", 1);
        let encoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::extension_node(partial_key.right_iter(), partial_key.len());
        let decoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::decode(&encoded).unwrap();
        assert_eq!(decoded, ProofNode::Extension { partial_key });
    }

    #[test]
    fn branch_encode_decode() {
        let mut children = [ProofBranchChild::Empty; nibble_ops::NIBBLE_LENGTH];
        children[2] = ProofBranchChild::Omitted;
        children[3] = ProofBranchChild::Included(b"value 3");
        children[7] = ProofBranchChild::Included(b"value 7");
        children[12] = ProofBranchChild::Omitted;

        let values = [
            ProofBranchValue::Empty,
            ProofBranchValue::Omitted,
            ProofBranchValue::Included(b"value"),
        ];
        for value in values.iter() {
            let encoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::branch_node(&children, &value);
            let decoded = <ReferenceProofNodeCodec as ProofNodeCodec<KeccakHasher>>
            ::decode(&encoded).unwrap();
            assert_eq!(decoded, ProofNode::Branch { children, value: *value });
        }
    }
}

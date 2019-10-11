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

//! The data structures included in the proof.

use crate::std::{self, vec::Vec};

use hash_db::Hasher;
use trie_db::{NibbleSlice, nibble_ops::NIBBLE_LENGTH};

/// A child entry in a proof branch node.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ProofBranchChild<'a> {
    Empty,
    Omitted,
    Included(&'a [u8]),
}

/// A child value in a proof branch node.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ProofBranchValue<'a> {
    Empty,
    Omitted,
    Included(&'a [u8]),
}

/// A proof node.
#[derive(Clone, Copy, PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum ProofNode<'a> {
    /// Null trie node; could be an empty root or an empty branch entry.
    Empty,
    /// Leaf node; has key slice and an omitted value.
    Leaf {
        partial_key: NibbleSlice<'a>,
    },
    /// Extension node; has key slice and an omitted child node reference.
    Extension {
        partial_key: NibbleSlice<'a>,
    },
    /// Branch node; has slice of children which may be empty, omitted, or included and a value,
    /// which also may be empty, omitted, or included.
    Branch {
        children: [ProofBranchChild<'a>; NIBBLE_LENGTH],
        value: ProofBranchValue<'a>,
    },
    /// Branch node with key slice. This is used as an alternative to extension nodes in some trie
    /// layouts.
    NibbledBranch {
        partial_key: NibbleSlice<'a>,
        children: [ProofBranchChild<'a>; NIBBLE_LENGTH],
        value: ProofBranchValue<'a>,
    }
}

/// Trait for proof node encoding/decoding.
pub trait ProofNodeCodec<H>: Sized
    where H: Hasher
{
    /// Codec error type.
    type Error: std::error::Error;

    /// Decode bytes to a `ProofNode`. Returns `Self::Error` on failure.
    fn decode(data: &[u8]) -> Result<ProofNode, Self::Error>;

    /// Decode bytes to the `Hasher`s output type. Returns `None` on failure.
    fn try_decode_hash(data: &[u8]) -> Option<H::Out>;

    /// Returns an encoded empty node.
    fn empty_node() -> &'static [u8];

    /// Returns an encoded leaf node.
    fn leaf_node(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
    ) -> Vec<u8>;

    /// Returns an encoded extension node.
    fn extension_node(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
    ) -> Vec<u8>;

    /// Returns an encoded branch node.
    fn branch_node<'a>(
        children: &'a [ProofBranchChild<'a>; NIBBLE_LENGTH],
        value: &ProofBranchValue<'a>,
    ) -> Vec<u8>;

    /// Returns an encoded branch node with a possible partial path.
    fn branch_node_nibbled<'a>(
        partial: impl Iterator<Item = u8>,
        number_nibble: usize,
        children: &'a [ProofBranchChild<'a>; NIBBLE_LENGTH],
        value: &ProofBranchValue<'a>,
    ) -> Vec<u8>;
}

/// Encode a proof node to a new byte vector.
pub fn encode_proof_node<C, H>(node: &ProofNode) -> Vec<u8>
    where
        C: ProofNodeCodec<H>,
        H: Hasher,
{
    match node {
        ProofNode::Empty => C::empty_node().to_vec(),
        ProofNode::Leaf { partial_key } => C::leaf_node(
            partial_key.right_iter(),
            partial_key.len(),
        ),
        ProofNode::Extension { partial_key } => C::extension_node(
            partial_key.right_iter(),
            partial_key.len(),
        ),
        ProofNode::Branch { children, value } => C::branch_node(children, value),
        ProofNode::NibbledBranch { partial_key, children, value } => C::branch_node_nibbled(
            partial_key.right_iter(),
            partial_key.len(),
            children,
            value
        ),
    }
}

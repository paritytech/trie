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

//! Generation and verification of compact proofs for Merkle-Patricia tries.
//!
//! Using this library, it is possible to generate a logarithm-space proof of inclusion or
//! non-inclusion of certain key-value pairs in a trie with a known root. The proof contains
//! information so that the verifier can reconstruct the subset of nodes in the trie required to
//! lookup the keys. The trie nodes are not included in their entirety as data which the verifier
//! can compute for themself is omitted. In particular, the values of included keys and and hashes
//! of other trie nodes in the proof are omitted.
//!
//! The proof is a sequence of the subset of nodes in the trie traversed while performing lookups
//! on all keys. The trie nodes are listed in post-order traversal order with some values and
//! internal hashes omitted. In particular, values on leaf nodes, child references on extension
//! nodes, values on branch nodes corresponding to a key in the statement, and child references on
//! branch nodes corresponding to another node in the proof are all omitted. The proof is verified
//! by iteratively reconstructing the trie nodes using the values proving as part of the statement
//! and the hashes of other reconstructed nodes. Since the nodes in the proof are arranged in
//! post-order traversal order, the construction can be done efficiently using a stack.

#[cfg(not(feature = "std"))]
extern crate alloc;

#[cfg(feature = "std")]
extern crate std;

#[cfg(not(feature = "std"))]
mod std {
    pub use core::cmp;
    pub use core::result;
    pub use alloc::vec;

    pub mod error {
        pub trait Error {}
		impl<T> Error for T {}
    }
}

pub mod node;
pub mod reference_codec;
mod util;

#[cfg(test)]
mod tests;

use hash_db::{HashDB, Hasher, EMPTY_PREFIX};
use trie_db::{
    ChildReference, DBValue, NodeCodec, Recorder, Trie, TrieDB, TrieLayout,
    nibble_ops::NIBBLE_LENGTH, node::Node,
};
use crate::std::{result::Result, vec::Vec};

use crate::node::{
    ProofNode, ProofBranchChild, ProofBranchValue, ProofNodeCodec, encode_proof_node,
};
use crate::util::{LeftAlignedNibbleSlice, post_order_compare};

type MemoryDB<H> = memory_db::MemoryDB<H, memory_db::HashKey<H>, DBValue>;

//! A compact proof of a set of key-value lookups in a trie with respect to a known root.
pub struct Proof {
    nodes: Vec<Vec<u8>>,
}

//! Generate a compact proof for key-value pairs in a trie given a set of keys.
pub fn generate_proof<'a, T, L, C, I, K>(trie: &T, keys: I) -> Result<Proof, &'static str>
    where
        T: Trie<L>,
        L: TrieLayout,
        C: ProofNodeCodec<L::Hash>,
        I: IntoIterator<Item=&'a K>,
        K: 'a + AsRef<[u8]>
{
    /// Sort items in post-order traversal order by key.
    let mut keys = keys.into_iter()
        .map(|key| key.as_ref())
        .collect::<Vec<_>>();
    keys.sort_by(|a, b| post_order_compare(a, b));

    // Look up all keys in order and record the nodes traversed during lookups.
    //
    // Ideally, we would only store the recorded nodes for one key at a time in memory, making the
    // memory requirements O(d) where d is the depth of the tree. However, borrowck makes this
    // difficult, so instead we store all recorded nodes for all keys in memory, making the memory
    // requirements O(d * k), where k is the number of keys.
    let mut recorder = Recorder::new();
    let values = keys.iter()
        .map(|key| {
            trie.get_with(key, &mut recorder)
                .map_err(|_| "failed to lookup key in trie")
        })
        .collect::<Result<Vec<_>, _>>()?;

    let recorded_nodes = recorder.drain();
    let mut recorded_nodes_iter = recorded_nodes.iter();

    // Stack of trie nodes traversed with additional information to construct proof nodes.
    struct NodeStackEntry<'a> {
        key: LeftAlignedNibbleSlice<'a>,
        node: Node<'a>,
        omit_branch_value: bool,
        omit_branch_children: [bool; NIBBLE_LENGTH],
    }
    let mut node_stack = <Vec<NodeStackEntry>>::new();

    // The nodes composing the final proof.
    let mut proof_nodes = Vec::new();

    for (key, expected_value) in keys.iter().zip(values.into_iter()) {
        let key_nibbles = LeftAlignedNibbleSlice::new(key);

        // Find last common trie node in the stack on the path to the new key. After this we are
        // guaranteed that until the end of the loop body that all stack entries will have a key
        // that is a prefix of the current key.
        while let Some(entry) = node_stack.pop() {
            if key_nibbles.starts_with(&entry.key) {
                node_stack.push(entry);
                break;
            } else {
                // Pop and finalize node from the stack that is not on the path to the current key.
                let proof_node = new_proof_node(
                    entry.node, entry.omit_branch_value, entry.omit_branch_children
                );
                proof_nodes.push(encode_proof_node::<C, L::Hash>(&proof_node));
            }
        }

        enum Step<'a> {
            FirstEntry,
            Descend(usize, &'a [u8]),
            FoundValue(Option<&'a [u8]>),
        }
        loop {
            let step = match node_stack.last_mut() {
                Some(entry) => match entry.node {
                    Node::Empty => Step::FoundValue(None),
                    Node::Leaf(partial_key, value) => {
                        if key_nibbles.contains(partial_key, entry.key.len()) &&
                            key_nibbles.len() == entry.key.len() + partial_key.len()
                        {
                            Step::FoundValue(Some(value))
                        } else {
                            Step::FoundValue(None)
                        }
                    }
                    Node::Extension(partial_key, child_data) => {
                        if key_nibbles.contains(partial_key, entry.key.len()) &&
                            key_nibbles.len() >= entry.key.len() + partial_key.len()
                        {
                            let child_key_len = entry.key.len() + partial_key.len();
                            Step::Descend(child_key_len, child_data)
                        } else {
                            Step::FoundValue(None)
                        }
                    }
                    Node::Branch(children, value) => {
                        if key_nibbles.len() == entry.key.len() {
                            entry.omit_branch_value = true;
                            Step::FoundValue(value)
                        } else {
                            let index = key_nibbles.at(entry.key.len())
                                .expect(
                                    "entry key is a prefix of key_nibbles due to stack invariant; \
                                    thus key_nibbles len is greater than equal to entry key; \
                                    also they are unequal due to else condition;
                                    qed"
                                )
                                as usize;
                            if let Some(child_data) = children[index] {
                                entry.omit_branch_children[index] = true;
                                let child_key_len = entry.key.len() + 1;
                                Step::Descend(child_key_len, child_data)
                            } else {
                                Step::FoundValue(None)
                            }
                        }
                    }
                    Node::NibbledBranch(partial_key, children, value) => {
                        if key_nibbles.contains(partial_key, entry.key.len()) {
                            if key_nibbles.len() == entry.key.len() + partial_key.len() {
                                entry.omit_branch_value = true;
                                Step::FoundValue(value)
                            } else {
                                let index = key_nibbles.at(entry.key.len() + partial_key.len())
                                    .expect(
                                        "key_nibbles contains partial key after entry key offset; \
                                        thus key_nibbles len is greater than equal to entry key len plus partial key len; \
                                        also they are unequal due to else condition;
                                        qed"
                                    )
                                    as usize;
                                if let Some(child_data) = children[index] {
                                    entry.omit_branch_children[index] = true;
                                    let child_key_len = entry.key.len() + partial_key.len() + 1;
                                    Step::Descend(child_key_len, child_data)
                                } else {
                                    Step::FoundValue(None)
                                }
                            }
                        } else {
                            Step::FoundValue(None)
                        }
                    }
                },
                None => Step::FirstEntry,
            };

            match step {
                Step::FirstEntry => {
                    let record = recorded_nodes_iter.next()
                        .ok_or_else(|| "out of recorded nodes")?;
                    let trie_node = L::Codec::decode(&record.data)
                        .map_err(|_| "failure to decode trie node")?;
                    node_stack.push(NodeStackEntry {
                        key: LeftAlignedNibbleSlice::new(&[]),
                        node: trie_node,
                        omit_branch_value: false,
                        omit_branch_children: [false; NIBBLE_LENGTH],
                    })
                },
                Step::Descend(child_key_len, child_ref) => {
                    let node_data = match L::Codec::try_decode_hash(child_ref) {
                        Some(hash) => {
                            // Since recorded nodes are listed in traversal order, the one we are
                            // looking for must be later in the sequence.
                            let child_record = recorded_nodes_iter
                                .find(|record| record.hash == hash)
                                .ok_or_else(|| "out of recorded nodes")?;
                            &child_record.data
                        }
                        None => child_ref,
                    };
                    let trie_node = L::Codec::decode(node_data)
                        .map_err(|_| "failure to decode trie node")?;
                    node_stack.push(NodeStackEntry {
                        key: key_nibbles.truncate(child_key_len),
                        node: trie_node,
                        omit_branch_value: false,
                        omit_branch_children: [false; NIBBLE_LENGTH],
                    })
                }
                Step::FoundValue(value) => {
                    if value != expected_value.as_ref().map(|v| v.as_ref()) {
                        return Err("different values between trie traversal and lookup");
                    }
                    break;
                }
            }
        }
    }

	// Pop and finalize remaining nodes in the stack.
    while let Some(entry) = node_stack.pop() {
        let proof_node = new_proof_node(
            entry.node, entry.omit_branch_value, entry.omit_branch_children
        );
        proof_nodes.push(encode_proof_node::<C, L::Hash>(&proof_node));
    }

	Ok(Proof { nodes: proof_nodes })
}

//! Verify a compact proof for key-value pairs in a trie given a root hash.
pub fn verify_proof<'a, L, C, I, K, V>(root: &<L::Hash as Hasher>::Out, proof: Proof, items: I)
    -> Result<(), &'static str>
    where
        L: TrieLayout,
        C: ProofNodeCodec<L::Hash>,
        I: IntoIterator<Item=&'a (K, Option<V>)>,
        K: 'a + AsRef<[u8]>,
        V: 'a + AsRef<[u8]>,
{
	/// Sort items in post-order traversal order by key.
    let mut items = items.into_iter()
        .map(|(k, v)| (k.as_ref(), v.as_ref().map(|v| v.as_ref())))
        .collect::<Vec<_>>();
    items.sort_by(|(a_key, _), (b_key, _)| post_order_compare(a_key, b_key));

    let mut items_iter = items.iter();

    // A stack of child references to fill in omitted branch children for later trie nodes in the
    // proof.
    let mut node_ref_stack = Vec::new();

	// A HashDB of the reconstructed trie nodes.
    let mut db = <MemoryDB<L::Hash>>::default();

	for encoded_proof_node in proof.nodes.iter() {
		let proof_node = C::decode(encoded_proof_node)
            .map_err(|_| "decoding failure")?;
        let trie_node = match proof_node {
            ProofNode::Empty => L::Codec::empty_node().to_vec(),
            ProofNode::Leaf { partial_key } => {
                let (_, value) = items_iter
                    .find(|(_key, value)| value.is_some())
                    .ok_or_else(|| "out of values")?;
                let value = value
                    .expect("value is guaranteed to be Some from find predicate; qed");
                L::Codec::leaf_node(partial_key.right(), value.as_ref())
            }
            ProofNode::Extension { partial_key } => {
                let child_ref = node_ref_stack.pop()
                    .ok_or_else(|| "referenced non-existent trie node")?;
                L::Codec::extension_node(
                    partial_key.right_iter(),
                    partial_key.len(),
                    child_ref,
                )
            },
            ProofNode::Branch { children, value } => {
                let (trie_children, trie_value) = handle_branch_node::<L::Hash, _>(
                    &mut node_ref_stack, &mut items_iter, children, value
                )?;
                L::Codec::branch_node(
                    trie_children.iter(),
                    trie_value,
                )
            }
            ProofNode::NibbledBranch { partial_key, children, value } => {
                let (trie_children, trie_value) = handle_branch_node::<L::Hash, _>(
                    &mut node_ref_stack, &mut items_iter, children, value
                )?;
				L::Codec::branch_node_nibbled(
                    partial_key.right_iter(),
                    partial_key.len(),
                    trie_children.iter(),
                    trie_value,
                )
            }
        };

        let trie_node_len = trie_node.len();
        let node_ref = if trie_node_len < L::Hash::LENGTH {
            let mut inline = <L::Hash as Hasher>::Out::default();
            inline.as_mut()[..trie_node_len].copy_from_slice(&trie_node);
            ChildReference::Inline(inline, trie_node_len)
        } else {
            let hash = db.insert(EMPTY_PREFIX, &trie_node);
            ChildReference::Hash(hash)
        };

        node_ref_stack.push(node_ref);
    }

    if node_ref_stack.len() != 1 {
        return Err("proof does not contain a single root trie node");
    }
    let root_ref = node_ref_stack.pop()
        .expect("length of node_ref_stack is guaranteed to be 1 above; qed");

    let root_hash = match root_ref {
        ChildReference::Inline(data, _) => db.insert(EMPTY_PREFIX, data.as_ref()),
        ChildReference::Hash(hash) => hash,
    };

    if root_hash != *root {
        return Err("root hash mismatch");
    }

	// Perform the key lookups on the reconstructed trie to ensure the values are correct.
    let trie = <TrieDB<L>>::new(&db, &root_hash)
        .map_err(|_| "could not construct trie")?;
    for (key, expected_value) in items.iter() {
        let actual_value = trie.get(key)
            .map_err(|_| "could not find key in trie subset")?;
        if actual_value.as_ref().map(|v| v.as_ref()) != *expected_value {
            return Err("incorrect value for key");
        }
    }

    Ok(())
}

fn handle_branch_node<'a, 'b, H, I>(
    node_ref_stack: &'b mut Vec<ChildReference<H::Out>>,
    items_iter: &'b mut I,
    children: [ProofBranchChild<'a>; NIBBLE_LENGTH],
    value: ProofBranchValue<'a>,
)
    -> Result<
        ([Option<ChildReference<H::Out>>; NIBBLE_LENGTH], Option<&'a [u8]>),
        &'static str
    >
    where
        H: Hasher,
        I: Iterator<Item=&'a (&'a [u8], Option<&'a [u8]>)>,
{
    let mut trie_children = [None; NIBBLE_LENGTH];
    for i in (0..NIBBLE_LENGTH).rev() {
        trie_children[i] = match children[i] {
            ProofBranchChild::Empty => None,
            ProofBranchChild::Omitted => {
                let child_ref = node_ref_stack.pop()
                    .ok_or_else(|| "referenced non-existent trie node")?;
                Some(child_ref)
            }
            ProofBranchChild::Included(node_data) => {
                let node_len = node_data.len();
                if node_len >= H::LENGTH {
                    return Err("inline branch child exceeds hash length");
                }
                let mut inline = H::Out::default();
                inline.as_mut()[..node_len].copy_from_slice(node_data);
                Some(ChildReference::Inline(inline, node_len))
            }
        };
    }
    let trie_value = match value {
        ProofBranchValue::Empty => None,
        ProofBranchValue::Omitted => {
            let (_key, value) = items_iter
                .find(|(_key, value)| value.is_some())
                .ok_or_else(|| "out of values")?;
            *value
        }
        ProofBranchValue::Included(value) => Some(value),
    };
    Ok((trie_children, trie_value))
}

fn new_proof_node(
    node: Node,
    omit_branch_value: bool,
    omit_branch_children: [bool; NIBBLE_LENGTH],
) -> ProofNode
{
    match node {
        Node::Empty => ProofNode::Empty,
        Node::Leaf(partial_key, _value) => ProofNode::Leaf { partial_key },
        Node::Extension(partial_key, _child) => ProofNode::Extension { partial_key },
        Node::Branch(children, value) => ProofNode::Branch {
            children: to_proof_children(children, omit_branch_children),
            value: to_proof_value(value, omit_branch_value),
        },
        Node::NibbledBranch(partial_key, children, value) => ProofNode::NibbledBranch {
            partial_key,
            children: to_proof_children(children, omit_branch_children),
            value: to_proof_value(value, omit_branch_value),
        },
    }
}

fn to_proof_children(
    children: [Option<&[u8]>; NIBBLE_LENGTH],
    omit_children: [bool; NIBBLE_LENGTH],
) -> [ProofBranchChild; NIBBLE_LENGTH]
{
    let mut proof_children = [ProofBranchChild::Empty; NIBBLE_LENGTH];
    for i in 0..NIBBLE_LENGTH {
        proof_children[i] = match children[i] {
            None => ProofBranchChild::Empty,
            Some(_) if omit_children[i] => ProofBranchChild::Omitted,
            Some(child_data) => ProofBranchChild::Included(child_data),
        };
    }
    proof_children
}

fn to_proof_value(value: Option<&[u8]>, omit_value: bool) -> ProofBranchValue {
    match value {
        None => ProofBranchValue::Empty,
        Some(_) if omit_value => ProofBranchValue::Omitted,
        Some(value) => ProofBranchValue::Included(value),
    }
}

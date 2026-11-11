// Copyright 2026 Parity Technologies
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

use reference_trie::{ExtensionLayout, NoExtensionLayout};
use std::mem::size_of;
use trie_db::{
	nibble_ops::NIBBLE_LENGTH,
	node::{Node, NodeHandle, NodeHandleOwned, NodeOwned, Value},
	NibbleSlice, NodeCodec, TrieHash, TrieLayout,
};

type Hash = TrieHash<ExtensionLayout>;
type Owned = NodeOwned<Hash>;
type Codec = <ExtensionLayout as TrieLayout>::Codec;

const HASH: [u8; 32] = [0x5a; 32];
/// Heap bytes one stored child costs.
const SLOT: usize = size_of::<Option<NodeHandleOwned<Hash>>>();

fn inline_leaf() -> Vec<u8> {
	let partial = NibbleSlice::new(&[0xab]);
	Codec::leaf_node(partial.right_iter(), partial.len(), Value::Inline(b"v"))
}

/// A branch with a hash child at each of `hashes` and an inline leaf at each of `inlines`.
fn branch(hashes: &[usize], inlines: &[usize], leaf: &[u8]) -> Owned {
	let mut children = [None; NIBBLE_LENGTH];
	hashes.iter().for_each(|i| children[*i] = Some(NodeHandle::Hash(&HASH)));
	inlines.iter().for_each(|i| children[*i] = Some(NodeHandle::Inline(leaf)));
	Node::Branch(children, None).to_owned_node::<ExtensionLayout>().unwrap()
}

fn all() -> Vec<usize> {
	(0..NIBBLE_LENGTH).collect()
}

#[test]
fn size_in_bytes_counts_the_children_buffer() {
	let full = branch(&all(), &[], &[]);
	assert_eq!(full.size_in_bytes(), size_of::<Owned>() + NIBBLE_LENGTH * SLOT);
}

#[test]
fn size_in_bytes_counts_the_children_buffer_of_a_nibbled_branch() {
	let children = [Some(NodeHandle::Hash(&HASH)); NIBBLE_LENGTH];
	let partial = NibbleSlice::new(&[0xab]);
	let node = Node::NibbledBranch(partial, children, None)
		.to_owned_node::<NoExtensionLayout>()
		.unwrap();
	let partial_bytes = node.partial_key().unwrap().inner().len();
	assert_eq!(node.size_in_bytes(), size_of::<Owned>() + partial_bytes + NIBBLE_LENGTH * SLOT);
}

#[test]
fn size_in_bytes_of_a_childless_branch_is_the_node_alone() {
	assert_eq!(branch(&[], &[], &[]).size_in_bytes(), size_of::<Owned>());
}

#[test]
fn sparse_branch_pays_only_for_existing_children() {
	// First and last nibble: the gap between them must cost nothing.
	let sparse = branch(&[0, 15], &[], &[]);
	assert_eq!(sparse.size_in_bytes(), size_of::<Owned>() + 2 * SLOT);
}

#[test]
fn size_in_bytes_counts_inline_children() {
	let leaf = inline_leaf();
	let inline_size = Codec::decode(&leaf)
		.unwrap()
		.to_owned_node::<ExtensionLayout>()
		.unwrap()
		.size_in_bytes();
	let node = branch(&[2], &[7], &leaf);
	assert_eq!(node.size_in_bytes(), size_of::<Owned>() + 2 * SLOT + inline_size);
}

#[test]
fn children_keep_their_nibble() {
	let leaf = inline_leaf();
	let (hashes, inlines) = ([1, 4, 15], [0, 9]);
	let node = branch(&hashes, &inlines, &leaf);
	let NodeOwned::Branch(children, None) = &node else { panic!("expected a branch") };

	let slots: Vec<_> = children.iter().collect();
	assert_eq!(slots.len(), NIBBLE_LENGTH);
	for i in all() {
		let expect_hash = hashes.contains(&i);
		let expect_inline = inlines.contains(&i);
		assert_eq!(children.get(i), slots[i].as_ref(), "nibble {i}");
		match children.get(i) {
			Some(NodeHandleOwned::Hash(h)) => assert!(expect_hash && h == &HASH, "nibble {}", i),
			Some(NodeHandleOwned::Inline(_)) => assert!(expect_inline, "nibble {}", i),
			None => assert!(!expect_hash && !expect_inline, "nibble {}", i),
		}
	}
	assert!(children.get(NIBBLE_LENGTH).is_none());
	assert!(children.get(usize::MAX).is_none());
	// One past the last existing child.
	assert_eq!(children.allocated_len(), 16);

	let nibbles: Vec<_> = node.child_iter().map(|(nibble, _)| nibble.unwrap()).collect();
	assert_eq!(nibbles, [0, 1, 4, 9, 15]);
}

#[test]
fn allocated_len_is_one_past_the_last_child() {
	for (hashes, expected) in [(&[][..], 0), (&[0], 1), (&[3, 6], 7), (&[15], 16)] {
		let NodeOwned::Branch(children, _) = branch(hashes, &[], &[]) else { unreachable!() };
		assert_eq!(children.allocated_len(), expected, "children at {hashes:?}");
	}
}

#[test]
fn owned_branch_encodes_like_the_borrowed_one() {
	let leaf = inline_leaf();
	for (hashes, inlines) in [(&[][..], &[][..]), (&[0, 15], &[]), (&[3], &[2, 8]), (&all(), &[])] {
		let node = branch(hashes, inlines, &leaf);
		let encoded = node.to_encoded::<Codec>();
		let decoded = Codec::decode(&encoded).unwrap().to_owned_node::<ExtensionLayout>().unwrap();
		assert!(decoded == node, "children at {:?} / {:?}", hashes, inlines);
		assert_eq!(decoded.child_iter().count(), hashes.len() + inlines.len());
	}
}

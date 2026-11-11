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
	ChildReference, NibbleSlice, NodeCodec, TrieHash, TrieLayout,
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

/// A different hash for each nibble, so a child can be told from its siblings.
fn distinct_hashes() -> Vec<Hash> {
	(0u8..16).map(|nibble| [nibble; 32]).collect()
}

fn owned(node: Node) -> Owned {
	node.to_owned_node::<ExtensionLayout>().unwrap()
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
		let child = children.get(i);
		assert_eq!(child, slots[i].as_ref(), "nibble {i}");
		match child {
			Some(NodeHandleOwned::Hash(h)) => assert!(expect_hash && h == &HASH, "nibble {}", i),
			Some(NodeHandleOwned::Inline(_)) => assert!(expect_inline, "nibble {}", i),
			None => assert!(!expect_hash && !expect_inline, "nibble {}", i),
		}
	}
	assert!(children.get(NIBBLE_LENGTH).is_none());
	assert!(children.get(usize::MAX).is_none());

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
fn every_child_keeps_its_nibble_for_every_presence_pattern() {
	let hashes = distinct_hashes();
	for mask in 0..=u16::MAX {
		let exists = |i: &usize| mask & (1 << i) != 0;
		let mut children = [None; NIBBLE_LENGTH];
		for i in all().into_iter().filter(exists) {
			children[i] = Some(NodeHandle::Hash(&hashes[i]));
		}
		let node = owned(Node::Branch(children, None));
		let NodeOwned::Branch(children, None) = &node else { panic!("expected a branch") };

		let expected: Vec<_> = all()
			.iter()
			.map(|i| exists(i).then(|| NodeHandleOwned::Hash(hashes[*i])))
			.collect();
		for i in all() {
			assert_eq!(children.get(i), expected[i].as_ref(), "mask {:#06x}, nibble {}", mask, i);
		}
		assert!(children.iter().eq(expected.iter()), "mask {:#06x}", mask);
		let existing: Vec<_> = node.child_iter().map(|(nibble, _)| nibble.unwrap()).collect();
		let nibbles: Vec<_> = (0u8..16).zip(&expected).filter(|(_, c)| c.is_some()).collect();
		assert!(existing.iter().eq(nibbles.iter().map(|(n, _)| n)), "mask {:#06x}", mask);
		let last = all().into_iter().filter(exists).last();
		assert_eq!(children.allocated_len(), last.map_or(0, |i| i + 1), "mask {:#06x}", mask);
		assert_eq!(node.size_in_bytes(), size_of::<Owned>() + existing.len() * SLOT);
	}
}

#[test]
fn owned_branch_encodes_like_the_borrowed_one() {
	let hashes = distinct_hashes();
	for mask in [0u16, 0x0001, 0x8001, 0x0105, 0x7fff, 0xfffe, u16::MAX] {
		let children = all().into_iter().map(|i| {
			let exists = mask & (1 << i) != 0;
			exists.then(|| ChildReference::Hash(hashes[i]))
		});
		let borrowed = Codec::branch_node(children, None);
		let node = owned(Codec::decode(&borrowed).unwrap());
		assert_eq!(node.to_encoded::<Codec>(), borrowed, "mask {:#06x}", mask);
	}
}

#[test]
fn owned_branch_with_inline_children_survives_its_encoding() {
	let leaf = inline_leaf();
	let node = branch(&[3], &[2, 8], &leaf);
	let decoded = owned(Codec::decode(&node.to_encoded::<Codec>()).unwrap());
	assert_eq!(decoded, node);
	assert_eq!(decoded.child_iter().count(), 3);
}

#[test]
fn debug_shows_each_child_at_its_nibble() {
	let NodeOwned::Branch(children, _) = branch(&[1], &[], &[]) else {
		panic!("expected a branch")
	};
	let debug = format!("{:?}", children);
	assert!(debug.starts_with("[None, Some(Hash("), "{}", debug);
	assert_eq!(debug.matches("None").count(), NIBBLE_LENGTH - 1, "{}", debug);
}

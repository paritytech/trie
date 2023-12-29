// Copyright 2017, 2020 Parity Technologies
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
use hex_literal::hex;
use reference_trie::test_layouts;
use trie_db::{node::Node, NibbleSlice, TrieDBBuilder, TrieDBNodeDoubleEndedIterator, TrieLayout};

use crate::iterator::{build_trie_db, nibble_vec};

test_layouts!(node_double_ended_iterator_works, node_double_ended_iterator);
fn node_double_ended_iterator<T: TrieLayout>() {
	let pairs = vec![
		(hex!("01").to_vec(), b"aaaa".to_vec()),
		(hex!("0123").to_vec(), b"bbbb".to_vec()),
		(hex!("02").to_vec(), vec![1; 32]),
	];

	let (memdb, root) = build_trie_db::<T>(&pairs);
	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();
	let mut iter = TrieDBNodeDoubleEndedIterator::new(&trie).unwrap();

	if T::USE_EXTENSION {
		match iter.next_back() {
			Some(Ok((prefix, Some(_), node))) => {
				assert_eq!(prefix, nibble_vec(hex!(""), 0));
				match node.node() {
					Node::Extension(partial, _) =>
						assert_eq!(partial, NibbleSlice::new_offset(&hex!("00")[..], 1)),
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}

		match iter.next_back() {
			Some(Ok((prefix, Some(_), node))) => {
				assert_eq!(prefix, nibble_vec(hex!("00"), 1));
				match node.node() {
					Node::Branch(_, _) => {},
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}
		match iter.next_back() {
			Some(Ok((prefix, Some(_), node))) => {
				assert_eq!(prefix, nibble_vec(hex!("02"), 2));
				match node.node() {
					Node::Leaf(partial, _) => assert_eq!(partial, NibbleSlice::new(&hex!("")[..])),
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}

		match iter.next_back() {
			Some(Ok((prefix, None, node))) => {
				assert_eq!(prefix, nibble_vec(hex!("01"), 2));
				match node.node() {
					Node::Branch(_, _) => {},
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}

		match iter.next_back() {
			Some(Ok((prefix, None, node))) => {
				assert_eq!(prefix, nibble_vec(hex!("0120"), 3));
				match node.node() {
					Node::Leaf(partial, _) =>
						assert_eq!(partial, NibbleSlice::new_offset(&hex!("03")[..], 1)),
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}

		assert!(iter.next_back().is_none());
	} else {
		let can_expand =
			T::MAX_INLINE_VALUE.unwrap_or(T::Hash::LENGTH as u32) < T::Hash::LENGTH as u32;

		match iter.next_back() {
			Some(Ok((prefix, Some(_), node))) => {
				assert_eq!(prefix, nibble_vec(hex!(""), 0));
				match node.node() {
					Node::NibbledBranch(partial, _, _) =>
						assert_eq!(partial, NibbleSlice::new_offset(&hex!("00")[..], 1)),
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}

		// Start from the last element and move backwards
		match iter.next_back() {
			Some(Ok((prefix, Some(_), node))) => {
				assert_eq!(prefix, nibble_vec(hex!("02"), 2));
				match node.node() {
					Node::Leaf(partial, _) => assert_eq!(partial, NibbleSlice::new(&hex!("")[..])),
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}

		match iter.next_back() {
			Some(Ok((prefix, hash, node))) => {
				if !can_expand {
					assert!(hash.is_none());
				}
				assert_eq!(prefix, nibble_vec(hex!("01"), 2));
				match node.node() {
					Node::NibbledBranch(partial, _, _) =>
						assert_eq!(partial, NibbleSlice::new(&hex!("")[..])),
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}

		match iter.next_back() {
			Some(Ok((prefix, hash, node))) => {
				if !can_expand {
					assert!(hash.is_none());
				}
				assert_eq!(prefix, nibble_vec(hex!("0120"), 3));
				match node.node() {
					Node::Leaf(partial, _) =>
						assert_eq!(partial, NibbleSlice::new_offset(&hex!("03")[..], 1)),
					_ => panic!("unexpected node"),
				}
			},
			_ => panic!("unexpected item"),
		}

		assert!(iter.next_back().is_none());
	}
}

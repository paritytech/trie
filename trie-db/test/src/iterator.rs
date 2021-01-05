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

use trie_db::{
	DBValue, TrieError, TrieMut,
	TrieIterator, TrieDBNodeIterator, NibbleSlice, NibbleVec,
	node::Node,
};
use hex_literal::hex;
use hash_db::{HashDB, Hasher};
use keccak_hasher::KeccakHasher;
use reference_trie::{
	RefTrieDB, RefTrieDBMut,
};
use reference_trie::{RefTrieDBNoExt, RefTrieDBMutNoExt};

type MemoryDB = memory_db::MemoryDB<KeccakHasher, memory_db::PrefixedKey<KeccakHasher>, DBValue>;

fn build_trie_db_with_extension(pairs: &[(Vec<u8>, Vec<u8>)])
	-> (MemoryDB, <KeccakHasher as Hasher>::Out)
{
	let mut memdb = MemoryDB::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
		for (x, y) in pairs.iter() {
			t.insert(x, y).unwrap();
		}
	}
	(memdb, root)
}

fn build_trie_db_without_extension(pairs: &[(Vec<u8>, Vec<u8>)])
	-> (MemoryDB, <KeccakHasher as Hasher>::Out)
{
	let mut memdb = MemoryDB::default();
	let mut root = Default::default();
	{
		let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
		for (x, y) in pairs.iter() {
			t.insert(x, y).unwrap();
		}
	}
	(memdb, root)
}

fn nibble_vec<T: AsRef<[u8]>>(bytes: T, len: usize) -> NibbleVec {
	let slice = NibbleSlice::new(bytes.as_ref());

	let mut v = NibbleVec::new();
	for i in 0..len {
		v.push(slice.at(i));
	}
	v
}

#[test]
fn iterator_works_with_extension() {
	let pairs = vec![
		(hex!("01").to_vec(), b"aaaa".to_vec()),
		(hex!("0123").to_vec(), b"bbbb".to_vec()),
		(hex!("02").to_vec(), vec![1; 32]),
	];

	let (memdb, root) = build_trie_db_with_extension(&pairs);
	let trie = RefTrieDB::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

	match iter.next() {
		Some(Ok((prefix, Some(_), node))) => {
			assert_eq!(prefix, nibble_vec(hex!(""), 0));
			match node.node() {
				Node::Extension(partial, _) =>
					assert_eq!(partial, NibbleSlice::new_offset(&hex!("00")[..], 1)),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, Some(_), node))) => {
			assert_eq!(prefix, nibble_vec(hex!("00"), 1));
			match node.node() {
				Node::Branch(_, _) => {},
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, None, node))) => {
			assert_eq!(prefix, nibble_vec(hex!("01"), 2));
			match node.node() {
				Node::Branch(_, _) => {},
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, None, node))) => {
			assert_eq!(prefix, nibble_vec(hex!("0120"), 3));
			match node.node() {
				Node::Leaf(partial, _) =>
					assert_eq!(partial, NibbleSlice::new_offset(&hex!("03")[..], 1)),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, Some(_), node))) => {
			assert_eq!(prefix, nibble_vec(hex!("02"), 2));
			match node.node() {
				Node::Leaf(partial, _) =>
					assert_eq!(partial, NibbleSlice::new(&hex!("")[..])),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	assert!(iter.next().is_none());
}

#[test]
fn iterator_works_without_extension() {
	let pairs = vec![
		(hex!("01").to_vec(), b"aaaa".to_vec()),
		(hex!("0123").to_vec(), b"bbbb".to_vec()),
		(hex!("02").to_vec(), vec![1; 32]),
	];

	let (memdb, root) = build_trie_db_without_extension(&pairs);
	let trie = RefTrieDBNoExt::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

	match iter.next() {
		Some(Ok((prefix, Some(_), node))) => {
			assert_eq!(prefix, nibble_vec(hex!(""), 0));
			match node.node() {
				Node::NibbledBranch(partial, _, _) =>
					assert_eq!(partial, NibbleSlice::new_offset(&hex!("00")[..], 1)),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, None, node))) => {
			assert_eq!(prefix, nibble_vec(hex!("01"), 2));
			match node.node() {
				Node::NibbledBranch(partial, _, _) =>
					assert_eq!(partial, NibbleSlice::new(&hex!("")[..])),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, None, node))) => {
			assert_eq!(prefix, nibble_vec(hex!("0120"), 3));
			match node.node() {
				Node::Leaf(partial, _) =>
					assert_eq!(partial, NibbleSlice::new_offset(&hex!("03")[..], 1)),
				_ => panic!("unexpected node"),
			}
		}

		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, Some(_), node))) => {
			assert_eq!(prefix, nibble_vec(hex!("02"), 2));
			match node.node() {
				Node::Leaf(partial, _) =>
					assert_eq!(partial, NibbleSlice::new(&hex!("")[..])),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	assert!(iter.next().is_none());
}

#[test]
fn iterator_over_empty_works() {
	let (memdb, root) = build_trie_db_with_extension(&[]);
	let trie = RefTrieDB::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

	match iter.next() {
		Some(Ok((prefix, Some(_), node))) => {
			assert_eq!(prefix, nibble_vec(hex!(""), 0));
			match node.node() {
				Node::Empty => {},
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	assert!(iter.next().is_none());
}

#[test]
fn seek_works_with_extension() {
	let pairs = vec![
		(hex!("01").to_vec(), b"aaaa".to_vec()),
		(hex!("0123").to_vec(), b"bbbb".to_vec()),
		(hex!("02").to_vec(), vec![1; 32]),
	];

	let (memdb, root) = build_trie_db_with_extension(&pairs);
	let trie = RefTrieDB::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

	TrieIterator::seek(&mut iter, &hex!("")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, _))) =>
			assert_eq!(prefix, nibble_vec(hex!(""), 0)),
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("00")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, _))) =>
			assert_eq!(prefix, nibble_vec(hex!("01"), 2)),
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("01")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, _))) =>
			assert_eq!(prefix, nibble_vec(hex!("01"), 2)),
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("02")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, _))) =>
			assert_eq!(prefix, nibble_vec(hex!("02"), 2)),
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("03")[..]).unwrap();
	assert!(iter.next().is_none());
}


#[test]
fn seek_works_without_extension() {
	let pairs = vec![
		(hex!("01").to_vec(), b"aaaa".to_vec()),
		(hex!("0123").to_vec(), b"bbbb".to_vec()),
		(hex!("02").to_vec(), vec![1; 32]),
	];

	let (memdb, root) = build_trie_db_without_extension(&pairs);
	let trie = RefTrieDBNoExt::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

	TrieIterator::seek(&mut iter, &hex!("")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, _))) =>
			assert_eq!(prefix, nibble_vec(hex!(""), 0)),
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("00")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, _))) =>
			assert_eq!(prefix, nibble_vec(hex!("01"), 2)),
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("01")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, _))) =>
			assert_eq!(prefix, nibble_vec(hex!("01"), 2)),
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("02")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, _))) =>
			assert_eq!(prefix, nibble_vec(hex!("02"), 2)),
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("03")[..]).unwrap();
	assert!(iter.next().is_none());
}

#[test]
fn seek_over_empty_works() {
	let (memdb, root) = build_trie_db_with_extension(&[]);
	let trie = RefTrieDB::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

	TrieIterator::seek(&mut iter, &hex!("")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, _, node))) => {
			assert_eq!(prefix, nibble_vec(hex!(""), 0));
			match node.node() {
				Node::Empty => {},
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	TrieIterator::seek(&mut iter, &hex!("00")[..]).unwrap();
	assert!(iter.next().is_none());
}

#[test]
fn iterate_over_incomplete_db() {
	let pairs = vec![
		(hex!("01").to_vec(), b"aaaa".to_vec()),
		(hex!("0123").to_vec(), b"bbbb".to_vec()),
		(hex!("02").to_vec(), vec![1; 32]),
		(hex!("03").to_vec(), vec![2; 32]),
	];

	let (mut memdb, root) = build_trie_db_with_extension(&pairs);

	// Look up the leaf node with prefix "02".
	let leaf_hash = {
		let trie = RefTrieDB::new(&memdb, &root).unwrap();
		let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

		TrieIterator::seek(&mut iter, &hex!("02")[..]).unwrap();
		match iter.next() {
			Some(Ok((_, Some(hash), node))) => {
				match node.node() {
					Node::Leaf(_, _) => hash,
					_ => panic!("unexpected node"),
				}
			}
			_ => panic!("unexpected item"),
		}
	};

	// Remove the leaf node from the DB.
	let prefix = (&hex!("02")[..], None);
	memdb.remove(&leaf_hash, prefix);

	// Seek to missing node returns error.
	{
		let trie = RefTrieDB::new(&memdb, &root).unwrap();
		let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

		match TrieIterator::seek(&mut iter, &hex!("02")[..]) {
			Err(ref err) if **err == TrieError::IncompleteDatabase(leaf_hash) => {},
			_ => panic!("expected IncompleteDatabase error"),
		}
	}

	// Iterate over missing node works.
	{
		let trie = RefTrieDB::new(&memdb, &root).unwrap();
		let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

		TrieIterator::seek(&mut iter, &hex!("0130")[..]).unwrap();
		match iter.next() {
			Some(Err(ref err)) if **err == TrieError::IncompleteDatabase(leaf_hash) => {},
			_ => panic!("expected IncompleteDatabase error"),
		}
		match iter.next() {
			Some(Ok((_, _, node))) => {
				match node.node() {
					Node::Leaf(_, v) =>
						assert_eq!(&v[..], &vec![2; 32][..]),
					_ => panic!("unexpected node"),
				}
			}
			_ => panic!("unexpected item"),
		}

		assert!(iter.next().is_none());
	}
}

#[test]
fn prefix_works_with_extension() {
	let pairs = vec![
		(hex!("01").to_vec(), b"aaaa".to_vec()),
		(hex!("0123").to_vec(), b"bbbb".to_vec()),
		(hex!("02").to_vec(), vec![1; 32]),
	];

	let (memdb, root) = build_trie_db_with_extension(&pairs);
	let trie = RefTrieDB::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

	iter.prefix(&hex!("01").to_vec()[..]).unwrap();

	match iter.next() {
		Some(Ok((prefix, None, node))) => {
			assert_eq!(prefix, nibble_vec(hex!("01"), 2));
			match node.node() {
				Node::Branch(_, _) => {},
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, None, node))) => {
			assert_eq!(prefix, nibble_vec(hex!("0120"), 3));
			match node.node() {
				Node::Leaf(partial, _) =>
					assert_eq!(partial, NibbleSlice::new_offset(&hex!("03")[..], 1)),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	assert!(iter.next().is_none());

	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();
	iter.prefix(&hex!("0010").to_vec()[..]).unwrap();
	assert!(iter.next().is_none());
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();
	iter.prefix(&hex!("10").to_vec()[..]).unwrap();
	assert!(iter.next().is_none());

}

#[test]
fn prefix_works_without_extension() {
	let pairs = vec![
		(hex!("01").to_vec(), b"aaaa".to_vec()),
		(hex!("0123").to_vec(), b"bbbb".to_vec()),
		(hex!("02").to_vec(), vec![1; 32]),
	];

	let (memdb, root) = build_trie_db_without_extension(&pairs);
	let trie = RefTrieDBNoExt::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();

	iter.prefix(&hex!("01").to_vec()[..]).unwrap();

	match iter.next() {
		Some(Ok((prefix, None, node))) => {
			assert_eq!(prefix, nibble_vec(hex!("01"), 2));
			match node.node() {
				Node::NibbledBranch(partial, _, _) =>
					assert_eq!(partial, NibbleSlice::new_offset(&hex!("")[..], 0)),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	match iter.next() {
		Some(Ok((prefix, None, node))) => {
			assert_eq!(prefix, nibble_vec(hex!("0120"), 3));
			match node.node() {
				Node::Leaf(partial, _) =>
					assert_eq!(partial, NibbleSlice::new_offset(&hex!("03")[..], 1)),
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	assert!(iter.next().is_none());

	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();
	iter.prefix(&hex!("0010").to_vec()[..]).unwrap();
	assert!(iter.next().is_none());
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();
	iter.prefix(&hex!("10").to_vec()[..]).unwrap();
	assert!(iter.next().is_none());

}

#[test]
fn prefix_over_empty_works() {
	let (memdb, root) = build_trie_db_with_extension(&[]);
	let trie = RefTrieDB::new(&memdb, &root).unwrap();
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();
	iter.prefix(&hex!("")[..]).unwrap();
	match iter.next() {
		Some(Ok((prefix, Some(_), node))) => {
			assert_eq!(prefix, nibble_vec(hex!(""), 0));
			match node.node() {
				Node::Empty => {},
				_ => panic!("unexpected node"),
			}
		}
		_ => panic!("unexpected item"),
	}

	assert!(iter.next().is_none());

	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();
	iter.prefix(&hex!("00")[..]).unwrap();
	assert!(iter.next().is_none());
}

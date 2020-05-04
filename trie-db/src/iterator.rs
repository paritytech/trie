// Copyright 2017, 2019 Parity Technologies
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

use super::{CError, DBValue, Result, Trie, TrieHash, TrieIterator, TrieLayout};
use hash_db::{Hasher, EMPTY_PREFIX};
use crate::triedb::TrieDB;
use crate::node::{NodePlan, NodeHandle, OwnedNode};
use crate::nibble::{NibbleSlice, NibbleVec, nibble_ops};

use crate::rstd::{rc::Rc, vec::Vec};

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Clone, Copy, Eq, PartialEq)]
enum Status {
	Entering,
	At,
	AtChild(usize),
	Exiting,
}

#[cfg_attr(feature = "std", derive(Debug))]
#[derive(Eq, PartialEq)]
struct Crumb<H: Hasher> {
	hash: Option<H::Out>,
	node: Rc<OwnedNode<DBValue>>,
	status: Status,
}

impl<H: Hasher> Crumb<H> {
	/// Move on to next status in the node's sequence.
	fn increment(&mut self) {
		self.status = match (self.status, self.node.node_plan()) {
			(Status::Entering, NodePlan::Extension { .. }) => Status::At,
			(Status::Entering, NodePlan::Branch { .. })
			| (Status::Entering, NodePlan::NibbledBranch { .. }) => Status::At,
			(Status::At, NodePlan::Branch { .. })
			| (Status::At, NodePlan::NibbledBranch { .. }) => Status::AtChild(0),
			(Status::AtChild(x), NodePlan::Branch { .. })
			| (Status::AtChild(x), NodePlan::NibbledBranch { .. })
			if x < (nibble_ops::NIBBLE_LENGTH - 1) => Status::AtChild(x + 1),
			_ => Status::Exiting,
		}
	}
}

/// Iterator for going through all nodes in the trie in pre-order traversal order.
pub struct TrieDBNodeIterator<'a, L: TrieLayout> {
	db: &'a TrieDB<'a, L>,
	trail: Vec<Crumb<L::Hash>>,
	key_nibbles: NibbleVec,
}

impl<'a, L: TrieLayout> TrieDBNodeIterator<'a, L> {
	/// Create a new iterator.
	pub fn new(db: &'a TrieDB<L>) -> Result<TrieDBNodeIterator<'a, L>, TrieHash<L>, CError<L>> {
		let mut r = TrieDBNodeIterator {
			db,
			trail: Vec::with_capacity(8),
			key_nibbles: NibbleVec::new(),
		};
		let (root_node, root_hash) = db.get_raw_or_lookup(
			*db.root(),
			NodeHandle::Hash(db.root().as_ref()),
			EMPTY_PREFIX
		)?;
		r.descend(root_node, root_hash);
		Ok(r)
	}

	/// Descend into a payload.
	fn descend(&mut self, node: OwnedNode<DBValue>, node_hash: Option<TrieHash<L>>) {
		self.trail.push(Crumb {
			hash: node_hash,
			status: Status::Entering,
			node: Rc::new(node),
		});
	}
}

impl<'a, L: TrieLayout> TrieDBNodeIterator<'a, L> {

	/// Seek a node position at 'key' for iterator.
	/// Returns true if the cursor is at or after the key, but still shares
	/// a common prefix with the key, return false if the key do not
	/// share its prefix with the node.
	/// This indicates if there is still nodes to iterate over in the case
	/// where we limit iteration to 'key' as a prefix.
	fn seek_prefix(
		&mut self,
		key: &[u8],
	) -> Result<bool, TrieHash<L>, CError<L>> {
		self.trail.clear();
		self.key_nibbles.clear();
		let key = NibbleSlice::new(key);

		let (mut node, mut node_hash) = self.db.get_raw_or_lookup(
			<TrieHash<L>>::default(),
			NodeHandle::Hash(self.db.root().as_ref()),
			EMPTY_PREFIX
		)?;
		let mut partial = key;
		let mut full_key_nibbles = 0;
		loop {
			let (next_node, next_node_hash) = {
				self.descend(node, node_hash);
				let crumb = self.trail.last_mut()
					.expect(
						"descend_into_node pushes a crumb onto the trial; \
						thus the trail is non-empty; qed"
					);
				let node_data = crumb.node.data();

				match crumb.node.node_plan() {
					NodePlan::Leaf { partial: partial_plan, .. } => {
						let slice = partial_plan.build(node_data);
						if slice < partial {
							crumb.status = Status::Exiting;
							return Ok(false);
						}
						return Ok(slice.starts_with(&partial));
					},
					NodePlan::Extension { partial: partial_plan, child } => {
						let slice = partial_plan.build(node_data);
						if !partial.starts_with(&slice) {
							if slice < partial {
								crumb.status = Status::Exiting;
								self.key_nibbles.append_partial(slice.right());
								return Ok(false);
							}
							return Ok(slice.starts_with(&partial));
						}

						full_key_nibbles += slice.len();
						partial = partial.mid(slice.len());
						crumb.status = Status::At;
						self.key_nibbles.append_partial(slice.right());

						let prefix = key.back(full_key_nibbles);
						self.db.get_raw_or_lookup(
							node_hash.unwrap_or_default(),
							child.build(node_data),
							prefix.left()
						)?
					},
					NodePlan::Branch { value: _, children } => {
						if partial.is_empty() {
							return Ok(true);
						}

						let i = partial.at(0);
						crumb.status = Status::AtChild(i as usize);
						self.key_nibbles.push(i);

						if let Some(child) = &children[i as usize] {
							full_key_nibbles += 1;
							partial = partial.mid(1);

							let prefix = key.back(full_key_nibbles);
							self.db.get_raw_or_lookup(
								node_hash.unwrap_or_default(),
								child.build(node_data),
								prefix.left()
							)?
						} else {
							return Ok(false);
						}
					},
					NodePlan::NibbledBranch { partial: partial_plan, value: _, children } => {
						let slice = partial_plan.build(node_data);
						if !partial.starts_with(&slice) {
							if slice < partial {
								crumb.status = Status::Exiting;
								self.key_nibbles.append_partial(slice.right());
								self.key_nibbles.push((nibble_ops::NIBBLE_LENGTH - 1) as u8);
								return Ok(false);
							}
							return Ok(slice.starts_with(&partial));
						}

						full_key_nibbles += slice.len();
						partial = partial.mid(slice.len());

						if partial.is_empty() {
							return Ok(true);
						}

						let i = partial.at(0);
						crumb.status = Status::AtChild(i as usize);
						self.key_nibbles.append_partial(slice.right());
						self.key_nibbles.push(i);

						if let Some(child) = &children[i as usize] {
							full_key_nibbles += 1;
							partial = partial.mid(1);

							let prefix = key.back(full_key_nibbles);
							self.db.get_raw_or_lookup(
								node_hash.unwrap_or_default(),
								child.build(node_data),
								prefix.left()
							)?
						} else {
							return Ok(false);
						}
					},
					NodePlan::Empty => {
						if !partial.is_empty() {
							crumb.status = Status::Exiting;
							return Ok(false);
						}
						return Ok(true);
					},
				}
			};

			node = next_node;
			node_hash = next_node_hash;
		}
	}

	/// Advance the iterator into a prefix, no value out of the prefix will be accessed
	/// or returned after this operation.
	pub fn prefix(&mut self, prefix: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		if self.seek_prefix(prefix)? {
			if let Some(v) = self.trail.pop() {
				self.trail.clear();
				self.trail.push(v);
			}
		} else {
			self.trail.clear();
		}

		Ok(())
	}

}

impl<'a, L: TrieLayout> TrieIterator<L> for TrieDBNodeIterator<'a, L> {
	fn seek(
		&mut self,
		key: &[u8],
	) -> Result<(), TrieHash<L>, CError<L>> {
		self.seek_prefix(key)
			.map(|_| ())
	}
}

impl<'a, L: TrieLayout> Iterator for TrieDBNodeIterator<'a, L> {
	type Item = Result<(NibbleVec, Option<TrieHash<L>>, Rc<OwnedNode<DBValue>>), TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		enum IterStep<O, E> {
			YieldNode,
			PopTrail,
			Continue,
			Descend(Result<(OwnedNode<DBValue>, Option<O>), O, E>),
		}
		loop {
			let iter_step = {
				let b = self.trail.last_mut()?;
				let node_data = b.node.data();

				match (b.status, b.node.node_plan()) {
					(Status::Entering, _) => IterStep::YieldNode,
					(Status::Exiting, node) => {
						match node {
							NodePlan::Empty | NodePlan::Leaf { .. } => {},
							NodePlan::Extension { partial, .. } => {
								self.key_nibbles.drop_lasts(partial.len());
							},
							NodePlan::Branch { .. } => { self.key_nibbles.pop(); },
							NodePlan::NibbledBranch { partial, .. } => {
								self.key_nibbles.drop_lasts(partial.len() + 1);
							},
						}
						IterStep::PopTrail
					},
					(Status::At, NodePlan::Extension { partial: partial_plan, child }) => {
						let partial = partial_plan.build(node_data);
						self.key_nibbles.append_partial(partial.right());
						IterStep::Descend::<TrieHash<L>, CError<L>>(
							self.db.get_raw_or_lookup(
								b.hash.unwrap_or_default(),
								child.build(node_data),
								self.key_nibbles.as_prefix()
							)
						)
					},
					(Status::At, NodePlan::Branch { .. }) => {
						self.key_nibbles.push(0);
						IterStep::Continue
					},
					(Status::At, NodePlan::NibbledBranch { partial: partial_plan, .. }) => {
						let partial = partial_plan.build(node_data);
						self.key_nibbles.append_partial(partial.right());
						self.key_nibbles.push(0);
						IterStep::Continue
					},
					(Status::AtChild(i), NodePlan::Branch { children, .. })
					| (Status::AtChild(i), NodePlan::NibbledBranch { children, .. }) => {
						if let Some(child) = &children[i] {
							self.key_nibbles.pop();
							self.key_nibbles.push(i as u8);
							IterStep::Descend::<TrieHash<L>, CError<L>>(
								self.db.get_raw_or_lookup(
									b.hash.unwrap_or_default(),
									child.build(node_data),
									self.key_nibbles.as_prefix()
								)
							)
						} else {
							IterStep::Continue
						}
					},
					_ => panic!(
						"Crumb::increment and TrieDBNodeIterator are implemented so that \
						the above arms are the only possible states"
					),
				}
			};

			match iter_step {
				IterStep::YieldNode => {
					let crumb = self.trail.last_mut()
						.expect(
							"method would have exited at top of previous block if trial were empty;\
							trial could not have been modified within the block since it was immutably borrowed;\
							qed"
						);
					crumb.increment();
					return Some(Ok((
						self.key_nibbles.clone(),
						crumb.hash,
						crumb.node.clone()
					)));
				},
				IterStep::PopTrail => {
					self.trail.pop()
						.expect(
							"method would have exited at top of previous block if trial were empty;\
							trial could not have been modified within the block since it was immutably borrowed;\
							qed"
						);
					self.trail.last_mut()?
						.increment();
				},
				IterStep::Descend::<TrieHash<L>, CError<L>>(Ok((node, node_hash))) => {
					self.descend(node, node_hash);
				},
				IterStep::Descend::<TrieHash<L>, CError<L>>(Err(err)) => {
					// Increment here as there is an implicit PopTrail.
					self.trail.last_mut()
						.expect(
							"method would have exited at top of previous block if trial were empty;\
								trial could not have been modified within the block since it was immutably borrowed;\
								qed"
						)
						.increment();
					return Some(Err(err));
				},
				IterStep::Continue => {
					self.trail.last_mut()
						.expect(
							"method would have exited at top of previous block if trial were empty;\
							trial could not have been modified within the block since it was immutably borrowed;\
							qed"
						)
						.increment();
				},
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use crate::DBValue;
	use hex_literal::hex;
	use hash_db::{HashDB, Hasher};
	use keccak_hasher::KeccakHasher;
	use reference_trie::{
		RefTrieDB, RefTrieDBMut,
		TrieError, TrieMut, TrieIterator, TrieDBNodeIterator, NibbleSlice, NibbleVec,
		node::Node,
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
}


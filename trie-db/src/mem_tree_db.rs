// Copyright 2017-2020 Parity Technologies
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

//! Flat memory-based `NodeDB` implementation.

use std::collections::HashMap;

use crate::{
	node_db::{Hasher, NodeDB, Prefix},
	Changeset, NewChangesetNode,
};

/// Node location which is just an index into the `nodes` vector.
pub type Location = Option<usize>;

/// Tree based `NodeDB` implementation.
#[derive(Clone)]
pub struct MemTreeDB<H>
where
	H: Hasher,
{
	nodes: Vec<NodeEntry<H::Out>>,
	roots: HashMap<H::Out, usize>,
	hashed_null_node: H::Out,
	null_node_data: Vec<u8>,
}

#[derive(Clone)]
enum NodeEntry<H> {
	Live { key: H, data: Vec<u8>, children: Vec<usize>, rc: u32 },
	Removed,
}

impl<H> Default for MemTreeDB<H>
where
	H: Hasher,
{
	fn default() -> Self {
		Self::from_null_node(&[0u8][..], [0u8][..].into())
	}
}

impl<H> MemTreeDB<H>
where
	H: Hasher,
{
	/// Create a new `MemoryDB` from a given null key/data
	pub fn from_null_node(null_key: &[u8], null_node_data: &[u8]) -> Self {
		MemTreeDB {
			nodes: vec![],
			roots: HashMap::default(),
			hashed_null_node: H::hash(null_key),
			null_node_data: null_node_data.to_vec(),
		}
	}

	/// Create a new instance of `Self`.
	pub fn new(data: &[u8]) -> Self {
		Self::from_null_node(data, data.into())
	}

	pub fn clear(&mut self) {
		self.nodes.clear();
		self.roots.clear();
	}

	pub fn remove_root(&mut self, key: &H::Out) {
		let Some(location) = self.roots.get(key) else {
			return;
		};

		if self.remove_tree(*location) {
			self.roots.remove(key);
		}
	}

	pub fn remove_node(&mut self, k: &H::Out) {
		let rem_root = self.roots.remove(k);
		#[cfg(debug_assertions)]
		{
			for (i, node) in self.nodes.iter_mut().enumerate() {
				if matches!(node, NodeEntry::Live { key, .. } if key == k) {
					assert!(rem_root.map(|r| r == i).unwrap_or(false));
					*node = NodeEntry::Removed;
				}
			}
		}
		if let Some(rem_root_ix) = rem_root {
			self.nodes[rem_root_ix] = NodeEntry::Removed;
		}
	}

	pub fn test_remove_node(&mut self, k: &H::Out) {
		self.roots.remove(k);
		for node in self.nodes.iter_mut() {
			if matches!(node, NodeEntry::Live { key, .. } if key == k) {
				*node = NodeEntry::Removed;
			}
		}
	}

	fn remove_tree(&mut self, location: usize) -> bool {
		let entry = self.nodes.get_mut(location).unwrap();
		match entry {
			NodeEntry::Live { rc, children, .. } =>
				if *rc == 1 {
					let children = std::mem::take(children);
					*entry = NodeEntry::Removed;
					for c in children {
						self.remove_tree(c);
					}
					true
				} else {
					*rc -= 1;
					false
				},
			NodeEntry::Removed => {
				panic!("Accessing removed node");
			},
		}
	}

	pub fn is_empty(&self) -> bool {
		self.roots.is_empty()
	}

	fn apply(&mut self, c: &Changeset<H::Out, Location>) -> usize {
		match c {
			Changeset::Existing(e) => {
				let location = e.location.unwrap_or_else(|| *self.roots.get(&e.hash).unwrap());
				let entry = self.nodes.get_mut(location).unwrap();
				match entry {
					NodeEntry::Live { rc, .. } => {
						*rc += 1;
					},
					NodeEntry::Removed => {
						panic!("Accessing removed node");
					},
				};
				location
			},
			Changeset::New(n) => {
				let children = n.children.iter().map(|c| self.apply(c)).collect();
				self.nodes.push(NodeEntry::Live {
					key: n.hash,
					data: n.data.clone(),
					children,
					rc: 1,
				});
				self.nodes.len() - 1
			},
		}
	}

	pub fn apply_commit(&mut self, commit: Changeset<H::Out, Location>) {
		if commit.root_hash() != self.hashed_null_node {
			let root = self.apply(&commit);
			let key = commit.hash();
			self.roots.insert(*key, root);
		}
		// In non test use, the root should be store before calling commit (known
		// from tree where commit was build from).
		if let Changeset::New(NewChangesetNode { removed_keys: Some((_, removed)), .. }) = &commit {
			for (k, _) in removed {
				self.remove_root(&k);
			}
		}
	}
}

impl<H> NodeDB<H, Vec<u8>, Location> for MemTreeDB<H>
where
	H: Hasher,
{
	fn get(
		&self,
		k: &H::Out,
		_prefix: Prefix,
		location: Location,
	) -> Option<(Vec<u8>, Vec<Location>)> {
		if k == &self.hashed_null_node {
			return Some((self.null_node_data.clone(), Default::default()))
		}

		let location = match location {
			Some(l) => l,
			None =>
				if let Some(l) = self.roots.get(k) {
					*l
				} else {
					return None
				},
		};
		match self.nodes.get(location) {
			Some(NodeEntry::Live { data, children, key, .. }) => {
				assert_eq!(k, key);
				Some((data.clone(), children.iter().map(|l| Some(*l)).collect()))
			},
			_ => None,
		}
	}

	fn contains(&self, key: &H::Out, _prefix: Prefix, location: Location) -> bool {
		if key == &self.hashed_null_node {
			return true;
		}
		if let Some(l) = location {
			l < self.nodes.len() && !matches!(self.nodes[l], NodeEntry::Removed)
		} else {
			self.roots.contains_key(key)
		}
	}
}

#[cfg(test)]
mod tests {
	use super::{MemTreeDB, NodeEntry};
	use crate::{
		keccak_hasher::{KeccakHash, KeccakHasher},
		node_db::{Hasher, NodeDB},
		Changeset, ExistingChangesetNode, NewChangesetNode,
	};

	fn hash(i: u32) -> KeccakHash {
		KeccakHasher::hash(&i.to_le_bytes())
	}

	#[test]
	fn test_apply_existing_node() {
		let mut db = MemTreeDB::<KeccakHasher>::default();

		// First, apply a new node
		let new_node = Changeset::New(NewChangesetNode {
			hash: hash(1),
			prefix: Default::default(),
			data: vec![1, 2, 3],
			children: vec![],
			removed_keys: None,
		});
		let new_location = db.apply(&new_node);

		// Then, apply an existing node that refers to the new node
		let existing_node = Changeset::Existing(ExistingChangesetNode {
			hash: hash(1),
			location: Some(new_location),
			prefix: Default::default(),
		});
		let existing_location = db.apply(&existing_node);

		assert_eq!(existing_location, new_location);
	}

	#[test]
	fn test_apply_new_node() {
		let mut db = MemTreeDB::<KeccakHasher>::default();
		let node = Changeset::New(NewChangesetNode {
			hash: KeccakHash::default(),
			prefix: Default::default(),
			data: vec![1, 2, 3],
			children: vec![],
			removed_keys: None,
		});
		let location = db.apply(&node);
		assert_eq!(location, db.nodes.len() - 1);
	}

	#[test]
	fn test_apply_commit() {
		let mut db = MemTreeDB::<KeccakHasher>::default();
		let commit = Changeset::New(NewChangesetNode {
			hash: KeccakHash::default(),
			prefix: Default::default(),
			data: vec![1, 2, 3],
			children: vec![],
			removed_keys: None,
		});
		db.apply_commit(commit);
		assert_eq!(db.roots.len(), 1);
	}

	#[test]
	fn test_commit_changeset_with_children() {
		let mut db = MemTreeDB::<KeccakHasher>::default();

		// Create two child nodes
		let child1 = Changeset::New(NewChangesetNode {
			hash: hash(1),
			prefix: Default::default(),
			data: vec![1, 2, 3],
			children: vec![],
			removed_keys: None,
		});
		let child2 = Changeset::New(NewChangesetNode {
			hash: hash(2),
			prefix: Default::default(),
			data: vec![4, 5, 6],
			children: vec![],
			removed_keys: None,
		});

		// Create a root node that refers to the child nodes
		let commit = Changeset::New(NewChangesetNode {
			hash: hash(0),
			prefix: Default::default(),
			data: vec![7, 8, 9],
			children: vec![child1, child2],
			removed_keys: None,
		});

		db.apply_commit(commit);

		// Check that the root node and child nodes are in the database
		assert_eq!(db.nodes.len(), 3);
		assert_eq!(db.roots.len(), 1);
	}

	#[test]
	fn test_get() {
		let mut db = MemTreeDB::<KeccakHasher>::default();
		let key = KeccakHash::default();
		db.nodes.push(NodeEntry::Live {
			key: key.clone(),
			data: vec![1, 2, 3],
			children: vec![],
			rc: 1,
		});
		db.roots.insert(key.clone(), 0);
		let result = db.get(&key, Default::default(), None);
		assert_eq!(result, Some((vec![1, 2, 3], vec![])));
	}

	#[test]
	fn test_contains() {
		let mut db = MemTreeDB::<KeccakHasher>::default();
		let key = KeccakHash::default();
		db.nodes.push(NodeEntry::Live {
			key: key.clone(),
			data: vec![1, 2, 3],
			children: vec![],
			rc: 1,
		});
		db.roots.insert(key.clone(), 0);
		assert!(db.contains(&key, Default::default(), None));
	}
}

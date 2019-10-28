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

use hash_db::{HashDBRef, Prefix, EMPTY_PREFIX};
use nibble::NibbleSlice;
use iterator::TrieDBNodeIterator;
use super::node::{Node, OwnedNode};
use node_codec::NodeCodec;
use super::lookup::Lookup;
use super::{Result, DBValue, Trie, TrieItem, TrieError, TrieIterator, Query,
	TrieLayout, CError, TrieHash};
use super::nibble::NibbleVec;
#[cfg(feature = "std")]
use ::std::fmt;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// A `Trie` implementation using a generic `HashDB` backing database, a `Hasher`
/// implementation to generate keys and a `NodeCodec` implementation to encode/decode
/// the nodes.
///
/// Use it as a `Trie` trait object. You can use `db()` to get the backing database object.
/// Use `get` and `contains` to query values associated with keys in the trie.
///
/// # Example
/// ```
/// extern crate trie_db;
/// extern crate reference_trie;
/// extern crate hash_db;
/// extern crate keccak_hasher;
/// extern crate memory_db;
///
/// use hash_db::Hasher;
/// use reference_trie::{RefTrieDBMut, RefTrieDB, Trie, TrieMut};
/// use trie_db::DBValue;
/// use keccak_hasher::KeccakHasher;
/// use memory_db::*;
///
/// fn main() {
///   let mut memdb = MemoryDB::<KeccakHasher, HashKey<_>, _>::default();
///   let mut root = Default::default();
///   RefTrieDBMut::new(&mut memdb, &mut root).insert(b"foo", b"bar").unwrap();
///   let t = RefTrieDB::new(&memdb, &root).unwrap();
///   assert!(t.contains(b"foo").unwrap());
///   assert_eq!(t.get(b"foo").unwrap().unwrap(), DBValue::from_slice(b"bar"));
/// }
/// ```
pub struct TrieDB<'db, L>
where
	L: TrieLayout,
{
	db: &'db dyn HashDBRef<L::Hash, DBValue>,
	root: &'db TrieHash<L>,
	/// The number of hashes performed so far in operations on this trie.
	hash_count: usize,
}

impl<'db, L> TrieDB<'db, L>
where
	L: TrieLayout,
{
	/// Create a new trie with the backing database `db` and `root`
	/// Returns an error if `root` does not exist
	pub fn new(
		db: &'db dyn HashDBRef<L::Hash, DBValue>,
		root: &'db TrieHash<L>
	) -> Result<Self, TrieHash<L>, CError<L>> {
		if !db.contains(root, EMPTY_PREFIX) {
			Err(Box::new(TrieError::InvalidStateRoot(*root)))
		} else {
			Ok(TrieDB {db, root, hash_count: 0})
		}
	}

	/// Get the backing database.
	pub fn db(&'db self) -> &'db dyn HashDBRef<L::Hash, DBValue> { self.db }

	/// Get the data of the root node.
	pub fn root_data(&self) -> Result<DBValue, TrieHash<L>, CError<L>> {
		self.db
			.get(self.root, EMPTY_PREFIX)
			.ok_or_else(|| Box::new(TrieError::InvalidStateRoot(*self.root)))
	}

	/// Given some node-describing data `node`, and node key return the actual node RLP.
	/// This could be a simple identity operation in the case that the node is sufficiently small,
	/// but may require a database lookup. If `is_root_data` then this is root-data and
	/// is known to be literal.
	///
	/// Return value is the node data and a boolean which is false if the value was looked up in
	/// the database and true if it was returned raw.
	///
	/// `partial_key` is encoded nibble slice that addresses the node.
	pub(crate) fn get_raw_or_lookup(
		&self, node: &[u8],
		partial_key: Prefix,
	) -> Result<(DBValue, bool), TrieHash<L>, CError<L>> {
		match (partial_key.0.is_empty() && partial_key.1.is_none(), L::Codec::try_decode_hash(node)) {
			(false, Some(key)) => {
				let data = self.db
					.get(&key, partial_key)
					.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(key)))?;
				Ok((data, false))
			}
			_ => Ok((DBValue::from_slice(node), true)),
		}
	}
}

impl<'db, L> Trie<L> for TrieDB<'db, L>
where
	L: TrieLayout,
{
	fn root(&self) -> &TrieHash<L> { self.root }

	fn get_with<'a, 'key, Q: Query<L::Hash>>(
		&'a self,
		key: &'key [u8],
		query: Q,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>>
		where 'a: 'key,
	{
		Lookup::<L, Q> {
			db: self.db,
			query: query,
			hash: self.root.clone(),
		}.look_up(NibbleSlice::new(key))
	}

	fn iter<'a>(&'a self)-> Result<
		Box<dyn TrieIterator<L, Item=TrieItem<TrieHash<L>, CError<L>>> + 'a>,
		TrieHash<L>,
		CError<L>,
	> {
		TrieDBIterator::new(self).map(|iter| Box::new(iter) as Box<_>)
	}
}


#[cfg(feature="std")]
// This is for pretty debug output only
struct TrieAwareDebugNode<'db, 'a, L>
where
	L: TrieLayout,
{
	trie: &'db TrieDB<'db, L>,
	node_key: &'a[u8],
	partial_key: NibbleVec,
	index: Option<u8>,
}

#[cfg(feature="std")]
impl<'db, 'a, L> fmt::Debug for TrieAwareDebugNode<'db, 'a, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if let Ok((node, _inline)) = self.trie.get_raw_or_lookup(self.node_key, self.partial_key.as_prefix()) {
			match L::Codec::decode(&node) {
				Ok(Node::Leaf(slice, value)) =>
					match (f.debug_struct("Node::Leaf"), self.index) {
						(ref mut d, Some(i)) => d.field("index", &i),
						(ref mut d, _) => d,
					}
						.field("slice", &slice)
						.field("value", &value)
						.finish(),
				Ok(Node::Extension(slice, item)) =>
					match (f.debug_struct("Node::Extension"), self.index) {
						(ref mut d, Some(i)) => d.field("index", &i),
						(ref mut d, _) => d,
					}
						.field("slice", &slice)
						.field("item", &TrieAwareDebugNode{
							trie: self.trie,
							node_key: item,
							partial_key: self.partial_key
								.clone_append_optional_slice_and_nibble(Some(&slice), None),
							index: None,
						})
						.finish(),
				Ok(Node::Branch(ref nodes, ref value)) => {
					let nodes: Vec<TrieAwareDebugNode<L>> = nodes.into_iter()
						.enumerate()
						.filter_map(|(i, n)| n.map(|n| (i, n)))
						.map(|(i, n)| TrieAwareDebugNode {
							trie: self.trie,
							index: Some(i as u8),
							node_key: n,
							partial_key: self.partial_key
								.clone_append_optional_slice_and_nibble(None, Some(i as u8)),
						})
						.collect();
					match (f.debug_struct("Node::Branch"), self.index) {
						(ref mut d, Some(ref i)) => d.field("index", i),
						(ref mut d, _) => d,
					}
						.field("nodes", &nodes)
						.field("value", &value)
						.finish()
				},
				Ok(Node::NibbledBranch(slice, nodes, value)) => {
					let nodes: Vec<TrieAwareDebugNode<L>> = nodes.into_iter()
						.enumerate()
						.filter_map(|(i, n)| n.map(|n| (i, n)))
						.map(|(i, n)| TrieAwareDebugNode {
							trie: self.trie,
							index: Some(i as u8),
							node_key: n,
							partial_key: self.partial_key
								.clone_append_optional_slice_and_nibble(Some(&slice), Some(i as u8)),
						}).collect();
					match (f.debug_struct("Node::NibbledBranch"), self.index) {
						(ref mut d, Some(ref i)) => d.field("index", i),
						(ref mut d, _) => d,
					}
						.field("slice", &slice)
						.field("nodes", &nodes)
						.field("value", &value)
						.finish()
				},
				Ok(Node::Empty) => f.debug_struct("Node::Empty").finish(),

				Err(e) => f.debug_struct("BROKEN_NODE")
					.field("index", &self.index)
					.field("key", &self.node_key)
					.field("error", &format!("ERROR decoding node branch Rlp: {}", e))
					.finish()
			}
		} else {
			f.debug_struct("BROKEN_NODE")
				.field("index", &self.index)
				.field("key", &self.node_key)
				.field("error", &"Not found")
				.finish()
		}
	}
}

#[cfg(feature="std")]
impl<'db, L> fmt::Debug for TrieDB<'db, L>
where
	L: TrieLayout,
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let root_rlp = self.root_data().unwrap();
		f.debug_struct("TrieDB")
			.field("hash_count", &self.hash_count)
			.field("root", &TrieAwareDebugNode {
				trie: self,
				node_key: &root_rlp[..],
				partial_key: NibbleVec::new(),
				index: None,
			})
			.finish()
	}
}

/// Iterator for going through all values in the trie in pre-order traversal order.
pub struct TrieDBIterator<'a, L: TrieLayout> {
	inner: TrieDBNodeIterator<'a, L>,
}

impl<'a, L: TrieLayout> TrieDBIterator<'a, L> {
	/// Create a new iterator.
	pub fn new(db: &'a TrieDB<L>) -> Result<TrieDBIterator<'a, L>, TrieHash<L>, CError<L>> {
		let inner = TrieDBNodeIterator::new(db)?;
		Ok(TrieDBIterator { inner })
	}
}

impl<'a, L: TrieLayout> TrieIterator<L> for TrieDBIterator<'a, L> {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		TrieIterator::seek(&mut self.inner, key)
	}

	fn prefix(&mut self, prefix: &[u8]) -> Result<(), TrieHash<L>, CError<L>> {
		TrieIterator::seek(&mut self.inner, prefix)
	}

}

impl<'a, L: TrieLayout> Iterator for TrieDBIterator<'a, L> {
	type Item = TrieItem<'a, TrieHash<L>, CError<L>>;

	fn next(&mut self) -> Option<Self::Item> {
		while let Some(item) = self.inner.next() {
			match item {
				Ok((mut prefix, _, node)) => {
					let maybe_value = match node.as_ref() {
						&OwnedNode::Leaf(ref partial, ref value) => {
						prefix.append(partial);
							Some(value.as_ref())
						}
						&OwnedNode::Branch(ref branch) =>
							branch.get_value(),
						&OwnedNode::NibbledBranch(ref partial, ref branch) => {
							prefix.append(partial);
							branch.get_value()
						}
						_ => None,
					};
					if let Some(value) = maybe_value {
						let (key_slice, maybe_extra_nibble) = prefix.as_prefix();
						let key = key_slice.to_vec();
						if let Some(extra_nibble) = maybe_extra_nibble {
							return Some(Err(Box::new(
								TrieError::ValueAtIncompleteKey(key, extra_nibble)
							)));
						}
						return Some(Ok((key, DBValue::from_slice(value))));
					}
				},
				Err(err) => return Some(Err(err)),
			}
		}
		None
	}
}

#[cfg(test)]
mod tests {
	use memory_db::{MemoryDB, PrefixedKey};
	use keccak_hasher::KeccakHasher;
	use DBValue;
	use reference_trie::{RefTrieDB, RefTrieDBMut, RefLookup, Trie, TrieMut, NibbleSlice};
	use reference_trie::{RefTrieDBNoExt, RefTrieDBMutNoExt};

	#[test]
	fn iterator_works() {
		let pairs = vec![
			(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
			(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
		];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			for (x, y) in &pairs {
				t.insert(x, y).unwrap();
			}
		}

		let trie = RefTrieDB::new(&memdb, &root).unwrap();

		let iter = trie.iter().unwrap();
		let mut iter_pairs = Vec::new();
		for pair in iter {
			let (key, value) = pair.unwrap();
			iter_pairs.push((key, value.to_vec()));
		}

		assert_eq!(pairs, iter_pairs);
	}

	#[test]
	fn iterator_works_without_extension() {
		let pairs = vec![
			(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
			(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
		];

		let mut memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
			for (x, y) in &pairs {
				t.insert(x, y).unwrap();
			}
		}

		let trie = RefTrieDBNoExt::new(&memdb, &root).unwrap();

		let iter = trie.iter().unwrap();
		let mut iter_pairs = Vec::new();
		for pair in iter {
			let (key, value) = pair.unwrap();
			iter_pairs.push((key, value.to_vec()));
		}

		assert_eq!(pairs, iter_pairs);
	}

	#[test]
	fn iterator_seek_works() {
		let pairs = vec![
			(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
			(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
		];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			for (x, y) in &pairs {
				t.insert(x, y).unwrap();
			}
		}

		let t = RefTrieDB::new(&memdb, &root).unwrap();

		let mut iter = t.iter().unwrap();
		assert_eq!(
			iter.next().unwrap().unwrap(),
			(
				hex!("0103000000000000000464").to_vec(),
				DBValue::from_slice(&hex!("fffffffffe")[..]),
			)
		);
		iter.seek(&hex!("00")[..]).unwrap();
		assert_eq!(
			pairs,
			iter.map(|x| x.unwrap())
				.map(|(k, v)| (k, v[..].to_vec()))
				.collect::<Vec<_>>()
		);
		let mut iter = t.iter().unwrap();
		iter.seek(&hex!("0103000000000000000465")[..]).unwrap();
		assert_eq!(
			&pairs[1..],
			&iter.map(|x| x.unwrap())
				.map(|(k, v)| (k, v[..].to_vec()))
				.collect::<Vec<_>>()[..]
		);
	}

	#[test]
	fn iterator_seek_works_without_extension() {
		let pairs = vec![
			(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
			(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
		];

		let mut memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
			for (x, y) in &pairs {
				t.insert(x, y).unwrap();
			}
		}

		let t = RefTrieDBNoExt::new(&memdb, &root).unwrap();

		let mut iter = t.iter().unwrap();
		assert_eq!(
			iter.next().unwrap().unwrap(),
			(hex!("0103000000000000000464").to_vec(), DBValue::from_slice(&hex!("fffffffffe")[..]))
		);
		iter.seek(&hex!("00")[..]).unwrap();
		assert_eq!(
			pairs,
			iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>(),
		);
		let mut iter = t.iter().unwrap();
		iter.seek(&hex!("0103000000000000000465")[..]).unwrap();
		assert_eq!(
			&pairs[1..],
			&iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>()[..],
		);
	}

	#[test]
	fn iterator() {
		let d = vec![
			DBValue::from_slice(b"A"),
			DBValue::from_slice(b"AA"),
			DBValue::from_slice(b"AB"),
			DBValue::from_slice(b"B"),
		];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			for x in &d {
				t.insert(x, x).unwrap();
			}
		}

		let t = RefTrieDB::new(&memdb, &root).unwrap();
		assert_eq!(
			d.iter()
				.map(|i| i.clone().into_vec())
				.collect::<Vec<_>>(),
			t.iter()
				.unwrap()
				.map(|x| x.unwrap().0)
				.collect::<Vec<_>>()
		);
		assert_eq!(d, t.iter().unwrap().map(|x| x.unwrap().1).collect::<Vec<_>>());
	}

	#[test]
	fn iterator_without_extension() {
		let d = vec![
			DBValue::from_slice(b"A"),
			DBValue::from_slice(b"AA"),
			DBValue::from_slice(b"AB"),
			DBValue::from_slice(b"B"),
		];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
			for x in &d {
				t.insert(x, x).unwrap();
			}
		}

		let t = RefTrieDBNoExt::new(&memdb, &root).unwrap();
		assert_eq!(
			d.iter().map(|i| i.clone().into_vec()).collect::<Vec<_>>(),
			t.iter().unwrap().map(|x| x.unwrap().0).collect::<Vec<_>>(),
		);
		assert_eq!(d, t.iter().unwrap().map(|x| x.unwrap().1).collect::<Vec<_>>());
	}

	#[test]
	fn iterator_seek() {
		let d = vec![
			DBValue::from_slice(b"A"),
			DBValue::from_slice(b"AA"),
			DBValue::from_slice(b"AB"),
			DBValue::from_slice(b"B"),
		];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
			for x in &d {
				t.insert(x, x).unwrap();
			}
		}

		let t = RefTrieDBNoExt::new(&memdb, &root).unwrap();
		let mut iter = t.iter().unwrap();
		assert_eq!(iter.next().unwrap().unwrap(), (b"A".to_vec(), DBValue::from_slice(b"A")));
		iter.seek(b"!").unwrap();
		assert_eq!(d, iter.map(|x| x.unwrap().1).collect::<Vec<_>>());
		let mut iter = t.iter().unwrap();
		iter.seek(b"A").unwrap();
		assert_eq!(d, &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
		let mut iter = t.iter().unwrap();
		iter.seek(b"AA").unwrap();
		assert_eq!(&d[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
		let mut iter = t.iter().unwrap();
		iter.seek(b"A!").unwrap();
		assert_eq!(&d[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
		let mut iter = t.iter().unwrap();
		iter.seek(b"AB").unwrap();
		assert_eq!(&d[2..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
		let mut iter = t.iter().unwrap();
		iter.seek(b"AB!").unwrap();
		assert_eq!(&d[3..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
		let mut iter = t.iter().unwrap();
		iter.seek(b"B").unwrap();
		assert_eq!(&d[3..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
		let mut iter = t.iter().unwrap();
		iter.seek(b"C").unwrap();
		assert_eq!(&d[4..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	}

	#[test]
	fn get_length_with_extension() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			t.insert(b"A", b"ABC").unwrap();
			t.insert(b"B", b"ABCBAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
		}

		let t = RefTrieDB::new(&memdb, &root).unwrap();
		assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
		assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(32));
		assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
	}

	#[test]
	fn get_length_without_extension() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMutNoExt::new(&mut memdb, &mut root);
			t.insert(b"A", b"ABC").unwrap();
			t.insert(b"B", b"ABCBA").unwrap();
		}

		let t = RefTrieDBNoExt::new(&memdb, &root).unwrap();
		assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
		assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(5));
		assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
	}

	#[test]
	fn debug_output_supports_pretty_print() {
		let d = vec![
			DBValue::from_slice(b"A"),
			DBValue::from_slice(b"AA"),
			DBValue::from_slice(b"AB"),
			DBValue::from_slice(b"B"),
		];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let root = {
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			for x in &d {
				t.insert(x, x).unwrap();
			}
			t.root().clone()
		};
		let t = RefTrieDB::new(&memdb, &root).unwrap();

		assert_eq!(format!("{:#?}", t),
"TrieDB {
    hash_count: 0,
    root: Node::Extension {
        slice: 4,
        item: Node::Branch {
            nodes: [
                Node::Branch {
                    index: 1,
                    nodes: [
                        Node::Branch {
                            index: 4,
                            nodes: [
                                Node::Leaf {
                                    index: 1,
                                    slice: ,
                                    value: [
                                        65,
                                        65,
                                    ],
                                },
                                Node::Leaf {
                                    index: 2,
                                    slice: ,
                                    value: [
                                        65,
                                        66,
                                    ],
                                },
                            ],
                            value: None,
                        },
                    ],
                    value: Some(
                        [
                            65,
                        ],
                    ),
                },
                Node::Leaf {
                    index: 2,
                    slice: ,
                    value: [
                        66,
                    ],
                },
            ],
            value: None,
        },
    },
}");
	
	}

	#[test]
	fn test_lookup_with_corrupt_data_returns_decoder_error() {

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			t.insert(b"A", b"ABC").unwrap();
			t.insert(b"B", b"ABCBA").unwrap();
		}

		let t = RefTrieDB::new(&memdb, &root).unwrap();

		// query for an invalid data type to trigger an error
		let q = |x: &[u8]| x.len() < 64;
		let lookup = RefLookup { db: t.db(), query: q, hash: root };
		let query_result = lookup.look_up(NibbleSlice::new(b"A"));
		assert_eq!(query_result.unwrap().unwrap(), true);
	}
}

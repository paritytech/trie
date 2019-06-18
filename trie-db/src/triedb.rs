// Copyright 2017, 2018 Parity Technologies
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

use hash_db::{Hasher, HashDBRef};
use nibbleslice::{self, NibbleSlice};
#[cfg(feature = "std")]
use nibbleslice::combine_encoded;
use super::node::{Node, OwnedNode};
use node_codec::NodeCodec;
use super::lookup::Lookup;
use super::{Result, DBValue, Trie, TrieItem, TrieError, TrieIterator, Query};
use ::core_::marker::PhantomData;

#[cfg(feature = "std")]
use ::std::fmt;
#[cfg(feature = "std")]
use ::std::borrow::Cow;
#[cfg(not(feature = "std"))]
use ::alloc::borrow::Cow;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use elastic_array::ElasticArray36;

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
pub struct TrieDB<'db, H, C>
where
	H: Hasher + 'db,
	C: NodeCodec<H>
{
	db: &'db dyn HashDBRef<H, DBValue>,
	root: &'db H::Out,
	/// The number of hashes performed so far in operations on this trie.
	hash_count: usize,
	codec_marker: PhantomData<C>,
}

impl<'db, H, C> TrieDB<'db, H, C>
where
	H: Hasher,
	C: NodeCodec<H>
{
	/// Create a new trie with the backing database `db` and `root`
	/// Returns an error if `root` does not exist
	pub fn new(
		db: &'db dyn HashDBRef<H, DBValue>,
		root: &'db H::Out,
	) -> Result<Self, H::Out, C::Error> {
		if !db.contains(root, nibbleslice::EMPTY_ENCODED) {
			Err(Box::new(TrieError::InvalidStateRoot(*root)))
		} else {
			Ok(TrieDB {db, root, hash_count: 0, codec_marker: PhantomData})
		}
	}

	/// Get the backing database.
	pub fn db(&'db self) -> &'db dyn HashDBRef<H, DBValue> { self.db }

	/// Get the data of the root node.
	pub fn root_data(&self) -> Result<DBValue, H::Out, C::Error> {
		self.db
			.get(self.root, nibbleslice::EMPTY_ENCODED)
			.ok_or_else(|| Box::new(TrieError::InvalidStateRoot(*self.root)))
	}

	/// Given some node-describing data `node`, and node key return the actual node RLP.
	/// This could be a simple identity operation in the case that the node is sufficiently small, but
	/// may require a database lookup. If `is_root_data` then this is root-data and
	/// is known to be literal.
	/// `partial_key` is encoded nibble slice that addresses the node.
	fn get_raw_or_lookup(&'db self, node: &[u8], partial_key: &[u8]) -> Result<Cow<'db, DBValue>, H::Out, C::Error> {
		match (partial_key == nibbleslice::EMPTY_ENCODED, C::try_decode_hash(node)) {
			(false, Some(key)) => {
				self.db
					.get(&key, partial_key)
					.map(|v| Cow::Owned(v))
					.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(key)))
			}
			_ => Ok(Cow::Owned(DBValue::from_slice(node)))
		}
	}
}

impl<'db, H, C> Trie<H, C> for TrieDB<'db, H, C>
where
	H: Hasher,
	C: NodeCodec<H>
{
	fn root(&self) -> &H::Out { self.root }

	fn get_with<'a, 'key, Q: Query<H>>(&'a self, key: &'key [u8], query: Q) -> Result<Option<Q::Item>, H::Out, C::Error>
		where 'a: 'key
	{
		Lookup {
			db: self.db,
			query: query,
			hash: self.root.clone(),
			marker: PhantomData::<C>,
		}.look_up(NibbleSlice::new(key))
	}

	fn iter<'a>(&'a self) -> Result<
		Box<dyn TrieIterator<H, C, Item=TrieItem<H::Out, C::Error>> + 'a>,
		H::Out,
		C::Error,
	> {
		TrieDBIterator::new(self).map(|iter| Box::new(iter) as Box<_>)
	}
}


#[cfg(feature="std")]
// This is for pretty debug output only
struct TrieAwareDebugNode<'db, 'a, H, C>
where
	H: Hasher + 'db,
	C: NodeCodec<H> + 'db
{
	trie: &'db TrieDB<'db, H, C>,
	node_key: &'a[u8],
	partial_key: ElasticArray36<u8>,
	index: Option<u8>,
}

#[cfg(feature="std")]
impl<'db, 'a, H, C> fmt::Debug for TrieAwareDebugNode<'db, 'a, H, C>
where
	H: Hasher,
	C: NodeCodec<H>
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		if let Ok(node) = self.trie.get_raw_or_lookup(self.node_key, &self.partial_key) {
			match C::decode(&node) {
				Ok(Node::Leaf(slice, value)) =>
					match (f.debug_struct("Node::Leaf"), self.index) {
						(ref mut d, Some(ref i)) => d.field("index", i),
						(ref mut d, _) => d,
					}
						.field("slice", &slice)
						.field("value", &value)
						.finish(),
				Ok(Node::Extension(ref slice, ref item)) =>
					match (f.debug_struct("Node::Extension"), self.index) {
						(ref mut d, Some(ref i)) => d.field("index", i),
						(ref mut d, _) => d,
					}
						.field("slice", &slice)
						.field("item", &TrieAwareDebugNode{
							trie: self.trie,
							node_key: item,
							partial_key: combine_encoded(&self.partial_key, item),
							index: None,
						})
						.finish(),
				Ok(Node::Branch(ref nodes, ref value)) => {
					let nodes: Vec<TrieAwareDebugNode<H, C>> = nodes.into_iter()
						.enumerate()
						.filter_map(|(i, n)| n.map(|n| (i, n)))
						.map(|(i, n)| TrieAwareDebugNode {
							trie: self.trie,
							index: Some(i as u8),
							node_key: n,
							partial_key: combine_encoded(&self.partial_key, n),
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
impl<'db, H, C> fmt::Debug for TrieDB<'db, H, C>
where
	H: Hasher,
	C: NodeCodec<H>
{
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		let root_rlp = self.root_data().unwrap();
		f.debug_struct("TrieDB")
			.field("hash_count", &self.hash_count)
			.field("root", &TrieAwareDebugNode {
				trie: self,
				node_key: &root_rlp[..],
				partial_key: Default::default(),
				index: None,
			})
			.finish()
	}
}

#[derive(Clone, Eq, PartialEq, Debug)]
enum Status {
	Entering,
	At,
	AtChild(usize),
	Exiting,
}

#[derive(Eq, PartialEq, Debug)]
struct Crumb {
	node: OwnedNode,
	status: Status,
}

impl Crumb {
	/// Move on to next status in the node's sequence.
	fn increment(&mut self) {
		self.status = match (&self.status, &self.node) {
			(_, &OwnedNode::Empty) => Status::Exiting,
			(&Status::Entering, _) => Status::At,
			(&Status::At, &OwnedNode::Branch(_)) => Status::AtChild(0),
			(&Status::AtChild(x), &OwnedNode::Branch(_)) if x < 15 => Status::AtChild(x + 1),
			_ => Status::Exiting,
		}
	}
}

/// Iterator for going through all values in the trie.
pub struct TrieDBIterator<'a, H: Hasher + 'a, C: NodeCodec<H> + 'a> {
	db: &'a TrieDB<'a, H, C>,
	trail: Vec<Crumb>,
	key_nibbles: Vec<u8>,
}

impl<'a, H: Hasher, C: NodeCodec<H>> TrieDBIterator<'a, H, C> {
	/// Create a new iterator.
	pub fn new(db: &'a TrieDB<H, C>) -> Result<TrieDBIterator<'a, H, C>, H::Out, C::Error> {
		let mut r = TrieDBIterator { db, trail: Vec::with_capacity(8), key_nibbles: Vec::with_capacity(64) };
		db.root_data().and_then(|root_data| r.descend(&root_data))?;
		Ok(r)
	}

	fn seek<'key>(&mut self, node_data: &DBValue, key: NibbleSlice<'key>) -> Result<(), H::Out, C::Error> {
		let mut node_data = Cow::Borrowed(node_data);
		let mut partial = key;
		let mut full_key_nibbles = 0;
		loop {
			let data = {
				let node = C::decode(&node_data)
					.map_err(|e|Box::new(TrieError::DecoderError(H::Out::default(), e)))?;
				match node {
					Node::Leaf(slice, _) => {
						if slice >= partial {
							self.trail.push(Crumb {
								status: Status::Entering,
								node: node.clone().into(),
							});
						} else {
							self.trail.push(Crumb {
								status: Status::Exiting,
								node: node.clone().into(),
							});
						}

						self.key_nibbles.extend(slice.iter());
						return Ok(())
					},
					Node::Extension(ref slice, ref item) => {
						if partial.starts_with(slice) {
							self.trail.push(Crumb {
								status: Status::At,
								node: node.clone().into(),
							});
							self.key_nibbles.extend(slice.iter());
							full_key_nibbles += slice.len();
							partial = partial.mid(slice.len());
							let data = self.db.get_raw_or_lookup(&*item, &key.encoded_leftmost(full_key_nibbles, false))?;
							data
						} else {
							self.descend(&node_data)?;
							return Ok(())
						}
					},
					Node::Branch(ref nodes, _) => match partial.is_empty() {
						true => {
							self.trail.push(Crumb {
								status: Status::Entering,
								node: node.clone().into(),
							});
							return Ok(())
						},
						false => {
							let i = partial.at(0);
							self.trail.push(Crumb {
								status: Status::AtChild(i as usize),
								node: node.clone().into(),
							});
							self.key_nibbles.push(i);
							full_key_nibbles += 1;
							partial = partial.mid(1);
							if let Some(ref child) = nodes[i as usize] {
								let child = self.db.get_raw_or_lookup(&*child, &key.encoded_leftmost(full_key_nibbles, false))?;
								child
							} else {
								return Ok(())
							}
						}
					},
					_ => return Ok(()),
				}
			};

			node_data = data;
		}
	}

	/// Descend into a payload.
	fn descend(&mut self, d: &[u8]) -> Result<(), H::Out, C::Error> {
		let node_data = &self.db.get_raw_or_lookup(d, &self.encoded_key())?;
		let node = C::decode(&node_data)
			.map_err(|e|Box::new(TrieError::DecoderError(H::Out::default(), e)))?;
		Ok(self.descend_into_node(node.into()))
	}

	/// Descend into a payload.
	fn descend_into_node(&mut self, node: OwnedNode) {
		self.trail.push(Crumb { status: Status::Entering, node });
		match &self.trail.last().expect("just pushed item; qed").node {
			&OwnedNode::Leaf(ref n, _) | &OwnedNode::Extension(ref n, _) => {
				self.key_nibbles.extend((0..n.len()).map(|i| n.at(i)));
			},
			_ => {}
		}
	}

	/// The present key.
	fn key(&self) -> Vec<u8> {
		// collapse the key_nibbles down to bytes.
		let nibbles = &self.key_nibbles;
		let mut i = 1;
		let mut result = <Vec<u8>>::with_capacity(nibbles.len() / 2);
		let len = nibbles.len();
		while i < len {
			result.push(nibbles[i - 1] * 16 + nibbles[i]);
			i += 2;
		}
		result
	}

	/// Encoded key for storage lookup
	fn encoded_key(&self) -> ElasticArray36<u8> {
		let key = self.key();
		let slice = NibbleSlice::new(&key);
		if self.key_nibbles.len() % 2 == 1 {
			NibbleSlice::new_composed(&slice, &NibbleSlice::new_offset(&self.key_nibbles[(self.key_nibbles.len() - 1)..], 1)).encoded(false)
		} else {
			slice.encoded(false)
		}
	}
}

impl<'a, H: Hasher, C: NodeCodec<H>> TrieIterator<H, C> for TrieDBIterator<'a, H, C> {
	/// Position the iterator on the first element with key >= `key`
	fn seek(&mut self, key: &[u8]) -> Result<(), H::Out, C::Error> {
		self.trail.clear();
		self.key_nibbles.clear();
		let root_node = self.db.root_data()?;
		self.seek(&root_node, NibbleSlice::new(key.as_ref()))
	}
}

impl<'a, H: Hasher, C: NodeCodec<H>> Iterator for TrieDBIterator<'a, H, C> {
	type Item = TrieItem<'a, H::Out, C::Error>;

	fn next(&mut self) -> Option<Self::Item> {
		enum IterStep<'b, O, E> {
			Continue,
			PopTrail,
			Descend(Result<Cow<'b, DBValue>, O, E>),
		}
		loop {
			let iter_step = {
				self.trail.last_mut()?.increment();
				let b = self.trail.last().expect("trail.last_mut().is_some(); qed");

				match (b.status.clone(), &b.node) {
					(Status::Exiting, n) => {
						match *n {
							OwnedNode::Leaf(ref n, _) | OwnedNode::Extension(ref n, _) => {
								let l = self.key_nibbles.len();
								self.key_nibbles.truncate(l - n.len());
							},
							OwnedNode::Branch(_) => { self.key_nibbles.pop(); },
							_ => {}
						}
						IterStep::PopTrail
					},
					(Status::At, &OwnedNode::Branch(ref branch)) if branch.has_value() => {
						let value = branch.get_value().expect("already checked `has_value`");
						return Some(Ok((self.key(), DBValue::from_slice(value))));
					},
					(Status::At, &OwnedNode::Leaf(_, ref v)) => {
						return Some(Ok((self.key(), v.clone())));
					},
					(Status::At, &OwnedNode::Extension(_, ref d)) => {
						IterStep::Descend::<H::Out, C::Error>(self.db.get_raw_or_lookup(&*d, &self.encoded_key()))
					},
					(Status::At, &OwnedNode::Branch(_)) => IterStep::Continue,
					(Status::AtChild(i), &OwnedNode::Branch(ref branch)) if branch.index(i).is_some() => {
						match i {
							0 => self.key_nibbles.push(0),
							i => *self.key_nibbles.last_mut()
								.expect("pushed as 0; moves sequentially; removed afterwards; qed") = i as u8,
						}
						IterStep::Descend::<H::Out, C::Error>(self.db.get_raw_or_lookup(
							&branch.index(i).expect("this arm guarded by branch[i].is_some(); qed"),
							&self.encoded_key()))
					},
					(Status::AtChild(i), &OwnedNode::Branch(_)) => {
						if i == 0 {
							self.key_nibbles.push(0);
						}
						IterStep::Continue
					},
					_ => panic!() // Should never see Entering or AtChild without a Branch here.
				}
			};

			match iter_step {
				IterStep::PopTrail => {
					self.trail.pop();
				},
				IterStep::Descend::<H::Out, C::Error>(Ok(d)) => {
					let node = C::decode(&d).ok()?;
					self.descend_into_node(node.into())
				},
				IterStep::Descend::<H::Out, C::Error>(Err(e)) => {
					return Some(Err(e))
				}
				IterStep::Continue => {},
			}
		}
	}
}

#[cfg(test)]
mod tests {
	use memory_db::{MemoryDB, PrefixedKey};
	use keccak_hasher::KeccakHasher;
	use DBValue;
	use reference_trie::{RefTrieDB, RefTrieDBMut, RefLookup, Trie, TrieMut, NibbleSlice};

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
		assert_eq!(iter.next().unwrap().unwrap(), (hex!("0103000000000000000464").to_vec(), DBValue::from_slice(&hex!("fffffffffe")[..])));
		iter.seek(&hex!("00")[..]).unwrap();
		assert_eq!(pairs, iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>());
		let mut iter = t.iter().unwrap();
		iter.seek(&hex!("0103000000000000000465")[..]).unwrap();
		assert_eq!(&pairs[1..], &iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>()[..]);
	}

	#[test]
	fn iterator() {
		let d = vec![DBValue::from_slice(b"A"), DBValue::from_slice(b"AA"), DBValue::from_slice(b"AB"), DBValue::from_slice(b"B")];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			for x in &d {
				t.insert(x, x).unwrap();
			}
		}

		let t = RefTrieDB::new(&memdb, &root).unwrap();
		assert_eq!(d.iter().map(|i| i.clone().into_vec()).collect::<Vec<_>>(), t.iter().unwrap().map(|x| x.unwrap().0).collect::<Vec<_>>());
		assert_eq!(d, t.iter().unwrap().map(|x| x.unwrap().1).collect::<Vec<_>>());
	}

	#[test]
	fn iterator_seek() {
		let d = vec![ DBValue::from_slice(b"A"), DBValue::from_slice(b"AA"), DBValue::from_slice(b"AB"), DBValue::from_slice(b"B") ];

		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			for x in &d {
				t.insert(x, x).unwrap();
			}
		}

		let t = RefTrieDB::new(&memdb, &root).unwrap();
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
	fn get_len() {
		let mut memdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut memdb, &mut root);
			t.insert(b"A", b"ABC").unwrap();
			t.insert(b"B", b"ABCBA").unwrap();
		}

		let t = RefTrieDB::new(&memdb, &root).unwrap();
		assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
		assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(5));
		assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
	}

	#[test]
	fn debug_output_supports_pretty_print() {
		let d = vec![ DBValue::from_slice(b"A"), DBValue::from_slice(b"AA"), DBValue::from_slice(b"AB"), DBValue::from_slice(b"B") ];

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
                                        65
                                    ]
                                },
                                Node::Leaf {
                                    index: 2,
                                    slice: ,
                                    value: [
                                        65,
                                        66
                                    ]
                                }
                            ],
                            value: None
                        }
                    ],
                    value: Some(
                        [
                            65
                        ]
                    )
                },
                Node::Leaf {
                    index: 2,
                    slice: ,
                    value: [
                        66
                    ]
                }
            ],
            value: None
        }
    }
}");
	}

	#[test]
	fn test_lookup_with_corrupt_data_returns_decoder_error() {
		use std::marker::PhantomData;

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
		let lookup = RefLookup { db: t.db(), query: q, hash: root, marker: PhantomData };
		let query_result = lookup.look_up(NibbleSlice::new(b"A"));
		assert_eq!(query_result.unwrap().unwrap(), true);
	}
}

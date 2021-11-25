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

//! Trie lookup via HashDB.

use hash_db::HashDBRef;
use crate::nibble::NibbleSlice;
use crate::node::{Node, NodeHandle, decode_hash, NodeOwned, NodeHandleOwned};
use crate::node_codec::NodeCodec;
use crate::rstd::boxed::Box;
use super::{DBValue, Result, TrieError, Query, TrieLayout, CError, TrieHash};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;

/// Trie lookup helper object.
pub struct Lookup<'a, L: TrieLayout, Q: Query<L::Hash>> {
	/// database to query from.
	pub db: &'a dyn HashDBRef<L::Hash, DBValue>,
	/// Query object to record nodes and transform data.
	pub query: Q,
	/// Hash to start at
	pub hash: TrieHash<L>,
}

impl<'a, L, Q> Lookup<'a, L, Q>
where
	L: TrieLayout,
	Q: Query<L::Hash>,
{
	/// Look up the given key. If the value is found, it will be passed to the given
	/// function to decode or copy.
	///
	/// It uses the given cache to speed-up lookups.
	pub fn look_up_with_cache(
		mut self,
		key: NibbleSlice,
		cache: &mut dyn crate::NodeCache<L>,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let mut partial = key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

		if let Some(node) = cache.fast_cache(key.right().1) {
			match &**node {
				NodeOwned::Leaf(_, value) => return Ok(Some(self.query.decode(&value))),
				NodeOwned::NibbledBranch(_, _, value) => return Ok(value.as_ref().map(|v| self.query.decode(&v))),
				_ => unreachable!(),
			}
		}

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let mut node: &_ = cache.get_or_insert(hash, &mut || {
				let node_data = match self.db.get(&hash, key.mid(key_nibbles).left()) {
					Some(value) => value,
					None => return Err(Box::new(match depth {
						0 => TrieError::InvalidStateRoot(hash),
						_ => TrieError::IncompleteDatabase(hash),
					}))
				};

				self.query.record(&hash, &node_data, depth);
				let decoded = match L::Codec::decode(&node_data[..]) {
					Ok(node) => node,
					Err(e) => {
						return Err(Box::new(TrieError::DecoderError(hash, e)))
					}
				};

				decoded.to_owned_node::<L>()
			})?;

			// this loop iterates through all inline children (usually max 1)
			// without incrementing the depth.
			loop {
				let next_node = match &**node {
					NodeOwned::Leaf(slice, value) => {
						if partial == *slice {
							let node_clone = node.clone();
							let decoded = self.query.decode(&value);
							drop(node);
							cache.fast_cache_insert(key.right().1, node_clone);
							return Ok(Some(decoded))
						} else {
							return Ok(None)
						}
					}
					NodeOwned::Extension(slice, item) => {
						if partial.starts_with_vec(&slice) {
							partial = partial.mid(slice.len());
							key_nibbles += slice.len();
							item
						} else {
							return Ok(None)
						}
					}
					NodeOwned::Branch(children, value) => if partial.is_empty() {
						return Ok(value.as_ref().map(move |val| self.query.decode(val)))
					} else {
						match &children[partial.at(0) as usize] {
							Some(x) => {
								partial = partial.mid(1);
								key_nibbles += 1;
								x
							}
							None => return Ok(None)
						}
					},
					NodeOwned::NibbledBranch(slice, children, value) => {
						if !partial.starts_with_vec(&slice) {
							return Ok(None)
						}

						if partial.len() == slice.len() {
							if let Some(value) = value.as_ref() {
								let node_clone = node.clone();
								let decoded = self.query.decode(&value);
								drop(node);
								cache.fast_cache_insert(key.right().1, node_clone);
								return Ok(Some(decoded))
							} else {
								return Ok(None)
							}
						} else {
							match &children[partial.at(slice.len()) as usize] {
								Some(x) => {
									partial = partial.mid(slice.len() + 1);
									key_nibbles += slice.len() + 1;
									x
								}
								None => return Ok(None)
							}
						}
					},
					NodeOwned::Empty => return Ok(None),
				};

				// check if new node data is inline or hash.
				match next_node {
					NodeHandleOwned::Hash(new_hash) => {
						hash = *new_hash;
						break;
					},
					NodeHandleOwned::Inline(inline_node) => {
						node = &inline_node;
					},
				}
			}
		}

		Ok(None)
	}

	/// Look up the given key. If the value is found, it will be passed to the given
	/// function to decode or copy.
	pub fn look_up(
		mut self,
		key: NibbleSlice,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let mut partial = key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let node_data = match self.db.get(&hash, key.mid(key_nibbles).left()) {
				Some(value) => value,
				None => return Err(Box::new(match depth {
					0 => TrieError::InvalidStateRoot(hash),
					_ => TrieError::IncompleteDatabase(hash),
				})),
			};

			self.query.record(&hash, &node_data, depth);

			// this loop iterates through all inline children (usually max 1)
			// without incrementing the depth.
			let mut node_data = &node_data[..];
			loop {
				let decoded = match L::Codec::decode(node_data) {
					Ok(node) => node,
					Err(e) => {
						return Err(Box::new(TrieError::DecoderError(hash, e)))
					}
				};
				let next_node = match decoded {
					Node::Leaf(slice, value) => {
						return Ok(match slice == partial {
							true => Some(self.query.decode(value)),
							false => None,
						})
					}
					Node::Extension(slice, item) => {
						if partial.starts_with(&slice) {
							partial = partial.mid(slice.len());
							key_nibbles += slice.len();
							item
						} else {
							return Ok(None)
						}
					}
					Node::Branch(children, value) => match partial.is_empty() {
						true => return Ok(value.map(move |val| self.query.decode(val))),
						false => match children[partial.at(0) as usize] {
							Some(x) => {
								partial = partial.mid(1);
								key_nibbles += 1;
								x
							}
							None => return Ok(None)
						}
					},
					Node::NibbledBranch(slice, children, value) => {
						if !partial.starts_with(&slice) {
							return Ok(None)
						}

						match partial.len() == slice.len() {
							true => return Ok(value.map(move |val| self.query.decode(val))),
							false => match children[partial.at(slice.len()) as usize] {
								Some(x) => {
									partial = partial.mid(slice.len() + 1);
									key_nibbles += slice.len() + 1;
									x
								}
								None => return Ok(None)
							}
						}
					},
					Node::Empty => return Ok(None),
				};

				// check if new node data is inline or hash.
				match next_node {
					NodeHandle::Hash(data) => {
						hash = decode_hash::<L::Hash>(data)
							.ok_or_else(|| Box::new(TrieError::InvalidHash(hash, data.to_vec())))?;
						break;
					},
					NodeHandle::Inline(data) => {
						node_data = data;
					},
				}
			}
		}
		Ok(None)
	}
}

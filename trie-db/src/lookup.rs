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
use crate::TrieCache;
use crate::nibble::NibbleSlice;
use crate::node::{Node, NodeHandle, decode_hash, NodeOwned, NodeHandleOwned};
use crate::node_codec::NodeCodec;
use crate::rstd::boxed::Box;
use super::{DBValue, Result, TrieError, Query, TrieLayout, CError, TrieHash};
#[cfg(not(feature = "std"))]
use alloc::vec::Vec;
use bytes::Bytes;

/// Trie lookup helper object.
pub struct Lookup<'a, 'cache, L: TrieLayout, Q: Query<L::Hash>> {
	/// database to query from.
	pub db: &'a dyn HashDBRef<L::Hash, DBValue>,
	/// Query object to record nodes and transform data.
	pub query: Q,
	/// Hash to start at
	pub hash: TrieHash<L>,
	/// Optional cache that should be used to speed up the lookup.
	pub cache: Option<&'cache mut dyn TrieCache<L>>,
}

impl<'a, 'cache, L, Q> Lookup<'a, 'cache, L, Q>
where
	L: TrieLayout,
	Q: Query<L::Hash>,
{
	/// Look up the given `nibble_key`.
	///
	/// If the value is found, it will be passed to the given function to decode or copy.
	///
	/// The given `full_key` should be the full key to the data that is requested. This will
	/// be used when there is a cache to potentially speed up the lookup.
	pub fn look_up(
		mut self,
		full_key: &[u8],
		nibble_key: NibbleSlice,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		match self.cache.take() {
			Some(cache) => self.look_up_with_cache(full_key, nibble_key, cache),
			None => self.look_up_without_cache(full_key, nibble_key),
		}
	}

	/// Look up the given key. If the value is found, it will be passed to the given
	/// function to decode or copy.
	///
	/// It uses the given cache to speed-up lookups.
	fn look_up_with_cache(
		mut self,
		full_key: &[u8],
		nibble_key: NibbleSlice,
		cache: &mut dyn crate::TrieCache<L>,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let res = if let Some(value) = cache.lookup_data_for_key(full_key) {
			value.clone()
		} else {
			let res = self.look_up_with_cache_internal(nibble_key, cache)?;
			cache.cache_data_for_key(full_key, res.clone());
			res
		};

		Ok(res.map(|v| self.query.decode(&v)))
	}

	fn look_up_with_cache_internal(
		&mut self,
		nibble_key: NibbleSlice,
		cache: &mut dyn crate::TrieCache<L>,
	) -> Result<Option<Bytes>, TrieHash<L>, CError<L>> {
		let mut partial = nibble_key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let mut node: &_ = cache.get_or_insert_node(hash, &mut || {
				let node_data = match self.db.get(&hash, nibble_key.mid(key_nibbles).left()) {
					Some(value) => value,
					None => return Err(Box::new(match depth {
						0 => TrieError::InvalidStateRoot(hash),
						_ => TrieError::IncompleteDatabase(hash),
					}))
				};

				// self.query.record(&hash, &node_data, depth);
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
				let next_node = match node {
					NodeOwned::Leaf(slice, value) => {
						return Ok((partial == *slice).then(|| value.clone()))
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
						return Ok(value.clone())
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
								return Ok(Some(value.clone()))
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
	///
	/// This version doesn't works without the cache.
	fn look_up_without_cache(
		mut self,
		full_key: &[u8],
		nibble_key: NibbleSlice,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let mut partial = nibble_key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let node_data = match self.db.get(&hash, nibble_key.mid(key_nibbles).left()) {
				Some(value) => value,
				None => return Err(Box::new(match depth {
					0 => TrieError::InvalidStateRoot(hash),
					_ => TrieError::IncompleteDatabase(hash),
				})),
			};

			// self.query.record(&hash, &node_data, depth);

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
						return Ok((slice == partial).then(|| self.query.decode(value)))
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
					Node::Branch(children, value) => if partial.is_empty() {
						return Ok(value.map(move |val| self.query.decode(val)))
					} else {
						match children[partial.at(0) as usize] {
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

						if partial.len() == slice.len() {
							return Ok(value.map(move |val| self.query.decode(val)))
						} else {
							match children[partial.at(slice.len()) as usize] {
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

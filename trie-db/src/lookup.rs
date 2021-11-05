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
use hashbrown::{HashMap, hash_map::Entry};
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
	pub fn look_up(
		mut self,
		key: NibbleSlice,
		cache: &mut HashMap<TrieHash<L>, NodeOwned<TrieHash<L>>>,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let mut partial = key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let mut node: &_ = cache.entry(hash).or_insert_with(|| {
					let node_data = match self.db.get(&hash, key.mid(key_nibbles).left()) {
						Some(value) => value,
						None => /*return Err(Box::new(match depth {
							0 => TrieError::InvalidStateRoot(hash),
							_ => TrieError::IncompleteDatabase(hash),
						}))*/ unimplemented!(),
					};

					self.query.record(&hash, &node_data, depth);
					let mut node_data = &node_data[..];
					let decoded = match L::Codec::decode(node_data) {
						Ok(node) => node,
						Err(e) => {
							unimplemented!()
							// return Err(Box::new(TrieError::DecoderError(hash, e)))
						}
					};

					decoded.to_owned_2::<L>().unwrap_or_else(|_| panic!())
				}
			);
			// this loop iterates through all inline children (usually max 1)
			// without incrementing the depth.
			loop {
				let next_node = match node {
					NodeOwned::Leaf(slice, value) => {
						return Ok(partial.vec_equal(&slice).then(|| self.query.decode(&value)))
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
							return Ok(value.as_ref().map(move |val| self.query.decode(val)))
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
						node = &*inline_node;
					},
				}
			}
		}
		Ok(None)
	}
}

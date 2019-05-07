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
use nibble::NibbleSlice;
use node::Node;
use node_codec::NodeCodec;
use super::{DBValue, Result, TrieError, Query, TrieLayOut, CError, TrieHash, ChildSliceIx};

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

/// Trie lookup helper object.
pub struct Lookup<'a, L: TrieLayOut, Q: Query<L::H>> {
	/// database to query from.
	pub db: &'a HashDBRef<L::H, DBValue>,
	/// Query object to record nodes and transform data.
	pub query: Q,
	/// Hash to start at
	pub hash: TrieHash<L>,
}

impl<'a, L, Q> Lookup<'a, L, Q>
where
	L: TrieLayOut,
	Q: Query<L::H>,
{
	/// Look up the given key. If the value is found, it will be passed to the given
	/// function to decode or copy.
	pub fn look_up(mut self, key: NibbleSlice<L::N>) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
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
				let decoded = match L::C::decode(node_data) {
					Ok(node) => node,
					Err(e) => {
						return Err(Box::new(TrieError::DecoderError(hash, e)))
					}
				};
				match decoded {
					Node::Leaf(slice, value) => {
						return Ok(match slice == partial {
							true => Some(self.query.decode(value)),
							false => None,
						})
					}
					Node::Extension(slice, item) => {
						if partial.starts_with(&slice) {
							node_data = item;
							partial = partial.mid(slice.len());
							key_nibbles += slice.len();
						} else {
							return Ok(None)
						}
					}
					Node::Branch(children, value) => match partial.is_empty() {
						true => return Ok(value.map(move |val| self.query.decode(val))),
						false => match children.0.slice_at(partial.at(0) as usize, children.1) {
							Some(x) => {
								node_data = x;
								partial = partial.mid(1);
								key_nibbles += 1;
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
							false => match children.0.slice_at(partial.at(slice.len()) as usize, children.1) {
								Some(x) => {
									node_data = x;
									partial = partial.mid(slice.len() + 1);
								}
								None => return Ok(None)
							}
						}
					},
					Node::Empty => return Ok(None),
				}

				// check if new node data is inline or hash.
				if let Some(h) = L::C::try_decode_hash(&node_data) {
					hash = h;
					break
				}
			}
		}
		Ok(None)
	}
}

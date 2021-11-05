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

use super::{CError, DBValue, Query, Result, TrieError, TrieHash, TrieLayout};
use crate::{
	nibble::NibbleSlice,
	node::{decode_hash, Node, NodeHandle, Value},
	node_codec::NodeCodec,
	rstd::boxed::Box,
};
use hash_db::{HashDBRef, Prefix};

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
	fn decode(
		mut self,
		v: Value,
		prefix: Prefix,
		depth: u32,
	) -> Result<Q::Item, TrieHash<L>, CError<L>> {
		match v {
			Value::Inline(value) => Ok(self.query.decode(value)),
			Value::Node(_, Some(value)) => Ok(self.query.decode(value.as_slice())),
			Value::Node(hash, None) => {
				let mut res = TrieHash::<L>::default();
				res.as_mut().copy_from_slice(hash);
				if let Some(value) = self.db.get(&res, prefix) {
					self.query.record(&res, &value, depth);
					Ok(self.query.decode(value.as_slice()))
				} else {
					Err(Box::new(TrieError::IncompleteDatabase(res)))
				}
			},
		}
	}

	/// Look up the given key. If the value is found, it will be passed to the given
	/// function to decode or copy.
	pub fn look_up(mut self, key: NibbleSlice) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let mut partial = key;
		let mut key_nibbles = 0;

		let mut full_key = key.clone();
		full_key.advance(key.len());
		let full_key = full_key.left();

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let hash = self.hash;
			let node_data = match self.db.get(&hash, key.mid(key_nibbles).left()) {
				Some(value) => value,
				None =>
					return Err(Box::new(match depth {
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
					Err(e) => return Err(Box::new(TrieError::DecoderError(hash, e))),
				};
				let next_node = match decoded {
					Node::Leaf(slice, value) =>
						return Ok(match slice == partial {
							true => Some(self.decode(value, full_key, depth)?),
							false => None,
						}),
					Node::Extension(slice, item) =>
						if partial.starts_with(&slice) {
							partial = partial.mid(slice.len());
							key_nibbles += slice.len();
							item
						} else {
							return Ok(None)
						},
					Node::Branch(children, value) => match partial.is_empty() {
						true =>
							if let Some(value) = value {
								return Ok(Some(self.decode(value, full_key, depth)?))
							} else {
								return Ok(None)
							},
						false => match children[partial.at(0) as usize] {
							Some(x) => {
								partial = partial.mid(1);
								key_nibbles += 1;
								x
							},
							None => return Ok(None),
						},
					},
					Node::NibbledBranch(slice, children, value) => {
						if !partial.starts_with(&slice) {
							return Ok(None)
						}

						match partial.len() == slice.len() {
							true =>
								if let Some(value) = value {
									return Ok(Some(self.decode(value, full_key, depth)?))
								} else {
									return Ok(None)
								},
							false => match children[partial.at(slice.len()) as usize] {
								Some(x) => {
									partial = partial.mid(slice.len() + 1);
									key_nibbles += slice.len() + 1;
									x
								},
								None => return Ok(None),
							},
						}
					},
					Node::Empty => return Ok(None),
				};

				// check if new node data is inline or hash.
				match next_node {
					NodeHandle::Hash(data) => {
						self.hash = decode_hash::<L::Hash>(data)
							.ok_or_else(|| Box::new(TrieError::InvalidHash(hash, data.to_vec())))?;
						break
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

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

use hash_db::{HashDBRef, Hasher};
use nibbleslice::NibbleSlice;
use node::Node;
use node_codec::NodeCodec;
use super::{DBValue, Result, TrieError, Query};
use ::core_::marker::PhantomData;

#[cfg(not(feature = "std"))]
use alloc::boxed::Box;

/// Trie lookup helper object.
pub struct Lookup<'a, H: Hasher + 'a, C: NodeCodec<H>, Q: Query<H>> {
	/// database to query from.
	pub db: &'a dyn HashDBRef<H, DBValue>,
	/// Query object to record nodes and transform data.
	pub query: Q,
	/// Hash to start at
	pub hash: H::Out,
	pub marker: PhantomData<C>, // TODO: probably not needed when all is said and done? When Query is made generic?
}

impl<'a, H, C, Q> Lookup<'a, H, C, Q>
where
	H: Hasher,
	C: NodeCodec<H>,
	Q: Query<H>,
{
	/// Look up the given key. If the value is found, it will be passed to the given
	/// function to decode or copy.
	pub fn look_up(mut self, key: NibbleSlice) -> Result<Option<Q::Item>, H::Out, C::Error> {
		let mut partial = key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let node_data = match self.db.get(&hash, &key.encoded_leftmost(key_nibbles, false)) {
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
				let decoded = match C::decode(node_data) {
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
						false => match children[partial.at(0) as usize] {
							Some(x) => {
								node_data = x;
								partial = partial.mid(1);
								key_nibbles += 1;
							}
							None => return Ok(None)
						}
					},
					_ => return Ok(None),
				}

				// check if new node data is inline or hash.
				if let Some(h) = C::try_decode_hash(&node_data) {
					hash = h;
					break
				}
			}
		}
		Ok(None)
	}
}

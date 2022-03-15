// Copyright 2017, 2018 Parity Technologies
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS"uhh BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

//! Trie lookup via HashDB.

use crate::{
	nibble::NibbleSlice,
	node::{decode_hash, Node, NodeHandle, NodeHandleOwned, NodeOwned, Value, ValueOwned},
	node_codec::NodeCodec,
	rstd::boxed::Box,
	Bytes, CError, DBValue, KeyTrieAccessValue, Query, Result, TrieAccess, TrieCache, TrieError,
	TrieHash, TrieLayout, TrieRecorder,
};
use hash_db::{HashDBRef, Prefix};

/// Trie lookup helper object.
pub struct Lookup<'a, 'cache, L: TrieLayout, Q: Query<L::Hash>> {
	/// database to query from.
	pub db: &'a dyn HashDBRef<L::Hash, DBValue>,
	/// Query object to record nodes and transform data.
	pub query: Q,
	/// Hash to start at
	pub hash: TrieHash<L>,
	/// Optional cache that should be used to speed up the lookup.
	pub cache: Option<&'cache mut dyn TrieCache<L::Codec>>,
	/// Optional recorder that will be called to record all trie accesses.
	pub recorder: Option<&'cache mut dyn TrieRecorder<TrieHash<L>>>,
}

impl<'a, 'cache, L, Q> Lookup<'a, 'cache, L, Q>
where
	L: TrieLayout,
	Q: Query<L::Hash>,
{
	/// Load the given value.
	///
	/// This will access the `db` if the value is not already in memory, but then it will put it
	/// into the given `cache` as `NodeOwned::Value`.
	///
	/// Returns the bytes representing the value.
	fn load_value(
		mut self,
		v: Value,
		prefix: Prefix,
		full_key: &[u8],
	) -> Result<Q::Item, TrieHash<L>, CError<L>> {
		match v {
			Value::Inline(value) => Ok(self.query.decode(value)),
			Value::Node(hash) => {
				let mut res = TrieHash::<L>::default();
				res.as_mut().copy_from_slice(hash);
				if let Some(value) = self.db.get(&res, prefix) {
					self.recorder.record(TrieAccess::Value {
						hash: res,
						value: value.as_slice().into(),
						full_key,
					});

					Ok(self.query.decode(&value))
				} else {
					Err(Box::new(TrieError::IncompleteDatabase(res)))
				}
			},
		}
	}

	/// Load the given value.
	///
	/// This will access the `db` if the value is not already in memory, but then it will put it
	/// into the given `cache` as `NodeOwned::Value`.
	///
	/// Returns the bytes representing the value and its hash.
	fn load_owned_value(
		&mut self,
		v: ValueOwned<TrieHash<L>>,
		prefix: Prefix,
		full_key: &[u8],
		cache: &mut dyn crate::TrieCache<L::Codec>,
	) -> Result<Option<(Bytes, TrieHash<L>)>, TrieHash<L>, CError<L>> {
		match v {
			ValueOwned::Inline(value, hash) => Ok(Some((value.clone(), hash))),
			ValueOwned::Node(hash) => {
				let value = cache
					.get_or_insert_node(hash, &mut || {
						let value = self
							.db
							.get(&hash, prefix)
							.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(hash)))?;

						Ok(NodeOwned::Value(value.into(), hash))
					})
					.map(|n| n.data().cloned())?;

				// `value` should always be `Some(_)`, but better be defensive.
				if let Some(ref value) = value {
					self.recorder.record(TrieAccess::Value {
						hash,
						value: value[..].into(),
						full_key,
					});
				}

				Ok(value.map(|v| (v, hash)))
			},
		}
	}

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
			None => self.look_up_without_cache(nibble_key, full_key),
		}
	}

	/// Look up the value hash for the given `nibble_key`.
	///
	/// The given `full_key` should be the full key to the data that is requested. This will
	/// be used when there is a cache to potentially speed up the lookup.
	pub fn look_up_hash(
		mut self,
		full_key: &[u8],
		nibble_key: NibbleSlice,
	) -> Result<Option<TrieHash<L>>, TrieHash<L>, CError<L>> {
		match self.cache.take() {
			Some(cache) => self.look_up_hash_with_cache(full_key, nibble_key, cache),
			None => self.look_up_without_cache(nibble_key, full_key),
		}
	}

	/// Look up the value hash for the given key.
	///
	/// It uses the given cache to speed-up lookups.
	fn look_up_hash_with_cache(
		mut self,
		full_key: &[u8],
		nibble_key: NibbleSlice,
		cache: &mut dyn crate::TrieCache<L::Codec>,
	) -> Result<Option<TrieHash<L>>, TrieHash<L>, CError<L>> {
		let res = if let Some(value) =
			cache.lookup_value_for_key(full_key).map(|v| v.as_ref().map(|v| v.hash))
		{
			self.recorder.record(TrieAccess::Key {
				key: full_key,
				value: value
					.as_ref()
					.map_or_else(|| KeyTrieAccessValue::NotFound, |_| KeyTrieAccessValue::HashOnly),
			});

			value
		} else {
			let data = self.look_up_with_cache_internal(nibble_key, full_key, cache)?;

			cache.cache_value_for_key(full_key, data.clone().map(Into::into));

			data.map(|d| d.1)
		};

		Ok(res)
	}

	/// Look up the given key. If the value is found, it will be passed to the given
	/// function to decode or copy.
	///
	/// It uses the given cache to speed-up lookups.
	fn look_up_with_cache(
		mut self,
		full_key: &[u8],
		nibble_key: NibbleSlice,
		cache: &mut dyn crate::TrieCache<L::Codec>,
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let res = if let Some(value) = cache
			.lookup_value_for_key(full_key)
			.and_then(|v| v.as_ref().map(|v| v.upgrade()))
		{
			self.recorder.record(TrieAccess::Key {
				key: full_key,
				value: value.as_ref().map_or_else(
					|| KeyTrieAccessValue::NotFound,
					|v| KeyTrieAccessValue::Found(v.0.as_ref().into()),
				),
			});

			value
		} else {
			let data = self.look_up_with_cache_internal(nibble_key, full_key, cache)?;

			cache.cache_value_for_key(full_key, data.clone().map(Into::into));
			data
		};

		Ok(res.map(|v| self.query.decode(&v.0)))
	}

	fn look_up_with_cache_internal(
		&mut self,
		nibble_key: NibbleSlice,
		full_key: &[u8],
		cache: &mut dyn crate::TrieCache<L::Codec>,
	) -> Result<Option<(Bytes, TrieHash<L>)>, TrieHash<L>, CError<L>> {
		let mut partial = nibble_key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

		let mut prefix = nibble_key.clone();
		prefix.advance(nibble_key.len());
		let prefix = prefix.left();

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let mut node = cache.get_or_insert_node(hash, &mut || {
				let node_data = match self.db.get(&hash, nibble_key.mid(key_nibbles).left()) {
					Some(value) => value,
					None =>
						return Err(Box::new(match depth {
							0 => TrieError::InvalidStateRoot(hash),
							_ => TrieError::IncompleteDatabase(hash),
						})),
				};

				let decoded = match L::Codec::decode(&node_data[..]) {
					Ok(node) => node,
					Err(e) => return Err(Box::new(TrieError::DecoderError(hash, e))),
				};

				decoded.to_owned_node::<L>()
			})?;

			self.recorder.record(TrieAccess::NodeOwned { hash, node_owned: node });

			// this loop iterates through all inline children (usually max 1)
			// without incrementing the depth.
			loop {
				let next_node = match node {
					NodeOwned::Leaf(slice, value) =>
						return if partial == *slice {
							let value = (*value).clone();
							drop(node);
							self.load_owned_value(value, prefix, full_key, cache)
						} else {
							Ok(None)
						},
					NodeOwned::Extension(slice, item) =>
						if partial.starts_with_vec(&slice) {
							partial = partial.mid(slice.len());
							key_nibbles += slice.len();
							item
						} else {
							return Ok(None)
						},
					NodeOwned::Branch(children, value) =>
						if partial.is_empty() {
							return if let Some(value) = value.clone() {
								drop(node);
								self.load_owned_value(value, prefix, full_key, cache)
							} else {
								Ok(None)
							}
						} else {
							match &children[partial.at(0) as usize] {
								Some(x) => {
									partial = partial.mid(1);
									key_nibbles += 1;
									x
								},
								None => return Ok(None),
							}
						},
					NodeOwned::NibbledBranch(slice, children, value) => {
						if !partial.starts_with_vec(&slice) {
							return Ok(None)
						}

						if partial.len() == slice.len() {
							return if let Some(value) = value.clone() {
								drop(node);
								self.load_owned_value(value, prefix, full_key, cache)
							} else {
								Ok(None)
							}
						} else {
							match &children[partial.at(slice.len()) as usize] {
								Some(x) => {
									partial = partial.mid(slice.len() + 1);
									key_nibbles += slice.len() + 1;
									x
								},
								None => return Ok(None),
							}
						}
					},
					NodeOwned::Empty => return Ok(None),
					NodeOwned::Value(_, _) => {
						unreachable!(
							"`NodeOwned::Value` can not be reached by using the hash of a node. \
							 `NodeOwned::Value` is only constructed when loading a value into memory, \
							 which needs to have a different hash than any node; qed",
						)
					},
				};

				// check if new node data is inline or hash.
				match next_node {
					NodeHandleOwned::Hash(new_hash) => {
						hash = *new_hash;
						break
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
		nibble_key: NibbleSlice,
		full_key: &[u8],
	) -> Result<Option<Q::Item>, TrieHash<L>, CError<L>> {
		let mut partial = nibble_key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

		let mut full_nibble_key = nibble_key.clone();
		full_nibble_key.advance(nibble_key.len());
		let full_nibble_key = full_nibble_key.left();

		// this loop iterates through non-inline nodes.
		for depth in 0.. {
			let node_data = match self.db.get(&hash, nibble_key.mid(key_nibbles).left()) {
				Some(value) => value,
				None =>
					return Err(Box::new(match depth {
						0 => TrieError::InvalidStateRoot(hash),
						_ => TrieError::IncompleteDatabase(hash),
					})),
			};

			self.recorder.record(TrieAccess::EncodedNode {
				hash,
				encoded_node: node_data.as_slice().into(),
			});

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
						return (slice == partial)
							.then(|| self.load_value(value, full_nibble_key, full_key))
							.transpose(),
					Node::Extension(slice, item) =>
						if partial.starts_with(&slice) {
							partial = partial.mid(slice.len());
							key_nibbles += slice.len();
							item
						} else {
							return Ok(None)
						},
					Node::Branch(children, value) =>
						if partial.is_empty() {
							return value
								.map(|val| self.load_value(val, full_nibble_key, full_key))
								.transpose()
						} else {
							match children[partial.at(0) as usize] {
								Some(x) => {
									partial = partial.mid(1);
									key_nibbles += 1;
									x
								},
								None => return Ok(None),
							}
						},
					Node::NibbledBranch(slice, children, value) => {
						if !partial.starts_with(&slice) {
							return Ok(None)
						}

						if partial.len() == slice.len() {
							return value
								.map(|val| self.load_value(val, full_nibble_key, full_key))
								.transpose()
						} else {
							match children[partial.at(slice.len()) as usize] {
								Some(x) => {
									partial = partial.mid(slice.len() + 1);
									key_nibbles += slice.len() + 1;
									x
								},
								None => return Ok(None),
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

	/// Traverse the trie to access `key`.
	///
	/// This is mainly useful when trie access should be recorded and a cache was active.
	/// With an active cache, there can be a short cut of just returning the data, without
	/// traversing the trie, but when we are recording a proof we need to get all trie nodes. So,
	/// this function can then be used to get all of the trie nodes to access `key`.
	///
	/// Returns `true` when the key was found inside the trie.
	pub fn traverse_to(mut self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		match self.cache.take() {
			Some(cache) => self
				.look_up_with_cache_internal(NibbleSlice::new(key), key, cache)
				.map(|b| b.is_some()),
			None => self.look_up_without_cache(NibbleSlice::new(key), key).map(|b| b.is_some()),
		}
	}
}

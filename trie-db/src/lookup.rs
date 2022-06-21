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

use crate::{
	nibble::NibbleSlice,
	node::{decode_hash, Node, NodeHandle, NodeHandleOwned, NodeOwned, Value, ValueOwned},
	node_codec::NodeCodec,
	rstd::boxed::Box,
	Bytes, CError, CachedValue, DBValue, Query, RecordedForKey, Result, TrieAccess, TrieCache,
	TrieError, TrieHash, TrieLayout, TrieRecorder,
};
use hash_db::{HashDBRef, Hasher, Prefix};

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
		v: Value,
		prefix: Prefix,
		full_key: &[u8],
		db: &dyn HashDBRef<L::Hash, DBValue>,
		recorder: &mut Option<&mut dyn TrieRecorder<TrieHash<L>>>,
		query: Q,
	) -> Result<Q::Item, TrieHash<L>, CError<L>> {
		match v {
			Value::Inline(value) => Ok(query.decode(&value)),
			Value::Node(hash) => {
				let mut res = TrieHash::<L>::default();
				res.as_mut().copy_from_slice(hash);
				if let Some(value) = db.get(&res, prefix) {
					if let Some(recorder) = recorder {
						recorder.record(TrieAccess::Value {
							hash: res,
							value: value.as_slice().into(),
							full_key,
						});
					}

					Ok(query.decode(&value))
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
		v: ValueOwned<TrieHash<L>>,
		prefix: Prefix,
		full_key: &[u8],
		cache: &mut dyn crate::TrieCache<L::Codec>,
		db: &dyn HashDBRef<L::Hash, DBValue>,
		recorder: &mut Option<&mut dyn TrieRecorder<TrieHash<L>>>,
	) -> Result<(Bytes, TrieHash<L>), TrieHash<L>, CError<L>> {
		match v {
			ValueOwned::Inline(value, hash) => Ok((value.clone(), hash)),
			ValueOwned::Node(hash) => {
				let node = cache.get_or_insert_node(hash, &mut || {
					let value = db
						.get(&hash, prefix)
						.ok_or_else(|| Box::new(TrieError::IncompleteDatabase(hash)))?;

					Ok(NodeOwned::Value(value.into(), hash))
				})?;

				let value = node
					.data()
					.expect(
						"We are caching a `NodeOwned::Value` for a value node \
						hash and this cached node has always data attached; qed",
					)
					.clone();

				if let Some(recorder) = recorder {
					recorder.record(TrieAccess::Value {
						hash,
						value: value.as_ref().into(),
						full_key,
					});
				}

				Ok((value, hash))
			},
		}
	}

	fn record<'b>(&mut self, get_access: impl FnOnce() -> TrieAccess<'b, TrieHash<L>>)
	where
		TrieHash<L>: 'b,
	{
		if let Some(recorder) = self.recorder.as_mut() {
			recorder.record(get_access());
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
			None => self.look_up_without_cache(nibble_key, full_key, Self::load_value),
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
			None => self.look_up_without_cache(
				nibble_key,
				full_key,
				|v, _, full_key, _, recorder, _| {
					Ok(match v {
						Value::Inline(v) => {
							let hash = L::Hash::hash(&v);

							if let Some(recoder) = recorder.as_mut() {
								recoder.record(TrieAccess::Value {
									hash,
									value: v.into(),
									full_key,
								});
							}

							hash
						},
						Value::Node(hash_bytes) => {
							if let Some(recoder) = recorder.as_mut() {
								recoder.record(TrieAccess::Hash { full_key });
							}

							let mut hash = TrieHash::<L>::default();
							hash.as_mut().copy_from_slice(hash_bytes);
							hash
						},
					})
				},
			),
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
		let value_cache_allowed = self
			.recorder
			.as_ref()
			// Check if the recorder has the trie nodes already recorded for this key.
			.map(|r| !r.trie_nodes_recorded_for_key(full_key).is_none())
			// If there is no recorder, we can always use the value cache.
			.unwrap_or(true);

		let res = if let Some(hash) = value_cache_allowed
			.then(|| cache.lookup_value_for_key(full_key).map(|v| v.hash()))
			.flatten()
		{
			hash
		} else {
			let hash_and_value = self.look_up_with_cache_internal(
				nibble_key,
				full_key,
				cache,
				|value, _, full_key, _, _, recorder| match value {
					ValueOwned::Inline(value, hash) => {
						if let Some(recorder) = recorder.as_mut() {
							recorder.record(TrieAccess::Value {
								hash,
								value: value.as_ref().into(),
								full_key,
							});
						}

						Ok((hash, Some(value.clone())))
					},
					ValueOwned::Node(hash) => {
						if let Some(recoder) = recorder.as_mut() {
							recoder.record(TrieAccess::Hash { full_key });
						}

						Ok((hash, None))
					},
				},
			)?;

			match &hash_and_value {
				Some((hash, Some(value))) =>
					cache.cache_value_for_key(full_key, (value.clone(), *hash).into()),
				Some((hash, None)) => cache.cache_value_for_key(full_key, (*hash).into()),
				None => cache.cache_value_for_key(full_key, CachedValue::NonExisting),
			}

			hash_and_value.map(|v| v.0)
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
		let trie_nodes_recorded =
			self.recorder.as_ref().map(|r| r.trie_nodes_recorded_for_key(full_key));

		let (value_cache_allowed, value_recording_required) = match trie_nodes_recorded {
			// If we already have the trie nodes recorded up to the value, we are allowed
			// to use the value cache.
			Some(RecordedForKey::Value) | None => (true, false),
			// If we only have recorded the hash, we are allowed to use the value cache, but
			// we may need to have the value recorded.
			Some(RecordedForKey::Hash) => (true, true),
			// As we don't allow the value cache, the second value can be actually anything.
			Some(RecordedForKey::None) => (false, true),
		};

		let lookup_data = |lookup: &mut Self,
		                   cache: &mut dyn crate::TrieCache<L::Codec>|
		 -> Result<Option<Bytes>, TrieHash<L>, CError<L>> {
			let data = lookup.look_up_with_cache_internal(
				nibble_key,
				full_key,
				cache,
				Self::load_owned_value,
			)?;

			cache.cache_value_for_key(full_key, data.clone().into());

			Ok(data.map(|d| d.0))
		};

		let res = match value_cache_allowed.then(|| cache.lookup_value_for_key(full_key)).flatten()
		{
			Some(CachedValue::NonExisting) => None,
			Some(CachedValue::ExistingHash(hash)) => {
				let data = Self::load_owned_value(
					// If we only have the hash cached, this can only be a value node.
					// For inline nodes we cache them directly as `CachedValue::Existing`.
					ValueOwned::Node(*hash),
					nibble_key.original_data_as_prefix(),
					full_key,
					cache,
					self.db,
					&mut self.recorder,
				)?;

				cache.cache_value_for_key(full_key, data.clone().into());

				Some(data.0)
			},
			Some(CachedValue::Existing { data, hash, .. }) =>
				if let Some(data) = data.upgrade() {
					if value_recording_required {
						// As a value is only raw data, we can directly record it.
						self.record(|| TrieAccess::Value {
							hash: *hash,
							value: data.as_ref().into(),
							full_key,
						});
					}

					Some(data)
				} else {
					lookup_data(&mut self, cache)?
				},
			None => lookup_data(&mut self, cache)?,
		};

		Ok(res.map(|v| self.query.decode(&v)))
	}

	/// When modifying any logic inside this function, you also need to do the same in
	/// [`Self::lookup_without_cache`].
	fn look_up_with_cache_internal<R>(
		&mut self,
		nibble_key: NibbleSlice,
		full_key: &[u8],
		cache: &mut dyn crate::TrieCache<L::Codec>,
		load_value_owned: impl Fn(
			ValueOwned<TrieHash<L>>,
			Prefix,
			&[u8],
			&mut dyn crate::TrieCache<L::Codec>,
			&dyn HashDBRef<L::Hash, DBValue>,
			&mut Option<&mut dyn TrieRecorder<TrieHash<L>>>,
		) -> Result<R, TrieHash<L>, CError<L>>,
	) -> Result<Option<R>, TrieHash<L>, CError<L>> {
		let mut partial = nibble_key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

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

			self.record(|| TrieAccess::NodeOwned { hash, node_owned: node });

			// this loop iterates through all inline children (usually max 1)
			// without incrementing the depth.
			loop {
				let next_node = match node {
					NodeOwned::Leaf(slice, value) =>
						return if partial == *slice {
							let value = (*value).clone();
							drop(node);
							load_value_owned(
								value,
								nibble_key.original_data_as_prefix(),
								full_key,
								cache,
								self.db,
								&mut self.recorder,
							)
							.map(Some)
						} else {
							self.record(|| TrieAccess::NonExisting { full_key });

							Ok(None)
						},
					NodeOwned::Extension(slice, item) =>
						if partial.starts_with_vec(&slice) {
							partial = partial.mid(slice.len());
							key_nibbles += slice.len();
							item
						} else {
							self.record(|| TrieAccess::NonExisting { full_key });

							return Ok(None)
						},
					NodeOwned::Branch(children, value) =>
						if partial.is_empty() {
							return if let Some(value) = value.clone() {
								drop(node);
								load_value_owned(
									value,
									nibble_key.original_data_as_prefix(),
									full_key,
									cache,
									self.db,
									&mut self.recorder,
								)
								.map(Some)
							} else {
								self.record(|| TrieAccess::NonExisting { full_key });

								Ok(None)
							}
						} else {
							match &children[partial.at(0) as usize] {
								Some(x) => {
									partial = partial.mid(1);
									key_nibbles += 1;
									x
								},
								None => {
									self.record(|| TrieAccess::NonExisting { full_key });

									return Ok(None)
								},
							}
						},
					NodeOwned::NibbledBranch(slice, children, value) => {
						if !partial.starts_with_vec(&slice) {
							self.record(|| TrieAccess::NonExisting { full_key });

							return Ok(None)
						}

						if partial.len() == slice.len() {
							return if let Some(value) = value.clone() {
								drop(node);
								load_value_owned(
									value,
									nibble_key.original_data_as_prefix(),
									full_key,
									cache,
									self.db,
									&mut self.recorder,
								)
								.map(Some)
							} else {
								self.record(|| TrieAccess::NonExisting { full_key });

								Ok(None)
							}
						} else {
							match &children[partial.at(slice.len()) as usize] {
								Some(x) => {
									partial = partial.mid(slice.len() + 1);
									key_nibbles += slice.len() + 1;
									x
								},
								None => {
									self.record(|| TrieAccess::NonExisting { full_key });

									return Ok(None)
								},
							}
						}
					},
					NodeOwned::Empty => {
						self.record(|| TrieAccess::NonExisting { full_key });

						return Ok(None)
					},
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
	/// When modifying any logic inside this function, you also need to do the same in
	/// [`Self::lookup_with_cache_internal`].
	fn look_up_without_cache<R>(
		mut self,
		nibble_key: NibbleSlice,
		full_key: &[u8],
		load_value: impl Fn(
			Value,
			Prefix,
			&[u8],
			&dyn HashDBRef<L::Hash, DBValue>,
			&mut Option<&mut dyn TrieRecorder<TrieHash<L>>>,
			Q,
		) -> Result<R, TrieHash<L>, CError<L>>,
	) -> Result<Option<R>, TrieHash<L>, CError<L>> {
		let mut partial = nibble_key;
		let mut hash = self.hash;
		let mut key_nibbles = 0;

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

			self.record(|| TrieAccess::EncodedNode {
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
						return if slice == partial {
							load_value(
								value,
								nibble_key.original_data_as_prefix(),
								full_key,
								self.db,
								&mut self.recorder,
								self.query,
							)
							.map(Some)
						} else {
							self.record(|| TrieAccess::NonExisting { full_key });

							Ok(None)
						},
					Node::Extension(slice, item) =>
						if partial.starts_with(&slice) {
							partial = partial.mid(slice.len());
							key_nibbles += slice.len();
							item
						} else {
							self.record(|| TrieAccess::NonExisting { full_key });

							return Ok(None)
						},
					Node::Branch(children, value) =>
						if partial.is_empty() {
							return if let Some(val) = value {
								load_value(
									val,
									nibble_key.original_data_as_prefix(),
									full_key,
									self.db,
									&mut self.recorder,
									self.query,
								)
								.map(Some)
							} else {
								self.record(|| TrieAccess::NonExisting { full_key });

								Ok(None)
							}
						} else {
							match children[partial.at(0) as usize] {
								Some(x) => {
									partial = partial.mid(1);
									key_nibbles += 1;
									x
								},
								None => {
									self.record(|| TrieAccess::NonExisting { full_key });

									return Ok(None)
								},
							}
						},
					Node::NibbledBranch(slice, children, value) => {
						if !partial.starts_with(&slice) {
							self.record(|| TrieAccess::NonExisting { full_key });

							return Ok(None)
						}

						if partial.len() == slice.len() {
							return if let Some(val) = value {
								load_value(
									val,
									nibble_key.original_data_as_prefix(),
									full_key,
									self.db,
									&mut self.recorder,
									self.query,
								)
								.map(Some)
							} else {
								self.record(|| TrieAccess::NonExisting { full_key });

								Ok(None)
							}
						} else {
							match children[partial.at(slice.len()) as usize] {
								Some(x) => {
									partial = partial.mid(slice.len() + 1);
									key_nibbles += slice.len() + 1;
									x
								},
								None => {
									self.record(|| TrieAccess::NonExisting { full_key });

									return Ok(None)
								},
							}
						}
					},
					Node::Empty => {
						self.record(|| TrieAccess::NonExisting { full_key });

						return Ok(None)
					},
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
}

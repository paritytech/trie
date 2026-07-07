// Copyright 2019, 2020 Parity Technologies
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

use hash_db::{HashDB, HashDBRef, Hasher, EMPTY_PREFIX};
use reference_trie::{test_layouts, ExtensionLayout};
use std::collections::{BTreeMap, BTreeSet};
use trie_db::{
	decode_compact, decode_compact_from_iter_with_known_values, encode_compact,
	encode_compact_skip_duplicate_values, DBValue, NodeCodec, Recorder, Trie, TrieDBBuilder,
	TrieDBMutBuilder, TrieError, TrieLayout, TrieMut,
};

type MemoryDB<T> = memory_db::MemoryDB<
	<T as TrieLayout>::Hash,
	memory_db::HashKey<<T as TrieLayout>::Hash>,
	DBValue,
>;

type PrefixedMemoryDB<T> = memory_db::MemoryDB<
	<T as TrieLayout>::Hash,
	memory_db::PrefixedKey<<T as TrieLayout>::Hash>,
	DBValue,
>;

fn test_encode_compact<L: TrieLayout>(
	entries: Vec<(&'static [u8], &'static [u8])>,
	keys: Vec<&'static [u8]>,
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(&'static [u8], Option<DBValue>)>) {
	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L>>::default();
		let mut root = Default::default();
		{
			let mut trie = <TrieDBMutBuilder<L>>::new(&mut db, &mut root).build();
			for (key, value) in entries.iter() {
				trie.insert(key, value).unwrap();
			}
		}
		(db, root)
	};

	// Lookup items in trie while recording traversed nodes.
	let mut recorder = Recorder::<L>::new();
	let items = {
		let mut items = Vec::with_capacity(keys.len());
		let trie = <TrieDBBuilder<L>>::new(&db, &root).with_recorder(&mut recorder).build();
		for key in keys {
			let value = trie.get(key).unwrap();
			items.push((key, value));
		}
		items
	};

	// Populate a partial trie DB with recorded nodes.
	let mut partial_db = MemoryDB::<L>::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	// Compactly encode the partial trie DB.
	let compact_trie = {
		let trie = <TrieDBBuilder<L>>::new(&partial_db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};

	(root, compact_trie, items)
}

fn test_decode_compact<L: TrieLayout>(
	mut db: impl HashDB<L::Hash, DBValue> + HashDBRef<L::Hash, DBValue>,
	encoded: &[Vec<u8>],
	items: &[(&'static [u8], Option<DBValue>)],
	expected_root: <L::Hash as Hasher>::Out,
	expected_used: usize,
) {
	// Reconstruct the partial DB from the compact encoding.
	let (root, used) = decode_compact::<L, _>(&mut db, encoded).unwrap();
	assert_eq!(root, expected_root);
	assert_eq!(used, expected_used);

	// Check that lookups for all items succeed.
	let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
	for (key, expected_value) in items {
		assert_eq!(&trie.get(key).unwrap(), expected_value);
	}
}

test_layouts!(trie_compact_encoding_works, trie_compact_encoding_works_internal);
fn trie_compact_encoding_works_internal<T: TrieLayout>() {
	let (root, mut encoded, items) = test_encode_compact::<T>(
		vec![
			// "alfa" is at a hash-referenced leaf node.
			(b"alfa", &[0; 32]),
			// "bravo" is at an inline leaf node.
			(b"bravo", b"bravo"),
			// "do" is at a hash-referenced branch node.
			(b"do", b"verb"),
			// "dog" is at an inline leaf node.
			(b"dog", b"puppy"),
			// "doge" is at a hash-referenced leaf node.
			(b"doge", &[0; 32]),
			// extension node "o" (plus nibble) to next branch.
			(b"horse", b"stallion"),
			(b"house", b"building"),
		],
		vec![
			b"do", b"dog", b"doge", b"bravo",
			b"d",      // None, witness is extension node with omitted child
			b"do\x10", // None, empty branch child
			b"halp",   // None, witness is extension node with non-omitted child
		],
	);

	encoded.push(Vec::new()); // Add an extra item to ensure it is not read.
	test_decode_compact::<T>(MemoryDB::<T>::default(), &encoded, &items, root, encoded.len() - 1);
	test_decode_compact::<T>(
		PrefixedMemoryDB::<T>::default(),
		&encoded,
		&items,
		root,
		encoded.len() - 1,
	);
}

test_layouts!(
	trie_decoding_fails_with_incomplete_database,
	trie_decoding_fails_with_incomplete_database_internal
);
fn trie_decoding_fails_with_incomplete_database_internal<T: TrieLayout>() {
	let (_, encoded, _) =
		test_encode_compact::<T>(vec![(b"alfa", &[0; 32]), (b"bravo", b"bravo")], vec![b"alfa"]);

	assert!(encoded.len() > 1);

	// Reconstruct the partial DB from the compact encoding.
	let mut db = MemoryDB::<T>::default();
	match decode_compact::<T, _>(&mut db, &encoded[..encoded.len() - 1]) {
		Err(err) => match *err {
			TrieError::IncompleteDatabase(_) => {},
			_ => panic!("got unexpected TrieError"),
		},
		_ => panic!("decode was unexpectedly successful"),
	}
}

/// A value above every tested layout threshold, so layouts with `MAX_INLINE_VALUE` store it as a
/// separate, hash-addressed value node shared by all keys mapping to it.
const SHARED_VALUE: &[u8] = &[4; 32];

/// Whether the layout stores [`SHARED_VALUE`] as a separate value node.
fn has_value_nodes<T: TrieLayout>() -> bool {
	T::MAX_INLINE_VALUE.map_or(false, |threshold| threshold as usize <= SHARED_VALUE.len())
}

/// Count the encoded items that consist of exactly the shared value, i.e. its detached copies.
fn count_shared_value_items(encoded: &[Vec<u8>]) -> usize {
	encoded.iter().filter(|item| item.as_slice() == SHARED_VALUE).count()
}

/// Entries where five nodes (one branch with value, four leaves) reference the shared value.
fn shared_value_entries() -> Vec<(&'static [u8], &'static [u8])> {
	vec![
		// "key" is at a branch node carrying the shared value.
		(b"key", SHARED_VALUE),
		(b"key1", SHARED_VALUE),
		(b"key2", SHARED_VALUE),
		(b"key3", SHARED_VALUE),
		// A distinct value node, must not be affected by deduplication.
		(b"key4", &[5; 32]),
		// A leaf in an unrelated part of the trie, referencing the shared value.
		(b"other", SHARED_VALUE),
	]
}

fn build_trie<T: TrieLayout>(
	entries: &[(&'static [u8], &'static [u8])],
) -> (MemoryDB<T>, <T::Hash as Hasher>::Out) {
	let mut db = <MemoryDB<T>>::default();
	let mut root = Default::default();
	{
		let mut trie = <TrieDBMutBuilder<T>>::new(&mut db, &mut root).build();
		for (key, value) in entries.iter() {
			trie.insert(key, value).unwrap();
		}
	}
	(db, root)
}

fn assert_entries_match<T: TrieLayout>(
	db: &(impl HashDB<T::Hash, DBValue> + HashDBRef<T::Hash, DBValue>),
	root: <T::Hash as Hasher>::Out,
	entries: &[(&'static [u8], &'static [u8])],
) {
	let trie = <TrieDBBuilder<T>>::new(db, &root).build();
	for (key, value) in entries.iter() {
		assert_eq!(trie.get(key).unwrap().as_deref(), Some(*value));
	}
}

test_layouts!(
	skip_duplicate_values_emits_shared_values_once,
	skip_duplicate_values_emits_shared_values_once_internal
);
fn skip_duplicate_values_emits_shared_values_once_internal<T: TrieLayout>() {
	let entries = shared_value_entries();
	let (db, root) = build_trie::<T>(&entries);

	let trie = <TrieDBBuilder<T>>::new(&db, &root).build();
	let encoded = encode_compact::<T>(&trie).unwrap();
	let deduplicated =
		encode_compact_skip_duplicate_values::<T>(&trie, &mut Default::default()).unwrap();

	if has_value_nodes::<T>() {
		// One detached copy per referencing node without deduplication...
		assert_eq!(count_shared_value_items(&encoded), 5);
		// ...exactly one with it.
		assert_eq!(count_shared_value_items(&deduplicated), 1);
		assert_eq!(deduplicated.len(), encoded.len() - 4);
	} else {
		// Without value nodes there is nothing to deduplicate.
		assert_eq!(deduplicated, encoded);
	}

	// The deduplicated encoding reconstructs a fully readable trie in a hash-keyed database...
	let mut hash_keyed_db = MemoryDB::<T>::default();
	let (decoded_root, used) = decode_compact::<T, _>(&mut hash_keyed_db, &deduplicated).unwrap();
	assert_eq!(decoded_root, root);
	assert_eq!(used, deduplicated.len());
	assert_entries_match::<T>(&hash_keyed_db, root, &entries);

	// ...and, thanks to the decoder re-inserting deduplicated values at every referencing
	// position, in a position-keyed (prefixed) database as well.
	let mut prefixed_db = PrefixedMemoryDB::<T>::default();
	let (decoded_root, _) = decode_compact::<T, _>(&mut prefixed_db, &deduplicated).unwrap();
	assert_eq!(decoded_root, root);
	assert_entries_match::<T>(&prefixed_db, root, &entries);

	// Both encodings must reconstruct the exact same databases: same entries at every position
	// and same reference counts (the deduplicated value is re-inserted once per referencing
	// node, so removal-consolidating consumers observe no difference either).
	let mut expected_hash_keyed_db = MemoryDB::<T>::default();
	decode_compact::<T, _>(&mut expected_hash_keyed_db, &encoded).unwrap();
	assert!(hash_keyed_db == expected_hash_keyed_db && expected_hash_keyed_db == hash_keyed_db);
	let mut expected_prefixed_db = PrefixedMemoryDB::<T>::default();
	decode_compact::<T, _>(&mut expected_prefixed_db, &encoded).unwrap();
	assert!(prefixed_db == expected_prefixed_db && expected_prefixed_db == prefixed_db);
}

test_layouts!(
	skip_duplicate_values_handles_missing_value_nodes,
	skip_duplicate_values_handles_missing_value_nodes_internal
);
fn skip_duplicate_values_handles_missing_value_nodes_internal<T: TrieLayout>() {
	let entries = shared_value_entries();
	let (db, root) = build_trie::<T>(&entries);

	// Record all keys, but leave the shared value node out of the partial trie. Referencing it
	// by hash without providing it is legal for a partial trie.
	let mut recorder = Recorder::<T>::new();
	{
		let trie = <TrieDBBuilder<T>>::new(&db, &root).with_recorder(&mut recorder).build();
		for (key, _) in entries.iter() {
			trie.get(key).unwrap();
		}
	}
	let mut partial_db = MemoryDB::<T>::default();
	for record in recorder.drain() {
		if record.data != SHARED_VALUE {
			partial_db.insert(EMPTY_PREFIX, &record.data);
		}
	}

	let trie = <TrieDBBuilder<T>>::new(&partial_db, &root).build();
	let encoded = encode_compact::<T>(&trie).unwrap();
	let deduplicated =
		encode_compact_skip_duplicate_values::<T>(&trie, &mut Default::default()).unwrap();

	// With no fetchable shared value there is nothing to deduplicate or detach: both encoders
	// must emit the referencing nodes unmodified.
	assert_eq!(deduplicated, encoded);
	assert_eq!(count_shared_value_items(&deduplicated), 0);

	let mut decoded_db = MemoryDB::<T>::default();
	let (decoded_root, _) = decode_compact::<T, _>(&mut decoded_db, &deduplicated).unwrap();
	assert_eq!(decoded_root, root);

	let trie = <TrieDBBuilder<T>>::new(&decoded_db, &root).build();
	// The distinct value is present either way.
	assert_eq!(trie.get(b"key4").unwrap().as_deref(), Some(&[5u8; 32][..]));
	if has_value_nodes::<T>() {
		// The shared value node is missing from the proof, so lookups must fail with an
		// incomplete database error rather than return a wrong result.
		match trie.get(b"key1") {
			Err(err) => match *err {
				TrieError::IncompleteDatabase(_) => {},
				_ => panic!("got unexpected TrieError"),
			},
			_ => panic!("lookup was unexpectedly successful"),
		}
	} else {
		// Values are inline; filtering the standalone value node removed nothing.
		assert_entries_match::<T>(&decoded_db, root, &entries);
	}
}

#[test]
fn decode_compact_counts_attached_value_items() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	// A trie whose compact encoding ends with an attached value: a single entry, so the encoding
	// is exactly the escaped root leaf directly followed by its detached value. The returned
	// item count must include the attached value, otherwise continuing to decode concatenated
	// encodings at that offset would re-read the value as a node.
	let (db, root) = build_trie::<L>(&[(b"key", SHARED_VALUE)]);
	let encoded = {
		let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};
	assert_eq!(encoded.len(), 2);
	assert_eq!(encoded[1].as_slice(), SHARED_VALUE);

	let mut decoded_db = MemoryDB::<L>::default();
	let (decoded_root, used) = decode_compact::<L, _>(&mut decoded_db, &encoded).unwrap();
	assert_eq!(decoded_root, root);
	assert_eq!(used, encoded.len());
}

#[test]
fn skip_duplicate_values_across_concatenated_encodings() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	// Two independent tries (think: a top trie and a child trie) sharing a value.
	let entries_a: Vec<(&'static [u8], &'static [u8])> =
		vec![(b"alpha1", SHARED_VALUE), (b"alpha2", SHARED_VALUE), (b"alpha3", &[7; 32])];
	let entries_b: Vec<(&'static [u8], &'static [u8])> =
		vec![(b"beta1", SHARED_VALUE), (b"beta2", SHARED_VALUE), (b"beta9", &[9; 32])];
	let (db_a, root_a) = build_trie::<L>(&entries_a);
	let (db_b, root_b) = build_trie::<L>(&entries_b);

	// Thread the seen-values set through both encodings: the second one references the shared
	// value without emitting it again.
	let mut seen_value_hashes = BTreeSet::new();
	let encoded_a = {
		let trie = <TrieDBBuilder<L>>::new(&db_a, &root_a).build();
		encode_compact_skip_duplicate_values::<L>(&trie, &mut seen_value_hashes).unwrap()
	};
	let encoded_b = {
		let trie = <TrieDBBuilder<L>>::new(&db_b, &root_b).build();
		encode_compact_skip_duplicate_values::<L>(&trie, &mut seen_value_hashes).unwrap()
	};
	assert_eq!(count_shared_value_items(&encoded_a), 1);
	assert_eq!(count_shared_value_items(&encoded_b), 0);

	// Decoding must then thread the known-values map the same way. Decode both encodings into
	// one position-keyed (prefixed) database, the demanding target.
	let mut prefixed_db = PrefixedMemoryDB::<L>::default();
	let mut known_values = BTreeMap::new();
	let (decoded_root_a, _) = decode_compact_from_iter_with_known_values::<L, _, _>(
		&mut prefixed_db,
		encoded_a.iter().map(Vec::as_slice),
		&mut known_values,
	)
	.unwrap();
	let (decoded_root_b, _) = decode_compact_from_iter_with_known_values::<L, _, _>(
		&mut prefixed_db,
		encoded_b.iter().map(Vec::as_slice),
		&mut known_values,
	)
	.unwrap();
	assert_eq!(decoded_root_a, root_a);
	assert_eq!(decoded_root_b, root_b);
	assert_entries_match::<L>(&prefixed_db, root_a, &entries_a);
	assert_entries_match::<L>(&prefixed_db, root_b, &entries_b);
}

#[test]
fn encoding_node_owned_and_decoding_node_works() {
	let entries: Vec<(&[u8], &[u8])> = vec![
		// "alfa" is at a hash-referenced leaf node.
		(b"alfa", &[0; 32]),
		// "bravo" is at an inline leaf node.
		(b"bravo", b"bravo"),
		// "do" is at a hash-referenced branch node.
		(b"do", b"verb"),
		// "dog" is at an inline leaf node.
		(b"dog", b"puppy"),
		// "doge" is at a hash-referenced leaf node.
		(b"doge", &[0; 32]),
		// extension node "o" (plus nibble) to next branch.
		(b"horse", b"stallion"),
		(b"house", b"building"),
	];

	// Populate DB with full trie from entries.
	let mut recorder = {
		let mut db = <MemoryDB<ExtensionLayout>>::default();
		let mut root = Default::default();
		let mut recorder = Recorder::<ExtensionLayout>::new();
		{
			let mut trie = <TrieDBMutBuilder<ExtensionLayout>>::new(&mut db, &mut root).build();
			for (key, value) in entries.iter() {
				trie.insert(key, value).unwrap();
			}
		}

		let trie = TrieDBBuilder::<ExtensionLayout>::new(&db, &root)
			.with_recorder(&mut recorder)
			.build();
		for (key, _) in entries.iter() {
			trie.get(key).unwrap();
		}

		recorder
	};

	for record in recorder.drain() {
		let node =
			<<ExtensionLayout as TrieLayout>::Codec as NodeCodec>::decode(&record.data).unwrap();
		let node_owned = node.to_owned_node::<ExtensionLayout>().unwrap();

		assert_eq!(record.data, node_owned.to_encoded::<<ExtensionLayout as TrieLayout>::Codec>());
	}
}

/// Verbatim copy of the compact-proof decoder from the released `trie-db` 0.31.0 (crates.io),
/// with only import paths adjusted. A frozen snapshot of already-deployed decoder behavior —
/// deliberately never updated — pinning that encodings produced by
/// `encode_compact_skip_duplicate_values` remain decodable by decoders that predate it.
mod trie_db_0_31_decoder {
	use hash_db::HashDB;
	use std::{convert::TryInto, marker::PhantomData};
	use trie_db::{
		nibble_ops::NIBBLE_LENGTH,
		node::{Node, NodeHandle, Value},
		CError, ChildReference, DBValue, NibbleVec, NodeCodec, TrieError, TrieHash, TrieLayout,
	};

	struct DecoderStackEntry<'a, C: NodeCodec> {
		node: Node<'a>,
		/// The next entry in the stack is a child of the preceding entry at this index. For branch
		/// nodes, the index is in [0, NIBBLE_LENGTH] and for extension nodes, the index is in
		/// [0, 1].
		child_index: usize,
		/// The reconstructed child references.
		children: Vec<Option<ChildReference<C::HashOut>>>,
		/// A value attached as a node. The node will need to use its hash as value.
		attached_value: Option<&'a [u8]>,
		_marker: PhantomData<C>,
	}

	impl<'a, C: NodeCodec> DecoderStackEntry<'a, C> {
		fn advance_child_index(&mut self) -> trie_db::Result<bool, C::HashOut, C::Error> {
			match self.node {
				Node::Extension(_, child) if self.child_index == 0 => {
					match child {
						NodeHandle::Inline(data) if data.is_empty() => return Ok(false),
						_ => {
							let child_ref = child.try_into().map_err(|hash| {
								Box::new(TrieError::InvalidHash(C::HashOut::default(), hash))
							})?;
							self.children[self.child_index] = Some(child_ref);
						},
					}
					self.child_index += 1;
				},
				Node::Branch(children, _) | Node::NibbledBranch(_, children, _) => {
					while self.child_index < NIBBLE_LENGTH {
						match children[self.child_index] {
							Some(NodeHandle::Inline(data)) if data.is_empty() => return Ok(false),
							Some(child) => {
								let child_ref = child.try_into().map_err(|hash| {
									Box::new(TrieError::InvalidHash(C::HashOut::default(), hash))
								})?;
								self.children[self.child_index] = Some(child_ref);
							},
							None => {},
						}
						self.child_index += 1;
					}
				},
				_ => {},
			}
			Ok(true)
		}

		fn push_to_prefix(&self, prefix: &mut NibbleVec) {
			match self.node {
				Node::Empty => {},
				Node::Leaf(partial, _) | Node::Extension(partial, _) => {
					prefix.append_partial(partial.right());
				},
				Node::Branch(_, _) => {
					prefix.push(self.child_index as u8);
				},
				Node::NibbledBranch(partial, _, _) => {
					prefix.append_partial(partial.right());
					prefix.push(self.child_index as u8);
				},
			}
		}

		fn pop_from_prefix(&self, prefix: &mut NibbleVec) {
			match self.node {
				Node::Empty => {},
				Node::Leaf(partial, _) | Node::Extension(partial, _) => {
					prefix.drop_lasts(partial.len());
				},
				Node::Branch(_, _) => {
					prefix.pop();
				},
				Node::NibbledBranch(partial, _, _) => {
					prefix.pop();
					prefix.drop_lasts(partial.len());
				},
			}
		}

		fn encode_node(self, attached_hash: Option<&[u8]>) -> Vec<u8> {
			let attached_hash = attached_hash.map(|h| Value::Node(h));
			match self.node {
				Node::Empty => C::empty_node().to_vec(),
				Node::Leaf(partial, value) => C::leaf_node(
					partial.right_iter(),
					partial.len(),
					attached_hash.unwrap_or(value),
				),
				Node::Extension(partial, _) => C::extension_node(
					partial.right_iter(),
					partial.len(),
					self.children[0].expect("required by method precondition; qed"),
				),
				Node::Branch(_, value) => C::branch_node(
					self.children.into_iter(),
					if attached_hash.is_some() { attached_hash } else { value },
				),
				Node::NibbledBranch(partial, _, value) => C::branch_node_nibbled(
					partial.right_iter(),
					partial.len(),
					self.children.iter(),
					if attached_hash.is_some() { attached_hash } else { value },
				),
			}
		}
	}

	pub fn decode_compact_from_iter<'a, L, DB, I>(
		db: &mut DB,
		encoded: I,
	) -> trie_db::Result<(TrieHash<L>, usize), TrieHash<L>, CError<L>>
	where
		L: TrieLayout,
		DB: HashDB<L::Hash, DBValue>,
		I: IntoIterator<Item = &'a [u8]>,
	{
		let mut stack: Vec<DecoderStackEntry<L::Codec>> = Vec::new();

		let mut prefix = NibbleVec::new();

		let mut iter = encoded.into_iter().enumerate();
		while let Some((i, encoded_node)) = iter.next() {
			let mut attached_node = 0;
			if let Some(header) = L::Codec::ESCAPE_HEADER {
				if encoded_node.starts_with(&[header]) {
					attached_node = 1;
				}
			}
			let node = L::Codec::decode(&encoded_node[attached_node..])
				.map_err(|err| Box::new(TrieError::DecoderError(<TrieHash<L>>::default(), err)))?;

			let children_len = match node {
				Node::Empty | Node::Leaf(..) => 0,
				Node::Extension(..) => 1,
				Node::Branch(..) | Node::NibbledBranch(..) => NIBBLE_LENGTH,
			};
			let mut last_entry = DecoderStackEntry {
				node,
				child_index: 0,
				children: vec![None; children_len],
				attached_value: None,
				_marker: PhantomData::default(),
			};

			if attached_node > 0 {
				// Read value
				if let Some((_, fetched_value)) = iter.next() {
					last_entry.attached_value = Some(fetched_value);
				} else {
					return Err(Box::new(TrieError::IncompleteDatabase(<TrieHash<L>>::default())))
				}
			}

			loop {
				if !last_entry.advance_child_index()? {
					last_entry.push_to_prefix(&mut prefix);
					stack.push(last_entry);
					break
				}

				let hash = last_entry
					.attached_value
					.as_ref()
					.map(|value| db.insert(prefix.as_prefix(), value));
				let node_data = last_entry.encode_node(hash.as_ref().map(|h| h.as_ref()));
				let node_hash = db.insert(prefix.as_prefix(), node_data.as_ref());

				if let Some(entry) = stack.pop() {
					last_entry = entry;
					last_entry.pop_from_prefix(&mut prefix);
					last_entry.children[last_entry.child_index] =
						Some(ChildReference::Hash(node_hash));
					last_entry.child_index += 1;
				} else {
					return Ok((node_hash, i + 1))
				}
			}
		}

		Err(Box::new(TrieError::IncompleteDatabase(<TrieHash<L>>::default())))
	}
}

#[test]
fn deduplicated_encoding_decodes_with_released_0_31_decoder() {
	// Layout storing every non-empty value as a separate value node.
	type L = reference_trie::HashedValueNoExtThreshold<1>;

	let entries = shared_value_entries();
	let (db, root) = build_trie::<L>(&entries);
	let trie = <TrieDBBuilder<L>>::new(&db, &root).build();
	let encoded = encode_compact::<L>(&trie).unwrap();
	let deduplicated =
		encode_compact_skip_duplicate_values::<L>(&trie, &mut Default::default()).unwrap();
	assert_eq!(count_shared_value_items(&deduplicated), 1);

	// Baseline: the released decoder handles the unmodified encoding.
	let mut baseline_db = MemoryDB::<L>::default();
	let (decoded_root, _) = trie_db_0_31_decoder::decode_compact_from_iter::<L, _, _>(
		&mut baseline_db,
		encoded.iter().map(Vec::as_slice),
	)
	.unwrap();
	assert_eq!(decoded_root, root);

	// The deduplicated encoding decodes with the released (pre-deduplication) decoder into a
	// hash-keyed database, with every entry readable: deduplicated nodes reference their value
	// by hash, and the value node is present from its first, still-attached occurrence.
	//
	// (Position-keyed databases are out of scope for the released decoder: it also inserts
	// attached values under an incomplete prefix, fixed only by #227.)
	let mut hash_keyed_db = MemoryDB::<L>::default();
	let (decoded_root, _) = trie_db_0_31_decoder::decode_compact_from_iter::<L, _, _>(
		&mut hash_keyed_db,
		deduplicated.iter().map(Vec::as_slice),
	)
	.unwrap();
	assert_eq!(decoded_root, root);
	assert_entries_match::<L>(&hash_keyed_db, root, &entries);
}

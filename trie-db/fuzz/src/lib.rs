// Copyright 2019 Parity Technologies
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

use arbitrary::Arbitrary;
use hash_db::Hasher;
use memory_db::{HashKey, MemoryDB, PrefixedKey};
pub use reference_trie::fuzz_double_iter;
use reference_trie::{
	calc_root, compare_insert_remove, fuzz_to_data,
	reference_trie_root_iter_build as reference_trie_root,
};
use std::convert::TryInto;
use trie_db::{
	proof::{generate_proof, verify_proof},
	DBValue, Trie, TrieDBBuilder, TrieDBIterator, TrieDBMutBuilder, TrieLayout, TrieMut,
};

fn fuzz_removal(data: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(bool, Vec<u8>, Vec<u8>)> {
	let mut res = Vec::new();
	let mut torem = None;
	for (a, d) in data.into_iter().enumerate() {
		if a % 7 == 6 {
			// a random removal some time
			res.push((true, d.0, d.1));
		} else {
			if a % 5 == 0 {
				torem = Some((true, d.0.clone(), d.1.clone()));
			}
			res.push((false, d.0, d.1));
			if a % 5 == 4 {
				if let Some(v) = torem.take() {
					res.push(v);
				}
			}
		}
	}
	res
}

pub fn fuzz_that_reference_trie_root<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(data));
}

pub fn fuzz_that_reference_trie_root_fix_length<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(data));
}

fn fuzz_to_data_fix_length(input: &[u8]) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut result = Vec::new();
	let mut ix = 0;
	loop {
		let keylen = 32;
		let key = if input.len() > ix + keylen { input[ix..ix + keylen].to_vec() } else { break };
		ix += keylen;
		let val = if input.len() > ix + 2 { input[ix..ix + 2].to_vec() } else { break };
		result.push((key, val));
	}
	result
}

fn data_sorted_unique(input: Vec<(Vec<u8>, Vec<u8>)>) -> Vec<(Vec<u8>, Vec<u8>)> {
	let mut m = std::collections::BTreeMap::new();
	for (k, v) in input.into_iter() {
		let _ = m.insert(k, v); // latest value for uniqueness
	}
	m.into_iter().collect()
}

pub fn fuzz_that_compare_implementations<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data(input));
	//println!("data:{:?}", &data);
	let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	let hashdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	reference_trie::compare_implementations::<T, _>(data, memdb, hashdb);
}

pub fn fuzz_that_no_extension_insert<T: TrieLayout>(input: &[u8]) {
	let data = fuzz_to_data(input);
	//println!("data{:?}", data);
	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
	for a in 0..data.len() {
		t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
	}
	// we are testing the RefTrie code here so we do not sort or check uniqueness
	// before.
	let data = data_sorted_unique(fuzz_to_data(input));
	//println!("data{:?}", data);
	assert_eq!(*t.root(), calc_root::<T, _, _, _>(data));
}

pub fn fuzz_that_no_extension_insert_remove<T: TrieLayout>(input: &[u8]) {
	let data = fuzz_to_data(input);
	let data = fuzz_removal(data);

	let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	compare_insert_remove::<T, _>(data, memdb);
}

pub fn fuzz_seek_iter<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));

	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for a in 0..data.len() {
			t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
		}
	}

	// fuzzing around a fix prefix of 6 nibble.
	let prefix = &b"012"[..];

	let mut iter_res2 = Vec::new();
	for a in data {
		if a.0.starts_with(prefix) {
			iter_res2.push(a.0);
		}
	}

	let mut iter_res = Vec::new();
	let mut error = 0;
	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();
		let mut iter = trie.iter().unwrap();
		if let Ok(_) = iter.seek(prefix) {
		} else {
			error += 1;
		}

		for x in iter {
			if let Ok((key, _)) = x {
				if key.starts_with(prefix) {
					iter_res.push(key);
				} else {
					break
				}
			} else {
				error += 1;
			}
		}
	}

	assert_eq!(iter_res, iter_res2);
	assert_eq!(error, 0);
}

pub fn fuzz_prefix_iter<T: TrieLayout>(input: &[u8]) {
	let data = data_sorted_unique(fuzz_to_data_fix_length(input));

	let mut memdb = MemoryDB::<_, HashKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for a in 0..data.len() {
			t.insert(&data[a].0[..], &data[a].1[..]).unwrap();
		}
	}

	// fuzzing around a fix prefix of 6 nibble.
	let prefix = &b"012"[..];

	let mut iter_res2 = Vec::new();
	for a in data {
		if a.0.starts_with(prefix) {
			iter_res2.push(a.0);
		}
	}

	let mut iter_res = Vec::new();
	let mut error = 0;
	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();
		let iter = TrieDBIterator::new_prefixed(&trie, prefix).unwrap();

		for x in iter {
			if let Ok((key, _)) = x {
				if key.starts_with(prefix) {
					iter_res.push(key);
				} else {
					println!("error out of range");
					error += 1;
				}
			} else {
				error += 1;
			}
		}
	}

	assert_eq!(iter_res, iter_res2);
	assert_eq!(error, 0);
}

#[derive(Debug, Clone, Arbitrary)]
pub struct PrefixSeekTestInput {
	keys: Vec<Vec<u8>>,
	prefix_key: Vec<u8>,
	seek_key: Vec<u8>,
}

fn printable_keys<T: AsRef<[u8]>>(iter: impl IntoIterator<Item = T>) -> String {
	iter.into_iter()
		.map(|key| format!("\"{}\"", array_bytes::bytes2hex("", key)))
		.collect::<Vec<_>>()
		.join(", ")
}

pub fn fuzz_prefix_seek_iter<T: TrieLayout>(mut input: PrefixSeekTestInput) {
	type PrefixedMemoryDB<T> =
		MemoryDB<<T as TrieLayout>::Hash, PrefixedKey<<T as TrieLayout>::Hash>, DBValue>;

	input.keys.retain_mut(|key| !key.is_empty());

	input.keys.sort_unstable();
	input.keys.dedup();

	let mut memdb = PrefixedMemoryDB::<T>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMutBuilder::<T>::new(&mut memdb, &mut root).build();
		for (index, key) in input.keys.iter().enumerate() {
			t.insert(&key, &[index as u8]).unwrap();
		}
	}

	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();
	let iter =
		trie_db::TrieDBIterator::new_prefixed_then_seek(&trie, &input.prefix_key, &input.seek_key)
			.unwrap();
	let output_keys: Vec<_> = iter.map(|item| item.unwrap().0).collect();

	let input_keys = input.keys;
	let seek_key = input.seek_key;
	let prefix_key = input.prefix_key;
	let expected_keys: Vec<_> = input_keys
		.iter()
		.filter(|key| key.starts_with(&prefix_key) && **key >= seek_key)
		.cloned()
		.collect();

	if output_keys != expected_keys {
		panic!(
			"Test failed!\nresult = [{result}]\nexpected = [{expected}]\nprefix_key = \"{prefix_key}\"\nseek_key = \"{seek_key}\"\nkeys = [{input_keys}]",
			result = printable_keys(output_keys),
			expected = printable_keys(expected_keys),
			prefix_key = array_bytes::bytes2hex("", prefix_key),
			seek_key = array_bytes::bytes2hex("", seek_key),
			input_keys = printable_keys(input_keys)
		);
	}
}

pub fn fuzz_that_verify_accepts_valid_proofs<T: TrieLayout>(input: &[u8]) {
	let mut data = fuzz_to_data(input);
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	let (root, proof, items) = test_generate_proof::<T>(data, keys);
	assert!(verify_proof::<T, _, _, _>(&root, &proof, items.iter()).is_ok());
}

pub fn fuzz_that_trie_codec_proofs<T: TrieLayout>(input: &[u8]) {
	let mut data = fuzz_to_data(input);
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	test_trie_codec_proof::<T>(data, keys);
}

pub fn fuzz_that_trie_codec_proofs_with_shared_values<T: TrieLayout>(input: &[u8]) {
	let mut data = fuzz_to_data(input);
	// Draw values from a tiny alphabet of large values, so many keys share a value node.
	for (_, value) in data.iter_mut() {
		let selector = value.first().copied().unwrap_or(0) % 4;
		*value = vec![selector; 64];
	}
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	test_trie_codec_proof::<T>(data, keys);
}

pub fn fuzz_that_trie_codec_proofs_with_shared_subtrees<T: TrieLayout>(input: &[u8]) {
	let data = fuzz_to_data(input);
	// Mirror every key under two first-nibble prefixes with identical suffixes, drawing values
	// from a tiny alphabet of large values, so the trie contains identically encoded sibling
	// subtrees (exercising node-level deduplication) referencing shared value nodes (for layouts
	// detaching values).
	let mut mirrored = Vec::with_capacity(data.len() * 2);
	for (key, value) in data {
		let value = vec![value.first().copied().unwrap_or(0) % 4; 64];
		for prefix in [0x00u8, 0x10] {
			let mut mirrored_key = Vec::with_capacity(key.len() + 1);
			mirrored_key.push(prefix);
			mirrored_key.extend_from_slice(&key);
			mirrored.push((mirrored_key, value.clone()));
		}
	}
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	// Mirrored pairs are adjacent, so the split mostly keeps both occurrences of a subtree.
	let mut keys = mirrored[(mirrored.len() / 3)..]
		.iter()
		.map(|(key, _)| key.clone())
		.collect::<Vec<_>>();
	mirrored.truncate(mirrored.len() * 2 / 3);

	let mirrored = data_sorted_unique(mirrored);
	keys.sort();
	keys.dedup();

	test_trie_codec_proof::<T>(mirrored, keys);
}

pub fn fuzz_that_verify_rejects_invalid_proofs<T: TrieLayout>(input: &[u8]) {
	if input.len() < 4 {
		return
	}

	let random_int = u32::from_le_bytes(input[0..4].try_into().expect("slice is 4 bytes")) as usize;

	let mut data = fuzz_to_data(&input[4..]);
	// Split data into 3 parts:
	// - the first 1/3 is added to the trie and not included in the proof
	// - the second 1/3 is added to the trie and included in the proof
	// - the last 1/3 is not added to the trie and the proof proves non-inclusion of them
	let mut keys = data[(data.len() / 3)..].iter().map(|(key, _)| key.clone()).collect::<Vec<_>>();
	data.truncate(data.len() * 2 / 3);

	let data = data_sorted_unique(data);
	keys.sort();
	keys.dedup();

	if keys.is_empty() {
		return
	}

	let (root, proof, mut items) = test_generate_proof::<T>(data, keys);

	// Make one item at random incorrect.
	let items_idx = random_int % items.len();
	match &mut items[items_idx] {
		(_, Some(value)) if random_int % 2 == 0 => value.push(0),
		(_, value) if value.is_some() => *value = None,
		(_, value) => *value = Some(DBValue::new()),
	}
	assert!(verify_proof::<T, _, _, _>(&root, &proof, items.iter()).is_err());
}

fn test_generate_proof<L: TrieLayout>(
	entries: Vec<(Vec<u8>, Vec<u8>)>,
	keys: Vec<Vec<u8>>,
) -> (<L::Hash as Hasher>::Out, Vec<Vec<u8>>, Vec<(Vec<u8>, Option<DBValue>)>) {
	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
		let mut root = Default::default();
		{
			let mut trie = TrieDBMutBuilder::<L>::new(&mut db, &mut root).build();
			for (key, value) in entries {
				trie.insert(&key, &value).unwrap();
			}
		}
		(db, root)
	};

	// Generate proof for the given keys..
	let proof = generate_proof::<_, L, _, _>(&db, &root, keys.iter()).unwrap();
	let trie = TrieDBBuilder::<L>::new(&db, &root).build();
	let items = keys
		.into_iter()
		.map(|key| {
			let value = trie.get(&key).unwrap();
			(key, value)
		})
		.collect();

	(root, proof, items)
}

/// Structure-aware input for the deduplicating compact-proof harness.
///
/// Unlike the byte-stream `fuzz_to_data` harnesses (which produce mostly disjoint keys and shallow
/// tries), this describes several tries drawn from a shared value pool, with keys squeezed into a
/// small nibble alphabet and optional (possibly nested) subtree mirroring. That deliberately
/// manufactures colliding keys, deep branches, extensions, nibbled branches carrying a value *and*
/// children, and recursively duplicated subtrees — the structures the deduplication code paths
/// need. Sharing one value pool across tries also exercises cross-encoding deduplication
/// (a threaded `seen_hashes` set).
#[derive(Debug, Clone, Arbitrary)]
pub struct DedupScenario {
	/// The tries in the scenario; capped to [`DedupScenario::MAX_TRIES`] at build time.
	tries: Vec<TrieSpec>,
	/// Pool of candidate values, shared by every trie so values (and whole subtrees) collide.
	value_pool: Vec<ValueSpec>,
}

impl DedupScenario {
	const MAX_TRIES: usize = 4;
	const MAX_BASE_KEYS: usize = 12;
	const MAX_KEY_BYTES: usize = 6;
	/// Squeeze raw bytes into a small alphabet so keys collide and branches form.
	const KEY_ALPHABET: usize = 4;
}

#[derive(Debug, Clone, Arbitrary)]
struct TrieSpec {
	/// Raw key material; squeezed to a small nibble alphabet at build time.
	keys: Vec<KeySpec>,
	/// Number of identical sibling subtrees to mirror the key set into (`1 + n % 4`, i.e. 1..=4).
	/// A value of 1 disables mirroring.
	mirror_copies: u8,
	/// When set, mirror the key set one extra level down first, so a duplicated subtree itself
	/// contains a duplicated sub-subtree (exercises nested subtree deduplication).
	nested_mirror: bool,
	/// Indices (modulo entry count) of the keys proven into the partial trie. Empty means "all".
	queried: Vec<u16>,
}

#[derive(Debug, Clone, Arbitrary)]
struct KeySpec {
	/// Raw key bytes; squeezed to the small alphabet and truncated at build time.
	bytes: Vec<u8>,
	/// Index (modulo pool length) of this key's value in the shared value pool.
	value: u16,
}

#[derive(Debug, Clone, Arbitrary)]
struct ValueSpec {
	/// Byte the value is filled with (small alphabet keeps distinct values few and sharing
	/// likely).
	selector: u8,
	/// Large values become separate (detachable) value nodes; small ones stay inline.
	large: bool,
}

/// Map a raw byte to the small key alphabet. Each symbol has equal nibbles so branches diverge at
/// byte boundaries: {0x00, 0x11, 0x22, 0x33}.
fn alphabet_byte(raw: u8) -> u8 {
	let symbol = (raw as usize % DedupScenario::KEY_ALPHABET) as u8;
	symbol * 0x11
}

/// Prepend `prefix` to every key in `entries`, cloning the values.
fn mirror_entries(entries: &[(Vec<u8>, Vec<u8>)], prefix: u8) -> Vec<(Vec<u8>, Vec<u8>)> {
	entries
		.iter()
		.map(|(key, value)| {
			let mut mirrored = Vec::with_capacity(key.len() + 1);
			mirrored.push(prefix);
			mirrored.extend_from_slice(key);
			(mirrored, value.clone())
		})
		.collect()
}

/// Materialize the shared value pool. Each spec is either a small inline value or a large value
/// node; an empty pool falls back to one of each.
fn build_value_pool(specs: &[ValueSpec]) -> Vec<Vec<u8>> {
	if specs.is_empty() {
		return vec![vec![0u8], vec![1u8; 32]]
	}
	specs
		.iter()
		.map(|spec| if spec.large { vec![spec.selector; 32] } else { vec![spec.selector] })
		.collect()
}

/// Build the sorted, unique `(key, value)` entries for one trie from its spec.
fn build_entries(spec: &TrieSpec, value_pool: &[Vec<u8>]) -> Vec<(Vec<u8>, Vec<u8>)> {
	// Base keys, squeezed into the small alphabet, truncated, and non-empty.
	let mut base: Vec<(Vec<u8>, Vec<u8>)> = Vec::new();
	for key_spec in spec.keys.iter().take(DedupScenario::MAX_BASE_KEYS) {
		let key: Vec<u8> = key_spec
			.bytes
			.iter()
			.take(DedupScenario::MAX_KEY_BYTES)
			.map(|raw| alphabet_byte(*raw))
			.collect();
		if key.is_empty() {
			continue
		}
		let value = value_pool[key_spec.value as usize % value_pool.len()].clone();
		base.push((key, value));
	}

	// Optionally mirror one extra level down first, so mirrored subtrees nest.
	if spec.nested_mirror {
		let mut nested = mirror_entries(&base, 0x01);
		nested.extend(mirror_entries(&base, 0x02));
		base = nested;
	}

	// Mirror into `copies` identical sibling subtrees below the root (distinct first nibbles).
	let copies = 1 + spec.mirror_copies as usize % 4;
	let entries = if copies >= 2 {
		const OUTER_PREFIXES: [u8; 4] = [0x00, 0x10, 0x20, 0x30];
		let mut mirrored = Vec::new();
		for &prefix in OUTER_PREFIXES.iter().take(copies) {
			mirrored.extend(mirror_entries(&base, prefix));
		}
		mirrored
	} else {
		base
	};

	data_sorted_unique(entries)
}

/// Select the keys proven into the partial trie: the listed indices (modulo entry count), or all
/// keys when none are listed.
fn select_queried(spec: &TrieSpec, entries: &[(Vec<u8>, Vec<u8>)]) -> Vec<Vec<u8>> {
	if spec.queried.is_empty() {
		return entries.iter().map(|(key, _)| key.clone()).collect()
	}
	let mut keys: Vec<Vec<u8>> = spec
		.queried
		.iter()
		.map(|index| entries[*index as usize % entries.len()].0.clone())
		.collect();
	keys.sort();
	keys.dedup();
	keys
}

/// Structure-aware, differential fuzz harness for deduplicated compact proofs.
///
/// Builds up to [`DedupScenario::MAX_TRIES`] tries, records the queried keys of each, and
/// consolidates all recorded nodes into one frozen union set — the fixed-backing-set
/// precondition of [`encode_compact_skip_duplicates`](trie_db::encode_compact_skip_duplicates)
/// (in Substrate, the single proof recorder shared by a whole block). Every trie is then encoded
/// from that set: plain ([`encode_compact`](trie_db::encode_compact)), self-contained
/// deduplicated (fresh seen-set) and deduplicated with one `seen_hashes` set threaded across all
/// tries. Plain encodings decode independently; threaded ones accumulate into one shared
/// hash-keyed database.
///
/// Oracles:
/// - every deduplicated encoding reconstructs its root and all proven keys;
/// - deduplication never grows the encoding (`Σ dedup <= Σ plain`);
/// - re-encoding a fully-seen trie emits only its root ("always emit root");
/// - a self-contained encoding reconstructs the same node set as plain;
/// - a self-contained encoding stays decodable by the released 0.31.0 decoder (hash-keyed);
/// - the threaded reconstruction yields exactly the node set of the plain reconstructions:
///   deduplication drops re-emissions, never nodes. Reference counts and positions are not
///   compared — a proof is a hash-keyed node set, not a mutable database, and deduplicated
///   encodings deliberately do not reconstruct per-position bookkeeping.
///
/// Threading `seen_hashes` across per-trie recorded sets instead violates the precondition and
/// drops nodes; `divergent_coverage_drops_nodes` in the smoke tests pins that failure mode.
pub fn fuzz_dedup_scenario<L: TrieLayout>(scenario: DedupScenario) {
	use hash_db::{HashDB, EMPTY_PREFIX};
	use std::collections::BTreeSet;
	use trie_db::{
		decode_compact, decode_compact_from_iter, encode_compact, encode_compact_skip_duplicates,
		Recorder,
	};

	let value_pool = build_value_pool(&scenario.value_pool);

	// Databases accumulated across all tries for the differential oracle. `expected_hashed` is
	// the plain reconstruction, `actual_hashed` the threaded deduplicated one.
	let mut expected_hashed = MemoryDB::<L::Hash, HashKey<_>, DBValue>::default();
	let mut actual_hashed = MemoryDB::<L::Hash, HashKey<_>, DBValue>::default();

	// Deduplication state threaded across every trie in the scenario.
	let mut seen_hashes = BTreeSet::new();

	let mut total_plain = 0usize;
	let mut total_dedup = 0usize;

	// Phase 1: build every trie and record its queried keys, consolidating all recorded nodes
	// into one frozen union set — so every encoding sees the same coverage below any shared hash
	// (the precondition of `encode_compact_skip_duplicates`).
	let mut union_partial = MemoryDB::<L::Hash, HashKey<_>, DBValue>::default();
	let mut recorded = Vec::new();
	for trie_spec in scenario.tries.iter().take(DedupScenario::MAX_TRIES) {
		let entries = build_entries(trie_spec, &value_pool);
		if entries.is_empty() {
			continue
		}

		// Build the full trie in a hash-keyed database.
		let mut db = MemoryDB::<L::Hash, HashKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut trie = TrieDBMutBuilder::<L>::new(&mut db, &mut root).build();
			for (key, value) in &entries {
				trie.insert(key, value).unwrap();
			}
		}

		// Record the partial trie for the proven keys.
		let queried = select_queried(trie_spec, &entries);
		let mut recorder = Recorder::<L>::new();
		let mut items = Vec::with_capacity(queried.len());
		{
			let trie = TrieDBBuilder::<L>::new(&db, &root).with_recorder(&mut recorder).build();
			for key in &queried {
				let value = trie.get(key).unwrap();
				items.push((key.clone(), value));
			}
		}
		for record in recorder.drain() {
			union_partial.emplace(record.hash, EMPTY_PREFIX, record.data);
		}
		recorded.push((root, items));
	}
	if recorded.is_empty() {
		return
	}

	// Phase 2: encode every trie from the frozen union set, threading `seen_hashes` in order.
	for (root, items) in &recorded {
		// Encode the partial trie three ways: plain, deduplicated with the threaded `seen_hashes`,
		// and deduplicated standalone (a fresh seen-set, i.e. a self-contained proof).
		let (plain, dedup, standalone) = {
			let trie = TrieDBBuilder::<L>::new(&union_partial, root).build();
			let plain = encode_compact::<L>(&trie).unwrap();
			let standalone =
				encode_compact_skip_duplicates::<L>(&trie, &mut BTreeSet::new()).unwrap();
			let dedup = encode_compact_skip_duplicates::<L>(&trie, &mut seen_hashes).unwrap();
			(plain, dedup, standalone)
		};
		assert!(dedup.len() <= plain.len(), "deduplication must not grow the encoding");
		total_plain += plain.len();
		total_dedup += dedup.len();

		// Idempotency: with every item already seen, re-encoding emits only the root.
		{
			let trie = TrieDBBuilder::<L>::new(&union_partial, root).build();
			let reencoded =
				encode_compact_skip_duplicates::<L>(&trie, &mut seen_hashes.clone()).unwrap();
			assert_eq!(reencoded.len(), 1, "re-encoding a fully-seen trie must emit only the root");
		}

		// A single self-contained encoding reconstructs the same node set as plain: within one
		// proof only references to already-emitted items are collapsed, so nothing goes missing.
		// Reference counts differ by design and are not compared.
		{
			let mut plain_hashed = MemoryDB::<L::Hash, HashKey<_>, DBValue>::default();
			let mut standalone_hashed = MemoryDB::<L::Hash, HashKey<_>, DBValue>::default();
			decode_compact::<L, _>(&mut plain_hashed, &plain).unwrap();
			decode_compact::<L, _>(&mut standalone_hashed, &standalone).unwrap();
			assert!(
				db_key_set(&plain_hashed) == db_key_set(&standalone_hashed),
				"single-encoding node-set mismatch"
			);
		}

		// Backward compatibility: the released 0.31.0 decoder must still reconstruct a readable
		// hash-keyed database from a self-contained encoding (an old node verifying a new proof).
		// It under-counts references, so we check readability only, not equality. Hash-keyed
		// only: 0.31.0 mis-prefixes attached values in a position-keyed database (fixed by #227).
		{
			let mut old_db = MemoryDB::<L::Hash, HashKey<_>, DBValue>::default();
			let (old_root, _) = reference_trie::trie_db_0_31_decoder::decode_compact_from_iter::<
				L,
				_,
				_,
			>(&mut old_db, standalone.iter().map(Vec::as_slice))
			.unwrap();
			assert_eq!(&old_root, root, "released 0.31.0 decoder must reconstruct the same root");
			let old_trie = TrieDBBuilder::<L>::new(&old_db, &old_root).build();
			for (key, expected_value) in items {
				assert_eq!(
					&old_trie.get(key).unwrap(),
					expected_value,
					"released 0.31.0 decoder must recover every proven key (refcounts aside)"
				);
			}
		}

		// Decode the plain encoding independently into the expected database.
		let (decoded_root, _) = decode_compact::<L, _>(&mut expected_hashed, &plain).unwrap();
		assert_eq!(&decoded_root, root);

		// Decode the deduplicated encoding into the shared actual database: items deduplicated
		// across encodings are present from the encoding that emitted them.
		let (decoded_root, _) =
			decode_compact_from_iter::<L, _, _>(&mut actual_hashed, dedup.iter().map(Vec::as_slice))
				.unwrap();
		assert_eq!(&decoded_root, root);

		// Every proven key resolves to its expected value in the reconstructed trie.
		let trie = TrieDBBuilder::<L>::new(&actual_hashed, root).build();
		for (key, expected_value) in items {
			assert_eq!(&trie.get(key).unwrap(), expected_value);
		}
	}

	// The threaded, cross-encoding differential: deduplication drops re-emissions, never nodes,
	// so the threaded reconstruction holds exactly the node set of the plain reconstructions.
	// Reference counts and positions are not compared — deduplicated encodings deliberately do
	// not reconstruct per-position bookkeeping.
	assert!(
		db_key_set(&actual_hashed) == db_key_set(&expected_hashed),
		"threaded reconstruction differs from the plain node set"
	);
	assert!(total_dedup <= total_plain);
}

/// The stored keys of a hash-keyed database, ignoring reference counts.
fn db_key_set<H: hash_db::Hasher>(
	db: &MemoryDB<H, HashKey<H>, DBValue>,
) -> std::collections::BTreeSet<Vec<u8>> {
	db.keys().into_iter().map(|(key, _rc)| key.as_ref().to_vec()).collect()
}

fn test_trie_codec_proof<L: TrieLayout>(entries: Vec<(Vec<u8>, Vec<u8>)>, keys: Vec<Vec<u8>>) {
	use hash_db::{HashDB, EMPTY_PREFIX};
	use trie_db::{decode_compact, encode_compact, encode_compact_skip_duplicates, Recorder};

	// Populate DB with full trie from entries.
	let (db, root) = {
		let mut db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
		let mut root = Default::default();
		{
			let mut trie = TrieDBMutBuilder::<L>::new(&mut db, &mut root).build();
			for (key, value) in entries {
				trie.insert(&key, &value).unwrap();
			}
		}
		(db, root)
	};
	let expected_root = root;
	// Lookup items in trie while recording traversed nodes.
	let mut recorder = Recorder::<L>::new();
	let items = {
		let mut items = Vec::with_capacity(keys.len());
		let trie = TrieDBBuilder::<L>::new(&db, &root).with_recorder(&mut recorder).build();
		for key in keys {
			let value = trie.get(key.as_slice()).unwrap();
			items.push((key, value));
		}
		items
	};

	// Populate a partial trie DB with recorded nodes.
	let mut partial_db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
	for record in recorder.drain() {
		partial_db.emplace(record.hash, EMPTY_PREFIX, record.data);
	}

	// Compactly encode the partial trie DB.
	let compact_trie = {
		let trie = TrieDBBuilder::<L>::new(&partial_db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};

	let expected_used = compact_trie.len();
	// Reconstruct the partial DB from the compact encoding.
	let mut db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
	let (root, used) = decode_compact::<L, _>(&mut db, &compact_trie).unwrap();
	assert_eq!(root, expected_root);
	assert_eq!(used, expected_used);

	// Check that lookups for all items succeed.
	let trie = TrieDBBuilder::<L>::new(&db, &root).build();
	for (key, expected_value) in &items {
		assert_eq!(&trie.get(key.as_slice()).unwrap(), expected_value);
	}

	// Round-trip the deduplicating encoding into a hash-keyed database.
	let deduplicated = {
		let trie = TrieDBBuilder::<L>::new(&partial_db, &expected_root).build();
		encode_compact_skip_duplicates::<L>(&trie, &mut Default::default()).unwrap()
	};
	assert!(deduplicated.len() <= expected_used);

	let mut hash_keyed_db = <MemoryDB<L::Hash, HashKey<_>, _>>::default();
	let (root, used) = decode_compact::<L, _>(&mut hash_keyed_db, &deduplicated).unwrap();
	assert_eq!(root, expected_root);
	assert_eq!(used, deduplicated.len());
	// Deduplication must not change the reconstructed node set (`db` holds the decoded
	// unmodified encoding); reference counts differ by design and are not compared.
	assert!(db_key_set(&hash_keyed_db) == db_key_set(&db));
	let trie = TrieDBBuilder::<L>::new(&hash_keyed_db, &root).build();
	for (key, expected_value) in &items {
		assert_eq!(&trie.get(key.as_slice()).unwrap(), expected_value);
	}
}

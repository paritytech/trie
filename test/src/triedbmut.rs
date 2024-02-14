// Copyright 2017, 2020 Parity Technologies
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

use std::ops::Deref;

use env_logger;
use log::debug;
use reference_trie::{
	reference_trie_root, test_layouts, ExtensionLayout, HashedValueNoExt,
	HashedValueNoExtThreshold, NoExtensionLayout, PrefixedMemoryDB, RefHasher, ReferenceNodeCodec,
	ReferenceNodeCodecNoExt, TestTrieCache,
};
use trie_db::{
	memory_db::{HashKey, MemoryDB, PrefixedKey},
	node_db::{Hasher, NodeDB, Prefix, EMPTY_PREFIX},
	test_utils::*,
	CachedValue, Changeset, DBValue, NodeCodec, Recorder, Trie, TrieCache, TrieDBBuilder,
	TrieDBMut, TrieDBMutBuilder, TrieDBNodeIterator, TrieError, TrieHash, TrieLayout, Value,
};

use crate::{TestCommit, TestDB};

type MemoryDBProof<T> =
	MemoryDB<<T as TrieLayout>::Hash, HashKey<<T as TrieLayout>::Hash>, DBValue>;

fn populate_trie<'db, T: TrieLayout>(
	db: &'db dyn NodeDB<T::Hash, DBValue, T::Location>,
	v: &[(Vec<u8>, Vec<u8>)],
) -> TrieDBMut<'db, T> {
	let mut t = TrieDBMutBuilder::<T>::new(db).build();
	for i in 0..v.len() {
		let key: &[u8] = &v[i].0;
		let val: &[u8] = &v[i].1;
		t.insert(key, val).unwrap();
	}
	t
}

fn unpopulate_trie<'db, T: TrieLayout>(
	t: &mut TrieDBMut<'db, T>,
	v: &[(Vec<u8>, Vec<u8>)],
) -> bool {
	for (_ix, i) in v.into_iter().enumerate() {
		let key: &[u8] = &i.0;
		if t.remove(key).is_err() {
			return false
		}
	}
	true
}

fn reference_hashed_null_node<T: TrieLayout>() -> <T::Hash as Hasher>::Out {
	if T::USE_EXTENSION {
		<ReferenceNodeCodec<T::Hash> as NodeCodec>::hashed_null_node()
	} else {
		<ReferenceNodeCodecNoExt<T::Hash> as NodeCodec>::hashed_null_node()
	}
}

#[test]
fn playpen() {
	env_logger::init();
	playpen_internal::<HashedValueNoExtThreshold<1, ()>>();
	playpen_internal::<HashedValueNoExt>();
	playpen_internal::<NoExtensionLayout>();
	playpen_internal::<ExtensionLayout>();
}
fn playpen_internal<T: TrieLayout>() {
	let mut seed = [0u8; 32];
	for test_i in 0..10_000 {
		if test_i % 50 == 0 {
			debug!("{:?} of 10000 stress tests done", test_i);
		}
		let initial_seed = seed.clone();
		let x = StandardMap {
			alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
			min_key: 5,
			journal_key: 0,
			value_mode: ValueMode::Index,
			count: 100,
		}
		.make_with(&mut seed);

		let real = reference_trie_root::<T, _, _, _>(x.clone());
		let mut memdb = PrefixedMemoryDB::<T>::default();
		let memtrie = populate_trie::<T>(&memdb, &x);
		// avoid duplicate
		let value_set: std::collections::BTreeMap<&[u8], &[u8]> =
			x.iter().map(|(k, v)| (k.as_slice(), v.as_slice())).collect();
		for (k, v) in value_set {
			assert_eq!(memtrie.get(k).unwrap().unwrap(), v);
		}
		let commit = memtrie.commit();
		let root = commit.apply_to(&mut memdb);

		if root != real {
			println!("TRIE MISMATCH");
			println!();
			println!("{:?} vs {:?}", root, real);
			for i in &x {
				println!("{:#x?} -> {:#x?}", i.0, i.1);
			}
		}
		assert_eq!(root, real);

		let mut memtrie = TrieDBMutBuilder::<T>::from_existing(&memdb, root).build();
		assert!(unpopulate_trie(&mut memtrie, &x), "{:?}", (test_i, initial_seed));
		let root = memtrie.commit().apply_to(&mut memdb);
		let hashed_null_node = reference_hashed_null_node::<T>();
		if root != hashed_null_node {
			println!("- TRIE MISMATCH");
			println!();
			println!("{:#x?} vs {:#x?}", root, hashed_null_node);
			for i in &x {
				println!("{:#x?} -> {:#x?}", i.0, i.1);
			}
		}
		assert_eq!(root, hashed_null_node);
	}
}

test_layouts!(init, init_internal);
fn init_internal<T: TrieLayout, DB: TestDB<T>>() {
	let memdb = DB::default();
	let t = TrieDBMutBuilder::<T>::new(&memdb).build();
	let hashed_null_node = reference_hashed_null_node::<T>();
	assert_eq!(t.commit().root_hash(), hashed_null_node);
}

test_layouts!(insert_on_empty, insert_on_empty_internal);
fn insert_on_empty_internal<T: TrieLayout, DB: TestDB<T>>() {
	let memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	assert_eq!(
		t.commit().root_hash(),
		reference_trie_root::<T, _, _, _>(vec![(vec![0x01u8, 0x23], vec![0x01u8, 0x23])]),
	);
}

test_layouts!(remove_to_empty, remove_to_empty_internal);
fn remove_to_empty_internal<T: TrieLayout, DB: TestDB<T>>() {
	let big_value = b"00000000000000000000000000000000";

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();

	t.insert(&[0x01], big_value).unwrap();
	t.insert(&[0x01, 0x23], big_value).unwrap();
	t.insert(&[0x01, 0x34], big_value).unwrap();
	t.remove(&[0x01]).unwrap();
	t.remove(&[0x01, 0x23]).unwrap();
	t.remove(&[0x01, 0x34]).unwrap();
	t.commit().commit_to(&mut memdb);
	assert!(memdb.is_empty());
}

test_layouts!(remove_to_empty_checked, remove_to_empty_checked_internal);
fn remove_to_empty_checked_internal<T: TrieLayout, DB: TestDB<T>>() {
	let big_value = b"00000000000000000000000000000000";

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01], big_value).unwrap();
	t.insert(&[0x01, 0x23], big_value).unwrap();
	t.insert(&[0x01, 0x34], big_value).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	let mut t = TrieDBMutBuilder::<T>::from_existing(&mut memdb, root).build();
	assert_eq!(t.get(&[0x01]).unwrap(), Some(big_value.to_vec()),);
	assert_eq!(t.get(&[0x01, 0x34]).unwrap(), Some(big_value.to_vec()),);
	t.remove(&[0x01]).unwrap();
	t.remove(&[0x01, 0x23]).unwrap();
	t.remove(&[0x01, 0x34]).unwrap();
	t.commit().commit_to(&mut memdb);
	assert!(memdb.is_empty());
}

test_layouts!(remove_to_empty_no_extension, remove_to_empty_no_extension_internal);
fn remove_to_empty_no_extension_internal<T: TrieLayout, DB: TestDB<T>>() {
	let big_value = b"00000000000000000000000000000000";
	let big_value2 = b"00000000000000000000000000000002";
	let big_value3 = b"00000000000000000000000000000004";

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();

	t.insert(&[0x01, 0x23], big_value3).unwrap();
	t.insert(&[0x01], big_value2).unwrap();
	t.insert(&[0x01, 0x34], big_value).unwrap();
	t.remove(&[0x01]).unwrap();

	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		&root,
		&reference_trie::calc_root::<T, _, _, _>(vec![
			(vec![0x01u8, 0x23], big_value3.to_vec()),
			(vec![0x01u8, 0x34], big_value.to_vec()),
		])
	);
}

test_layouts!(insert_replace_root, insert_replace_root_internal);
fn insert_replace_root_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0x01u8, 0x23], &[0x23u8, 0x45]).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		root,
		reference_trie_root::<T, _, _, _>(vec![(vec![0x01u8, 0x23], vec![0x23u8, 0x45])]),
	);
}

test_layouts!(insert_make_branch_root, insert_make_branch_root_internal);
fn insert_make_branch_root_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0x11u8, 0x23], &[0x11u8, 0x23]).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		root,
		reference_trie_root::<T, _, _, _>(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x11u8, 0x23], vec![0x11u8, 0x23])
		])
	);
}

test_layouts!(insert_into_branch_root, insert_into_branch_root_internal);
fn insert_into_branch_root_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0xf1u8, 0x23], &[0xf1u8, 0x23]).unwrap();
	t.insert(&[0x81u8, 0x23], &[0x81u8, 0x23]).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		root,
		reference_trie_root::<T, _, _, _>(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x81u8, 0x23], vec![0x81u8, 0x23]),
			(vec![0xf1u8, 0x23], vec![0xf1u8, 0x23]),
		])
	);
}

test_layouts!(insert_value_into_branch_root, insert_value_into_branch_root_internal);
fn insert_value_into_branch_root_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[], &[0x0]).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		root,
		reference_trie_root::<T, _, _, _>(vec![
			(vec![], vec![0x0]),
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
		])
	);
}

test_layouts!(insert_split_leaf, insert_split_leaf_internal);
fn insert_split_leaf_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0x01u8, 0x34], &[0x01u8, 0x34]).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		root,
		reference_trie_root::<T, _, _, _>(vec![
			(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
			(vec![0x01u8, 0x34], vec![0x01u8, 0x34]),
		])
	);
}

test_layouts!(insert_split_extenstion, insert_split_extenstion_internal);
fn insert_split_extenstion_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01, 0x23, 0x45], &[0x01]).unwrap();
	t.insert(&[0x01, 0xf3, 0x45], &[0x02]).unwrap();
	t.insert(&[0x01, 0xf3, 0xf5], &[0x03]).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		root,
		reference_trie_root::<T, _, _, _>(vec![
			(vec![0x01, 0x23, 0x45], vec![0x01]),
			(vec![0x01, 0xf3, 0x45], vec![0x02]),
			(vec![0x01, 0xf3, 0xf5], vec![0x03]),
		])
	);
}

test_layouts!(insert_big_value, insert_big_value_internal);
fn insert_big_value_internal<T: TrieLayout, DB: TestDB<T>>() {
	let big_value0 = b"00000000000000000000000000000000";
	let big_value1 = b"11111111111111111111111111111111";

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], big_value0).unwrap();
	t.insert(&[0x11u8, 0x23], big_value1).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		root,
		reference_trie_root::<T, _, _, _>(vec![
			(vec![0x01u8, 0x23], big_value0.to_vec()),
			(vec![0x11u8, 0x23], big_value1.to_vec())
		])
	);
}

test_layouts!(insert_duplicate_value, insert_duplicate_value_internal);
fn insert_duplicate_value_internal<T: TrieLayout, DB: TestDB<T>>() {
	let big_value = b"00000000000000000000000000000000";

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], big_value).unwrap();
	t.insert(&[0x11u8, 0x23], big_value).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	assert_eq!(
		root,
		reference_trie_root::<T, _, _, _>(vec![
			(vec![0x01u8, 0x23], big_value.to_vec()),
			(vec![0x11u8, 0x23], big_value.to_vec())
		])
	);
}

test_layouts!(test_at_empty, test_at_empty_internal);
fn test_at_empty_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	assert_eq!(t.get(&[0x5]).unwrap(), None);
}

test_layouts!(test_at_one_and_two, test_at_one_and_two_internal);
fn test_at_one_and_two_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), vec![0x1u8, 0x23]);
	let root = t.commit().commit_to(&mut memdb);
	let mut t = TrieDBMutBuilder::<T>::from_existing(&mut memdb, root).build();
	assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), vec![0x1u8, 0x23]);
	t.insert(&[0x01u8, 0x23, 0x00], &[0x01u8, 0x24]).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	let mut t = TrieDBMutBuilder::<T>::from_existing(&mut memdb, root).build();
	t.insert(&[0x01u8, 0x23, 0x00], &[0x01u8, 0x25]).unwrap();
	// This test that middle node get resolved correctly (modified
	// triedbmut node due to change of child node).
	assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), vec![0x1u8, 0x23]);
}

test_layouts!(test_at_three, test_at_three_internal);
fn test_at_three_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0xf1u8, 0x23], &[0xf1u8, 0x23]).unwrap();
	t.insert(&[0x81u8, 0x23], &[0x81u8, 0x23]).unwrap();
	assert_eq!(t.get(&[0x01, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
	assert_eq!(t.get(&[0xf1, 0x23]).unwrap().unwrap(), vec![0xf1u8, 0x23]);
	assert_eq!(t.get(&[0x81, 0x23]).unwrap().unwrap(), vec![0x81u8, 0x23]);
	assert_eq!(t.get(&[0x82, 0x23]).unwrap(), None);
	let root = memdb.commit(t.commit());
	let t = TrieDBMutBuilder::<T>::from_existing(&memdb, root).build();
	assert_eq!(t.get(&[0x01, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
	assert_eq!(t.get(&[0xf1, 0x23]).unwrap().unwrap(), vec![0xf1u8, 0x23]);
	assert_eq!(t.get(&[0x81, 0x23]).unwrap().unwrap(), vec![0x81u8, 0x23]);
	assert_eq!(t.get(&[0x82, 0x23]).unwrap(), None);
}

#[test]
fn test_nibbled_branch_changed_value() {
	let memdb = MemoryDB::<RefHasher, PrefixedKey<_>, DBValue>::default();
	let mut t = reference_trie::RefTrieDBMutNoExtBuilder::new(&memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0x01u8, 0x23, 0x11], &[0xf1u8, 0x23]).unwrap();
	assert_eq!(t.get(&[0x01u8, 0x23]).unwrap(), Some(vec![0x01u8, 0x23]));
}

test_layouts!(stress, stress_internal);
fn stress_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut seed = Default::default();
	for _ in 0..1000 {
		let x = StandardMap {
			alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
			min_key: 5,
			journal_key: 0,
			value_mode: ValueMode::Index,
			count: 4,
		}
		.make_with(&mut seed);

		let real = reference_trie_root::<T, _, _, _>(x.clone());
		let mut memdb = DB::default();
		let memtrie = populate_trie::<T>(&mut memdb, &x);
		let mut y = x.clone();
		y.sort_by(|ref a, ref b| a.0.cmp(&b.0));
		let mut memdb2 = DB::default();
		let memtrie_sorted = populate_trie::<T>(&mut memdb2, &y);
		let root = memtrie.commit().commit_to(&mut memdb);
		let root2 = memtrie_sorted.commit().commit_to(&mut memdb2);
		if root != real || root2 != real {
			println!("TRIE MISMATCH");
			println!();
			println!("ORIGINAL... {:#x?}", root);
			for i in &x {
				println!("{:#x?} -> {:#x?}", i.0, i.1);
			}
			println!("SORTED... {:#x?}", root2);
			for i in &y {
				println!("{:#x?} -> {:#x?}", i.0, i.1);
			}
		}
		assert_eq!(root, real);
		assert_eq!(root2, real);
	}
}

test_layouts!(test_trie_existing, test_trie_existing_internal);
fn test_trie_existing_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	let root = t.commit().commit_to(&mut memdb);
	let _ = TrieDBMutBuilder::<T>::from_existing(&memdb, root);
}

test_layouts!(insert_empty, insert_empty_internal);
fn insert_empty_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut seed = Default::default();
	let x = StandardMap {
		alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
		min_key: 5,
		journal_key: 0,
		value_mode: ValueMode::Index,
		count: 4,
	}
	.make_with(&mut seed);

	let mut db = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&db).build();
	for &(ref key, ref value) in &x {
		t.insert(key, value).unwrap();
	}
	let root = db.commit(t.commit());

	assert_eq!(root, reference_trie_root::<T, _, _, _>(x.clone()));

	let mut t = TrieDBMutBuilder::<T>::from_existing(&db, root).build();
	for &(ref key, _) in &x {
		t.insert(key, &[]).unwrap();
	}
	assert!(t.is_empty());
	let root = db.commit(t.commit());

	let hashed_null_node = reference_hashed_null_node::<T>();
	assert_eq!(root, hashed_null_node);
}

test_layouts!(return_old_values, return_old_values_internal);
fn return_old_values_internal<T: TrieLayout, DB: TestDB<T>>() {
	let threshold = T::MAX_INLINE_VALUE;
	let mut seed = Default::default();
	let x = StandardMap {
		alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
		min_key: 5,
		journal_key: 0,
		value_mode: ValueMode::Index,
		count: 2,
	}
	.make_with(&mut seed);

	let mut db = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut db).build();
	for &(ref key, ref value) in &x {
		assert!(t.insert(key, value).unwrap() == None);
		if threshold.map(|t| value.len() < t as usize).unwrap_or(true) {
			assert_eq!(t.insert(key, value).unwrap(), Some(Value::Inline(value.clone().into())));
		} else {
			assert!(matches!(t.insert(key, value).unwrap(), Some(Value::NewNode(..))));
		}
	}
	for (key, value) in x {
		if threshold.map(|t| value.len() < t as usize).unwrap_or(true) {
			assert_eq!(t.remove(&key).unwrap(), Some(Value::Inline(value.into())));
		} else {
			assert!(matches!(t.remove(&key).unwrap(), Some(Value::NewNode(..))));
		}
		assert_eq!(t.remove(&key).unwrap(), None);
	}
}

#[test]
fn insert_empty_allowed() {
	let mut db = MemoryDB::<RefHasher, PrefixedKey<_>, DBValue>::default();
	let mut t = reference_trie::RefTrieDBMutAllowEmptyBuilder::new(&db).build();
	t.insert(b"test", &[]).unwrap();
	let root = t.commit().apply_to(&mut db);

	assert_eq!(
		root,
		reference_trie_root::<reference_trie::AllowEmptyLayout, _, _, _>(vec![(
			b"test".to_vec(),
			Vec::new()
		)],)
	);
	let t = reference_trie::RefTrieDBMutAllowEmptyBuilder::from_existing(&db, root).build();
	assert_eq!(t.get(b"test").unwrap(), Some(Vec::new()));
}

#[test]
fn register_proof_without_value() {
	use reference_trie::HashedValueNoExtThreshold;
	use std::{cell::RefCell, collections::HashMap};
	use Prefix;

	type Layout = HashedValueNoExtThreshold<1, ()>;
	type MemoryDB = trie_db::memory_db::MemoryDB<RefHasher, PrefixedKey<RefHasher>, DBValue>;
	let x = [
		(b"test1".to_vec(), vec![1; 32]), // inline
		(b"test1234".to_vec(), vec![2; 36]),
		(b"te".to_vec(), vec![3; 32]),
	];

	let mut memdb = MemoryDB::default();
	let t = populate_trie::<Layout>(&mut memdb, &x);
	let root = t.commit().apply_to(&mut memdb);
	{
		let trie = TrieDBBuilder::<Layout>::new(&memdb, &root).build();
		println!("{:?}", trie);
	}

	struct ProofRecorder {
		db: MemoryDB,
		record: RefCell<HashMap<Vec<u8>, Vec<u8>>>,
	}
	// Only to test without threads.
	unsafe impl Send for ProofRecorder {}
	unsafe impl Sync for ProofRecorder {}

	impl NodeDB<RefHasher, DBValue, ()> for ProofRecorder {
		fn get(
			&self,
			key: &<RefHasher as Hasher>::Out,
			prefix: Prefix,
			_location: (),
		) -> Option<(DBValue, Vec<()>)> {
			let v = NodeDB::get(&self.db, key, prefix, ());
			if let Some((v, _)) = v.as_ref() {
				self.record.borrow_mut().entry(key[..].to_vec()).or_insert_with(|| v.clone());
			}
			v
		}
		fn contains(
			&self,
			key: &<RefHasher as Hasher>::Out,
			prefix: Prefix,
			_locatoin: (),
		) -> bool {
			self.get(key, prefix, ()).is_some()
		}
	}

	let mut memdb = ProofRecorder { db: memdb, record: Default::default() };

	let root_proof = root.clone();
	let mut trie = TrieDBMutBuilder::<Layout>::from_existing(&mut memdb, root).build();
	// touch te value (test1 remains untouch).
	trie.get(b"te").unwrap();
	// cut test_1234 prefix
	trie.insert(b"test12", &[2u8; 36][..]).unwrap();
	// remove 1234
	trie.remove(b"test1234").unwrap();

	// proof should contain value for 'te' only.
	type MemoryDBProof = trie_db::memory_db::MemoryDB<RefHasher, HashKey<RefHasher>, DBValue>;
	let mut memdb_from_proof = MemoryDBProof::default();
	for (_key, value) in memdb.record.into_inner().into_iter() {
		memdb_from_proof.insert(EMPTY_PREFIX, value.as_slice());
	}

	let db_unpacked = memdb_from_proof.clone();
	let root_unpacked = root_proof.clone();

	let mut memdb_from_proof = db_unpacked.clone();
	let root_proof = root_unpacked.clone();
	{
		let mut trie =
			TrieDBMutBuilder::<Layout>::from_existing(&mut memdb_from_proof, root_proof).build();
		trie.get(b"te").unwrap();
		trie.insert(b"test12", &[2u8; 36][..]).unwrap();
		trie.remove(b"test1234").unwrap();
	}

	let mut memdb_from_proof = db_unpacked.clone();
	let root_proof = root_unpacked.clone();
	{
		use trie_db::Trie;
		let trie = TrieDBBuilder::<Layout>::new(&memdb_from_proof, &root_proof).build();
		assert!(trie.get(b"te").unwrap().is_some());
		assert!(matches!(
			trie.get(b"test1").map_err(|e| *e),
			Err(TrieError::IncompleteDatabase(..))
		));
	}

	{
		let trie =
			TrieDBMutBuilder::<Layout>::from_existing(&mut memdb_from_proof, root_proof).build();
		assert!(trie.get(b"te").unwrap().is_some());
		assert!(matches!(
			trie.get(b"test1").map_err(|e| *e),
			Err(TrieError::IncompleteDatabase(..))
		));
	}
}

test_layouts!(test_recorder, test_recorder_internal);
fn test_recorder_internal<T: TrieLayout, DB: TestDB<T>>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 64]),
		(b"B".to_vec(), vec![4; 64]),
	];

	// Add some initial data to the trie
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (key, value) in key_value.iter().take(1) {
		t.insert(key, value).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	// Add more data, but this time only to the overlay.
	// While doing that we record all trie accesses to replay this operation.
	let mut recorder = Recorder::<T>::new();
	let mut overlay = memdb.clone();
	let new_root = root;
	{
		let mut trie = TrieDBMutBuilder::<T>::from_existing(&mut overlay, new_root)
			.with_recorder(&mut recorder)
			.build();

		for (key, value) in key_value.iter().skip(1) {
			trie.insert(key, value).unwrap();
		}
	}

	let mut partial_db = MemoryDBProof::<T>::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	// Replay the it, but this time we use the proof.
	let validated_root = root;
	{
		let mut trie =
			TrieDBMutBuilder::<T>::from_existing(&mut partial_db, validated_root).build();

		for (key, value) in key_value.iter().skip(1) {
			trie.insert(key, value).unwrap();
		}
	}

	assert_eq!(new_root, validated_root);
}

test_layouts!(test_recorder_witch_cache, test_recorder_with_cache_internal);
fn test_recorder_with_cache_internal<T: TrieLayout, DB: TestDB<T>>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 64]),
		(b"B".to_vec(), vec![4; 64]),
	];

	// Add some initial data to the trie
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (key, value) in key_value.iter().take(1) {
		t.insert(key, value).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);
	let mut validated_root = root;

	let mut cache = TestTrieCache::<T>::default();

	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).with_cache(&mut cache).build();

		// Only read one entry.
		assert_eq!(key_value[0].1, trie.get(&key_value[0].0).unwrap().unwrap());
	}

	// Root should now be cached.
	assert!(cache.get_node(&root, Default::default()).is_some());

	// Add more data, but this time only to the overlay.
	// While doing that we record all trie accesses to replay this operation.
	let mut recorder = Recorder::<T>::new();
	let mut overlay = memdb.clone();
	let mut trie = TrieDBMutBuilder::<T>::from_existing(&mut overlay, root)
		.with_recorder(&mut recorder)
		.with_cache(&mut cache)
		.build();

	for (key, value) in key_value.iter().skip(1) {
		trie.insert(key, value).unwrap();
	}
	let new_root = trie.commit().commit_to(&mut overlay);

	let t = TrieDBBuilder::<T>::new(&overlay, &new_root).with_cache(&mut cache).build();
	for (key, _) in key_value.iter().skip(1) {
		t.get(key).unwrap();
	}

	for (key, value) in key_value.iter().skip(1) {
		let cached_value = cache.lookup_value_for_key(key).unwrap();

		assert_eq!(value, cached_value.data().flatten().unwrap().deref());
		assert_eq!(T::Hash::hash(&value), cached_value.hash().unwrap());
	}

	let mut partial_db = MemoryDBProof::<T>::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	// Replay the it, but this time we use the proof.
	{
		let mut trie = TrieDBMutBuilder::<T>::from_existing(&partial_db, validated_root).build();

		for (key, value) in key_value.iter().skip(1) {
			trie.insert(key, value).unwrap();
		}
		validated_root = trie.commit().apply_to(&mut partial_db);
	}

	assert_eq!(new_root, validated_root);
}

test_layouts!(test_insert_remove_data_with_cache, test_insert_remove_data_with_cache_internal);
fn test_insert_remove_data_with_cache_internal<T: TrieLayout, DB: TestDB<T>>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		// Should be inlined
		(b"AC".to_vec(), vec![7; 4]),
		(b"AB".to_vec(), vec![3; 64]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut cache = TestTrieCache::<T>::default();
	let mut recorder = Recorder::<T>::new();
	let mut memdb = DB::default();
	let mut trie = TrieDBMutBuilder::<T>::new(&mut memdb)
		.with_recorder(&mut recorder)
		.with_cache(&mut cache)
		.build();

	// Add all values
	for (key, value) in key_value.iter() {
		trie.insert(key, value).unwrap();
	}

	// Remove only the last 2 elements
	for (key, _) in key_value.iter().skip(3) {
		let _ = trie.remove(key);
	}
	let mut memdb = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
	let root = trie.commit().apply_to(&mut memdb);
	let t = TrieDBBuilder::<T>::new(&memdb, &root).with_cache(&mut cache).build();
	for (key, _) in &key_value {
		t.get(key).unwrap();
	}

	// Then only the first 3 elements should be in the cache and the last
	// two ones should be added as non-existent.
	for (key, value) in key_value.iter().take(3) {
		let key_str = String::from_utf8_lossy(key);

		let cached_value = cache
			.lookup_value_for_key(key)
			.unwrap_or_else(|| panic!("Failed to lookup `{}`", key_str));

		assert_eq!(value, cached_value.data().flatten().unwrap().deref(), "{:?}", key_str);
		assert_eq!(T::Hash::hash(&value), cached_value.hash().unwrap());
	}

	for (key, _) in key_value.iter().skip(3) {
		assert!(matches!(cache.lookup_value_for_key(key).unwrap(), CachedValue::NonExisting));
	}
}

#[test]
fn test_two_assets_memory_db() {
	test_two_assets_memory_db_inner_1::<HashedValueNoExtThreshold<1, ()>>();
	test_two_assets_memory_db_inner_2::<HashedValueNoExtThreshold<1, ()>>();
}
fn test_two_assets_memory_db_inner_1<T: TrieLayout>() {
	let memdb = PrefixedMemoryDB::<T>::new(&[0u8]);
	let mut state = TrieDBMutBuilder::<T>::new(&memdb).build();

	let key1 = [1u8; 3];
	let data1 = [1u8; 2];
	state.insert(key1.as_ref(), &data1).unwrap();
	assert_eq!(state.get(key1.as_ref()).unwrap().unwrap(), data1); //PASSING
	let key2 = [2u8; 3];
	let data2 = [2u8; 2];
	state.insert(key2.as_ref(), &data2).unwrap();
	assert_eq!(state.get(key1.as_ref()).unwrap().unwrap(), data1);

	state.commit();
}

fn test_two_assets_memory_db_inner_2<T: TrieLayout>() {
	let memdb = PrefixedMemoryDB::<T>::new(&[0u8]);
	let mut state = TrieDBMutBuilder::<T>::new(&memdb).build();

	let key1 = [1u8];
	let data1 = [1u8; 2];
	state.insert(key1.as_ref(), &data1).unwrap();
	assert_eq!(state.get(key1.as_ref()).unwrap().unwrap(), data1);
	let key2 = [1u8, 2];
	let data2 = [2u8; 2];
	state.insert(key2.as_ref(), &data2).unwrap();
	assert_eq!(state.get(key1.as_ref()).unwrap().unwrap(), data1);
	assert_eq!(state.get(key2.as_ref()).unwrap().unwrap(), data2);

	let key3 = [1u8, 3];
	let data3 = [3u8; 2];
	state.insert(key3.as_ref(), &data3).unwrap();
	assert_eq!(state.get(key1.as_ref()).unwrap().unwrap(), data1);
	assert_eq!(state.get(key2.as_ref()).unwrap().unwrap(), data2);
	assert_eq!(state.get(key3.as_ref()).unwrap().unwrap(), data3);
}

test_layouts!(attached_trie, attached_trie_internal);
fn attached_trie_internal<T: TrieLayout, DB: TestDB<T>>() {
	use std::collections::BTreeMap;
	struct ATrie<T: TrieLayout> {
		root: TrieHash<T>,
		data: BTreeMap<Vec<u8>, Vec<u8>>,
		changeset: Option<Box<Changeset<TrieHash<T>, T::Location>>>,
	}
	// Running a typical attached trie scenario (childtrie on substrate):
	// different trie, attached trie root written all
	// at once with treerefset before parent tree commit.
	// Direct copy if using ref counting and location in db.
	// Pruning.
	let mut seed = Default::default();
	let nb_attached_trie = 10;
	//	let nb_attached_trie = 1;
	let support_location = DB::support_location();
	let mut memdb = DB::default();
	let mut attached_tries: BTreeMap<Vec<u8>, ATrie<T>> = Default::default();
	let mut keyspaced_memdb;
	let mut main_trie: ATrie<T> =
		ATrie { root: Default::default(), data: Default::default(), changeset: None };
	for i in 0..nb_attached_trie + 1 {
		let x = StandardMap {
			alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
			min_key: 3,
			journal_key: 0,
			value_mode: ValueMode::Index,
			count: 20,
			//count: 2,
		}
		.make_with(&mut seed);

		let mut memtrie = populate_trie::<T>(&mut memdb, &x);
		let data: BTreeMap<Vec<u8>, Vec<u8>> = x.iter().cloned().collect();
		if i == nb_attached_trie {
			for (k, c) in attached_tries.iter_mut() {
				let key: &[u8] = &k[..];
				let val: &[u8] = c.root.as_ref();
				let changeset = c.changeset.take().unwrap();
				memtrie.insert_with_tree_ref(key, val, Some(changeset)).unwrap();
			}
			let changeset = memtrie.commit();
			let root = changeset.commit_to(&mut memdb);
			main_trie.root = root;
			main_trie.data = data;
		} else {
			let attached_trie_root_key = data.iter().next().unwrap().0;
			let changeset = memtrie.commit_with_keyspace(attached_trie_root_key);
			let root = changeset.root_hash();
			attached_tries.insert(
				attached_trie_root_key.clone(),
				ATrie { root, data, changeset: Some(changeset.into()) },
			);
		}
	}
	// check data
	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &main_trie.root).build();
		for (k, v) in main_trie.data.iter() {
			assert_eq!(&trie.get(k).unwrap().unwrap(), v);
		}
	}
	for (root_key, attached_trie) in &attached_tries {
		let (attached_trie_root, attached_trie_location) =
			attached_trie_root(&memdb, &main_trie.root, root_key).unwrap();

		let child_memdb: &dyn NodeDB<_, _, _> = if support_location {
			&memdb
		} else {
			assert!(attached_trie_location.is_none());
			keyspaced_memdb = KeySpacedDB::new(&memdb, &root_key[..]);
			&keyspaced_memdb
		};

		let trie = TrieDBBuilder::<T>::new_with_db_location(
			child_memdb,
			&attached_trie_root,
			attached_trie_location.unwrap_or_default(),
		)
		.build();
		for (k, v) in attached_trie.data.iter() {
			assert_eq!(&trie.get(k).unwrap().unwrap(), v);
		}
	}
	// Modifying an existing child trie.
	let (root_key, a_attached_trie) = attached_tries.iter().next().unwrap();
	let (a_attached_trie_root, attached_trie_location) =
		attached_trie_root(&memdb, &main_trie.root, &root_key).unwrap();
	let (tree_ref_changeset, treeref_root_hash) = {
		assert_eq!(a_attached_trie_root, a_attached_trie.root);
		let child_memdb: &dyn NodeDB<_, _, _> = if support_location {
			&memdb
		} else {
			keyspaced_memdb = KeySpacedDB::new(&memdb, &root_key[..]);
			&keyspaced_memdb
		};
		let mut attached_trie = TrieDBMutBuilder::<T>::from_existing_with_db_location(
			child_memdb,
			a_attached_trie_root,
			attached_trie_location.unwrap_or_default(),
		)
		.build();
		attached_trie.remove(a_attached_trie.data.iter().next().unwrap().0).unwrap();
		attached_trie.insert(b"make_sure_it_changes", b"value").unwrap();
		let changeset = attached_trie.commit_with_keyspace(root_key);
		let new_root = changeset.root_hash();
		assert!(new_root != a_attached_trie_root);
		(changeset, new_root)
	};
	let mut main_trie = TrieDBMutBuilder::<T>::from_existing(&memdb, main_trie.root).build();
	main_trie
		.insert_with_tree_ref(root_key, treeref_root_hash.as_ref(), Some(tree_ref_changeset.into()))
		.unwrap();
	let changeset = main_trie.commit();
	let main_root = changeset.root_hash();
	changeset.commit_to(&mut memdb);
	// checking modification
	let (a_attached_trie_root, attached_trie_location) =
		attached_trie_root(&memdb, &main_root, root_key).unwrap();
	let child_memdb: &dyn NodeDB<_, _, _> = if support_location {
		&memdb
	} else {
		keyspaced_memdb = KeySpacedDB::new(&memdb, &root_key[..]);
		&keyspaced_memdb
	};
	let trie = TrieDBBuilder::<T>::new_with_db_location(
		child_memdb,
		&a_attached_trie_root,
		attached_trie_location.unwrap_or_default(),
	)
	.build();
	trie.get(b"make_sure_it_changes").unwrap().unwrap();
	let mut first = true;
	for (k, v) in a_attached_trie.data.iter() {
		if first {
			assert!(&trie.get(k).unwrap().is_none());
			first = false;
		} else {
			assert_eq!(&trie.get(k).unwrap().unwrap(), v);
		}
	}
	trie.get(b"make_sure_it_changes").unwrap().unwrap();
}

#[cfg(test)]
fn attached_trie_root<T: TrieLayout, DB: TestDB<T>>(
	memdb: &DB,
	main_root: &TrieHash<T>,
	root_key: &[u8],
) -> Option<(TrieHash<T>, Option<T::Location>)> {
	let trie = TrieDBBuilder::<T>::new(memdb, main_root).build();
	// Note could have a variant of get_with here that goes into
	// encoded node hash and locations.
	let mut iter = TrieDBNodeIterator::new(&trie).unwrap();
	use trie_db::TrieIterator;
	iter.seek(root_key).unwrap();
	let item = iter.next()?.unwrap();
	let node = &item.2;
	let location = node.node_plan().additional_ref_location(node.locations());
	let root = iter.item_from_raw(&item)?.unwrap();
	if root.0.as_slice() != root_key {
		return None;
	}
	let mut root_hash = TrieHash::<T>::default();
	root_hash.as_mut().copy_from_slice(&root.1);
	Some((root_hash, location))
}

pub struct KeySpacedDB<'a, H, T, DL>(&'a dyn NodeDB<H, T, DL>, &'a [u8]);

impl<'a, H, T, DL> KeySpacedDB<'a, H, T, DL> {
	#[inline]
	pub fn new(db: &'a dyn NodeDB<H, T, DL>, ks: &'a [u8]) -> Self {
		KeySpacedDB(db, ks)
	}
}

impl<'a, H, T, L> NodeDB<H, T, L> for KeySpacedDB<'a, H, T, L>
where
	H: Hasher,
	T: From<&'static [u8]>,
{
	fn get(&self, key: &H::Out, prefix: Prefix, location: L) -> Option<(T, Vec<L>)> {
		let derived_prefix = trie_db::triedbmut::prefix_prefix(self.1, prefix);
		self.0.get(key, (&derived_prefix.0, derived_prefix.1), location)
	}

	fn contains(&self, key: &H::Out, prefix: Prefix, location: L) -> bool {
		let derived_prefix = trie_db::triedbmut::prefix_prefix(self.1, prefix);
		self.0.contains(key, (&derived_prefix.0, derived_prefix.1), location)
	}
}

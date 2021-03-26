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

use env_logger;
use trie_standardmap::*;
use log::debug;
use memory_db::{MemoryDB, PrefixedKey};
use hash_db::Hasher;
use trie_db::{TrieDBMut, TrieMut, NodeCodec, HashDBHybridDyn,
	TrieLayout, DBValue};
use reference_trie::{ExtensionLayout, ExtensionLayoutHybrid, NoExtensionLayout,
	NoExtensionLayoutHybrid, RefHasher, test_layouts, ReferenceNodeCodec,
	ReferenceNodeCodecNoExt, reference_trie_root_iter_build as reference_trie_root};

fn populate_trie<'db, T: TrieLayout>(
	db: &'db mut dyn HashDBHybridDyn<T::Hash, DBValue>,
	root: &'db mut <T::Hash as Hasher>::Out,
	v: &[(Vec<u8>, Vec<u8>)]
) -> TrieDBMut<'db, T> {
	let mut t = TrieDBMut::<T>::new(db, root);
	for i in 0..v.len() {
		let key: &[u8]= &v[i].0;
		let val: &[u8] = &v[i].1;
		t.insert(key, val).unwrap();
	}
	t
}

fn unpopulate_trie<'db, T: TrieLayout>(t: &mut TrieDBMut<'db, T>, v: &[(Vec<u8>, Vec<u8>)]) {
	for i in v {
		let key: &[u8]= &i.0;
		t.remove(key).unwrap();
	}
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
	playpen_internal::<NoExtensionLayout>();
	playpen_internal::<ExtensionLayout>();
	playpen_internal::<NoExtensionLayoutHybrid>();
	playpen_internal::<ExtensionLayoutHybrid>();
}
fn playpen_internal<T: TrieLayout>() {
	let mut seed = Default::default();
	for test_i in 0..10 {
		if test_i % 50 == 0 {
			debug!("{:?} of 10000 stress tests done", test_i);
		}
		let x = StandardMap {
			alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
			min_key: 5,
			journal_key: 0,
			value_mode: ValueMode::Index,
			count: 100,
		}.make_with(&mut seed);

		let real = reference_trie_root::<T, _, _, _>(x.clone());
		let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut memtrie = populate_trie::<T>(&mut memdb, &mut root, &x);

		memtrie.commit();
		if *memtrie.root() != real {
			println!("TRIE MISMATCH");
			println!();
			println!("{:?} vs {:?}", memtrie.root(), real);
			for i in &x {
				println!("{:#x?} -> {:#x?}", i.0, i.1);
			}
		}
		assert_eq!(*memtrie.root(), real);
		unpopulate_trie(&mut memtrie, &x);
		memtrie.commit();
		let hashed_null_node = reference_hashed_null_node::<T>();
		if *memtrie.root() != hashed_null_node {
			println!("- TRIE MISMATCH");
			println!();
			println!("{:#x?} vs {:#x?}", memtrie.root(), hashed_null_node);
			for i in &x {
				println!("{:#x?} -> {:#x?}", i.0, i.1);
			}
		}
		assert_eq!(*memtrie.root(), hashed_null_node);
	}
}

test_layouts!(init, init_internal);
fn init_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	let hashed_null_node = reference_hashed_null_node::<T>();
	assert_eq!(*t.root(), hashed_null_node);
}

test_layouts!(insert_on_empty, insert_on_empty_internal);
fn insert_on_empty_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	assert_eq!(
		*t.root(),
		reference_trie_root::<T, _, _, _>(vec![(vec![0x01u8, 0x23], vec![0x01u8, 0x23])]),
	);
}

test_layouts!(remove_to_empty, remove_to_empty_internal);
fn remove_to_empty_internal<T: TrieLayout>() {
	let big_value = b"00000000000000000000000000000000";

	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);

		t.insert(&[0x01], big_value).unwrap();
		t.insert(&[0x01, 0x23], big_value).unwrap();
		t.insert(&[0x01, 0x34], big_value).unwrap();
		t.remove(&[0x01]).unwrap();
		t.remove(&[0x01, 0x23]).unwrap();
		t.remove(&[0x01, 0x34]).unwrap();
	}
	assert_eq!(memdb.keys().len(), 0);
}

test_layouts!(remove_to_empty_no_extension, remove_to_empty_no_extension_internal);
fn remove_to_empty_no_extension_internal<T: TrieLayout>() {
	let big_value = b"00000000000000000000000000000000";
	let big_value2 = b"00000000000000000000000000000002";
	let big_value3 = b"00000000000000000000000000000004";

	let mut memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);

		t.insert(&[0x01, 0x23], big_value3).unwrap();
		t.insert(&[0x01], big_value2).unwrap();
		t.insert(&[0x01, 0x34], big_value).unwrap();
		t.remove(&[0x01]).unwrap();
		// commit on drop
	}
	assert_eq!(&root, &reference_trie::calc_root::<T, _, _, _>(vec![
	 (vec![0x01u8, 0x23], big_value3.to_vec()),
	 (vec![0x01u8, 0x34], big_value.to_vec()),
	]));
}

test_layouts!(insert_replace_root, insert_replace_root_internal);
fn insert_replace_root_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0x01u8, 0x23], &[0x23u8, 0x45]).unwrap();
	assert_eq!(
		*t.root(),
		reference_trie_root::<T, _, _, _>(vec![(vec![0x01u8, 0x23], vec![0x23u8, 0x45])]),
	);
}

test_layouts!(insert_make_branch_root, insert_make_branch_root_internal);
fn insert_make_branch_root_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0x11u8, 0x23], &[0x11u8, 0x23]).unwrap();
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(vec![
		(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
		(vec![0x11u8, 0x23], vec![0x11u8, 0x23])
	]));
}

test_layouts!(insert_into_branch_root, insert_into_branch_root_internal);
fn insert_into_branch_root_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0xf1u8, 0x23], &[0xf1u8, 0x23]).unwrap();
	t.insert(&[0x81u8, 0x23], &[0x81u8, 0x23]).unwrap();
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(vec![
		(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
		(vec![0x81u8, 0x23], vec![0x81u8, 0x23]),
		(vec![0xf1u8, 0x23], vec![0xf1u8, 0x23]),
	]));
}

test_layouts!(insert_value_into_branch_root, insert_value_into_branch_root_internal);
fn insert_value_into_branch_root_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[], &[0x0]).unwrap();
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(vec![
		(vec![], vec![0x0]),
		(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
	]));
}

test_layouts!(insert_split_leaf, insert_split_leaf_internal);
fn insert_split_leaf_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0x01u8, 0x34], &[0x01u8, 0x34]).unwrap();
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(vec![
		(vec![0x01u8, 0x23], vec![0x01u8, 0x23]),
		(vec![0x01u8, 0x34], vec![0x01u8, 0x34]),
	]));
}

test_layouts!(insert_split_extenstion, insert_split_extenstion_internal);
fn insert_split_extenstion_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01, 0x23, 0x45], &[0x01]).unwrap();
	t.insert(&[0x01, 0xf3, 0x45], &[0x02]).unwrap();
	t.insert(&[0x01, 0xf3, 0xf5], &[0x03]).unwrap();
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(vec![
		(vec![0x01, 0x23, 0x45], vec![0x01]),
		(vec![0x01, 0xf3, 0x45], vec![0x02]),
		(vec![0x01, 0xf3, 0xf5], vec![0x03]),
	]));
}

test_layouts!(insert_big_value, insert_big_value_internal);
fn insert_big_value_internal<T: TrieLayout>() {
	let big_value0 = b"00000000000000000000000000000000";
	let big_value1 = b"11111111111111111111111111111111";

	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], big_value0).unwrap();
	t.insert(&[0x11u8, 0x23], big_value1).unwrap();
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(vec![
		(vec![0x01u8, 0x23], big_value0.to_vec()),
		(vec![0x11u8, 0x23], big_value1.to_vec())
	]));
}

test_layouts!(insert_duplicate_value, insert_duplicate_value_internal);
fn insert_duplicate_value_internal<T: TrieLayout>() {
	let big_value = b"00000000000000000000000000000000";

	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], big_value).unwrap();
	t.insert(&[0x11u8, 0x23], big_value).unwrap();
	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(vec![
		(vec![0x01u8, 0x23], big_value.to_vec()),
		(vec![0x11u8, 0x23], big_value.to_vec())
	]));
}

test_layouts!(test_at_empty, test_at_empty_internal);
fn test_at_empty_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	assert_eq!(t.get(&[0x5]).unwrap(), None);
}

test_layouts!(test_at_one, test_at_one_internal);
fn test_at_one_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), vec![0x1u8, 0x23]);
	t.commit();
	assert_eq!(t.get(&[0x1, 0x23]).unwrap().unwrap(), vec![0x1u8, 0x23]);
}

test_layouts!(test_at_three, test_at_three_internal);
fn test_at_three_internal<T: TrieLayout>() {
	let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut memdb, &mut root);
	t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	t.insert(&[0xf1u8, 0x23], &[0xf1u8, 0x23]).unwrap();
	t.insert(&[0x81u8, 0x23], &[0x81u8, 0x23]).unwrap();
	assert_eq!(t.get(&[0x01, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
	assert_eq!(t.get(&[0xf1, 0x23]).unwrap().unwrap(), vec![0xf1u8, 0x23]);
	assert_eq!(t.get(&[0x81, 0x23]).unwrap().unwrap(), vec![0x81u8, 0x23]);
	assert_eq!(t.get(&[0x82, 0x23]).unwrap(), None);
	t.commit();
	assert_eq!(t.get(&[0x01, 0x23]).unwrap().unwrap(), vec![0x01u8, 0x23]);
	assert_eq!(t.get(&[0xf1, 0x23]).unwrap().unwrap(), vec![0xf1u8, 0x23]);
	assert_eq!(t.get(&[0x81, 0x23]).unwrap().unwrap(), vec![0x81u8, 0x23]);
	assert_eq!(t.get(&[0x82, 0x23]).unwrap(), None);
}

test_layouts!(stress, stress_internal);
fn stress_internal<T: TrieLayout>() {
	let mut seed = Default::default();
	for _ in 0..50 {
		let x = StandardMap {
			alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
			min_key: 5,
			journal_key: 0,
			value_mode: ValueMode::Index,
			count: 4,
		}.make_with(&mut seed);

		let real = reference_trie_root::<T, _, _, _>(x.clone());
		let mut memdb = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		let mut memtrie = populate_trie::<T>(&mut memdb, &mut root, &x);
		let mut y = x.clone();
		y.sort_by(|ref a, ref b| a.0.cmp(&b.0));
		let mut memdb2 = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
		let mut root2 = Default::default();
		let mut memtrie_sorted = populate_trie::<T>(&mut memdb2, &mut root2, &y);
		if *memtrie.root() != real || *memtrie_sorted.root() != real {
			println!("TRIE MISMATCH");
			println!();
			println!("ORIGINAL... {:#x?}", memtrie.root());
			for i in &x {
				println!("{:#x?} -> {:#x?}", i.0, i.1);
			}
			println!("SORTED... {:#x?}", memtrie_sorted.root());
			for i in &y {
				println!("{:#x?} -> {:#x?}", i.0, i.1);
			}
		}
		assert_eq!(*memtrie.root(), real);
		assert_eq!(*memtrie_sorted.root(), real);
	}
}

test_layouts!(test_trie_existing, test_trie_existing_internal);
fn test_trie_existing_internal<T: TrieLayout>() {
	let mut db = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	{
		let mut t = TrieDBMut::<T>::new(&mut db, &mut root);
		t.insert(&[0x01u8, 0x23], &[0x01u8, 0x23]).unwrap();
	}

	{
		 let _ = TrieDBMut::<T>::from_existing(&mut db, &mut root);
	}
}

test_layouts!(insert_empty, insert_empty_internal);
fn insert_empty_internal<T: TrieLayout>() {
	let mut seed = Default::default();
	let x = StandardMap {
			alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
			min_key: 5,
			journal_key: 0,
			value_mode: ValueMode::Index,
			count: 4,
	}.make_with(&mut seed);

	let mut db = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut db, &mut root);
	for &(ref key, ref value) in &x {
		t.insert(key, value).unwrap();
	}

	assert_eq!(*t.root(), reference_trie_root::<T, _, _, _>(x.clone()));

	for &(ref key, _) in &x {
		t.insert(key, &[]).unwrap();
	}

	assert!(t.is_empty());
	let hashed_null_node = reference_hashed_null_node::<T>();
	assert_eq!(*t.root(), hashed_null_node);
}

test_layouts!(return_old_values, return_old_values_internal);
fn return_old_values_internal<T: TrieLayout>() {
	let mut seed = Default::default();
	let x = StandardMap {
			alphabet: Alphabet::Custom(b"@QWERTYUIOPASDFGHJKLZXCVBNM[/]^_".to_vec()),
			min_key: 5,
			journal_key: 0,
			value_mode: ValueMode::Index,
			count: 2,
	}.make_with(&mut seed);

	let mut db = MemoryDB::<T::Hash, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = TrieDBMut::<T>::new(&mut db, &mut root);
	for &(ref key, ref value) in &x {
		assert!(t.insert(key, value).unwrap().is_none());
		assert_eq!(t.insert(key, value).unwrap(), Some(value.clone()));
	}
	for (key, value) in x {
		assert_eq!(t.remove(&key).unwrap(), Some(value));
		assert!(t.remove(&key).unwrap().is_none());
	}
}

#[test]
fn insert_empty_allowed() {
	let mut db = MemoryDB::<RefHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	let mut t = reference_trie::RefTrieDBMutAllowEmpty::new(&mut db, &mut root);
	t.insert(b"test", &[]).unwrap();

	assert_eq!(*t.root(), reference_trie_root::<reference_trie::AllowEmptyLayout, _, _, _>(
		vec![(b"test".to_vec(), Vec::new())],
	));
	assert_eq!(t.get(b"test").unwrap(), Some(Vec::new()));
}

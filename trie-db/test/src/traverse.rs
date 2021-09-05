// Copyright 2017, 2021 Parity Technologies
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

//! Traverse tests.

use reference_trie::{RefTrieDBMutNoExt, RefTrieDBNoExt, InputAction,
trie_traverse_key_no_extension_build, NoExtensionLayout, batch_update,
unprefixed_detached_trie, prefixed_detached_trie,
};

use memory_db::{MemoryDB, PrefixedKey};
//	use memory_db::{MemoryDB, HashKey as PrefixedKey};
use keccak_hasher::KeccakHasher;
use trie_db::{DBValue, OwnedPrefix, TrieMut, NibbleSlice};
use hash_db::HashDB;
use crate::triedbmut::populate_trie_no_extension;

type H256 = <KeccakHasher as hash_db::Hasher>::Out;

fn memory_db_from_delta(
	delta: impl Iterator<Item = (OwnedPrefix, H256, Option<Vec<u8>>)>,
	mdb: &mut MemoryDB<KeccakHasher, PrefixedKey<KeccakHasher>, DBValue>,
	check_order: bool,
) {
	// Ordering logic is almost always correct between delet and create (delete first in case of
	// same location), there is one exception: deleting a node resulting to fusing a parent, then
	// the parent fusing can write at a prior index.
	// Therefore a `ProcessStack` that need ordering for delete will need a buffer.
	// Such buffer will be at maximum the size of the stack depth minus one or the number of child
	// in a branch (but since it is triggered by consecutive node fuse it should really be small).
	// Then we limit this test to insert here.
	let mut previous_prefix_insert = None;
	//let cp_prefix = |previous: &OwnedPrefix, next: &OwnedPrefix, prev_delete: bool, is_delet: bool| {
	let cp_prefix = |previous: &OwnedPrefix, next: &OwnedPrefix| {
		if check_order {
			println!("{:?} -> {:?}", previous, next);
			/*			if previous == next {
			// we can have two same value if it is deletion then creation
			assert!(prev_delete && !is_delet);
			return;
			}*/
			let prev_slice = NibbleSlice::new(previous.0.as_slice());
			let p_at = |i| {
				if i < prev_slice.len() {
					Some(prev_slice.at(i))
				} else if i == prev_slice.len() {
					previous.1
				} else {
					None
				}
			};

			let next_slice = NibbleSlice::new(next.0.as_slice());
			let n_at = |i| {
				if i < next_slice.len() {
					Some(next_slice.at(i))
				} else if i == next_slice.len() {
					next.1
				} else {
					None
				}
			};
			let mut i = 0;
			loop {
				match (p_at(i), n_at(i)) {
					(Some(p), Some(n)) => {
						if p < n {
							break;
						} else if p == n {
							i += 1;
						} else {
							panic!("Misordered results");
						}
					},
					(Some(_p), None) => {
						// moving upward is fine
						break;
					},
					(None, Some(_p)) => {
						// next is bellow first, that is not correct
						panic!("Misordered results");
					},
					(None, None) => {
						panic!("Two consecutive action at same node")
							//unreachable!("equality tested firsthand")
					},
				}
			}
		}
	};
	for (p, h, v) in delta {
		let is_delete = v.is_none();
		if !is_delete {
			previous_prefix_insert.as_ref().map(|prev| cp_prefix(prev, &p));
		}

		//println!("p{:?}, {:?}, {:?}", p, h, v);
		if let Some(v) = v {
			let prefix = (p.0.as_ref(), p.1);
			// damn elastic array in value looks costy
			mdb.emplace(h, prefix, v[..].into());
		} else {
			let prefix = (p.0.as_ref(), p.1);
			mdb.remove(&h, prefix);
		}
		if !is_delete {
			previous_prefix_insert = Some(p);
		}
	}
}

fn compare_with_triedbmut(
	x: &[(Vec<u8>, Vec<u8>)],
	v: &[(Vec<u8>, Option<Vec<u8>>)],
) {
	let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	populate_trie_no_extension(&mut db, &mut root, x).commit();
	{
		let t = RefTrieDBNoExt::new(&db, &root);
		println!("bef {:?}", t);
	}

	println!("AB {:?}",  db.clone().drain());
	let initial_root = root.clone();
	let mut initial_db = db.clone();
	// reference
	{
		let mut t = RefTrieDBMutNoExt::from_existing(&mut db, &mut root).unwrap();
		for i in 0..v.len() {
			let key: &[u8]= &v[i].0;
			if let Some(val) = v[i].1.as_ref() {
				t.insert(key, val.as_ref()).unwrap();
			} else {
				t.remove(key).unwrap();
			}
		}
	}
	println!("AA {:?}",  db.clone().drain());
	{
		let t = RefTrieDBNoExt::new(&db, &root);
		println!("aft {:?}", t);
	}


	let (calc_root, payload, _detached) = trie_traverse_key_no_extension_build(
		&mut initial_db,
		&initial_root,
		v.iter().map(|(a, b)| (a, b.as_ref())),
	);

	assert_eq!(calc_root, root);

	let mut batch_delta = initial_db;
	memory_db_from_delta(payload, &mut batch_delta, true);
	// test by checking both triedb only
	let t2 = RefTrieDBNoExt::new(&db, &root).unwrap();
	println!("{:?}", t2);
	let t2b = RefTrieDBNoExt::new(&batch_delta, &calc_root).unwrap();
	println!("{:?}", t2b);

	println!("{:?}", db.clone().drain());
	println!("{:?}", batch_delta.clone().drain());
	assert!(db == batch_delta);
}

fn compare_with_triedbmut_detach(
	x: &[(Vec<u8>, Vec<u8>)],
	d: &Vec<u8>,
) {
	let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
	let mut root = Default::default();
	populate_trie_no_extension(&mut db, &mut root, x).commit();
	{
		let t = RefTrieDBNoExt::new(&db, &root);
		println!("bef {:?}", t);
	}
	let initial_root = root.clone();
	let initial_db = db.clone();
	// reference
	{
		let mut t = RefTrieDBMutNoExt::from_existing(&mut db, &mut root).unwrap();
		for i in 0..x.len() {
			if x[i].0.starts_with(d) {
				let key: &[u8]= &x[i].0;
				t.remove(key).unwrap();
			}
		}
	}
	{
		let t = RefTrieDBNoExt::new(&db, &root);
		println!("aft {:?}", t);
	}
	let elements = Some(d.clone()).into_iter().map(|k| (k, InputAction::<Vec<u8>, _>::Detach));
	let (calc_root, payload, payload_detached, detached_root) = batch_update::<NoExtensionLayout, _, _, _, _>(
		&initial_db,
		&initial_root,
		elements,
	).unwrap();

	assert_eq!(calc_root, root);

	let mut batch_delta = initial_db.clone();
	memory_db_from_delta(payload.into_iter(), &mut batch_delta, true);
	memory_db_from_delta(payload_detached.into_iter(), &mut batch_delta, false);
	// test by checking both triedb only
	let t2 = RefTrieDBNoExt::new(&db, &root).unwrap();
	println!("{:?}", t2);
	let t2b = RefTrieDBNoExt::new(&batch_delta, &calc_root).unwrap();
	println!("{:?}", t2b);

	if let Some((_k, _, d_root)) = detached_root.iter().next() {
		unprefixed_detached_trie::<NoExtensionLayout>(
			&mut batch_delta,
			None,
			d_root.clone(),
			d.as_ref(),
		).unwrap();
		let t2b = RefTrieDBNoExt::new(&batch_delta, d_root).unwrap();
		println!("{:?}", t2b);
		prefixed_detached_trie::<NoExtensionLayout>(
			&mut batch_delta,
			None,
			d_root.clone(),
			d.as_ref(),
		).unwrap();
	}

	println!("{:?}", db.clone().drain());
	println!("{:?}", batch_delta.clone().drain());

	// attach back
	let elements = detached_root.into_iter().map(|(k, _prefix, root)| (k, InputAction::<Vec<u8>, _>::Attach(root)));
	let (calc_root, payload, payload_detached, _detached_root) = batch_update::<NoExtensionLayout, _, _, _, _>(
		&batch_delta,
		&calc_root,
		elements,
	).unwrap();
	// TODO this did not work previously for a valid reason: find it again and explain.
	// assert!(detached_root.is_empty());
	memory_db_from_delta(payload.into_iter(), &mut batch_delta, true);
	memory_db_from_delta(payload_detached.into_iter(), &mut batch_delta, false);
	// test by checking both triedb only
	let t2 = RefTrieDBNoExt::new(&initial_db, &initial_root).unwrap();
	println!("{:?}", t2);
	let t2b = RefTrieDBNoExt::new(&batch_delta, &calc_root).unwrap();
	println!("{:?}", t2b);
	assert!(calc_root == initial_root);

	println!("{:?}", initial_db.clone().drain());
	println!("{:?}", batch_delta.clone().drain());
	batch_delta.purge();
	assert!(initial_db == batch_delta);
}

#[test]
fn empty_node_null_key() {
	compare_with_triedbmut(
		&[],
		&[
		(vec![], Some(vec![0xffu8, 0x33])),
		],
	);
	compare_with_triedbmut_detach(&[], &vec![]);
}

#[test]
fn non_empty_node_null_key() {
	let db = &[
		(vec![0x0u8], vec![4, 32]),
	];
	compare_with_triedbmut(
		db,
		&[
		(vec![], Some(vec![0xffu8, 0x33])),
		],
	);
	compare_with_triedbmut_detach(db, &vec![]);
	compare_with_triedbmut_detach(&[
		(vec![0x01u8, 0x23], vec![4, 32]),
	], &vec![0x01u8]);
}

#[test]
fn empty_node_with_key() {
	compare_with_triedbmut(
		&[],
		&[
		(vec![0x04u8], Some(vec![0xffu8, 0x33])),
		],
	);
}

#[test]
fn simple_fuse() {
	compare_with_triedbmut(
		&[
		(vec![0x04u8], vec![4, 32]),
		(vec![0x04, 0x04], vec![4, 33]),
		(vec![0x04, 0x04, 0x04], vec![4, 35]),
		],
		&[
		(vec![0x04u8, 0x04], None),
		],
	);
}

#[test]
fn dummy1() {
	let db = &[
		(vec![0x04u8], vec![4, 32]),
	];
	compare_with_triedbmut(
		db,
		&[
		(vec![0x06u8], Some(vec![0xffu8, 0x33])),
		(vec![0x08u8], Some(vec![0xffu8, 0x33])),
		],
	);
	compare_with_triedbmut_detach(db, &vec![0x04u8]);
	compare_with_triedbmut_detach(db, &vec![0x04u8, 0x01]);
	compare_with_triedbmut_detach(db, &vec![]);
}

#[test]
fn two_recursive_mid_insert() {
	compare_with_triedbmut(
		&[
		(vec![0x0u8], vec![4, 32]),
		],
		&[
		(vec![0x04u8], Some(vec![0xffu8, 0x33])),
		(vec![0x20u8], Some(vec![0xffu8, 0x33])),
		],
	);
}

#[test]
fn dummy2() {
	let db = &[
		(vec![0x01u8, 0x01u8, 0x23], vec![0x01u8; 32]),
		(vec![0x01u8, 0x81u8, 0x23], vec![0x02u8; 32]),
		(vec![0x01u8, 0xf1u8, 0x23], vec![0x01u8, 0x24]),
	];
	compare_with_triedbmut(
		db,
		&[
		(vec![0x01u8, 0x01u8, 0x23], Some(vec![0xffu8; 32])),
		(vec![0x01u8, 0x81u8, 0x23], Some(vec![0xfeu8; 32])),
		(vec![0x01u8, 0x81u8, 0x23], None),
		],
	);
	compare_with_triedbmut_detach(db, &vec![]);
	compare_with_triedbmut_detach(db, &vec![0x02]);
	compare_with_triedbmut_detach(db, &vec![0x01u8]);
	compare_with_triedbmut_detach(db, &vec![0x01u8, 0x81]);
	compare_with_triedbmut_detach(db, &vec![0x01u8, 0x81, 0x23]);
}

#[test]
fn dummy2_20() {
	compare_with_triedbmut_detach(&[
		(vec![0], vec![0, 0]),
		(vec![1], vec![0, 0]),
		(vec![8], vec![1, 0]),
	], &vec![0]);
	/* Detach does fuse a branch, and
	 * then when attaching it will swap.
	 * compare_with_triedbmut_detach(&[
		(vec![0], vec![50, 0]),
		(vec![8], vec![0, 50]),
		(vec![50], vec![0, 42]),
	], &vec![0]);*/
}

#[test]
fn dummy2_23() {
	compare_with_triedbmut_detach(&[
		(vec![0], vec![3; 40]),
		(vec![1], vec![2; 40]),
		(vec![8], vec![1; 40]),
	], &vec![0]);
}

#[test]
fn dettach_middle() {
	let db = &[
		(vec![0x00u8, 0x01, 0x23], vec![0x01u8; 32]),
		(vec![0x00, 0x01, 0x81u8, 0x23], vec![0x02u8; 32]),
		(vec![0x00, 0x01, 0xf1u8, 0x23], vec![0x01u8, 0x24]),
	];
	compare_with_triedbmut_detach(db, &vec![0x00u8]);
	compare_with_triedbmut_detach(db, &vec![0x00u8, 0x01, 0x81]);
}

#[test]
fn delete_to_empty() {
	compare_with_triedbmut(
		&[
		(vec![1, 254u8], vec![4u8; 33]),
		],
		&[
		(vec![1, 254u8], None),
		],
	);
}

#[test]
fn fuse_root_node() {
	compare_with_triedbmut(
		&[
		(vec![2, 254u8], vec![4u8; 33]),
		(vec![1, 254u8], vec![4u8; 33]),
		],
		&[
		(vec![1, 254u8], None),
		],
	);
}

#[test]
fn dummy4() {
	compare_with_triedbmut(
		&[
		(vec![255u8, 251, 127, 255, 255], vec![255, 255]),
		(vec![255, 255, 127, 112, 255], vec![0, 4]),
		(vec![255, 127, 114, 253, 195], vec![1, 2]),
		],
		&[
		(vec![0u8], Some(vec![4; 251])),
		(vec![255, 251, 127, 255, 255], Some(vec![1, 2])),
		],
	);
}

#[test]
fn dummy6() {
	compare_with_triedbmut(
		&[
		(vec![0, 144, 64, 212, 141, 1, 0, 0, 255, 144, 64, 212, 141, 1, 0, 141, 206, 0], vec![255, 255]),
		(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0], vec![0, 4]),
		(vec![0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 208, 208, 208, 208, 208, 208, 208], vec![1, 2]),
		],
		&[
		(vec![0, 6, 8, 21, 1, 4, 0, 0, 0, 0, 0, 0, 0, 0, 0, 35, 199, 215], Some(vec![4, 251])),
		(vec![0, 144, 64, 212, 141, 1, 0, 0, 255, 144, 64, 212, 141, 1, 0, 141, 206, 0], None),
		(vec![141, 135, 207, 0, 63, 203, 216, 185, 162, 77, 154, 214, 210, 0, 0, 0, 0, 128], Some(vec![49, 251])),
		(vec![208, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 128, 6, 8, 21, 1, 4, 0], Some(vec![4, 21])),
		],
	);
}

#[test]
fn fuse_with_child_partial() {
	compare_with_triedbmut(
		&[
		(vec![212], vec![212, 212]),
		],
		&[
		(vec![58], Some(vec![63, 0])),
		(vec![63], None),
		(vec![212], None),
		],
	);
}

#[test]
fn dummy7() {
	compare_with_triedbmut(
		&[
		(vec![0], vec![0, 212]),
		(vec![8, 8], vec![0, 212]),
		],
		&[
		(vec![0], None),
		(vec![8, 0], Some(vec![63, 0])),
		(vec![128], None),
		],
	);
}

#[test]
fn dummy8() {
	compare_with_triedbmut(
		&[
		(vec![0], vec![0, 212]),
		(vec![8, 8], vec![0, 212]),
		],
		&[
		(vec![0], None),
		(vec![8, 0], Some(vec![63, 0])),
		(vec![128], Some(vec![63, 0])),
		],
	);
}

#[test]
fn dummy9() {
	compare_with_triedbmut(
		&[
		(vec![0], vec![0, 212]),
		(vec![1], vec![111, 22]),
		],
		&[
		(vec![0], None),
		(vec![5], Some(vec![63, 0])),
		(vec![14], None),
		(vec![64], Some(vec![63, 0])),
		],
	);
}

#[test]
fn dummy_51() {
	compare_with_triedbmut(
		&[
		(vec![9, 9, 9, 9, 9, 9, 9, 9, 9, 9], vec![1, 2]),
		],
		&[
		(vec![9, 1, 141, 44, 212, 0, 0, 51, 138, 32], Some(vec![4, 251])),
		(vec![128], Some(vec![49, 251])),
		],
	);
}

#[test]
fn emptied_then_insert() {
	compare_with_triedbmut(
		&[
		(vec![9, 9, 9, 9, 9, 9, 9, 9, 9, 9], vec![1, 2]),
		],
		&[
		(vec![9, 9, 9, 9, 9, 9, 9, 9, 9, 9], None),
		(vec![128], Some(vec![49, 251])),
		],
	);
}

#[test]
fn dummy5() {
	compare_with_triedbmut(
		&[
		(vec![9, 9, 9, 9, 9, 9, 9, 9, 9, 9], vec![1, 2]),
		],
		&[
		(vec![9, 1, 141, 44, 212, 0, 0, 51, 138, 32], Some(vec![4, 251])),
		(vec![9, 9, 9, 9, 9, 9, 9, 9, 9, 9], None),
		(vec![128], Some(vec![49, 251])),
		],
	);
}

#[test]
fn dummy_big() {
	compare_with_triedbmut(
		&[
		(vec![255, 255, 255, 255, 255, 255, 15, 0, 98, 34, 255, 0, 197, 193, 31, 5, 64, 0, 248, 197, 247, 231, 58, 0, 3, 214, 1, 192, 122, 39, 226, 0], vec![1, 2]),
		(vec![144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144], vec![1, 2]),

		],
		&[
		(vec![144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144], None),
		(vec![144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 144, 208], Some(vec![4; 32])),
		(vec![255, 255, 255, 255, 255, 255, 15, 0, 98, 34, 255, 0, 197, 193, 31, 5, 64, 0, 248, 197, 247, 231, 58, 0, 3, 214, 1, 192, 122, 39, 226, 0], None),
		],
	);
}

#[test]
fn single_latest_change_value_does_not_work() {
	compare_with_triedbmut(
		&[
		(vec![0, 0, 0, 0], vec![255;32]),
		(vec![0, 0, 0, 3], vec![5; 32]),
		(vec![0, 0, 6, 0], vec![6; 32]),
		(vec![0, 0, 0, 170], vec![1; 32]),
		(vec![0, 0, 73, 0], vec![2; 32]),
		(vec![0, 0, 0, 0], vec![3; 32]),
		(vec![0, 199, 141, 0], vec![4; 32]),
		],
		&[
		(vec![0, 0, 0, 0], Some(vec![0; 32])),
		(vec![0, 0, 199, 141], Some(vec![0; 32])),
		(vec![0, 199, 141, 0], None),
		(vec![12, 0, 128, 0, 0, 0, 0, 0, 0, 4, 64, 2, 4], Some(vec![0; 32])),
		(vec![91], None),
		],
	);
}

#[test]
fn chained_fuse() {
	compare_with_triedbmut(
		&[
		(vec![0u8], vec![1; 32]),
		(vec![0, 212], vec![2; 32]),
		(vec![0, 212, 96], vec![3; 32]),
		(vec![0, 212, 96, 88], vec![3; 32]),
		],
		&[
		(vec![0u8], None),
		(vec![0, 212], None),
		(vec![0, 212, 96], None),
		(vec![0, 212, 96, 88], Some(vec![3; 32])),
		],
	);
}

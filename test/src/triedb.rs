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

use hex_literal::hex;
use reference_trie::{
	test_layouts, test_layouts_substrate, HashedValueNoExtThreshold, PrefixedMemoryDB,
	TestTrieCache,
};
use trie_db::{
	encode_compact,
	memory_db::{HashKey, MemoryDB},
	node_db::{Hasher, EMPTY_PREFIX},
	CachedValue, DBValue, Lookup, NibbleSlice, RecordedForKey, Recorder, Trie, TrieCache,
	TrieDBBuilder, TrieDBMutBuilder, TrieLayout, TrieRecorder,
};

use crate::{TestCommit, TestDB};

type MemoryDBProof<T> =
	MemoryDB<<T as TrieLayout>::Hash, HashKey<<T as TrieLayout>::Hash>, DBValue>;

test_layouts!(iterator_works, iterator_works_internal);
fn iterator_works_internal<T: TrieLayout, DB: TestDB<T>>() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000010000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (x, y) in &pairs {
		t.insert(x, y).unwrap();
	}
	let commit = t.commit();
	let root = memdb.commit(commit);

	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();

	let iter = trie.iter().unwrap();
	let mut iter_pairs = Vec::new();
	for pair in iter {
		let (key, value) = pair.unwrap();
		iter_pairs.push((key, value.to_vec()));
	}

	assert_eq!(pairs, iter_pairs);
}

test_layouts!(iterator_seek_works, iterator_seek_works_internal);
fn iterator_seek_works_internal<T: TrieLayout, DB: TestDB<T>>() {
	let pairs = vec![
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec()),
		(hex!("0103000000000000000469").to_vec(), hex!("ffffffffff").to_vec()),
	];

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (x, y) in &pairs {
		t.insert(x, y).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();

	let mut iter = t.iter().unwrap();
	assert_eq!(
		iter.next().unwrap().unwrap(),
		(hex!("0103000000000000000464").to_vec(), hex!("fffffffffe").to_vec(),)
	);
	iter.seek(&hex!("00")[..]).unwrap();
	assert_eq!(
		pairs,
		iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>()
	);
	let mut iter = t.iter().unwrap();
	iter.seek(&hex!("0103000000000000000465")[..]).unwrap();
	assert_eq!(
		&pairs[1..],
		&iter.map(|x| x.unwrap()).map(|(k, v)| (k, v[..].to_vec())).collect::<Vec<_>>()[..]
	);
}

test_layouts!(double_ended_iterator, double_ended_iterator_internal);
fn double_ended_iterator_internal<T: TrieLayout, DB: TestDB<T>>() {
	let pairs = vec![
		(hex!("01").to_vec(), hex!("01").to_vec()),
		(hex!("02").to_vec(), hex!("02").to_vec()),
		(hex!("03").to_vec(), hex!("03").to_vec()),
		(hex!("10").to_vec(), hex!("10").to_vec()),
		(hex!("11").to_vec(), hex!("11").to_vec()),
	];

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (x, y) in &pairs {
		t.insert(x, y).unwrap();
	}
	let commit = t.commit();
	let root = memdb.commit(commit);

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();
	assert_eq!(pairs, t.iter().unwrap().map(|x| x.unwrap()).collect::<Vec<_>>());

	let mut iter = t.into_double_ended_iter().unwrap();

	for i in 0..pairs.len() {
		assert_eq!(iter.next().unwrap().unwrap(), pairs[i].clone());
	}
	assert!(iter.next().is_none());

	for i in (0..pairs.len()).rev() {
		assert_eq!(iter.next_back().unwrap().unwrap(), pairs[i].clone());
	}
	assert!(iter.next_back().is_none());
}

test_layouts!(iterator, iterator_internal);
fn iterator_internal<T: TrieLayout, DB: TestDB<T>>() {
	let d = vec![b"A".to_vec(), b"AA".to_vec(), b"AB".to_vec(), b"B".to_vec()];

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for x in &d {
		t.insert(x, x).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();
	assert_eq!(
		d.iter().map(|i| i.clone()).collect::<Vec<_>>(),
		t.iter().unwrap().map(|x| x.unwrap().0).collect::<Vec<_>>()
	);
	assert_eq!(d, t.iter().unwrap().map(|x| x.unwrap().1).collect::<Vec<_>>());
}

test_layouts!(iterator_seek, iterator_seek_internal);
fn iterator_seek_internal<T: TrieLayout, DB: TestDB<T>>() {
	let d = vec![b"A".to_vec(), b"AA".to_vec(), b"AB".to_vec(), b"AS".to_vec(), b"B".to_vec()];
	let vals = vec![vec![0; 32], vec![1; 32], vec![2; 32], vec![4; 32], vec![3; 32]];

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (k, val) in d.iter().zip(vals.iter()) {
		t.insert(k, val.as_slice()).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();
	let mut iter = t.iter().unwrap();
	assert_eq!(iter.next().unwrap().unwrap(), (b"A".to_vec(), vals[0].clone()));
	iter.seek(b"!").unwrap();
	assert_eq!(vals, iter.map(|x| x.unwrap().1).collect::<Vec<_>>());
	let mut iter = t.iter().unwrap();
	iter.seek(b"A").unwrap();
	assert_eq!(vals, &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AA").unwrap();
	assert_eq!(&vals[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed(&t, b"aaaaa").unwrap();
	assert_eq!(&vals[..0], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed(&t, b"A").unwrap();
	assert_eq!(&vals[..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AA").unwrap();
	assert_eq!(&vals[1..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AR").unwrap();
	assert_eq!(&vals[3..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AS").unwrap();
	assert_eq!(&vals[3..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"A", b"AB").unwrap();
	assert_eq!(&vals[2..4], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let iter = trie_db::TrieDBIterator::new_prefixed_then_seek(&t, b"", b"AB").unwrap();
	assert_eq!(&vals[2..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"A!").unwrap();
	assert_eq!(&vals[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AB").unwrap();
	assert_eq!(&vals[2..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"AB!").unwrap();
	assert_eq!(&vals[3..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"B").unwrap();
	assert_eq!(&vals[4..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	let mut iter = t.iter().unwrap();
	iter.seek(b"C").unwrap();
	assert_eq!(&vals[5..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
}

fn trie_from_hex_keys<T, DB: TestDB<T>>(
	keys: &[&str],
	callback: impl FnOnce(&mut trie_db::TrieDB<T>),
) where
	T: TrieLayout,
{
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (index, key) in keys.iter().enumerate() {
		t.insert(&array_bytes::hex2bytes(key).unwrap(), &[index as u8]).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	let mut t = TrieDBBuilder::<T>::new(&memdb, &root).build();
	callback(&mut t);
}

fn test_prefixed_then_seek<T: TrieLayout, DB: TestDB<T>>(
	keys: &[&str],
	prefix_key: &str,
	seek_key: &str,
	expected: &[&str],
) {
	let prefix_key = array_bytes::hex2bytes(prefix_key).unwrap();
	let seek_key = array_bytes::hex2bytes(seek_key).unwrap();

	trie_from_hex_keys::<T, DB>(keys, |trie| {
		let iter =
			trie_db::TrieDBIterator::new_prefixed_then_seek(&trie, &prefix_key, &seek_key).unwrap();
		let output: Vec<_> = iter.map(|x| array_bytes::bytes2hex("", x.unwrap().0)).collect();
		assert_eq!(output, expected);
	});
}

// This test reproduces an actual real-world issue: https://github.com/polkadot-js/apps/issues/9103
test_layouts_substrate!(iterator_prefixed_then_seek_real_world);
fn iterator_prefixed_then_seek_real_world<T: TrieLayout>() {
	let keys = &[
		"6cf4040bbce30824850f1a4823d8c65faeefaa25a5bae16a431719647c1d99da",
		"6cf4040bbce30824850f1a4823d8c65ff536928ca5ba50039bc2766a48ddbbab",
		"70f943199f1a2dde80afdaf3f447db834e7b9012096b41c4eb3aaf947f6ea429",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d007fc7effcb0c044a0c41fd8a77eb55d2133058a86d1f4d6f8e45612cd271eefd77f91caeaacfe011b8f41540e0a793b0fd51b245dae19382b45386570f2b545fab75e3277910f7324b55f47c29f9965e8298371404e50ac",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d0179c23cd593c770fde9fc7aa8f84b3e401e654b8986c67728844da0080ec9ee222b41a85708a471a511548302870b53f40813d8354b6d2969e1b7ca9e083ecf96f9647e004ecb41c7f26f0110f778bdb3d9da31bef323d9",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d024de296f88310247001277477f4ace4d0aa5685ea2928d518a807956e4806a656520d6520b8ac259f684aa0d91961d76f697716f04e6c997338d03560ab7d703829fe7b9d0e6d7eff8d8412fc428364c2f474a67b36586d",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d13dc5d83f2361c14d05933eb3182a92ac14665718569703baf1da25c7d571843b6489f03d8549c87bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d1786d20bbb4b91eb1f5765432d750bd0111a0807c8d04f05110ffaf73f4fa7b360422c13bc97efc3a2324d9fa8f954b424c0bcfce7236a2e8107dd31c2042a9860a964f8472fda49749dec3f146e81470b55aa0f3930d854",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d18c246484ec5335a40903e7cd05771be7c0b8459333f1ae2925c3669fc3e5accd0f38c4711a15544bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d1aca749033252ce75245528397430d14cb8e8c09248d81ee5de00b6ae93ee880b6d19a595e6dc106bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d1d6bceb91bc07973e7b3296f83af9f1c4300ce9198cc3b44c54dafddb58f4a43aee44a9bef1a2e9dbfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d203383772f45721232139e1a8863b0f2f8d480bdc15bcc1f2033cf467e137059558da743838f6b58bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d2197cc5c3eb3a6a67538e0dc3eaaf8c820d71310d377499c4a5d276381789e0a234475e69cddf709d207458083d6146d3a36fce7f1fe05b232702bf154096e5e3a8c378bdc237d7a27909acd663563917f0f70bb0e8e61a3",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d4f19c117f2ea36100f753c4885aa8d63b4d65a0dc32106f829f89eeabd52c37105c9bdb75f752469729fa3f0e7d907c1d949192c8e264a1a510c32abe3a05ed50be2262d5bfb981673ec80a07fd2ce28c7f27cd0043a788c",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d547d5aaa651bafa63d077560dfe823ac75665ebf1dcfd96a06e45499f03dda31282977706918d4821b8f41540e0a793b0fd51b245dae19382b45386570f2b545fab75e3277910f7324b55f47c29f9965e8298371404e50ac",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d6037207d54d69a082ea225ab4a412e4b87d6f5612053b07c405cf05ea25e482a4908c0713be2998abfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d63d0920de0c7315ebaed1d639d926961d28af89461c31eca890441e449147d23bb7c9d4fc42d7c16bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d7912c66be82a5972e5bc11c8d10551a296ba9aaff8ca6ab22a8cd1987974b87a97121c871f786d2e17e0a629acf01c38947f170b7e02a9ebb4ee60f83779acb99b71114c01a4f0a60694611a1502c399c77214ffa26e955b",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d7aa00f217f3a374a2f1ca0f388719f84099e8157a8a83c5ccf54eae1617f93933fa976baa629e6febfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d9e1c3c8ab41943cf377b1aa724d7f518a3cfc96a732bdc4658155d09ed2bfc31b5ccbc6d8646b59f1b8f41540e0a793b0fd51b245dae19382b45386570f2b545fab75e3277910f7324b55f47c29f9965e8298371404e50ac",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d9fb8d6d95d5214a3305a4fa07e344eb99fad4be3565d646c8ac5af85514d9c96702c9c207be234958dbdb9185f467d2be3b84e8b2f529f7ec3844b378a889afd6bd31a9b5ed22ffee2019ad82c6692f1736dd41c8bb85726",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8d9fb8d6d95d5214a3305a4fa07e344eb99fad4be3565d646c8ac5af85514d9c96702c9c207be23495ec1caa509591a36a8403684384ce40838c9bd7fc49d933a10d3b26e979273e2f17ebf0bf41cd90e4287e126a59d5a243",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8da7fc066aae2ffe03b36e9a72f9a39cb2befac7e47f320309f31f1c1676288d9596045807304b3d79bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8daf3c377b0fddf7c7ad6d390fab0ab45ac16c21645be880af5cab2fbbeb04820401a4c9f766c17bef9fc14a2e16ade86fe26ee81d4497dc6aab81cc5f5bb0458d6149a763ecb09aefec06950dd61db1ba025401d2a04e3b9d",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8daf3c377b0fddf7c7ad6d390fab0ab45ac16c21645be880af5cab2fbbeb04820401a4c9f766c17befbfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8db60505ba8b77ef03ed805436d3242f26dc828084b12aaf4bcb96af468816a182b5360149398aad6b1dafe949b0918138ceef924f6393d1818a04842301294604972da17b24b31b155e4409a01273733b8d21a156c2e7eb71",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8dbd27136a6e028656073cc840bfabb48fe935880c4c4c990ee98458b2fed308e9765f7f7f717dd3b2862fa5361d3b55afa6040e582687403c852b2d065b24f253276cc581226991f8e1818a78fc64c39da7f0b383c6726e0f",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8dca40d91320edd326500f9e8b5a0b23a8bdf21549f98f0e014f66b6a18bdd78e337a6c05d670c80c88a55d4c7bb6fbae546e2d03ac9ab16e85fe11dad6adfd6a20618905477b831d7d48ca32d0bfd2bdc8dbeba26ffe2c710",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8dd27478512243ed62c1c1f7066021798a464d4cf9099546d5d9907b3369f1b9d7a5aa5d60ca845619bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8de6da5659cbbe1489abbe99c4d3a474f4d1e78edb55a9be68d8f52c6fe730388a298e6f6325db3da7bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8de6da5659cbbe1489abbe99c4d3a474f4d1e78edb55a9be68d8f52c6fe730388a298e6f6325db3da7e94ca3e8c297d82f71e232a2892992d1f6480475fb797ce64e58f773d8fafd9fbcee4bdf4b14f2a71b6d3a428cf9f24b",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8decdd1760c61ff7234f2876dbe817af803170233320d778b92043b2359e3de6d16c9e5359f6302da31c84d6f551ad2a831263ef956f0cdb3b4810cefcb2d0b57bcce7b82007016ae4fe752c31d1a01b589a7966cea03ec65c",
		"7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8df9981ee6b69eb7af2153af34f39ffc06e2daa5272c99798c8849091284dc8905f2a76b65754c2089bfa5709836ba729443c319659e83ad5ee133e6f11af51d883e56216e9e1bbb1e2920c7c6120cbb55cd469b1f95b61601",
		"7474449cca95dc5d0c00e71735a6d17d4e7b9012096b41c4eb3aaf947f6ea429",
		"89d139e01a5eb2256f222e5fc5dbe6b33c9c1284130706f5aea0c8b3d4c54d89",
		"89d139e01a5eb2256f222e5fc5dbe6b36254e9d55588784fa2a62b726696e2b1"
	];

	let target_key = "7474449cca95dc5d0c00e71735a6d17d3cd15a3fd6e04e47bee3922dbfa92c8da7dad55cf08ffe8194efa962146801b0503092b1ed6a3fa6aee9107334aefd7965bbe568c3d24c6d";
	test_prefixed_then_seek::<T, PrefixedMemoryDB<T>>(keys, target_key, target_key, &[]);
}

// This is the real-word test, but simplified.
test_layouts_substrate!(iterator_prefixed_then_seek_simple);
fn iterator_prefixed_then_seek_simple<T: TrieLayout>() {
	test_prefixed_then_seek::<T, PrefixedMemoryDB<T>>(&["0100"], "00", "00", &[]);
}

// These are just tests that the fuzzer barfed out while working on the fix for the real-world
// issue.
test_layouts_substrate!(iterator_prefixed_then_seek_testcase_1);
fn iterator_prefixed_then_seek_testcase_1<T: TrieLayout>() {
	test_prefixed_then_seek::<T, PrefixedMemoryDB<T>>(&["00"], "00", "", &["00"])
}

test_layouts_substrate!(iterator_prefixed_then_seek_testcase_2);
fn iterator_prefixed_then_seek_testcase_2<T: TrieLayout>() {
	test_prefixed_then_seek::<T, PrefixedMemoryDB<T>>(&["00", "0003"], "00", "", &["00", "0003"])
}

test_layouts_substrate!(iterator_prefixed_then_seek_testcase_3);
fn iterator_prefixed_then_seek_testcase_3<T: TrieLayout>() {
	test_prefixed_then_seek::<T, PrefixedMemoryDB<T>>(&["20"], "20", "0700", &["20"])
}

test_layouts_substrate!(iterator_prefixed_then_seek_testcase_4);
fn iterator_prefixed_then_seek_testcase_4<T: TrieLayout>() {
	let keys = &["1701", "ffffffffffffffffffffffdfffffffffffffffffffffffffffffffffffffffff"];
	test_prefixed_then_seek::<T, PrefixedMemoryDB<T>>(
		keys,
		"1701",
		"ffff27272727274949494949ce494949494949494949491768687b737373732b",
		&[],
	)
}

test_layouts_substrate!(iterator_prefixed_then_seek_testcase_5);
fn iterator_prefixed_then_seek_testcase_5<T: TrieLayout>() {
	test_prefixed_then_seek::<T, PrefixedMemoryDB<T>>(&["20"], "20", "20", &["20"])
}

test_layouts!(get_length_with_extension, get_length_with_extension_internal);
fn get_length_with_extension_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(b"A", b"ABC").unwrap();
	t.insert(b"B", b"ABCBAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
	let root = t.commit().commit_to(&mut memdb);

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();
	assert_eq!(t.get_with(b"A", |x: &[u8]| x.len()).unwrap(), Some(3));
	assert_eq!(t.get_with(b"B", |x: &[u8]| x.len()).unwrap(), Some(32));
	assert_eq!(t.get_with(b"C", |x: &[u8]| x.len()).unwrap(), None);
}

test_layouts!(debug_output_supports_pretty_print, debug_output_supports_pretty_print_internal);
fn debug_output_supports_pretty_print_internal<T: TrieLayout, DB: TestDB<T>>()
where
	T::Location: std::fmt::Debug,
{
	let d = vec![b"A".to_vec(), b"AA".to_vec(), b"AB".to_vec(), b"B".to_vec()];

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for x in &d {
		t.insert(x, x).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();

	if T::USE_EXTENSION {
		assert_eq!(
			format!("{:#?}", t),
			"TrieDB {
    root: Node::Extension {
        slice: 4,
        item: Node::Branch {
            nodes: [
                Node::Branch {
                    index: 1,
                    nodes: [
                        Node::Branch {
                            index: 4,
                            nodes: [
                                Node::Leaf {
                                    index: 1,
                                    slice: ,
                                    value: Inline(
                                        [
                                            65,
                                            65,
                                        ],
                                    ),
                                },
                                Node::Leaf {
                                    index: 2,
                                    slice: ,
                                    value: Inline(
                                        [
                                            65,
                                            66,
                                        ],
                                    ),
                                },
                            ],
                            value: None,
                        },
                    ],
                    value: Some(
                        Inline(
                            [
                                65,
                            ],
                        ),
                    ),
                },
                Node::Leaf {
                    index: 2,
                    slice: ,
                    value: Inline(
                        [
                            66,
                        ],
                    ),
                },
            ],
            value: None,
        },
    },
}"
		)
	} else {
		// untested without extension
	};
}

test_layouts!(
	test_lookup_with_corrupt_data_returns_decoder_error,
	test_lookup_with_corrupt_data_returns_decoder_error_internal
);
fn test_lookup_with_corrupt_data_returns_decoder_error_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	t.insert(b"A", b"ABC").unwrap();
	t.insert(b"B", b"ABCBA").unwrap();
	let root = t.commit().commit_to(&mut memdb);

	let t = TrieDBBuilder::<T>::new(&memdb, &root).build();

	// query for an invalid data type to trigger an error
	let q = |x: &[u8]| x.len() < 64;
	let lookup = Lookup::<T, _> {
		db: t.db(),
		query: q,
		hash: root,
		location: Default::default(),
		cache: None,
		recorder: None,
	};
	let query_result = lookup.look_up(&b"A"[..], NibbleSlice::new(b"A"));
	assert_eq!(query_result.unwrap().unwrap(), true);
}

test_layouts!(test_recorder, test_recorder_internal);
fn test_recorder_internal<T: TrieLayout, DB: TestDB<T>>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = memdb.commit(t.commit());

	let mut recorder = Recorder::<T>::new();
	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).with_recorder(&mut recorder).build();

		for (key, value) in key_value.iter().take(3) {
			assert_eq!(*value, trie.get(key).unwrap().unwrap());
		}
	}

	let mut partial_db = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	{
		let trie = TrieDBBuilder::<T>::new(&partial_db, &root).build();

		for (key, value) in key_value.iter().take(3) {
			assert_eq!(*value, trie.get(key).unwrap().unwrap());
		}
		assert!(trie.get(&key_value[3].0).is_err());
	}
}

test_layouts!(test_recorder_with_cache, test_recorder_with_cache_internal);
fn test_recorder_with_cache_internal<T: TrieLayout, DB: TestDB<T>>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut memdb = DB::default();

	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	let mut cache = TestTrieCache::<T>::default();

	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).with_cache(&mut cache).build();

		// Only read one entry.
		assert_eq!(key_value[1].1, trie.get(&key_value[1].0).unwrap().unwrap());
	}

	// Root should now be cached.
	assert!(cache.get_node(&root, Default::default()).is_some());
	// Also the data should be cached.
	let value = cache.lookup_value_for_key(&key_value[1].0).unwrap();

	assert_eq!(key_value[1].1, value.data().unwrap().unwrap().deref());
	assert_eq!(T::Hash::hash(&key_value[1].1), value.hash().unwrap());

	// And the rest not
	assert!(cache.lookup_value_for_key(&key_value[0].0).is_none());
	assert!(cache.lookup_value_for_key(&key_value[2].0).is_none());
	assert!(cache.lookup_value_for_key(&key_value[3].0).is_none());

	// Run this multiple times to ensure that the cache is not interfering the recording.
	for i in 0..6 {
		eprintln!("Round: {}", i);

		// Ensure that it works with a filled value/node cache and without it.
		if i < 2 {
			cache.clear_value_cache();
		} else if i < 4 {
			cache.clear_node_cache();
		}

		let mut recorder = Recorder::<T>::new();
		{
			let trie = TrieDBBuilder::<T>::new(&memdb, &root)
				.with_cache(&mut cache)
				.with_recorder(&mut recorder)
				.build();

			for (key, value) in key_value.iter().take(2) {
				assert_eq!(*value, trie.get(key).unwrap().unwrap());
			}

			assert_eq!(
				T::Hash::hash(&key_value[2].1),
				trie.get_hash(&key_value[2].0).unwrap().unwrap()
			);
			assert_eq!(key_value[2].1, trie.get(&key_value[2].0).unwrap().unwrap());
		}

		let mut partial_db = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
		for record in recorder.drain() {
			partial_db.insert(EMPTY_PREFIX, &record.data);
		}

		{
			let trie = TrieDBBuilder::<T>::new(&partial_db, &root).build();

			for (key, value) in key_value.iter().take(3) {
				assert_eq!(*value, trie.get(key).unwrap().unwrap());
			}

			assert!(trie.get(&key_value[3].0).is_err());
		}
	}
}

test_layouts!(test_recorder_with_cache_get_hash, test_recorder_with_cache_get_hash_internal);
fn test_recorder_with_cache_get_hash_internal<T: TrieLayout, DB: TestDB<T>>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
	];

	let mut memdb = DB::default();

	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	let mut cache = TestTrieCache::<T>::default();

	{
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).with_cache(&mut cache).build();

		// Only read one entry.
		assert_eq!(
			T::Hash::hash(&key_value[1].1),
			trie.get_hash(&key_value[1].0).unwrap().unwrap()
		);
	}

	// Root should now be cached.
	assert!(cache.get_node(&root, Default::default()).is_some());
	// Also the data should be cached.

	if T::MAX_INLINE_VALUE.map_or(true, |l| l as usize > key_value[1].1.len()) {
		assert!(matches!(
			cache.lookup_value_for_key(&key_value[1].0).unwrap(),
			CachedValue::Existing { hash, .. } if *hash == T::Hash::hash(&key_value[1].1)
		));
	} else {
		assert!(matches!(
			cache.lookup_value_for_key(&key_value[1].0).unwrap(),
			CachedValue::ExistingHash(hash, _) if *hash == T::Hash::hash(&key_value[1].1)
		));
	}

	// Run this multiple times to ensure that the cache is not interfering the recording.
	for i in 0..6 {
		// Ensure that it works with a filled value/node cache and without it.
		if i < 2 {
			cache.clear_value_cache();
		} else if i < 4 {
			cache.clear_node_cache();
		}

		let mut recorder = Recorder::<T>::new();
		{
			let trie = TrieDBBuilder::<T>::new(&memdb, &root)
				.with_cache(&mut cache)
				.with_recorder(&mut recorder)
				.build();

			assert_eq!(
				T::Hash::hash(&key_value[2].1),
				trie.get_hash(&key_value[2].0).unwrap().unwrap()
			);
			assert_eq!(
				T::Hash::hash(&key_value[1].1),
				trie.get_hash(&key_value[1].0).unwrap().unwrap()
			);
		}

		let mut partial_db = MemoryDB::<T::Hash, HashKey<_>, DBValue>::default();
		for record in recorder.drain() {
			partial_db.insert(EMPTY_PREFIX, &record.data);
		}

		{
			let trie = TrieDBBuilder::<T>::new(&partial_db, &root).build();

			assert_eq!(
				T::Hash::hash(&key_value[2].1),
				trie.get_hash(&key_value[2].0).unwrap().unwrap()
			);
			assert_eq!(
				T::Hash::hash(&key_value[1].1),
				trie.get_hash(&key_value[1].0).unwrap().unwrap()
			);

			// Check if the values are part of the proof or not, based on the layout.
			if T::MAX_INLINE_VALUE.map_or(true, |l| l as usize > key_value[2].1.len()) {
				assert_eq!(key_value[2].1, trie.get(&key_value[2].0).unwrap().unwrap());
			} else {
				assert!(trie.get(&key_value[2].0).is_err());
			}

			if T::MAX_INLINE_VALUE.map_or(true, |l| l as usize > key_value[1].1.len()) {
				assert_eq!(key_value[1].1, trie.get(&key_value[1].0).unwrap().unwrap());
			} else {
				assert!(trie.get(&key_value[1].0).is_err());
			}
		}
	}
}

test_layouts!(test_merkle_value, test_merkle_value_internal);
fn test_merkle_value_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();

	// Data set.
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AAAA".to_vec(), vec![3; 64]),
		(b"AAB".to_vec(), vec![4; 64]),
		(b"AABBBB".to_vec(), vec![4; 1]),
		(b"AB".to_vec(), vec![5; 1]),
		(b"B".to_vec(), vec![6; 1]),
	];
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = memdb.commit(t.commit());

	// Ensure we can fetch the merkle values for all present keys.
	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();
	for (key, _) in &key_value {
		trie.lookup_first_descendant(key).unwrap().unwrap();
	}

	// Key is not present and has no descedant, but shares a prefix.
	let hash = trie.lookup_first_descendant(b"AAAAX").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"AABX").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"AABC").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"ABX").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"AABBBBX").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"BX").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"AC").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"BC").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"AAAAX").unwrap();
	assert!(hash.is_none());
	// Key shares the first nibble with b"A".
	let hash = trie.lookup_first_descendant(b"C").unwrap();
	assert!(hash.is_none());

	// Key not present, but has a descendent.
	let hash = trie.lookup_first_descendant(b"AAA").unwrap().unwrap();
	let expected = trie.lookup_first_descendant(b"AAAA").unwrap().unwrap();
	assert_eq!(hash, expected);
	let hash = trie.lookup_first_descendant(b"AABB").unwrap().unwrap();
	let expected = trie.lookup_first_descendant(b"AABBBB").unwrap().unwrap();
	assert_eq!(hash, expected);
	let hash = trie.lookup_first_descendant(b"AABBB").unwrap().unwrap();
	let expected = trie.lookup_first_descendant(b"AABBBB").unwrap().unwrap();
	assert_eq!(hash, expected);

	// Prefix AABB in between AAB and AABBBB, but has different ending char.
	let hash = trie.lookup_first_descendant(b"AABBX").unwrap();
	assert!(hash.is_none());
}

test_layouts!(test_merkle_value_single_key, test_merkle_value_single_key_internal);
fn test_merkle_value_single_key_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();

	// Data set.
	let key_value = vec![(b"AAA".to_vec(), vec![1; 64])];
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = memdb.commit(t.commit());

	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();

	let hash = trie.lookup_first_descendant(b"AA").unwrap().unwrap();
	let expected = trie.lookup_first_descendant(b"AAA").unwrap().unwrap();
	assert_eq!(hash, expected);

	// Trie does not contain AAC or AAAA.
	let hash = trie.lookup_first_descendant(b"AAC").unwrap();
	assert!(hash.is_none());
	let hash = trie.lookup_first_descendant(b"AAAA").unwrap();
	assert!(hash.is_none());
}

test_layouts!(test_merkle_value_branches, test_merkle_value_branches_internal);
fn test_merkle_value_branches_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();

	// Data set.
	let key_value = vec![(b"AAAA".to_vec(), vec![1; 64]), (b"AABA".to_vec(), vec![2; 64])];
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = memdb.commit(t.commit());

	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();

	// The hash is returned from the branch node.
	let hash = trie.lookup_first_descendant(b"A").unwrap().unwrap();
	let aaaa_hash = trie.lookup_first_descendant(b"AAAA").unwrap().unwrap();
	let aaba_hash = trie.lookup_first_descendant(b"AABA").unwrap().unwrap();
	// Ensure the hash is not from any leaf.
	assert_ne!(hash, aaaa_hash);
	assert_ne!(hash, aaba_hash);
}

test_layouts!(test_merkle_value_empty_trie, test_merkle_value_empty_trie_internal);
fn test_merkle_value_empty_trie_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();

	// Valid state root.
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	t.insert(&[], &[]).unwrap();
	let root = memdb.commit(t.commit());

	// Data set is empty.
	let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();

	let hash = trie.lookup_first_descendant(b"").unwrap();
	assert!(hash.is_none());

	let hash = trie.lookup_first_descendant(b"A").unwrap();
	assert!(hash.is_none());

	let hash = trie.lookup_first_descendant(b"AA").unwrap();
	assert!(hash.is_none());

	let hash = trie.lookup_first_descendant(b"AAA").unwrap();
	assert!(hash.is_none());

	let hash = trie.lookup_first_descendant(b"AAAA").unwrap();
	assert!(hash.is_none());
}

test_layouts!(test_merkle_value_modification, test_merkle_value_modification_internal);
fn test_merkle_value_modification_internal<T: TrieLayout, DB: TestDB<T>>() {
	let mut memdb = DB::default();

	let key_value = vec![(b"AAAA".to_vec(), vec![1; 64]), (b"AABA".to_vec(), vec![2; 64])];
	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = memdb.commit(t.commit());

	let (a_hash_lhs, aaaa_hash_lhs, aaba_hash_lhs) = {
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();

		// The hash is returned from the branch node.
		let hash = trie.lookup_first_descendant(b"A").unwrap().unwrap();
		let aaaa_hash = trie.lookup_first_descendant(b"AAAA").unwrap().unwrap();
		let aaba_hash = trie.lookup_first_descendant(b"AABA").unwrap().unwrap();

		// Ensure the hash is not from any leaf.
		assert_ne!(hash, aaaa_hash);
		assert_ne!(hash, aaba_hash);

		(hash, aaaa_hash, aaba_hash)
	};

	// Modify AABA and expect AAAA to return the same merkle value.
	let mut t = TrieDBMutBuilder::<T>::from_existing(&memdb, root).build();
	t.insert(b"AABA", &vec![3; 64]).unwrap();
	let root = memdb.commit(t.commit());

	let (a_hash_rhs, aaaa_hash_rhs, aaba_hash_rhs) = {
		let trie = TrieDBBuilder::<T>::new(&memdb, &root).build();

		// The hash is returned from the branch node.
		let hash = trie.lookup_first_descendant(b"A").unwrap().unwrap();
		let aaaa_hash = trie.lookup_first_descendant(b"AAAA").unwrap().unwrap();
		let aaba_hash = trie.lookup_first_descendant(b"AABA").unwrap().unwrap();

		// Ensure the hash is not from any leaf.
		assert_ne!(hash, aaaa_hash);
		assert_ne!(hash, aaba_hash);

		(hash, aaaa_hash, aaba_hash)
	};

	// AAAA was not modified.
	assert_eq!(aaaa_hash_lhs, aaaa_hash_rhs);
	// Changes to AABA must propagate to the root.
	assert_ne!(aaba_hash_lhs, aaba_hash_rhs);
	assert_ne!(a_hash_lhs, a_hash_rhs);
}

test_layouts!(iterator_seek_with_recorder, iterator_seek_with_recorder_internal);
fn iterator_seek_with_recorder_internal<T: TrieLayout, DB: TestDB<T>>() {
	let d = vec![b"A".to_vec(), b"AA".to_vec(), b"AB".to_vec(), b"B".to_vec()];
	let vals = vec![vec![0; 64], vec![1; 64], vec![2; 64], vec![3; 64]];

	let mut memdb = DB::default();
	let mut t = TrieDBMutBuilder::<T>::new(&mut memdb).build();
	for (k, val) in d.iter().zip(vals.iter()) {
		t.insert(k, val.as_slice()).unwrap();
	}
	let root = t.commit().commit_to(&mut memdb);

	let mut recorder = Recorder::<T>::new();
	{
		let t = TrieDBBuilder::<T>::new(&memdb, &root).with_recorder(&mut recorder).build();
		let mut iter = t.iter().unwrap();
		iter.seek(b"AA").unwrap();
		assert_eq!(&vals[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	}

	let mut partial_db = MemoryDBProof::<T>::default();
	for record in recorder.drain() {
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	// Replay with from the proof.
	{
		let trie = TrieDBBuilder::<T>::new(&partial_db, &root).build();

		let mut iter = trie.iter().unwrap();
		iter.seek(b"AA").unwrap();
		assert_eq!(&vals[1..], &iter.map(|x| x.unwrap().1).collect::<Vec<_>>()[..]);
	}
}

test_layouts!(test_cache, test_cache_internal);
fn test_cache_internal<T: TrieLayout, DB: TestDB<T>>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
		(b"BC".to_vec(), vec![4; 64]),
	];

	let mut memdb = DB::default();
	let mut cache = TestTrieCache::<T>::default();

	let changeset = {
		let mut t = TrieDBMutBuilder::<T>::new(&memdb).with_cache(&mut cache).build();
		for (key, value) in &key_value {
			t.insert(key, value).unwrap();
		}
		t.commit()
	};
	let root = memdb.commit(changeset);
	let t = TrieDBBuilder::<T>::new(&memdb, &root).with_cache(&mut cache).build();
	for (key, _) in &key_value {
		t.get(key).unwrap();
	}

	// Ensure that when we cache the same value multiple times under different keys,
	// the first cached key is still working.
	assert_eq!(
		cache.lookup_value_for_key(&b"B"[..]).unwrap().data().flatten().unwrap(),
		vec![4u8; 64]
	);
	assert_eq!(
		cache.lookup_value_for_key(&b"BC"[..]).unwrap().data().flatten().unwrap(),
		vec![4u8; 64]
	);

	// Ensure that we don't insert the same node multiple times, which would result in invalidating
	// cached values.
	let cached_value = cache.lookup_value_for_key(&b"AB"[..]).unwrap().clone();
	assert_eq!(cached_value.data().flatten().unwrap(), vec![3u8; 4]);

	let mut t = TrieDBMutBuilder::<T>::new(&memdb).with_cache(&mut cache).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = memdb.commit(t.commit());

	assert_eq!(
		cache.lookup_value_for_key(&b"AB"[..]).unwrap().data().flatten().unwrap(),
		vec![3u8; 4]
	);
	assert_eq!(cached_value.data().flatten().unwrap(), vec![3u8; 4]);

	// Clear all nodes and ensure that the value cache works flawlessly.
	cache.clear_node_cache();

	{
		let t = TrieDBBuilder::<T>::new(&memdb, &root).with_cache(&mut cache).build();
		for (key, value) in &key_value {
			assert_eq!(*value, t.get(key).unwrap().unwrap());
		}
	}

	// Ensure `get_hash` is also working properly
	cache.clear_node_cache();

	{
		let t = TrieDBBuilder::<T>::new(&mut memdb, &root).with_cache(&mut cache).build();
		for (key, value) in &key_value {
			assert_eq!(T::Hash::hash(value), t.get_hash(key).unwrap().unwrap());
		}
	}
}

#[test]
fn test_record_value() {
	type L = HashedValueNoExtThreshold<33, ()>;
	// one root branch and two leaf, one with inline value, the other with node value.
	let key_value = vec![(b"A".to_vec(), vec![1; 32]), (b"B".to_vec(), vec![1; 33])];

	// Add some initial data to the trie
	let mut memdb = PrefixedMemoryDB::<L>::default();
	let mut t = TrieDBMutBuilder::<L>::new(&memdb).build();
	for (key, value) in key_value.iter() {
		t.insert(key, value).unwrap();
	}
	let root = t.commit().apply_to(&mut memdb);

	// Value access would record a two nodes (branch and leaf with value 32 len inline).
	let mut recorder = Recorder::<L>::new();
	let overlay = memdb.clone();
	let new_root = root;
	{
		let trie = TrieDBBuilder::<L>::new(&overlay, &new_root)
			.with_recorder(&mut recorder)
			.build();

		trie.get(key_value[0].0.as_slice()).unwrap();
	}

	let mut partial_db = MemoryDBProof::<L>::default();
	let mut count = 0;
	for record in recorder.drain() {
		count += 1;
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	assert_eq!(count, 2);

	let compact_proof = {
		let trie = <TrieDBBuilder<L>>::new(&partial_db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};
	assert_eq!(compact_proof.len(), 2);
	// two child branch with only one child accessed
	assert_eq!(compact_proof[0].len(), 38);
	// leaf node with inline 32 byte value
	assert_eq!(compact_proof[1].len(), 34);

	// Value access on node returns three items: a branch a leaf and a value node
	let mut recorder = Recorder::<L>::new();
	let overlay = memdb.clone();
	let new_root = root;
	{
		let trie = TrieDBBuilder::<L>::new(&overlay, &new_root)
			.with_recorder(&mut recorder)
			.build();

		trie.get(key_value[1].0.as_slice()).unwrap();
	}

	let mut partial_db = MemoryDBProof::<L>::default();
	let mut count = 0;
	for record in recorder.drain() {
		count += 1;
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	assert_eq!(count, 3);

	let compact_proof = {
		let trie = <TrieDBBuilder<L>>::new(&partial_db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};
	assert_eq!(compact_proof.len(), 3);
	// two child branch with only one child accessed
	assert_eq!(compact_proof[0].len(), 38);
	// leaf with ommited hash value and escape header
	assert_eq!(compact_proof[1].len(), 3);
	// value node 33 bytes
	assert_eq!(compact_proof[2].len(), 33);

	// Hash access would record two node (branch and leaf with value 32 len inline).
	let mut recorder = Recorder::<L>::new();
	let overlay = memdb.clone();
	let new_root = root;
	{
		let trie = TrieDBBuilder::<L>::new(&overlay, &new_root)
			.with_recorder(&mut recorder)
			.build();

		trie.get_hash(key_value[0].0.as_slice()).unwrap();
	}

	let mut partial_db = MemoryDBProof::<L>::default();
	let mut count = 0;
	for record in recorder.drain() {
		count += 1;
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	assert_eq!(count, 2);

	let compact_proof = {
		let trie = <TrieDBBuilder<L>>::new(&partial_db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};
	assert_eq!(compact_proof.len(), 2);
	// two child branch with only one child accessed
	assert_eq!(compact_proof[0].len(), 38);
	// leaf node with inline 32 byte value
	assert_eq!(compact_proof[1].len(), 34);

	// Hash access would record two node (branch and leaf with value 32 len inline).
	let mut recorder = Recorder::<L>::new();
	let overlay = memdb.clone();
	let new_root = root;
	{
		let trie = TrieDBBuilder::<L>::new(&overlay, &new_root)
			.with_recorder(&mut recorder)
			.build();

		trie.get_hash(key_value[1].0.as_slice()).unwrap();
	}

	let mut partial_db = MemoryDBProof::<L>::default();
	let mut count = 0;
	for record in recorder.drain() {
		count += 1;
		partial_db.insert(EMPTY_PREFIX, &record.data);
	}

	assert_eq!(count, 2);

	let compact_proof = {
		let trie = <TrieDBBuilder<L>>::new(&partial_db, &root).build();
		encode_compact::<L>(&trie).unwrap()
	};
	assert_eq!(compact_proof.len(), 2);
	// two child branch with only one child accessed
	assert_eq!(compact_proof[0].len(), 38);
	// leaf with value hash only.
	assert_eq!(compact_proof[1].len(), 33);
}

test_layouts!(test_trie_nodes_recorded, test_trie_nodes_recorded_internal);
fn test_trie_nodes_recorded_internal<T: TrieLayout, DB: TestDB<T>>() {
	let key_value = vec![
		(b"A".to_vec(), vec![1; 64]),
		(b"AA".to_vec(), vec![2; 64]),
		(b"AB".to_vec(), vec![3; 4]),
		(b"B".to_vec(), vec![4; 64]),
		(b"BC".to_vec(), vec![4; 64]),
	];
	const NON_EXISTENT_KEY: &[u8] = &*b"NOT";

	let mut memdb = DB::default();

	let mut t = TrieDBMutBuilder::<T>::new(&memdb).build();
	for (key, value) in &key_value {
		t.insert(key, value).unwrap();
	}
	let root = memdb.commit(t.commit());

	for mut cache in [Some(TestTrieCache::<T>::default()), None] {
		for get_hash in [true, false] {
			let mut recorder = Recorder::<T>::default();
			{
				let trie = TrieDBBuilder::<T>::new(&memdb, &root)
					.with_recorder(&mut recorder)
					.with_optional_cache(cache.as_mut().map(|c| c as &mut _))
					.build();
				for (key, _) in &key_value {
					if get_hash {
						assert!(trie.get_hash(key).unwrap().is_some());
					} else {
						assert!(trie.get(key).unwrap().is_some());
					}
				}

				if get_hash {
					assert!(trie.get_hash(&NON_EXISTENT_KEY).unwrap().is_none());
				} else {
					assert!(trie.get(&NON_EXISTENT_KEY).unwrap().is_none());
				}
			}

			for (key, value) in &key_value {
				let recorded = recorder.trie_nodes_recorded_for_key(&key);

				let is_inline = T::MAX_INLINE_VALUE.map_or(true, |m| value.len() < m as usize);

				let expected = if get_hash && !is_inline {
					RecordedForKey::Hash
				} else {
					RecordedForKey::Value
				};

				assert_eq!(
					expected,
					recorded,
					"{:?} max_inline: {:?} get_hash: {get_hash}",
					String::from_utf8(key.to_vec()),
					T::MAX_INLINE_VALUE
				);
			}

			assert_eq!(
				RecordedForKey::Value,
				recorder.trie_nodes_recorded_for_key(&NON_EXISTENT_KEY),
			);
		}
	}
}

// Copyright 2017, 2019 Parity Technologies
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

//! Alternative tools for working with key value iterator without recursion.

use elastic_array::ElasticArray36;
use hash_db::{Hasher, HashDB};
use std::marker::PhantomData;
use crate::triedbmut::{ChildReference};
use crate::nibbleslice::NibbleSlice;
use node_codec::NodeCodec;


fn biggest_depth(v1: &[u8], v2: &[u8]) -> usize {
	// sorted assertion preventing out of bound
	for a in 0..v1.len() {
		if v1[a] == v2[a] {
		} else {
			if (v1[a] >> 4) ==	(v2[a] >> 4) {
				return a * 2 + 1;
			} else {
				return a * 2;
			}
		}
	}
	return v1.len() * 2;
}

// warn! start at 0 // TODO change biggest_depth??
// warn! slow don't loop on that when possible
#[inline(always)]
fn nibble_at(v1: &[u8], ix: usize) -> u8 {
	if ix % 2 == 0 {
		v1[ix/2] >> 4
	} else {
		v1[ix/2] & 15
	}
}

/*
// TODO remove for nibbleslice api TODO can be variable size
fn encoded_nibble(ori: &[u8], is_leaf: bool) -> ElasticArray36<u8> {
	let l = ori.len();
	let mut r = ElasticArray36::new();
	let mut i = l % 2;
	r.push(if i == 1 {0x10 + ori[0]} else {0} + if is_leaf {0x20} else {0});
	while i < l {
		r.push(ori[i] * 16 + ori[i+1]);
		i += 2;
	}
	r
}
*/

type CacheNode<HO> = Option<ChildReference<HO>>;

// (64 * 16) aka 2*byte size of key * nb nibble value, 2 being byte/nible (8/4)
// TODO test others layout
// first usize to get nb of added value, second usize last added index
// second str is in branch value
struct CacheAccum<H: Hasher,C,V> (Vec<([CacheNode<<H as Hasher>::Out>; NIBBLE_SIZE], bool, Option<V>)>,PhantomData<(H,C)>);

#[inline(always)]
fn new_vec_slice_buff<HO>() -> [CacheNode<HO>; NIBBLE_SIZE] {
	[
		None, None, None, None,
		None, None, None, None,
		None, None, None, None,
		None, None, None, None,
	]
}

/// initially allocated cache
const INITIAL_DEPTH: usize = 10;
const NIBBLE_SIZE: usize = 16;
impl<H,C,V> CacheAccum<H,C,V>
where
	H: Hasher,
	C: NodeCodec<H>,
	V: AsRef<[u8]>,
	{

	fn new() -> Self {
		let mut v = Vec::with_capacity(INITIAL_DEPTH);
		(0..INITIAL_DEPTH).for_each(|_|v.push((new_vec_slice_buff(), false, None)));
		CacheAccum(v, PhantomData)
	}

	#[inline(always)]
	fn set_node(&mut self, depth:usize, nibble_ix:usize, node: CacheNode<H::Out>) {
		if depth >= self.0.len() {
			for _i in self.0.len()..depth + 1 { 
				self.0.push((new_vec_slice_buff(), false, None));
			}
		}
		self.0[depth].0[nibble_ix] = node;
		self.0[depth].1 = true;
	}

	#[inline(always)]
	fn touched(&self, depth:usize) -> bool {
		self.0[depth].1
	}

	#[inline(always)]
	fn reset_depth(&mut self, depth:usize) {
		self.0[depth].1 = false;
		for i in 0..NIBBLE_SIZE {
			self.0[depth].0[i] = None;
		}
	}

	fn flush_val (
		&mut self,
		cb_ext: &mut impl ProcessEncodedNode<<H as Hasher>::Out>,
		target_depth: usize, 
		(k2, v2): &(impl AsRef<[u8]>,impl AsRef<[u8]>), 
	) {
		let nibble_value = nibble_at(&k2.as_ref()[..], target_depth);
		// is it a branch value (two candidate same ix)
		let nkey = NibbleSlice::new_offset(&k2.as_ref()[..],target_depth+1).encoded(true);
		// Note: fwiu, having fixed key size, all values are in leaf (no value in
		// branch). TODO run metrics on a node to count branch with values
		let encoded = C::leaf_node(&nkey.as_ref()[..], &v2.as_ref()[..]);
		let hash = cb_ext.process(encoded, false);

		// insert hash in branch (first level branch only at this point)
		self.set_node(target_depth, nibble_value as usize, Some(hash));
	}

	fn flush_branch(
		&mut self,
		no_ext: bool,
		cb_ext: &mut impl ProcessEncodedNode<<H as Hasher>::Out>,
		ref_branch: impl AsRef<[u8]> + Ord,
		new_depth: usize, 
		old_depth: usize,
		is_last: bool,
	) {
		let mut last_branch_ix = None;
		for d in (new_depth..=old_depth).rev() {

			let touched = self.touched(d);

			if touched || d == new_depth {
			if let Some(branch_d) = last_branch_ix.take() {

				let last_root = d == 0 && is_last;
				// reduce slice for branch
				let parent_branch = touched;
				// TODO change this offset to not use nibble slice api (makes it hard to get the index
				// thing)
				let (slice_size, offset) = if parent_branch && last_root {
					// corner branch last
					(branch_d - d - 1, d + 1)
				} else if last_root {
					// corner case non branch last
					(branch_d - d, d)
				} else {
					(branch_d - d - 1, d + 1)
				};

				let nkey = if slice_size > 0 {
					Some(NibbleSlice::new_offset(&ref_branch.as_ref()[..],offset)
						.encoded_leftmost(slice_size, false))
				} else {
					None
				};
	
				let is_root = d == 0 && is_last && !parent_branch;
				let h = if no_ext {
					// enc branch
					self.alt_no_ext(cb_ext, branch_d, is_root, nkey)
				} else {
					self.standard_ext(cb_ext, branch_d, is_root, nkey)
				};
				// put hash in parent
				let nibble: u8 = nibble_at(&ref_branch.as_ref()[..],d);
				self.set_node(d, nibble as usize, Some(h));
			}
			}

		
			if d > new_depth || is_last {
				if touched {
					last_branch_ix = Some(d);
				}
			}

		}
		if let Some(d) = last_branch_ix {
			if no_ext {
				self.alt_no_ext(cb_ext, d, true, None);
			} else {
				self.standard_ext(cb_ext, d, true, None);
			}
		}
	}

	#[inline(always)]
	fn standard_ext(
		&mut self,
		cb_ext: &mut impl ProcessEncodedNode<<H as Hasher>::Out>,
		branch_d: usize,
		is_root: bool,
		nkey: Option<ElasticArray36<u8>>,
	) -> ChildReference<<H as Hasher>::Out> {
		// enc branch
		let v = self.0[branch_d].2.take();
		let encoded = C::branch_node(self.0[branch_d].0.iter(), v.as_ref().map(|v|v.as_ref()));
		self.reset_depth(branch_d);
		let branch_hash = cb_ext.process(encoded, is_root && nkey.is_none());

		if let Some(nkey) = nkey {
			let encoded = C::ext_node(&nkey[..], branch_hash);
			let h = cb_ext.process(encoded, is_root);
			h
		} else {
			branch_hash
		}
	}

	#[inline(always)]
	fn alt_no_ext(
		&mut self,
		cb_ext: &mut impl ProcessEncodedNode<<H as Hasher>::Out>,
		branch_d: usize,
		is_root: bool,
		nkey: Option<ElasticArray36<u8>>,
		) -> ChildReference<<H as Hasher>::Out> {
		// enc branch
		let v = self.0[branch_d].2.take();
		let encoded = C::branch_node_nibbled(
			// warn direct use of default empty nible encoded: NibbleSlice::new_offset(&[],0).encoded(false);
			nkey.as_ref().map(|v|&v[..]).unwrap_or(&[0]),
			self.0[branch_d].0.iter(), v.as_ref().map(|v|v.as_ref()));

		self.reset_depth(branch_d);
		cb_ext.process(encoded, is_root)
	}

}

pub fn trie_visit_no_ext<H, C, I, A, B, F>(input: I, cb_ext: &mut F) 
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
		H: Hasher,
		C: NodeCodec<H>,
		F: ProcessEncodedNode<<H as Hasher>::Out>,
	{
		trie_visit_inner::<H, C, I, A, B, F>(input, cb_ext, true)
	}

pub fn trie_visit<H, C, I, A, B, F>(input: I, cb_ext: &mut F) 
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
		H: Hasher,
		C: NodeCodec<H>,
		F: ProcessEncodedNode<<H as Hasher>::Out>,
	{
		trie_visit_inner::<H, C, I, A, B, F>(input, cb_ext, false)
	}

// put no_ext as a trait: probably not worth it (fn designed for that)?
fn trie_visit_inner<H, C, I, A, B, F>(input: I, cb_ext: &mut F, no_ext: bool) 
	where
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
		H: Hasher,
		C: NodeCodec<H>,
		F: ProcessEncodedNode<<H as Hasher>::Out>,
	{
	let mut depth_queue = CacheAccum::<H,C,B>::new();
	// compare iter ordering
	let mut iter_input = input.into_iter();
	if let Some(mut prev_val) = iter_input.next() {
		//println!("!st{:?},{:?}",&prev_val.0.as_ref(),&prev_val.1.as_ref());
		// depth of last item TODO rename to last_depth
		let mut prev_depth = 0;

		for (k, v) in iter_input {
			//println!("!{:?},{:?}",&k.as_ref(),&v.as_ref());
			let common_depth = biggest_depth(&prev_val.0.as_ref()[..], &k.as_ref()[..]);
			// 0 is a reserved value : could use option
			let depth_item = common_depth;
			if common_depth == prev_val.0.as_ref().len() * 2 {
				//println!("stack {} ", common_depth);
				// the new key include the previous one : branch value case
				// just stored value at branch depth
				depth_queue.0[common_depth].2 = Some(prev_val.1);
				depth_queue.0[common_depth].1 = true;
			} else if depth_item >= prev_depth {
				//println!("fv {}", depth_item);
				// put prev with next (common branch prev val can be flush)
				depth_queue.flush_val(cb_ext, depth_item, &prev_val);
			} else if depth_item < prev_depth {
				//println!("fbv {}", prev_depth);
				// do not put with next, previous is last of a branch
				depth_queue.flush_val(cb_ext, prev_depth, &prev_val);
				let ref_branches = prev_val.0;
				//println!("fb {} {}", depth_item, prev_depth);
				depth_queue.flush_branch(no_ext, cb_ext, ref_branches, depth_item, prev_depth, false); // TODO flush at prev flush depth instead ??
			}

			prev_val = (k, v);
			prev_depth = depth_item;
		}
		// last pendings
		if prev_depth == 0
			&& !depth_queue.touched(0) {
			// one single element corner case
			let (k2, v2) = prev_val; 
			let nkey = NibbleSlice::new_offset(&k2.as_ref()[..],prev_depth).encoded(true);
			let encoded = C::leaf_node(&nkey.as_ref()[..], &v2.as_ref()[..]);
			cb_ext.process(encoded, true);
		} else {
			//println!("fbvl {}", prev_depth);
			depth_queue.flush_val(cb_ext, prev_depth, &prev_val);
			let ref_branches = prev_val.0;
			//println!("fbl {} {}", 0, prev_depth);
			depth_queue.flush_branch(no_ext, cb_ext, ref_branches, 0, prev_depth, true);
		}
	} else {
		// nothing null root corner case
		cb_ext.process(C::empty_node(), true);
	}
}

pub trait ProcessEncodedNode<HO> {
	fn process(&mut self, Vec<u8>, bool) -> ChildReference<HO>;
}

/// Get trie root and insert node in hash db on parsing.
/// As for all `ProcessEncodedNode` implementation, it 
/// is only for full trie parsing (not existing trie).
pub struct TrieBuilder<'a, H, HO, V, DB> {
	pub db: &'a mut DB,
	pub root: Option<HO>,
	_ph: PhantomData<(H,V)>,
}

impl<'a, H, HO, V, DB> TrieBuilder<'a, H, HO, V, DB> {
	pub fn new(db: &'a mut DB) -> Self {
		TrieBuilder { db, root: None, _ph: PhantomData } 
	}
}

impl<'a, H: Hasher, V, DB: HashDB<H,V>> ProcessEncodedNode<<H as Hasher>::Out> for TrieBuilder<'a, H, <H as Hasher>::Out, V, DB> {
	fn process(&mut self, enc_ext: Vec<u8>, is_root: bool) -> ChildReference<<H as Hasher>::Out> {
		let len = enc_ext.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&enc_ext[..len]);

			return ChildReference::Inline(h, len);
		}
		let hash = self.db.insert(&enc_ext[..]);
		if is_root {
			//println!("isroot touch");
			self.root = Some(hash.clone());
		};
		ChildReference::Hash(hash)
	}
}

/// Get trie root hash on parsing
pub struct TrieRoot<H, HO> {
	pub root: Option<HO>,
	_ph: PhantomData<(H)>,
}

impl<H, HO> Default for TrieRoot<H, HO> {
	fn default() -> Self {
		TrieRoot { root: None, _ph: PhantomData } 
	}
}

impl<H: Hasher> ProcessEncodedNode<<H as Hasher>::Out> for TrieRoot<H, <H as Hasher>::Out> {
	fn process(&mut self, enc_ext: Vec<u8>, is_root: bool) -> ChildReference<<H as Hasher>::Out> {
		let len = enc_ext.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&enc_ext[..len]);

			return ChildReference::Inline(h, len);
		}
		let hash = <H as Hasher>::hash(&enc_ext[..]);
		if is_root {
			self.root = Some(hash.clone());
		};
		ChildReference::Hash(hash)
	}
}

/// Get trie root hash on parsing
/// -> this seems to match current implementation
/// of trie_root but I think it should return the 
/// full stream of trie (which would not be doable
/// with current `ProcessEncodedNode` definition
/// but can be doable by switching to something
/// similar to `TrieStream` (initially the trait
/// was a simple FnMut but it make sense to move
/// to something more refined).
pub struct TrieRootUnhashed<H> {
	pub root: Option<Vec<u8>>,
	_ph: PhantomData<(H)>,
}

impl<H> Default for TrieRootUnhashed<H> {
	fn default() -> Self {
		TrieRootUnhashed { root: None, _ph: PhantomData } 
	}
}

impl<H: Hasher> ProcessEncodedNode<<H as Hasher>::Out> for TrieRootUnhashed<H> {
	fn process(&mut self, enc_ext: Vec<u8>, is_root: bool) -> ChildReference<<H as Hasher>::Out> {
		let len = enc_ext.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&enc_ext[..len]);

			return ChildReference::Inline(h, len);
		}
		let hash = <H as Hasher>::hash(&enc_ext[..]);
		if is_root {
			self.root = Some(enc_ext);
		};
		ChildReference::Hash(hash)
	}
}



#[cfg(test)]
mod test {
	use super::*;
	use env_logger;
	use standardmap::*;
	use DBValue;
	use memory_db::MemoryDB;
	use hash_db::{Hasher, HashDB};
	use keccak_hasher::KeccakHasher;
	use reference_trie::{RefTrieDBMut, RefTrieDB, Trie, TrieMut,
	ReferenceNodeCodec, ref_trie_root};

	#[test]
	fn trie_root_empty () {
		compare_impl(vec![])
	}

	#[test]
	fn trie_one_node () {
		compare_impl(vec![
			(vec![1u8,2u8,3u8,4u8],vec![7u8]),
		]);
	}

	#[test]
	fn root_extension_one () {
		compare_impl(vec![
			(vec![1u8,2u8,3u8,3u8],vec![8u8;32]),
			(vec![1u8,2u8,3u8,4u8],vec![7u8;32]),
		]);
	}

	fn compare_impl(data: Vec<(Vec<u8>,Vec<u8>)>) {
		let memdb = MemoryDB::default();
		let hashdb = MemoryDB::<KeccakHasher, DBValue>::default();
		reference_trie::compare_impl(data, memdb, hashdb);
	}
	fn compare_impl_no_ext(data: Vec<(Vec<u8>,Vec<u8>)>) {
		let memdb = MemoryDB::default();
		let hashdb = MemoryDB::<KeccakHasher, DBValue>::default();
		reference_trie::compare_impl_no_ext(data, memdb, hashdb);
	}
	fn compare_impl_no_ext_unordered(data: Vec<(Vec<u8>,Vec<u8>)>) {
		let memdb = MemoryDB::default();
		let hashdb = MemoryDB::<KeccakHasher, DBValue>::default();
		reference_trie::compare_impl_no_ext_unordered(data, memdb, hashdb);
	}
/*	fn compare_impl_no_ext_unordered_rem(data: Vec<(Vec<u8>,Vec<u8>)>, rem: &[(usize,usize)]) {
		let memdb = MemoryDB::default();
		let hashdb = MemoryDB::<KeccakHasher, DBValue>::default();
		reference_trie::compare_impl_no_ext_unordered_rem(data, rem, memdb, hashdb);
	}*/



	fn compare_root(data: Vec<(Vec<u8>,Vec<u8>)>) {
		let memdb = MemoryDB::default();
		reference_trie::compare_root(data, memdb);
	}
	fn compare_unhashed(data: Vec<(Vec<u8>,Vec<u8>)>) {
		let memdb = MemoryDB::default();
		reference_trie::compare_unhashed(data, memdb);
	}



	#[test]
	fn trie_middle_node1 () {
		compare_impl(vec![
			(vec![1u8,2u8],vec![8u8;32]),
			(vec![1u8,2u8,3u8,4u8],vec![7u8;32]),
		]);
	}

	#[test]
	fn trie_middle_node2 () {
		compare_impl(vec![
			(vec![0u8,2u8,3u8,5u8,3u8],vec![1u8;32]),
			(vec![1u8,2u8],vec![8u8;32]),
			(vec![1u8,2u8,3u8,4u8],vec![7u8;32]),
			(vec![1u8,2u8,3u8,5u8],vec![7u8;32]),
			(vec![1u8,2u8,3u8,5u8,3u8],vec![7u8;32]),
		]);
	}
	#[test]
	fn root_extension_bis () {
		compare_root(vec![
			(vec![1u8,2u8,3u8,3u8],vec![8u8;32]),
			(vec![1u8,2u8,3u8,4u8],vec![7u8;32]),
		]);
	}
	#[test]
	fn root_extension_tierce () {
		compare_unhashed(vec![
			(vec![1u8,2u8,3u8,3u8],vec![8u8;2]),
			(vec![1u8,2u8,3u8,4u8],vec![7u8;2]),
		]);
	}
	#[test]
	fn root_extension_tierce_big () {
		// on more content unhashed would hash
		compare_unhashed(vec![
			(vec![1u8,2u8,3u8,3u8],vec![8u8;32]),
			(vec![1u8,2u8,3u8,4u8],vec![7u8;32]),
			(vec![1u8,6u8,3u8,3u8],vec![8u8;32]),
			(vec![6u8,2u8,3u8,3u8],vec![8u8;32]),
			(vec![6u8,2u8,3u8,13u8],vec![8u8;32]),
		]);
	}


	#[test]
	fn trie_middle_node2x () {
		compare_impl(vec![
			(vec![0u8,2u8,3u8,5u8,3u8],vec![1u8;2]),
			(vec![1u8,2u8],vec![8u8;2]),
			(vec![1u8,2u8,3u8,4u8],vec![7u8;2]),
			(vec![1u8,2u8,3u8,5u8],vec![7u8;2]),
			(vec![1u8,2u8,3u8,5u8,3u8],vec![7u8;2]),
		]);
 }
	#[test]
	fn fuzz1 () {
		compare_impl(vec![
			(vec![01u8],vec![42u8,9]),
			(vec![01u8,0u8],vec![0u8,0]),
			(vec![255u8,2u8],vec![1u8,0]),
		]);
	}
	#[test]
	fn fuzz2 () {
		compare_impl(vec![
			(vec![0,01u8],vec![42u8,9]),
			(vec![0,01u8,0u8],vec![0u8,0]),
			(vec![0,255u8,2u8],vec![1u8,0]),
		]);
	}
	#[test]
	fn fuzz3 () {
		compare_impl(vec![
			(vec![0],vec![196, 255]),
 /*		 (vec![48],vec![138, 255]),
			(vec![67],vec![0, 0]),
			(vec![128],vec![255, 0]), */
			(vec![247],vec![0, 196]),
			(vec![255],vec![0, 0]),
		]);
	}
	#[test]
	fn fuzz_noext1 () {
		compare_impl_no_ext(vec![
			(vec![0],vec![128, 0]),
			(vec![128],vec![0, 0]),
		]);
	}
	#[test]
	fn fuzz_noext2 () {
		compare_impl_no_ext(vec![
			(vec![0],vec![6, 255]),
			(vec![6],vec![255, 186]),
			(vec![255],vec![186, 255]),
		]);
	}
	#[test]
	fn fuzz_noext2_bis () {
		compare_impl_no_ext(vec![
			(vec![0xaa], vec![0xa0]),
			(vec![0xaa, 0xaa], vec![0xaa]),
			(vec![0xaa, 0xbb], vec![0xab]),
			(vec![0xbb], vec![0xb0]),
			(vec![0xbb, 0xbb], vec![0xbb]),
			(vec![0xbb, 0xcc], vec![0xbc]),
		]);
	}

	#[test]
	fn fuzz_noext3 () {
		compare_impl_no_ext_unordered(vec![
			(vec![11,252],vec![11, 0]),
			(vec![11,0],vec![0, 0]),
			(vec![0],vec![0, 0]),
		]);
	}
/*	#[test]
	fn fuzz_noextrem1 () {
		compare_impl_no_ext_unordered_rem(vec![
			(vec![0],vec![0, 0]),
			(vec![0],vec![0, 0]),
			(vec![0],vec![0, 0]),
			(vec![0],vec![0, 0]),
			(vec![0],vec![0, 0]),
			(vec![0],vec![0, 0]),
			(vec![0],vec![0, 0]),
		], &[(0,4)]);
	}*/

}

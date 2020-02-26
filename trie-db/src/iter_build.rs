// Copyright 2017, 2019 Parity Technologies
//
// Licensed under the Apache License, Version .0 (the "License");
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

//! Alternative tools for working with key value ordered iterator without recursion.
//! This is iterative implementation of `trie_root` algorithm, using `NodeCodec`
//! implementation.
//! See `trie_visit` function.

use hash_db::{Hasher, HashDB, Prefix, ComplexLayout};
use ordered_trie::{HashDBComplex, HasherComplex};
use crate::rstd::{cmp::max, marker::PhantomData, vec::Vec, EmptyIter, ops::Range};
use crate::triedbmut::{ChildReference};
use crate::nibble::NibbleSlice;
use crate::nibble::nibble_ops;
use crate::node_codec::{NodeCodec, EncodedNoChild};
use crate::{TrieLayout, TrieHash};
use crate::rstd::borrow::Borrow;

macro_rules! exponential_out {
	(@3, [$($inpp:expr),*]) => { exponential_out!(@2, [$($inpp,)* $($inpp),*]) };
	(@2, [$($inpp:expr),*]) => { exponential_out!(@1, [$($inpp,)* $($inpp),*]) };
	(@1, [$($inpp:expr),*]) => { [$($inpp,)* $($inpp),*] };
}

type CacheNode<HO> = Option<ChildReference<HO>>;

#[inline(always)]
fn new_vec_slice_buffer<HO>() -> [CacheNode<HO>; 16] {
	exponential_out!(@3, [None, None])
}

type ArrayNode<T> = [CacheNode<TrieHash<T>>; 16];

/// Struct containing iteration cache, can be at most the length of the lowest nibble.
///
/// Note that it is not memory optimal (all depth are allocated even if some are empty due
/// to node partial).
/// Three field are used, a cache over the children, an optional associated value and the depth.
struct CacheAccum<T: TrieLayout, V> (Vec<(ArrayNode<T>, Option<V>, usize)>, PhantomData<T>);

/// Initially allocated cache depth.
const INITIAL_DEPTH: usize = 10;

#[inline]
fn register_children_buf<T: TrieLayout>() -> Option<[Option<Range<usize>>; 16]> {
	if T::COMPLEX_HASH {
		Some(Default::default())
	} else {
		None
	}
}

impl<T, V> CacheAccum<T, V>
	where
		T: TrieLayout,
		V: AsRef<[u8]>,
{

	fn new() -> Self {
		let v = Vec::with_capacity(INITIAL_DEPTH);
		CacheAccum(v, PhantomData)
	}

	#[inline(always)]
	fn set_cache_value(&mut self, depth:usize, value: Option<V>) {
		if self.0.is_empty() || self.0[self.0.len() - 1].2 < depth {
			self.0.push((new_vec_slice_buffer(), None, depth));
		}
		let last = self.0.len() - 1;
		debug_assert!(self.0[last].2 <= depth);
		self.0[last].1 = value;
	}

	#[inline(always)]
	fn set_node(&mut self, depth: usize, nibble_index: usize, node: CacheNode<TrieHash<T>>) {
		if self.0.is_empty() || self.0[self.0.len() - 1].2 < depth {
			self.0.push((new_vec_slice_buffer(), None, depth));
		}

		let last = self.0.len() - 1;
		debug_assert!(self.0[last].2 == depth);

		self.0[last].0.as_mut()[nibble_index] = node;
	}

	#[inline(always)]
	fn last_depth(&self) -> usize {
		let ix = self.0.len();
		if ix > 0 {
			let last = ix - 1;
			self.0[last].2
		} else {
			0
		}
	}

	#[inline(always)]
	fn last_last_depth(&self) -> usize {
		let ix = self.0.len();
		if ix > 1 {
			let last = ix - 2;
			self.0[last].2
		} else {
			0
		}
	}

	#[inline(always)]
	fn is_empty(&self) -> bool {
		self.0.is_empty()
	}
	#[inline(always)]
	fn is_one(&self) -> bool {
		self.0.len() == 1
	}

	#[inline(always)]
	fn reset_depth(&mut self, depth: usize) {
		debug_assert!(self.0[self.0.len() - 1].2 == depth);
		self.0.pop();
	}

	fn flush_value (
		&mut self,
		callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
		target_depth: usize,
		(k2, v2): &(impl AsRef<[u8]>, impl AsRef<[u8]>),
	) {
		let nibble_value = nibble_ops::left_nibble_at(&k2.as_ref()[..], target_depth);
		// is it a branch value (two candidate same ix)
		let nkey = NibbleSlice::new_offset(&k2.as_ref()[..], target_depth + 1);
		let encoded = T::Codec::leaf_node(nkey.right(), &v2.as_ref()[..]);
		let pr = NibbleSlice::new_offset(
			&k2.as_ref()[..],
			k2.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE - nkey.len(),
		);
		let iter: Option<(EmptyIter<Option<_>>, _)> = None;
		let hash = callback.process(pr.left(), (encoded, EncodedNoChild::Unused), false, iter);

		// insert hash in branch (first level branch only at this point)
		self.set_node(target_depth, nibble_value as usize, Some(hash));
	}

	fn flush_branch(
		&mut self,
		no_extension: bool,
		callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
		ref_branch: impl AsRef<[u8]> + Ord,
		new_depth: usize,
		is_last: bool,
	) {

		while self.last_depth() > new_depth || is_last && !self.is_empty() {

			let lix = self.last_depth();
			let llix = max(self.last_last_depth(), new_depth);

			let (offset, slice_size, is_root) =
				if llix == 0 && is_last && self.is_one() {
				// branch root
				(llix, lix - llix, true)
			} else {
				(llix + 1, lix - llix - 1, false)
			};
			let nkey = if slice_size > 0 {
				Some((offset, slice_size))
			} else {
				None
			};

			let h = if no_extension {
				// encode branch
				self.no_extension(&ref_branch.as_ref()[..], callback, lix, is_root, nkey)
			} else {
				self.standard_extension(&ref_branch.as_ref()[..], callback, lix, is_root, nkey)
			};
			if !is_root {
				// put hash in parent
				let nibble: u8 = nibble_ops::left_nibble_at(&ref_branch.as_ref()[..], llix);
				self.set_node(llix, nibble as usize, Some(h));
			}
		}
	}

	#[inline(always)]
	fn standard_extension(
		&mut self,
		key_branch: &[u8],
		callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
		branch_d: usize,
		is_root: bool,
		nkey: Option<(usize, usize)>,
	) -> ChildReference<TrieHash<T>> {
		let last = self.0.len() - 1;
		assert_eq!(self.0[last].2, branch_d);

		// encode branch
		let v = self.0[last].1.take();

		let mut register_children = register_children_buf::<T>();
		let encoded = T::Codec::branch_node(
			self.0[last].0.as_ref().iter(),
			v.as_ref().map(|v| v.as_ref()),
			register_children.as_mut().map(|t| t.as_mut()), // TODO switch fully to codec approach or just return trim info
		);
		let pr = NibbleSlice::new_offset(&key_branch, branch_d);
		let branch_hash = if T::COMPLEX_HASH {
			let len = self.0[last].0.as_ref().iter().filter(|v| v.is_some()).count();
			let children = self.0[last].0.as_ref().iter();
			callback.process(pr.left(), encoded, is_root && nkey.is_none(), Some((children, len)))
		} else {
			let iter: Option<(EmptyIter<Option<_>>, _)> = None;
			callback.process(pr.left(), encoded, is_root && nkey.is_none(), iter)
		};
		self.reset_depth(branch_d);

		if let Some(nkeyix) = nkey {
			let pr = NibbleSlice::new_offset(&key_branch, nkeyix.0);
			let nib = pr.right_range_iter(nkeyix.1);
			let encoded = T::Codec::extension_node(nib, nkeyix.1, branch_hash);
			let iter: Option<(EmptyIter<Option<_>>, _)> = None;
			let h = callback.process(pr.left(), (encoded, EncodedNoChild::Unused), is_root, iter);
			h
		} else {
			branch_hash
		}
	}

	#[inline(always)]
	fn no_extension(
		&mut self,
		key_branch: &[u8],
		callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
		branch_d: usize,
		is_root: bool,
		nkey: Option<(usize, usize)>,
		) -> ChildReference<TrieHash<T>> {
		let last = self.0.len() - 1;
		debug_assert!(self.0[last].2 == branch_d);
		// encode branch
		let v = self.0[last].1.take();
		let nkeyix = nkey.unwrap_or((0, 0));
		let mut register_children = register_children_buf::<T>();
		let pr = NibbleSlice::new_offset(&key_branch, nkeyix.0);
		let encoded = T::Codec::branch_node_nibbled(
			pr.right_range_iter(nkeyix.1),
			nkeyix.1,
			self.0[last].0.as_ref().iter(), v.as_ref().map(|v| v.as_ref()),
			register_children.as_mut().map(|t| t.as_mut()), // TODO switch fully to codec approach
		);
		let ext_length = nkey.as_ref().map(|nkeyix| nkeyix.0).unwrap_or(0);
		let pr = NibbleSlice::new_offset(
			&key_branch,
			branch_d - ext_length,
		);
		let result = if T::COMPLEX_HASH {
			let len = self.0[last].0.as_ref().iter().filter(|v| v.is_some()).count();
			let children = self.0[last].0.as_ref().iter();
			callback.process(pr.left(), encoded, is_root, Some((children, len)))
		} else {
			let iter: Option<(EmptyIter<Option<_>>, _)> = None;
			callback.process(pr.left(), encoded, is_root, iter)
		};
		self.reset_depth(branch_d);
		result
	}

}

/// Function visiting trie from key value inputs with a `ProccessEncodedNode` callback.
/// This is the main entry point of this module.
/// Calls to each node occurs ordered by byte key value but with longest keys first (from node to
/// branch to root), this differs from standard byte array ordering a bit.
pub fn trie_visit<T, I, A, B, F>(input: I, callback: &mut F)
	where
		T: TrieLayout,
		I: IntoIterator<Item = (A, B)>,
		A: AsRef<[u8]> + Ord,
		B: AsRef<[u8]>,
		F: ProcessEncodedNode<TrieHash<T>>,
{
	let no_extension = !T::USE_EXTENSION;
	let mut depth_queue = CacheAccum::<T, B>::new();
	// compare iter ordering
	let mut iter_input = input.into_iter();
	if let Some(mut previous_value) = iter_input.next() {
		// depth of last item
		let mut last_depth = 0;

		let mut single = true;
		for (k, v) in iter_input {
			single = false;
			let common_depth = nibble_ops::biggest_depth(&previous_value.0.as_ref()[..], &k.as_ref()[..]);
			// 0 is a reserved value : could use option
			let depth_item = common_depth;
			if common_depth == previous_value.0.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE {
				// the new key include the previous one : branch value case
				// just stored value at branch depth
				depth_queue.set_cache_value(common_depth, Some(previous_value.1));
			} else if depth_item >= last_depth {
				// put previous with next (common branch previous value can be flush)
				depth_queue.flush_value(callback, depth_item, &previous_value);
			} else if depth_item < last_depth {
				// do not put with next, previous is last of a branch
				depth_queue.flush_value(callback, last_depth, &previous_value);
				let ref_branches = previous_value.0;
				depth_queue.flush_branch(no_extension, callback, ref_branches, depth_item, false);
			}

			previous_value = (k, v);
			last_depth = depth_item;
		}
		// last pendings
		if single {
			// one single element corner case
			let (k2, v2) = previous_value;
			let nkey = NibbleSlice::new_offset(&k2.as_ref()[..], last_depth);
			let encoded = T::Codec::leaf_node(nkey.right(), &v2.as_ref()[..]);
			let pr = NibbleSlice::new_offset(
				&k2.as_ref()[..],
				k2.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE - nkey.len(),
			);
			let iter: Option<(EmptyIter<Option<_>>, _)> = None;
			callback.process(pr.left(), (encoded, EncodedNoChild::Unused), true, iter);
		} else {
			depth_queue.flush_value(callback, last_depth, &previous_value);
			let ref_branches = previous_value.0;
			depth_queue.flush_branch(no_extension, callback, ref_branches, 0, true);
		}
	} else {
		let iter: Option<(EmptyIter<Option<_>>, _)> = None;
		// nothing null root corner case
		callback.process(hash_db::EMPTY_PREFIX, (T::Codec::empty_node().to_vec(), EncodedNoChild::Unused), true, iter);
	}
}

/// Visitor trait to implement when using `trie_visit`.
pub trait ProcessEncodedNode<HO> {
	/// Function call with prefix, encoded value and a boolean indicating if the
	/// node is the root for each node of the trie.
	///
	/// Note that the returned value can change depending on implementation,
	/// but usually it should be the Hash of encoded node.
	/// This is not something direcly related to encoding but is here for
	/// optimisation purpose (builder hash_db does return this value).
	fn process(
		&mut self,
		prefix: Prefix,
		encoded_node: (Vec<u8>, EncodedNoChild),
		is_root: bool,
		complex_hash: Option<(impl Iterator<Item = impl Borrow<Option<ChildReference<HO>>>>, usize)>,
	) -> ChildReference<HO>;
}

/// Get trie root and insert visited node in a hash_db.
/// As for all `ProcessEncodedNode` implementation, it
/// is only for full trie parsing (not existing trie).
pub struct TrieBuilder<'a, H, HO, V, DB> {
	db: &'a mut DB,
	pub root: Option<HO>,
	_ph: PhantomData<(H, V)>,
}

impl<'a, H, HO, V, DB> TrieBuilder<'a, H, HO, V, DB> {
	pub fn new(db: &'a mut DB) -> Self {
		TrieBuilder { db, root: None, _ph: PhantomData }
	}
}

/// Get trie root and insert visited node in a hash_db.
/// As for all `ProcessEncodedNode` implementation, it
/// is only for full trie parsing (not existing trie).
pub struct TrieBuilderComplex<'a, H, HO, V, DB> {
	db: &'a mut DB,
	pub root: Option<HO>,
	_ph: PhantomData<(H, V)>,
}

impl<'a, H, HO, V, DB> TrieBuilderComplex<'a, H, HO, V, DB> {
	pub fn new(db: &'a mut DB) -> Self {
		TrieBuilderComplex { db, root: None, _ph: PhantomData }
	}
}


impl<'a, H: Hasher, V, DB: HashDB<H, V>> ProcessEncodedNode<<H as Hasher>::Out>
	for TrieBuilder<'a, H, <H as Hasher>::Out, V, DB> {
	fn process(
		&mut self,
		prefix: Prefix,
		(encoded_node, _no_child): (Vec<u8>, EncodedNoChild),
		is_root: bool,
		complex_hash: Option<(impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>, usize)>,
	) -> ChildReference<<H as Hasher>::Out> {
		let len = encoded_node.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len);
		}
		let hash = self.db.insert(prefix, &encoded_node[..]);
		if is_root {
			self.root = Some(hash.clone());
		};
		ChildReference::Hash(hash)
	}
}

impl<'a, H: HasherComplex, V, DB: HashDBComplex<H, V>> ProcessEncodedNode<<H as Hasher>::Out>
	for TrieBuilderComplex<'a, H, <H as Hasher>::Out, V, DB> {
	fn process(
		&mut self,
		prefix: Prefix,
		(encoded_node, no_child): (Vec<u8>, EncodedNoChild),
		is_root: bool,
		complex_hash: Option<(impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>, usize)>,
	) -> ChildReference<<H as Hasher>::Out> {
		let len = encoded_node.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len);
		}
		
		let hash = if let Some((children, nb_children)) = complex_hash {
			let iter = children
				.filter_map(|v| match v.borrow().as_ref() {
					Some(ChildReference::Hash(v)) => Some(Some(v.clone())),
					Some(ChildReference::Inline(v, _l)) => Some(Some(v.clone())),
					None => None,
				});
			self.db.insert_complex(
				prefix,
				&encoded_node[..],
				no_child.encoded_no_child(&encoded_node[..]),
				nb_children,
				iter,
				EmptyIter::default(),
				false,
			)
		} else {
			self.db.insert(prefix, &encoded_node[..])
		};
		if is_root {
			self.root = Some(hash.clone());
		};
		ChildReference::Hash(hash)
	}
}

/// Calculate the trie root of the trie.
pub struct TrieRoot<H, HO> {
	/// The resulting root.
	pub root: Option<HO>,
	_ph: PhantomData<H>,
}

impl<H, HO> Default for TrieRoot<H, HO> {
	fn default() -> Self {
		TrieRoot { root: None, _ph: PhantomData }
	}
}

impl<H: Hasher> ProcessEncodedNode<<H as Hasher>::Out> for TrieRoot<H, <H as Hasher>::Out> {
	fn process(
		&mut self,
		_: Prefix,
		(encoded_node, _no_child): (Vec<u8>, EncodedNoChild),
		is_root: bool,
		complex_hash: Option<(impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>, usize)>,
	) -> ChildReference<<H as Hasher>::Out> {
		let len = encoded_node.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len);
		}
		let hash = <H as Hasher>::hash(&encoded_node[..]);
		if is_root {
			self.root = Some(hash.clone());
		};
		ChildReference::Hash(hash)
	}
}

/// Calculate the trie root of the trie.
pub struct TrieRootComplex<H, HO> {
	/// The resulting root.
	pub root: Option<HO>,
	_ph: PhantomData<H>,
}

impl<H, HO> Default for TrieRootComplex<H, HO> {
	fn default() -> Self {
		TrieRootComplex { root: None, _ph: PhantomData }
	}
}

impl<H: HasherComplex> ProcessEncodedNode<<H as Hasher>::Out> for TrieRootComplex<H, <H as Hasher>::Out> {
	fn process(
		&mut self,
		_: Prefix,
		(encoded_node, no_child): (Vec<u8>, EncodedNoChild),
		is_root: bool,
		complex_hash: Option<(impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>, usize)>,
	) -> ChildReference<<H as Hasher>::Out> {
		let len = encoded_node.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len);
		}
		let hash = if let Some((children, nb_children)) = complex_hash {
			let iter = children
				.filter_map(|v| match v.borrow().as_ref() {
					Some(ChildReference::Hash(v)) => Some(Some(v.clone())),
					Some(ChildReference::Inline(v, _l)) => Some(Some(v.clone())),
					None => None,
				});
			<H as HasherComplex>::hash_complex(
				no_child.encoded_no_child(&encoded_node[..]),
				nb_children,
				iter,
				EmptyIter::default(),
				false,
			).expect("only proof fails: TODO two primitives")
		} else {
			<H as Hasher>::hash(&encoded_node[..])
		};
	
		if is_root {
			self.root = Some(hash.clone());
		};
		ChildReference::Hash(hash)
	}
}


/// Get the trie root node encoding.
pub struct TrieRootUnhashed<H> {
	/// The resulting encoded root.
	pub root: Option<Vec<u8>>,
	_ph: PhantomData<H>,
}

impl<H> Default for TrieRootUnhashed<H> {
	fn default() -> Self {
		TrieRootUnhashed { root: None, _ph: PhantomData }
	}
}

/// Get the trie root node encoding.
pub struct TrieRootUnhashedComplex<H> {
	/// The resulting encoded root.
	pub root: Option<Vec<u8>>,
	_ph: PhantomData<H>,
}

impl<H> Default for TrieRootUnhashedComplex<H> {
	fn default() -> Self {
		TrieRootUnhashedComplex { root: None, _ph: PhantomData }
	}
}

#[cfg(feature = "std")]
/// Calculate the trie root of the trie.
/// Print a debug trace.
pub struct TrieRootPrint<H, HO> {
	/// The resulting root.
	pub root: Option<HO>,
	_ph: PhantomData<H>,
}

#[cfg(feature = "std")]
impl<H, HO> Default for TrieRootPrint<H, HO> {
	fn default() -> Self {
		TrieRootPrint { root: None, _ph: PhantomData }
	}
}

#[cfg(feature = "std")]
impl<H: Hasher> ProcessEncodedNode<<H as Hasher>::Out> for TrieRootPrint<H, <H as Hasher>::Out> {
	fn process(
		&mut self,
		p: Prefix,
		(encoded_node, _no_child): (Vec<u8>, EncodedNoChild),
		is_root: bool,
		complex_hash: Option<(impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>, usize)>,
	) -> ChildReference<<H as Hasher>::Out> {
		println!("Encoded node: {:x?}", &encoded_node);
		println!("	with prefix: {:x?}", &p);
		let len = encoded_node.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			println!("	inline len {}", len);
			return ChildReference::Inline(h, len);
		}
		let hash = <H as Hasher>::hash(&encoded_node[..]);
		if is_root {
			self.root = Some(hash.clone());
		};
		println!("	hashed to {:x?}", hash.as_ref());
		ChildReference::Hash(hash)
	}
}

impl<H: Hasher> ProcessEncodedNode<<H as Hasher>::Out> for TrieRootUnhashed<H> {
	fn process(
		&mut self,
		_: Prefix,
		(encoded_node, _no_child): (Vec<u8>, EncodedNoChild),
		is_root: bool,
		complex_hash: Option<(impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>, usize)>,
	) -> ChildReference<<H as Hasher>::Out> {
		let len = encoded_node.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len);
		}
		let hash = <H as Hasher>::hash(&encoded_node[..]);
		if is_root {
			self.root = Some(encoded_node);
		};
		ChildReference::Hash(hash)
	}
}

impl<H: HasherComplex> ProcessEncodedNode<<H as Hasher>::Out> for TrieRootUnhashedComplex<H> {
	fn process(
		&mut self,
		_: Prefix,
		(encoded_node, no_child): (Vec<u8>, EncodedNoChild),
		is_root: bool,
		complex_hash: Option<(impl Iterator<Item = impl Borrow<Option<ChildReference<H::Out>>>>, usize)>,
	) -> ChildReference<<H as Hasher>::Out> {
		let len = encoded_node.len();
		if !is_root && len < <H as Hasher>::LENGTH {
			let mut h = <<H as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len);
		}
		let hash = if let Some((children, nb_children)) = complex_hash {
			let iter = children
				.filter_map(|v| match v.borrow().as_ref() {
					Some(ChildReference::Hash(v)) => Some(Some(v.clone())),
					Some(ChildReference::Inline(v, _l)) => Some(Some(v.clone())),
					None => None,
				});
			<H as HasherComplex>::hash_complex(
				no_child.encoded_no_child(&encoded_node[..]),
				nb_children,
				iter,
				EmptyIter::default(),
				false,
			).expect("only proof fails: TODO two primitives")
		} else {
			<H as Hasher>::hash(&encoded_node[..])
		};

		if is_root {
			self.root = Some(encoded_node);
		};
		ChildReference::Hash(hash)
	}
}


#[cfg(test)]
mod test {
	use crate::DBValue;
	use memory_db::{MemoryDB, HashKey, PrefixedKey};
	use keccak_hasher::KeccakHasher;

	#[test]
	fn trie_root_empty () {
		compare_implementations(vec![])
	}

	#[test]
	fn trie_one_node () {
		compare_implementations(vec![
			(vec![1u8, 2u8, 3u8, 4u8], vec![7u8]),
		]);
	}

	#[test]
	fn root_extension_one () {
		compare_implementations(vec![
			(vec![1u8, 2u8, 3u8, 3u8], vec![8u8;32]),
			(vec![1u8, 2u8, 3u8, 4u8], vec![7u8;32]),
		]);
	}

	fn test_iter(data: Vec<(Vec<u8>, Vec<u8>)>) {
		use reference_trie::{RefTrieDBMut, TrieMut, RefTrieDB, Trie};

		let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMut::new(&mut db, &mut root);
			for i in 0..data.len() {
				let key: &[u8]= &data[i].0;
				let value: &[u8] = &data[i].1;
				t.insert(key, value).unwrap();
			}
		}
		let t = RefTrieDB::new(&db, &root).unwrap();
		for (i, kv) in t.iter().unwrap().enumerate() {
			let (k, v) = kv.unwrap();
			let key: &[u8]= &data[i].0;
			let value: &[u8] = &data[i].1;
			assert_eq!(k, key);
			assert_eq!(v, value);
		}
		for (k, v) in data.into_iter() {
			assert_eq!(&t.get(&k[..]).unwrap().unwrap()[..], &v[..]);
		}
	}

	fn test_iter_no_extension(data: Vec<(Vec<u8>, Vec<u8>)>) {
		use reference_trie::{RefTrieDBMutNoExt, TrieMut, RefTrieDBNoExt, Trie};

		let mut db = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		let mut root = Default::default();
		{
			let mut t = RefTrieDBMutNoExt::new(&mut db, &mut root);
			for i in 0..data.len() {
				let key: &[u8]= &data[i].0;
				let value: &[u8] = &data[i].1;
				t.insert(key, value).unwrap();
			}
		}
		let t = RefTrieDBNoExt::new(&db, &root).unwrap();
		for (i, kv) in t.iter().unwrap().enumerate() {
			let (k, v) = kv.unwrap();
			let key: &[u8]= &data[i].0;
			let value: &[u8] = &data[i].1;
			assert_eq!(k, key);
			assert_eq!(v, value);
		}
		for (k, v) in data.into_iter() {
			assert_eq!(&t.get(&k[..]).unwrap().unwrap()[..], &v[..]);
		}
	}

	fn compare_implementations(data: Vec<(Vec<u8>, Vec<u8>)>) {
		test_iter(data.clone());
		test_iter_no_extension(data.clone());
		compare_implementations_h(data.clone());
		compare_implementations_prefixed(data.clone());
		compare_implementations_no_extension(data.clone());
		compare_implementations_no_extension_prefixed(data.clone());
	}

	fn compare_implementations_prefixed(data: Vec<(Vec<u8>, Vec<u8>)>) {
		let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
		let hashdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		reference_trie::compare_implementations(data, memdb, hashdb);
	}
	fn compare_implementations_h(data: Vec<(Vec<u8>, Vec<u8>)>) {
		let memdb = MemoryDB::<_, HashKey<_>, _>::default();
		let hashdb = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
		reference_trie::compare_implementations(data, memdb, hashdb);
	}
	fn compare_implementations_no_extension(data: Vec<(Vec<u8>, Vec<u8>)>) {
		let memdb = MemoryDB::<_, HashKey<_>, _>::default();
		let hashdb = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
		reference_trie::compare_implementations_no_extension(data, memdb, hashdb);
	}
	fn compare_implementations_no_extension_prefixed(data: Vec<(Vec<u8>, Vec<u8>)>) {
		let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
		let hashdb = MemoryDB::<KeccakHasher, PrefixedKey<_>, DBValue>::default();
		reference_trie::compare_implementations_no_extension(data, memdb, hashdb);
	}
	fn compare_implementations_no_extension_unordered(data: Vec<(Vec<u8>, Vec<u8>)>) {
		let memdb = MemoryDB::<_, HashKey<_>, _>::default();
		let hashdb = MemoryDB::<KeccakHasher, HashKey<_>, DBValue>::default();
		reference_trie::compare_implementations_no_extension_unordered(data, memdb, hashdb);
	}
	fn compare_no_extension_insert_remove(data: Vec<(bool, Vec<u8>, Vec<u8>)>) {
		let memdb = MemoryDB::<_, PrefixedKey<_>, _>::default();
		reference_trie::compare_no_extension_insert_remove(data, memdb);
	}
	fn compare_root(data: Vec<(Vec<u8>, Vec<u8>)>) {
		let memdb = MemoryDB::<_, HashKey<_>, _>::default();
		reference_trie::compare_root(data, memdb);
	}
	fn compare_unhashed(data: Vec<(Vec<u8>, Vec<u8>)>) {
		reference_trie::compare_unhashed(data);
	}
	fn compare_unhashed_no_extension(data: Vec<(Vec<u8>, Vec<u8>)>) {
		reference_trie::compare_unhashed_no_extension(data);
	}

	// Following tests are a bunch of detected issue here for non regression.

	#[test]
	fn trie_middle_node1 () {
		compare_implementations(vec![
			(vec![1u8, 2u8], vec![8u8;32]),
			(vec![1u8, 2u8, 3u8, 4u8], vec![7u8;32]),
		]);
	}
	#[test]
	fn trie_middle_node2 () {
		compare_implementations(vec![
			(vec![0u8, 2u8, 3u8, 5u8, 3u8], vec![1u8;32]),
			(vec![1u8, 2u8], vec![8u8;32]),
			(vec![1u8, 2u8, 3u8, 4u8], vec![7u8;32]),
			(vec![1u8, 2u8, 3u8, 5u8], vec![7u8;32]),
			(vec![1u8, 2u8, 3u8, 5u8, 3u8], vec![7u8;32]),
		]);
	}
	#[test]
	fn root_extension_bis () {
		compare_root(vec![
			(vec![1u8, 2u8, 3u8, 3u8], vec![8u8;32]),
			(vec![1u8, 2u8, 3u8, 4u8], vec![7u8;32]),
		]);
	}
	#[test]
	fn root_extension_tierce () {
		let d = vec![
			(vec![1u8, 2u8, 3u8, 3u8], vec![8u8;2]),
			(vec![1u8, 2u8, 3u8, 4u8], vec![7u8;2]),
		];
		compare_unhashed(d.clone());
		compare_unhashed_no_extension(d);
	}
	#[test]
	fn root_extension_tierce_big () {
		// on more content unhashed would hash
		compare_unhashed(vec![
			(vec![1u8, 2u8, 3u8, 3u8], vec![8u8;32]),
			(vec![1u8, 2u8, 3u8, 4u8], vec![7u8;32]),
			(vec![1u8, 6u8, 3u8, 3u8], vec![8u8;32]),
			(vec![6u8, 2u8, 3u8, 3u8], vec![8u8;32]),
			(vec![6u8, 2u8, 3u8, 13u8], vec![8u8;32]),
		]);
	}
	#[test]
	fn trie_middle_node2x () {
		compare_implementations(vec![
			(vec![0u8, 2u8, 3u8, 5u8, 3u8], vec![1u8;2]),
			(vec![1u8, 2u8], vec![8u8;2]),
			(vec![1u8, 2u8, 3u8, 4u8], vec![7u8;2]),
			(vec![1u8, 2u8, 3u8, 5u8], vec![7u8;2]),
			(vec![1u8, 2u8, 3u8, 5u8, 3u8], vec![7u8;2]),
		]);
	}
	#[test]
	fn fuzz1 () {
		compare_implementations(vec![
			(vec![01u8], vec![42u8, 9]),
			(vec![01u8, 0u8], vec![0u8, 0]),
			(vec![255u8, 2u8], vec![1u8, 0]),
		]);
	}
	#[test]
	fn fuzz2 () {
		compare_implementations(vec![
			(vec![0, 01u8], vec![42u8, 9]),
			(vec![0, 01u8, 0u8], vec![0u8, 0]),
			(vec![0, 255u8, 2u8], vec![1u8, 0]),
		]);
	}
	#[test]
	fn fuzz3 () {
		compare_implementations(vec![
			(vec![0], vec![196, 255]),
			(vec![48], vec![138, 255]),
			(vec![67], vec![0, 0]),
			(vec![128], vec![255, 0]),
			(vec![247], vec![0, 196]),
			(vec![255], vec![0, 0]),
		]);
	}
	#[test]
	fn fuzz_no_extension1 () {
		compare_implementations(vec![
			(vec![0], vec![128, 0]),
			(vec![128], vec![0, 0]),
		]);
	}
	#[test]
	fn fuzz_no_extension2 () {
		compare_implementations(vec![
			(vec![0], vec![6, 255]),
			(vec![6], vec![255, 186]),
			(vec![255], vec![186, 255]),
		]);
	}
	#[test]
	fn fuzz_no_extension5 () {
		compare_implementations(vec![
			(vec![0xaa], vec![0xa0]),
			(vec![0xaa, 0xaa], vec![0xaa]),
			(vec![0xaa, 0xbb], vec![0xab]),
			(vec![0xbb], vec![0xb0]),
			(vec![0xbb, 0xbb], vec![0xbb]),
			(vec![0xbb, 0xcc], vec![0xbc]),
		]);
	}
	#[test]
	fn fuzz_no_extension3 () {
		compare_implementations(vec![
			(vec![0], vec![0, 0]),
			(vec![11, 0], vec![0, 0]),
			(vec![11, 252], vec![11, 0]),
		]);

		compare_implementations_no_extension_unordered(vec![
			(vec![11, 252], vec![11, 0]),
			(vec![11, 0], vec![0, 0]),
			(vec![0], vec![0, 0]),
		]);
	}
	#[test]
	fn fuzz_no_extension4 () {
		compare_implementations_no_extension(vec![
			(vec![0x01, 0x56], vec![0x1]),
			(vec![0x02, 0x42], vec![0x2]),
			(vec![0x02, 0x50], vec![0x3]),
		]);
	}
	#[test]
	fn fuzz_no_extension_insert_remove_1 () {
		let data = vec![
			(false, vec![0], vec![251, 255]),
			(false, vec![0, 1], vec![251, 255]),
			(false, vec![0, 1, 2], vec![255; 32]),
			(true, vec![0, 1], vec![0, 251]),
		];
		compare_no_extension_insert_remove(data);
	}
	#[test]
	fn fuzz_no_extension_insert_remove_2 () {
		let data = vec![
			(false, vec![0x00], vec![0xfd, 0xff]),
			(false, vec![0x10, 0x00], vec![1;32]),
			(false, vec![0x11, 0x10], vec![0;32]),
			(true, vec![0x10, 0x00], vec![])
		];
		compare_no_extension_insert_remove(data);
	}
	#[test]
	fn two_bytes_nibble_length () {
		let data = vec![
			(vec![00u8], vec![0]),
			(vec![01u8;64], vec![0;32]),
		];
		compare_implementations_no_extension(data.clone());
		compare_implementations_no_extension_prefixed(data.clone());
	}
	#[test]
	#[should_panic]
	fn too_big_nibble_length_old () {
		compare_implementations_h(vec![
			(vec![01u8;64], vec![0;32]),
		]);
	}
	#[test]
	fn too_big_nibble_length_new () {
		compare_implementations_no_extension(vec![
			(vec![01u8;((u16::max_value() as usize + 1) / 2) + 1], vec![0;32]),
		]);
	}
	#[test]
	fn polka_re_test () {
		compare_implementations(vec![
			(vec![77, 111, 111, 55, 111, 104, 121, 97], vec![68, 97, 105, 55, 105, 101, 116, 111]),
			(vec![101, 105, 67, 104, 111, 111, 66, 56], vec![97, 56, 97, 113, 117, 53, 97]),
			(vec![105, 97, 48, 77, 101, 105, 121, 101], vec![69, 109, 111, 111, 82, 49, 97, 105]),
		]);
	}

}

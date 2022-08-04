// Copyright 2017, 2020 Parity Technologies
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

use crate::{
	nibble::{nibble_ops, NibbleSlice},
	node::Value,
	node_codec::NodeCodec,
	rstd::{cmp::max, marker::PhantomData, vec::Vec},
	triedbmut::ChildReference,
	DBValue, TrieHash, TrieLayout,
};
use hash_db::{HashDB, Hasher, Prefix};

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
struct CacheAccum<T: TrieLayout, V>(Vec<(ArrayNode<T>, Option<V>, usize)>);

/// Initially allocated cache depth.
const INITIAL_DEPTH: usize = 10;

impl<T, V> CacheAccum<T, V>
where
	T: TrieLayout,
	V: AsRef<[u8]>,
{
	fn new() -> Self {
		let v = Vec::with_capacity(INITIAL_DEPTH);
		CacheAccum(v)
	}

	#[inline(always)]
	fn set_cache_value(&mut self, depth: usize, value: Option<V>) {
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

	fn flush_value(
		&mut self,
		callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
		target_depth: usize,
		(k2, v2): &(impl AsRef<[u8]>, impl AsRef<[u8]>),
	) {
		let nibble_value = nibble_ops::left_nibble_at(&k2.as_ref()[..], target_depth);
		// is it a branch value (two candidate same ix)
		let nkey = NibbleSlice::new_offset(&k2.as_ref()[..], target_depth + 1);
		let pr = NibbleSlice::new_offset(
			&k2.as_ref()[..],
			k2.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE - nkey.len(),
		);

		let hashed;
		let value = if let Some(value) = Value::new_inline(v2.as_ref(), T::MAX_INLINE_VALUE) {
			value
		} else {
			hashed = callback.process_inner_hashed_value((k2.as_ref(), None), v2.as_ref());
			Value::Node(hashed.as_ref())
		};
		let encoded = T::Codec::leaf_node(nkey.right_iter(), nkey.len(), value);
		let hash = callback.process(pr.left(), encoded, false);

		// insert hash in branch (first level branch only at this point)
		self.set_node(target_depth, nibble_value as usize, Some(hash));
	}

	fn flush_branch(
		&mut self,
		callback: &mut impl ProcessEncodedNode<TrieHash<T>>,
		ref_branch: impl AsRef<[u8]> + Ord,
		new_depth: usize,
		is_last: bool,
	) {
		while self.last_depth() > new_depth || is_last && !self.is_empty() {
			let lix = self.last_depth();
			let llix = max(self.last_last_depth(), new_depth);

			let (offset, slice_size, is_root) = if llix == 0 && is_last && self.is_one() {
				// branch root
				(llix, lix - llix, true)
			} else {
				(llix + 1, lix - llix - 1, false)
			};
			let nkey = if slice_size > 0 { Some((offset, slice_size)) } else { None };

			let h = if T::USE_EXTENSION {
				self.standard_extension(&ref_branch.as_ref()[..], callback, lix, is_root, nkey)
			} else {
				// encode branch
				self.no_extension(&ref_branch.as_ref()[..], callback, lix, is_root, nkey)
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

		let (children, v, depth) = self.0.pop().expect("checked");

		debug_assert!(branch_d == depth);
		let pr = NibbleSlice::new_offset(&key_branch, branch_d);

		let hashed;
		let value = if let Some(v) = v.as_ref() {
			Some(if let Some(value) = Value::new_inline(v.as_ref(), T::MAX_INLINE_VALUE) {
				value
			} else {
				let mut prefix = NibbleSlice::new_offset(&key_branch, 0);
				prefix.advance(branch_d);
				hashed = callback.process_inner_hashed_value(prefix.left(), v.as_ref());
				Value::Node(hashed.as_ref())
			})
		} else {
			None
		};

		// encode branch
		let encoded = T::Codec::branch_node(children.iter(), value);
		let branch_hash = callback.process(pr.left(), encoded, is_root && nkey.is_none());

		if let Some(nkeyix) = nkey {
			let pr = NibbleSlice::new_offset(&key_branch, nkeyix.0);
			let nib = pr.right_range_iter(nkeyix.1);
			let encoded = T::Codec::extension_node(nib, nkeyix.1, branch_hash);
			callback.process(pr.left(), encoded, is_root)
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
		let (children, v, depth) = self.0.pop().expect("checked");

		debug_assert!(branch_d == depth);
		// encode branch
		let nkeyix = nkey.unwrap_or((branch_d, 0));
		let pr = NibbleSlice::new_offset(&key_branch, nkeyix.0);
		let hashed;
		let value = if let Some(v) = v.as_ref() {
			Some(if let Some(value) = Value::new_inline(v.as_ref(), T::MAX_INLINE_VALUE) {
				value
			} else {
				let mut prefix = NibbleSlice::new_offset(&key_branch, 0);
				prefix.advance(branch_d);
				hashed = callback.process_inner_hashed_value(prefix.left(), v.as_ref());
				Value::Node(hashed.as_ref())
			})
		} else {
			None
		};

		let encoded = T::Codec::branch_node_nibbled(
			pr.right_range_iter(nkeyix.1),
			nkeyix.1,
			children.iter(),
			value,
		);
		callback.process(pr.left(), encoded, is_root)
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
	let mut depth_queue = CacheAccum::<T, B>::new();
	// compare iter ordering
	let mut iter_input = input.into_iter();
	if let Some(mut previous_value) = iter_input.next() {
		// depth of last item
		let mut last_depth = 0;

		let mut single = true;
		for (k, v) in iter_input {
			single = false;
			let common_depth =
				nibble_ops::biggest_depth(&previous_value.0.as_ref()[..], &k.as_ref()[..]);
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
				depth_queue.flush_branch(callback, ref_branches, depth_item, false);
			}

			previous_value = (k, v);
			last_depth = depth_item;
		}
		// last pendings
		if single {
			// one single element corner case
			let (k2, v2) = previous_value;
			let nkey = NibbleSlice::new_offset(&k2.as_ref()[..], last_depth);
			let pr = NibbleSlice::new_offset(
				&k2.as_ref()[..],
				k2.as_ref().len() * nibble_ops::NIBBLE_PER_BYTE - nkey.len(),
			);

			let hashed;
			let value = if let Some(value) = Value::new_inline(v2.as_ref(), T::MAX_INLINE_VALUE) {
				value
			} else {
				hashed = callback.process_inner_hashed_value((k2.as_ref(), None), v2.as_ref());
				Value::Node(hashed.as_ref())
			};

			let encoded = T::Codec::leaf_node(nkey.right_iter(), nkey.len(), value);
			callback.process(pr.left(), encoded, true);
		} else {
			depth_queue.flush_value(callback, last_depth, &previous_value);
			let ref_branches = previous_value.0;
			depth_queue.flush_branch(callback, ref_branches, 0, true);
		}
	} else {
		// nothing null root corner case
		callback.process(hash_db::EMPTY_PREFIX, T::Codec::empty_node().to_vec(), true);
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
		encoded_node: Vec<u8>,
		is_root: bool,
	) -> ChildReference<HO>;

	/// Callback for hashed value in encoded node.
	fn process_inner_hashed_value(&mut self, prefix: Prefix, value: &[u8]) -> HO;
}

/// Get trie root and insert visited node in a hash_db.
/// As for all `ProcessEncodedNode` implementation, it
/// is only for full trie parsing (not existing trie).
pub struct TrieBuilder<'a, T: TrieLayout, DB> {
	db: &'a mut DB,
	pub root: Option<TrieHash<T>>,
}

impl<'a, T: TrieLayout, DB> TrieBuilder<'a, T, DB> {
	pub fn new(db: &'a mut DB) -> Self {
		TrieBuilder { db, root: None }
	}
}

impl<'a, T, DB> ProcessEncodedNode<TrieHash<T>> for TrieBuilder<'a, T, DB>
where
	T: TrieLayout,
	DB: HashDB<T::Hash, DBValue>,
{
	fn process(
		&mut self,
		prefix: Prefix,
		encoded_node: Vec<u8>,
		is_root: bool,
	) -> ChildReference<TrieHash<T>> {
		let len = encoded_node.len();
		if !is_root && len < <T::Hash as Hasher>::LENGTH {
			let mut h = <<T::Hash as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len)
		}
		let hash = self.db.insert(prefix, &encoded_node[..]);
		if is_root {
			self.root = Some(hash);
		};
		ChildReference::Hash(hash)
	}

	fn process_inner_hashed_value(&mut self, prefix: Prefix, value: &[u8]) -> TrieHash<T> {
		self.db.insert(prefix, value)
	}
}

/// Calculate the trie root of the trie.
pub struct TrieRoot<T: TrieLayout> {
	/// The resulting root.
	pub root: Option<TrieHash<T>>,
}

impl<T: TrieLayout> Default for TrieRoot<T> {
	fn default() -> Self {
		TrieRoot { root: None }
	}
}

impl<T: TrieLayout> ProcessEncodedNode<TrieHash<T>> for TrieRoot<T> {
	fn process(
		&mut self,
		_: Prefix,
		encoded_node: Vec<u8>,
		is_root: bool,
	) -> ChildReference<TrieHash<T>> {
		let len = encoded_node.len();
		if !is_root && len < <T::Hash as Hasher>::LENGTH {
			let mut h = <<T::Hash as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len)
		}
		let hash = <T::Hash as Hasher>::hash(encoded_node.as_slice());
		if is_root {
			self.root = Some(hash);
		};
		ChildReference::Hash(hash)
	}

	fn process_inner_hashed_value(&mut self, _prefix: Prefix, value: &[u8]) -> TrieHash<T> {
		<T::Hash as Hasher>::hash(value)
	}
}

/// Get the trie root node encoding.
pub struct TrieRootUnhashed<T: TrieLayout> {
	/// The resulting encoded root.
	pub root: Option<Vec<u8>>,
	_ph: PhantomData<T>,
}

impl<T: TrieLayout> Default for TrieRootUnhashed<T> {
	fn default() -> Self {
		TrieRootUnhashed { root: None, _ph: PhantomData }
	}
}

#[cfg(feature = "std")]
/// Calculate the trie root of the trie.
/// Print a debug trace.
pub struct TrieRootPrint<T: TrieLayout> {
	/// The resulting root.
	pub root: Option<TrieHash<T>>,
	_ph: PhantomData<T>,
}

#[cfg(feature = "std")]
impl<T: TrieLayout> Default for TrieRootPrint<T> {
	fn default() -> Self {
		TrieRootPrint { root: None, _ph: PhantomData }
	}
}

#[cfg(feature = "std")]
impl<T: TrieLayout> ProcessEncodedNode<TrieHash<T>> for TrieRootPrint<T> {
	fn process(
		&mut self,
		p: Prefix,
		encoded_node: Vec<u8>,
		is_root: bool,
	) -> ChildReference<TrieHash<T>> {
		println!("Encoded node: {:x?}", &encoded_node);
		println!("	with prefix: {:x?}", &p);
		let len = encoded_node.len();
		if !is_root && len < <T::Hash as Hasher>::LENGTH {
			let mut h = <<T::Hash as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			println!("	inline len {}", len);
			return ChildReference::Inline(h, len)
		}
		let hash = <T::Hash as Hasher>::hash(encoded_node.as_slice());
		if is_root {
			self.root = Some(hash);
		};
		println!("	hashed to {:x?}", hash.as_ref());
		ChildReference::Hash(hash)
	}

	fn process_inner_hashed_value(&mut self, _prefix: Prefix, value: &[u8]) -> TrieHash<T> {
		println!("Hashed node: {:x?}", &value);
		<T::Hash as Hasher>::hash(value)
	}
}

impl<T: TrieLayout> ProcessEncodedNode<TrieHash<T>> for TrieRootUnhashed<T> {
	fn process(
		&mut self,
		_: Prefix,
		encoded_node: Vec<u8>,
		is_root: bool,
	) -> ChildReference<<T::Hash as Hasher>::Out> {
		let len = encoded_node.len();
		if !is_root && len < <T::Hash as Hasher>::LENGTH {
			let mut h = <<T::Hash as Hasher>::Out as Default>::default();
			h.as_mut()[..len].copy_from_slice(&encoded_node[..len]);

			return ChildReference::Inline(h, len)
		}
		let hash = <T::Hash as Hasher>::hash(encoded_node.as_slice());

		if is_root {
			self.root = Some(encoded_node);
		};
		ChildReference::Hash(hash)
	}

	fn process_inner_hashed_value(&mut self, _prefix: Prefix, value: &[u8]) -> TrieHash<T> {
		<T::Hash as Hasher>::hash(value)
	}
}

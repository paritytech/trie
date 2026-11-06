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

//! A mutable trie that supports transactions.

use super::{
	Node, NodeHandle, NodeStorage, RootedNodeStorage, StorageHandle, Stored, TrieDBMutCore, Value,
};
use crate::{
	nibble::BackingByteVec,
	rstd::{mem, ops::Index, vec::Vec},
	CError, DBValue, Result, TrieCache, TrieHash, TrieLayout, TrieRecorder,
};
use core::sync::atomic::{AtomicU64, Ordering};
use hash_db::HashDBRef;

#[cfg(feature = "std")]
use crate::rstd::fmt;

/// Sequence of the next [`StorageMark`]. Shared by all storages, so a mark taken from another
/// storage is never live in this one.
static NEXT_MARK: AtomicU64 = AtomicU64::new(0);

/// Storage whose nodes in use at a live mark are never overwritten. A rewind cuts `nodes` back to
/// the length of the mark and frees again the slots reused since, which restores the trie as it
/// was then: a node written before a mark only references nodes that existed when the mark was
/// taken.
///
/// Nodes written since the newest mark are not seen by any snapshot, so their slots are reused.
/// Free slots stay free across a mark. A discard drops a mark and every later one, and the slots
/// only those marks kept alive are reused.
///
/// Retired database nodes are forgotten: this storage is never committed, and a rollback could
/// not undo a death row.
struct TransactionalNodeStorage<L: TrieLayout> {
	nodes: Vec<Stored<L>>,
	/// The marks that can still be rewound to, oldest first.
	live_marks: Vec<LiveMark>,
	/// Length of the arena at the newest live mark; nodes below it are never overwritten.
	frozen_below: usize,
	/// Slots that neither the trie nor any mark still on the stack uses.
	free_indices: Vec<usize>,
	/// Slots below `frozen_below` that the trie no longer uses, in the order they left it. They
	/// keep their node because a live mark may still use it. A discard moves those no live mark
	/// needs any more to `free_indices`.
	dead_slots: Vec<usize>,
	/// A rewind frees again the slots logged after its mark.
	reuse_log: ReuseLog,
}

impl<L: TrieLayout> TransactionalNodeStorage<L> {
	fn empty() -> Self {
		Self {
			nodes: Vec::new(),
			live_marks: Vec::new(),
			frozen_below: 0,
			free_indices: Vec::new(),
			dead_slots: Vec::new(),
			reuse_log: ReuseLog::default(),
		}
	}

	fn mark(&mut self) -> StorageMark {
		self.frozen_below = self.nodes.len();
		let mark = StorageMark {
			nodes: self.nodes.len(),
			sequence: NEXT_MARK.fetch_add(1, Ordering::Relaxed),
			dead_slots: self.dead_slots.len(),
			reused_slots: self.reuse_log.len(),
		};
		self.live_marks
			.push(LiveMark { mark, untouched_free_slots: self.free_indices.len() });
		mark
	}

	/// Position of `mark` in the live marks, if it can still be rewound to.
	fn live_position(&self, mark: &StorageMark) -> core::result::Result<usize, InvalidSnapshot> {
		self.live_marks
			.binary_search_by_key(&mark.sequence, |live| live.mark.sequence)
			.map_err(|_| InvalidSnapshot)
	}

	/// Cut the arena back to `mark`.
	///
	/// Fails, without touching the arena, if `mark` was taken from another storage or was dropped
	/// from the live marks by a rewind below it or by a discard.
	fn rewind(&mut self, mark: &StorageMark) -> core::result::Result<(), InvalidSnapshot> {
		let position = self.live_position(mark)?;
		let untouched_free_slots = self.live_marks[position..]
			.iter()
			.map(|live| live.untouched_free_slots)
			.min()
			.expect("position is live; qed");
		self.live_marks.truncate(position + 1);
		self.nodes.truncate(mark.nodes);
		self.frozen_below = mark.nodes;
		self.dead_slots.truncate(mark.dead_slots);
		self.free_indices.extend(self.reuse_log.drain_from(mark.reused_slots));
		let pushed_since_mark = self.free_indices.split_off(untouched_free_slots);
		self.free_indices
			.extend(pushed_since_mark.into_iter().filter(|slot| *slot < mark.nodes));
		self.live_marks[position].untouched_free_slots = self.free_indices.len();
		self.reuse_log.truncate_arena(mark.nodes);
		debug_assert_eq!(self.reuse_log.positions.len(), self.nodes.len());
		Ok(())
	}

	/// Drop `mark` and every later mark, and reuse the slots only they kept alive.
	///
	/// Fails, without touching the arena, under the same conditions as [`Self::rewind`].
	fn discard_from(&mut self, mark: &StorageMark) -> core::result::Result<(), InvalidSnapshot> {
		let position = self.live_position(mark)?;
		let dropped_untouched = self
			.live_marks
			.drain(position..)
			.map(|live| live.untouched_free_slots)
			.min()
			.expect("position is live; qed");
		if let Some(newest) = self.live_marks.last_mut() {
			newest.untouched_free_slots = newest.untouched_free_slots.min(dropped_untouched);
		}
		let frozen_below = self.live_marks.last().map_or(0, |newest| newest.mark.nodes);
		self.frozen_below = frozen_below;
		self.reuse_log.retain_from(mark.reused_slots, |slot| slot < frozen_below);
		for slot in self.dead_slots.split_off(mark.dead_slots) {
			if self.needed_by_a_live_mark(slot) {
				self.dead_slots.push(slot);
			} else {
				self.free(slot);
			}
		}
		Ok(())
	}

	/// Length of the reuse log at the newest mark.
	fn reused_at_newest_mark(&self) -> usize {
		self.live_marks.last().map_or(0, |live| live.mark.reused_slots)
	}

	/// Whether a live mark still needs the node in `slot`: the slot is below the freeze line and
	/// was not written after the newest mark.
	fn needed_by_a_live_mark(&self, slot: usize) -> bool {
		slot < self.frozen_below && !self.reuse_log.logged_since(slot, self.reused_at_newest_mark())
	}

	/// Makes `slot` free, forgetting its reuse if it was logged.
	fn free(&mut self, slot: usize) {
		self.reuse_log.remove(slot);
		self.free_indices.push(slot);
	}
}

/// Free slots below the freeze line that were reused. Truncating the arena does not free them, so
/// a rewind frees those logged since its mark.
///
/// A watermark is the log's length at a mark: the slots logged since that mark are at or after
/// it. Each slot can be removed in constant time.
#[derive(Default)]
struct ReuseLog {
	slots: Vec<usize>,
	/// Position of each slot in `slots`, one entry per slot in the arena.
	positions: Vec<Option<usize>>,
}

impl ReuseLog {
	fn len(&self) -> usize {
		self.slots.len()
	}

	/// Logs given `slot` as reused.
	fn push(&mut self, slot: usize) {
		self.positions[slot] = Some(self.slots.len());
		self.slots.push(slot);
	}

	/// Whether `slot` was logged at or after `watermark`.
	fn logged_since(&self, slot: usize, watermark: usize) -> bool {
		self.positions[slot].is_some_and(|position| position >= watermark)
	}

	/// Forgets `slot` if it is logged.
	fn remove(&mut self, slot: usize) {
		let Some(position) = self.positions[slot].take() else { return };
		self.slots.swap_remove(position);
		if let Some(moved) = self.slots.get(position) {
			self.positions[*moved] = Some(position);
		}
	}

	/// Remove the slots logged since `watermark`.
	fn drain_from(&mut self, watermark: usize) -> impl Iterator<Item = usize> + '_ {
		let positions = &mut self.positions;
		self.slots.drain(watermark..).inspect(move |slot| positions[*slot] = None)
	}

	/// Of the slots logged since `watermark`, keep only those that pass `keep`.
	fn retain_from(&mut self, watermark: usize, keep: impl Fn(usize) -> bool) {
		for slot in self.slots.split_off(watermark) {
			if keep(slot) {
				self.push(slot);
			} else {
				self.positions[slot] = None;
			}
		}
	}

	fn grow_arena(&mut self) {
		self.positions.push(None);
	}

	fn truncate_arena(&mut self, len: usize) {
		self.positions.truncate(len);
	}
}

/// The snapshot does not describe the trie: it was taken from another trie, the trie was rolled
/// back to a point before it, or it was discarded.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct InvalidSnapshot;

#[cfg(feature = "std")]
impl fmt::Display for InvalidSnapshot {
	fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
		write!(f, "The snapshot was taken from another trie or dropped by a rollback or a discard")
	}
}

#[cfg(feature = "std")]
impl std::error::Error for InvalidSnapshot {}

/// Where a [`TransactionalNodeStorage`] stood when a snapshot was taken.
#[derive(Clone, Copy)]
struct StorageMark {
	/// Arena length at the mark. A rewind cuts the arena back to it, and the freeze line returns
	/// to it after a rewind or a discard.
	nodes: usize,
	/// Identifies the mark on the stack. Later marks have higher sequences.
	sequence: u64,
	/// Length of `dead_slots` at the mark. A rewind cuts the list back to it: slots that died
	/// later are in the trie again. A discard only looks at the slots that died later.
	dead_slots: usize,
	/// Length of the reuse log at the mark. A rewind frees again the slots handed out later. A
	/// discard only looks at those.
	reused_slots: usize,
}

/// A mark that can still be rewound to.
struct LiveMark {
	mark: StorageMark,
	/// Lowest length of `free_indices` while the mark was the newest, so that much of its start
	/// did not change in that time. A rewind to the mark starts the count again.
	untouched_free_slots: usize,
}

impl<L: TrieLayout> NodeStorage<L> for TransactionalNodeStorage<L> {
	fn alloc(&mut self, stored: Stored<L>) -> StorageHandle {
		if let Some(idx) = self.free_indices.pop() {
			if let Some(newest) = self.live_marks.last_mut() {
				newest.untouched_free_slots =
					newest.untouched_free_slots.min(self.free_indices.len());
			}
			if idx < self.frozen_below {
				self.reuse_log.push(idx);
			}
			self.nodes[idx] = stored;
			StorageHandle(idx)
		} else {
			self.nodes.push(stored);
			self.reuse_log.grow_arena();
			debug_assert_eq!(self.reuse_log.positions.len(), self.nodes.len());
			StorageHandle(self.nodes.len() - 1)
		}
	}

	fn destroy(&mut self, handle: StorageHandle) -> Stored<L> {
		let index = handle.0;
		if self.needed_by_a_live_mark(index) {
			self.dead_slots.push(index);
			return self.nodes[index].clone()
		}
		self.free(index);
		mem::replace(&mut self.nodes[index], Stored::New(Node::Empty))
	}

	fn retire(&mut self, _hash: TrieHash<L>, _prefix: (BackingByteVec, Option<u8>)) {}
}

impl<'a, L: TrieLayout> Index<&'a StorageHandle> for TransactionalNodeStorage<L> {
	type Output = Node<L>;

	fn index(&self, handle: &'a StorageHandle) -> &Node<L> {
		self.nodes[handle.0].node()
	}
}

impl<L: TrieLayout> RootedNodeStorage<L, TransactionalNodeStorage<L>> {
	fn snapshot(&mut self) -> TrieDBMutSnapshot<L> {
		TrieDBMutSnapshot { root_handle: self.root_handle.clone(), storage_mark: self.nodes.mark() }
	}

	fn rollback_to(
		&mut self,
		snapshot: &TrieDBMutSnapshot<L>,
	) -> core::result::Result<(), InvalidSnapshot> {
		self.nodes.rewind(&snapshot.storage_mark)?;
		self.root_handle = snapshot.root_handle.clone();
		Ok(())
	}

	fn discard_from(
		&mut self,
		snapshot: &TrieDBMutSnapshot<L>,
	) -> core::result::Result<(), InvalidSnapshot> {
		self.nodes.discard_from(&snapshot.storage_mark)
	}
}

/// In-memory state of a [`TransactionalTrieDBMut`], detached from its borrows.
///
/// Created with [`Self::new`] and borrowed by [`TransactionalTrieDBMutBuilder::from_detached`]. The
/// trie writes its changes here as it makes them. An insert or remove that fails can leave the
/// trie inconsistent: the nodes it took apart are gone, but the root still points at them.
/// Rolling back to a snapshot taken before the operation restores the trie.
pub struct DetachedTrieDBMut<L: TrieLayout> {
	storage: RootedNodeStorage<L, TransactionalNodeStorage<L>>,
}

impl<L: TrieLayout> DetachedTrieDBMut<L> {
	/// The trie at `root`, without in-memory nodes.
	pub fn new(root: TrieHash<L>) -> Self {
		Self {
			storage: RootedNodeStorage {
				nodes: TransactionalNodeStorage::empty(),
				root_handle: NodeHandle::Hash(root),
			},
		}
	}

	/// Take a snapshot to roll back to, see [`TransactionalTrieDBMut::snapshot`].
	pub fn snapshot(&mut self) -> TrieDBMutSnapshot<L> {
		self.storage.snapshot()
	}

	/// Roll back to `snapshot`, see [`TransactionalTrieDBMut::rollback_to`].
	///
	/// Fails, leaving the state as it is, if `snapshot` was taken from another trie, the state was
	/// rolled back to a point before it, or it was discarded.
	pub fn rollback_to(
		&mut self,
		snapshot: &TrieDBMutSnapshot<L>,
	) -> core::result::Result<(), InvalidSnapshot> {
		self.storage.rollback_to(snapshot)
	}

	/// Discard `snapshot` and every later one, see [`TransactionalTrieDBMut::discard_from`].
	///
	/// Fails, leaving the state as it is, under the same conditions as [`Self::rollback_to`].
	pub fn discard_from(
		&mut self,
		snapshot: &TrieDBMutSnapshot<L>,
	) -> core::result::Result<(), InvalidSnapshot> {
		self.storage.discard_from(snapshot)
	}
}

/// A point a [`TransactionalTrieDBMut`] can be rolled back to.
///
/// A snapshot becomes invalid once the trie is rolled back to a point before it or it is
/// discarded. Rolling back to an invalid snapshot fails with [`InvalidSnapshot`].
pub struct TrieDBMutSnapshot<L: TrieLayout> {
	root_handle: NodeHandle<TrieHash<L>>,
	storage_mark: StorageMark,
}

// Not derived, as that would require `L: Clone`.
impl<L: TrieLayout> Clone for TrieDBMutSnapshot<L> {
	fn clone(&self) -> Self {
		Self { root_handle: self.root_handle.clone(), storage_mark: self.storage_mark }
	}
}

/// A builder for creating a [`TransactionalTrieDBMut`].
pub struct TransactionalTrieDBMutBuilder<'db, L: TrieLayout> {
	db: &'db dyn HashDBRef<L::Hash, DBValue>,
	cache: Option<&'db mut dyn TrieCache<L::Codec>>,
	recorder: Option<&'db mut dyn TrieRecorder<TrieHash<L>>>,
	detached: &'db mut DetachedTrieDBMut<L>,
}

impl<'db, L: TrieLayout> TransactionalTrieDBMutBuilder<'db, L> {
	/// Create a builder that continues a trie from its `detached` state, with the backing
	/// database `db`.
	///
	/// This doesn't check if the root of `detached` exists in the given `db`. If it doesn't exist
	/// it will fail when trying to lookup any key.
	pub fn from_detached(
		db: &'db dyn HashDBRef<L::Hash, DBValue>,
		detached: &'db mut DetachedTrieDBMut<L>,
	) -> Self {
		Self { db, cache: None, recorder: None, detached }
	}

	/// Use the given `cache` for the db.
	pub fn with_cache(mut self, cache: &'db mut dyn TrieCache<L::Codec>) -> Self {
		self.cache = Some(cache);
		self
	}

	/// Use the given optional `cache` for the db.
	pub fn with_optional_cache<'cache: 'db>(
		mut self,
		cache: Option<&'cache mut dyn TrieCache<L::Codec>>,
	) -> Self {
		// Make the compiler happy by "converting" the lifetime
		self.cache = cache.map(|c| c as _);
		self
	}

	/// Use the given `recorder` to record trie accesses.
	pub fn with_recorder(mut self, recorder: &'db mut dyn TrieRecorder<TrieHash<L>>) -> Self {
		self.recorder = Some(recorder);
		self
	}

	/// Use the given optional `recorder` to record trie accesses.
	pub fn with_optional_recorder<'recorder: 'db>(
		mut self,
		recorder: Option<&'recorder mut dyn TrieRecorder<TrieHash<L>>>,
	) -> Self {
		// Make the compiler happy by "converting" the lifetime
		self.recorder = recorder.map(|r| r as _);
		self
	}

	/// Build the [`TransactionalTrieDBMut`].
	pub fn build(self) -> TransactionalTrieDBMut<'db, L> {
		TransactionalTrieDBMut {
			core: TrieDBMutCore {
				db: self.db,
				cache: self.cache,
				recorder: self.recorder.map(core::cell::RefCell::new),
				storage: &mut self.detached.storage,
			},
		}
	}
}

/// A mutable trie whose changes can be rolled back.
///
/// A transaction is a snapshot taken at its start, see [`Self::snapshot`]. If the transaction
/// fails, roll back to it with [`Self::rollback_to`]. If it commits, discard it with
/// [`Self::discard_from`]. Discarding a snapshot also discards every snapshot taken after it.
///
/// The in-memory state lives in the [`DetachedTrieDBMut`] borrowed by
/// [`TransactionalTrieDBMutBuilder::from_detached`], and every change is written there directly,
/// so a rollback can undo a failed operation.
///
/// The trie is never committed: it reads the backing database but never writes to it, and it
/// never writes a root. Nodes replaced by later changes are reused, except those a snapshot may
/// still need, which stay allocated until a rollback or a discard frees them, or the detached
/// storage is dropped.
pub struct TransactionalTrieDBMut<'a, L>
where
	L: TrieLayout,
{
	core: TrieDBMutCore<
		'a,
		L,
		&'a mut RootedNodeStorage<L, TransactionalNodeStorage<L>>,
		&'a dyn HashDBRef<L::Hash, DBValue>,
	>,
}

impl<'a, L> TransactionalTrieDBMut<'a, L>
where
	L: TrieLayout,
{
	/// Is the trie empty?
	pub fn is_empty(&self) -> bool {
		self.core.is_empty()
	}

	/// Does the trie contain a given key?
	pub fn contains(&self, key: &[u8]) -> Result<bool, TrieHash<L>, CError<L>> {
		self.get(key).map(|value| value.is_some())
	}

	/// What is the value of the given key in this trie?
	pub fn get(&self, key: &[u8]) -> Result<Option<DBValue>, TrieHash<L>, CError<L>> {
		self.core.get(key)
	}

	/// Insert a `key`/`value` pair into the trie. An empty value is equivalent to removing
	/// `key` from the trie. Returns the old value associated with this key, if it existed.
	pub fn insert(
		&mut self,
		key: &[u8],
		value: &[u8],
	) -> Result<Option<Value<L>>, TrieHash<L>, CError<L>> {
		self.core.insert(key, value)
	}

	/// Remove a `key` from the trie. Equivalent to making it equal to the empty
	/// value. Returns the old value associated with this key, if it existed.
	pub fn remove(&mut self, key: &[u8]) -> Result<Option<Value<L>>, TrieHash<L>, CError<L>> {
		self.core.remove(key)
	}

	/// Take a snapshot to later roll back to. Cheap: it does not copy the trie.
	///
	/// Takes `&mut self` because nodes written before the snapshot are no longer reused in place.
	pub fn snapshot(&mut self) -> TrieDBMutSnapshot<L> {
		self.core.storage.snapshot()
	}

	/// Roll back all changes made since `snapshot` was taken.
	///
	/// Only the trie is restored: what the recorder recorded and the cache cached since the
	/// snapshot stays.
	///
	/// Fails, leaving the trie as it is, if `snapshot` was taken from another trie, the trie was
	/// rolled back to a point before it, or it was discarded.
	pub fn rollback_to(
		&mut self,
		snapshot: &TrieDBMutSnapshot<L>,
	) -> core::result::Result<(), InvalidSnapshot> {
		self.core.storage.rollback_to(snapshot)
	}

	/// Discards `snapshot` and every snapshot taken after it: none of them can be rolled back
	/// to any more, and the nodes only they kept alive are reused. The trie is not changed.
	///
	/// Fails, leaving the trie as it is, under the same conditions as [`Self::rollback_to`].
	pub fn discard_from(
		&mut self,
		snapshot: &TrieDBMutSnapshot<L>,
	) -> core::result::Result<(), InvalidSnapshot> {
		self.core.storage.discard_from(snapshot)
	}

	/// Number of slots in the in-memory node arena, freed ones included. A diagnostic for tests,
	/// not part of the stable API.
	#[doc(hidden)]
	pub fn arena_len(&self) -> usize {
		self.core.storage.nodes.nodes.len()
	}
}

// Copyright 2020 Parity Technologies
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

//! This module contains traits and structs related to the `MallocSizeOf` trait.

use core::marker::PhantomData;
use parity_util_mem::{malloc_size, MallocSizeOf};

/// Used to implement incremental evaluation of `MallocSizeOf` for a collection.
pub trait MemTracker<T> {
	/// Update `malloc_size_of` when a value is removed.
	fn on_remove(&mut self, _value: &T) {}
	/// Update `malloc_size_of` when a value is inserted.
	fn on_insert(&mut self, _value: &T) {}
	/// Reset `malloc_size_of` to zero.
	fn on_clear(&mut self) {}
	/// Get the allocated size of the values.
	fn get_size(&self) -> usize {
		0
	}
}

/// `MemTracker` implementation for types
/// which implement `MallocSizeOf`.
#[derive(Eq, PartialEq)]
pub struct MemCounter<T> {
	malloc_size_of_values: usize,
	_phantom: PhantomData<T>,
}

impl<T> MemCounter<T> {
	// Create a new instance of MemCounter<T>.
	pub fn new() -> Self {
		Self { malloc_size_of_values: 0, _phantom: PhantomData }
	}
}

impl<T> Default for MemCounter<T> {
	fn default() -> Self {
		Self::new()
	}
}

impl<T> Clone for MemCounter<T> {
	fn clone(&self) -> Self {
		Self { malloc_size_of_values: self.malloc_size_of_values, _phantom: PhantomData }
	}
}

impl<T> Copy for MemCounter<T> {}

impl<T: MallocSizeOf> MemTracker<T> for MemCounter<T> {
	fn on_remove(&mut self, value: &T) {
		self.malloc_size_of_values -= malloc_size(value);
	}
	fn on_insert(&mut self, value: &T) {
		self.malloc_size_of_values += malloc_size(value);
	}
	fn on_clear(&mut self) {
		self.malloc_size_of_values = 0;
	}
	fn get_size(&self) -> usize {
		self.malloc_size_of_values
	}
}

/// No-op `MemTracker` implementation for when we want to
/// construct a `MemoryDB` instance that does not track memory usage.
#[derive(PartialEq, Eq)]
pub struct NoopTracker<T>(PhantomData<T>);

impl<T> Default for NoopTracker<T> {
	fn default() -> Self {
		Self(PhantomData)
	}
}

impl<T> Clone for NoopTracker<T> {
	fn clone(&self) -> Self {
		Self::default()
	}
}

impl<T> Copy for NoopTracker<T> {}

impl<T> MemTracker<T> for NoopTracker<T> {}

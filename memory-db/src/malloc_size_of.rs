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
pub trait MallocSizeOfCallback<T> {
	/// Update `malloc_size_of` when a value is removed.
	fn on_value_removed(&mut self, _value: &T) {}
	/// Update `malloc_size_of` when a value is inserted.
	fn on_value_inserted(&mut self, _value: &T) {}
	/// Reset `malloc_size_of` to zero.
	fn on_clear(&mut self) {}
	/// Get the allocated size of the values.
	fn get(&self) -> usize { 0 }
}

/// `MallocSizeOfCallback` implementation for types
/// which implement `MallocSizeOf`.
#[derive(Eq, PartialEq)]
pub struct CountingCallback<T> {
	malloc_size_of_values: usize,
	_phantom: PhantomData<T>,
}

impl<T> CountingCallback<T> {
	// Create a new instance of CountingCallback<T>.
	pub fn new() -> Self {
		Self {
			malloc_size_of_values: 0,
			_phantom: PhantomData,
		}
	}
}

impl<T> Default for CountingCallback<T> {
	fn default() -> Self {
		Self::new()
	}
}

impl<T> Clone for CountingCallback<T> {
	fn clone(&self) -> Self {
		Self {
			malloc_size_of_values: self.malloc_size_of_values,
			_phantom: PhantomData,
		}
	}
}

impl<T> Copy for CountingCallback<T> {}

impl<T: MallocSizeOf> MallocSizeOfCallback<T> for CountingCallback<T> {
	fn on_value_removed(&mut self, value: &T) {
		self.malloc_size_of_values -= malloc_size(value);
	}
	fn on_value_inserted(&mut self, value: &T) {
		self.malloc_size_of_values += malloc_size(value);
	}
	fn on_clear(&mut self) {
		self.malloc_size_of_values = 0;
	}
	fn get(&self) -> usize {
		self.malloc_size_of_values
	}
}

/// No-op `MallocSizeOfCallback` implementation.
#[derive(Default, Debug, Clone, Copy, PartialEq, Eq)]
pub struct NoopCallback;

impl<T> MallocSizeOfCallback<T> for NoopCallback {}

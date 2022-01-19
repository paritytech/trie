// Copyright 2021, 2021 Parity Technologies
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
#![cfg_attr(not(feature = "std"), no_std)]

#[cfg(feature = "std")]
mod rstd {
	pub use std::{result, vec};
}

#[cfg(not(feature = "std"))]
mod rstd {
	pub use alloc::vec;
	pub use core::result;
	pub trait Error {}
	impl<T> Error for T {}
}

mod eip1186;
pub use eip1186::{generate_proof, verify_proof, VerifyError};

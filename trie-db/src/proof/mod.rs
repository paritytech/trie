// Copyright 2019, 2020 Parity Technologies
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

//! Generation and verification of compact proofs for Merkle-Patricia tries.
//!
//! Using this module, it is possible to generate a logarithmic-space proof of inclusion or
//! non-inclusion of certain key-value pairs in a trie with a known root. The proof contains
//! information so that the verifier can reconstruct the subset of nodes in the trie required to
//! lookup the keys. The trie nodes are not included in their entirety as data which the verifier
//! can compute for themself is omitted. In particular, the values of included keys and and hashes
//! of other trie nodes in the proof are omitted.
//!
//! The proof is a sequence of the subset of nodes in the trie traversed while performing lookups
//! on all keys. The trie nodes are listed in pre-order traversal order with some values and
//! internal hashes omitted. In particular, values on leaf nodes, child references on extension
//! nodes, values on branch nodes corresponding to a key in the statement, and child references on
//! branch nodes corresponding to another node in the proof are all omitted. The proof is verified
//! by iteratively reconstructing the trie nodes using the values proving as part of the statement
//! and the hashes of other reconstructed nodes. Since the nodes in the proof are arranged in
//! pre-order traversal order, the construction can be done efficiently using a stack.

pub use self::{
	generate::generate_proof,
	verify::{verify_proof, Error as VerifyError},
};

mod generate;
mod verify;

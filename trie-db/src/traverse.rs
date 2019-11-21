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

//! Alternative to iterator for traversing a trie.
//!
//! The traversal stack is updatable, and this is therefore usable for
//! batch update of ordered key values.

/// StackedNode can be updated.
pub enum StackedNode<'a> {
	// after #34 do switch to &'a[u8] and NodePlan, for now just
	// decode as needed
	// Unchanged(&'a[u8]),
	Unchanged(&'a[u8], Node<'a>),
	Changed(OwnedNode),
}

/// Visitor trait to implement when using `trie_visit`.
pub trait ProcessEncodedNode<HO> {
	fn enter(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode, is_root: bool);
	fn exit(&mut self, prefix: &NibbleVec, stacked: &mut StackedNode, is_root: bool);
}



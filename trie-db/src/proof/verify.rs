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

//! Verification of compact proofs for Merkle-Patricia tries.

use crate::rstd::{
	convert::TryInto, iter::Peekable, marker::PhantomData, result::Result, vec, vec::Vec,
	iter::from_fn, iter::FromFn,
};
use crate::{
	CError, ChildReference, nibble::LeftNibbleSlice, nibble_ops::NIBBLE_LENGTH,
	node::{Node, NodeHandle}, NodeCodec, TrieHash, TrieLayout, EncodedNoChild,
};
use hash_db::Hasher;
use ordered_trie::{BinaryHasher, HasherComplex};
use crate::node_codec::{Bitmap, BITMAP_LENGTH};


/// Errors that may occur during proof verification. Most of the errors types simply indicate that
/// the proof is invalid with respect to the statement being verified, and the exact error type can
/// be used for debugging.
#[derive(PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum Error<HO, CE> {
	/// The statement being verified contains multiple key-value pairs with the same key. The
	/// parameter is the duplicated key.
	DuplicateKey(Vec<u8>),
	/// The proof contains at least one extraneous node.
	ExtraneousNode,
	/// The proof contains at least one extraneous value which should have been omitted from the
	/// proof.
	ExtraneousValue(Vec<u8>),
	/// The proof contains at least one extraneous hash reference the should have been omitted.
	ExtraneousHashReference(HO),
	/// The proof contains an invalid child reference that exceeds the hash length.
	InvalidChildReference(Vec<u8>),
	/// The proof indicates that an expected value was not found in the trie.
	ValueMismatch(Vec<u8>),
	/// The proof is missing trie nodes required to verify.
	IncompleteProof,
	/// The root hash computed from the proof is incorrect.
	RootMismatch(HO),
	/// One of the proof nodes could not be decoded.
	DecodeError(CE),
}

#[cfg(feature = "std")]
impl<HO: std::fmt::Debug, CE: std::error::Error> std::fmt::Display for Error<HO, CE> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		match self {
			Error::DuplicateKey(key) =>
				write!(f, "Duplicate key in input statement: key={:?}", key),
			Error::ExtraneousNode =>
				write!(f, "Extraneous node found in proof"),
			Error::ExtraneousValue(key) =>
				write!(
					f,
					"Extraneous value found in proof should have been omitted: key={:?}",
					key
				),
			Error::ExtraneousHashReference(hash) =>
				write!(
					f,
					"Extraneous hash reference found in proof should have been omitted: hash={:?}",
					hash
				),
			Error::InvalidChildReference(data) =>
				write!(f, "Invalid child reference exceeds hash length: {:?}", data),
			Error::ValueMismatch(key) =>
				write!(f, "Expected value was not found in the trie: key={:?}", key),
			Error::IncompleteProof =>
				write!(f, "Proof is incomplete -- expected more nodes"),
			Error::RootMismatch(hash) =>
				write!(f, "Computed incorrect root {:?} from proof", hash),
			Error::DecodeError(err) =>
				write!(f, "Unable to decode proof node: {}", err),
		}
	}
}

#[cfg(feature = "std")]
impl<HO: std::fmt::Debug, CE: std::error::Error + 'static> std::error::Error for Error<HO, CE> {
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			Error::DecodeError(err) => Some(err),
			_ => None,
		}
	}
}

struct StackEntry<'a, C: NodeCodec, H> {
	/// The prefix is the nibble path to the node in the trie.
	prefix: LeftNibbleSlice<'a>,
	node: Node<'a>,
	is_inline: bool,
	/// The value associated with this trie node.
	value: Option<&'a [u8]>,
	/// The next entry in the stack is a child of the preceding entry at this index. For branch
	/// nodes, the index is in [0, NIBBLE_LENGTH] and for extension nodes, the index is in [0, 1].
	child_index: usize,
	/// The child references to use in reconstructing the trie nodes.
	children: Vec<Option<ChildReference<C::HashOut>>>,
	complex: Option<(Bitmap, Vec<C::HashOut>)>,
	_marker: PhantomData<(C, H)>,
}

impl<'a, C: NodeCodec, H: BinaryHasher> StackEntry<'a, C, H>
	where
		H: BinaryHasher<Out = C::HashOut>,
{
	fn new(node_data: &'a [u8], prefix: LeftNibbleSlice<'a>, is_inline: bool, complex: bool)
		   -> Result<Self, Error<C::HashOut, C::Error>>
	{
		let children_len = NIBBLE_LENGTH;
		let mut	children = vec![None; NIBBLE_LENGTH]; // TODO use array
		let (node, complex) = if !is_inline && complex {
			// TODO factorize with trie_codec
			let encoded_node = node_data;
			let (mut node, mut offset) = C::decode_no_child(encoded_node)
				.map_err(Error::DecodeError)?;
			match &mut node {
				Node::Branch(b_child, _) | Node::NibbledBranch(_, b_child, _) => {
					if encoded_node.len() < offset + 3 {
						// TODO new error or move this parte to codec trait and use codec error
						return Err(Error::IncompleteProof);
					}
					let keys_position = Bitmap::decode(&encoded_node[offset..offset + BITMAP_LENGTH]);
					offset += BITMAP_LENGTH;

					let mut nb_additional;
					// inline nodes
					loop {
						let nb = encoded_node[offset] as usize;
						offset += 1;
						if nb >= 128 {
							nb_additional = nb - 128;
							break;
						}
						if encoded_node.len() < offset + nb + 2 {
							return Err(Error::IncompleteProof);
						}
						let ix = encoded_node[offset] as usize;
						offset += 1;
						let inline = &encoded_node[offset..offset + nb];
						if ix >= NIBBLE_LENGTH {
							return Err(Error::IncompleteProof);
						}
						b_child[ix] = Some(NodeHandle::Inline(inline));
						offset += nb;
					}
					let hash_len = <H as BinaryHasher>::NULL_HASH.len();
					let additional_len = nb_additional * hash_len;
					if encoded_node.len() < offset + additional_len {
						return Err(Error::IncompleteProof);
					}
					let additional_hashes = from_fn(move || {
						if nb_additional > 0 {
							let mut hash = <H::Out>::default();
							hash.as_mut().copy_from_slice(&encoded_node[offset..offset + hash_len]);
							offset += hash_len;
							nb_additional -= 1;
							Some(hash)
						} else {
							None
						}
					});
					// TODO dedicated iterator type instead of from_fn to avoid alloc
					let additional_hashes: Vec<H::Out> = additional_hashes.collect();
					(node, Some((keys_position, additional_hashes)))
				},
				_ => (node, None),
			}
		} else {
			(C::decode(node_data)
				.map_err(Error::DecodeError)?, None)
		};
		let value = match node {
			Node::Empty | Node::Extension(_, _) => None,
			Node::Leaf(_, value) => Some(value),
			Node::Branch(_, value) | Node::NibbledBranch(_, _, value) => value,
		};


		Ok(StackEntry {
			node,
			is_inline,
			prefix,
			value,
			child_index: 0,
			children,
			complex,
			_marker: PhantomData::default(),
		})
	}

	/// Encode this entry to an encoded trie node with data properly reconstructed.
	fn encode_node(&mut self) -> Result<(Vec<u8>, EncodedNoChild), Error<C::HashOut, C::Error>> {
		self.complete_children()?;
		Ok(match self.node {
			Node::Empty =>
				(C::empty_node().to_vec(), EncodedNoChild::Unused),
			Node::Leaf(partial, _) => {
				let value = self.value
					.expect(
						"value is assigned to Some in StackEntry::new; \
						value is only ever reassigned in the ValueMatch::MatchesLeaf match \
						clause, which assigns only to Some"
					);
				(C::leaf_node(partial.right(), value), EncodedNoChild::Unused)
			}
			Node::Extension(partial, _) => {
				let child = self.children[0]
					.expect("the child must be completed since child_index is 1");
				(C::extension_node(
					partial.right_iter(),
					partial.len(),
					child
				), EncodedNoChild::Unused)
			}
			Node::Branch(_, _) => {
				let mut register_children: [Option<_>; NIBBLE_LENGTH] = Default::default();
				let register_children = &mut register_children[..];
				C::branch_node(
					self.children.iter(),
					self.value,
					Some(register_children), // TODO again unused register result
				)
			},
			Node::NibbledBranch(partial, _, _) => {
				let mut register_children: [Option<_>; NIBBLE_LENGTH] = Default::default();
				let register_children = &mut register_children[..];
				C::branch_node_nibbled(
					partial.right_iter(),
					partial.len(),
					self.children.iter(),
					self.value,
					Some(register_children), // TODO again unused register result
				)
			},
		})
	}

	fn advance_child_index<I>(
		&mut self,
		child_prefix: LeftNibbleSlice<'a>,
		proof_iter: &mut I,
		complex: bool,
	) -> Result<Self, Error<C::HashOut, C::Error>>
		where
			I: Iterator<Item=&'a Vec<u8>>,
	{
		match self.node {
			Node::Extension(_, child) => {
				// Guaranteed because of sorted keys order.
				assert_eq!(self.child_index, 0);
				Self::make_child_entry(proof_iter, child, child_prefix, complex)
			}
			Node::Branch(children, _) | Node::NibbledBranch(_, children, _) => {
				// because this is a branch
				assert!(child_prefix.len() > 0);
				let child_index = child_prefix.at(child_prefix.len() - 1)
					.expect("it's less than prefix.len(); qed")
					as usize;
				while self.child_index < child_index {
					if let Some(child) = children[self.child_index] {
						let child_ref = child.try_into()
							.map_err(Error::InvalidChildReference)?;
						self.children[self.child_index] = Some(child_ref);
					}
					self.child_index += 1;
				}
				let child = children[self.child_index]
					.expect("guaranteed by advance_item");
				Self::make_child_entry(proof_iter, child, child_prefix, complex)
			}
			_ => panic!("cannot have children"),
		}
	}

	/// Populate the remaining references in `children` with references copied the node itself.
	fn complete_children(&mut self) -> Result<(), Error<C::HashOut, C::Error>> {
		match self.node {
			Node::Extension(_, child) if self.child_index == 0 => {
				let child_ref = child.try_into()
					.map_err(Error::InvalidChildReference)?;
				self.children[self.child_index] = Some(child_ref);
				self.child_index += 1;
			}
			Node::Branch(children, _) | Node::NibbledBranch(_, children, _) => {
				while self.child_index < NIBBLE_LENGTH {
					if let Some(child) = children[self.child_index] {
						let child_ref = child.try_into()
							.map_err(Error::InvalidChildReference)?;
						self.children[self.child_index] = Some(child_ref);
					}
					self.child_index += 1;
				}
			}
			_ => {}
		}
		Ok(())
	}

	fn make_child_entry<I>(
		proof_iter: &mut I,
		child: NodeHandle<'a>,
		prefix: LeftNibbleSlice<'a>,
		complex: bool,
	) -> Result<Self, Error<C::HashOut, C::Error>>
		where
			I: Iterator<Item=&'a Vec<u8>>,
	{
		match child {
			NodeHandle::Inline(data) => {
				if data.is_empty() {
					let node_data = proof_iter.next()
						.ok_or(Error::IncompleteProof)?;
					StackEntry::new(node_data, prefix, false, complex)
				} else {
					StackEntry::new(data, prefix, true, complex)
				}
			}
			NodeHandle::Hash(data) => {
				let mut hash = C::HashOut::default();
				if data.len() != hash.as_ref().len() {
					return Err(Error::InvalidChildReference(data.to_vec()));
				}
				hash.as_mut().copy_from_slice(data);
				Err(Error::ExtraneousHashReference(hash))
			}
		}
	}

	fn advance_item<I>(&mut self, items_iter: &mut Peekable<I>)
					   -> Result<Step<'a>, Error<C::HashOut, C::Error>>
		where
			I: Iterator<Item=(&'a [u8], Option<&'a [u8]>)>
	{
		let step = loop {
			if let Some((key_bytes, value)) = items_iter.peek().cloned() {
				let key = LeftNibbleSlice::new(key_bytes);
				if key.starts_with(&self.prefix) {
					match match_key_to_node(&key, self.prefix.len(), &self.node) {
						ValueMatch::MatchesLeaf => {
							if value.is_none() {
								return Err(Error::ValueMismatch(key_bytes.to_vec()));
							}
							self.value = value;
						}
						ValueMatch::MatchesBranch =>
							self.value = value,
						ValueMatch::NotFound =>
							if value.is_some() {
								return Err(Error::ValueMismatch(key_bytes.to_vec()));
							},
						ValueMatch::NotOmitted =>
							return Err(Error::ExtraneousValue(key_bytes.to_vec())),
						ValueMatch::IsChild(child_prefix) =>
							break Step::Descend(child_prefix),
					}

					items_iter.next();
					continue;
				}
			}
			break Step::UnwindStack;
		};
		Ok(step)
	}
}

enum ValueMatch<'a> {
	/// The key matches a leaf node, so the value at the key must be present.
	MatchesLeaf,
	/// The key matches a branch node, so the value at the key may or may not be present.
	MatchesBranch,
	/// The key was not found to correspond to value in the trie, so must not be present.
	NotFound,
	/// The key matches a location in trie, but the value was not omitted.
	NotOmitted,
	/// The key may match below a child of this node. Parameter is the prefix of the child node.
	IsChild(LeftNibbleSlice<'a>),
}

/// Determines whether a node on the stack carries a value at the given key or whether any nodes
/// in the subtrie do. The prefix of the node is given by the first `prefix_len` nibbles of `key`.
fn match_key_to_node<'a>(key: &LeftNibbleSlice<'a>, prefix_len: usize, node: &Node)
						 -> ValueMatch<'a>
{
	match node {
		Node::Empty => ValueMatch::NotFound,
		Node::Leaf(partial, value) => {
			if key.contains(partial, prefix_len) &&
				key.len() == prefix_len + partial.len() {
				if value.is_empty() {
					ValueMatch::MatchesLeaf
				} else {
					ValueMatch::NotOmitted
				}
			} else {
				ValueMatch::NotFound
			}
		}
		Node::Extension(partial, _) => {
			if key.contains(partial, prefix_len) {
				ValueMatch::IsChild(key.truncate(prefix_len + partial.len()))
			} else {
				ValueMatch::NotFound
			}
		}
		Node::Branch(children, value) => {
			match_key_to_branch_node(key, prefix_len, children, value)
		}
		Node::NibbledBranch(partial, children, value) => {
			if key.contains(partial, prefix_len) {
				match_key_to_branch_node(key, prefix_len + partial.len(), children, value)
			} else {
				ValueMatch::NotFound
			}
		}
	}
}

/// Determines whether a branch node on the stack carries a value at the given key or whether any
/// nodes in the subtrie do. The key of the branch node value is given by the first
/// `prefix_plus_partial_len` nibbles of `key`.
fn match_key_to_branch_node<'a>(
	key: &LeftNibbleSlice<'a>,
	prefix_plus_partial_len: usize,
	children: &[Option<NodeHandle>; NIBBLE_LENGTH],
	value: &Option<&[u8]>,
) -> ValueMatch<'a>
{
	if key.len() == prefix_plus_partial_len {
		if value.is_none() {
			ValueMatch::MatchesBranch
		} else {
			ValueMatch::NotOmitted
		}
	} else {
		let index = key.at(prefix_plus_partial_len)
			.expect("it's less than prefix.len(); qed")
			as usize;
		if children[index].is_some() {
			ValueMatch::IsChild(key.truncate(prefix_plus_partial_len + 1))
		} else {
			ValueMatch::NotFound
		}
	}
}

enum Step<'a> {
	Descend(LeftNibbleSlice<'a>),
	UnwindStack,
}

/// Verify a compact proof for key-value pairs in a trie given a root hash.
pub fn verify_proof<'a, L, I, K, V>(root: &<L::Hash as Hasher>::Out, proof: &[Vec<u8>], items: I)
									-> Result<(), Error<TrieHash<L>, CError<L>>>
	where
		L: TrieLayout,
		I: IntoIterator<Item=&'a (K, Option<V>)>,
		K: 'a + AsRef<[u8]>,
		V: 'a + AsRef<[u8]>,
{
	// Sort items.
	let mut items = items.into_iter()
		.map(|(k, v)| (k.as_ref(), v.as_ref().map(|v| v.as_ref())))
		.collect::<Vec<_>>();
	items.sort();

	if items.is_empty() {
		return if proof.is_empty() {
			Ok(())
		} else {
			Err(Error::ExtraneousNode)
		};
	}

	// Check for duplicates.
	for i in 1..items.len() {
		if items[i].0 == items[i - 1].0 {
			return Err(Error::DuplicateKey(items[i].0.to_vec()));
		}
	}

	// Iterate simultaneously in order through proof nodes and key-value pairs to verify.
	let mut proof_iter = proof.iter();
	let mut items_iter = items.into_iter().peekable();

	// A stack of child references to fill in omitted branch children for later trie nodes in the
	// proof.
	let mut stack: Vec<StackEntry<L::Codec, L::Hash>> = Vec::new();

	let root_node = match proof_iter.next() {
		Some(node) => node,
		None => return Err(Error::IncompleteProof),
	};
	let mut last_entry = StackEntry::new(
		root_node,
		LeftNibbleSlice::new(&[]),
		false,
		L::COMPLEX_HASH,
	)?;
	loop {
		// Insert omitted value.
		match last_entry.advance_item(&mut items_iter)? {
			Step::Descend(child_prefix) => {
				let next_entry = last_entry.advance_child_index(
					child_prefix,
					&mut proof_iter,
					L::COMPLEX_HASH,
				)?;
				stack.push(last_entry);
				last_entry = next_entry;
			}
			Step::UnwindStack => {
				let is_inline = last_entry.is_inline;
				let (node_data, no_child) = last_entry.encode_node()?;

				let child_ref = if is_inline {
					if node_data.len() > L::Hash::LENGTH {
						return Err(Error::InvalidChildReference(node_data));
					}
					let mut hash = <TrieHash<L>>::default();
					&mut hash.as_mut()[..node_data.len()].copy_from_slice(node_data.as_ref());
					ChildReference::Inline(hash, node_data.len())
				} else {
					ChildReference::Hash(if let Some((bitmap_keys, additional_hash)) = last_entry.complex {
						let children = last_entry.children;
						let nb_children = children.iter().filter(|v| v.is_some()).count();
						let children = children.into_iter()
							.enumerate()
							.filter_map(|(ix, v)| {
								v.as_ref().map(|v| (ix, v.clone()))
							})
							.map(|(ix, child_ref)| {
								if bitmap_keys.value_at(ix) {
									Some(match child_ref {
										ChildReference::Hash(h) => h,
										ChildReference::Inline(h, _) => h,
									})
								} else {
									None
								}
							});

						if let Some(h) = L::Hash::hash_complex(
							&no_child.encoded_no_child(node_data.as_slice())[..],
							nb_children,
							children,
							additional_hash.into_iter(),
							true,
						) {
							h
						} else {
							// TODO better error for the invalid
							// complex hash
							return Err(Error::RootMismatch(Default::default()));
						}
					} else {
						L::Hash::hash(&node_data)
					})
				};

				if let Some(entry) = stack.pop() {
					last_entry = entry;
					last_entry.children[last_entry.child_index] = Some(child_ref);
					last_entry.child_index += 1;
				} else {
					if proof_iter.next().is_some() {
						return Err(Error::ExtraneousNode);
					}
					let computed_root = match child_ref {
						ChildReference::Hash(hash) => hash,
						ChildReference::Inline(_, _) => panic!(
							"the bottom item on the stack has is_inline = false; qed"
						),
					};
					if computed_root != *root {
						return Err(Error::RootMismatch(computed_root));
					}
					break;
				}
			}
		}
	}

	Ok(())
}

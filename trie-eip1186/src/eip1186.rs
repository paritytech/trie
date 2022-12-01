use crate::rstd::{result::Result, vec::Vec};
use hash_db::{HashDBRef, Hasher};
use trie_db::{
	node::{decode_hash, Node, NodeHandle, Value},
	recorder::Recorder,
	CError, DBValue, NibbleSlice, NodeCodec, Result as TrieResult, Trie, TrieDBBuilder, TrieHash,
	TrieLayout,
};

/// Generate an eip-1186 compatible proof for key-value pairs in a trie given a key.
pub fn generate_proof<L>(
	db: &dyn HashDBRef<L::Hash, DBValue>,
	root: &TrieHash<L>,
	key: &[u8],
) -> TrieResult<(Vec<Vec<u8>>, Option<Vec<u8>>), TrieHash<L>, CError<L>>
where
	L: TrieLayout,
{
	let mut recorder = Recorder::<L>::new();

	let item = {
		let trie = TrieDBBuilder::<L>::new(db, root).with_recorder(&mut recorder).build();
		trie.get(key)?
	};

	let proof: Vec<Vec<u8>> = recorder.drain().into_iter().map(|r| r.data).collect();
	Ok((proof, item))
}

/// Errors that may occur during proof verification. Most of the errors types simply indicate that
/// the proof is invalid with respect to the statement being verified, and the exact error type can
/// be used for debugging.
#[derive(PartialEq, Eq)]
#[cfg_attr(feature = "std", derive(Debug))]
pub enum VerifyError<'a, HO, CE> {
	/// The proof does not contain any value for the given key
	/// the error carries the nibbles left after traversing the trie
	NonExistingValue(NibbleSlice<'a>),
	/// The proof contains a value for the given key
	/// while we were expecting to find a non-existence proof
	ExistingValue(Vec<u8>),
	/// The proof indicates that the trie contains a different value.
	/// the error carries the value contained in the trie
	ValueMismatch(Vec<u8>),
	/// The proof is missing trie nodes required to verify.
	IncompleteProof,
	/// The node hash computed from the proof is not matching.
	HashMismatch(HO),
	/// One of the proof nodes could not be decoded.
	DecodeError(CE),
	/// Error in converting a plain hash into a HO
	HashDecodeError(&'a [u8]),
}

#[cfg(feature = "std")]
impl<'a, HO: std::fmt::Debug, CE: std::error::Error> std::fmt::Display for VerifyError<'a, HO, CE> {
	fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> Result<(), std::fmt::Error> {
		match self {
			VerifyError::NonExistingValue(key) => {
				write!(f, "Key does not exist in trie: reaming key={:?}", key)
			},
			VerifyError::ExistingValue(value) => {
				write!(f, "trie contains a value for given key value={:?}", value)
			},
			VerifyError::ValueMismatch(key) => {
				write!(f, "Expected value was not found in the trie: key={:?}", key)
			},
			VerifyError::IncompleteProof => write!(f, "Proof is incomplete -- expected more nodes"),
			VerifyError::HashMismatch(hash) => write!(f, "hash mismatch found: hash={:?}", hash),
			VerifyError::DecodeError(err) => write!(f, "Unable to decode proof node: {}", err),
			VerifyError::HashDecodeError(plain_hash) => {
				write!(f, "Unable to decode hash value plain_hash: {:?}", plain_hash)
			},
		}
	}
}

#[cfg(feature = "std")]
impl<'a, HO: std::fmt::Debug, CE: std::error::Error + 'static> std::error::Error
	for VerifyError<'a, HO, CE>
{
	fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
		match self {
			VerifyError::DecodeError(err) => Some(err),
			_ => None,
		}
	}
}

/// Verify a compact proof for key-value pairs in a trie given a root hash.
pub fn verify_proof<'a, L>(
	root: &<L::Hash as Hasher>::Out,
	proof: &'a [Vec<u8>],
	raw_key: &'a [u8],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	if proof.is_empty() {
		return Err(VerifyError::IncompleteProof)
	}
	let key = NibbleSlice::new(raw_key);
	process_node::<L>(Some(root), &proof[0], key, &proof[1..])
}

fn process_node<'a, L>(
	expected_node_hash: Option<&<L::Hash as Hasher>::Out>,
	encoded_node: &'a [u8],
	key: NibbleSlice<'a>,
	proof: &'a [Vec<u8>],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	if let Some(expected) = expected_node_hash {
		let calculated_node_hash = <L::Hash as Hasher>::hash(encoded_node);
		if calculated_node_hash != *expected {
			return Err(VerifyError::HashMismatch(calculated_node_hash))
		}
	}
	let node = <L::Codec as NodeCodec>::decode(encoded_node).map_err(VerifyError::DecodeError)?;
	match node {
		Node::Empty => process_empty::<L>(key, proof),
		Node::Leaf(nib, data) => process_leaf::<L>(nib, data, key, proof),
		Node::Extension(nib, handle) =>
			process_extension::<L>(&nib, handle, key, proof),
		Node::Branch(children, maybe_data) =>
			process_branch::<L>(children, maybe_data, key, proof),
		Node::NibbledBranch(nib, children, maybe_data) =>
			process_nibbledbranch::<L>(nib, children, maybe_data, key, proof),
	}
}

fn process_empty<'a, L>(
	key: NibbleSlice<'a>,
	_: &[Vec<u8>],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	// Ok(key)
	Ok(vec![])
}

fn process_leaf<'a, L>(
	nib: NibbleSlice,
	data: Value<'a>,
	key: NibbleSlice<'a>,
	proof: &'a [Vec<u8>],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	if key != nib {
		return Err(VerifyError::NonExistingValue(key))
	}
	match_value::<L>(Some(data), key, proof)
}
fn process_extension<'a, L>(
	nib: &NibbleSlice,
	handle: NodeHandle<'a>,
	mut key: NibbleSlice<'a>,
	proof: &'a [Vec<u8>],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	if !key.starts_with(nib) {
		return Err(VerifyError::NonExistingValue(key))
	}
	key.advance(nib.len());

	match handle {
		NodeHandle::Inline(encoded_node) =>
			process_node::<L>(None, encoded_node, key, proof),
		NodeHandle::Hash(plain_hash) => {
			let new_root = decode_hash::<L::Hash>(plain_hash)
				.ok_or(VerifyError::HashDecodeError(plain_hash))?;
			process_node::<L>(Some(&new_root), &proof[0], key, &proof[1..])
		},
	}
}

fn process_nibbledbranch<'a, L>(
	nib: NibbleSlice,
	children: [Option<NodeHandle<'a>>; 16],
	maybe_data: Option<Value<'a>>,
	mut key: NibbleSlice<'a>,
	proof: &'a [Vec<u8>],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	key.advance(nib.len());

	if key.is_empty() {
		match_value::<L>(maybe_data, key, proof)
	} else {
		match_children::<L>(children, key, proof)
	}
}

fn process_branch<'a, L>(
	children: [Option<NodeHandle<'a>>; 16],
	maybe_data: Option<Value<'a>>,
	key: NibbleSlice<'a>,
	proof: &'a [Vec<u8>],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	if key.is_empty() {
		match_value::<L>(maybe_data, key, proof)
	} else {
		match_children::<L>(children, key, proof)
	}
}
fn match_children<'a, L>(
	children: [Option<NodeHandle<'a>>; 16],
	mut key: NibbleSlice<'a>,
	proof: &'a [Vec<u8>],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	match children.get(key.at(0) as usize) {
		Some(Some(NodeHandle::Hash(hash))) =>
			if proof.is_empty() {
				Err(VerifyError::IncompleteProof)
			} else {
				key.advance(1);
				let new_root =
					decode_hash::<L::Hash>(hash).ok_or(VerifyError::HashDecodeError(hash))?;
				process_node::<L>(Some(&new_root), &proof[0], key, &proof[1..])
			},
		Some(Some(NodeHandle::Inline(encoded_node))) => {
			key.advance(1);
			process_node::<L>(None, encoded_node, key, proof)
		},
		Some(None) => Err(VerifyError::NonExistingValue(key)),
		None => panic!("key index is out of range in children array"),
	}
}

fn match_value<'a, L>(
	maybe_data: Option<Value<'a>>,
	key: NibbleSlice<'a>,
	proof: &'a [Vec<u8>],
) -> Result<Vec<u8>, VerifyError<'a, TrieHash<L>, CError<L>>>
where
	L: TrieLayout,
{
	match (maybe_data, proof.first()) {
		(None, _) => Err(VerifyError::NonExistingValue(key)),
		(Some(Value::Inline(inline_data)), _) => Ok(inline_data.to_vec()),
		(Some(Value::Node(plain_hash)), Some(next_proof_item)) => {
			let node_hash = decode_hash::<L::Hash>(plain_hash)
				.ok_or(VerifyError::HashDecodeError(plain_hash))?;
			Ok(next_proof_item.to_vec())
		},
		(Some(Value::Node(_)), None) => Err(VerifyError::IncompleteProof),
	}
}

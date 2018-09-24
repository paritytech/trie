[![Build Status](https://travis-ci.org/paritytech/trie.svg?branch=master)](https://travis-ci.org/paritytech/trie)

# Trie

A generic implementation of the Base-16 Modified Merkle Tree ("Trie") data structure,
provided under the Apache2 license.

The implementation comes in two formats:

- Trie DB (`trie-db` crate) which can be combined with a backend database to provide
   a persistent trie structure whose contents can be modified and whose root hash
   recalculated efficiently.
- Trie Hash (`trie-hash` crate) which provides a closed-form function that accepts a
   sorted enumeration of keys and values (exactly the format provided by
   `BTreeMap<(&[u8], &[u8])>`) and provides a root calculated entirely in-memory and
   closed form.

Trie Hash alone is able to be used in `no_std` builds by disabling its (default)
`std` feature.

In addition to these, several support crates are provided:

- `hash-db` crate, used to provide `Hasher` (trait for all things that
   can make cryptographic hashes) and `HashDB` (trait for databases that can have byte
   slices pushed into them and allow for them to be retrieved based on their hash).
   Suitable for `no_std`, though in this case will only provide `Hasher`.
- `memory-db` crate, contains `MemoryDB`, an implementation of a `HashDB` using only
   in in-memory map.
- `hash256-std-hasher` crate, an implementation of a `std::hash::Hasher` for 32-byte
   keys that have already been hashed. Useful for `MemoryDB`.

There are also three crates used only for testing:

- `keccak-hasher` crate, an implementation of `Hasher` based on the Keccak-256 algorithm.
- `reference-trie` crate, an implementation of a simple trie format; this provides both
   a `NodeCodec` and `TrieStream` implementation making it suitable for both Trie DB and
   Trie Hash.
- `trie-standardmap` crate, a key/value generation tool for creating large test datasets
   to specific qualities.

In the spirit of all things Rust, this aims to be reliable, secure, and high performance.

Used in the [Substrate](https://parity.io/substrate) project. If you use this crate and
would your project listed here, please contact us.

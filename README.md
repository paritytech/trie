[![Build Status](https://travis-ci.org/paritytech/parity-common.svg?branch=master)](https://travis-ci.org/paritytech/parity-common)

# Trie

A generic implementation of the Base-16 Modified Merkle Tree ("Trie") data structure.
The implementation comes in two formats:

- Trie DB (`trie-db` crate) which can be combined with a backend database to provide
   a persistent trie structure whose contents can be modified and whose root hash
   recalculated efficiently.
- Trie Hash (`trie-hash` crate) which provides a closed-form function that accepts a
   sorted enumeration of keys and values (exactly the format provided by
   `BTreeMap<(&[u8], &[u8])>`) and provides a root calculated entirely in-memory and
   closed form.

In the spirit of all things Rust, this aims to be reliable, secure, and high performance.

Used in the [Substrate](https://parity.io/substrate) project. If you use this crate and
would your project listed here, please contact us.

Provided under the Apache2 license.
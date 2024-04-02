[![Build Status](https://github.com/paritytech/trie/actions/workflows/rust.yml/badge.svg)](https://github.com/paritytech/trie/actions)
# Trie

A generic implementation of the Base-16 Modified Merkle Tree ("Trie") data structure,
provided under the Apache2 license.

Trie Hash alone is able to be used in `no_std` builds by disabling its (default)
`std` feature.
Implementation is in `subtrie` crate.

Testing in  `reference-trie` crate and `trie-db-test`.

In the spirit of all things Rust, this aims to be reliable, secure, and high performance.

Used in the [Substrate](https://parity.io/substrate) project. If you use this crate and
would your project listed here, please contact us.

## Buidling &c.

Building is done through cargo, as you'd expect.

### Building

```
cargo build --all
```

### Testing

```
cargo test --all
```

### Benchmarking

```
cargo bench --all
```

### Building in `no_std`

```
cargo build --no-default-features
```

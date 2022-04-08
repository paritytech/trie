# Changelog

The format is based on [Keep a Changelog].

[Keep a Changelog]: http://keepachangelog.com/en/1.0.0/

## [Unreleased]
- Do not check for root in `TrieDB` and `TrieDBMut` constructors: [#155](https://github.com/paritytech/trie/pull/155)

  To get back the old behavior you have to add the following code:
  ```
  if !db.contains(root, EMPTY_PREFIX) {
    return Err(InvalidStateRoot(root))
  }
  ```

## [0.23.1] - 2022-02-04
- Updated `hashbrown` to 0.12. [#150](https://github.com/paritytech/trie/pull/150)

## [0.23.0] - 2021-10-19
- Support for value nodes. [#142](https://github.com/paritytech/trie/pull/142)

## [0.22.6] - 2021-07-02
- Updated `hashbrown` to 0.11. [#131](https://github.com/paritytech/trie/pull/131)

## [0.22.3] - 2021-01-28
### Added
- Decode with an iterator. [#121](https://github.com/paritytech/trie/pull/121)

## [0.22.2] - 2021-01-05
- Update `hashbrown` to 0.9. [#118](https://github.com/paritytech/trie/pull/118)

## [0.22.1] - 2020-07-24
- Use `ahash` feature of hashbrown. [#103](https://github.com/paritytech/trie/pull/103)

## [0.22.0] - 2020-07-06
- Update hashbrown to 0.8. [#97](https://github.com/paritytech/trie/pull/97)

## [0.21.0] - 2020-06-04
- Added `ALLOW_EMPTY` to `TrieLayout`. [#92](https://github.com/paritytech/trie/pull/92)

## [0.20.0] - 2020-02-07
- Prefix iterator. [#39](https://github.com/paritytech/trie/pull/39)
- Update trie-root to v0.16.0 and memory-db to v0.19.0 and reference-trie to v0.20.0 [#78](https://github.com/paritytech/trie/pull/78)

## [0.19.2] - 2020-01-16
- Compact proofs support. [#45](https://github.com/paritytech/trie/pull/45)

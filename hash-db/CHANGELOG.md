# Changelog

The format is based on [Keep a Changelog].

[Keep a Changelog]: http://keepachangelog.com/en/1.0.0/

## [0.17.0] - 2026-11-24
- Implement `HashDBRef` for `&dyn HashDBRef`, as for `&dyn HashDB` and `&mut dyn HashDB`.
  [#240](https://github.com/paritytech/trie/pull/240)
- `HashDB` and `PlainDB` no longer require `Send + Sync`.
  [#214](https://github.com/paritytech/trie/pull/214)

## [0.16.0] - 2023-03-14
- Requires Hash to be Ord. [#188](https://github.com/paritytech/trie/pull/188)



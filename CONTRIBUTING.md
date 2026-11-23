# Contributing to trie

`trie` welcomes contribution from everyone in the form of suggestions, bug
reports, pull requests, and feedback. This document gives some guidance if you
are thinking of helping us.

Please reach out here in a GitHub issue or in the parity channel on [gitter] if we can do anything to help you contribute.

[gitter]: https://gitter.im/paritytech/parity

## Submitting bug reports and feature requests

When reporting a bug or asking for help, please include enough details so that
the people helping you can reproduce the behavior you are seeing. For some tips
on how to approach this, read about how to produce a [Minimal, Complete, and
Verifiable example].

[Minimal, Complete, and Verifiable example]: https://stackoverflow.com/help/mcve

When making a feature request, please make it clear what problem you intend to
solve with the feature, any ideas for how `trie` could support solving that problem, any possible alternatives, and any disadvantages.

## Versioning

As many crates in the rust ecosystem, all crates in `trie` follow [semantic versioning]. This means bumping PATCH version on bug fixes that don't break backwards compatibility, MINOR version on new features and MAJOR version otherwise (MAJOR.MINOR.PATCH). Versions < 1.0 are considered to have the format 0.MAJOR.MINOR, which means bumping MINOR version for all non-breaking changes.

If you bump a dependency that is publicly exposed in a crate's API (e.g. `pub use dependency;` or `pub field: dependency::Dependency`) and the version transition for the dependency was semver-breaking, then it is considered to be a breaking change for the consuming crate as well. To put it simply, if your change could cause a compilation error in user's code, it is a breaking change.

Bumping versions should be done in a separate from regular code changes PR.

[semantic versioning]: https://semver.org/

## Releasing a new version

This part of the guidelines is for `trie` maintainers.

Crates are published by paritytech/crates_publish_automation as `parity-crate-owner`.

1. Merge a PR that bumps the version of each crate being released and of the
   workspace crates depending on it, and turns `## [Unreleased]` in their
   changelogs into `## [X.Y.Z] - YYYY-MM-DD`.
2. Publish a GitHub Release from `master` with tag `<crate>-vX.Y.Z` for the
   main crate released (`trie-db` whenever it is bumped) and the changelog
   entries as notes. For a patch of an old line, target its `backport/<line>`
   branch instead and untick "Set as the latest release", the branch must
   contain `.github/workflows/release.yml`.
3. The `Release` workflow packages the crates and hands them to the publisher,
   which publishes the versions crates.io does not have yet. Check crates.io.
   If it fails, an issue labelled `failure` is opened here, fix the cause and
   re-run the workflow, already published versions are skipped.

## Conduct

We follow [Substrate Code of Conduct].

[Substrate Code of Conduct]: https://github.com/paritytech/substrate/blob/master/CODE_OF_CONDUCT.adoc

## Attribution

This guideline is adapted from [Serde's CONTRIBUTING guide].

[Serde's CONTRIBUTING guide]: https://github.com/serde-rs/serde/blob/master/CONTRIBUTING.md

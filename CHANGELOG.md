# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases stay on `v0.x` until the `taggity.yaml` schema and CLI are stable:
under semver, `v1.0.0` is a compatibility promise, and the spec format has not
earned one yet.

## [Unreleased]

### Added

- Domain types: `Verdict`, `Signals`, `Evidence`, and machine-readable `Reason`
  codes for every `UNKNOWN` outcome.
- Structural test enforcing that exactly one code path may conclude
  `NOT_VULNERABLE`, walking the AST rather than matching text.
- CI across Linux, macOS, and Windows with race detection, golangci-lint,
  gosec, and CodeQL.
- `depguard` rules that make the engine/LLM separation a build failure rather
  than a review comment.

[Unreleased]: https://github.com/nickelsec/taggity/commits/main

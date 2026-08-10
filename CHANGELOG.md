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
- Working CLI: `check`, `audit`, `init`, and `export`.
- `export` records unreviewed disagreements separately from established
  versions, so an unresolved observation is never published as a claim.
- `Report.Overclaims()`, rendered as `CLAIMED BUT NOT OBSERVED`. Versions the
  advisory claims are affected but where the engine found the fix are shown
  rather than reduced to a count. They remain excluded from findings and from
  export.

### Fixed

- The audit report could print `0 finding(s)` for an advisory that was
  demonstrably wrong. Under an `indicates: fixed` rule, an over-claimed version
  classifies as `narrower-than-claimed`, which was never rendered. Found while
  auditing GHSA-wxj7-3fx5-pp9m.
- `RuleString` rendered both polarities identically, so an evidence record or
  an exported OSV document could not distinguish "calls X, which is the danger"
  from "calls X, which is the fix". Inverted-polarity rules now render
  `calls: X (indicates: fixed)`.
- `Repo.Tags` discarded the error returned by the tag iterator.
- Cache directories are created 0750 rather than 0755.

### Changed

- `.golangci.yaml` disables now cover the whole `default: all` set, each with a
  reason. The first real run reported 203 issues; the remainder were fixed.
  `golangci-lint` and `gosec` both report clean.

[Unreleased]: https://github.com/nickelsec/taggity/commits/main

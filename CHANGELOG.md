# Changelog

All notable changes to this project are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Releases stay on `v0.x` until the `taggity.yaml` schema and CLI are stable:
under semver, `v1.0.0` is a compatibility promise, and the spec format has not
earned one yet.

## [Unreleased]

## [0.1.0] - 2026-08-10

The deterministic engine. No model runs anywhere in this release, and
`internal/llm` does not exist — which is what makes "a model cannot affect a
verdict" true by construction rather than by policy.

Audited against three real multi-branch advisories: one confirmed finding
(GHSA-wxj7-3fx5-pp9m over-claims MLflow 3.0.0 and 3.0.1), one that resolved to
*the advisory is correct* after investigation, and one negative control that the
engine correctly says nothing about. Zero under-reports throughout.

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
- `audit` and `export` refuse to run a spec against an advisory it does not
  name, rather than producing a confident report about the wrong one.
- Release binaries for Linux, macOS, and Windows on amd64 and arm64, with
  sha256 checksums and an SPDX SBOM per archive. Built with `CGO_ENABLED=0` and
  `-trimpath`, and timestamped from the commit, so they are reproducible.
- `go install` builds report the module version via `runtime/debug` when no
  linker flag was supplied, so an installed binary is attributable to a release.

### Fixed

- The audit report could print `0 finding(s)` for an advisory that was
  demonstrably wrong. Under an `indicates: fixed` rule, an over-claimed version
  classifies as `narrower-than-claimed`, which was never rendered. Found while
  auditing GHSA-wxj7-3fx5-pp9m.
- Boundary selection treated an open-below claim (`introduced: 0`) as covering
  only the release line of its fixed version, so every earlier line looked
  unmentioned and was probed as suspicious silence. On PYSEC-2026-564 that
  produced twelve false findings against an advisory that is correct.
- `RuleString` rendered both polarities identically, so an evidence record or
  an exported OSV document could not distinguish "calls X, which is the danger"
  from "calls X, which is the fix". Inverted-polarity rules now render
  `calls: X (indicates: fixed)`.
- `make test-live` ran the ordinary hermetic suite. No file carried a `live`
  build tag, so the corpus tests behind `//go:build corpus` never ran from a
  Make target — while the README advertised it as the way to reproduce every
  claim the project makes. The target is now `make test-corpus`, with
  `-count=1` so a cached pass cannot stand in for a real one.
- `signal.code.aliases` was parsed, documented, and then silently discarded:
  nothing evaluated it, so a spec written to survive a rename still reported
  `UNKNOWN [symbol_not_found]`. It is now rejected with an error naming the
  alternative. The field stays in the schema, so a v0.2.0 spec needs no
  migration.
- The top-level usage omitted `--package`, which `taggity init` requires, so
  the documented command failed on copy-paste.
- `Repo.Tags` discarded the error returned by the tag iterator.
- Cache directories are created 0750 rather than 0755.

### Changed

- `.golangci.yaml` disables now cover the whole `default: all` set, each with a
  reason. The first real run reported 203 issues; the remainder were fixed.
  `golangci-lint` and `gosec` both report clean.

[Unreleased]: https://github.com/nickelsec/taggity/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nickelsec/taggity/releases/tag/v0.1.0

# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [semver](https://semver.org/spec/v2.0.0.html).

Releases stay on `v0.x` until the spec schema and the CLI settle. `v1.0.0` is a
compatibility promise and neither has earned one yet.

## [Unreleased]

### Added

- `defaults` rule kind, asking whether a symbol declares a parameter with a
  given default value. Some fixes change a signature rather than a call body:
  PyYAML closed its arbitrary-execution bug by changing
  `load(stream, Loader=Loader)` to `Loader=None` while still calling
  `Loader(stream)` either way, which a `calls` rule cannot distinguish. A
  parameter with no default never matches, so a version that made the argument
  required is not reported as carrying the dangerous default.
- `taggity init --defaults param=value`.
- `unsupported_rule` reason, so a spec written for a newer build yields
  `UNKNOWN` rather than being evaluated as though its question had been
  answered.

### Changed

- A rule that sets no match field, or more than one, is now rejected. Two
  fields would mean the engine answers one and ignores the other, giving the
  author a narrower question than they wrote.

## [0.1.0] - 2026-08-10

First release. Deterministic engine, no model involved anywhere in it.

### Commands

- `check <pkg>@<version>` reports `VULNERABLE`, `NOT_VULNERABLE` or `UNKNOWN`
  for one version, with the commit and tag it read.
- `audit` probes an advisory's boundary versions and reports where the claimed
  range disagrees with the source. Findings group consecutive versions that
  share a verdict, so one edit shows up once rather than once per release.
- `init` scaffolds a spec.
- `export` emits OSV JSON for what the audit established. Unreviewed
  disagreements and `UNKNOWN` versions are recorded separately rather than
  published as claims.

### Engine

- Verdicts are three-valued. `UNKNOWN` carries a machine-readable reason
  (`no_tag`, `file_absent`, `symbol_not_found`, `ambiguous_symbol`,
  `unparseable_version`, `parse_failed`) and is never treated as safe.
- Matching runs on tree-sitter, so a call in a comment, docstring or nested
  function does not count.
- Tags are normalised into PEP 440 and indexed, which handles the tag spellings
  real repositories use.
- Rules can match the fix rather than the danger via `indicates: fixed`, for
  vulnerabilities closed by adding a guard.
- A spec that names an advisory is rejected against a different one.
- `signal.code.aliases` parses but is not evaluated, and a spec that sets it is
  rejected rather than silently ignored.

### Guarantees

- Exactly one code path can conclude `NOT_VULNERABLE`, enforced by a test that
  walks the AST rather than matching text.
- `depguard` denies any import of `internal/llm` from outside it. That package
  does not exist yet, which is what makes "a model cannot change a verdict" a
  build-time property.

### Verification

Audited against three multi-branch advisories in `testdata/corpus/`: one
confirmed finding (GHSA-wxj7-3fx5-pp9m over-claims MLflow 3.0.0 and 3.0.1), one
that resolved to the advisory being correct, and one four-branch case the engine
correctly reports nothing about. No under-reports.

### Distribution

Binaries for Linux, macOS and Windows on amd64 and arm64, with SHA-256 checksums
and an SPDX SBOM per archive. Built with `CGO_ENABLED=0` and `-trimpath`,
timestamped from the commit.

[Unreleased]: https://github.com/nickelsec/taggity/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/nickelsec/taggity/releases/tag/v0.1.0

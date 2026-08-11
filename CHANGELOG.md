# Changelog

Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [semver](https://semver.org/spec/v2.0.0.html).

Releases stay on `v0.x` until the spec schema and the CLI settle. `v1.0.0` is a
compatibility promise and neither has earned one yet.

## [Unreleased]

## [0.2.0] - 2026-08-11

A minor release rather than a patch: three spec fields are new, so a spec
written against this release will not load on 0.1.0. Existing specs are
unchanged and every 0.1.0 spec still validates.

### Added

- `defaults` rule kind, asking whether a symbol declares a parameter with a
  given default value. Some fixes change a signature rather than a call body:
  PyYAML closed its arbitrary-execution bug by changing
  `load(stream, Loader=Loader)` to `Loader=None` while still calling
  `Loader(stream)` either way, which a `calls` rule cannot distinguish. A
  parameter with no default never matches, so a version that made the argument
  required is not reported as carrying the dangerous default.
- `signal.code_any`, a list of code locations where the version is affected if
  any of them matches. A fix can span files: the sink in one module, the guard
  added in a validator in another. `signal.code` still takes a single location
  and existing specs are unchanged.
- `signal.code.aliases` is evaluated. An alias pins an earlier name for the same
  construct to a half-open version range, so a symbol that was renamed does not
  read as absence. The spec's own symbol is tried first and an alias only
  answers where it found nothing, so adding one cannot change a version that
  already had an answer. A verdict reached through an alias records `alias` as
  its evidence source and names the symbol that was actually read, because an
  alias is a human claim that two names are the same construct and a reader has
  to be able to see it.

  Aliases cover a rename. They do nothing for a guard reimplemented in another
  module under a different decomposition, which is the more common shape.
- `authoring.mode` is validated, and `reviewed_by` is required when it is `ai`.
  An alias with `source: llm` likewise requires `approved_by`. A model may
  propose a name; only a human may stand behind one, and until now that rule
  lived only in a doc comment.
- `taggity init --defaults param=value`.
- `unsupported_rule` reason, so a spec written for a newer build yields
  `UNKNOWN` rather than being evaluated as though its question had been
  answered.

### Fixed

- `check` summarised a multi-location spec using the first location rather than
  the one that answered. A symbol that moves between files leaves most locations
  absent at any given tag, so the rule line named a rule that never fired, the
  verdict line paired `VULNERABLE` with another location's "not present"
  message, and the provenance line named a file that is not in the tree that was
  examined. That last one is the output a maintainer checks first. Verdicts were
  correct throughout and none change; only what the output says about them does.
  Single-location specs are unaffected.
- A not-found symbol now names the closest definitions in the file. The reason
  code alone cannot separate a typo in the spec from a version that genuinely
  lacks the code, and those need opposite responses: edit one line, or go read
  the version. Nothing is suggested when no name is close, since a wrong guess
  sends the reader to fix a spec that was already right.
- The rule line claimed a match when the deciding location had not matched, so
  a run where nothing was found still read `matched:`.
- Two locations holding equal records were both marked as deciding, which read
  as agreement between places that were not separately consulted.
- `.gitignore` listed the built binary as `taggity`, an unanchored pattern that
  git matches against any path component. Every new file under `cmd/taggity/`
  and `internal/taggity/` was ignored, including new tests. Already-tracked
  files kept working, which is why it went unnoticed. The patterns are now
  anchored to the repository root.
- `export` recorded one symbol and one file in its OSV provenance. Across a
  version range the answering location changes as code moves, so no single pair
  describes the report. The block now lists every location the spec named,
  under `locations`.
- Boundary selection probed versions the repository does not tag. A claim can
  name a version that was never released, or something that is not a version:
  PYSEC-2021-382 lists a commit hash where a fixed version belongs. Each one
  spent a probe to learn `no_tag` and reported a gap that said nothing about
  the advisory. The qutebrowser audit drops from seven probes with a spurious
  gap to five with none, and the finding is unchanged.
- A release line was treated as unmentioned when a claim covered it without
  naming its endpoints. A claim spanning 1.0.0 to 3.0.1 covers all of line 2,
  and a claim with no fixed version covers every line above its introduced.
  Both were probed as silence, which disagrees with a claim that already warns
  about them. Line coverage is now derived from the releases rather than from
  the claim's endpoints, which subsumes the earlier `introduced: 0` special
  case.
- Pre-release versions compared as text, so `1.0.0rc10` sorted before
  `1.0.0rc9` and `1.0.0b10` before `1.0.0b2`. Advisory claims are routinely
  written against a pre-release, and this reaches boundary selection through
  the release below an introduced version. No corpus result changes: released
  versions are filtered out before the affected comparison runs, so the bug was
  unreachable rather than harmless.
- `stripTagPrefix` removed a leading `v` without checking that a digit followed,
  turning `version-1.2.3` into `ersion-1.2.3`. The tag then failed to parse and
  was discarded, so a version that was tagged resolved as `no_tag`.
- `FileAt` reported `no_tag` when a commit object could not be read, and
  `file_absent` when a blob could not be read after its tree entry was found.
  Both describe the wrong failure. They now report `commit_unreadable`, a new
  reason whose remedy is to re-clone rather than to look for a missing tag.
  `Resolve` reported `no_tag` when the tag iterator itself failed, and now does
  the same.
- Duplicate spellings of one version were resolved by byte order, which picks
  `release-2.0.5` over `v2.0.5` because `r` sorts before `v`. The tag name
  appears in evidence, so the plainest spelling now wins.

### Changed

- A rule that sets no match field, or more than one, is now rejected. Two
  fields would mean the engine answers one and ignores the other, giving the
  author a narrower question than they wrote.
- A `code_any` list repeating a location is rejected. The repeat cannot change
  a verdict, but it doubles the work and prints one answer twice. Two rules
  against the same file and symbol are still allowed: one fix can add a guard
  and remove a sink in the same function.
- Evidence records carry the polarity of the rule that produced them, and
  `check` lists every location when a spec has more than one. The location that
  produced the verdict is marked with `*`.
- The README leads with `check` and a single version, and introduces range
  auditing after it. Asking whether one release contains the vulnerable code is
  the question people arrive with, and auditing an advisory's range is that
  question asked at the edges of a claim.
- Documented that a rule asks whether a construct is present, which is not
  always the same question as whether the bug is. Where a fix adds a guard
  around an unchanged sink, a rule naming the sink keeps reporting `VULNERABLE`
  after the fix lands.

### Notes

Boundary selection is covered by property tests over generated claim shapes and
tag topologies, asserting invariants rather than outputs. They found two of the
bugs listed above on their first run, without needing the advisory that would
have exposed them.

Guard-shaped fixes dominate. Filtering the PyPI advisory database for
multi-range advisories whose fix deletes a dangerous call leaves seven
candidates out of 1549 packages, all single-range. Of nine advisories audited,
only two removed a call, so `indicates: fixed` is the primary path rather than
the exception.

Five more advisories audited, targeted by query rather than by hand. Two were
consistent at every boundary (litestar, three branches; bugsink, four), and one
produced the project's first under-report: PYSEC-2021-382 marks qutebrowser
1.8.0 through 1.14.1 as safe when the fix does not land until 2.4.0. See
`testdata/corpus/AUDIT-FINDINGS.md`.

Only `any` exists as a combinator. An `all` combinator would let one location's
UNKNOWN turn the whole result into NOT_VULNERABLE unless the three-valued
conjunction is exactly right, and that is the direction that under-reports. It
waits until it has its own adversarial fixtures.

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

[Unreleased]: https://github.com/nickelsec/taggity/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/nickelsec/taggity/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/nickelsec/taggity/releases/tag/v0.1.0

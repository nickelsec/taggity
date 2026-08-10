# taggity

[![CI](https://github.com/nickelsec/taggity/actions/workflows/ci.yml/badge.svg)](https://github.com/nickelsec/taggity/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue)](LICENSE)

```
  ◇──◇──◆──◆──◇
     [ TAGGITY ]
       └─ hunt the tags

  testing where it breaks.
```

Audits published vulnerability advisories and finds where their affected
version ranges are wrong.

> **Status: early development.** The engine is being built in the open. No
> release yet — see [Limitations](#limitations) before relying on anything here.

## The problem

Filing a vulnerability report means stating which versions are affected. Working
that out accurately is manual archaeology — trace the fix commit, map it to
tags, check whether the fix was backported to every maintenance branch. Because
it is expensive, people guess, and "version X and earlier" is usually wrong.

The errors are real and measurable. In `github/advisory-database` there are
**108 merged pull requests correcting affected version ranges** and **99
mentioning backports**. One React Router advisory drew four separate corrections
from four different people, each doing the same archaeology by hand. A
django-haystack advisory shipped with the literal string `eval()` where its
version range should have been — visible to humans, inert to every scanner.

Wrong ranges are not cosmetic. A version wrongly marked safe is a version whose
users are never told to upgrade.

## What taggity does

It answers one question, reproducibly:

> Does this exact version contain this exact vulnerable construct?

Given a spec, it resolves the version to a commit, parses the source, and
reports `VULNERABLE`, `NOT_VULNERABLE`, or `UNKNOWN` — with evidence detailed
enough for someone else to re-derive the answer by hand.

```yaml
package: { ecosystem: PyPI, name: examplepkg }
repo: https://github.com/example/examplepkg
advisory: GHSA-xxxx-yyyy-zzzz

signal:
  code:
    file: src/parser.py
    symbol: Alpha.parse_untrusted
    rule: { calls: eval }
```

Running that against an advisory's boundary versions surfaces disagreements: a
range claiming `>= 2.0.0` while the vulnerable code is still present in 1.9.x
because the fix was never backported.

## Usage

```sh
# Check one version.
taggity check redis@4.5.4 --spec spec.yaml

# Audit an advisory's boundaries. A range is an assertion about its edges, so
# only those are probed — 11 checks against redis-py's 157 tags.
taggity audit --spec spec.yaml --advisory GHSA-8fww-64cx-x8p5.json

# Scaffold a spec.
taggity init --repo https://github.com/redis/redis-py --package redis \
  --file redis/asyncio/client.py --symbol Redis.execute_command --calls eval

# Emit OSV for what the audit established.
taggity export --spec spec.yaml --advisory GHSA-8fww-64cx-x8p5.json
```

A real audit reads like this:

```
GHSA-8fww-64cx-x8p5  redis
  claims  >= 4.5.0, < 4.5.4
  claims  >= 4.2.0, < 4.4.4
  probed  11 of 157 tags

  DISAGREEMENTS
    5.3.1–8.1.0      NOT_VULNERABLE  [unmentioned-line]

  GAPS (could not answer)
    2.10.6–4.1.4     [file_absent]

  1 finding(s) across 4 versions · 4 consistent · 0 narrower · 1 gap(s)
```

Findings are grouped by structural change rather than counted per version. One
edit shows up at every release after it, so counting versions would inflate a
report by however many happened to be probed.

**A disagreement is a reading assignment, not a conclusion.** The example above
was investigated by hand and turned out to be correct behaviour: the guard was
deliberately removed one release after the fix and replaced with a different
mechanism. `taggity export` records unreviewed disagreements separately from
established versions for exactly this reason — it will not publish one as fact.

## Reproducibility, not confidence

There is no reliable ground truth here. NVD and GHSA are themselves frequently
wrong, and independent tools disagree on the same vulnerability with no arbiter.
A tool emitting `VULNERABLE (confidence: 92%)` would be making a claim no
experiment could falsify.

So taggity does not claim to be right. It claims to be **reproducible**: here is
exactly what was checked, here is how to repeat it, here is where it was
uncertain. Every finding ships with the command that reproduces it.

## Design

**`UNKNOWN` is a real answer.** When a symbol has been refactored away or a
version has no matching tag, the honest output is "I could not determine this",
not a guess. `UNKNOWN` versions are excluded from exported OSV rather than
assumed safe.

**Under-reporting is the only unacceptable failure.** Wrongly flagging a version
is recoverable — a maintainer disputes it and the range narrows. Wrongly
clearing one means a scanner stays silent. Exactly one code path in this
repository can conclude `NOT_VULNERABLE`, and a test enforces that structurally.

**Verdicts are structural, not textual.** Matching uses a real parser
([gotreesitter](https://github.com/odvcencio/gotreesitter), pure Go, no cgo), so
`eval(` in a comment, a docstring, or a nested function does not count as a
call. An early prototype used substring matching and was wrong on three of six
adversarial cases while looking entirely correct.

## Limitations

Stated plainly, because a tool that overclaims here is worse than no tool.

- **PyPI only.** The ecosystem interface exists; npm is next.
- **One rule type: `calls`.** Everything else returns `UNKNOWN`. This covers
  `eval`, `exec`, `pickle.loads`, `os.system`, and similar sinks, but not
  vulnerabilities that are not call-shaped. PyYAML's `yaml.load` fix changed a
  default argument rather than a call, and `calls` cannot express that.
- **A git repository is required.** Missing or unreachable means a hard error,
  never a verdict.
- **The tag is assumed to be what was published.** Uploads from a dirty tree and
  untagged hotfixes are not detected.
- **Aliased imports are not resolved.** `from pickle import loads; loads(x)`
  will not match `calls: pickle.loads`.
- **No execution, no reachability analysis.** Code presence is not
  exploitability.

## Development

```sh
make test       # hermetic tests
make test-live  # clones real repositories over the network
make lint
make build
```

## License

Apache-2.0. See [LICENSE](LICENSE).

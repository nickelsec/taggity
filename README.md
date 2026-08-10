# taggity

[![CI](https://github.com/nickelsec/taggity/actions/workflows/ci.yml/badge.svg)](https://github.com/nickelsec/taggity/actions/workflows/ci.yml)

```
     ┌─ taggity ─┐
     │           ▼
  ◇──◇──◇──◆──◆──◇
           └──┬──┘
          vulnerable
```

Checks whether a published advisory's affected version range matches the source.

Advisories get version ranges wrong regularly. A fix gets backported to 2.x but
not 1.x, and the advisory only mentions 2.x. Or the range is copied from a
release note that was already wrong. In `github/advisory-database` there are 99
merged pull requests mentioning backports, most of them corrections someone
worked out by hand.

taggity answers one question, repeatably: does this exact version contain this
exact construct? Point it at an advisory and it probes the versions where the
claimed range would be wrong.

## Install

```sh
go install github.com/nickelsec/taggity/cmd/taggity@latest
```

Binaries for Linux, macOS and Windows are on the
[releases page](https://github.com/nickelsec/taggity/releases), with checksums
and an SBOM. Pure Go, no cgo, so nothing needs a C compiler.

## How it works

You write a spec describing the vulnerable construct:

```yaml
package:
  ecosystem: PyPI
  name: examplepkg
repo: https://github.com/example/examplepkg
advisory: GHSA-xxxx-yyyy-zzzz

signal:
  code:
    file: src/parser.py
    symbol: Alpha.parse_untrusted
    rule:
      calls: eval
```

A rule asks one structural question. `calls` looks for a call in the symbol's
own scope. `defaults` looks at parameter defaults, which is what you need when
a fix changed a signature rather than a call body:

```yaml
    rule:
      defaults:
        Loader: Loader
```

That one is the PyYAML case. `load()` constructs a `Loader` in every released
version, so asking about the call cannot find the boundary; asking about the
default puts it at 5.1, where the advisory says it is.

Then run it against a version, or against a whole advisory:

```sh
taggity check redis@4.5.3 --spec spec.yaml

taggity audit --spec testdata/corpus/GHSA-8fww-64cx-x8p5.yaml \
  --advisory testdata/corpus/GHSA-8fww-64cx-x8p5.json
```

An audit looks like this:

```
GHSA-8fww-64cx-x8p5  redis
  claims  >= 4.5.0, < 4.5.4
  claims  >= 4.2.0, < 4.4.4
  rule    calls: asyncio.shield (indicates: fixed) in Redis.execute_command
          (matches the FIX; a match means the fix is present)
  probed  11 of 157 tags

  DISAGREEMENTS
    5.3.1-8.1.0      NOT_VULNERABLE  [unmentioned-line]

  GAPS (could not answer)
    2.10.6-4.1.4     [file_absent]

  1 finding(s) across 4 versions · 4 consistent · 0 narrower · 1 gap(s) across 3 versions
```

A range is a claim about its edges, so only the edges get probed. That is 11
checks against redis-py's 157 tags instead of 157.

A disagreement is something to go read, not a correction to file. The one above
was investigated by hand and turned out to be fine: the guard was deliberately
removed a release after the fix and replaced with a different mechanism.
`taggity export` keeps unreviewed disagreements out of its OSV output for that
reason.

`taggity init` will scaffold a spec if you would rather not write the YAML by
hand.

## Three-valued verdicts

Verdicts are `VULNERABLE`, `NOT_VULNERABLE`, or `UNKNOWN`.

`UNKNOWN` is an answer. Going backwards through history a symbol gets renamed,
a file moves, code gets refactored, and the construct stops matching for
reasons that have nothing to do with the vulnerability. A tool that reports
"not vulnerable" there is confidently wrong in the direction that gets someone
compromised, so taggity says it could not tell and gives a reason code.

Wrongly flagging a version is recoverable; a maintainer disputes it and the
range narrows. Wrongly clearing one means a scanner stays quiet. Exactly one
code path in the repository can conclude `NOT_VULNERABLE`, and
`internal/taggity/invariant_test.go` walks the AST to keep it that way.

Matching runs on a real parser
([gotreesitter](https://github.com/odvcencio/gotreesitter)), so `eval(` in a
comment, a docstring or a nested function is not a call. An early prototype
used substring matching and was wrong on three of six adversarial cases while
looking entirely correct.

## What it does not do

- PyPI only. `package.ecosystem` is recorded and echoed into exported OSV, but
  nothing dispatches on it. There is one code path and it assumes Python.
- Two rule kinds. `calls` covers `eval`, `exec`, `pickle.loads`, `os.system`
  and similar sinks. `defaults` covers a changed default argument, which is how
  PyYAML's `yaml.load` was fixed. Vulnerabilities of any other shape, such as
  changed callee behaviour, are `UNKNOWN`.
- Needs a git repository. No repo, no answer.
- Assumes the tag is what was published. Uploads from a dirty tree and
  untagged hotfixes are invisible.
- Does not resolve aliased imports. `from pickle import loads; loads(x)` will
  not match `calls: pickle.loads`.
- `signal.code.aliases` is reserved. It parses, so specs written now will not
  need migrating, but nothing evaluates it and a spec that sets it is rejected
  rather than silently ignored.
- No execution and no reachability analysis. Code being present is not the same
  as it being exploitable.
- `check` exits 0 even when the verdict is `VULNERABLE`. The exit status says
  whether the run worked, not what it found, so that a loop over versions is
  usable. Read the verdict on stdout, or pass `--quiet` to get it alone.

Some fixes add a guard rather than removing a dangerous call. Those specs set
`indicates: fixed` and their verdicts read inverted. It works, but it is the
weaker direction: a guard that disappears may have been reimplemented rather
than removed.

## Development

```sh
make test         # hermetic, no network
make test-corpus  # clones real repositories and checks against real advisories
make lint
make build
```

The corpus lives in `testdata/corpus/` alongside notes on what each case
established. `make test-corpus` is what reproduces the results above.

## License

Apache-2.0. See [LICENSE](LICENSE).

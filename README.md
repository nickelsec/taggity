# taggity

[![CI](https://github.com/nickelsec/taggity/actions/workflows/ci.yml/badge.svg)](https://github.com/nickelsec/taggity/actions/workflows/ci.yml)

```
     ┌─ taggity ─┐
     │           ▼
  ◇──◇──◇──◆──◆──◇
           └──┬──┘
          vulnerable
```

Answers one question about a released version: does it contain the vulnerable
code?

```sh
taggity check pyyaml@3.13 --spec testdata/corpus/GHSA-rprw-h62v-c2w7-defaults.yaml
```

```
  present    VULNERABLE      load declares Loader=Loader
  → VULNERABLE
  at 3.13 (a2d481b8dbd2) lib/yaml/__init__.py
```

The verdict comes with the tag, the commit and the file it was read from, so
anyone can check the answer by hand. Verdicts are `VULNERABLE`,
`NOT_VULNERABLE` or `UNKNOWN`, and the third one is used often: when the symbol
moved or the file was unreadable, taggity says so instead of reporting the
version clean.

Once you can ask that about one version, you can ask it about the edges of an
advisory's range, which is where advisories tend to be wrong. A fix gets
backported to 2.x but not 1.x and the advisory only mentions 2.x. Or the range
is copied from a release note that was already wrong. In
`github/advisory-database` there are 99 merged pull requests mentioning
backports, most of them corrections someone worked out by hand. `taggity audit`
probes the versions where the claimed range would be wrong.

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

Then run it against a version:

```sh
taggity check redis@4.5.3 --spec spec.yaml
```

### When the code moves

Symbols get renamed and files get split, so a spec naming one path stops
matching for reasons that have nothing to do with the vulnerability. A package
that grew a `client/` package out of a single module can leave the same function
in three different files across one version range.

`code_any` takes several locations and the version counts as affected if any of
them matches:

```yaml
signal:
  code_any:
    - file: src/examplepkg/client/utils.py
      symbol: build_request
      rule: { calls: requests.get }
    - file: src/examplepkg/client/base.py
      symbol: Client._build_request
      rule: { calls: requests.get }
    - file: src/examplepkg/client.py
      symbol: Client._build_request
      rule: { calls: requests.get }
```

Output names the location that answered, and marks it in the breakdown:

```
  present    VULNERABLE      Client._build_request calls requests.get

     UNKNOWN         src/examplepkg/client/utils.py  not present at v1.4.0
     UNKNOWN         src/examplepkg/client/base.py   not present at v1.4.0
   * VULNERABLE      src/examplepkg/client.py        Client._build_request calls requests.get
```

If no location matches and one of them could not be read, the result is
`UNKNOWN`, not `NOT_VULNERABLE`. A location that was never examined is not a
location found clean.

When the symbol itself was renamed rather than moved, pin the old name to the
versions that carried it. A method promoted to a module function is the common
case:

```yaml
      symbol: build_request
      aliases:
        - symbol: Client._build_request
          versions:
            until: "2.0.0"
          source: human
```

The spec's own symbol is tried first, so an alias only answers where the real
name found nothing and adding one cannot change a version that already had an
answer. A verdict reached through an alias says so:

```
  * VULNERABLE  src/examplepkg/client.py  Client._build_request calls requests.get
                (alias for build_request)
```

An alias is a human claim that two names are the same construct, so the output
names the symbol that was actually read and leaves that claim visible.

## Auditing an advisory's range

A range is a claim about its edges, so `audit` probes the edges:

```sh
taggity audit --spec testdata/corpus/GHSA-8fww-64cx-x8p5.yaml \
  --advisory testdata/corpus/GHSA-8fww-64cx-x8p5.json
```

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

That is 11 checks against redis-py's 157 tags instead of 157.

A disagreement is something to go read, not a correction to file. The one above
was investigated by hand and turned out to be fine: the guard was deliberately
removed a release after the fix and replaced with a different mechanism.
`taggity export` keeps unreviewed disagreements out of its OSV output for that
reason.

Some of them hold up. PYSEC-2021-382 splits qutebrowser's CVE-2021-41146 into
`< 1.8.0` and `>= 2.0.0, < 2.4.0`, which leaves 1.8.0 through 1.14.1 implied
safe. The guard exists in no 1.x release, the advisory's own text says the fix
landed in 2.4.0, and the GHSA record for the same CVE uses one correct range of
`>= 1.7.0, < 2.4.0`. Eleven minor releases marked safe that are not.

`taggity init` will scaffold a spec if you would rather not write the YAML by
hand.

## Three valued verdicts

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
- Rules ask whether a construct is present, which is not always the same
  question as whether the bug is. A missing input check is a good example: the
  sink is there before and after the fix, and only a guard around it changes.
  A rule naming the sink will keep reporting `VULNERABLE` after the fix lands.
  Write the rule against something the fix actually adds or removes, and if
  nothing structural changes, the spec cannot express that vulnerability.
- Needs a git repository. No repo, no answer.
- Assumes the tag is what was published. Uploads from a dirty tree and
  untagged hotfixes are invisible.
- Does not resolve aliased imports. `from pickle import loads; loads(x)` will
  not match `calls: pickle.loads`.
- Aliases cover a renamed symbol, not a reimplemented one. Pinning the old name
  works when a fix renamed a function; it does nothing when the protection moved
  to a different module with a different decomposition, which is the more common
  shape and still reads as absence.
- No execution and no reachability analysis. Code being present is not the same
  as it being exploitable.
- `check` exits 0 even when the verdict is `VULNERABLE`. The exit status says
  whether the run worked, not what it found, so that a loop over versions is
  usable. Read the verdict on stdout, or pass `--quiet` to get it alone.

Most fixes add a guard rather than removing a dangerous call, so most specs set
`indicates: fixed` and their verdicts read inverted. That is the weaker
direction: a guard that disappears may have been reimplemented rather than
removed, which happened twice in the corpus.

Expect to hit it. Filtering the PyPI advisory database for multi-range
advisories whose fix deletes a dangerous call leaves seven candidates out of
1549 packages, and all seven are single-range. Of nine advisories audited here,
only two removed a call.

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

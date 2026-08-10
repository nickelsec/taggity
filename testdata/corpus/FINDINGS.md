# Corpus findings

What the engine does when pointed at real advisories and real repositories.
Ground truth is established by reading the source at each tag, not by trusting
the advisory.

Run with `go test -tags corpus ./internal/check/ -v`.

## Results

| | |
|---|---|
| versions checked | 10 |
| correct | 10 |
| under-reports | **0** |
| over-reports | 0 |
| unknown | 1 (`no_tag`, correct) |

Every mechanical component behaved: version resolution across three tag
conventions, blob reads, symbol resolution including `Class.method`
qualification, scope-correct call matching, and `UNKNOWN` for an unresolvable
version.

**That number is not a claim of usefulness.** See below.

## The finding that matters: `calls` cannot see either PyYAML fix

Both corpus advisories are real, both were fixed, and in both cases the
`calls` rule reports the construct as present at every version including the
fixed ones.

### GHSA-rprw-h62v-c2w7 — `yaml.load` arbitrary code execution

Claimed range `>= 0, < 5.1`. The 5.1 fix changed the signature from
`load(stream, Loader=Loader)` to `load(stream, Loader=None)` plus a warning
path that defaults to `FullLoader`.

`load` still calls `Loader(stream)` in 3.12, 3.13, 5.1, 5.4.1 and 6.0.1.
The vulnerability lived in a **default argument value**, and a call rule cannot
express that.

### GHSA-6757-jp84-gxfx — `python/object/apply` code execution

Claimed range `>= 5.1b7, < 5.3.1`. Verified by reading
`lib/yaml/constructor.py` at each tag:
`FullConstructor.construct_python_object_apply` calls
`self.make_python_instance` at 5.1, 5.3, 5.3.1 and 6.0.1. Commit `0cedb2a`
changed what `make_python_instance` does; it did not remove the call.

The registration that did move (`FullConstructor` to `UnsafeConstructor`) is a
module-level statement, and `calls` only looks inside function definitions.

## What this says about the tool

The engine answers the question it is asked, correctly. The gap is the
**question**: a `calls` rule expresses "does X call Y", and a large class of
real fixes are not call-shaped.

Vulnerability shapes seen so far and whether `calls` reaches them:

| shape | expressible? |
|---|---|
| dangerous sink invoked (`eval`, `os.system`, `pickle.loads`) | yes |
| default argument changed (`Loader=Loader` to `Loader=None`) | **no** |
| behaviour of the callee changed | **no** |
| module-level registration moved | **no** |
| guard added before the sink | no — and deliberately so, since proving absence points at under-reporting |

Two consequences:

1. A `VULNERABLE` verdict means *the construct in the spec is present*, never
   *this version is exploitable*. Reports must say so.
2. The corpus decides which rule kind earns its adversarial fixtures next.
   Right now the evidence points at a rule that can see argument defaults, not
   at broader call matching.

## Process note: the corpus caught a bad spec, not a bad engine

The first run showed two under-reports on GHSA-6757. Investigation showed the
call site is `self.make_python_instance(...)`, an attribute expression, while
the spec asked for the bare name `make_python_instance`. The engine was right
and the spec was wrong.

That is the correct division of labour — the spec carries the claim and the
engine reports what is there — but it means **a spec is only as good as the
question it encodes**, and a wrong spec produces a confident wrong answer. This
is the strongest argument for reviewing model-drafted specs rather than
trusting them.

## Not yet exercised

- Multi-branch backports, where an advisory covers several release lines.
  `redis-py` GHSA-8fww-64cx-x8p5 (`>= 4.5.0, < 4.5.4` and `>= 4.2.0, < 4.4.4`)
  is the obvious next case.
- Boundary selection, which is what turns per-version checks into an audit.
- Any advisory whose fix genuinely removes a call — needed to prove the engine
  can produce a `NOT_VULNERABLE` on real code rather than only on fixtures.

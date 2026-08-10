# Audit findings

First end-to-end audit: boundary selection driving the engine against a real
advisory. Run with `go test -tags corpus ./internal/audit/ -v`.

## GHSA-8fww-64cx-x8p5 — redis-py, multi-branch backport

The case the design targets: one advisory, two release lines, each with its own
backported fix.

```
claims  >= 4.5.0, < 4.5.4
claims  >= 4.2.0, < 4.4.4

157 tags in the repository, 11 probed (7.0%)

version    fix present?   rule                   outcome
2.10.6     UNKNOWN        unmentioned-line       [file_absent]
3.5.3      UNKNOWN        unmentioned-line       [file_absent]
4.1.4      UNKNOWN        below-introduced       [file_absent]
4.4.3      absent         below-fixed            consistent
4.4.4      PRESENT        fixed                  consistent
4.5.3      absent         below-fixed            consistent
4.5.4      PRESENT        fixed                  consistent
5.3.1      absent         unmentioned-line       DISAGREEMENT
6.4.0      absent         unmentioned-line       DISAGREEMENT
7.4.1      absent         unmentioned-line       DISAGREEMENT
8.1.0      absent         unmentioned-line       DISAGREEMENT

findings 4 · consistent 4 · narrower 0 · unknown 3
```

### What worked

**The engine independently located both backported fixes.** Without being told
where they were, `asyncio.shield` was found in `Redis.execute_command` at
exactly 4.4.4 and 4.5.4 — the two versions the advisory names as fixed — and in
neither 4.4.3 nor 4.5.3. That is the multi-branch backport case resolving
correctly on real code.

**Boundary selection is cheap.** Eleven checks against 157 tags. Auditing at
scale is arithmetically possible.

**`file_absent` behaved as designed.** `redis/asyncio/client.py` did not exist
before 4.2.x, so the three oldest probes returned `UNKNOWN [file_absent]` and
the audit continued rather than aborting. Those three are honest gaps, not
failures.

### The finding that needs a human

`asyncio.shield` is **absent from 5.0.1 and every later release**. Verified by
reading `redis/asyncio/client.py` at v5.0.1: `execute_command` returns to the
pre-fix shape, calling `conn.retry.call_with_retry` directly with no shield.

That is a genuine structural observation. What it means is not settled:

- the guard may have been superseded by a different mechanism in 5.x
- or the fix may not have carried forward across the major version

Determining which requires reading the 5.x rewrite, and this is exactly the
"needs review" case the design intends to surface rather than assert.

## Two problems this run exposed

### 1. Inverted-polarity specs broke the classifier — fixed

The `calls` vocabulary can only ask "is this construct present". The redis fix
*added* a call, so the spec asks whether the **fix** is present, and verdicts
must be read backwards.

The classifier did not know that, so it first labelled 4.4.4 and 4.5.4 —
correctly-fixed versions — as disagreements. The verdicts were right and the
outcomes were wrong.

Fixed by adding polarity to the rule:

```yaml
rule:
  calls: asyncio.shield
  indicates: fixed        # default is "vulnerable"
```

After the fix all four in-range boundaries classify as consistent, and the only
disagreements are the 5.x-onward absences described above.

### 2. Unmentioned-line probes need release-line awareness

The 5.x through 8.x probes fire the `unmentioned-line` rule, which is correct —
the advisory says nothing about them. But an advisory about 4.x should probably
not treat 8.x as a suspicious silence; those lines postdate the fix entirely.

Worth revisiting once there is a second multi-branch case to compare against.
Probing them is cheap and the answers are honest, so this is noise rather than
error.

## Status against the plan

The product thesis is no longer untested. The engine drove a real advisory's
boundaries, located both backported fixes unaided, classified every in-range
version consistently with the advisory, and surfaced four versions where the
guard is absent.

Two honest caveats on that result.

**The four disagreements are one observation, not four.** They are consecutive
releases in the 5.x-and-later lines, all reflecting the same structural change.
A report that counted them as four findings would overstate what was found.

**A disagreement is not yet a correction.** The engine established that
`asyncio.shield` is absent from 5.x; it did not establish that 5.x is
vulnerable. The 5.x rewrite may guard the same race differently. Filing this as
an advisory correction without reading that rewrite is exactly the false
disagreement the design warns about — the tool's job here is to point a human at
four versions worth reading, and it did that.

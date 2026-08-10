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

findings 1 (4 versions) · consistent 4 · narrower 0 · unknown 1 (3 versions)

FINDING  5.3.1-8.1.0    [unmentioned-line]
gap      2.10.6-4.1.4   [file_absent]
```

Findings are grouped: consecutive probed versions sharing a verdict are one
structural observation, not one per version. See below.

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

### The finding, and what it turned out to mean — RESOLVED

The audit flagged `asyncio.shield` as absent from every 5.x release. Following
that up by hand produced a more precise answer than the audit could.

**Walking every released tag** and counting occurrences in
`redis/asyncio/client.py`:

```
v4.4.4   1 -> 4    fix lands on the 4.4 line
v4.5.0   4 -> 0    4.5.0 predates the backport
v4.5.4   1 -> 4    fix lands on the 4.5 line
v4.5.5   4 -> 0    removed, one release later
```

The guard did not survive into 5.x because **it was removed in 4.5.5**, the very
next release after the fix. Across the whole async surface — `client.py`,
`connection.py`, `cluster.py`, `retry.py` — 4.5.4 has seven occurrences and
5.0.0 has none. It did not move; it was taken out.

**Why:** the shield caused its own problems. Issue #2722 reports
`read() called while another coroutine is already waiting for incoming data`
against 4.5.4 specifically. PR #2695, listed in the 4.5.5 release notes as
*"Optionally disable disconnects in read_response"*, replaced the approach, and
its description says the earlier work *"prompted recent changes to async code
that are not necessary."*

**So 5.x is not unpatched.** The race is addressed by a different mechanism, and
the advisory's ranges are correct. This was a true observation about the code
and a false signal about the vulnerability.

### What this cost, and what it is worth

The audit could not have reached this conclusion. It observed an absence; a
human read four PRs, an issue thread, and a changelog to learn that the absence
was deliberate and safe.

That is the intended division of labour, but it sets the honest expectation:
**a disagreement is a reading assignment, not a finding.** Had this been filed
as an advisory correction on the strength of the audit alone, it would have been
wrong, and wrong in public against a maintainer.

It also sharpens a design point. Matching on a *guard* rather than a *danger* is
fragile precisely because guards get replaced: the construct disappearing means
"this specific implementation is gone", not "the protection is gone". Specs with
`indicates: fixed` should be read with that in mind, and preferred only when no
danger-shaped rule is available.

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
boundaries, located both backported fixes unaided, and classified every in-range
version consistently with the advisory.

It also produced four disagreements that a human resolved to *not a finding*.
That is a useful result rather than a disappointing one — the first real audit
established a working pipeline and calibrated what its output means.

Three things the run settled:

**The four disagreements were one observation** — now reported that way. A
single commit in 4.5.5 explained every one of them, so counting per version
inflated the report fourfold. Reports group consecutive versions sharing a
verdict and reason, and stop grouping at any gap, since a construct that
disappears and returns is two changes rather than one span. Raw per-version
tallies remain available for when probe count is what matters.

**A guard-shaped spec is fragile by construction.** Matching the absence of
`asyncio.shield` cannot distinguish "protection removed" from "protection
reimplemented", and here it was the latter. Prefer danger-shaped rules; use
`indicates: fixed` only when nothing else is available, and treat its
disagreements as weaker evidence.

**Zero under-reports held.** Nothing affected was reported safe, on either the
in-range versions or the follow-up investigation.

## GHSA-wxj7-3fx5-pp9m — MLflow, and the first real finding

The second multi-branch case. MLflow's `gateway_proxy_handler` forwarded a
caller-supplied `gateway_path` into an outbound request (SSRF, CWE-918). The fix
extracted `_validate_gateway_path` and calls it before the request is built, and
was released on two lines: 3.1.0 on mainline, 2.22.2 as a backport.

```
claims  >= 3.0.0rc0, < 3.1.0
claims  < 2.22.2

174 tags in the repository, 7 probed (4.0%)

version    fix present?   rule                   outcome
0.9.1      UNKNOWN        unmentioned-line       [symbol_not_found]
1.30.0     UNKNOWN        unmentioned-line       [symbol_not_found]
2.22.1     absent         below-fixed            consistent
2.22.2     PRESENT        fixed                  consistent
2.22.4     PRESENT        below-introduced       consistent
3.0.1      PRESENT        below-fixed            narrower-than-claimed
3.1.0      PRESENT        fixed                  consistent

OVERCLAIM  3.0.1          [below-fixed]
gap        0.9.1-1.30.0   [symbol_not_found]
```

### The finding

**The advisory's 3.x range is wrong.** It claims `>= 3.0.0rc0, < 3.1.0` and
enumerates `3.0.0` and `3.0.1` as affected. Both already contain the fix.

Verified three independent ways:

- **By tag content.** `_validate_gateway_path` is absent from every 3.0.0
  release candidate (rc0–rc3) and present at 3.0.0, 3.0.1 and 3.1.0.
- **By history.** Commit `4a0f6c1345` ("Validate `gateway_path` in
  `gateway_proxy_handler`", #15970) landed 2025-06-02, and
  `git tag --contains` lists `v3.0.0`.
- **By the engine**, which reached the same boundaries unaided.

The range should end at the last release candidate. As published, two shipped
releases are marked vulnerable when they are not — the over-report direction,
so nobody is left unwarned, but the advisory is still wrong.

This is the first observation in the corpus that survived investigation. The
redis one did not.

### What worked

**Both branches' fixes located unaided**, at 2.22.2 and 3.1.0, absent at 2.22.1.
The backport case resolved correctly a second time.

**Boundary selection stayed cheap and was sufficient.** Seven probes out of 174
tags (4.0%), and the edge probe alone exposed the error — `below-fixed` selects
only the version immediately under `fixed`, which was 3.0.1. Probing the range
interior would have cost more and found the same thing.

**`symbol_not_found` behaved as designed.** `gateway_proxy_handler` did not exist
in 0.9.1 or 1.30.0, so those probes are honest gaps rather than false clears.

### The defect this run exposed — fixed

**The finding was invisible.** It classified as `narrower-than-claimed`, which
`Findings()` deliberately excludes, and the report printed **`0 finding(s)`** for
an advisory that is demonstrably wrong. The only trace was a `1 narrower` count
in the summary line.

The exclusion itself is right: `Narrower` normally means the engine could not see
something the advisory claims, which is usually the spec's blind spot. But that
reasoning assumes a **danger-shaped** rule. Under `indicates: fixed` the polarity
inverts — `Narrower` means *the guard was found present*, which is positive
evidence, not missing evidence.

Fixed by adding `Report.Overclaims()` and rendering it as its own section,
`CLAIMED BUT NOT OBSERVED (needs review, not a finding)`. It stays out of
`Findings()` and out of `export`, so nothing unreviewed is ever published as a
claim — but it is now on screen where a reader will see it.

### What this says about `unmentioned-line`

The rule fired twice here (0.9.1, 1.30.0) and both times returned
`symbol_not_found` — honest gaps, no noise. Combined with redis, where it
produced four true-but-immaterial disagreements, the picture is that the rule is
**not wrong, but its yield depends entirely on how far the unmentioned lines are
from the fix.** No change yet; a third case should decide whether it needs
release-line distance awareness.

### Two guard-shaped fixes out of two

Worth naming: both multi-branch advisories in the corpus were fixed by **adding a
check**, not by removing a dangerous call. The `calls` vocabulary was designed
around danger-shaped constructs, and real backported fixes keep turning out to be
the other shape.

That makes `indicates: fixed` the common path rather than the exception, despite
the redis run establishing that it is the fragile one. A rule kind that can
express "this argument is unvalidated" would fit these cases better than
inverting polarity does.

## Next

Two multi-branch cases audited, one real finding. The boundary rules generalised:
both located their fixes unaided, and both stayed under 7% of tags probed.

The open question is no longer whether the engine works but whether the rule
vocabulary matches the shape of real fixes. Two for two on guard-shaped fixes
suggests it does not, quite.

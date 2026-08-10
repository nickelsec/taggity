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

**The four disagreements were one observation.** Consecutive releases reflecting
a single change. Reports must group by structural change, not count versions,
or a single edit reads as four findings.

**A guard-shaped spec is fragile by construction.** Matching the absence of
`asyncio.shield` cannot distinguish "protection removed" from "protection
reimplemented", and here it was the latter. Prefer danger-shaped rules; use
`indicates: fixed` only when nothing else is available, and treat its
disagreements as weaker evidence.

**Zero under-reports held.** Nothing affected was reported safe, on either the
in-range versions or the follow-up investigation.

## Next

The engine has now been exercised end to end on one advisory. A second
multi-branch case is needed before the boundary rules can be trusted to
generalise — particularly the `unmentioned-line` rule, whose only outing so far
produced four true-but-immaterial disagreements.

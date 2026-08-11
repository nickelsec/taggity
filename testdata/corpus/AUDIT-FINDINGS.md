# Audit findings

First end-to-end audit: boundary selection driving the engine against a real
advisory. Run with `go test -tags corpus ./internal/audit/ -v`.

## GHSA-8fww-64cx-x8p5: redis-py, multi-branch backport

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
exactly 4.4.4 and 4.5.4, the two versions the advisory names as fixed, and in
neither 4.4.3 nor 4.5.3. That is the multi-branch backport case resolving
correctly on real code.

**Boundary selection is cheap.** Eleven checks against 157 tags. Auditing at
scale is arithmetically possible.

**`file_absent` behaved as designed.** `redis/asyncio/client.py` did not exist
before 4.2.x, so the three oldest probes returned `UNKNOWN [file_absent]` and
the audit continued rather than aborting. Those three are honest gaps, not
failures.

### The finding, and what it turned out to mean: RESOLVED

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
next release after the fix. Across the whole async surface (`client.py`,
`connection.py`, `cluster.py`, `retry.py`) 4.5.4 has seven occurrences and
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

### 1. Inverted-polarity specs broke the classifier: fixed

The `calls` vocabulary can only ask "is this construct present". The redis fix
*added* a call, so the spec asks whether the **fix** is present, and verdicts
must be read backwards.

The classifier did not know that, so it first labelled 4.4.4 and 4.5.4, both
correctly-fixed versions, as disagreements. The verdicts were right and the
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

The 5.x through 8.x probes fire the `unmentioned-line` rule, which is correct:
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
That is a useful result rather than a disappointing one. The first real audit
established a working pipeline and calibrated what its output means.

Three things the run settled:

**The four disagreements were one observation**, now reported that way. A
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

## GHSA-wxj7-3fx5-pp9m: MLflow, and the first real finding

The second multi-branch case. MLflow's `gateway_proxy_handler` forwarded a
caller-supplied `gateway_path` into an outbound request (SSRF, CWE-918). The fix
extracted `_validate_gateway_path` and calls it before the request is built, and
was released on two lines: 3.1.0 on mainline, 2.22.2 as a backport.

```
claims  >= 3.0.0rc0, < 3.1.0
claims  < 2.22.2

174 tags in the repository, 5 probed (2.9%)

version    fix present?   rule                   outcome
2.22.1     absent         below-fixed            consistent
2.22.2     PRESENT        fixed                  consistent
2.22.4     PRESENT        below-introduced       consistent
3.0.1      PRESENT        below-fixed            narrower-than-claimed
3.1.0      PRESENT        fixed                  consistent

OVERCLAIM  3.0.1          [below-fixed]
```

Originally 7 probes. The open-below fix described under Vitrage removed 0.9.1
and 1.30.0: both sit below the claim `< 2.22.2`, which covers them, so they
were never unmentioned lines. Their `symbol_not_found` results were noise
rather than gaps in coverage, and the finding is unchanged.

### The finding

**The advisory's 3.x range is wrong.** It claims `>= 3.0.0rc0, < 3.1.0` and
enumerates `3.0.0` and `3.0.1` as affected. Both already contain the fix.

Verified three independent ways:

- **By tag content.** `_validate_gateway_path` is absent from every 3.0.0
  release candidate (rc0,rc3) and present at 3.0.0, 3.0.1 and 3.1.0.
- **By history.** Commit `4a0f6c1345` ("Validate `gateway_path` in
  `gateway_proxy_handler`", #15970) landed 2025-06-02, and
  `git tag --contains` lists `v3.0.0`.
- **By the engine**, which reached the same boundaries unaided.

The range should end at the last release candidate. As published, two shipped
releases are marked vulnerable when they are not, the over-report direction,
so nobody is left unwarned, but the advisory is still wrong.

This is the first observation in the corpus that survived investigation. The
redis one did not.

### What worked

**Both branches' fixes located unaided**, at 2.22.2 and 3.1.0, absent at 2.22.1.
The backport case resolved correctly a second time.

**Boundary selection stayed cheap and was sufficient.** Five probes out of 174
tags (2.9%), and the edge probe alone exposed the error, `below-fixed` selects
only the version immediately under `fixed`, which was 3.0.1. Probing the range
interior would have cost more and found the same thing.

**`symbol_not_found` behaved as designed** on the run this section originally
recorded: `gateway_proxy_handler` did not exist in 0.9.1 or 1.30.0, so those
probes returned honest gaps rather than false clears. Those two versions are no
longer probed at all, see the note under the table.

### The defect this run exposed: fixed

**The finding was invisible.** It classified as `narrower-than-claimed`, which
`Findings()` deliberately excludes, and the report printed **`0 finding(s)`** for
an advisory that is demonstrably wrong. The only trace was a `1 narrower` count
in the summary line.

The exclusion itself is right: `Narrower` normally means the engine could not see
something the advisory claims, which is usually the spec's blind spot. But that
reasoning assumes a **danger-shaped** rule. Under `indicates: fixed` the polarity
inverts, `Narrower` means *the guard was found present*, which is positive
evidence, not missing evidence.

Fixed by adding `Report.Overclaims()` and rendering it as its own section,
`CLAIMED BUT NOT OBSERVED (needs review, not a finding)`. It stays out of
`Findings()` and out of `export`, so nothing unreviewed is ever published as a
claim, but it is now on screen where a reader will see it.

### What this says about `unmentioned-line`

As originally run the rule fired twice here (0.9.1, 1.30.0) and both times
returned `symbol_not_found`, honest gaps, no noise. Combined with redis, where
it produced four true-but-immaterial disagreements, the reading was that the
rule is **not wrong, but its yield depends on how far the unmentioned lines are
from the fix.**

The Vitrage case then showed those two probes should never have fired: both sit
below an open-below claim that covers them. After that fix the rule does not
fire on this advisory at all, which is the correct behaviour and removes MLflow
as evidence either way.

### Two guard-shaped fixes out of two

Worth naming: both multi-branch advisories in the corpus were fixed by **adding a
check**, not by removing a dangerous call. The `calls` vocabulary was designed
around danger-shaped constructs, and real backported fixes keep turning out to be
the other shape.

That makes `indicates: fixed` the common path rather than the exception, despite
the redis run establishing that it is the fragile one. A rule kind that can
express "this argument is unvalidated" would fit these cases better than
inverting polarity does.

## PYSEC-2026-564: OpenStack Vitrage, the negative control

Deliberately chosen to be **danger-shaped** and **correct**. Vitrage's
`create_predicate` built a lambda as a string from a caller-supplied query dict
and ran it through `eval()`; the fix replaces that with `_create_query_function`,
composing real callables from an operator table. The dangerous call is *removed*,
so this is the polarity the `calls` rule was designed for, no inversion.

The advisory patches **four maintenance branches**:

```
claims  < 12.0.1
claims  >= 13.0.0.0rc1, < 13.0.1
claims  >= 14.0.0.0rc1, < 14.0.1
claims  >= 15.0.0.0rc1, < 15.0.1

61 tags in the repository, 8 probed (13.1%)

version    eval present?  rule                   outcome
12.0.0     PRESENT        below-fixed            consistent
12.0.1     absent         fixed                  consistent
13.0.0     PRESENT        below-fixed            consistent
13.0.1     absent         fixed                  consistent
14.0.0     PRESENT        below-fixed            consistent
14.0.1     absent         fixed                  consistent
15.0.0     PRESENT        below-fixed            consistent
15.0.1     absent         fixed                  consistent

0 finding(s) · 8 consistent · 0 narrower · 0 gap(s)
```

**Every boundary agrees, and the report is empty.** All four backported fixes
were located unaided. Verified by hand first: `eval` is present at 12.0.0,
13.0.0, 14.0.0 and 15.0.0 and absent at each fix.

This is the case the corpus was missing. A tool only ever exercised on wrong
advisories has never demonstrated that it stays quiet on right ones, and a false
correction filed against a maintainer is the most expensive way this project can
fail. Staying silent here is the result.

### The defect this run exposed: fixed

It was not silent on the first run. It reported **twelve disagreements**, spanning
0.7.0 through 11.0.0, every one of them false.

`SelectBoundaries` tracked which release lines an advisory "mentions" by taking
the major version of each literal `introduced` and `fixed` event. The first
Vitrage claim is `introduced: 0, fixed: 12.0.1`, which covers *everything ever
released before 12.0.1*, but only major 12 was marked. Lines 0 through 11 looked
like silence, so the `unmentioned-line` rule probed the newest release of each,
found `eval` (correctly), and called each one a disagreement with an advisory
that explicitly warns about them.

Fixed by treating an open-below claim as covering every earlier line. Probes fell
from 20 to 8, the twelve false findings disappeared, and the redis 5.x,8.x
finding, which depends on lines *above* the claims, is unaffected. Both
directions are pinned by regression tests.

This is the most serious defect found so far. The earlier two were reporting
problems; this one manufactured findings out of correct advisories, in the
direction that gets a maintainer's time wasted.

### What it says about `unmentioned-line`

Third outing, third distinct behaviour:

| advisory | fired on | result |
|---|---|---|
| redis-py | 5.x,8.x, above the claims | true, immaterial (guard replaced in 4.5.5) |
| MLflow | 0.9.1, 1.30.0, below an open claim | two spurious probes; no longer fires |
| Vitrage | 0.7.0-11.0.0, below an open claim | **twelve false positives** |

The Vitrage case was a bug rather than a property of the rule, and it is now
fixed. But the pattern across all three is consistent: **the rule's value depends
entirely on where the unmentioned line sits relative to the claims.** Above them
it is doing the job it was written for. Below an open-below claim it was pure
noise. That is a stronger argument for release-line distance awareness than
either earlier run made on its own.

## The targeted run: five advisories, one under-report

The first three advisories were picked by hand. This batch was picked by query,
to find out whether the finding rate is one in three or one in thirty.

Targeting: `pypa/advisory-database`, filtered to advisories with two to six
independent fixed versions, a code-execution or traversal shape in the summary,
and a linked fix commit. TensorFlow was excluded because the same advisory is
mirrored across three packages and the code is mostly C++. That leaves 111
candidates; five were audited.

| advisory | package | branches | result |
|---|---|---|---|
| PYSEC-2026-2605 | litestar | 3 | consistent at all 6 boundaries |
| PYSEC-2026-1226 | bugsink | 4 | consistent at all 8 boundaries |
| PYSEC-2021-382 | qutebrowser | 2 | **under-report** |
| PYSEC-2026-797 | cobbler | 2 | 2 disagreements, both explained |
| PYSEC-2026-1127 | ansys-geometry | 2 | not audited: fix was a rename plus lint pragmas |

Three of these are now corpus cases with tests: the qutebrowser finding, and
litestar and bugsink as negative controls. Cobbler is not, because a spec whose
guard name was renamed out of existence would keep reporting disagreements that
are not findings, which is noise in a regression suite rather than evidence.

### The finding: PYSEC-2021-382 marks vulnerable versions as safe

qutebrowser's Windows installer registers a `qutebrowserurl:` URL handler, and a
crafted URL could execute qutebrowser commands, reaching arbitrary code through
`:spawn` or `:debug-pyeval` (CVE-2021-41146). The fix adds
`_validate_untrusted_args` and calls it at the top of `main()`.

The advisory splits the affected versions into two ranges:

```
claims  < 1.8.0
claims  >= 2.0.0, < 2.4.0
```

That leaves **1.8.0 through 1.14.1 unmentioned, and therefore implied safe.**
They are not safe. Verified three ways:

- **By tag content.** `_validate_untrusted_args` appears in no 1.x release. The
  whole `--untrusted-args` mechanism is absent from 1.8.0, 1.8.1, 1.8.2, 1.8.3,
  1.9.0 and 2.0.0, and first appears at 2.4.0.
- **By the advisory's own text**, which says "The issue has been fixed in
  qutebrowser v2.4.0".
- **By the GHSA record.** GHSA-vw27-fwjf-5qxm covers the same CVE with a single
  range, `>= 1.7.0, < 2.4.0`, and gets it right.

The affected-versions list in the PYSEC record has a matching hole: it
enumerates 64 versions and not one of them is in 1.8.x through 1.14.x.

**This is the first under-report the project has found**, and it is the failure
mode the entire verdict model exists to prevent. The MLflow finding was an
over-claim, which is recoverable. This one leaves users of eleven minor releases
without a reason to upgrade.

The engine reached it from a probe of 7 tags out of 100.

### cobbler: two disagreements, neither a finding

Worth recording because both are the known guard-shaped failure rather than
anything new.

**3.3.7** renamed the entire `kickstart` vocabulary to `autoinstall`: 46
occurrences of `kickstart` at 2.1.0, zero at 3.3.7, against 52 of `autoinstall`.
The guard `_validate_ks_template_path` is a `ks`-era name, so its absence means
the protection was reimplemented under new naming rather than removed. This is
exactly the redis-py pattern.

**2.1.0** predates the advisory's claimed introduction of 2.4.0. `modify_item`
there is unguarded, but the advisory does not claim the version is affected, and
a rule matching the guard cannot distinguish "before the vulnerability" from
"after the fix was reverted".

Both were resolved by reading the source at those tags, which took minutes
rather than the hours the redis case cost. Knowing the failure mode in advance
is most of the work.

### What the run says about the finding rate

One under-report in five audited advisories. That is a real rate rather than a
single anecdote, though five is still a small sample and the targeting was
deliberately biased toward advisories likely to be wrong.

Two of the five were clean at every boundary, which is the more reassuring
result: the tool stayed silent on correct advisories with three and four
backported branches respectively.

**Five of five fixes were guard-shaped**, adding a check rather than removing a
dangerous call, so all five specs needed `indicates: fixed`. Across eight
multi-branch advisories now audited, only Vitrage was danger-shaped. The `calls`
vocabulary was designed around the shape that turns out to be the exception.

## Finishing the sweep: eight audited, one finding

Three more from the shortlist, plus one that could not be audited at all.

| advisory | package | ranges | result |
|---|---|---|---|
| GHSA-r7q7-xcjw-qx8q | tqdm | 2 (overlapping) | consistent, after a false positive was fixed |
| GHSA-hg4c-rgvm-964g | pycsw | 3 | consistent |
| GHSA-76x8-gg39-5jjg | cherrypy | 2 | **unauditable** |

**CherryPy is the new category.** The advisory claims `< 2.1.1` and
`>= 3.0, < 3.0.2`, and the fix commit is from 2007. The repository's oldest tag
is `cherrypy-3.1.0beta`, so neither claimed boundary exists in git at all. Not a
gap the tool can report against a probe: there is nothing to probe. An advisory
older than its own repository history is outside what any source-based auditor
can answer.

That makes **eight advisories audited from the mechanical sweep, one finding**,
and one where the question could not be put.

### The defect this run exposed: overlapping claims manufactured a disagreement

tqdm's advisory carries two ranges that overlap and share a fixed version:

```
>= 4.4.1,  < 4.11.2
>= 4.10.0, < 4.11.2
```

4.9.0 sits below the second claim's `introduced` while sitting **inside** the
first. Boundary selection probed it as `below-introduced`, whose whole meaning
is "the advisory says this version is safe" — and the advisory says the
opposite. The construct is present at 4.9.0, so the run reported a disagreement
against a correct advisory.

This is the failure direction that matters most. A missed finding costs a
finding; a false one costs a maintainer's time and this project's credibility
the first time a correction is filed and turns out to be wrong.

`below-introduced` now skips any version another claim already covers. The two
real findings in the corpus, qutebrowser and trytond, are unaffected: both sit
below every claim, not between two overlapping ones.

## The second under-report: trytond, and the first found without targeting

GHSA-m9jj-5qvj-5fhx patches arbitrary command execution in Tryton's `ir.cron`.
Callback arguments were expanded with `safe_eval`, which despite the name
evaluates a Python expression, so anyone able to write a cron record ran code as
the cron user. The fix replaces it with `ast.literal_eval`.

Four branches, four backports, all located correctly:

```
2.4.14 VULNERABLE   2.4.15 NOT_VULNERABLE
2.6.13 VULNERABLE   2.6.14 NOT_VULNERABLE
2.8.10 VULNERABLE   2.8.11 NOT_VULNERABLE
3.2.2  VULNERABLE   3.2.3  NOT_VULNERABLE
```

**The finding is below all of them.** The advisory carries entries for two
package names. The `tryton` entries say `introduced: 0`. The `trytond` entries,
which are what a PyPI scanner reads, start at **2.4.0**.

`safe_eval(cron.args)` is present in 1.8.11, 2.0.9 and 2.2.14, and all three are
real `trytond` releases on PyPI. A scanner checking `trytond==1.8.11` stays
silent about a version that evaluates a user-writable field.

The advisory's authors knew: they wrote `introduced: 0` for the same
vulnerability under the other package name. The lower bound was not carried
across.

This is the second under-report in the corpus and the first found without
targeting. The qutebrowser case was reached by looking for advisories that
looked wrong; this one came out of a mechanical sweep.

### The defect this case exposed: decorated methods were invisible

`Cron._callback` is a plain method through 2.6 and a `@classmethod` from 2.8 on.
The 2.8 and 3.2 probes returned `UNKNOWN [symbol_not_found]` while the source
plainly contained the method.

tree-sitter wraps a decorated method in a `decorated_definition` node, and the
method query matched only bare `function_definition` children of a class body.
So **every `@classmethod`, `@staticmethod` and `@property` was invisible to a
`Class.method` lookup**, in a language where decorated methods are ordinary.

It was silent in the worst way: `symbol_not_found` reads as "the code is not
here" rather than "the query could not see it". Under an inverted-polarity spec
that is an UNKNOWN where a NOT_VULNERABLE belonged, which suppresses a finding.

The fixture already covered decorated *functions* at module level, which is why
this survived. It did not cover a decorated method inside a class.

The `did you mean` suggestion added in 0.2.0 is what made it obvious: the report
said `symbol Cron._callback not found; did you mean _callback?`, which is a
strange thing to say about a method that exists, and pointed straight at the
query rather than at the advisory.

## The unbiased run: four advisories, no findings

Every earlier run targeted advisories chosen because something looked wrong.
This one did not. The whole PyPI OSV database was filtered mechanically and the
first four workable candidates were audited, whatever they turned out to say.

**24,848 advisories → 3,294 multi-range with a repository → 35 workable → 5
audited.** Nothing was skipped after a spec was written. The fifth, trytond, is
the under-report recorded above; the four below are the ones that came back
clean.

| advisory | package | ranges | probed | result |
|---|---|---|---|---|
| GHSA-wv28-7fpw-fj49 | lektor | 2 | 3 of 52 | consistent |
| GHSA-gh82-f9x8-5frx | keras | 2 | 5 of 120 | consistent |
| GHSA-5hr4-253g-cpx2 | web3 | 2 | 9 of 257 | consistent, 1 narrower |
| GHSA-8cw9-5hmv-77w6 | sanic | 3 | 9 of 89 | consistent, 4 gaps |

**Zero findings across these four.** Every spec reproduced both fix boundaries
by hand first, so the silence is the tool agreeing with four correct advisories
rather than the tool failing to look.

With trytond and the three above, that makes **one under-report in eight
mechanically selected advisories**, against one in five when the picking was
deliberate. Eight is still a small sample and the two rates should not be
compared as though they were measured. The useful claim is narrower and now
supported: wrong ranges are found without needing to guess which advisories to
look at.

What the earlier sessions could not say, and this run can: the finding did not
depend on judgement about which advisory looked suspect. The filter was
mechanical and trytond came out of it.

The eight also cost two engine defects, both in the direction of reporting
something that was not there or missing something that was: decorated methods
were invisible to a qualified lookup, and overlapping claims manufactured a
disagreement. Neither would have surfaced from specs written against code the
author had already read.

### What the rejections say

The filter's rejections are more informative than its survivors:

| rejected | reason |
|---|---|
| 2,016 | not Python, or enterprise backport sprawl (TensorFlow, Salt) |
| 1,108 | CWE not expressible as a call or a default |
| 58 | memory-safety class, so native code |
| 26 | no fix commit or PR to read |

**A third of multi-range PyPI advisories name a CWE this vocabulary cannot
ask about.** That is the vocabulary gap measured rather than asserted.

Two of the 35 survivors turned out to be inexpressible only after the diff was
read, which no CWE filter would have caught:

- **RestrictedPython GHSA-xjw2-6jm9-rf67.** The fix widened a conditional from
  `isinstance(object, str) and name == 'format'` to also cover `format_map` and
  `str` subclasses, and wrapped a module in an attribute delegator. No call is
  added or removed, so there is nothing for `calls` to ask.
- **tortoise-orm GHSA-9j2c-x8qm-qmjq.** The fix monkey-patches PyPika's value
  wrapper with escaping logic. The vulnerability is what the function does, not
  which functions it calls.

Both are the documented limit: a rule asks whether a construct is present, which
is not the same question as whether a bug is.

### What the run exercised

**Tag normalisation, on real data.** web3.py tags releases `v8.0.0-beta.2` while
the advisory claims `8.0.0b2`. Both normalise to the same PEP 440 version and
the probe resolved correctly. That path had only ever been exercised by tests.

**The `any` combinator refusing to guess.** Sanic 21.12.2 has the fix, and
`sanic/mixins/routes.py` proves the vulnerable construct absent. But
`sanic/static.py` does not exist at that tag, so the version reads `UNKNOWN
[file_absent]` rather than NOT_VULNERABLE. One location examined and clean does
not license a verdict about a location never read.

Worth stating plainly because it has a cost: a spec spanning eras with
`code_any` reports fixed versions as UNKNOWN once the older file disappears.
Correct under the prime directive, and noisier than a reader expects.

### The defect this run exposed: a whole claim probed by nobody

Both lektor and web3.py fix their second branch on a **pre-release**:
`>= 3.4.0b1, < 3.4.0b11` and `>= 8.0.0b1, < 8.0.0b2`. Boundary selection
deliberately skips pre-releases, because an advisory range is a statement about
releases and probing a release candidate invites noise. That decision is right.

What was wrong is what happened next. Neither edge is a released version, so
**no boundary was selected anywhere in the claim** and the report said:

```
  probed  3 of 52 tags
  0 finding(s) · 3 consistent · 0 narrower · 0 gap(s)
```

Three consistent, nothing else, reading as agreement with a two-branch
advisory whose second branch was never looked at. Not a wrong verdict, a
missing one presented as agreement, which is the failure mode this project
exists to complain about in other people's data.

`Report.UnprobedClaims` now reports it, and the audit prints:

```
  NOT PROBED (no released version at these edges)
    >= 3.4.0b1, < 3.4.0b11
```

It fires on two existing corpus cases too, both correctly. pymatgen
(PYSEC-2024-226) and qutebrowser (PYSEC-2021-382) each carry a claim naming a
**commit hash** where a fixed version belongs. Boundary selection already
dropped those as unprobeable and the notes above already recorded it; what is
new is that the report says so instead of the reader having to know.

**A danger-shaped fix in the wild.** Sanic's fix deletes the weak
`sub("^[/]*", ...)` strip rather than adding a guard, so its spec uses the
natural polarity. Three of three vulnerable versions matched. That is the third
danger-shaped case in the corpus and it remains the exception: the other three
advisories in this run were all guard-shaped.

## Next

Nine advisories audited across four sessions: two real findings, one of them an
under-report, and five engine defects. Three of those defects were surfaced by
running unfamiliar cases; the other two by property tests over generated claim
shapes, which is the cheaper way to find them.

The unbiased run adds four more, for **thirteen advisories and two findings**.

The open question is no longer whether findings exist. It is whether the
disagreement-to-finding ratio is workable at scale: the targeted run produced
three disagreements, of which one was real. A researcher auditing fifty
advisories would read fifty reports to file perhaps ten corrections, which is
worth it, but only if resolving each disagreement stays a matter of minutes.

The unbiased run reframes that estimate downward. Four correct advisories in a
row, mechanically selected, suggests ten corrections per fifty is a targeted-
hunting rate rather than a general one. The value is in choosing which fifty.

The corpus now holds seven audited advisories with tests, four of them negative
controls. Those are the cases that catch false positives, and one already has:
the Vitrage run found a boundary-selection bug manufacturing twelve findings out
of a correct advisory.

Boundary selection is now covered by property tests rather than only by example.
They generate claim shapes against tag topologies and assert invariants: every
probe is a real tag, `unmentioned-line` never fires inside a claim, probe count
tracks claims rather than tags, and selection is deterministic under shuffled
input. They found two further bugs on their first run.

## Danger-shaped fixes are rare, and that is the result

Both real findings were reached with `indicates: fixed`, which the design treats
as the weaker evidence and which cobbler showed again is fragile when a guard is
renamed rather than removed. So the natural polarity was searched for
deliberately.

Filtering `pypa/advisory-database` for multi-range advisories whose fix commit
is a net deletion of a dangerous call leaves **seven** candidates out of 1549
packages. Every one is single-range: pymatgen, limnoria, searchor, torch,
django-tastypie, langchain-experimental, tenable-jira-cloud. None has the
multi-branch shape that produces findings.

That is worth stating as a finding about the domain rather than a gap in the
tool. **Guard-shaped fixes dominate Python security patches.** Across nine
audited advisories only Vitrage and pymatgen removed a dangerous call, and both
advisories were correct. `indicates: fixed` is the primary path, not the
exception, and the vocabulary should be judged on how well it serves that.

pymatgen (PYSEC-2024-226) is in the corpus as the danger-shaped case: eval on a
caller-supplied basis-change string, removed in 2024.2.20. Two probes of 424
tags, both consistent. Its value is that the natural polarity is exercised end
to end at all, not that it found anything.

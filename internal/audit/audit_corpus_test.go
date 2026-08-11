//go:build corpus

package audit_test

import (
	"path/filepath"
	"testing"

	"github.com/nickelsec/taggity/internal/audit"
	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/git"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

func corpusPath(name string) string {
	return filepath.Join("..", "..", "testdata", "corpus", name)
}

// TestAuditRedisMultiBranch is the case the whole design targets: an advisory
// covering two release lines, each with its own backported fix.
//
// The spec has inverted polarity: it asks whether the FIX is present, because
// the fix added asyncio.shield rather than removing a dangerous call. So
// VULNERABLE means "fix applied" here. See the spec file.
func TestAuditRedisMultiBranch(t *testing.T) {
	sp, err := spec.Load(corpusPath("GHSA-8fww-64cx-x8p5.yaml"))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	adv, err := audit.LoadAdvisory(corpusPath("GHSA-8fww-64cx-x8p5.json"))
	if err != nil {
		t.Fatalf("advisory: %v", err)
	}

	repo, err := git.OpenOrClone(sp.Repo)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	_, allTags, err := repo.Tags()
	if err != nil {
		t.Fatalf("tags: %v", err)
	}

	claims := adv.Claims(sp.Package.Name)
	if len(claims) != 2 {
		t.Fatalf("expected two claimed ranges, got %d: this advisory is the "+
			"multi-branch case", len(claims))
	}
	for _, c := range claims {
		t.Logf("claims %s", c)
	}

	boundaries := audit.SelectBoundaries(claims, allTags)
	t.Logf("selected %d boundaries from %d tags", len(boundaries), len(allTags))
	if len(boundaries) == 0 {
		t.Fatal("no boundaries selected")
	}
	if len(boundaries) > 12 {
		t.Errorf("selected %d boundaries; probing edges should stay small",
			len(boundaries))
	}

	c := &check.Checker{Source: repo}
	rep := audit.Run(c, sp, adv, boundaries)

	t.Logf("\n%s  %s", rep.AdvisoryID, rep.Package)
	t.Logf("  %-10s %-14s %-22s %s", "version", "shield", "rule", "outcome")
	for _, res := range rep.Results {
		t.Log(res.Describe())
	}

	findings, consistent, narrower, unknown := rep.Counts()
	rawDis, _, _, rawUnk := rep.VersionCounts()
	t.Logf("\n  findings %d (%d versions) · consistent %d · narrower %d · "+
		"unknown %d (%d versions)",
		findings, rawDis, consistent, narrower, unknown, rawUnk)

	for _, f := range rep.Findings() {
		t.Logf("  FINDING  %-14s %-14s %v", f.Span(), f.Verdict, f.Rules)
	}
	for _, u := range rep.Unknowns() {
		t.Logf("  gap      %-14s [%s] %v", u.Span(), u.Reason, u.Rules)
	}

	// Four consecutive 5.x-and-later releases reflect one commit in 4.5.5.
	// Counting them separately would inflate this report fourfold.
	if findings > 1 {
		t.Errorf("reported %d findings for what grouping should collapse; "+
			"consecutive versions sharing a verdict are one observation", findings)
	}
	if rawDis <= findings {
		t.Errorf("grouping did not reduce anything: %d versions, %d findings",
			rawDis, findings)
	}

	// The engine must independently locate both fixed versions. This is the
	// substantive claim: without being told where the fixes are, it finds
	// asyncio.shield at 4.4.4 and 4.5.4 and nowhere below them.
	fixApplied := map[string]bool{}
	for _, res := range rep.Results {
		if res.Signals.Overall() == taggity.Vulnerable {
			fixApplied[res.Boundary.Version] = true
		}
	}
	for _, want := range []string{"4.4.4", "4.5.4"} {
		if !fixApplied[want] {
			t.Errorf("fix not detected at %s; the advisory names it as fixed", want)
		}
	}
	for _, wantNot := range []string{"4.4.3", "4.5.3"} {
		if fixApplied[wantNot] {
			t.Errorf("fix detected at %s, which the advisory says is affected", wantNot)
		}
	}
}

// TestAuditBoundariesAreCheap records the cost of auditing one advisory. If
// this number grew into the dozens, auditing at scale would stop being viable.
func TestAuditBoundariesAreCheap(t *testing.T) {
	sp, err := spec.Load(corpusPath("GHSA-8fww-64cx-x8p5.yaml"))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	adv, err := audit.LoadAdvisory(corpusPath("GHSA-8fww-64cx-x8p5.json"))
	if err != nil {
		t.Fatalf("advisory: %v", err)
	}
	repo, err := git.OpenOrClone(sp.Repo)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	_, allTags, _ := repo.Tags()

	boundaries := audit.SelectBoundaries(adv.Claims(sp.Package.Name), allTags)
	t.Logf("%d tags in the repository, %d probed (%.1f%%)",
		len(allTags), len(boundaries),
		100*float64(len(boundaries))/float64(len(allTags)))
}

// TestAuditMLflowOverclaimsThreeZero is the project's first real finding.
//
// GHSA-wxj7-3fx5-pp9m claims >= 3.0.0rc0, < 3.1.0 and enumerates 3.0.0 and
// 3.0.1 as affected. Both already contain the fix: commit 4a0f6c1345
// ("Validate `gateway_path` in `gateway_proxy_handler`", #15970) landed
// 2025-06-02 and `git tag --contains` lists v3.0.0. Only the rc line predates
// it. The 3.x range should end at the last release candidate, not at 3.1.0.
//
// Like the redis spec this one has inverted polarity: it matches the FIX, so
// VULNERABLE means "guard present". That is also why the observation lands in
// Overclaims rather than Findings, and why Overclaims has to be rendered: the
// report said "0 finding(s)" for an advisory that is demonstrably wrong.
func TestAuditMLflowOverclaimsThreeZero(t *testing.T) {
	rep := runCorpusAudit(t, "GHSA-wxj7-3fx5-pp9m")

	if n := len(rep.Claims); n != 2 {
		t.Fatalf("claimed ranges = %d, want 2", n)
	}
	guard := verdicts(rep)

	// Both branches' fixes must be located without being told where they are.
	for _, want := range []string{"2.22.2", "3.1.0"} {
		if guard[want] != taggity.Vulnerable {
			t.Errorf("fix not detected at %s, which the advisory names as fixed", want)
		}
	}
	if guard["2.22.1"] != taggity.NotVulnerable {
		t.Errorf("2.22.1 = %v, want the guard absent one release before the backport",
			guard["2.22.1"])
	}

	// The finding. 3.0.1 is claimed affected and carries the guard.
	if guard["3.0.1"] != taggity.Vulnerable {
		t.Errorf("3.0.1 = %v, want VULNERABLE (guard present): v3.0.0 contains "+
			"the fix commit, so the advisory's 3.x range overclaims", guard["3.0.1"])
	}

	var spans []string
	for _, o := range rep.Overclaims() {
		spans = append(spans, o.Span())
		t.Logf("  OVERCLAIM  %-14s %-14s %v", o.Span(), o.Verdict, o.Rules)
	}
	if len(spans) == 0 {
		t.Fatal("no overclaim reported; the 3.x range is wrong and the report " +
			"must not render that as zero findings")
	}
}

// TestAuditVitrageAgreesWithACorrectAdvisory is the corpus negative control.
//
// PYSEC-2026-564 patches an eval injection in OpenStack Vitrage across FOUR
// maintenance branches (12.0.1, 13.0.1, 14.0.1, 15.0.1). Checked by hand, the
// advisory is right at every boundary: eval is present at 12.0.0, 13.0.0,
// 14.0.0 and 15.0.0 and absent at each fix.
//
// A tool only ever exercised on wrong advisories has never shown that it stays
// quiet on right ones, and a false correction filed against a maintainer is the
// most expensive way this project can fail. Every probed boundary must classify
// consistent, and the report must contain nothing at all.
//
// The fix here removes the dangerous call rather than adding a guard, so the
// spec needs no polarity inversion. See TestAuditPymatgenDangerShaped for the
// other case that exercises the natural polarity.
func TestAuditVitrageAgreesWithACorrectAdvisory(t *testing.T) {
	rep := runCorpusAudit(t, "PYSEC-2026-564")

	if n := len(rep.Claims); n != 4 {
		t.Fatalf("claimed ranges = %d, want 4: this advisory is the "+
			"four-branch case", n)
	}

	// query.py and create_predicate exist throughout, so there is nothing to
	// report and no honest gap either.
	requireSilent(t, rep, false)

	// All four backported fixes must be located unaided, and eval must still be
	// present in the release immediately below each one.
	verdict := verdicts(rep)
	for _, fixed := range []string{"12.0.1", "13.0.1", "14.0.1", "15.0.1"} {
		if verdict[fixed] != taggity.NotVulnerable {
			t.Errorf("%s = %v, want NOT_VULNERABLE: the advisory names it as fixed",
				fixed, verdict[fixed])
		}
	}
	for _, affected := range []string{"12.0.0", "13.0.0", "14.0.0", "15.0.0"} {
		if verdict[affected] != taggity.Vulnerable {
			t.Errorf("%s = %v, want VULNERABLE: eval is still present there",
				affected, verdict[affected])
		}
	}

	// Four ranges over 61 tags must not turn into a full scan.
	if len(rep.Results) > 12 {
		t.Errorf("probed %d versions for four ranges; boundary probing should "+
			"stay proportional to the edges", len(rep.Results))
	}
}

// TestAuditPyYAMLDefaults audits an advisory the calls rule could not express.
//
// PyYAML's load() constructs a Loader in every released version, so a presence
// rule reports the construct throughout and never locates the fix. The
// vulnerability was in the default argument: 5.1 changed Loader=Loader to
// Loader=None. With a defaults rule the boundary resolves exactly.
func TestAuditPyYAMLDefaults(t *testing.T) {
	rep := runCorpusAudit(t, "GHSA-rprw-h62v-c2w7", "GHSA-rprw-h62v-c2w7-defaults")
	verdict := verdicts(rep)

	// The advisory names 5.1 as the fix, and the engine must agree without
	// being told where to look.
	if verdict["5.1"] != taggity.NotVulnerable {
		t.Errorf("5.1 = %v, want NOT_VULNERABLE: the default changed here",
			verdict["5.1"])
	}
	if v, probed := verdict["4.1"]; probed && v != taggity.Vulnerable {
		t.Errorf("4.1 = %v, want VULNERABLE: Loader=Loader is declared there", v)
	}

	// The advisory is correct, so nothing should be reported. Gaps are allowed:
	// lib/yaml/__init__.py does not exist in the oldest tags.
	requireSilent(t, rep, true)
}

// TestAuditQutebrowserUnderReport is the corpus case for the failure the whole
// design exists to catch: an advisory marking vulnerable versions as safe.
//
// PYSEC-2021-382 splits CVE-2021-41146 into two ranges, "< 1.8.0" and
// ">= 2.0.0, < 2.4.0", which leaves 1.8.0 through 1.14.1 unmentioned and
// therefore implied safe. The guard exists in no 1.x release: the whole
// --untrusted-args mechanism arrives in 2.4.0, which the advisory's own text
// states. GHSA-vw27-fwjf-5qxm covers the same CVE with a single correct range
// of >= 1.7.0, < 2.4.0.
//
// Anyone running 1.8.x through 1.14.x is not being told to upgrade, which is
// the only unacceptable direction.
func TestAuditQutebrowserUnderReport(t *testing.T) {
	rep := runCorpusAudit(t, "PYSEC-2021-382")
	verdict := verdicts(rep)

	// The guard arrives at 2.4.0 and exists nowhere before it. Under inverted
	// polarity VULNERABLE means the fix is present.
	if verdict["2.4.0"] != taggity.Vulnerable {
		t.Errorf("2.4.0 = %v, want VULNERABLE: the guard lands here",
			verdict["2.4.0"])
	}
	if verdict["1.8.0"] != taggity.NotVulnerable {
		t.Errorf("1.8.0 = %v, want NOT_VULNERABLE: the guard does not exist in 1.x",
			verdict["1.8.0"])
	}

	// The finding itself. 1.8.0 is named as a fixed version and is not fixed.
	var spans []string
	for _, f := range rep.Findings() {
		spans = append(spans, f.Span())
		t.Logf("  FINDING  %-16s %-15s %v", f.Span(), f.Verdict, f.Rules)
	}
	if len(spans) == 0 {
		t.Fatal("no finding reported; the advisory marks 1.8.0 as fixed when " +
			"the guard does not exist until 2.4.0")
	}
}

// runCorpusAudit loads a spec and its advisory, clones the repository, and
// probes the boundaries. The setup is identical for every corpus case, so the
// tests that use it can be about the result rather than the plumbing.
//
// The spec and the advisory usually share a basename. One advisory carries two
// specs asking it different questions, so the spec name may be given
// separately.
func runCorpusAudit(t *testing.T, name string, specName ...string) *audit.Report {
	t.Helper()

	spFile := name
	if len(specName) > 0 {
		spFile = specName[0]
	}
	sp, err := spec.Load(corpusPath(spFile + ".yaml"))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	adv, err := audit.LoadAdvisory(corpusPath(name + ".json"))
	if err != nil {
		t.Fatalf("advisory: %v", err)
	}
	repo, err := git.OpenOrClone(sp.Repo)
	if err != nil {
		t.Fatalf("clone: %v", err)
	}
	_, allTags, err := repo.Tags()
	if err != nil {
		t.Fatalf("tags: %v", err)
	}

	boundaries := audit.SelectBoundaries(adv.Claims(sp.Package.Name), allTags)
	rep := audit.Run(&check.Checker{Source: repo}, sp, adv, boundaries)

	t.Logf("\n%s  %s", rep.AdvisoryID, rep.Package)
	for _, res := range rep.Results {
		t.Log(res.Describe())
	}
	return rep
}

// verdicts indexes a report by version, for asserting on specific boundaries.
func verdicts(rep *audit.Report) map[string]taggity.Verdict {
	out := map[string]taggity.Verdict{}
	for _, res := range rep.Results {
		out[res.Boundary.Version] = res.Signals.Overall()
	}
	return out
}

// requireSilent asserts that an audit reported nothing at all. Gaps are allowed
// only where the test says they are expected, since a gap is an honest answer
// but still means a boundary went unexamined.
func requireSilent(t *testing.T, rep *audit.Report, allowGaps bool) {
	t.Helper()
	for _, f := range rep.Findings() {
		t.Errorf("false finding %s %v: the advisory is correct at every boundary",
			f.Span(), f.Rules)
	}
	for _, o := range rep.Overclaims() {
		t.Errorf("false overclaim %s %v", o.Span(), o.Rules)
	}
	if allowGaps {
		return
	}
	for _, u := range rep.Unknowns() {
		t.Errorf("gap %s [%s]: every boundary should have been readable",
			u.Span(), u.Reason)
	}
}

// TestAuditLitestarAgreesWithACorrectAdvisory is a negative control across
// three maintenance branches.
//
// PYSEC-2026-2605 patches a path traversal in Litestar's static file serving:
// get_fs_info joined a caller-supplied path and checked containment without
// normalising first. The fix adds os.path.normpath and shipped on 2.6.4, 2.7.2
// and 2.8.3. Checked by hand, the advisory is right at every boundary.
func TestAuditLitestarAgreesWithACorrectAdvisory(t *testing.T) {
	rep := runCorpusAudit(t, "PYSEC-2026-2605")

	if n := len(rep.Claims); n != 3 {
		t.Fatalf("claimed ranges = %d, want 3", n)
	}

	// Older releases predate litestar/static_files/base.py, so those probes are
	// honest file_absent gaps rather than answers.
	requireSilent(t, rep, true)

	v := verdicts(rep)
	// All three backported fixes must be located without being told where.
	// Inverted polarity: VULNERABLE means the guard is present.
	for _, fixed := range []string{"2.6.4", "2.7.2", "2.8.3"} {
		if v[fixed] != taggity.Vulnerable {
			t.Errorf("%s = %v, want VULNERABLE: the advisory names it as fixed",
				fixed, v[fixed])
		}
	}
	for _, affected := range []string{"2.6.3", "2.7.1", "2.8.2"} {
		if v[affected] != taggity.NotVulnerable {
			t.Errorf("%s = %v, want NOT_VULNERABLE: the guard is absent there",
				affected, v[affected])
		}
	}
}

// TestAuditBugsinkAgreesWithACorrectAdvisory is the widest negative control in
// the corpus: four maintenance branches.
//
// PYSEC-2026-1226 patches a path traversal in Bugsink's ingestion, where a
// caller-supplied event_id was used directly as a filename. The fix normalises
// it through uuid.UUID(event_id).hex and shipped on 1.4.3, 1.5.5, 1.6.4 and
// 1.7.4.
//
// The advisory also lists ">= 1.6.0, < 1.6.4" twice. Boundary selection has to
// collapse the duplicate rather than probing those versions again.
func TestAuditBugsinkAgreesWithACorrectAdvisory(t *testing.T) {
	rep := runCorpusAudit(t, "PYSEC-2026-1226")

	// Five claimed ranges, one of them a duplicate of another.
	if n := len(rep.Claims); n != 5 {
		t.Fatalf("claimed ranges = %d, want 5 including the duplicate", n)
	}

	requireSilent(t, rep, false)

	v := verdicts(rep)
	for _, fixed := range []string{"1.4.3", "1.5.5", "1.6.4", "1.7.4"} {
		if v[fixed] != taggity.Vulnerable {
			t.Errorf("%s = %v, want VULNERABLE: the advisory names it as fixed",
				fixed, v[fixed])
		}
	}
	for _, affected := range []string{"1.4.2", "1.5.4", "1.6.3", "1.7.3"} {
		if v[affected] != taggity.NotVulnerable {
			t.Errorf("%s = %v, want NOT_VULNERABLE: the guard is absent there",
				affected, v[affected])
		}
	}

	// The duplicated range must not double the probe count. Four branches with
	// two edges each, plus the newest unmentioned line, is nine.
	if len(rep.Results) != 9 {
		t.Errorf("probed %d versions, want 9: the duplicated range should "+
			"collapse rather than probing 1.6.x twice", len(rep.Results))
	}
}

// TestAuditPymatgenDangerShaped is the corpus case for a fix that removes a
// dangerous call rather than adding a guard.
//
// Every other multi-branch advisory here was fixed by adding a check, so their
// specs set indicates: fixed and their verdicts read backwards. Pymatgen ran a
// caller-supplied basis-change string through eval and the fix deletes it, so
// this spec asks the question the calls rule was designed for and VULNERABLE
// means what it says.
//
// The advisory is correct, so the audit reports nothing. Its value is that the
// natural polarity is exercised end to end at all.
func TestAuditPymatgenDangerShaped(t *testing.T) {
	rep := runCorpusAudit(t, "PYSEC-2024-226")

	sp, err := spec.Load(corpusPath("PYSEC-2024-226.yaml"))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	if !sp.MatchMeansVulnerable() {
		t.Fatal("this case exists to exercise the natural polarity")
	}

	requireSilent(t, rep, false)

	v := verdicts(rep)
	if v["2024.2.8"] != taggity.Vulnerable {
		t.Errorf("2024.2.8 = %v, want VULNERABLE: eval is still called there",
			v["2024.2.8"])
	}
	if v["2024.2.20"] != taggity.NotVulnerable {
		t.Errorf("2024.2.20 = %v, want NOT_VULNERABLE: the fix removed eval",
			v["2024.2.20"])
	}

	// Two of the three claims name a commit hash where a version belongs.
	// Those are unprobeable, and selecting them would spend probes to report
	// gaps that say nothing about the advisory.
	if len(rep.Results) != 2 {
		t.Errorf("probed %d versions, want 2: the commit-hash claims are not "+
			"probeable and should not be selected", len(rep.Results))
	}
}

// The three cases below came from an unbiased sweep of the PyPI OSV database
// rather than from advisories that looked suspect. All three are correct, which
// is the point: they catch a false finding, and they were selected by a filter
// rather than by judgement.

// TestAuditLektorAgreesWithACorrectAdvisory is a two-branch negative control.
//
// GHSA-wv28-7fpw-fj49 patches a path traversal in Lektor's editor API:
// make_editor_session took a path from the admin API without checking it stayed
// inside the database root. The fix adds a _is_valid_path guard and shipped on
// 3.3.11 and 3.4.0b11. Checked by hand, the advisory is right at both.
func TestAuditLektorAgreesWithACorrectAdvisory(t *testing.T) {
	rep := runCorpusAudit(t, "GHSA-wv28-7fpw-fj49")
	requireSilent(t, rep, false)

	v := verdicts(rep)
	// Inverted polarity: VULNERABLE means the guard is present.
	if v["3.3.11"] != taggity.Vulnerable {
		t.Errorf("3.3.11 = %v, want VULNERABLE: the guard ships there", v["3.3.11"])
	}

	// The second claim is fixed on a beta, and boundary selection probes only
	// released versions. That leaves the branch unexamined, which the report
	// has to say rather than counting the rest as agreement.
	unprobed := rep.UnprobedClaims()
	if len(unprobed) != 1 {
		t.Fatalf("unprobed claims = %d, want 1: >= 3.4.0b1, < 3.4.0b11 has no "+
			"released version at either edge", len(unprobed))
	}
	if unprobed[0].Fixed != "3.4.0b11" {
		t.Errorf("unprobed claim = %v, want the beta branch", unprobed[0])
	}
}

// TestAuditWeb3ReportsAnUnprobedBetaBranch is a negative control for the
// mainline branch and the case for saying so when a branch is skipped.
//
// GHSA-5hr4-253g-cpx2 patches an SSRF in web3.py's CCIP Read handling. It
// claims two branches: >= 6.0.0b3, < 7.15.0, and >= 8.0.0b1, < 8.0.0b2. Only
// the first has a released edge, so the second is never probed.
//
// 7.16.0 lands as narrower-than-claimed, which is correct and not a finding:
// it carries the guard and sits above the claimed fix, so the advisory says
// nothing about it.
func TestAuditWeb3ReportsAnUnprobedBetaBranch(t *testing.T) {
	rep := runCorpusAudit(t, "GHSA-5hr4-253g-cpx2")

	for _, f := range rep.Findings() {
		t.Errorf("false finding %s %v: the advisory is correct where it was "+
			"probed", f.Span(), f.Rules)
	}

	v := verdicts(rep)
	if v["7.15.0"] != taggity.Vulnerable {
		t.Errorf("7.15.0 = %v, want VULNERABLE: the mainline fix ships there",
			v["7.15.0"])
	}
	if v["7.14.1"] != taggity.NotVulnerable {
		t.Errorf("7.14.1 = %v, want NOT_VULNERABLE: the guard is not there yet",
			v["7.14.1"])
	}

	unprobed := rep.UnprobedClaims()
	if len(unprobed) != 1 || unprobed[0].Fixed != "8.0.0b2" {
		t.Errorf("unprobed claims = %v, want the 8.0.0b1-8.0.0b2 branch: both "+
			"edges are pre-releases and neither is probed", unprobed)
	}
}

// TestAuditSanicKeepsAGapRatherThanGuessing is the case for what `any` costs.
//
// GHSA-8cw9-5hmv-77w6 patches a path traversal in Sanic's static handler across
// three branches. The handler moved from a module-level function in
// sanic/static.py to a mixin method, so the spec names both. At 21.12.2 the
// mixin proves the construct absent, but sanic/static.py does not exist at that
// tag, so the version reads UNKNOWN rather than NOT_VULNERABLE.
//
// That is the prime directive costing something real: one location examined and
// clean does not license a verdict about a location that was never read.
func TestAuditSanicKeepsAGapRatherThanGuessing(t *testing.T) {
	rep := runCorpusAudit(t, "GHSA-8cw9-5hmv-77w6")
	requireSilent(t, rep, true)

	v := verdicts(rep)
	for _, ver := range []string{"20.12.6", "21.12.1", "22.6.0"} {
		if v[ver] != taggity.Vulnerable {
			t.Errorf("%s = %v, want VULNERABLE: the weak check is still there",
				ver, v[ver])
		}
	}
	// The fixed versions must not read as clean when a location was unreadable.
	for _, ver := range []string{"21.12.2", "22.6.1"} {
		if v[ver] == taggity.NotVulnerable {
			t.Errorf("%s = NOT_VULNERABLE, but sanic/static.py could not be "+
				"read there; an unexamined location is not a clean one", ver)
		}
	}
}

// TestAuditTrytondUnderReport is the second under-report in the corpus, and the
// first found by an unbiased sweep rather than by targeting.
//
// GHSA-m9jj-5qvj-5fhx patches arbitrary command execution in Tryton's ir.cron:
// callback arguments were expanded with safe_eval, which despite the name
// evaluates a Python expression. The fix replaces it with ast.literal_eval and
// was backported across four branches.
//
// The advisory carries entries for two package names. The `tryton` entries say
// introduced: 0, so the authors knew older releases were affected. The
// `trytond` entries, which are what a PyPI scanner reads, start at 2.4.0.
// safe_eval(cron.args) is present in 1.8.11, 2.0.9 and 2.2.14, all real
// trytond releases.
//
// This case also exposed the decorated-method blind spot: _callback is a
// @classmethod from 2.8 on, and a Class.method lookup could not see it.
func TestAuditTrytondUnderReport(t *testing.T) {
	rep := runCorpusAudit(t, "GHSA-m9jj-5qvj-5fhx")

	var spans []string
	for _, f := range rep.Findings() {
		spans = append(spans, f.Span())
		t.Logf("  FINDING  %-16s %-15s %v", f.Span(), f.Verdict, f.Rules)
	}
	if len(spans) == 0 {
		t.Fatal("no finding reported; safe_eval is present below 2.4.0, which " +
			"the trytond claims never mention")
	}

	// The four backports must still read correctly, or the finding above is
	// noise from a spec that does not track the fix.
	v := verdicts(rep)
	for _, c := range []struct {
		version string
		want    taggity.Verdict
	}{
		{"2.4.14", taggity.Vulnerable},
		{"2.4.15", taggity.NotVulnerable},
		{"2.6.14", taggity.NotVulnerable},
		{"2.8.11", taggity.NotVulnerable},
		{"3.2.3", taggity.NotVulnerable},
	} {
		if got, ok := v[c.version]; ok && got != c.want {
			t.Errorf("%s = %v, want %v", c.version, got, c.want)
		}
	}

	// 2.8.11 resolves only if a @classmethod is matched as a class method.
	if v["2.8.11"] == taggity.Unknown {
		t.Error("2.8.11 = UNKNOWN: _callback is a @classmethod there, and a " +
			"decorated method is still a method")
	}
}

// TestAuditTqdmOverlappingClaims is the corpus case for a false positive that
// overlapping ranges used to manufacture.
//
// GHSA-r7q7-xcjw-qx8q claims >= 4.4.1, < 4.11.2 alongside >= 4.10.0, < 4.11.2.
// 4.9.0 sits below the second claim's introduced version while inside the
// first, so the advisory already says it is affected. Selecting it as
// below-introduced asserted the opposite and reported a disagreement against a
// correct advisory.
//
// The fix is danger-shaped: _sh, a subprocess wrapper run at import time, was
// deleted outright.
func TestAuditTqdmOverlappingClaims(t *testing.T) {
	rep := runCorpusAudit(t, "GHSA-r7q7-xcjw-qx8q")

	for _, f := range rep.Findings() {
		t.Errorf("false finding %s %v: 4.9.0 is inside the wider claim, so the "+
			"advisory does not call it safe", f.Span(), f.Rules)
	}

	v := verdicts(rep)
	if v["4.11.1"] != taggity.Vulnerable {
		t.Errorf("4.11.1 = %v, want VULNERABLE: _sh is still called there",
			v["4.11.1"])
	}
	// 4.11.2 deleted the whole block, so the symbol is gone. That is a gap, not
	// a clean bill of health.
	if v["4.11.2"] == taggity.NotVulnerable {
		t.Error("4.11.2 = NOT_VULNERABLE, but commit_hash no longer exists " +
			"there; a symbol that vanished was not examined")
	}
}

// TestAuditPycswAgreesAcrossThreeBranches is a negative control that needs
// code_any to reach every branch.
//
// GHSA-hg4c-rgvm-964g patches a SQL injection in pycsw's CQL_TEXT handling
// across three lines. The 2.x line moved CSW request handling out of server.py
// into pycsw/ogc/csw/csw2.py, where getrecords reaches the helper through
// self.parent, so a spec naming one file answers for only part of the range.
//
// The helper is still defined after the fix and called elsewhere, so a rule
// counting occurrences in the file would never reach zero. Asking about
// getrecords specifically is what makes the boundary visible.
func TestAuditPycswAgreesAcrossThreeBranches(t *testing.T) {
	rep := runCorpusAudit(t, "GHSA-hg4c-rgvm-964g")
	// 1.8.6 and 1.10.5 predate csw2.py, so gaps are expected there.
	requireSilent(t, rep, true)

	v := verdicts(rep)
	for _, ver := range []string{"1.8.5", "1.10.4", "2.0.1"} {
		if v[ver] != taggity.Vulnerable {
			t.Errorf("%s = %v, want VULNERABLE: the unsafe call is still in "+
				"getrecords there", ver, v[ver])
		}
	}
	if v["2.0.2"] != taggity.NotVulnerable {
		t.Errorf("2.0.2 = %v, want NOT_VULNERABLE: the fix routes CQL through "+
			"cql2fes1 there", v["2.0.2"])
	}
}

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
// The spec has inverted polarity — it asks whether the FIX is present, because
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
// Like the redis spec this one has inverted polarity — it matches the FIX, so
// VULNERABLE means "guard present". That is also why the observation lands in
// Overclaims rather than Findings, and why Overclaims has to be rendered: the
// report said "0 finding(s)" for an advisory that is demonstrably wrong.
func TestAuditMLflowOverclaimsThreeZero(t *testing.T) {
	sp, err := spec.Load(corpusPath("GHSA-wxj7-3fx5-pp9m.yaml"))
	if err != nil {
		t.Fatalf("spec: %v", err)
	}
	adv, err := audit.LoadAdvisory(corpusPath("GHSA-wxj7-3fx5-pp9m.json"))
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
		t.Fatalf("expected two claimed ranges, got %d", len(claims))
	}

	boundaries := audit.SelectBoundaries(claims, allTags)
	rep := audit.Run(&check.Checker{Source: repo}, sp, adv, boundaries)

	t.Logf("\n%s  %s", rep.AdvisoryID, rep.Package)
	for _, res := range rep.Results {
		t.Log(res.Describe())
	}

	guard := map[string]taggity.Verdict{}
	for _, res := range rep.Results {
		guard[res.Boundary.Version] = res.Signals.Overall()
	}

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

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
	t.Logf("\n  findings %d · consistent %d · narrower %d · unknown %d",
		findings, consistent, narrower, unknown)

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

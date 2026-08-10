//go:build corpus

// Corpus tests run the whole engine against real advisories and real
// repositories. They clone over the network, so they are behind a build tag and
// excluded from the default suite.
//
//	go test -tags corpus ./internal/check/ -v
package check_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// expectation is what a human determined to be true for one version, by reading
// the source. These are the graded answers the scanner is measured against.
type expectation struct {
	version string
	want    taggity.Verdict
	reason  taggity.Reason
	note    string
}

type corpusCase struct {
	specFile string
	// claimed is the advisory's asserted range, for reporting disagreements.
	claimed  string
	versions []expectation
}

func TestCorpus(t *testing.T) {
	cases := []corpusCase{
		{
			specFile: "GHSA-rprw-h62v-c2w7.yaml",
			claimed:  ">= 0, < 5.1",
			versions: []expectation{
				// load() constructs a Loader in every one of these. The
				// advisory's fix landed in 5.1, but it changed the default
				// argument rather than removing the call, so `calls` reports
				// the construct as present throughout. That is a true answer
				// to the question the spec asks.
				{version: "3.12", want: taggity.Vulnerable},
				{version: "3.13", want: taggity.Vulnerable},
				{version: "5.1", want: taggity.Vulnerable,
					note: "advisory says fixed here; calls cannot see a default-arg change"},
				{version: "5.4.1", want: taggity.Vulnerable},
				{version: "6.0.1", want: taggity.Vulnerable},
				{version: "99.0.0", want: taggity.Unknown, reason: taggity.ReasonNoTag},
			},
		},
		{
			// The same advisory as above, asked with a defaults rule. The
			// boundary the calls rule could not see is located exactly.
			specFile: "GHSA-rprw-h62v-c2w7-defaults.yaml",
			claimed:  ">= 0, < 5.1",
			versions: []expectation{
				{version: "3.12", want: taggity.Vulnerable},
				{version: "3.13", want: taggity.Vulnerable},
				{version: "5.1", want: taggity.NotVulnerable,
					note: "the fix changed Loader=Loader to Loader=None"},
				{version: "5.4.1", want: taggity.NotVulnerable},
				// 6.0 made Loader a required argument. No default at all is not
				// the dangerous default, and reporting it as one would call a
				// fixed version vulnerable.
				{version: "6.0.1", want: taggity.NotVulnerable,
					note: "Loader has no default here"},
			},
		},
		{
			specFile: "GHSA-6757-jp84-gxfx.yaml",
			claimed:  ">= 5.1b7, < 5.3.1",
			versions: []expectation{
				// Verified by reading lib/yaml/constructor.py at each tag:
				// construct_python_object_apply calls self.make_python_instance
				// in all four, including the versions the advisory calls fixed.
				// The 5.3.1 fix changed what make_python_instance does, not
				// whether it is called, so a calls rule reports the construct
				// as present throughout. This is a true answer to the question
				// the spec asks and a false signal about the vulnerability.
				{version: "5.1", want: taggity.Vulnerable},
				{version: "5.3", want: taggity.Vulnerable},
				{version: "5.3.1", want: taggity.Vulnerable,
					note: "advisory says fixed; the call survives the fix"},
				{version: "6.0.1", want: taggity.Vulnerable,
					note: "same"},
			},
		},
	}

	var total, correct, unknown, underReport, overReport int

	for _, cc := range cases {
		sp, err := spec.Load(filepath.Join("..", "..", "testdata", "corpus", cc.specFile))
		if err != nil {
			t.Fatalf("%s: %v", cc.specFile, err)
		}
		c, err := check.New(sp.Repo)
		if err != nil {
			t.Fatalf("%s: %v", cc.specFile, err)
		}

		t.Logf("\n%s  (%s)\n  claims: %s\n  spec:   %s %s\n",
			sp.Advisory, sp.Package.Name, cc.claimed,
			sp.Signal.Code.Symbol, sp.RuleString())

		for _, exp := range cc.versions {
			total++
			got := c.Version(sp, exp.version)
			overall := got.Overall()

			status := "ok"
			switch {
			case overall == exp.want:
				correct++
				if overall == taggity.Unknown {
					unknown++
				}
			case exp.want == taggity.Vulnerable && overall == taggity.NotVulnerable:
				underReport++
				status = "UNDER-REPORT"
			case exp.want == taggity.NotVulnerable && overall == taggity.Vulnerable:
				overReport++
				status = "over-report"
			default:
				status = "MISMATCH"
				if overall == taggity.Unknown {
					unknown++
				}
			}

			line := fmt.Sprintf("  %-8s %-15s want %-15s %s",
				exp.version, overall, exp.want, status)
			if got.Reason != taggity.ReasonNone {
				line += " [" + string(got.Reason) + "]"
			}
			if exp.note != "" {
				line += "  " + exp.note
			}
			t.Log(line)

			if status == "UNDER-REPORT" {
				t.Errorf("%s@%s: reported safe but is affected. This is the one "+
					"failure mode the design forbids.", sp.Package.Name, exp.version)
			}
		}
	}

	t.Logf("\n=== corpus summary ===")
	t.Logf("  checked:       %d", total)
	t.Logf("  correct:       %d", correct)
	t.Logf("  unknown:       %d", unknown)
	t.Logf("  over-reports:  %d  (recoverable)", overReport)
	t.Logf("  under-reports: %d  (unacceptable)", underReport)
}

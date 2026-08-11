package audit

import (
	"testing"

	"github.com/nickelsec/taggity/internal/taggity"
)

// report builds a Report from a compact description: one entry per probed
// version, in ascending order.
func report(entries ...Result) *Report {
	return &Report{Results: entries}
}

func res(version string, outcome Outcome, v taggity.Verdict, reason taggity.Reason, rule string) Result {
	return Result{
		Boundary: Boundary{Version: version, Rule: rule},
		Signals:  taggity.Signals{Present: v, Reason: reason},
		Outcome:  outcome,
	}
}

// The case that motivated grouping. The redis-py audit probed four releases
// spanning 5.3.1 to 8.1.0 and reported four disagreements, when a single commit
// in 4.5.5 explained every one of them.
func TestConsecutiveDisagreementsAreOneFinding(t *testing.T) {
	r := report(
		res("4.5.4", Consistent, taggity.Vulnerable, "", RuleFixed),
		res("5.3.1", Disagreement, taggity.NotVulnerable, "", RuleUnmentioned),
		res("6.4.0", Disagreement, taggity.NotVulnerable, "", RuleUnmentioned),
		res("7.4.1", Disagreement, taggity.NotVulnerable, "", RuleUnmentioned),
		res("8.1.0", Disagreement, taggity.NotVulnerable, "", RuleUnmentioned),
	)

	got := r.Findings()
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1: four releases reflecting one change "+
			"must not be counted four times", len(got))
	}
	if got[0].Span() != "5.3.1-8.1.0" {
		t.Errorf("span = %q, want 5.3.1-8.1.0", got[0].Span())
	}
	if len(got[0].Versions) != 4 {
		t.Errorf("finding covers %d versions, want 4", len(got[0].Versions))
	}

	findings, _, _, _ := r.Counts()
	if findings != 1 {
		t.Errorf("Counts reports %d findings, want 1", findings)
	}
	raw, _, _, _ := r.VersionCounts()
	if raw != 4 {
		t.Errorf("VersionCounts reports %d disagreements, want 4: the raw tally "+
			"is still available when probe count is what matters", raw)
	}
}

// A gap means something changed and changed back, which is two observations
// rather than one span.
func TestNonAdjacentDisagreementsStaySeparate(t *testing.T) {
	r := report(
		res("1.0.0", Disagreement, taggity.NotVulnerable, "", RuleUnmentioned),
		res("2.0.0", Consistent, taggity.Vulnerable, "", RuleFixed),
		res("3.0.0", Disagreement, taggity.NotVulnerable, "", RuleUnmentioned),
	)

	got := r.Findings()
	if len(got) != 2 {
		t.Fatalf("got %d findings, want 2: a consistent version between two "+
			"disagreements means the construct came back", len(got))
	}
	if got[0].Span() != "1.0.0" || got[1].Span() != "3.0.0" {
		t.Errorf("spans = %q and %q, want 1.0.0 and 3.0.0",
			got[0].Span(), got[1].Span())
	}
}

// Adjacent disagreements that disagree for different reasons are different
// observations, even though both are disagreements.
func TestDifferentVerdictsDoNotMerge(t *testing.T) {
	r := report(
		res("1.0.0", Disagreement, taggity.Vulnerable, "", RuleBelowIntroduced),
		res("2.0.0", Disagreement, taggity.NotVulnerable, "", RuleUnmentioned),
	)

	if got := r.Findings(); len(got) != 2 {
		t.Fatalf("got %d findings, want 2: opposite verdicts are not one "+
			"observation", len(got))
	}
}

// Unknowns group too. The redis run could not read the spec file at three
// consecutive early versions, which is one gap in coverage, not three.
func TestConsecutiveUnknownsGroupByReason(t *testing.T) {
	r := report(
		res("2.10.6", Indeterminate, taggity.Unknown, taggity.ReasonFileAbsent, RuleUnmentioned),
		res("3.5.3", Indeterminate, taggity.Unknown, taggity.ReasonFileAbsent, RuleUnmentioned),
		res("4.1.4", Indeterminate, taggity.Unknown, taggity.ReasonFileAbsent, RuleBelowIntroduced),
		res("4.4.3", Consistent, taggity.NotVulnerable, "", RuleBelowFixed),
	)

	got := r.Unknowns()
	if len(got) != 1 {
		t.Fatalf("got %d unknown groups, want 1", len(got))
	}
	if got[0].Reason != taggity.ReasonFileAbsent {
		t.Errorf("reason = %q, want file_absent", got[0].Reason)
	}
	if got[0].Span() != "2.10.6-4.1.4" {
		t.Errorf("span = %q, want 2.10.6-4.1.4", got[0].Span())
	}
	// Both selection rules that contributed are recorded, so the report can
	// explain why each version was probed.
	if len(got[0].Rules) != 2 {
		t.Errorf("rules = %v, want both contributing rules", got[0].Rules)
	}
}

// Adjacent unknowns with different reasons are separate gaps: a missing file
// and an unresolvable version need different follow-up.
func TestUnknownsWithDifferentReasonsSeparate(t *testing.T) {
	r := report(
		res("1.0.0", Indeterminate, taggity.Unknown, taggity.ReasonFileAbsent, RuleUnmentioned),
		res("2.0.0", Indeterminate, taggity.Unknown, taggity.ReasonSymbolNotFound, RuleUnmentioned),
	)

	if got := r.Unknowns(); len(got) != 2 {
		t.Fatalf("got %d unknown groups, want 2: a missing file and a missing "+
			"symbol are different problems", len(got))
	}
}

func TestSingleVersionFindingRendersWithoutRange(t *testing.T) {
	r := report(res("1.8.7", Disagreement, taggity.Vulnerable, "", RuleUnmentioned))

	got := r.Findings()
	if len(got) != 1 {
		t.Fatalf("got %d findings, want 1", len(got))
	}
	if got[0].Span() != "1.8.7" {
		t.Errorf("span = %q, want the bare version", got[0].Span())
	}
}

func TestEmptyReportHasNoFindings(t *testing.T) {
	r := report()
	if got := r.Findings(); len(got) != 0 {
		t.Errorf("empty report yielded %d findings", len(got))
	}
	if got := r.Unknowns(); len(got) != 0 {
		t.Errorf("empty report yielded %d unknown groups", len(got))
	}
}

// A claim with no probed version anywhere in it was never examined, and a
// report that stays quiet about it reads as agreement with the whole advisory.
//
// This happens for real in two shapes: a branch fixed on a pre-release, since
// boundary selection probes only released versions, and a claim naming a commit
// hash where a version belongs.
func TestUnprobedClaimsAreReported(t *testing.T) {
	cases := []struct {
		name    string
		claims  []Claim
		results []Result
		want    int
	}{
		{
			name: "a branch fixed on a prerelease is never probed",
			claims: []Claim{
				{Introduced: "0", Fixed: "3.3.11"},
				{Introduced: "3.4.0b1", Fixed: "3.4.0b11"},
			},
			results: []Result{
				res("3.3.10", Consistent, taggity.NotVulnerable, "", RuleBelowFixed),
				res("3.3.11", Consistent, taggity.Vulnerable, "", RuleFixed),
			},
			want: 1,
		},
		{
			name:   "a claim naming a commit hash is not probeable",
			claims: []Claim{{Introduced: "0", Fixed: "c231cbd3d5147ee920a37b6ee9dd236b376bcf5a"}},
			results: []Result{
				res("2024.2.20", Consistent, taggity.NotVulnerable, "", RuleFixed),
			},
			want: 1,
		},
		{
			name:   "a claim probed at its fixed edge is covered",
			claims: []Claim{{Introduced: "0", Fixed: "3.3.11"}},
			results: []Result{
				res("3.3.11", Consistent, taggity.Vulnerable, "", RuleFixed),
			},
			want: 0,
		},
		{
			name:   "a claim probed in its interior is covered",
			claims: []Claim{{Introduced: "2.0.0", Fixed: "2.4.0"}},
			results: []Result{
				res("2.3.9", Consistent, taggity.NotVulnerable, "", RuleBelowFixed),
			},
			want: 0,
		},
		{
			name:   "an open-ended claim is covered by any probe above it",
			claims: []Claim{{Introduced: "1.0.0"}},
			results: []Result{
				res("2.0.0", Consistent, taggity.NotVulnerable, "", RuleUnmentioned),
			},
			want: 0,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			r := &Report{Claims: c.claims, Results: c.results}
			if got := len(r.UnprobedClaims()); got != c.want {
				t.Errorf("UnprobedClaims() = %d, want %d: %v",
					got, c.want, r.UnprobedClaims())
			}
		})
	}
}

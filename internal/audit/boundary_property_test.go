package audit

import (
	"fmt"
	"math/rand"
	"testing"

	"github.com/nickelsec/taggity/internal/git"
)

// The boundary rules have produced three defects so far, and every one was
// found by running a new advisory rather than by review: inverted polarity
// mislabelling correct fixes, findings counted per version instead of per
// change, and an open-below claim leaving every earlier line looking
// unmentioned. That last one manufactured twelve false findings out of a
// correct advisory.
//
// Those bugs live in the interaction between claim shapes and tag topologies,
// which is a space too large to cover by example. These tests generate the
// space and assert properties that must hold across all of it, so the next one
// does not need the right advisory to come along before it is visible.

// topology is a generated repository shape.
type topology struct {
	name string
	tags []git.TagRef
}

func mkTags(t *testing.T, versions ...string) []git.TagRef {
	t.Helper()
	out := make([]git.TagRef, 0, len(versions))
	for _, v := range versions {
		parsed, ok := git.ParseVersion(v)
		if !ok {
			t.Fatalf("test setup: %q does not parse", v)
		}
		out = append(out, git.TagRef{Name: v, Ver: parsed})
	}
	return out
}

// topologies covers the repository shapes real packages actually have. Each one
// has bitten some advisory in the corpus.
func topologies(t *testing.T) []topology {
	t.Helper()
	return []topology{
		{"single line", mkTags(t, "1.0.0", "1.0.1", "1.0.2", "1.1.0")},
		{"two lines", mkTags(t, "1.0.0", "1.9.9", "2.0.0", "2.1.0", "2.1.1")},
		{"many lines", mkTags(t,
			"0.9.0", "1.0.0", "2.0.0", "3.0.0", "4.0.0", "5.0.0", "6.0.0")},
		{"deep patch line", mkTags(t,
			"2.0.0", "2.0.1", "2.0.2", "2.0.3", "2.0.4", "2.0.5", "2.0.6")},
		{"prereleases interleaved", mkTags(t,
			"1.0.0rc1", "1.0.0", "1.1.0rc1", "1.1.0rc2", "1.1.0", "2.0.0rc1", "2.0.0")},
		{"four maintenance branches", mkTags(t,
			"12.0.0", "12.0.1", "13.0.0", "13.0.1", "14.0.0", "14.0.1",
			"15.0.0", "15.0.1")},
		{"sparse majors", mkTags(t, "1.0.0", "7.0.0", "8.0.0", "99.0.0")},
		{"single tag", mkTags(t, "1.0.0")},
		{"only prereleases", mkTags(t, "1.0.0rc1", "1.0.0rc2")},
	}
}

// claimSets covers the claim shapes advisories are written in, including the
// ones that have caused bugs.
func claimSets() []struct {
	name   string
	claims []Claim
} {
	return []struct {
		name   string
		claims []Claim
	}{
		{"nothing claimed", nil},
		{"open below", []Claim{{Introduced: "0", Fixed: "2.0.0"}}},
		{"open below, empty introduced", []Claim{{Fixed: "2.0.0"}}},
		{"bounded", []Claim{{Introduced: "1.0.0", Fixed: "2.0.0"}}},
		{"open above", []Claim{{Introduced: "1.0.0"}}},
		{"two branches", []Claim{
			{Introduced: "1.0.0", Fixed: "1.9.9"},
			{Introduced: "2.0.0", Fixed: "2.1.0"},
		}},
		{"four branches", []Claim{
			{Introduced: "0", Fixed: "12.0.1"},
			{Introduced: "13.0.0", Fixed: "13.0.1"},
			{Introduced: "14.0.0", Fixed: "14.0.1"},
			{Introduced: "15.0.0", Fixed: "15.0.1"},
		}},
		{"duplicated range", []Claim{
			{Introduced: "1.0.0", Fixed: "2.0.0"},
			{Introduced: "1.0.0", Fixed: "2.0.0"},
		}},
		{"overlapping ranges", []Claim{
			{Introduced: "1.0.0", Fixed: "2.1.0"},
			{Introduced: "1.5.0", Fixed: "2.0.0"},
		}},
		{"prerelease boundaries", []Claim{{Introduced: "1.0.0rc1", Fixed: "2.0.0rc1"}}},
		{"versions absent from the repo", []Claim{
			{Introduced: "42.0.0", Fixed: "43.0.0"},
		}},
		{"unparseable versions", []Claim{{Introduced: "not-a-version", Fixed: "also-not"}}},
	}
}

// each runs f over every topology and claim shape.
func each(t *testing.T, f func(t *testing.T, tags []git.TagRef, claims []Claim, got []Boundary)) {
	t.Helper()
	for _, topo := range topologies(t) {
		for _, cs := range claimSets() {
			t.Run(topo.name+"/"+cs.name, func(t *testing.T) {
				f(t, topo.tags, cs.claims, SelectBoundaries(cs.claims, topo.tags))
			})
		}
	}
}

// Every probed version must be a tag the repository actually has. A boundary
// naming a version that does not exist resolves to no_tag, which spends a probe
// to learn nothing.
func TestPropertyEveryBoundaryIsARealTag(t *testing.T) {
	each(t, func(t *testing.T, tags []git.TagRef, _ []Claim, got []Boundary) {
		t.Helper()
		have := map[string]bool{}
		for _, tag := range tags {
			have[tag.Ver.Original] = true
		}
		for _, b := range got {
			if !have[b.Version] {
				t.Errorf("probed %q, which is not a tag in this repository", b.Version)
			}
		}
	})
}

// A version is probed once. Two rules can select the same version, and the more
// specific one wins, but the version must not appear twice: the report would
// double count it and a finding would be inflated.
func TestPropertyNoVersionIsProbedTwice(t *testing.T) {
	each(t, func(t *testing.T, _ []git.TagRef, _ []Claim, got []Boundary) {
		t.Helper()
		seen := map[string]string{}
		for _, b := range got {
			if prev, dup := seen[b.Version]; dup {
				t.Errorf("%s probed twice, by %q and %q", b.Version, prev, b.Rule)
			}
			seen[b.Version] = b.Rule
		}
	})
}

// This is the open-below regression as a property.
//
// unmentioned-line exists to probe release lines an advisory is silent about.
// A version the advisory already covers is not silence, and probing it as
// though it were produces a disagreement with a claim that agrees. On
// PYSEC-2026-564 that was twelve false findings.
func TestPropertyUnmentionedNeverFiresInsideAClaim(t *testing.T) {
	each(t, func(t *testing.T, _ []git.TagRef, claims []Claim, got []Boundary) {
		t.Helper()
		for _, b := range got {
			if b.Rule != RuleUnmentioned {
				continue
			}
			v, ok := git.ParseVersion(b.Version)
			if !ok {
				continue
			}
			for _, c := range claims {
				if !covers(c, v) {
					continue
				}
				t.Errorf("%s selected as %s while claim %+v covers it",
					b.Version, RuleUnmentioned, c)
			}
		}
	})
}

// Auditing has to stay cheap or it cannot be done at scale. The probe count is
// a function of how many edges the claims have, not of how many tags the
// repository happens to carry.
func TestPropertyProbeCountTracksClaimsNotTags(t *testing.T) {
	each(t, func(t *testing.T, tags []git.TagRef, claims []Claim, got []Boundary) {
		t.Helper()
		// Two edges per claim, plus at most one unmentioned probe per release
		// line. Anything beyond that means a rule is scanning rather than
		// probing edges.
		lines := map[int]bool{}
		for _, tag := range tags {
			if len(tag.Ver.Release) > 0 {
				lines[tag.Ver.Release[0]] = true
			}
		}
		ceiling := 2*len(claims) + len(lines)
		if len(got) > ceiling {
			t.Errorf("probed %d versions from %d claims over %d tags; the edges "+
				"allow at most %d", len(got), len(claims), len(tags), ceiling)
		}
	})
}

// Probes come back in ascending version order. A report reads as a walk through
// history, and an out-of-order line makes a span like 5.3.1-8.1.0 meaningless.
func TestPropertyBoundariesAreSortedAscending(t *testing.T) {
	each(t, func(t *testing.T, _ []git.TagRef, _ []Claim, got []Boundary) {
		t.Helper()
		for i := 1; i < len(got); i++ {
			a, aok := git.ParseVersion(got[i-1].Version)
			b, bok := git.ParseVersion(got[i].Version)
			if !aok || !bok {
				continue
			}
			if a.Compare(b) > 0 {
				t.Errorf("out of order: %s before %s", got[i-1].Version, got[i].Version)
			}
		}
	})
}

// Selection reads claims and tags, so the same inputs must give the same
// output. Map iteration order is not guaranteed, and an audit that reordered
// itself between runs would not be reproducible.
func TestPropertySelectionIsDeterministic(t *testing.T) {
	each(t, func(t *testing.T, tags []git.TagRef, claims []Claim, got []Boundary) {
		t.Helper()
		for range 20 {
			again := SelectBoundaries(claims, tags)
			if len(again) != len(got) {
				t.Fatalf("run returned %d boundaries, first returned %d",
					len(again), len(got))
			}
			for i := range got {
				if again[i] != got[i] {
					t.Fatalf("boundary %d differs between runs: %+v then %+v",
						i, got[i], again[i])
				}
			}
		}
	})
}

// Tag order arrives from a map walk, so selection cannot depend on it.
func TestPropertyTagOrderDoesNotMatter(t *testing.T) {
	// #nosec G404 -- shuffling test fixtures, not generating secrets.
	rng := rand.New(rand.NewSource(1))
	each(t, func(t *testing.T, tags []git.TagRef, claims []Claim, got []Boundary) {
		t.Helper()
		for range 10 {
			shuffled := make([]git.TagRef, len(tags))
			copy(shuffled, tags)
			rng.Shuffle(len(shuffled), func(i, j int) {
				shuffled[i], shuffled[j] = shuffled[j], shuffled[i]
			})

			again := SelectBoundaries(claims, shuffled)
			if len(again) != len(got) {
				t.Fatalf("shuffled tags gave %d boundaries, ordered gave %d",
					len(again), len(got))
			}
			for i := range got {
				if again[i] != got[i] {
					t.Fatalf("shuffled tags changed boundary %d: %+v then %+v",
						i, got[i], again[i])
				}
			}
		}
	})
}

// A release candidate is not a release, and an advisory range is a statement
// about releases. Probing one invites a disagreement about a version nobody
// installed.
func TestPropertyPrereleasesAreNeverProbed(t *testing.T) {
	each(t, func(t *testing.T, _ []git.TagRef, _ []Claim, got []Boundary) {
		t.Helper()
		for _, b := range got {
			v, ok := git.ParseVersion(b.Version)
			if ok && v.IsPrerelease() {
				t.Errorf("probed prerelease %s", b.Version)
			}
		}
	})
}

// Every boundary carries the rule that selected it, and reports cite that rule
// to explain a finding. A blank or unknown rule would make a finding
// unexplainable.
func TestPropertyEveryBoundaryCitesAKnownRule(t *testing.T) {
	known := map[string]bool{
		RuleBelowIntroduced: true,
		RuleFixed:           true,
		RuleBelowFixed:      true,
		RuleUnmentioned:     true,
	}
	each(t, func(t *testing.T, _ []git.TagRef, _ []Claim, got []Boundary) {
		t.Helper()
		for _, b := range got {
			if !known[b.Rule] {
				t.Errorf("%s cites rule %q, which no report can explain",
					b.Version, b.Rule)
			}
		}
	})
}

// ExpectAffected is what classify compares a verdict against, so a rule that
// set it inconsistently would label correct versions as disagreements. The
// value follows from the rule alone.
func TestPropertyExpectAffectedFollowsFromTheRule(t *testing.T) {
	want := map[string]bool{
		RuleBelowIntroduced: false, // the advisory says this one is safe
		RuleFixed:           false, // and this one is fixed
		RuleBelowFixed:      true,  // this one it calls affected
		RuleUnmentioned:     false, // and about this one it says nothing
	}
	each(t, func(t *testing.T, _ []git.TagRef, _ []Claim, got []Boundary) {
		t.Helper()
		for _, b := range got {
			if b.ExpectAffected != want[b.Rule] {
				t.Errorf("%s selected by %s expects affected=%v, want %v",
					b.Version, b.Rule, b.ExpectAffected, want[b.Rule])
			}
		}
	})
}

// Selection must not panic or hang on input an advisory database can actually
// contain. Every one of these has appeared in a real record.
func TestPropertySurvivesDegenerateInput(t *testing.T) {
	tags := mkTags(t, "1.0.0", "2.0.0")

	cases := []struct {
		name   string
		claims []Claim
		tags   []git.TagRef
	}{
		{"no tags", []Claim{{Introduced: "1.0.0", Fixed: "2.0.0"}}, nil},
		{"no claims", nil, tags},
		{"neither", nil, nil},
		{"empty claim", []Claim{{}}, tags},
		{"fixed below introduced", []Claim{{Introduced: "2.0.0", Fixed: "1.0.0"}}, tags},
		{"identical bounds", []Claim{{Introduced: "1.0.0", Fixed: "1.0.0"}}, tags},
		{"commit hash as a version", []Claim{
			{Introduced: "0", Fixed: "8f46ba3f6dc7b18375f7aa63c48a1fe461190430"},
		}, tags},
		{"epoch", []Claim{{Introduced: "1!1.0.0", Fixed: "1!2.0.0"}}, tags},
		{"very long version", []Claim{
			{Introduced: "1.0.0.0.0.0.0.0.0.0", Fixed: "2.0.0.0.0.0.0.0.0.0"},
		}, tags},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := SelectBoundaries(c.claims, c.tags)
			// The result may be empty; it may not be wrong.
			for _, b := range got {
				if b.Version == "" {
					t.Error("selected an empty version")
				}
			}
		})
	}
}

// A version the advisory calls fixed and a version it calls affected are
// different claims about the same code, so they must never be the same probe
// with the same expectation.
func TestPropertyFixedAndBelowFixedDisagree(t *testing.T) {
	each(t, func(t *testing.T, _ []git.TagRef, _ []Claim, got []Boundary) {
		t.Helper()
		byRule := map[string][]string{}
		for _, b := range got {
			byRule[b.Rule] = append(byRule[b.Rule], b.Version)
		}
		for _, fixed := range byRule[RuleFixed] {
			for _, below := range byRule[RuleBelowFixed] {
				if fixed == below {
					t.Errorf("%s is both fixed and below-fixed", fixed)
				}
			}
		}
	})
}

// A generated smoke test over random topologies, to reach shapes the curated
// list does not name. The assertions are the same invariants; the point is the
// input.
func TestPropertyRandomTopologies(t *testing.T) {
	// #nosec G404 -- generating test topologies, not secrets.
	rng := rand.New(rand.NewSource(42))

	for i := range 200 {
		majors := 1 + rng.Intn(4)
		var versions []string
		for maj := 1; maj <= majors; maj++ {
			for patch := range 1 + rng.Intn(4) {
				versions = append(versions, fmt.Sprintf("%d.0.%d", maj, patch))
			}
		}
		tags := mkTags(t, versions...)

		claims := []Claim{{
			Introduced: versions[rng.Intn(len(versions))],
			Fixed:      versions[rng.Intn(len(versions))],
		}}
		if rng.Intn(3) == 0 {
			claims[0].Introduced = "0"
		}

		got := SelectBoundaries(claims, tags)

		have := map[string]bool{}
		for _, tag := range tags {
			have[tag.Ver.Original] = true
		}
		seen := map[string]bool{}
		for _, b := range got {
			if !have[b.Version] {
				t.Fatalf("case %d: probed %q, not a tag in %v", i, b.Version, versions)
			}
			if seen[b.Version] {
				t.Fatalf("case %d: %q probed twice", i, b.Version)
			}
			seen[b.Version] = true

			v, _ := git.ParseVersion(b.Version)
			if b.Rule == RuleUnmentioned && covers(claims[0], v) {
				t.Fatalf("case %d: %q selected as unmentioned while %+v covers it",
					i, b.Version, claims[0])
			}
		}
	}
}

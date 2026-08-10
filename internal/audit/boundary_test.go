package audit

import (
	"testing"

	"github.com/nickelsec/taggity/internal/git"
)

func tags(versions ...string) []git.TagRef {
	out := make([]git.TagRef, 0, len(versions))
	for _, v := range versions {
		parsed, ok := git.ParseVersion(v)
		if !ok {
			panic("bad test version " + v)
		}
		out = append(out, git.TagRef{Name: "v" + v, Ver: parsed})
	}
	return out
}

func rules(bs []Boundary) map[string]string {
	out := map[string]string{}
	for _, b := range bs {
		out[b.Version] = b.Rule
	}
	return out
}

func TestSelectBoundariesProbesEdges(t *testing.T) {
	available := tags("1.9.8", "1.9.9", "2.0.0", "2.1.3", "2.1.4", "2.2.0")
	claims := []Claim{{Introduced: "2.0.0", Fixed: "2.1.4"}}

	got := rules(SelectBoundaries(claims, available))

	// The version below `introduced`: the advisory says this one is safe.
	if got["1.9.9"] != RuleBelowIntroduced {
		t.Errorf("1.9.9 rule = %q, want %q", got["1.9.9"], RuleBelowIntroduced)
	}
	// The fix itself, and the version below it.
	if got["2.1.4"] != RuleFixed {
		t.Errorf("2.1.4 rule = %q, want %q", got["2.1.4"], RuleFixed)
	}
	if got["2.1.3"] != RuleBelowFixed {
		t.Errorf("2.1.3 rule = %q, want %q", got["2.1.3"], RuleBelowFixed)
	}
	// Interior versions are not probed: a range is an assertion about its
	// edges, so probing the middle costs time and proves nothing extra.
	if _, probed := got["2.0.0"]; probed {
		t.Error("2.0.0 was probed; interior versions add cost without evidence")
	}
}

// The rule that produces findings. An advisory discussing only 2.x says nothing
// about whether 1.x was ever patched, and a fix backported to one line but not
// another is the most common way a published range is wrong.
//
// Note that when the unmentioned line sits immediately below the introduced
// version, both rules select the same version and expect the same answer. The
// more specific reason is recorded; what matters is that the version is probed.
func TestSelectBoundariesProbesUnmentionedReleaseLines(t *testing.T) {
	available := tags("1.8.5", "1.8.7", "2.0.0", "2.1.3", "2.1.4")
	claims := []Claim{{Introduced: "2.0.0", Fixed: "2.1.4"}}

	got := rules(SelectBoundaries(claims, available))

	if _, probed := got["1.8.7"]; !probed {
		t.Error("newest 1.x release was not probed; a fix backported to 2.x " +
			"while 1.x kept the vulnerable code is exactly the case that " +
			"produces findings")
	}
	if _, probed := got["1.8.5"]; probed {
		t.Error("only the newest release of an unmentioned line is worth probing")
	}
}

// When an advisory covers a middle release line, the lines above and below it
// are both unmentioned and both worth probing. This is the shape that isolates
// the unmentioned-line rule from the below-introduced rule.
func TestSelectBoundariesProbesLinesAboveAndBelow(t *testing.T) {
	available := tags("1.8.7", "2.0.0", "2.1.3", "2.1.4", "3.0.0", "3.2.1")
	claims := []Claim{{Introduced: "2.0.0", Fixed: "2.1.4"}}

	got := rules(SelectBoundaries(claims, available))

	if got["3.2.1"] != RuleUnmentioned {
		t.Errorf("newest 3.x release rule = %q, want %q: the advisory says "+
			"nothing about whether 3.x ever carried the fix",
			got["3.2.1"], RuleUnmentioned)
	}
	if _, probed := got["1.8.7"]; !probed {
		t.Error("newest 1.x release was not probed")
	}
}

// Multi-branch backports are the case the whole design targets: two ranges over
// two release lines, each with its own fix.
func TestSelectBoundariesHandlesMultipleRanges(t *testing.T) {
	available := tags("4.1.9", "4.2.0", "4.4.3", "4.4.4", "4.5.0", "4.5.3", "4.5.4")
	claims := []Claim{
		{Introduced: "4.5.0", Fixed: "4.5.4"},
		{Introduced: "4.2.0", Fixed: "4.4.4"},
	}

	got := rules(SelectBoundaries(claims, available))

	for _, want := range []struct{ version, rule string }{
		{"4.4.4", RuleFixed},
		{"4.5.4", RuleFixed},
		{"4.4.3", RuleBelowFixed},
		{"4.5.3", RuleBelowFixed},
		{"4.1.9", RuleBelowIntroduced},
	} {
		if got[want.version] != want.rule {
			t.Errorf("%s rule = %q, want %q", want.version, got[want.version], want.rule)
		}
	}
}

func TestSelectBoundariesSkipsPrereleases(t *testing.T) {
	available := tags("2.0.0", "2.1.0b3", "2.1.3", "2.1.4")
	claims := []Claim{{Introduced: "2.0.0", Fixed: "2.1.4"}}

	for _, b := range SelectBoundaries(claims, available) {
		if v, _ := git.ParseVersion(b.Version); v.IsPrerelease() {
			t.Errorf("probed prerelease %s: an advisory range is a statement "+
				"about releases", b.Version)
		}
	}
}

func TestSelectBoundariesStaysSmall(t *testing.T) {
	versions := make([]string, 0, 50)
	for minor := range 50 {
		versions = append(versions, "2."+itoa(minor)+".0")
	}
	available := tags(versions...)
	claims := []Claim{{Introduced: "2.0.0", Fixed: "2.49.0"}}

	got := SelectBoundaries(claims, available)
	// Cheapness is the point: if auditing an advisory cost fifty checks, doing
	// it at scale would not be possible.
	if len(got) > 8 {
		t.Errorf("selected %d boundaries from 50 versions; probing edges should "+
			"stay in single digits", len(got))
	}
}

func TestSelectBoundariesEmptyInputs(t *testing.T) {
	if got := SelectBoundaries(nil, nil); got != nil {
		t.Errorf("no tags should yield no boundaries, got %v", got)
	}
	if got := SelectBoundaries([]Claim{{Introduced: "1.0.0"}}, nil); got != nil {
		t.Errorf("no tags should yield no boundaries, got %v", got)
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// An open-below claim covers every earlier release line, not just the line its
// fixed version happens to sit on.
//
// This is the PYSEC-2026-564 regression. Vitrage claims "< 12.0.1" among its
// four ranges, which covers everything ever released before 12.0.1. Marking
// only major 12 as mentioned left lines 0 through 11 looking like silence, so
// the unmentioned-line rule probed the newest release of each and reported
// twelve disagreements — every one of them a version the advisory does warn
// about. Twelve false findings on an advisory that was correct.
func TestSelectBoundariesTreatsOpenBelowClaimAsCoveringEarlierLines(t *testing.T) {
	available := tags(
		"9.0.0", "10.0.0", "11.0.0",
		"12.0.0", "12.0.1",
		"13.0.0", "13.0.1",
	)
	claims := []Claim{
		{Introduced: "0", Fixed: "12.0.1"},
		{Introduced: "13.0.0", Fixed: "13.0.1"},
	}

	got := rules(SelectBoundaries(claims, available))
	for _, v := range []string{"9.0.0", "10.0.0", "11.0.0"} {
		if r, ok := got[v]; ok {
			t.Errorf("%s probed as %q; it is inside the claim \"< 12.0.1\" and "+
				"is not an unmentioned line", v, r)
		}
	}

	// The edges of both ranges must still be probed.
	for v, want := range map[string]string{
		"12.0.0": RuleBelowFixed,
		"12.0.1": RuleFixed,
		"13.0.0": RuleBelowFixed,
		"13.0.1": RuleFixed,
	} {
		if got[v] != want {
			t.Errorf("%s selected by %q, want %q", v, got[v], want)
		}
	}
}

// The narrowing above must not silence the case the rule exists for: a line
// ABOVE every claimed range is still unexamined territory, and a fix that never
// made it there is the most common way a published range is wrong.
func TestSelectBoundariesStillProbesLinesAboveTheClaims(t *testing.T) {
	available := tags("1.0.0", "2.0.0", "3.0.0", "3.0.1", "4.0.0", "5.0.0")
	claims := []Claim{{Introduced: "0", Fixed: "3.0.1"}}

	got := rules(SelectBoundaries(claims, available))
	for _, v := range []string{"4.0.0", "5.0.0"} {
		if got[v] != RuleUnmentioned {
			t.Errorf("%s selected by %q, want %q: the advisory says nothing "+
				"about this line", v, got[v], RuleUnmentioned)
		}
	}
	if _, ok := got["1.0.0"]; ok {
		t.Error("1.0.0 is below the claim's fixed version and is already covered")
	}
}

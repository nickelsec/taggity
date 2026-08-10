package audit

import (
	"sort"

	"github.com/nickelsec/taggity/internal/git"
)

// Boundary is a version worth probing, and why it was chosen.
type Boundary struct {
	Version string
	// Rule names which selection rule produced this version, so a report can
	// explain itself and so a finding can be traced back to its reasoning.
	Rule string
	// ExpectAffected is what the advisory implies about this version.
	ExpectAffected bool
}

// Selection rules, named so reports and findings can cite them.
const (
	RuleBelowIntroduced = "below-introduced" // claim says safe here
	RuleFixed           = "fixed"            // claim says the fix landed here
	RuleBelowFixed      = "below-fixed"      // claim says affected here
	RuleUnmentioned     = "unmentioned-line" // claim is silent about this line
)

// SelectBoundaries picks the versions where a claim would be wrong.
//
// Verifying an entire range is unnecessary: a range is an assertion about its
// edges, and the interior follows. Four rules cover the ways an edge can be
// misplaced, and the fourth is where findings actually come from — an advisory
// that discusses only 2.x is silent about whether 1.8.x was ever patched, and
// that silence is exactly how backported fixes get missed.
func SelectBoundaries(claims []Claim, available []git.TagRef) []Boundary {
	if len(available) == 0 {
		return nil
	}

	// Released versions in ascending order, prereleases excluded: an advisory
	// range is a statement about releases, and probing a release candidate
	// invites noise.
	var rel []git.TagRef
	for _, t := range available {
		if !t.Ver.IsPrerelease() {
			rel = append(rel, t)
		}
	}
	sort.Slice(rel, func(i, j int) bool { return rel[i].Ver.Compare(rel[j].Ver) < 0 })
	if len(rel) == 0 {
		return nil
	}

	// A version can satisfy several rules at once: 4.4.4 may be one range's
	// fixed version and also sit below another range's introduced. Record the
	// most specific reason rather than whichever rule ran first, because the
	// rule is what a report cites to explain a finding.
	at := map[string]Boundary{}
	add := func(v, rule string, affected bool) {
		if v == "" {
			return
		}
		if prev, ok := at[v]; ok && precedence(prev.Rule) >= precedence(rule) {
			return
		}
		at[v] = Boundary{Version: v, Rule: rule, ExpectAffected: affected}
	}

	mentioned := map[int]bool{} // release lines the advisory talks about

	for _, c := range claims {
		if c.Introduced != "" && c.Introduced != "0" {
			if v, ok := predecessor(rel, c.Introduced); ok {
				// The advisory says this version is unaffected. If the
				// construct is present, users of it are not being warned.
				add(v, RuleBelowIntroduced, false)
			}
			if maj, ok := majorOf(c.Introduced); ok {
				mentioned[maj] = true
			}
		}
		if c.Fixed != "" {
			add(c.Fixed, RuleFixed, false)
			if v, ok := predecessor(rel, c.Fixed); ok {
				add(v, RuleBelowFixed, true)
			}
			if maj, ok := majorOf(c.Fixed); ok {
				mentioned[maj] = true
				// "introduced: 0" means every release before Fixed, not just
				// Fixed's own line. Marking only the literal major left every
				// earlier line looking like silence, so an advisory that
				// already covers them reported them as disagreements. On
				// PYSEC-2026-564 that was twelve false findings from a claim
				// reading "< 12.0.1", each one a version the advisory does
				// warn about.
				if c.Introduced == "" || c.Introduced == "0" {
					for m := range maj {
						mentioned[m] = true
					}
				}
			}
		}
	}

	// Release lines the advisory never mentions. A fix backported to 2.x while
	// 1.x quietly kept the vulnerable code is the single most common way a
	// published range is wrong.
	for maj, newest := range newestPerLine(rel) {
		if mentioned[maj] {
			continue
		}
		add(newest, RuleUnmentioned, false)
	}

	out := make([]Boundary, 0, len(at))
	for _, b := range at {
		out = append(out, b)
	}
	sort.Slice(out, func(i, j int) bool {
		a, _ := git.ParseVersion(out[i].Version)
		b, _ := git.ParseVersion(out[j].Version)
		return a.Compare(b) < 0
	})
	return out
}

// precedence orders the selection rules by how specifically they identify a
// version. A version named directly by the advisory is described by that fact
// rather than by an incidental relationship to some other range.
func precedence(rule string) int {
	switch rule {
	case RuleFixed:
		return 3
	case RuleBelowFixed:
		return 2
	case RuleBelowIntroduced:
		return 1
	default: // RuleUnmentioned
		return 0
	}
}

// predecessor returns the highest released version strictly below v.
func predecessor(rel []git.TagRef, v string) (string, bool) {
	target, ok := git.ParseVersion(v)
	if !ok {
		return "", false
	}
	var best string
	found := false
	for _, t := range rel {
		if t.Ver.Compare(target) < 0 {
			best, found = t.Ver.Original, true
		}
	}
	return best, found
}

// newestPerLine maps each major version to its newest release.
func newestPerLine(rel []git.TagRef) map[int]string {
	out := map[int]string{}
	best := map[int]git.Version{}
	for _, t := range rel {
		maj, ok := majorOfVer(t.Ver)
		if !ok {
			continue
		}
		if cur, seen := best[maj]; !seen || t.Ver.Compare(cur) > 0 {
			best[maj] = t.Ver
			out[maj] = t.Ver.Original
		}
	}
	return out
}

func majorOf(v string) (int, bool) {
	parsed, ok := git.ParseVersion(v)
	if !ok {
		return 0, false
	}
	return majorOfVer(parsed)
}

func majorOfVer(v git.Version) (int, bool) {
	if len(v.Release) == 0 {
		return 0, false
	}
	return v.Release[0], true
}

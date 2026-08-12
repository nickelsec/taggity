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

// DescribeRule renders a selection rule as the reason a version was worth
// probing, in the words someone reading a report would use.
//
// The constants stay as stable identifiers for --verbose and for anything
// parsing output; this is the display layer.
func DescribeRule(rule string) string {
	switch rule {
	case RuleBelowIntroduced:
		return "the advisory says this version is safe"
	case RuleFixed:
		return "the advisory says the fix landed here"
	case RuleBelowFixed:
		return "the advisory says this version is affected"
	case RuleUnmentioned:
		return "the advisory never mentions this release line"
	default:
		return rule
	}
}

// SelectBoundaries picks the versions where a claim would be wrong.
//
// Verifying an entire range is unnecessary: a range is an assertion about its
// edges, and the interior follows. Four rules cover the ways an edge can be
// misplaced, and the fourth is where findings actually come from. An advisory
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
	// Only released tags are probeable. A claim may name a version this
	// repository never tagged, or something that is not a version at all:
	// PYSEC-2021-382 lists a commit hash where a fixed version belongs.
	// Selecting one spends a probe to learn no_tag and reports a gap that says
	// nothing about the advisory.
	probeable := make(map[string]bool, len(rel))
	for _, t := range rel {
		probeable[t.Ver.Original] = true
	}

	at := map[string]Boundary{}
	add := func(v, rule string, affected bool) {
		if v == "" || !probeable[v] {
			return
		}
		if prev, ok := at[v]; ok && precedence(prev.Rule) >= precedence(rule) {
			return
		}
		at[v] = Boundary{Version: v, Rule: rule, ExpectAffected: affected}
	}

	for _, c := range claims {
		if c.Introduced != "" && c.Introduced != "0" {
			if v, ok := predecessor(rel, c.Introduced); ok {
				// The advisory says this version is unaffected, unless another
				// claim covers it. Ranges overlap in practice: tqdm's advisory
				// carries >= 4.4.1, < 4.11.2 alongside >= 4.10.0, < 4.11.2, and
				// 4.9.0 sits below the second while inside the first.
				//
				// Probing it as below-introduced asserts the advisory calls it
				// safe when the advisory says the opposite, and finding the
				// construct there reports a disagreement that does not exist.
				// A false correction filed against a maintainer is the most
				// expensive way this tool can fail.
				if !coveredByAny(claims, v) {
					add(v, RuleBelowIntroduced, false)
				}
			}
		}
		if c.Fixed != "" {
			add(c.Fixed, RuleFixed, false)
			if v, ok := predecessor(rel, c.Fixed); ok {
				add(v, RuleBelowFixed, true)
			}
		}
	}

	mentioned := mentionedLines(claims, rel)

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

// mentionedLines reports which release lines the advisory already talks about.
//
// A line counts as mentioned when some claim covers a release on it, which is
// not the same as the line appearing in a claim's endpoints. "introduced: 0"
// names no line but covers every line below its fixed version; a claim with no
// fixed version covers every line above its introduced; and a claim spanning
// 1.0.0 to 3.0.1 covers the whole of line 2 without naming it. Deriving this
// from the releases rather than from the endpoints handles all three, and the
// version below an introduced version stays outside the range on purpose.
func mentionedLines(claims []Claim, rel []git.TagRef) map[int]bool {
	mentioned := map[int]bool{}
	for _, t := range rel {
		line, ok := majorOfVer(t.Ver)
		if !ok {
			continue
		}
		for _, c := range claims {
			if covers(c, t.Ver) {
				mentioned[line] = true
				break
			}
		}
	}
	return mentioned
}

// covers reports whether a claim's range includes v.
func covers(c Claim, v git.Version) bool {
	if c.Introduced != "" && c.Introduced != "0" {
		lo, ok := git.ParseVersion(c.Introduced)
		if !ok {
			return false
		}
		if v.Compare(lo) < 0 {
			return false
		}
	}
	if c.Fixed == "" {
		return true
	}
	hi, ok := git.ParseVersion(c.Fixed)
	if !ok {
		// A claim whose fixed version cannot be parsed states a lower bound and
		// nothing more, so treat it as open above rather than as covering
		// nothing. Reading it as empty would leave real lines looking silent.
		return true
	}
	return v.Compare(hi) < 0
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

func majorOfVer(v git.Version) (int, bool) {
	if len(v.Release) == 0 {
		return 0, false
	}
	return v.Release[0], true
}

// coveredByAny reports whether any claim marks version as affected.
//
// Overlapping ranges are common: an advisory may carry a wide claim and a
// narrower one that shares its fixed version. A version inside the wide claim
// is claimed affected no matter where it sits relative to the narrow one.
func coveredByAny(claims []Claim, version string) bool {
	v, ok := git.ParseVersion(version)
	if !ok {
		return false
	}
	for _, c := range claims {
		if covers(c, v) {
			return true
		}
	}
	return false
}

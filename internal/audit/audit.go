package audit

import (
	"fmt"
	"slices"

	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// Outcome classifies one probed version.
type Outcome string

const (
	// Disagreement is the only reportable finding: the advisory implies this
	// version is safe and the construct is present. Users of it are not being
	// told to upgrade.
	Disagreement Outcome = "DISAGREEMENT"

	// Consistent means the result matches what the advisory implies.
	Consistent Outcome = "consistent"

	// Narrower means the advisory claims a version is affected and the
	// construct is absent.
	//
	// This is recorded but deliberately not treated as a finding. A calls rule
	// over-reports by design and, as the corpus showed, misses many real fixes
	// entirely, so this direction is far more likely to be a blind spot in the
	// spec than an error in the advisory. Reporting it as a finding is how a
	// false correction gets filed against a maintainer.
	Narrower Outcome = "narrower-than-claimed"

	// Indeterminate means the check could not answer.
	Indeterminate Outcome = "unknown"
)

// Result is one probed version.
type Result struct {
	Boundary Boundary
	Signals  taggity.Signals
	Outcome  Outcome
}

// Report is the audit of one advisory against one spec.
type Report struct {
	AdvisoryID string
	Package    string
	Claims     []Claim
	Results    []Result
}

// Finding is one structural observation, covering every consecutive probed
// version that shares it.
//
// Versions are grouped rather than listed individually because a single edit to
// a file shows up at every release after it. Counting versions instead of
// changes inflates a report by however many releases happened to be probed.
type Finding struct {
	// From and To bound the affected versions, inclusive. They are equal when
	// a single version is involved.
	From, To string
	// Versions are the probed versions this finding covers, in order.
	Versions []string
	// Verdict is what the engine concluded for all of them.
	Verdict taggity.Verdict
	// Reason is set when the verdict is Unknown.
	Reason taggity.Reason
	// Rules are the boundary rules that selected these versions.
	Rules []string
}

// Span renders the finding's version range for a report.
func (f Finding) Span() string {
	if f.From == f.To {
		return f.From
	}
	return f.From + "-" + f.To
}

// Findings returns disagreements, grouped into structural observations.
func (r *Report) Findings() []Finding {
	return r.group(func(res Result) bool { return res.Outcome == Disagreement })
}

// Unknowns returns indeterminate results, grouped the same way. A run that
// could not answer for six consecutive versions has one gap, not six.
func (r *Report) Unknowns() []Finding {
	return r.group(func(res Result) bool { return res.Outcome == Indeterminate })
}

// Overclaims returns narrower-than-claimed results, grouped the same way.
//
// These are not findings and are never exported: see Narrower for why this
// direction is more often a blind spot in the spec than an error in the
// advisory. They are returned separately so a report can render them, since a
// count in the summary line is easy to miss.
//
// Under an inverted-polarity rule this direction carries real weight. A match
// there means the guard was found present in a version the advisory calls
// affected, which is evidence rather than the absence of it.
func (r *Report) Overclaims() []Finding {
	return r.group(func(res Result) bool { return res.Outcome == Narrower })
}

// group collapses runs of adjacent matching results that share a verdict and
// reason. Adjacency is by probe order, which SelectBoundaries already sorts
// ascending by version.
//
// Grouping stops at any version that does not match the predicate: a
// disagreement at 5.3.1 and another at 8.1.0 with a consistent 6.0.0 between
// them are two observations, because something changed and changed back.
func (r *Report) group(match func(Result) bool) []Finding {
	var out []Finding
	var cur *Finding

	flush := func() {
		if cur != nil {
			out = append(out, *cur)
			cur = nil
		}
	}

	for _, res := range r.Results {
		if !match(res) {
			flush()
			continue
		}
		v := res.Signals.Overall()
		if cur != nil && (cur.Verdict != v || cur.Reason != res.Signals.Reason) {
			flush()
		}
		if cur == nil {
			cur = &Finding{
				From:    res.Boundary.Version,
				Verdict: v,
				Reason:  res.Signals.Reason,
			}
		}
		cur.To = res.Boundary.Version
		cur.Versions = append(cur.Versions, res.Boundary.Version)
		if !slices.Contains(cur.Rules, res.Boundary.Rule) {
			cur.Rules = append(cur.Rules, res.Boundary.Rule)
		}
	}
	flush()
	return out
}

// Counts summarises the run. Findings and unknowns are counted as grouped
// observations; consistent and narrower results are counted per version, since
// they are not reported individually.
func (r *Report) Counts() (findings, consistent, narrower, unknown int) {
	for _, res := range r.Results {
		switch res.Outcome {
		case Consistent:
			consistent++
		case Narrower:
			narrower++
		default:
			// Disagreement and Indeterminate are counted as grouped
			// observations below, not per version.
		}
	}
	return len(r.Findings()), consistent, narrower, len(r.Unknowns())
}

// VersionCounts reports the raw per-version tallies, for when the number of
// probes matters rather than the number of observations.
func (r *Report) VersionCounts() (disagreements, consistent, narrower, unknown int) {
	for _, res := range r.Results {
		switch res.Outcome {
		case Disagreement:
			disagreements++
		case Consistent:
			consistent++
		case Narrower:
			narrower++
		case Indeterminate:
			unknown++
		}
	}
	return
}

// Versions lists the boundaries this report probed.
func (r *Report) Versions() []string {
	out := make([]string, 0, len(r.Results))
	for _, res := range r.Results {
		out = append(out, res.Boundary.Version)
	}
	return out
}

// Run probes an advisory's boundaries and classifies each result.
//
// A version whose spec file has moved yields Indeterminate and the audit
// continues. Aborting would let one relocated file discard an otherwise useful
// audit, and the relocation may itself be what the advisory got wrong.
func Run(c *check.Checker, sp *spec.Spec, adv *Advisory, boundaries []Boundary) *Report {
	rep := &Report{
		AdvisoryID: adv.ID,
		Package:    sp.Package.Name,
		Claims:     adv.Claims(sp.Package.Name),
	}

	matchMeansVuln := sp.Signal.Code.Rule.MatchMeansVulnerable()

	for _, b := range boundaries {
		sig := c.Version(sp, b.Version)
		rep.Results = append(rep.Results, Result{
			Boundary: b,
			Signals:  sig,
			Outcome:  classify(b, sig.Overall(), matchMeansVuln),
		})
	}
	return rep
}

// classify compares a verdict against what the advisory implies.
//
// matchMeansVulnerable carries the spec's polarity. A rule may match the danger
// (calls: eval) or the guard (calls: asyncio.shield); without knowing which,
// a correctly fixed version would be reported as a disagreement.
func classify(b Boundary, v taggity.Verdict, matchMeansVulnerable bool) Outcome {
	var affected bool
	switch v {
	case taggity.Vulnerable:
		affected = matchMeansVulnerable
	case taggity.NotVulnerable:
		affected = !matchMeansVulnerable
	default:
		return Indeterminate
	}

	switch {
	case affected && !b.ExpectAffected:
		// The advisory implies this version is safe and it is not. Users of it
		// are not being told to upgrade.
		return Disagreement
	case !affected && b.ExpectAffected:
		return Narrower
	default:
		return Consistent
	}
}

// Describe renders a one-line summary of a result for terminal output.
func (r Result) Describe() string {
	line := fmt.Sprintf("  %-10s %-14s %-22s %s",
		r.Boundary.Version, r.Signals.Overall(), r.Boundary.Rule, r.Outcome)
	if r.Signals.Reason != taggity.ReasonNone {
		line += " [" + string(r.Signals.Reason) + "]"
	}
	return line
}

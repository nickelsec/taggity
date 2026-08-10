package audit

import (
	"fmt"

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
	// entirely — so this direction is far more likely to be a blind spot in the
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

// Findings returns only the results worth acting on.
func (r *Report) Findings() []Result {
	var out []Result
	for _, res := range r.Results {
		if res.Outcome == Disagreement {
			out = append(out, res)
		}
	}
	return out
}

// Counts summarises the run.
func (r *Report) Counts() (findings, consistent, narrower, unknown int) {
	for _, res := range r.Results {
		switch res.Outcome {
		case Disagreement:
			findings++
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

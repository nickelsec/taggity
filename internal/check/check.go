// Package check implements the primitive: given a spec and a version, decide
// whether that version contains the vulnerable construct, and record enough
// evidence for someone else to re-derive the answer.
package check

import (
	"fmt"

	"github.com/nickelsec/taggity/internal/git"
	"github.com/nickelsec/taggity/internal/predicate"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// Source supplies the bytes to examine. It is an interface so tests can run
// without a network or a working tree.
type Source interface {
	// Resolve maps a published version to a commit and the tag that produced
	// it, or explains why it could not.
	Resolve(version string) (commit, tag string, reason taggity.Reason)
	// FileAt reads a repository-relative path at a commit.
	FileAt(commit, path string) ([]byte, taggity.Reason)
}

// Checker evaluates specs against versions.
type Checker struct {
	Source Source
}

// New returns a Checker reading from a git repository. The repository is a hard
// precondition: if it cannot be cloned there is no way to answer anything, so
// this fails immediately rather than producing a run of Unknowns.
func New(repoURL string) (*Checker, error) {
	repo, err := git.OpenOrClone(repoURL)
	if err != nil {
		return nil, fmt.Errorf("repository is required: %w", err)
	}
	return &Checker{Source: repo}, nil
}

// Version evaluates one version and returns its signals.
//
// Every early return is Unknown with a reason. Only the predicate may conclude
// that a version is unaffected, and only from positive evidence that the
// construct is absent.
func (c *Checker) Version(s *spec.Spec, version string) taggity.Signals {
	commit, tag, reason := c.Source.Resolve(version)
	if reason != taggity.ReasonNone {
		return unknown(reason, taggity.Evidence{
			Signal:  "present",
			Verdict: taggity.Unknown,
			Rule:    s.RuleString(),
			Detail:  fmt.Sprintf("version %s did not resolve to a tag", version),
		})
	}

	locations := s.Signal.Locations()
	evidence := make([]taggity.Evidence, 0, len(locations))
	verdicts := make([]taggity.Verdict, 0, len(locations))
	reasons := make([]taggity.Reason, 0, len(locations))

	for _, loc := range locations {
		src, reason := c.Source.FileAt(commit, loc.File)
		if reason != taggity.ReasonNone {
			verdicts = append(verdicts, taggity.Unknown)
			reasons = append(reasons, reason)
			evidence = append(evidence, taggity.Evidence{
				Signal:  "present",
				Verdict: taggity.Unknown,
				Commit:  commit,
				Tag:     tag,
				File:    loc.File,
				Rule:    loc.Rule.String(),
				Detail:  fmt.Sprintf("%s not present at %s", loc.File, tag),
			})
			continue
		}

		res := evaluate(src, loc)
		verdicts = append(verdicts, res.Verdict)
		reasons = append(reasons, res.Reason)
		evidence = append(evidence, taggity.Evidence{
			Signal:         "present",
			Verdict:        res.Verdict,
			Commit:         commit,
			Tag:            tag,
			File:           loc.File,
			Symbol:         loc.Symbol,
			StartByte:      res.Definition.Start,
			EndByte:        res.Definition.End,
			Rule:           loc.Rule.String(),
			Matcher:        predicate.MatcherName,
			MatcherVersion: predicate.MatcherVersion,
			Source:         "static",
			Detail:         detail(res, loc),
		})
	}

	verdict, reason := combineAny(verdicts, reasons)
	return taggity.Signals{
		Present:  verdict,
		Reason:   reason,
		Evidence: evidence,
	}
}

// combineAny reduces per-location verdicts under "any": the construct is
// present if it was found anywhere.
//
// The three-valued part is the whole point. A match anywhere is decisive, so
// one location's UNKNOWN cannot suppress another's VULNERABLE. But with no
// match, an UNKNOWN means some location was never really examined, and calling
// that NOT_VULNERABLE would report safety the engine did not establish.
func combineAny(verdicts []taggity.Verdict, reasons []taggity.Reason) (taggity.Verdict, taggity.Reason) {
	if len(verdicts) == 0 {
		return taggity.Unknown, taggity.ReasonUnsupportedRule
	}

	firstUnknown := -1
	for i, v := range verdicts {
		if v == taggity.Vulnerable {
			return taggity.Vulnerable, taggity.ReasonNone
		}
		if v != taggity.NotVulnerable && firstUnknown < 0 {
			firstUnknown = i
		}
	}
	if firstUnknown >= 0 {
		return taggity.Unknown, reasons[firstUnknown]
	}
	// Every location was examined and none matched. The verdict is whatever the
	// predicate already concluded for them, which keeps the sole assignment of
	// NotVulnerable inside internal/predicate.
	return verdicts[0], taggity.ReasonNone
}

// evaluate runs the rule kind the spec asks for.
//
// A rule kind this build does not implement yields Unknown rather than falling
// through to any verdict. Validate rejects such a spec before it reaches here,
// so this is the second of two guards on the same failure.
func evaluate(src []byte, code spec.Code) predicate.Result {
	switch code.Rule.Kind() {
	case "calls":
		return predicate.Calls(src, code.Symbol, code.Rule.Calls)
	case "defaults":
		param, value, ok := code.Rule.Default()
		if !ok {
			return predicate.Result{
				Verdict: taggity.Unknown,
				Reason:  taggity.ReasonUnsupportedRule,
			}
		}
		return predicate.Defaults(src, code.Symbol, param, value)
	default:
		return predicate.Result{
			Verdict: taggity.Unknown,
			Reason:  taggity.ReasonUnsupportedRule,
		}
	}
}

func detail(res predicate.Result, code spec.Code) string {
	switch res.Reason {
	case taggity.ReasonSymbolNotFound:
		return fmt.Sprintf("symbol %s not found", code.Symbol)
	case taggity.ReasonAmbiguousSymbol:
		return fmt.Sprintf("symbol %s is defined %d times; qualify it as Class.method",
			code.Symbol, len(res.Candidates))
	case taggity.ReasonParseFailed:
		return "source did not parse"
	case taggity.ReasonUnsupportedRule:
		return "this build does not implement the rule kind the spec asks for"
	default:
		if param, value, ok := code.Rule.Default(); ok {
			return fmt.Sprintf("%s declares %s=%s", code.Symbol, param, value)
		}
		return fmt.Sprintf("%s calls %s", code.Symbol, code.Rule.Calls)
	}
}

func unknown(r taggity.Reason, ev taggity.Evidence) taggity.Signals {
	return taggity.Signals{
		Present:  taggity.Unknown,
		Reason:   r,
		Evidence: []taggity.Evidence{ev},
	}
}

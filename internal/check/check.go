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

	src, reason := c.Source.FileAt(commit, s.Signal.Code.File)
	if reason != taggity.ReasonNone {
		return unknown(reason, taggity.Evidence{
			Signal:  "present",
			Verdict: taggity.Unknown,
			Commit:  commit,
			Tag:     tag,
			File:    s.Signal.Code.File,
			Rule:    s.RuleString(),
			Detail:  fmt.Sprintf("%s not present at %s", s.Signal.Code.File, tag),
		})
	}

	res := evaluate(src, s)

	ev := taggity.Evidence{
		Signal:         "present",
		Verdict:        res.Verdict,
		Commit:         commit,
		Tag:            tag,
		File:           s.Signal.Code.File,
		Symbol:         s.Signal.Code.Symbol,
		StartByte:      res.Definition.Start,
		EndByte:        res.Definition.End,
		Rule:           s.RuleString(),
		Matcher:        predicate.MatcherName,
		MatcherVersion: predicate.MatcherVersion,
		Source:         "static",
		Detail:         detail(res, s),
	}

	return taggity.Signals{
		Present:  res.Verdict,
		Reason:   res.Reason,
		Evidence: []taggity.Evidence{ev},
	}
}

// evaluate runs the rule kind the spec asks for.
//
// A rule kind this build does not implement yields Unknown rather than falling
// through to any verdict. Validate rejects such a spec before it reaches here,
// so this is the second of two guards on the same failure.
func evaluate(src []byte, s *spec.Spec) predicate.Result {
	code := s.Signal.Code
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

func detail(res predicate.Result, s *spec.Spec) string {
	switch res.Reason {
	case taggity.ReasonSymbolNotFound:
		return fmt.Sprintf("symbol %s not found", s.Signal.Code.Symbol)
	case taggity.ReasonAmbiguousSymbol:
		return fmt.Sprintf("symbol %s is defined %d times; qualify it as Class.method",
			s.Signal.Code.Symbol, len(res.Candidates))
	case taggity.ReasonParseFailed:
		return "source did not parse"
	case taggity.ReasonUnsupportedRule:
		return "this build does not implement the rule kind the spec asks for"
	default:
		if param, value, ok := s.Signal.Code.Rule.Default(); ok {
			return fmt.Sprintf("%s declares %s=%s", s.Signal.Code.Symbol, param, value)
		}
		return fmt.Sprintf("%s calls %s", s.Signal.Code.Symbol, s.Signal.Code.Rule.Calls)
	}
}

func unknown(r taggity.Reason, ev taggity.Evidence) taggity.Signals {
	return taggity.Signals{
		Present:  taggity.Unknown,
		Reason:   r,
		Evidence: []taggity.Evidence{ev},
	}
}

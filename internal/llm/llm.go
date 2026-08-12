// Package llm turns a description of a vulnerability into a spec, and explains
// why a check could not answer.
//
// Nothing outside this package may import it, which depguard enforces as a
// build failure. That is the whole architecture of the project in one rule: a
// model proposes what to look for, and deterministic code decides what is
// there. The same spec evaluated twice gives the same verdict because the spec,
// not the model, is what gets evaluated.
//
// Two consequences follow, and both are load-bearing:
//
// Nothing here returns a taggity.Verdict. Draft returns a spec; Locate returns
// somewhere else to look. A verdict always comes from internal/predicate
// parsing real source.
//
// A model may widen a search and may never narrow a verdict. Turning an Unknown
// into Vulnerable by finding the moved file is fine, because the engine then
// re-checks and confirms it. Turning one into NotVulnerable would clear a
// version on a model's say-so, and a scanner staying quiet is how someone gets
// compromised.
package llm

import (
	"context"

	"github.com/nickelsec/taggity/internal/spec"
)

// Provider is one model behind one API.
//
// An interface for the same reason check.Source is one: tests substitute a fake
// and the hermetic suite never reaches the network. It is deliberately small,
// since a layer that orchestrated several calls would be a layer reasoning
// about verdicts.
type Provider interface {
	// Draft proposes a spec from a description of a vulnerability.
	Draft(ctx context.Context, req DraftRequest) (*spec.Spec, error)

	// Locate proposes somewhere else to look when a check could not answer. It
	// returns an explanation and, when it has one, a suggested amendment. It
	// never returns a verdict.
	Locate(ctx context.Context, req LocateRequest) (*Suggestion, error)

	// Name and Model identify what produced a draft, recorded in the spec so a
	// reader can attribute it.
	Name() string
	Model() string
}

// DraftRequest is everything the model gets to write a spec.
type DraftRequest struct {
	// Describe is the researcher's own account of the vulnerability: what goes
	// wrong, in which file, ideally at which line. A vague description produces
	// a vague spec.
	Describe string

	// Repo is the upstream repository URL, recorded in the spec.
	Repo string

	// Package and Ecosystem name the published artifact.
	Package   string
	Ecosystem string

	// Advisory is the advisory ID, when there is one.
	Advisory string

	// Sources are the files the model may read, keyed by repository-relative
	// path. Whole files, at HEAD.
	Sources map[string]string

	// Diff is the fix commit's patch, when one is known. Far better input than
	// a source file: a diff shows which token *changed*, and a rule naming a
	// token that is identical before and after proves nothing.
	Diff string
}

// LocateRequest asks where else a construct might live.
type LocateRequest struct {
	// Version is the release that could not be answered for.
	Version string

	// Reason is the machine-readable reason the check gave up, so the model can
	// tell "the file is not here" from "the file is here and the function is
	// not".
	Reason string

	// Spec is what was asked, rendered as YAML.
	Spec string

	// Sources are whatever could be read at that version, keyed by path. May be
	// empty, which is itself informative.
	Sources map[string]string

	// Tree lists repository-relative paths at that version, so the model can
	// see where a file went rather than guess.
	Tree []string
}

// Suggestion is what a model proposes about a version that could not be
// answered.
//
// It carries no verdict, by construction. Explanation is prose for a human;
// File and Symbol are a place to look, which the caller turns into a spec
// amendment and re-checks with the ordinary engine.
type Suggestion struct {
	// Explanation says why the check could not answer, in a sentence.
	Explanation string

	// File and Symbol name somewhere else to look. Both empty means the model
	// has no proposal, which is a legitimate answer: a version that predates
	// the feature entirely has nowhere else to look.
	File   string
	Symbol string
}

// HasProposal reports whether the suggestion names somewhere to re-check.
func (s *Suggestion) HasProposal() bool {
	return s != nil && s.File != "" && s.Symbol != ""
}

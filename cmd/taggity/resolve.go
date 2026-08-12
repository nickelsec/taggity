package main

import (
	"context"
	"fmt"

	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/git"
	"github.com/nickelsec/taggity/internal/llm"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// resolved is what --llm adds to a version the engine could not answer.
//
// Verdict is only set when the engine re-checked somewhere the model pointed at
// and got an answer. The model never fills it in, which is the whole point:
// "the file is somewhere else" is a search failure, not evidence about what is
// in the file.
type resolved struct {
	Explanation string
	File        string
	Symbol      string

	// Verdict is what the engine concluded after re-checking, or Unevaluated
	// when there was nowhere to look.
	Verdict taggity.Verdict
}

// resolver turns a gap into an explanation, and where possible into a verdict
// the engine produced.
type resolver struct {
	provider llm.Provider
	repo     *git.Repo
	spec     *spec.Spec
	specYAML string
}

// resolve explains one gap and, when the model proposes a location, re-checks
// there.
//
// The sequence matters and is the architecture in four steps:
//
//  1. the engine gave up and said why;
//  2. the model reads the tree and proposes where else to look;
//  3. that proposal becomes an ordinary spec location;
//  4. the engine re-checks and decides.
//
// Step 4 is not optional. A model that named a file has narrowed a search, and
// nothing more: the code may be there, the version may predate the feature, or
// it may have moved and been fixed. Only the parser can tell those apart.
func (r *resolver) resolve(version string, reason taggity.Reason) *resolved {
	commit, _, resolveReason := r.repo.Resolve(version)
	if resolveReason != taggity.ReasonNone {
		return nil
	}

	// Whatever the spec named, at that version, so the model sees what the
	// engine saw rather than HEAD.
	sources := map[string]string{}
	for _, loc := range r.spec.Signal.Locations() {
		if src, reason := r.repo.FileAt(commit, loc.File); reason == taggity.ReasonNone {
			sources[loc.File] = string(src)
		}
	}

	tree, err := r.repo.TreePaths(commit, ".py")
	if err != nil {
		tree = nil
	}

	suggestion, err := r.provider.Locate(context.Background(), llm.LocateRequest{
		Version: version,
		Reason:  string(reason),
		Spec:    r.specYAML,
		Sources: sources,
		Tree:    tree,
	})
	if err != nil {
		return &resolved{Explanation: fmt.Sprintf("could not ask: %v", err)}
	}

	out := &resolved{
		Explanation: suggestion.Explanation,
		File:        suggestion.File,
		Symbol:      suggestion.Symbol,
	}
	if !suggestion.HasProposal() {
		return out
	}

	// The proposal becomes an ordinary location and goes through the ordinary
	// engine. Nothing here is a special case: the same predicate, the same
	// polarity, the same rule.
	amended := *r.spec
	primary := r.spec.Primary()
	amended.Signal = spec.Signal{
		Code: spec.Code{
			File:   suggestion.File,
			Symbol: suggestion.Symbol,
			Rule:   primary.Rule,
		},
	}
	if err := amended.Validate(); err != nil {
		out.Explanation += fmt.Sprintf(" (the proposed location does not "+
			"validate: %v)", err)
		return out
	}

	sig := (&check.Checker{Source: r.repo}).Version(&amended, version)
	out.Verdict = sig.Overall()
	return out
}

// describe renders a resolved gap for a report.
func (r *resolved) describe(indent string) string {
	if r == nil {
		return ""
	}
	out := indent + r.Explanation + "\n"
	if r.Verdict != taggity.Unevaluated && r.File != "" {
		out += fmt.Sprintf("%staggity re-checked %s and found: %s\n",
			indent, r.File, r.Verdict)
	}
	return out
}

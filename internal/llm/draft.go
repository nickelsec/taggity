package llm

import (
	"context"
	"fmt"

	"github.com/nickelsec/taggity/internal/spec"
)

// completer is one round trip to a model: a system prompt, a user prompt, and
// whatever text comes back.
//
// Everything above this line is provider-independent. Only the HTTP call
// differs between Anthropic and OpenRouter, so Draft and Locate are written
// once here rather than copied per provider, where the two would drift.
type completer interface {
	complete(ctx context.Context, system, user string) (string, error)
	Name() string
	Model() string
}

// draft proposes a spec, then stamps provenance and the fields the caller
// already knows.
func draft(ctx context.Context, c completer, req DraftRequest) (*spec.Spec, error) {
	reply, err := c.complete(ctx, draftSystem+"\n\n"+draftExamples, buildDraftPrompt(req))
	if err != nil {
		return nil, err
	}

	sp, err := parseSpec(reply)
	if err != nil {
		return nil, err
	}

	// Provenance is set here rather than trusted from the reply. A model
	// reporting which model wrote something is not evidence of anything, and
	// these fields are what a reader uses to attribute the draft.
	sp.Authoring.Mode = spec.ModeAI
	sp.Authoring.Provider = c.Name()
	sp.Authoring.Model = c.Model()
	sp.Authoring.ReviewedBy = ""

	// The caller knows these; the model only guesses at them.
	if req.Repo != "" {
		sp.Repo = req.Repo
	}
	if req.Advisory != "" {
		sp.Advisory = req.Advisory
	}
	if req.Package != "" {
		sp.Package.Name = req.Package
	}
	if req.Ecosystem != "" {
		sp.Package.Ecosystem = req.Ecosystem
	}

	// Overriding those fields can invalidate what the model returned, so
	// validate after rather than before.
	if err := sp.Validate(); err != nil {
		return nil, fmt.Errorf("the drafted spec does not validate: %w", err)
	}
	return sp, nil
}

// locate asks where else a construct might live. It returns an explanation and
// at most a place to look, never a verdict.
func locate(ctx context.Context, c completer, req LocateRequest) (*Suggestion, error) {
	reply, err := c.complete(ctx, locateSystem, buildLocatePrompt(req))
	if err != nil {
		return nil, err
	}
	return parseSuggestion(reply)
}

package llm

import (
	"errors"
	"fmt"
	"strings"

	"github.com/nickelsec/taggity/internal/spec"
)

// ErrNoSpec reports that a response contained no usable spec.
var ErrNoSpec = errors.New("no spec in the model's reply")

// parseSpec turns a reply into a validated spec.
//
// Strict on purpose: a partial spec is worse than none, because it looks like
// work that was done. A model returning prose instead of YAML is the ordinary
// case rather than an edge case, so the failure has to be loud and has to show
// what came back.
func parseSpec(reply string) (*spec.Spec, error) {
	body := stripFence(strings.TrimSpace(reply))
	if body == "" {
		return nil, ErrNoSpec
	}

	sp, err := spec.Parse([]byte(body))
	if err != nil {
		return nil, fmt.Errorf("%w: %w\n\nthe model replied:\n%s",
			ErrNoSpec, err, truncate(body, 800))
	}
	return sp, nil
}

// stripFence removes a Markdown code fence.
//
// The instructions say YAML only and models mostly comply, but a fence is the
// one deviation common enough that failing on it would be pedantry rather than
// strictness.
func stripFence(s string) string {
	if !strings.HasPrefix(s, "```") {
		return s
	}
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[i+1:]
	}
	if i := strings.LastIndex(s, "```"); i >= 0 {
		s = s[:i]
	}
	return strings.TrimSpace(s)
}

// parseSuggestion reads the WHY/FILE/SYMBOL form.
//
// A missing or "-" file means the model has no proposal, which is a real answer
// rather than a failure: a version predating the feature has nowhere else to
// look. An explanation with no proposal is still worth printing.
func parseSuggestion(reply string) (*Suggestion, error) {
	var s Suggestion
	for line := range strings.SplitSeq(reply, "\n") {
		line = strings.TrimSpace(line)
		switch {
		case strings.HasPrefix(line, "WHY:"):
			s.Explanation = strings.TrimSpace(strings.TrimPrefix(line, "WHY:"))
		case strings.HasPrefix(line, "FILE:"):
			s.File = cleanField(strings.TrimPrefix(line, "FILE:"))
		case strings.HasPrefix(line, "SYMBOL:"):
			s.Symbol = cleanField(strings.TrimPrefix(line, "SYMBOL:"))
		}
	}

	if s.Explanation == "" {
		return nil, fmt.Errorf("no WHY line in the model's reply:\n%s",
			truncate(reply, 400))
	}
	// Half a proposal is not a proposal. Re-checking a file without a symbol,
	// or a symbol without a file, would spend a probe to learn nothing.
	if s.File == "" || s.Symbol == "" {
		s.File, s.Symbol = "", ""
	}
	return &s, nil
}

func cleanField(v string) string {
	v = strings.TrimSpace(v)
	if v == "-" || v == "none" || v == "n/a" {
		return ""
	}
	return strings.Trim(v, "`\"'")
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "\n[truncated]"
}

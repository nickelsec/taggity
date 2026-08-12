package main

import (
	"bytes"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/nickelsec/taggity/internal/llm"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// The description is where the file comes from, because internal/git reads a
// path it is given and cannot enumerate a tree. Missing a path costs the model
// the file it needed; a false positive costs one failed read.
func TestPathsIn(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want []string
	}{
		{
			name: "a line number is stripped",
			in:   "SSRF in proxy_handler at server.py:43, url reaches requests.get",
			want: []string{"server.py"},
		},
		{
			name: "a nested path survives",
			in:   "the bug is in src/mcp/client/auth.py in the discovery method",
			want: []string{"src/mcp/client/auth.py"},
		},
		{
			name: "two files",
			in:   "handler.py calls into validator.py without checking",
			want: []string{"handler.py", "validator.py"},
		},
		{
			name: "punctuation around the path",
			in:   "see (trytond/ir/cron.py) for the safe_eval call",
			want: []string{"trytond/ir/cron.py"},
		},
		{
			name: "no path at all",
			in:   "there is an SSRF in the proxy handler somewhere",
			want: nil,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := pathsIn(c.in)
			if !slices.Equal(got, c.want) {
				t.Errorf("pathsIn(%q) = %v, want %v", c.in, got, c.want)
			}
		})
	}
}

// A shell splits an unquoted sentence into words. Rejecting that would be a
// papercut on the first command anyone runs.
func TestDraftAcceptsAnUnquotedDescription(t *testing.T) {
	var out, errOut bytes.Buffer
	err := runDraft([]string{"--repo", "github.com/x/y", "SSRF", "in", "server.py"},
		&out, &errOut)

	// No API key in the test environment, so this stops at the provider. The
	// point is that it got past argument parsing rather than complaining about
	// the description.
	if err == nil {
		t.Skip("an API key is set; this test asserts on the no-key path")
	}
	if strings.Contains(err.Error(), "describe the vulnerability") {
		t.Errorf("an unquoted description was rejected: %v", err)
	}
}

func TestDraftRequiresADescriptionAndARepo(t *testing.T) {
	var out, errOut bytes.Buffer

	if err := runDraft([]string{"--repo", "github.com/x/y"}, &out, &errOut); err == nil {
		t.Error("accepted an empty description")
	} else if !strings.Contains(err.Error(), "describe") {
		t.Errorf("error should ask for a description, got: %v", err)
	}

	errOut.Reset()
	if err := runDraft([]string{"SSRF in server.py"}, &out, &errOut); err == nil {
		t.Error("accepted a draft with no repository")
	} else if !strings.Contains(err.Error(), "repo") {
		t.Errorf("error should ask for a repository, got: %v", err)
	}
}

// The note is a comment so the output stays a loadable spec whether it is read
// or piped straight into a file.
func TestEmitSpecOutputStaysLoadable(t *testing.T) {
	sp := &spec.Spec{Repo: "https://github.com/x/y"}
	sp.Package.Ecosystem = "PyPI"
	sp.Package.Name = "foo"
	sp.Authoring.Mode = spec.ModeAI
	sp.Authoring.Provider = "anthropic"
	sp.Signal.Code.File = "a.py"
	sp.Signal.Code.Symbol = "f"
	sp.Signal.Code.Rule.Calls = "eval"

	var out bytes.Buffer
	if err := emitSpec(&out, sp, "", "# Drafted by anthropic/model.\n"); err != nil {
		t.Fatalf("emit: %v", err)
	}

	body := out.String()
	if !strings.Contains(body, "# Drafted by anthropic/model.") {
		t.Error("the note was dropped")
	}

	// The whole output, note included, has to parse. A drafted spec that needs
	// hand-editing before it will load is a spec nobody trusts.
	got, err := spec.Parse([]byte(body))
	if err != nil {
		t.Fatalf("drafted output does not load: %v\n%s", err, body)
	}
	if got.Signal.Code.Symbol != "f" {
		t.Errorf("symbol = %q, want f", got.Signal.Code.Symbol)
	}

	// A drafted spec must run before anyone has reviewed it: the loop that
	// makes it trustworthy is to probe two versions and see whether the rule
	// discriminates.
	if got.Authoring.Mode != spec.ModeAI {
		t.Errorf("mode = %q, want ai", got.Authoring.Mode)
	}
	if !got.Authoring.RequiresReview() {
		t.Error("a drafted spec with no reviewer must still be flagged for " +
			"export, which is where the claim leaves the machine")
	}
}

// TestSeamIsEnforcedByConfig guards the rule that makes the architecture real:
// a model may propose what to look for, and only deterministic code decides
// what is there.
//
// The rule silently did nothing from v0.1.0 to 0.3.0, because depguard was
// listed under both `disable` and `enable` in .golangci.yaml and disable wins.
// Three plans cited it as a guarantee while an engine package could have
// imported internal/llm without complaint.
//
// This asserts on the config rather than on behaviour, since golangci-lint is
// not available to the test binary. It is a smoke alarm, not a proof: the proof
// is `golangci-lint run` in CI, which now fails when an engine package reaches
// for internal/llm.
func TestSeamIsEnforcedByConfig(t *testing.T) {
	cfg, err := os.ReadFile(filepath.Join("..", "..", ".golangci.yaml"))
	if err != nil {
		t.Fatalf("reading lint config: %v", err)
	}
	text := string(cfg)

	// The failure that shipped: depguard appeared under both disable and
	// enable, and disable wins. Counting mentions catches it without parsing
	// YAML, since the rule should be named once to enable it and once as a
	// settings key.
	if strings.Count(text, "- depguard") > 1 {
		t.Error("depguard is listed twice, which is how it ended up disabled: " +
			"under `default: all`, a disable entry beats an enable entry and " +
			"the seam rule silently stops running")
	}

	if !strings.Contains(text, "llm-out-of-engine") {
		t.Fatal("the llm-out-of-engine rule is gone")
	}

	// Every package that can produce a verdict has to be covered by name. A
	// pattern that matches nothing is exactly how this rule failed before.
	for _, pkg := range []string{"audit", "check", "git", "predicate", "spec", "taggity"} {
		if !strings.Contains(text, "internal/"+pkg+"/*.go") {
			t.Errorf("internal/%s is not covered by the seam rule", pkg)
		}
	}
}

// The architecture in one assertion: a model narrows a search, and only the
// engine decides what is there.
//
// resolved.Verdict is filled in by check.Checker after re-parsing a file the
// model named. If it were ever set from a model's reply, "the file is somewhere
// else" would become evidence about what is in that file, which it is not: the
// code may be there, the version may predate the feature, or it may have moved
// and been fixed.
func TestResolvedCarriesNoModelVerdict(t *testing.T) {
	// A suggestion with nowhere to look must leave the verdict unevaluated
	// rather than defaulting to anything.
	r := &resolved{Explanation: "the feature did not exist yet"}
	if r.Verdict != taggity.Unevaluated {
		t.Errorf("verdict = %v, want Unevaluated: nothing was checked",
			r.Verdict)
	}
	if got := r.describe("  "); strings.Contains(got, "re-checked") {
		t.Errorf("claimed a re-check that never happened:\n%s", got)
	}

	// With a verdict, the output has to name the file the engine actually read,
	// so a reader can repeat the check by hand.
	r = &resolved{
		Explanation: "the module was split; this handler moved",
		File:        "pycsw/ogc/csw/csw2.py",
		Symbol:      "Csw2.getrecords",
		Verdict:     taggity.Vulnerable,
	}
	got := r.describe("  ")
	for _, want := range []string{"re-checked", "csw2.py", "VULNERABLE"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}

// Half a proposal cannot be re-checked, so it must not be treated as one.
func TestSuggestionNeedsBothFileAndSymbol(t *testing.T) {
	cases := []struct {
		name string
		in   llm.Suggestion
		want bool
	}{
		{"both", llm.Suggestion{File: "a.py", Symbol: "f"}, true},
		{"file only", llm.Suggestion{File: "a.py"}, false},
		{"symbol only", llm.Suggestion{Symbol: "f"}, false},
		{"neither", llm.Suggestion{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.HasProposal(); got != c.want {
				t.Errorf("HasProposal() = %v, want %v", got, c.want)
			}
		})
	}
}

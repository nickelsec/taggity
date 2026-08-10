package spec_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/nickelsec/taggity/internal/spec"
)

const minimal = `
package:
  ecosystem: PyPI
  name: foo
repo: https://github.com/example/foo
signal:
  code:
    file: src/parser.py
    symbol: Alpha.parse
    rule:
      calls: eval
`

func TestParseMinimalSpec(t *testing.T) {
	s, err := spec.Parse([]byte(minimal))
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if s.Package.Name != "foo" || s.Signal.Code.Rule.Calls != "eval" {
		t.Errorf("round-trip lost fields: %+v", s)
	}
	// Absent polarity must default to the danger-shaped reading. A spec that
	// omits the field is the common case, and defaulting the other way would
	// invert every verdict in a report.
	if !s.Signal.Code.Rule.MatchMeansVulnerable() {
		t.Error("omitted indicates must default to vulnerable")
	}
}

// A typo in a field name must fail the parse.
//
// The alternative is a spec that loads cleanly and evaluates something other
// than what was written, `call:` instead of `calls:` would leave the rule
// empty, and an empty rule is not a question anyone asked.
func TestParseRejectsUnknownFields(t *testing.T) {
	cases := map[string]string{
		"misspelled rule key":  strings.Replace(minimal, "calls: eval", "call: eval", 1),
		"misspelled top level": strings.Replace(minimal, "repo:", "repository:", 1),
		"unknown nested key":   strings.Replace(minimal, "    symbol:", "    symbal:", 1),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := spec.Parse([]byte(src)); err == nil {
				t.Error("unknown field accepted; a typo must not evaluate silently")
			}
		})
	}
}

func TestParseRejectsMalformedYAML(t *testing.T) {
	for _, src := range []string{
		"package: [unclosed",
		"\tpackage:\n  name: foo", // tabs are not valid YAML indentation
		"package:\n name: foo\n  ecosystem: PyPI",
	} {
		if _, err := spec.Parse([]byte(src)); err == nil {
			t.Errorf("malformed YAML accepted: %q", src)
		}
	}
}

// Every field Validate requires is required because without it the engine
// cannot ask a question at all. Missing any one of them must be an error, not
// a run of UNKNOWNs that looks like a completed audit.
func TestValidateRequiresEveryEvaluableField(t *testing.T) {
	cases := map[string]string{
		"repo":   "repo: https://github.com/example/foo",
		"name":   "  name: foo",
		"file":   "    file: src/parser.py",
		"symbol": "    symbol: Alpha.parse",
		"calls":  "      calls: eval",
	}
	for field, line := range cases {
		t.Run("missing "+field, func(t *testing.T) {
			src := strings.Replace(minimal, line+"\n", "", 1)
			if src == minimal {
				t.Fatalf("test setup: %q not found in fixture", line)
			}
			_, err := spec.Parse([]byte(src))
			if err == nil {
				t.Fatalf("spec without %s was accepted", field)
			}
			if !strings.Contains(err.Error(), field) {
				t.Errorf("error should name the missing field %q, got: %v", field, err)
			}
		})
	}
}

// Validate reports every problem at once. A spec with four omissions should not
// take four runs to fix.
func TestValidateReportsAllErrorsTogether(t *testing.T) {
	err := (&spec.Spec{}).Validate()
	if err == nil {
		t.Fatal("empty spec passed validation")
	}
	for _, want := range []string{"repo", "package.name", "file", "symbol", "calls"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("joined error missing %q:\n%v", want, err)
		}
	}
}

// Polarity decides how every verdict in a report is read. An unrecognised value
// must be rejected rather than falling through to a default, because either
// default would silently mislabel a whole audit.
func TestValidateRejectsUnknownPolarity(t *testing.T) {
	for _, bad := range []string{"Fixed", "FIXED", "vuln", "true", "patched"} {
		src := strings.Replace(minimal,
			"      calls: eval",
			"      calls: eval\n      indicates: "+bad, 1)
		_, err := spec.Parse([]byte(src))
		if err == nil {
			t.Errorf("indicates: %q was accepted; polarity is not case-insensitive "+
				"and has exactly two values", bad)
			continue
		}
		if !strings.Contains(err.Error(), "indicates") {
			t.Errorf("error for %q should name the field, got: %v", bad, err)
		}
	}
}

func TestValidateAcceptsBothPolarities(t *testing.T) {
	for _, good := range []string{spec.IndicatesVulnerable, spec.IndicatesFixed} {
		src := strings.Replace(minimal,
			"      calls: eval",
			"      calls: eval\n      indicates: "+good, 1)
		s, err := spec.Parse([]byte(src))
		if err != nil {
			t.Fatalf("indicates: %q rejected: %v", good, err)
		}
		want := good == spec.IndicatesVulnerable
		if s.Signal.Code.Rule.MatchMeansVulnerable() != want {
			t.Errorf("indicates: %q gave MatchMeansVulnerable=%v, want %v",
				good, !want, want)
		}
	}
}

// Spec paths are repository paths, which are always forward-slashed. Accepting
// a Windows-style path would produce file_absent on every probe, an audit that
// reports nothing but gaps, on a machine where the spec was written.
func TestValidateRejectsBackslashPaths(t *testing.T) {
	src := strings.Replace(minimal, "file: src/parser.py", `file: src\parser.py`, 1)
	_, err := spec.Parse([]byte(src))
	if err == nil {
		t.Fatal("backslash path accepted")
	}
	if !strings.Contains(err.Error(), "forward slashes") {
		t.Errorf("error should explain the convention, got: %v", err)
	}
}

func TestLoadReadsFromDisk(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "taggity.yaml")
	if err := os.WriteFile(path, []byte(minimal), 0o600); err != nil {
		t.Fatal(err)
	}
	s, err := spec.Load(path)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	if s.Package.Name != "foo" {
		t.Errorf("name = %q, want foo", s.Package.Name)
	}
}

func TestLoadMissingFileNamesTheProblem(t *testing.T) {
	_, err := spec.Load(filepath.Join(t.TempDir(), "absent.yaml"))
	if err == nil {
		t.Fatal("loading a missing spec succeeded")
	}
	if !strings.Contains(err.Error(), "reading spec") {
		t.Errorf("error should say what it was doing, got: %v", err)
	}
}

// The forward-compatibility fields must already round-trip. A spec written
// today should not need migrating when model-assisted authoring arrives, and
// the only way to know that holds is to parse one.
func TestAuthoringRoundTrips(t *testing.T) {
	src := minimal + `
authoring:
  mode: ai
  provider: anthropic
  model: claude-opus-4
  reviewed_by: nick
`
	s, err := spec.Parse([]byte(src))
	if err != nil {
		t.Fatalf("v0.2.0 fields rejected by the v0.1.0 parser: %v", err)
	}
	if s.Authoring.Mode != "ai" || s.Authoring.ReviewedBy != "nick" {
		t.Errorf("authoring lost: %+v", s.Authoring)
	}
	if s.Authoring.Provider != "anthropic" || s.Authoring.Model != "claude-opus-4" {
		t.Errorf("model provenance lost: %+v", s.Authoring)
	}
}

const withAliases = `      calls: eval
    aliases:
      - symbol: Alpha.parse_untrusted
        versions: "<1.0.0"
        source: llm
        confidence: 0.8
        approved_by: nick`

// The alias schema must survive a v0.1.0 parser structurally, so a v0.2.0 spec
// needs no migration. Forward compatibility is about the shape of the document,
// not about whether this release acts on it.
func TestAliasSchemaStillParses(t *testing.T) {
	src := strings.Replace(minimal, "      calls: eval", withAliases, 1)

	var s spec.Spec
	if err := yaml.Unmarshal([]byte(src), &s); err != nil {
		t.Fatalf("alias schema does not parse: %v", err)
	}
	if len(s.Signal.Code.Aliases) != 1 {
		t.Fatalf("aliases lost: %+v", s.Signal.Code.Aliases)
	}
	if a := s.Signal.Code.Aliases[0]; a.Source != "llm" || a.Confidence != 0.8 {
		t.Errorf("alias provenance lost: %+v", a)
	}
}

// Nothing reads aliases in v0.1.0, so accepting one would discard a field the
// author wrote specifically to prevent a symbol_not_found UNKNOWN, and then
// report that UNKNOWN. Rejecting is the only option that does not silently
// produce the outcome the alias existed to avoid.
func TestValidateRejectsAliasesRatherThanIgnoringThem(t *testing.T) {
	src := strings.Replace(minimal, "      calls: eval", withAliases, 1)

	_, err := spec.Parse([]byte(src))
	if err == nil {
		t.Fatal("a spec with aliases loaded; the field is not evaluated, so " +
			"accepting it would discard the author's input silently")
	}
	if !strings.Contains(err.Error(), "aliases") {
		t.Errorf("error must name the field, got: %v", err)
	}
	// The message has to say what to do instead, not just that it failed.
	if !strings.Contains(err.Error(), "symbol") {
		t.Errorf("error should point at qualifying the symbol, got: %v", err)
	}
}

// taggity init writes a spec and validates it before emitting. If the zero-value
// Aliases slice ever marshalled as `aliases: []`, init would produce output that
// fails its own validator.
func TestSpecWithoutAliasesEmitsNoAliasKey(t *testing.T) {
	s, err := spec.Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	out, err := yaml.Marshal(s)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "aliases") {
		t.Errorf("empty aliases marshalled into the document:\n%s", out)
	}
	if _, err := spec.Parse(out); err != nil {
		t.Errorf("a marshalled spec no longer loads: %v", err)
	}
}

// RuleString appears in every evidence record and in exported OSV, where it is
// the only statement of what was actually asked. Under inverted polarity the
// same rule string means the opposite thing, so it has to say which.
func TestRuleStringRecordsPolarity(t *testing.T) {
	danger, err := spec.Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	guardSrc := strings.Replace(minimal,
		"      calls: eval",
		"      calls: eval\n      indicates: fixed", 1)
	guard, err := spec.Parse([]byte(guardSrc))
	if err != nil {
		t.Fatal(err)
	}

	if danger.RuleString() == guard.RuleString() {
		t.Errorf("both polarities render as %q; evidence cannot distinguish "+
			"'calls eval, which is the danger' from 'calls eval, which is the fix'",
			danger.RuleString())
	}
	if !strings.Contains(danger.RuleString(), "eval") {
		t.Errorf("rule string lost the target: %q", danger.RuleString())
	}
}

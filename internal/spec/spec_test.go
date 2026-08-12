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
		t.Fatalf("authoring provenance rejected: %v", err)
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
        versions:
          until: "1.0.0"
        source: llm
        confidence: 0.8
        approved_by: nick`

// The alias schema unmarshals on its own, separately from Validate. Parsing and
// validation failing together would hide which one broke, and the document
// shape is what a spec written against an older release depends on.
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

// A spec with aliases now loads, since the engine evaluates them.
func TestValidateAcceptsAliases(t *testing.T) {
	src := strings.Replace(minimal, "      calls: eval", withAliases, 1)

	s, err := spec.Parse([]byte(src))
	if err != nil {
		t.Fatalf("a spec with aliases was rejected: %v", err)
	}
	if got := s.Signal.Code.Aliases[0].Versions.Until; got != "1.0.0" {
		t.Errorf("alias range lost: %q", got)
	}
}

// A model may propose a name; only a human may stand behind one. Without the
// approval the provenance records who suggested the alias and nobody who
// checked it, which is the distinction the authoring model rests on.
func TestValidateRequiresApprovalForModelProposedAliases(t *testing.T) {
	src := strings.Replace(minimal, "      calls: eval", `      calls: eval
    aliases:
      - symbol: old_name
        source: llm
        confidence: 0.9`, 1)

	_, err := spec.Parse([]byte(src))
	if err == nil {
		t.Fatal("an unapproved model-proposed alias was accepted")
	}
	if !strings.Contains(err.Error(), "approved_by") {
		t.Errorf("error must name the missing field, got: %v", err)
	}
}

func TestValidateRejectsMalformedAliases(t *testing.T) {
	cases := map[string]string{
		"no symbol": `      calls: eval
    aliases:
      - versions:
          until: "1.0.0"`,
		"unknown source": `      calls: eval
    aliases:
      - symbol: old_name
        source: telepathy`,
	}
	for name, block := range cases {
		t.Run(name, func(t *testing.T) {
			src := strings.Replace(minimal, "      calls: eval", block, 1)
			if _, err := spec.Parse([]byte(src)); err == nil {
				t.Error("accepted a malformed alias")
			}
		})
	}
}

func TestValidateAuthoringMode(t *testing.T) {
	withMode := func(block string) string {
		return strings.Replace(minimal, "signal:", block+"\nsignal:", 1)
	}

	// A drafted spec has to load, or the useful loop is blocked: draft, then
	// immediately probe two versions to see whether the rule discriminates.
	// Checking a version makes no claim about anything.
	if _, err := spec.Parse([]byte(withMode("authoring:\n  mode: ai"))); err != nil {
		t.Errorf("mode: ai without a reviewer was rejected: %v\n"+
			"a drafted spec must be runnable before anyone has reviewed it", err)
	}

	if _, err := spec.Parse([]byte(withMode("authoring:\n  mode: banana"))); err == nil {
		t.Error("an unknown authoring mode was accepted")
	}

	ok := withMode("authoring:\n  mode: ai\n  reviewed_by: nick")
	if _, err := spec.Parse([]byte(ok)); err != nil {
		t.Errorf("a reviewed ai-authored spec was rejected: %v", err)
	}
	if _, err := spec.Parse([]byte(withMode("authoring:\n  mode: manual"))); err != nil {
		t.Errorf("mode: manual was rejected: %v", err)
	}
}

// Publishing is where a model-drafted spec becomes a claim someone receives, so
// that is where a reviewer is required. Loading and checking are not.
func TestRequiresReview(t *testing.T) {
	cases := []struct {
		name string
		in   spec.Authoring
		want bool
	}{
		{"drafted, unreviewed", spec.Authoring{Mode: spec.ModeAI}, true},
		{"drafted, reviewed", spec.Authoring{Mode: spec.ModeAI, ReviewedBy: "nick"}, false},
		{"hand written", spec.Authoring{Mode: spec.ModeManual}, false},
		{"nothing recorded", spec.Authoring{}, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.RequiresReview(); got != c.want {
				t.Errorf("RequiresReview() = %v, want %v", got, c.want)
			}
		})
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

// A rule asks exactly one question. Two match fields would mean the engine
// evaluates one and ignores the other, so a spec whose author expected both to
// hold would silently get a narrower question than they wrote.
func TestValidateRejectsMoreThanOneRuleKind(t *testing.T) {
	src := strings.Replace(minimal,
		"      calls: eval",
		"      calls: eval\n      defaults:\n        Loader: Loader", 1)

	_, err := spec.Parse([]byte(src))
	if err == nil {
		t.Fatal("a rule setting both calls and defaults was accepted")
	}
	if !strings.Contains(err.Error(), "defaults") {
		t.Errorf("error should name the conflicting field, got: %v", err)
	}
}

func TestValidateRejectsRuleWithNoQuestion(t *testing.T) {
	src := strings.Replace(minimal, "      calls: eval\n", "", 1)

	_, err := spec.Parse([]byte(src))
	if err == nil {
		t.Fatal("a rule with no match field was accepted")
	}
	for _, want := range []string{"calls", "defaults"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should list %q as an option, got: %v", want, err)
		}
	}
}

func TestDefaultsRuleParsesAndRenders(t *testing.T) {
	src := strings.Replace(minimal,
		"      calls: eval",
		"      defaults:\n        Loader: Loader", 1)

	s, err := spec.Parse([]byte(src))
	if err != nil {
		t.Fatalf("defaults rule rejected: %v", err)
	}
	if s.Signal.Code.Rule.Kind() != "defaults" {
		t.Errorf("kind = %q, want defaults", s.Signal.Code.Rule.Kind())
	}
	param, value, ok := s.Signal.Code.Rule.Default()
	if !ok || param != "Loader" || value != "Loader" {
		t.Errorf("Default() = (%q, %q, %v)", param, value, ok)
	}
	// The rule string is the only statement of what was asked that reaches an
	// evidence record, so it has to name the kind.
	if got := s.RuleString(); !strings.Contains(got, "defaults") {
		t.Errorf("RuleString() = %q, want it to name the rule kind", got)
	}
}

// A defaults rule with several parameters would be two questions, and the
// engine answers one rule per signal.
func TestValidateRejectsMultipleDefaults(t *testing.T) {
	src := strings.Replace(minimal,
		"      calls: eval",
		"      defaults:\n        Loader: Loader\n        mode: unsafe", 1)

	if _, err := spec.Parse([]byte(src)); err == nil {
		t.Fatal("a defaults rule with two parameters was accepted")
	}
}

func TestValidateRejectsEmptyDefaultValue(t *testing.T) {
	src := strings.Replace(minimal,
		"      calls: eval",
		"      defaults:\n        Loader: \"\"", 1)

	if _, err := spec.Parse([]byte(src)); err == nil {
		t.Fatal("a defaults rule with an empty value was accepted")
	}
}

const multiLocation = `
package:
  ecosystem: PyPI
  name: foo
repo: https://github.com/example/foo
signal:
  code_any:
    - file: src/handler.py
      symbol: proxy
      rule:
        calls: requests.request
    - file: src/validator.py
      symbol: validate
      rule:
        calls: re.fullmatch
`

func TestParseMultipleLocations(t *testing.T) {
	s, err := spec.Parse([]byte(multiLocation))
	if err != nil {
		t.Fatalf("code_any rejected: %v", err)
	}
	locs := s.Signal.Locations()
	if len(locs) != 2 {
		t.Fatalf("locations = %d, want 2", len(locs))
	}
	if locs[0].File != "src/handler.py" || locs[1].File != "src/validator.py" {
		t.Errorf("locations lost their order: %+v", locs)
	}
	// A report has to say the verdict came from several questions.
	if got := s.RuleString(); !strings.Contains(got, "any of 2") {
		t.Errorf("RuleString() = %q, want it to name the location count", got)
	}
}

func TestSingleLocationStillWorks(t *testing.T) {
	s, err := spec.Parse([]byte(minimal))
	if err != nil {
		t.Fatal(err)
	}
	locs := s.Signal.Locations()
	if len(locs) != 1 || locs[0].File != "src/parser.py" {
		t.Errorf("locations = %+v, want the single code block", locs)
	}
	if strings.Contains(s.RuleString(), "any of") {
		t.Errorf("RuleString() = %q, want no location count for one location",
			s.RuleString())
	}
}

func TestValidateRejectsBothCodeAndCodeAny(t *testing.T) {
	src := strings.Replace(minimal, "signal:\n  code:", `signal:
  code_any:
    - file: b.py
      symbol: g
      rule:
        calls: exec
  code:`, 1)

	if _, err := spec.Parse([]byte(src)); err == nil {
		t.Fatal("a signal setting both code and code_any was accepted")
	}
}

// Errors must name which entry failed, or an author with five locations cannot
// tell which one to fix.
func TestValidateNamesTheFailingLocation(t *testing.T) {
	src := strings.Replace(multiLocation, "      symbol: validate\n", "", 1)

	_, err := spec.Parse([]byte(src))
	if err == nil {
		t.Fatal("a location missing its symbol was accepted")
	}
	if !strings.Contains(err.Error(), "code_any[1]") {
		t.Errorf("error should name the failing index, got: %v", err)
	}
}

// Polarity decides how every verdict in a report is read, so locations cannot
// disagree: one of them would mean the opposite of what the report says.
func TestValidateRejectsMixedPolarity(t *testing.T) {
	src := strings.Replace(multiLocation,
		"        calls: re.fullmatch",
		"        calls: re.fullmatch\n        indicates: fixed", 1)

	_, err := spec.Parse([]byte(src))
	if err == nil {
		t.Fatal("locations with disagreeing polarity were accepted")
	}
	if !strings.Contains(err.Error(), "polarity") {
		t.Errorf("error should explain the constraint, got: %v", err)
	}
}

func TestConsistentPolarityAcrossLocationsIsFine(t *testing.T) {
	src := strings.ReplaceAll(multiLocation,
		"      rule:\n", "      rule:\n        indicates: fixed\n")

	s, err := spec.Parse([]byte(src))
	if err != nil {
		t.Fatalf("matching polarity rejected: %v", err)
	}
	if s.MatchMeansVulnerable() {
		t.Error("spec polarity should follow its locations")
	}
}

// A repeated location asks one question twice. It cannot change a verdict, but
// it doubles the work and prints one answer as if two places agreed.
func TestValidateRejectsDuplicateLocations(t *testing.T) {
	const dup = `
package:
  ecosystem: PyPI
  name: foo
repo: https://github.com/example/foo
signal:
  code_any:
    - file: a.py
      symbol: f
      rule: { calls: eval }
    - file: a.py
      symbol: f
      rule: { calls: eval }
`
	if _, err := spec.Parse([]byte(dup)); err == nil {
		t.Error("a repeated location was accepted")
	} else if !strings.Contains(err.Error(), "repeats") {
		t.Errorf("error = %q, want it to name the repetition", err)
	}

	// Same file and symbol asking a different question is not a duplicate: one
	// fix can add a guard and remove a sink in the same function.
	const distinct = `
package:
  ecosystem: PyPI
  name: foo
repo: https://github.com/example/foo
signal:
  code_any:
    - file: a.py
      symbol: f
      rule: { calls: eval }
    - file: a.py
      symbol: f
      rule: { calls: exec }
`
	if _, err := spec.Parse([]byte(distinct)); err != nil {
		t.Errorf("two different rules on one symbol were rejected: %v", err)
	}
}

// Package spec parses taggity.yaml, the portable description of a
// vulnerability that makes a verdict reproducible by someone else.
package spec

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

// Spec describes one vulnerability precisely enough for an independent party to
// re-run the check and get the same answer.
type Spec struct {
	Package   Package   `yaml:"package"`
	Repo      string    `yaml:"repo"`
	Advisory  string    `yaml:"advisory,omitempty"`
	Authoring Authoring `yaml:"authoring,omitempty"`
	Signal    Signal    `yaml:"signal"`
}

// Package identifies the distribution the advisory is about.
type Package struct {
	Ecosystem string `yaml:"ecosystem"`
	Name      string `yaml:"name"`
}

// Authoring records how the spec was produced. The fields exist from the first
// release even though nothing populates the model ones yet: a spec written
// today must not need migrating when model-assisted authoring arrives.
type Authoring struct {
	// Mode is "manual" or "ai".
	Mode string `yaml:"mode,omitempty"`
	// Provider and Model identify the assisting model, when there was one.
	Provider string `yaml:"provider,omitempty"`
	Model    string `yaml:"model,omitempty"`
	// ReviewedBy names the human who approved the spec. A model-drafted spec
	// nobody reviewed is not a spec anyone should act on.
	ReviewedBy string `yaml:"reviewed_by,omitempty"`
}

// Signal groups the evidence sources. Only Code is implemented; the others are
// declared so their absence reads as "not evaluated" rather than "not
// applicable".
type Signal struct {
	Code Code `yaml:"code"`
}

// Code locates the vulnerable construct in source.
type Code struct {
	// File is the repository-relative path, forward slashes on all platforms.
	File string `yaml:"file"`

	// Symbol is the definition to examine. Qualify it as Class.method when a
	// bare name would be ambiguous; an ambiguous name yields Unknown rather
	// than a guess.
	Symbol string `yaml:"symbol"`

	// Rule is the structural question asked of that symbol.
	Rule Rule `yaml:"rule"`

	// Aliases give earlier names for the same construct, so a rename does not
	// read as absence. Each is pinned by a human and evaluated
	// deterministically thereafter.
	//
	// The field is in the schema from the first release so a spec written today
	// needs no migration when model-assisted authoring arrives. NOTHING
	// EVALUATES IT IN v0.1.0, and Validate rejects a non-empty list rather than
	// accepting input the engine would discard: an alias exists precisely to
	// prevent a symbol_not_found UNKNOWN, so ignoring one silently produces the
	// outcome its author wrote it to avoid.
	Aliases []Alias `yaml:"aliases,omitempty"`
}

// Rule is the structural predicate. Exactly one match field may be set.
//
// The vocabulary is deliberately small: every rule kind needs its own
// adversarial fixtures before it can be trusted, and an untested rule kind is
// how soft edges enter the core. Anything outside the vocabulary is Unknown.
type Rule struct {
	// Calls asks whether the symbol calls this function in its own scope.
	// Dotted targets such as pickle.loads are matched exactly; a bare name
	// does not match a dotted call.
	Calls string `yaml:"calls,omitempty"`

	// Defaults asks whether the symbol declares a parameter with a given
	// default value, written as `param: value`.
	//
	// Some fixes change a default rather than a call. PyYAML closed its
	// arbitrary-execution bug by changing load(stream, Loader=Loader) to
	// Loader=None while still calling Loader(stream) either way, which a calls
	// rule cannot distinguish. A parameter with no default never matches.
	Defaults map[string]string `yaml:"defaults,omitempty"`

	// Indicates declares what a match means. Default "vulnerable": the
	// construct is the danger, as with calls: eval.
	//
	// Some fixes add a call rather than removing one, redis-py wrapped its
	// command path in asyncio.shield, and the only honest way to express that
	// with a presence rule is to match the guard and say so. Without this
	// field a report would label a correctly fixed version as a disagreement,
	// because the engine cannot infer polarity from the target's name.
	Indicates string `yaml:"indicates,omitempty"`
}

// Polarity values for Rule.Indicates.
const (
	IndicatesVulnerable = "vulnerable"
	IndicatesFixed      = "fixed"
)

// MatchMeansVulnerable reports whether a positive match should be read as the
// version being affected.
func (r Rule) MatchMeansVulnerable() bool {
	return r.Indicates != IndicatesFixed
}

// Kind names the rule kind this rule asks for.
func (r Rule) Kind() string {
	switch {
	case r.Calls != "":
		return "calls"
	case len(r.Defaults) > 0:
		return "defaults"
	default:
		return ""
	}
}

// validate reports whether the rule asks exactly one answerable question.
//
// Setting two match fields is rejected rather than resolved by precedence. The
// engine would evaluate one and ignore the other, so a spec whose author
// expected both to hold would silently get a narrower question than they wrote.
func (r Rule) validate() error {
	set := 0
	if r.Calls != "" {
		set++
	}
	if len(r.Defaults) > 0 {
		set++
	}

	switch {
	case set == 0:
		return errors.New(
			"signal.code.rule needs one of: calls, defaults")
	case set > 1:
		return errors.New(
			"signal.code.rule sets more than one of calls and defaults; a rule " +
				"asks exactly one question, so split this into separate signals")
	}

	for param, value := range r.Defaults {
		if param == "" || value == "" {
			return fmt.Errorf(
				"signal.code.rule.defaults has an empty parameter or value (%q: %q)",
				param, value)
		}
	}
	if len(r.Defaults) > 1 {
		return errors.New(
			"signal.code.rule.defaults takes one parameter; a rule asks exactly " +
				"one question")
	}
	return nil
}

// Default returns the single parameter and value a defaults rule asks about.
func (r Rule) Default() (param, value string, ok bool) {
	for p, v := range r.Defaults {
		return p, v, true
	}
	return "", "", false
}

// Alias is a previous name for the symbol, restricted to a version range.
type Alias struct {
	Symbol   string `yaml:"symbol"`
	Versions string `yaml:"versions,omitempty"`
	// Source is "human" or "llm"; Confidence and Model apply to the latter.
	Source     string  `yaml:"source,omitempty"`
	Confidence float64 `yaml:"confidence,omitempty"`
	Model      string  `yaml:"model,omitempty"`
	ApprovedBy string  `yaml:"approved_by,omitempty"`
}

// Load reads and validates a spec file.
func Load(path string) (*Spec, error) {
	// #nosec G304 -- the path is the spec the user asked to run; reading an
	// operator-supplied file is what this function is for.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading spec: %w", err)
	}
	return Parse(b)
}

// Parse validates a spec from bytes. Unknown fields are rejected: a typo in a
// rule name must fail loudly rather than silently evaluating nothing.
func Parse(b []byte) (*Spec, error) {
	var s Spec
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&s); err != nil {
		return nil, fmt.Errorf("parsing spec: %w", err)
	}
	if err := s.Validate(); err != nil {
		return nil, err
	}
	return &s, nil
}

// Validate reports whether the spec can be evaluated at all.
func (s *Spec) Validate() error {
	var errs []error
	if s.Repo == "" {
		errs = append(errs, errors.New("repo is required: the engine reads source from git"))
	}
	if s.Package.Name == "" {
		errs = append(errs, errors.New("package.name is required"))
	}
	if s.Signal.Code.File == "" {
		errs = append(errs, errors.New("signal.code.file is required"))
	}
	if s.Signal.Code.Symbol == "" {
		errs = append(errs, errors.New("signal.code.symbol is required"))
	}
	if err := s.Signal.Code.Rule.validate(); err != nil {
		errs = append(errs, err)
	}
	if strings.ContainsRune(s.Signal.Code.File, '\\') {
		errs = append(errs, errors.New("signal.code.file must use forward slashes"))
	}
	// Reserved, not implemented. Accepting this would discard a field the author
	// wrote specifically to prevent an UNKNOWN, and report that UNKNOWN anyway.
	if len(s.Signal.Code.Aliases) > 0 {
		errs = append(errs, errors.New(
			"signal.code.aliases is not evaluated in v0.1.0: the field is reserved "+
				"for model-assisted authoring. Remove it, or qualify "+
				"signal.code.symbol as Class.method instead. A spec whose aliases "+
				"are ignored would report UNKNOWN [symbol_not_found] rather than matching"))
	}
	switch s.Signal.Code.Rule.Indicates {
	case "", IndicatesVulnerable, IndicatesFixed:
	default:
		errs = append(errs, fmt.Errorf(
			"signal.code.rule.indicates is %q, must be %q or %q",
			s.Signal.Code.Rule.Indicates, IndicatesVulnerable, IndicatesFixed))
	}
	return errors.Join(errs...)
}

// RuleString renders the rule for evidence records.
//
// Polarity is part of the rule, not a footnote. The same target means opposite
// things under the two polarities, "calls asyncio.shield" is the danger in one
// spec and the fix in another. This string is the only statement of what
// was asked that reaches an evidence record or an exported OSV document. A
// reader who cannot tell which question was asked cannot reproduce the answer.
func (s *Spec) RuleString() string {
	rule := s.Signal.Code.Rule
	r := "calls: " + rule.Calls
	if param, value, ok := rule.Default(); ok {
		r = "defaults: " + param + "=" + value
	}
	if !rule.MatchMeansVulnerable() {
		return r + " (indicates: fixed)"
	}
	return r
}

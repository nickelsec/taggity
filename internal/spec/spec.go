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

// Mode values for Authoring.Mode.
const (
	ModeManual = "manual"
	ModeAI     = "ai"
)

// validate reports every problem with the authoring block.
func (a Authoring) validate() []error {
	var errs []error
	switch a.Mode {
	case "", ModeManual:
	case ModeAI:
		// The output of this tool is a public claim that a maintainer is wrong.
		// Recording which model drafted a spec and nobody who checked it would
		// put that claim's provenance at "a model said so".
		if a.ReviewedBy == "" {
			errs = append(errs, fmt.Errorf(
				"authoring.reviewed_by is required when mode is %q: a spec no "+
					"human approved is not one to act on", ModeAI))
		}
	default:
		errs = append(errs, fmt.Errorf("authoring.mode is %q, must be %q or %q",
			a.Mode, ModeManual, ModeAI))
	}
	return errs
}

// Signal groups the evidence sources. Only code is implemented; the others are
// declared so their absence reads as "not evaluated" rather than "not
// applicable".
type Signal struct {
	// Code is a single location, for the common case.
	Code Code `yaml:"code,omitempty"`

	// CodeAny holds several locations, and the version is affected if any of
	// them matches. A fix can span files: the sink in one module and the guard
	// added in a validator in another.
	//
	// Only "any" exists. An "all" combinator would let one location's UNKNOWN
	// turn the whole result into NOT_VULNERABLE unless the three-valued
	// conjunction is exactly right, and that is the direction that under-reports.
	// It waits until it has its own adversarial fixtures.
	CodeAny []Code `yaml:"code_any,omitempty"`
}

// Locations returns every code location this signal evaluates, in order.
func (s Signal) Locations() []Code {
	if len(s.CodeAny) > 0 {
		return s.CodeAny
	}
	return []Code{s.Code}
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
	// read as absence. Each is pinned to a version range by a human and
	// evaluated deterministically thereafter: the name decides the verdict, not
	// whatever proposed it.
	//
	// Symbol is tried first and aliases only when it does not resolve, so adding
	// one cannot change a version that already answered.
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
	Symbol string `yaml:"symbol"`

	// Versions bounds where the name applies, half-open as everywhere else:
	// introduced is inclusive, until is exclusive. Both are optional, and an
	// empty range means the alias applies to every version.
	//
	// The bound is a claim about which releases carried the old name, so it is
	// worth stating even when it seems redundant. An unbounded alias will
	// happily match a same-named function in an unrelated era.
	Versions Range `yaml:"versions,omitempty"`

	// Source is "human" or "llm"; Confidence and Model apply to the latter.
	Source     string  `yaml:"source,omitempty"`
	Confidence float64 `yaml:"confidence,omitempty"`
	Model      string  `yaml:"model,omitempty"`
	ApprovedBy string  `yaml:"approved_by,omitempty"`
}

// Source values for Alias.Source.
const (
	SourceHuman = "human"
	SourceLLM   = "llm"
)

// Range is a half-open version range: Introduced <= v < Until.
type Range struct {
	Introduced string `yaml:"introduced,omitempty"`
	Until      string `yaml:"until,omitempty"`
}

// Unbounded reports whether the range covers every version.
func (r Range) Unbounded() bool {
	return r.Introduced == "" && r.Until == ""
}

// validate reports every problem with one alias. field names it for the error.
//
// Version strings are checked for syntax by the caller, which owns the version
// comparator. This package stays a leaf: it parses and validates the document,
// and knows nothing about repositories.
func (a Alias) validate(field string) []error {
	var errs []error
	if a.Symbol == "" {
		errs = append(errs, fmt.Errorf("%s.symbol is required", field))
	}

	switch a.Source {
	case "", SourceHuman:
	case SourceLLM:
		// A model may propose a name; only a human may stand behind one. Without
		// this the provenance fields record who suggested the alias and nobody
		// who checked it, which is the distinction the whole authoring model
		// rests on.
		if a.ApprovedBy == "" {
			errs = append(errs, fmt.Errorf(
				"%s.approved_by is required when source is %q: a model-proposed "+
					"alias nobody approved is not evidence", field, SourceLLM))
		}
	default:
		errs = append(errs, fmt.Errorf("%s.source is %q, must be %q or %q",
			field, a.Source, SourceHuman, SourceLLM))
	}
	return errs
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
	if s.Signal.Code.File != "" && len(s.Signal.CodeAny) > 0 {
		errs = append(errs, errors.New(
			"signal sets both code and code_any; use one or the other"))
	}
	errs = append(errs, s.Authoring.validate()...)
	seen := make(map[string]int)
	for i, loc := range s.Signal.Locations() {
		field := "signal.code"
		if len(s.Signal.CodeAny) > 0 {
			field = fmt.Sprintf("signal.code_any[%d]", i)
		}
		errs = append(errs, loc.validate(field)...)

		// Polarity decides how every verdict in a report is read, so a spec
		// cannot mix directions. Two locations disagreeing would make one of
		// them mean the opposite of what the report says it means.
		if i > 0 && loc.Rule.MatchMeansVulnerable() != s.Signal.CodeAny[0].Rule.MatchMeansVulnerable() {
			errs = append(errs, fmt.Errorf(
				"%s.rule.indicates disagrees with the first location; every "+
					"location in a code_any list must share one polarity", field))
		}

		// A repeated location asks one question twice. It cannot change a
		// verdict, but it doubles the work and prints the same row twice, which
		// reads as corroboration from two places that do not exist.
		key := loc.File + "\x00" + loc.Symbol + "\x00" + loc.Rule.String()
		if prev, ok := seen[key]; ok {
			errs = append(errs, fmt.Errorf(
				"%s repeats signal.code_any[%d]; every location must differ",
				field, prev))
		} else {
			seen[key] = i
		}
	}
	return errors.Join(errs...)
}

// validate reports every problem with one code location. field names the
// location so an error points at the right entry in a code_any list.
func (c Code) validate(field string) []error {
	var errs []error
	if c.File == "" {
		errs = append(errs, fmt.Errorf("%s.file is required", field))
	}
	if c.Symbol == "" {
		errs = append(errs, fmt.Errorf("%s.symbol is required", field))
	}
	if err := c.Rule.validate(); err != nil {
		errs = append(errs, fmt.Errorf("%s.rule: %w", field, err))
	}
	if strings.ContainsRune(c.File, '\\') {
		errs = append(errs, fmt.Errorf("%s.file must use forward slashes", field))
	}
	switch c.Rule.Indicates {
	case "", IndicatesVulnerable, IndicatesFixed:
	default:
		errs = append(errs, fmt.Errorf(
			"%s.rule.indicates is %q, must be %q or %q",
			field, c.Rule.Indicates, IndicatesVulnerable, IndicatesFixed))
	}
	for i, a := range c.Aliases {
		errs = append(errs, a.validate(fmt.Sprintf("%s.aliases[%d]", field, i))...)
	}
	return errs
}

// Primary returns the first code location, which is the one a single-location
// spec describes and the one a report cites when summarising a multi-location
// spec.
func (s *Spec) Primary() Code {
	locs := s.Signal.Locations()
	return locs[0]
}

// MatchMeansVulnerable reports the spec's polarity.
//
// Polarity belongs to the spec rather than to a location: a report reads every
// verdict the same way, so a multi-location spec cannot mix directions. The
// first location decides, and Validate rejects the rest disagreeing.
func (s *Spec) MatchMeansVulnerable() bool {
	return s.Primary().Rule.MatchMeansVulnerable()
}

// RuleString renders the rule for evidence records.
//
// Polarity is part of the rule, not a footnote. The same target means opposite
// things under the two polarities, "calls asyncio.shield" is the danger in one
// spec and the fix in another. This string is the only statement of what
// was asked that reaches an evidence record or an exported OSV document. A
// reader who cannot tell which question was asked cannot reproduce the answer.
func (s *Spec) RuleString() string {
	locs := s.Signal.Locations()
	r := locs[0].Rule.String()
	if len(locs) > 1 {
		// A reader has to know the verdict came from several questions, not one.
		return fmt.Sprintf("any of %d, first: %s", len(locs), r)
	}
	return r
}

// String renders the question a rule asks, including its polarity.
//
// Every evidence record carries this, and it is the only statement of what was
// asked that reaches a reader. The same target means opposite things under the
// two polarities, so a string that omitted it could not be reproduced from.
func (r Rule) String() string {
	q := "calls: " + r.Calls
	if param, value, ok := r.Default(); ok {
		q = "defaults: " + param + "=" + value
	}
	if !r.MatchMeansVulnerable() {
		return q + " (indicates: fixed)"
	}
	return q
}

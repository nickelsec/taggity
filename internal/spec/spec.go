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
	Aliases []Alias `yaml:"aliases,omitempty"`
}

// Rule is the structural predicate. Exactly one field may be set.
//
// The vocabulary is deliberately small: every rule kind needs its own
// adversarial fixtures before it can be trusted, and an untested rule kind is
// how soft edges enter the core. Anything outside the vocabulary is Unknown.
type Rule struct {
	// Calls asks whether the symbol calls this function in its own scope.
	// Dotted targets such as pickle.loads are matched exactly; a bare name
	// does not match a dotted call.
	Calls string `yaml:"calls,omitempty"`
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
	if s.Signal.Code.Rule.Calls == "" {
		errs = append(errs, errors.New(
			"signal.code.rule.calls is required: v0.1.0 supports only the calls rule"))
	}
	if strings.ContainsRune(s.Signal.Code.File, '\\') {
		errs = append(errs, errors.New("signal.code.file must use forward slashes"))
	}
	return errors.Join(errs...)
}

// RuleString renders the rule for evidence records.
func (s *Spec) RuleString() string {
	return "calls: " + s.Signal.Code.Rule.Calls
}

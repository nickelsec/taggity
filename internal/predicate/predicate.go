// Package predicate answers structural questions about source code.
//
// Matching is done on the parse tree rather than on text. An early prototype
// searched the symbol's byte span for the target string and was wrong on three
// of six adversarial cases. It counted `eval(` appearing in a comment, in a
// docstring, and inside a nested function. Those are over-reports, which the
// project tolerates in principle, but an over-report here becomes a public
// claim that a maintainer's advisory is wrong.
package predicate

import (
	ts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"

	"github.com/nickelsec/taggity/internal/taggity"
)

// MatcherName and MatcherVersion are recorded in evidence. A parser upgrade can
// change verdicts, so a verdict is only reproducible alongside the version that
// produced it.
const (
	MatcherName    = "gotreesitter"
	MatcherVersion = "v0.48.1"
)

// Python queries. These are the only language-specific part of this package:
// the walk, the scoping rule, and the verdict logic are all language-neutral.
const (
	qFuncs = `(function_definition name: (identifier) @name) @fn`

	// Methods carry their enclosing class so a spec can disambiguate two
	// same-named definitions.
	qMethods = `(class_definition
  name: (identifier) @class
  body: (block (function_definition name: (identifier) @method) @fn))`

	// Dotted sinks such as pickle.loads have an attribute callee rather than an
	// identifier. Both shapes are captured; Text yields the full dotted name,
	// so a bare target never matches a dotted call.
	qCalls = `
(call function: (identifier) @callee) @call
(call function: (attribute)  @callee) @call
`
)

// Definition is a function or method definition and the bytes it spans.
type Definition struct {
	Name      string // bare name, e.g. parse_untrusted
	Qualified string // Class.method, empty for module-level functions
	Start     uint32
	End       uint32
}

// matches reports whether this definition is the one the spec asked for.
func (d Definition) matches(symbol string) bool {
	if d.Qualified != "" && d.Qualified == symbol {
		return true
	}
	return d.Name == symbol
}

// Result is the outcome of evaluating a rule against one file.
type Result struct {
	Verdict taggity.Verdict
	Reason  taggity.Reason
	// Definition is the matched symbol, when exactly one matched.
	Definition Definition
	// Candidates lists nearby symbol names when the target was not found or
	// was ambiguous, so an Unknown tells the researcher what to do next.
	Candidates []string
}

// Calls reports whether symbol calls target within its own scope.
//
// The only path to NotVulnerable is the final return: the symbol was found and
// no qualifying call exists inside it. Every other outcome is Unknown with a
// reason, because a failure to answer is not evidence of safety.
func Calls(src []byte, symbol, target string) Result {
	lang := grammars.PythonLanguage()
	parser := ts.NewParser(lang)

	tree, err := parser.Parse(src)
	if err != nil {
		return Result{Verdict: taggity.Unknown, Reason: taggity.ReasonParseFailed}
	}
	if tree.RootNode().HasError() {
		return Result{Verdict: taggity.Unknown, Reason: taggity.ReasonParseFailed}
	}

	defs, err := definitions(lang, tree, src)
	if err != nil {
		return Result{Verdict: taggity.Unknown, Reason: taggity.ReasonParseFailed}
	}

	var matched []Definition
	for _, d := range defs {
		if d.matches(symbol) {
			matched = append(matched, d)
		}
	}

	switch len(matched) {
	case 0:
		return Result{
			Verdict:    taggity.Unknown,
			Reason:     taggity.ReasonSymbolNotFound,
			Candidates: names(defs),
		}
	case 1:
		// Unambiguous.
	default:
		// Answering for either definition would answer a question the spec did
		// not ask. The spec must qualify the symbol as Class.method.
		return Result{
			Verdict:    taggity.Unknown,
			Reason:     taggity.ReasonAmbiguousSymbol,
			Candidates: qualifiedNames(matched),
		}
	}
	want := matched[0]

	qc, err := ts.NewQuery(qCalls, lang)
	if err != nil {
		return Result{Verdict: taggity.Unknown, Reason: taggity.ReasonParseFailed}
	}

	for _, m := range qc.Execute(tree) {
		for _, c := range m.Captures {
			if c.Name != "callee" || c.Text(src) != target {
				continue
			}
			pos := c.Node.StartByte()
			if pos < want.Start || pos >= want.End {
				continue
			}
			// A call inside a nested definition belongs to that definition, not
			// to this one. The innermost enclosing definition owns it.
			if owner := innermost(defs, pos); owner != nil && owner.Start == want.Start {
				return Result{Verdict: taggity.Vulnerable, Definition: want}
			}
		}
	}

	// Symbol found, no qualifying call. This is the sole assignment of
	// NotVulnerable in the repository; see internal/taggity/doc.go.
	return Result{Verdict: taggity.NotVulnerable, Definition: want}
}

// definitions collects every function and method definition with its span.
func definitions(lang *ts.Language, tree *ts.Tree, src []byte) ([]Definition, error) {
	qf, err := ts.NewQuery(qFuncs, lang)
	if err != nil {
		return nil, err
	}
	qm, err := ts.NewQuery(qMethods, lang)
	if err != nil {
		return nil, err
	}

	var defs []Definition
	for _, m := range qf.Execute(tree) {
		var d Definition
		for _, c := range m.Captures {
			switch c.Name {
			case "name":
				d.Name = c.Text(src)
			case "fn":
				d.Start, d.End = c.Node.StartByte(), c.Node.EndByte()
			}
		}
		defs = append(defs, d)
	}

	// Attach Class.method qualifiers by matching on start byte.
	qual := make(map[uint32]string)
	for _, m := range qm.Execute(tree) {
		var class, method string
		var start uint32
		for _, c := range m.Captures {
			switch c.Name {
			case "class":
				class = c.Text(src)
			case "method":
				method = c.Text(src)
			case "fn":
				start = c.Node.StartByte()
			}
		}
		if class != "" && method != "" {
			qual[start] = class + "." + method
		}
	}
	for i := range defs {
		if q, ok := qual[defs[i].Start]; ok {
			defs[i].Qualified = q
		}
	}
	return defs, nil
}

// innermost returns the smallest definition containing pos.
//
// This is the scoping rule, and it is language-neutral: it falls out of byte
// spans rather than from knowing which node types introduce a scope, so nested
// functions, lambdas, and async definitions need no special handling.
func innermost(defs []Definition, pos uint32) *Definition {
	var best *Definition
	size := ^uint32(0)
	for i := range defs {
		d := &defs[i]
		if pos >= d.Start && pos < d.End && d.End-d.Start < size {
			best, size = d, d.End-d.Start
		}
	}
	return best
}

func names(defs []Definition) []string {
	out := make([]string, 0, len(defs))
	for _, d := range defs {
		if d.Qualified != "" {
			out = append(out, d.Qualified)
			continue
		}
		out = append(out, d.Name)
	}
	return out
}

func qualifiedNames(defs []Definition) []string {
	out := make([]string, 0, len(defs))
	for _, d := range defs {
		if d.Qualified != "" {
			out = append(out, d.Qualified)
			continue
		}
		out = append(out, d.Name)
	}
	return out
}

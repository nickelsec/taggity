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

	// Only parameters that carry a default produce these nodes. A parameter with
	// no default is a bare identifier or a typed_parameter and never matches,
	// which is what a defaults rule needs: "no default" is not "this default".
	//
	// An annotated parameter is a different node type, and annotated code is
	// common enough that missing it would be a large blind spot.
	qDefaults = `
(default_parameter name: (identifier) @param value: (_) @value)
(typed_default_parameter name: (identifier) @param value: (_) @value)
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
	// MatchedSymbol is the name that resolved. It differs from the spec's
	// symbol when an alias answered, and a verdict reached that way has to say
	// so: the code examined was not the code the spec named.
	MatchedSymbol string
}

// scope is a parsed file narrowed to the single definition a spec named.
type scope struct {
	lang *ts.Language
	tree *ts.Tree
	defs []Definition
	want Definition
	// matched is the name that resolved, which is not the spec's symbol when an
	// alias answered.
	matched string
}

// resolve parses src and locates the one definition the spec asked about.
//
// symbols is tried in order and the first name that resolves wins. The spec's
// own symbol comes first, so an alias can only answer where the real name found
// nothing: adding one cannot change a version that already had an answer.
//
// It returns a Result instead of a scope whenever the question cannot be
// answered, so every rule kind shares the same failure vocabulary and none of
// them can accidentally treat a resolution failure as evidence of absence.
func resolve(src []byte, symbols []string) (scope, *Result) {
	unknown := func(r taggity.Reason, candidates []string) *Result {
		return &Result{Verdict: taggity.Unknown, Reason: r, Candidates: candidates}
	}

	if len(symbols) == 0 {
		return scope{}, unknown(taggity.ReasonSymbolNotFound, nil)
	}

	lang := grammars.PythonLanguage()
	parser := ts.NewParser(lang)

	tree, err := parser.Parse(src)
	if err != nil || tree.RootNode().HasError() {
		return scope{}, unknown(taggity.ReasonParseFailed, nil)
	}

	defs, err := definitions(lang, tree, src)
	if err != nil {
		return scope{}, unknown(taggity.ReasonParseFailed, nil)
	}

	for _, symbol := range symbols {
		var matched []Definition
		for _, d := range defs {
			if d.matches(symbol) {
				matched = append(matched, d)
			}
		}

		switch len(matched) {
		case 0:
			continue
		case 1:
			return scope{
				lang:    lang,
				tree:    tree,
				defs:    defs,
				want:    matched[0],
				matched: symbol,
			}, nil
		default:
			// Ambiguity stops the search rather than falling through to an
			// alias. Two definitions of the requested name is a question the
			// spec has to answer by qualifying it; resolving a different name
			// instead would answer something nobody asked.
			return scope{}, unknown(taggity.ReasonAmbiguousSymbol, qualifiedNames(matched))
		}
	}

	return scope{}, unknown(taggity.ReasonSymbolNotFound, names(defs))
}

// owns reports whether pos belongs to the resolved definition rather than to a
// nested one.
func (s scope) owns(pos uint32) bool {
	if pos < s.want.Start || pos >= s.want.End {
		return false
	}
	owner := innermost(s.defs, pos)
	return owner != nil && owner.Start == s.want.Start
}

// Calls reports whether symbol calls target within its own scope.
//
// NotVulnerable requires the symbol to have been found and no qualifying call
// to exist inside it. Every other outcome is Unknown with a reason, because a
// failure to answer is not evidence of safety.
func Calls(src []byte, symbols []string, target string) Result {
	sc, bad := resolve(src, symbols)
	if bad != nil {
		return *bad
	}

	qc, err := ts.NewQuery(qCalls, sc.lang)
	if err != nil {
		return Result{Verdict: taggity.Unknown, Reason: taggity.ReasonParseFailed}
	}
	tree := sc.tree

	for _, m := range qc.Execute(tree) {
		for _, c := range m.Captures {
			if c.Name != "callee" || c.Text(src) != target {
				continue
			}
			// A call inside a nested definition belongs to that definition, not
			// to this one. The innermost enclosing definition owns it.
			if sc.owns(c.Node.StartByte()) {
				return present(true, sc)
			}
		}
	}

	return present(false, sc)
}

// Defaults reports whether symbol declares parameter with the given default
// value.
//
// This covers fixes that change a default rather than adding or removing a
// call. PyYAML closed its arbitrary-execution bug by changing
// load(stream, Loader=Loader) to load(stream, Loader=None); the call to Loader
// is present either way, so a calls rule cannot tell the versions apart.
//
// A parameter with no default never matches. Once PyYAML made Loader a required
// argument the vulnerable default was gone, and reporting that as a match would
// be wrong in the direction that matters.
func Defaults(src []byte, symbols []string, param, value string) Result {
	sc, bad := resolve(src, symbols)
	if bad != nil {
		return *bad
	}

	qd, err := ts.NewQuery(qDefaults, sc.lang)
	if err != nil {
		return Result{Verdict: taggity.Unknown, Reason: taggity.ReasonParseFailed}
	}

	for _, m := range qd.Execute(sc.tree) {
		var name, val string
		var pos uint32
		var seen bool
		for _, c := range m.Captures {
			switch c.Name {
			case "param":
				name, pos, seen = c.Text(src), c.Node.StartByte(), true
			case "value":
				val = c.Text(src)
			}
		}
		if !seen || name != param || val != value {
			continue
		}
		// Defaults belong to the definition that declares them, so a nested
		// function's parameters never answer for its parent.
		if sc.owns(pos) {
			return present(true, sc)
		}
	}

	return present(false, sc)
}

// present converts a completed structural search into a verdict.
//
// Every rule kind routes its final answer through here. That keeps the sole
// assignment of NotVulnerable in one place, which is the invariant
// internal/taggity/invariant_test.go enforces; see internal/taggity/doc.go.
func present(found bool, sc scope) Result {
	if found {
		return Result{
			Verdict:       taggity.Vulnerable,
			Definition:    sc.want,
			MatchedSymbol: sc.matched,
		}
	}
	return Result{
		Verdict:       taggity.NotVulnerable,
		Definition:    sc.want,
		MatchedSymbol: sc.matched,
	}
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

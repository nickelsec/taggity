package predicate

import (
	"strings"
	"testing"

	ts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// TestGrammarContract fails when the pinned grammar stops matching the queries.
// It runs in the normal suite rather than behind a build tag so that a
// dependency bump is caught by CI.
func TestGrammarContract(t *testing.T) {
	if err := VerifyGrammar(); err != nil {
		t.Fatalf("grammar contract broken: %v\n\n"+
			"The parser dependency was probably upgraded. Do not relax the\n"+
			"expected counts to make this pass: a call query that matches\n"+
			"nothing makes every version report NOT_VULNERABLE.", err)
	}
}

// TestRenamesFailLoudly records what the parser already protects against, so
// that the contract check is scoped to the risk that actually remains.
//
// gotreesitter validates both node types and field names when a query is
// compiled: a renamed node or field is rejected outright rather than silently
// matching nothing. That covers the failure mode this guard was written for.
func TestRenamesFailLoudly(t *testing.T) {
	lang := grammars.PythonLanguage()

	for _, q := range []string{
		`(call_expression function: (identifier) @callee)`, // node renamed
		`(call callee: (identifier) @callee)`,              // field renamed
		`(function_definition label: (identifier) @n)`,     // field renamed
	} {
		if _, err := ts.NewQuery(q, lang); err == nil {
			t.Errorf("query %q compiled against the grammar; a rename that\n"+
				"compiles can match nothing, and zero call matches reads as\n"+
				"NOT_VULNERABLE", q)
		}
	}
}

// TestWrongShapeStillCompiles is the risk the count check exists for.
//
// Compile-time validation catches renames but not a query that is merely
// wrong: dropping the `function:` field still compiles and still matches, but
// it captures every identifier in the call including its arguments. Nothing
// about that fails, and verdicts quietly become wrong.
func TestWrongShapeStillCompiles(t *testing.T) {
	lang := grammars.PythonLanguage()

	// One call, one argument identifier.
	src := []byte("def f():\n    return helper(target)\n")
	parser := ts.NewParser(lang)
	tree, err := parser.Parse(src)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}

	const unfielded = `(call (identifier) @callee)`
	q, err := ts.NewQuery(unfielded, lang)
	if err != nil {
		t.Skipf("grammar rejects the unfielded form: %v", err)
	}

	got := 0
	for _, m := range q.Execute(tree) {
		for _, c := range m.Captures {
			if c.Name == "callee" {
				got++
			}
		}
	}
	if got <= 1 {
		t.Skip("unfielded query does not over-match in this grammar")
	}
	t.Logf("dropping the field captures %d identifiers where one is the callee", got)

	// VerifyGrammar pins the count, so a query of the wrong shape fails.
	if err := VerifyGrammar(); err != nil {
		t.Fatalf("contract should hold for the real queries: %v", err)
	}
}

// TestGrammarProbeIsHonest guards the guard: if the probe stopped containing
// the constructs it claims to, the contract counts would be meaningless.
func TestGrammarProbeIsHonest(t *testing.T) {
	for _, want := range []string{"class C:", "def m(self)", "def f()", "helper(1)", "mod.helper(2)"} {
		if !strings.Contains(grammarProbe, want) {
			t.Errorf("probe no longer contains %q; the expected counts are stale", want)
		}
	}
}

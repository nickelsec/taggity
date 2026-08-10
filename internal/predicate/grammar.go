package predicate

import (
	"errors"
	"fmt"

	ts "github.com/odvcencio/gotreesitter"
	"github.com/odvcencio/gotreesitter/grammars"
)

// grammarProbe is a minimal Python source whose structure is known exactly. It
// exists so the queries can be checked against the grammar rather than merely
// compiled: a query that compiles but matches nothing is the dangerous case.
const grammarProbe = `class C:
    def m(self):
        return helper(1)

def f(stream, Loader=Loader, mode: str = None):
    return mod.helper(2)
`

// Expected match counts for grammarProbe. These are contract values: if the
// grammar changes such that they no longer hold, the queries no longer mean
// what this package assumes.
const (
	probeFuncs    = 2 // C.m and f
	probeMethods  = 1 // C.m
	probeCalls    = 2 // helper(1) and mod.helper(2)
	probeDefaults = 2 // Loader=Loader plus the annotated mode; `stream` has no default
)

// VerifyGrammar checks that the queries still match the grammar shipped with
// the pinned parser.
//
// This guards a failure mode that is otherwise invisible. The queries are
// strings matched against a grammar that lives in a dependency; if an upstream
// node type is renamed, a query silently matches nothing. For the function
// query that degrades safely, because no definitions found means Unknown. For
// the call query it does not: zero calls found is indistinguishable from a
// symbol that makes no such call, so every version would be reported
// NOT_VULNERABLE.
//
// A scanner that confidently reports everything safe is the exact outcome the
// verdict model exists to prevent, so the contract is asserted rather than
// assumed.
func VerifyGrammar() error {
	lang := grammars.PythonLanguage()
	if lang == nil {
		return fmt.Errorf("python grammar unavailable from %s %s",
			MatcherName, MatcherVersion)
	}

	parser := ts.NewParser(lang)
	tree, err := parser.Parse([]byte(grammarProbe))
	if err != nil {
		return fmt.Errorf("parsing grammar probe: %w", err)
	}
	if tree.RootNode().HasError() {
		return errors.New("grammar probe did not parse cleanly")
	}

	checks := []struct {
		name    string
		query   string
		capture string
		want    int
	}{
		{"function definitions", qFuncs, "fn", probeFuncs},
		{"class methods", qMethods, "method", probeMethods},
		{"call sites", qCalls, "callee", probeCalls},
		{"default parameters", qDefaults, "param", probeDefaults},
	}

	for _, c := range checks {
		q, err := ts.NewQuery(c.query, lang)
		if err != nil {
			return fmt.Errorf("%s query does not compile against the grammar: %w",
				c.name, err)
		}
		got := 0
		for _, m := range q.Execute(tree) {
			for _, cap := range m.Captures {
				if cap.Name == c.capture {
					got++
				}
			}
		}
		if got != c.want {
			return fmt.Errorf(
				"%s query matched %d %q captures, expected %d: the grammar has "+
					"changed shape and this query no longer means what the "+
					"predicate assumes",
				c.name, got, c.capture, c.want)
		}
	}
	return nil
}

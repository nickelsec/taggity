package taggity

import (
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// repoRoot walks up from this source file to the module root.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate test source file")
	}
	// internal/taggity/invariant_test.go -> repository root
	return filepath.Clean(filepath.Join(filepath.Dir(self), "..", ".."))
}

// TestNotVulnerableAssignedOnce enforces the invariant documented in doc.go:
// exactly one place in the repository may conclude NotVulnerable.
//
// Absence of the vulnerable construct is the only genuinely negative evidence
// available. Every other failure to answer, no tag, missing file, unresolved
// symbol, ambiguous symbol, parse error, must return Unknown. Collapsing any
// of those into NotVulnerable would under-report, which is the one failure mode
// this project treats as unacceptable.
//
// The check is structural rather than textual: it walks the AST of every
// non-test file and counts expressions that actually evaluate to the
// NotVulnerable constant, so it cannot be fooled by the identifier appearing in
// a comment, a string, or a switch label.
//
// If this test fails, the correct response is almost never to update the
// expected count. It is to route the new path to Unknown with a Reason.
func TestNotVulnerableAssignedOnce(t *testing.T) {
	root := repoRoot(t)

	type site struct {
		file string
		line int
	}
	var sites []site

	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			switch d.Name() {
			case ".git", "testdata", "vendor":
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(path, ".go") || strings.HasSuffix(path, "_test.go") {
			return nil
		}

		fset := token.NewFileSet()
		f, perr := parser.ParseFile(fset, path, nil, 0)
		if perr != nil {
			return perr
		}

		// Track how this file refers to the constant: dot-imported, qualified
		// by package name, or (inside the package itself) bare.
		selfPkg := f.Name.Name == "taggity"
		qualifiers := map[string]bool{}
		for _, imp := range f.Imports {
			if strings.Trim(imp.Path.Value, `"`) != "github.com/nickelsec/taggity/internal/taggity" {
				continue
			}
			switch {
			case imp.Name == nil:
				qualifiers["taggity"] = true
			case imp.Name.Name == ".":
				selfPkg = true
			default:
				qualifiers[imp.Name.Name] = true
			}
		}

		// Case labels read a verdict; they never produce one. Excluding them
		// keeps the budget focused on code that can actually conclude a version
		// is unaffected.
		inCaseLabel := map[ast.Node]bool{}
		ast.Inspect(f, func(n ast.Node) bool {
			cc, ok := n.(*ast.CaseClause)
			if !ok {
				return true
			}
			for _, expr := range cc.List {
				ast.Inspect(expr, func(sub ast.Node) bool {
					inCaseLabel[sub] = true
					return true
				})
			}
			return true
		})

		rel, _ := filepath.Rel(root, path)
		ast.Inspect(f, func(n ast.Node) bool {
			switch e := n.(type) {
			case *ast.SelectorExpr:
				id, ok := e.X.(*ast.Ident)
				if ok && qualifiers[id.Name] && e.Sel.Name == "NotVulnerable" && !inCaseLabel[e] {
					sites = append(sites, site{rel, fset.Position(e.Pos()).Line})
				}
				// Do not descend: X is a package qualifier, not a value.
				return false
			case *ast.Ident:
				if selfPkg && e.Name == "NotVulnerable" && !inCaseLabel[e] {
					sites = append(sites, site{rel, fset.Position(e.Pos()).Line})
				}
			}
			return true
		})
		return nil
	})
	if err != nil {
		t.Fatalf("walking repository: %v", err)
	}

	// Four references in this package are structural rather than conclusions
	// about a version: the constant declaration, its String case, and the two
	// mentions in Signals.Overall. The fifth is the real one, the single
	// assignment in predicate.Calls, reached only when the symbol was found and
	// no qualifying call exists inside it.
	//
	// Raising this number means a second code path can now conclude that a
	// version is unaffected. Do that only with a reason recorded here.
	const allowed = 5

	if len(sites) > allowed {
		t.Errorf("NotVulnerable referenced %d times, expected at most %d.\n"+
			"A new path concluding NotVulnerable removes the only structural\n"+
			"guard against under-reporting. Route it to Unknown with a Reason\n"+
			"instead, or change this budget deliberately and say why.",
			len(sites), allowed)
		for _, s := range sites {
			t.Logf("  %s:%d", s.file, s.line)
		}
	}
}

// TestUnevaluatedIsZeroValue pins the choice of zero value. If Vulnerable or
// NotVulnerable were zero, a partially populated Signals would silently claim
// something about a version that was never examined.
func TestUnevaluatedIsZeroValue(t *testing.T) {
	var v Verdict
	if v != Unevaluated {
		t.Fatalf("zero Verdict is %v, must be Unevaluated", v)
	}
	if got := v.String(); got != "—" {
		t.Errorf("unevaluated renders %q, want the em dash placeholder", got)
	}

	var s Signals
	if got := s.Overall(); got != Unknown {
		t.Errorf("zero Signals overall = %v, want Unknown: a struct nobody\n"+
			"filled in must never read as a verdict", got)
	}
}

// TestOverallNeverInventsSafety checks the collapse rule: only positive
// evidence of absence yields NotVulnerable.
func TestOverallNeverInventsSafety(t *testing.T) {
	cases := []struct {
		name string
		in   Signals
		want Verdict
	}{
		{"nothing evaluated", Signals{}, Unknown},
		{"present found it", Signals{Present: Vulnerable}, Vulnerable},
		{"present proved absence", Signals{Present: NotVulnerable}, NotVulnerable},
		{"present unresolved", Signals{Present: Unknown}, Unknown},
		{
			"unresolved presence, reachable says yes",
			Signals{Present: Unknown, Reachable: Vulnerable},
			Vulnerable,
		},
		{
			"absent code but a PoC fired: trust the PoC and widen",
			Signals{Present: NotVulnerable, Triggers: Vulnerable},
			Vulnerable,
		},
		{
			"unresolved presence with unresolved reachability stays Unknown",
			Signals{Present: Unknown, Reachable: Unknown, Triggers: Unknown},
			Unknown,
		},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.Overall(); got != c.want {
				t.Errorf("Overall() = %v, want %v", got, c.want)
			}
		})
	}
}

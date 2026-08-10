package predicate_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nickelsec/taggity/internal/predicate"
	"github.com/nickelsec/taggity/internal/taggity"
)

// fixture holds Python constructs chosen to defeat a naive matcher. Every case
// here failed, or could plausibly fail, some earlier implementation.
func fixture(t *testing.T) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "fixtures", "python_constructs.py"))
	if err != nil {
		t.Fatalf("reading fixture: %v", err)
	}
	return b
}

func TestCallsAgainstAdversarialConstructs(t *testing.T) {
	src := fixture(t)

	cases := []struct {
		symbol string
		target string
		want   taggity.Verdict
		reason taggity.Reason
		why    string
	}{
		// Text that looks like a call but is not one. A substring matcher was
		// wrong on all three of these.
		{symbol: "comment_only", target: "eval", want: taggity.NotVulnerable,
			why: "eval( appears in a comment"},
		{symbol: "docstring_only", target: "eval", want: taggity.NotVulnerable,
			why: "eval( appears in a docstring"},
		{symbol: "string_literal_only", target: "eval", want: taggity.NotVulnerable,
			why: "eval( appears in a string literal"},

		// Scope. A call inside a nested definition belongs to that definition.
		{symbol: "outer_with_nested", target: "eval", want: taggity.NotVulnerable,
			why: "the call is inside nested_evil, not the outer function"},
		{symbol: "nested_evil", target: "eval", want: taggity.Vulnerable,
			why: "the nested definition really does call it"},
		{symbol: "nested_is_clean", target: "eval", want: taggity.Vulnerable,
			why: "outer calls it directly even though its helper does not"},
		{symbol: "helper", target: "eval", want: taggity.NotVulnerable},

		// Definition forms that are not a plain `def`.
		{symbol: "real_call", target: "eval", want: taggity.Vulnerable},
		{symbol: "async_real_call", target: "eval", want: taggity.Vulnerable,
			why: "async def"},
		{symbol: "decorated_real_call", target: "eval", want: taggity.Vulnerable},
		{symbol: "multiline_decorated", target: "eval", want: taggity.Vulnerable,
			why: "decorator spans several lines"},
		{symbol: "lambda_holder", target: "eval", want: taggity.Vulnerable,
			why: "a lambda body is part of the enclosing definition"},
		{symbol: "continuation", target: "eval", want: taggity.Vulnerable,
			why: "call split across a line continuation"},
		{symbol: "clean_no_eval", target: "eval", want: taggity.NotVulnerable},

		// Attribute calls. os.eval is not eval.
		{symbol: "attribute_call", target: "eval", want: taggity.NotVulnerable,
			why: "os.eval() must not match a bare eval target"},

		// Dotted targets, so that pickle.loads and friends are expressible.
		{symbol: "dotted_sink", target: "pickle.loads", want: taggity.Vulnerable},
		{symbol: "dotted_other", target: "pickle.loads", want: taggity.NotVulnerable,
			why: "json.loads is a different sink"},
		{symbol: "dotted_sink", target: "loads", want: taggity.NotVulnerable,
			why: "a bare target must not match a dotted call, or calls: system " +
				"would match every foo.system() in the tree"},

		// Ambiguity must not be resolved by guessing.
		{symbol: "parse_untrusted", target: "eval", want: taggity.Unknown,
			reason: taggity.ReasonAmbiguousSymbol,
			why:    "Alpha and Beta both define it"},
		{symbol: "Alpha.parse_untrusted", target: "eval", want: taggity.Vulnerable,
			why: "qualified, so unambiguous"},
		{symbol: "Beta.parse_untrusted", target: "eval", want: taggity.NotVulnerable,
			why: "the other definition of the same name is clean"},
		{symbol: "dup_method", target: "eval", want: taggity.Unknown,
			reason: taggity.ReasonAmbiguousSymbol},
		{symbol: "Gamma.dup_method", target: "eval", want: taggity.Vulnerable},
		{symbol: "Delta.dup_method", target: "eval", want: taggity.NotVulnerable},

		{symbol: "no_such_function", target: "eval", want: taggity.Unknown,
			reason: taggity.ReasonSymbolNotFound},

		// Known limitation, pinned so it cannot regress silently: an aliased
		// import produces a bare identifier, which a dotted target misses.
		{symbol: "aliased_import_call", target: "pickle.loads", want: taggity.NotVulnerable,
			why: "KNOWN GAP: from pickle import loads; loads(x)"},

		// Known over-report, also pinned: `eval` rebound to something safe
		// still reads as a call. Detecting this needs dataflow, and the error
		// is in the safe direction.
		{symbol: "shadowed_name", target: "eval", want: taggity.Vulnerable,
			why: "KNOWN OVER-REPORT: eval is locally rebound"},
	}

	for _, c := range cases {
		name := c.symbol + "/" + c.target
		t.Run(name, func(t *testing.T) {
			got := predicate.Calls(src, c.symbol, c.target)
			if got.Verdict != c.want {
				t.Errorf("verdict = %v, want %v (%s)", got.Verdict, c.want, c.why)
			}
			if c.reason != "" && got.Reason != c.reason {
				t.Errorf("reason = %q, want %q", got.Reason, c.reason)
			}
		})
	}
}

// TestUnknownOffersCandidates checks that an unresolved symbol tells the
// researcher what to do next rather than just refusing to answer.
func TestUnknownOffersCandidates(t *testing.T) {
	src := fixture(t)

	res := predicate.Calls(src, "parse_untrusteds", "eval")
	if res.Verdict != taggity.Unknown {
		t.Fatalf("verdict = %v, want Unknown", res.Verdict)
	}
	if len(res.Candidates) == 0 {
		t.Fatal("no candidates offered; an Unknown with no next step is not actionable")
	}

	res = predicate.Calls(src, "parse_untrusted", "eval")
	if res.Reason != taggity.ReasonAmbiguousSymbol {
		t.Fatalf("reason = %q, want ambiguous_symbol", res.Reason)
	}
	if len(res.Candidates) != 2 {
		t.Errorf("candidates = %v, want the two qualified names", res.Candidates)
	}
}

// TestNeverPanicsOnMalformedSource checks that unparseable input degrades to
// Unknown rather than crashing or, worse, reporting absence.
func TestNeverPanicsOnMalformedSource(t *testing.T) {
	for _, src := range []string{
		"", "def broken(:\n", "\x00\x01\x02", "def f():\n\treturn eval(",
	} {
		res := predicate.Calls([]byte(src), "f", "eval")
		if res.Verdict == taggity.NotVulnerable {
			t.Errorf("malformed source %q returned NotVulnerable; "+
				"a parse failure is not evidence of safety", src)
		}
	}
}

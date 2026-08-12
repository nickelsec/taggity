package llm

import (
	"strings"
	"testing"
)

// A model returning prose instead of YAML is the ordinary case, not an edge
// case, and a partial spec is worse than none: it looks like work that was
// done.
func TestParseSpecRejectsAnythingThatIsNotASpec(t *testing.T) {
	cases := map[string]string{
		"empty":          "",
		"prose":          "I looked at the file and the vulnerability is in the request handler.",
		"apology":        "I'm sorry, I don't have enough information to write a spec.",
		"truncated yaml": "package:\n  ecosystem: PyPI\n  name: foo\nrepo: https://x/y\nsignal:\n  code:\n    file:",
		"no signal":      "package:\n  ecosystem: PyPI\n  name: foo\nrepo: https://github.com/x/y\n",
		"rule with no kind": `package:
  ecosystem: PyPI
  name: foo
repo: https://github.com/x/y
signal:
  code:
    file: a.py
    symbol: f
    rule: {}`,
	}

	for name, reply := range cases {
		t.Run(name, func(t *testing.T) {
			sp, err := parseSpec(reply)
			if err == nil {
				t.Fatalf("accepted a reply that is not a spec: %+v", sp)
			}
			if sp != nil {
				t.Error("returned a spec alongside an error; a partial spec " +
					"looks like work that was done")
			}
		})
	}
}

func TestParseSpecAcceptsAValidReply(t *testing.T) {
	const reply = `package:
  ecosystem: PyPI
  name: trytond
repo: https://github.com/tryton/trytond
signal:
  code:
    file: trytond/ir/cron.py
    symbol: Cron._callback
    rule:
      calls: safe_eval
      indicates: vulnerable`

	sp, err := parseSpec(reply)
	if err != nil {
		t.Fatalf("a valid spec was rejected: %v", err)
	}
	if sp.Signal.Code.Symbol != "Cron._callback" {
		t.Errorf("symbol = %q, want Cron._callback", sp.Signal.Code.Symbol)
	}
	if sp.Signal.Code.Rule.Calls != "safe_eval" {
		t.Errorf("rule = %q, want safe_eval", sp.Signal.Code.Rule.Calls)
	}
}

// The instructions say YAML only, and models mostly comply. A code fence is the
// one deviation common enough that failing on it would be pedantry.
func TestParseSpecStripsACodeFence(t *testing.T) {
	const reply = "```yaml\n" + `package:
  ecosystem: PyPI
  name: foo
repo: https://github.com/x/y
signal:
  code:
    file: a.py
    symbol: f
    rule:
      calls: eval` + "\n```"

	sp, err := parseSpec(reply)
	if err != nil {
		t.Fatalf("a fenced spec was rejected: %v", err)
	}
	if sp.Signal.Code.File != "a.py" {
		t.Errorf("file = %q, want a.py", sp.Signal.Code.File)
	}
}

// A failed parse has to show what came back. Debugging a model that started
// apologising is impossible if the reply is swallowed.
func TestParseSpecErrorQuotesTheReply(t *testing.T) {
	_, err := parseSpec("I cannot help with that request.")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "cannot help") {
		t.Errorf("error does not show the reply: %v", err)
	}
}

func TestParseSuggestion(t *testing.T) {
	cases := []struct {
		name       string
		reply      string
		wantFile   string
		wantSymbol string
		wantErr    bool
	}{
		{
			name: "a proposal",
			reply: "WHY: the module was split in 2.0 and this handler moved.\n" +
				"FILE: pycsw/ogc/csw/csw2.py\nSYMBOL: Csw2.getrecords",
			wantFile:   "pycsw/ogc/csw/csw2.py",
			wantSymbol: "Csw2.getrecords",
		},
		{
			// A real answer, not a failure: a version predating the feature has
			// nowhere else to look, and inventing a path wastes a check.
			name:  "nowhere to look",
			reply: "WHY: the OAuth client did not exist until 1.10.\nFILE: -\nSYMBOL: -",
		},
		{
			// Half a proposal cannot be re-checked, so it is dropped entirely
			// rather than probed.
			name:  "file without symbol",
			reply: "WHY: it moved.\nFILE: a/b.py\nSYMBOL: -",
		},
		{
			name:    "no explanation",
			reply:   "FILE: a/b.py\nSYMBOL: f",
			wantErr: true,
		},
		{
			name:    "prose only",
			reply:   "The file seems to have been moved somewhere else.",
			wantErr: true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := parseSuggestion(c.reply)
			if c.wantErr {
				if err == nil {
					t.Fatalf("accepted a reply with no WHY: %+v", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("rejected a usable reply: %v", err)
			}
			if got.File != c.wantFile || got.Symbol != c.wantSymbol {
				t.Errorf("file=%q symbol=%q, want %q and %q",
					got.File, got.Symbol, c.wantFile, c.wantSymbol)
			}
			if got.Explanation == "" {
				t.Error("explanation is empty; it is the point of the call")
			}
		})
	}
}

// The prompt has to teach polarity rather than lean on a default. The corpus is
// close to an even split, nine danger-shaped against seven guard-shaped, so a
// model that always picks one is wrong about half the time.
func TestDraftPromptTeachesBothPolarities(t *testing.T) {
	full := draftSystem + draftExamples

	for _, want := range []string{"indicates: vulnerable", "indicates: fixed"} {
		if !strings.Contains(full, want) {
			t.Errorf("the prompt never shows %q", want)
		}
	}
	if !strings.Contains(full, "defaults:") {
		t.Error("the prompt never shows the defaults rule kind")
	}
	if !strings.Contains(full, "code_any") {
		t.Error("the prompt never shows code_any, so a moved construct " +
			"cannot be expressed")
	}
	// The failure this catches is a rule naming a token identical on both sides
	// of the fix, which matches every version and proves nothing. Matched on
	// single words so that rewrapping the prompt does not break the test.
	for _, want := range []string{"THE FIX CHANGED", "proves nothing", "one side"} {
		if !strings.Contains(full, want) {
			t.Errorf("the prompt does not warn that a rule must name something "+
				"the fix changed: missing %q", want)
		}
	}
}

// The one thing that would break the architecture is a model talking its way
// into a verdict, so the instruction has to be explicit rather than implied.
func TestLocatePromptForbidsAVerdict(t *testing.T) {
	for _, want := range []string{
		"YOU DO NOT DECIDE",
		"Never say vulnerable",
		"narrowing a search",
	} {
		if !strings.Contains(locateSystem, want) {
			t.Errorf("the locate prompt is missing %q", want)
		}
	}
}

// The diff is the strongest signal available: it shows which token changed,
// which no source file alone can show.
func TestDraftPromptHighlightsTheDiff(t *testing.T) {
	got := buildDraftPrompt(DraftRequest{
		Describe: "SSRF in the proxy handler",
		Repo:     "https://github.com/x/y",
		Package:  "foo",
		Diff:     "-  requests.get(url)\n+  validate(url)\n   requests.get(url)",
	})

	if !strings.Contains(got, "THE FIX") {
		t.Error("the diff is not called out as the fix")
	}
	if !strings.Contains(got, "only one side") {
		t.Error("the prompt does not ask for a token on one side of the fix")
	}
	if !strings.Contains(got, "SSRF in the proxy handler") {
		t.Error("the description was dropped")
	}
}

// An empty ecosystem must not reach the model as an empty field.
func TestDraftPromptDefaultsEcosystem(t *testing.T) {
	got := buildDraftPrompt(DraftRequest{Describe: "x", Package: "foo"})
	if !strings.Contains(got, "ecosystem: PyPI") {
		t.Errorf("ecosystem did not default to PyPI:\n%s", got)
	}
}

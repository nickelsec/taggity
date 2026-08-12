package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// multiSpec is a spec naming three locations, the shape a symbol that moved
// between files across a version range needs.
func multiSpec() *spec.Spec {
	sp := &spec.Spec{Repo: "https://github.com/x/y"}
	sp.Package.Ecosystem = "PyPI"
	sp.Package.Name = "foo"
	for _, loc := range []struct{ file, symbol, calls string }{
		{"new/place.py", "build_urls", "urls.append"},
		{"mid/place.py", "Client._discover", "httpx.Request"},
		{"old/place.py", "Client._discover", "httpx.Request"},
	} {
		c := spec.Code{File: loc.file, Symbol: loc.symbol}
		c.Rule.Calls = loc.calls
		sp.Signal.CodeAny = append(sp.Signal.CodeAny, c)
	}
	return sp
}

func render(t *testing.T, sp *spec.Spec, sig taggity.Signals) string {
	t.Helper()
	var buf bytes.Buffer
	printCheck(&buf, sp, "1.19.0", sig, false, false)
	return buf.String()
}

// The bug this guards against shipped in v0.1.0 and surfaced on a real
// advisory: with three locations the summary named the first one regardless of
// which answered, so a VULNERABLE verdict printed the provenance of a file that
// did not exist in the tree that was examined.
func TestCheckOutputNamesTheDecidingLocation(t *testing.T) {
	sig := taggity.Signals{
		Present: taggity.Vulnerable,
		Evidence: []taggity.Evidence{
			{
				File:    "new/place.py",
				Verdict: taggity.Unknown,
				Detail:  "new/place.py not present at v1.19.0",
			},
			{
				File:    "mid/place.py",
				Verdict: taggity.Unknown,
				Detail:  "mid/place.py not present at v1.19.0",
			},
			{
				File:    "old/place.py",
				Symbol:  "Client._discover",
				Verdict: taggity.Vulnerable,
				Commit:  "6c26d087df34aaaa",
				Tag:     "v1.19.0",
				Rule:    "calls: httpx.Request",
				Detail:  "Client._discover calls httpx.Request",
			},
		},
	}

	out := render(t, multiSpec(), sig)

	// The provenance line is the one output that must never be wrong: it is
	// what a maintainer checks first when a correction reaches them.
	if !strings.Contains(out, "at v1.19.0 (6c26d087df3) old/place.py") &&
		!strings.Contains(out, "old/place.py") {
		t.Errorf("provenance did not name the deciding file:\n%s", out)
	}
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "at v1.19.0") {
			if !strings.Contains(line, "old/place.py") {
				t.Errorf("provenance names a file that did not decide: %q", line)
			}
		}
		// The present line carries the verdict; it must not carry another
		// location's failure text alongside it.
		if strings.Contains(line, "present") && strings.Contains(line, "VULNERABLE") {
			if strings.Contains(line, "not present at") {
				t.Errorf("VULNERABLE paired with a failure message: %q", line)
			}
		}
	}

	if !strings.Contains(out, "calls: httpx.Request") {
		t.Errorf("rule line did not name the rule that fired:\n%s", out)
	}
	if !strings.Contains(out, "Client._discover") {
		t.Errorf("symbol line did not name the symbol examined:\n%s", out)
	}
}

// Every location unreadable stays UNKNOWN and must not borrow a verdict.
func TestCheckOutputAllLocationsAbsent(t *testing.T) {
	sig := taggity.Signals{
		Present: taggity.Unknown,
		Reason:  taggity.ReasonFileAbsent,
		Evidence: []taggity.Evidence{
			{File: "new/place.py", Verdict: taggity.Unknown, Detail: "new/place.py not present at v1.19.0"},
			{File: "mid/place.py", Verdict: taggity.Unknown, Detail: "mid/place.py not present at v1.19.0"},
			{File: "old/place.py", Verdict: taggity.Unknown, Detail: "old/place.py not present at v1.19.0"},
		},
	}

	out := render(t, multiSpec(), sig)

	if !strings.Contains(out, "UNKNOWN") {
		t.Errorf("want UNKNOWN when nothing could be read:\n%s", out)
	}
	if strings.Contains(out, "NOT_VULNERABLE") {
		t.Errorf("unreadable locations must never render as safe:\n%s", out)
	}
	// The reason is stated in plain English by default. The code itself is
	// behind --verbose, so this asserts the sentence rather than the constant.
	if !strings.Contains(out, taggity.ReasonFileAbsent.Describe()) {
		t.Errorf("an UNKNOWN must say why:\n%s", out)
	}

	var verbose bytes.Buffer
	printCheck(&verbose, multiSpec(), "1.19.0", sig, false, true)
	if !strings.Contains(verbose.String(), "file_absent") {
		t.Errorf("--verbose must still print the machine-readable code:\n%s",
			verbose.String())
	}
}

// A single-location spec is the common case and its output must not change.
func TestCheckOutputSingleLocationUnchanged(t *testing.T) {
	sp := testSpec("")
	sig := taggity.Signals{
		Present: taggity.Vulnerable,
		Evidence: []taggity.Evidence{{
			File:    "a.py",
			Symbol:  "f",
			Verdict: taggity.Vulnerable,
			Commit:  "abc123def456789",
			Tag:     "v1.0.0",
			Rule:    "calls: eval",
			Detail:  "f calls eval",
		}},
	}

	out := render(t, sp, sig)

	if !strings.Contains(out, "calls: eval in f") {
		t.Errorf("single-location rule line changed shape:\n%s", out)
	}
	// The per-location breakdown is noise when there is only one location.
	if strings.Contains(out, "→ VULNERABLE      a.py") {
		t.Errorf("breakdown block should not render for one location:\n%s", out)
	}
	// The provenance line must carry all three: what was read, at which tag,
	// and at which commit. A correction is checked against exactly those.
	for _, want := range []string{"a.py", "v1.0.0", "abc123def456"} {
		if !strings.Contains(out, want) {
			t.Errorf("provenance line lost %q:\n%s", want, out)
		}
	}
}

// --quiet exists so a loop over versions can read the verdict alone.
func TestCheckQuietPrintsVerdictOnly(t *testing.T) {
	var buf bytes.Buffer
	printCheck(&buf, testSpec(""), "1.0.0", taggity.Signals{Present: taggity.Vulnerable}, true, false)

	if got := strings.TrimSpace(buf.String()); got != "VULNERABLE" {
		t.Errorf("quiet output = %q, want the bare verdict", got)
	}
}

// A spec matching the fix inverts how its verdicts read, and the note saying so
// is the only thing preventing a reader from inverting the meaning.
func TestCheckOutputWarnsOnInvertedPolarity(t *testing.T) {
	sig := taggity.Signals{
		Present:  taggity.Vulnerable,
		Evidence: []taggity.Evidence{{File: "a.py", Symbol: "f", Verdict: taggity.Vulnerable}},
	}

	out := render(t, testSpec("fixed"), sig)
	if !strings.Contains(out, "matches the FIX") {
		t.Errorf("inverted polarity must be stated in the output:\n%s", out)
	}

	plain := render(t, testSpec(""), sig)
	if strings.Contains(plain, "matches the FIX") {
		t.Errorf("a danger-shaped spec must not carry the inversion note:\n%s", plain)
	}
}

// The deciding row is found by position, not by value. Two locations can hold
// equal records, and marking every equal one would claim several places agreed
// when only one was consulted.
func TestCheckOutputMarksExactlyOneRow(t *testing.T) {
	same := taggity.Evidence{
		File:    "a.py",
		Symbol:  "f",
		Verdict: taggity.Vulnerable,
		Rule:    "calls: eval",
		Detail:  "f calls eval",
	}
	sig := taggity.Signals{
		Present:  taggity.Vulnerable,
		Evidence: []taggity.Evidence{same, same},
	}

	out := render(t, multiSpec(), sig)

	marked := 0
	for line := range strings.SplitSeq(out, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "*") {
			marked++
		}
	}
	if marked != 1 {
		t.Errorf("marked %d rows, want exactly 1:\n%s", marked, out)
	}
}

// Only a match is a match. When every location failed to answer, the deciding
// record is the one that reported the failure, and calling it "matched" says
// the opposite of what happened.
func TestCheckOutputDoesNotClaimAMatchWhenNoneMatched(t *testing.T) {
	sig := taggity.Signals{
		Present: taggity.Unknown,
		Reason:  taggity.ReasonFileAbsent,
		Evidence: []taggity.Evidence{
			{File: "a.py", Verdict: taggity.Unknown, Rule: "calls: eval", Detail: "a.py not present at v1.0.0"},
			{File: "b.py", Verdict: taggity.Unknown, Rule: "calls: eval", Detail: "b.py not present at v1.0.0"},
		},
	}

	out := render(t, multiSpec(), sig)
	if strings.Contains(out, "matched:") {
		t.Errorf("output claims a match where nothing matched:\n%s", out)
	}
}

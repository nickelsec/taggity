package check_test

import (
	"strings"
	"testing"

	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// fakeSource stands in for a git repository so the wiring can be tested without
// a network or a working tree.
type fakeSource struct {
	commit string
	tag    string
	// resolveReason and fileReason force the two failure paths.
	resolveReason taggity.Reason
	fileReason    taggity.Reason
	src           string

	// gotCommit and gotPath record what the checker asked for.
	gotCommit string
	gotPath   string
}

func (f *fakeSource) Resolve(string) (string, string, taggity.Reason) {
	if f.resolveReason != taggity.ReasonNone {
		return "", "", f.resolveReason
	}
	return f.commit, f.tag, taggity.ReasonNone
}

func (f *fakeSource) FileAt(commit, path string) ([]byte, taggity.Reason) {
	f.gotCommit, f.gotPath = commit, path
	if f.fileReason != taggity.ReasonNone {
		return nil, f.fileReason
	}
	return []byte(f.src), taggity.ReasonNone
}

func testSpec(file, symbol string) *spec.Spec {
	s := &spec.Spec{Repo: "https://github.com/example/foo"}
	s.Package.Ecosystem = "PyPI"
	s.Package.Name = "foo"
	s.Signal.Code.File = file
	s.Signal.Code.Symbol = symbol
	s.Signal.Code.Rule.Calls = "eval"
	return s
}

const src = `
def safe(data):
    return json.loads(data)

def unsafe(data):
    return eval(data)
`

func TestVersionReportsPresence(t *testing.T) {
	f := &fakeSource{commit: "abc123", tag: "v1.2.3", src: src}
	sig := (&check.Checker{Source: f}).Version(testSpec("a.py", "unsafe"), "1.2.3")

	if sig.Overall() != taggity.Vulnerable {
		t.Fatalf("verdict = %v, want VULNERABLE", sig.Overall())
	}
	if sig.Reason != taggity.ReasonNone {
		t.Errorf("a decided verdict must carry no reason, got %q", sig.Reason)
	}
	if len(sig.Evidence) != 1 {
		t.Fatalf("evidence records = %d, want 1", len(sig.Evidence))
	}

	// Evidence exists so a third party can re-derive the answer. Missing the
	// commit or the matcher version makes that impossible.
	ev := sig.Evidence[0]
	if ev.Commit != "abc123" || ev.Tag != "v1.2.3" {
		t.Errorf("evidence lost the resolution: commit=%q tag=%q", ev.Commit, ev.Tag)
	}
	if ev.Matcher == "" || ev.MatcherVersion == "" {
		t.Error("evidence must name the matcher and its version")
	}
	if ev.EndByte <= ev.StartByte {
		t.Errorf("evidence must span the definition, got [%d,%d)", ev.StartByte, ev.EndByte)
	}
}

func TestVersionReportsAbsence(t *testing.T) {
	f := &fakeSource{commit: "abc123", tag: "v1.2.3", src: src}
	sig := (&check.Checker{Source: f}).Version(testSpec("a.py", "safe"), "1.2.3")

	if sig.Overall() != taggity.NotVulnerable {
		t.Fatalf("verdict = %v, want NOT_VULNERABLE: safe() does not call eval",
			sig.Overall())
	}
}

// Both failure paths must yield Unknown carrying the reason they failed for.
// Neither may look like a version that was examined and found clean.
func TestVersionNeverInventsSafety(t *testing.T) {
	cases := []struct {
		name string
		src  *fakeSource
		want taggity.Reason
	}{
		{
			name: "version does not resolve to a tag",
			src:  &fakeSource{resolveReason: taggity.ReasonNoTag},
			want: taggity.ReasonNoTag,
		},
		{
			name: "file absent at that commit",
			src: &fakeSource{
				commit: "abc123", tag: "v1.2.3",
				fileReason: taggity.ReasonFileAbsent,
			},
			want: taggity.ReasonFileAbsent,
		},
		{
			name: "symbol refactored away",
			src:  &fakeSource{commit: "abc123", tag: "v1.2.3", src: src},
			want: taggity.ReasonSymbolNotFound,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			symbol := "unsafe"
			if c.want == taggity.ReasonSymbolNotFound {
				symbol = "gone"
			}
			sig := (&check.Checker{Source: c.src}).
				Version(testSpec("a.py", symbol), "1.2.3")

			if sig.Overall() != taggity.Unknown {
				t.Fatalf("verdict = %v, want UNKNOWN: an unreadable version is "+
					"not a version found safe", sig.Overall())
			}
			if sig.Reason != c.want {
				t.Errorf("reason = %q, want %q", sig.Reason, c.want)
			}
			if len(sig.Evidence) == 0 {
				t.Error("an UNKNOWN still has to say what was attempted")
			}
		})
	}
}

// An ambiguous symbol answers a different question than the one asked: it
// reports on whichever definition happened to be found first. That must be
// Unknown, and the detail must tell the author how to fix the spec.
func TestVersionRefusesAmbiguousSymbols(t *testing.T) {
	const twoClasses = `
class Alpha:
    def parse(self, data):
        return eval(data)

class Beta:
    def parse(self, data):
        return json.loads(data)
`
	f := &fakeSource{commit: "abc123", tag: "v1.2.3", src: twoClasses}
	sig := (&check.Checker{Source: f}).Version(testSpec("a.py", "parse"), "1.2.3")

	if sig.Overall() != taggity.Unknown {
		t.Fatalf("verdict = %v, want UNKNOWN for a name defined twice", sig.Overall())
	}
	if sig.Reason != taggity.ReasonAmbiguousSymbol {
		t.Errorf("reason = %q, want %q", sig.Reason, taggity.ReasonAmbiguousSymbol)
	}
	if d := sig.Evidence[0].Detail; !strings.Contains(d, "Class.method") {
		t.Errorf("detail should tell the author how to disambiguate, got %q", d)
	}
}

// The checker must read the path the spec names at the commit the source
// resolved. Passing the version string, or a path from somewhere else, would
// silently examine the wrong bytes.
func TestVersionReadsTheResolvedCommit(t *testing.T) {
	f := &fakeSource{commit: "deadbeef", tag: "v9.9.9", src: src}
	(&check.Checker{Source: f}).Version(testSpec("pkg/mod.py", "unsafe"), "9.9.9")

	if f.gotCommit != "deadbeef" {
		t.Errorf("read at commit %q, want the resolved commit", f.gotCommit)
	}
	if f.gotPath != "pkg/mod.py" {
		t.Errorf("read path %q, want the spec's file", f.gotPath)
	}
}

// Polarity belongs to the spec, not the engine. The checker reports what is in
// the file either way; only the rule string records which question was asked.
// If the verdict itself flipped here, audit.classify would invert it a second
// time and mislabel every version.
func TestVersionIgnoresPolarity(t *testing.T) {
	f := &fakeSource{commit: "abc123", tag: "v1.2.3", src: src}

	danger := testSpec("a.py", "unsafe")
	guard := testSpec("a.py", "unsafe")
	guard.Signal.Code.Rule.Indicates = spec.IndicatesFixed

	a := (&check.Checker{Source: f}).Version(danger, "1.2.3")
	b := (&check.Checker{Source: f}).Version(guard, "1.2.3")

	if a.Overall() != b.Overall() {
		t.Errorf("polarity changed the verdict (%v vs %v); it must only change "+
			"how the verdict is read", a.Overall(), b.Overall())
	}
	if a.Evidence[0].Rule == b.Evidence[0].Rule {
		t.Error("evidence must record which polarity was asked")
	}
}

func TestNewRequiresAResolvableRepository(t *testing.T) {
	_, err := check.New("not-a-github-url")
	if err == nil {
		t.Fatal("a checker was built without a repository")
	}
	if !strings.Contains(err.Error(), "repository is required") {
		t.Errorf("error should state the precondition, got: %v", err)
	}
}

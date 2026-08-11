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

// multiSpec builds a spec with several code locations under `any`.
func multiSpec(locs ...spec.Code) *spec.Spec {
	s := &spec.Spec{Repo: "https://github.com/example/foo"}
	s.Package.Ecosystem = "PyPI"
	s.Package.Name = "foo"
	s.Signal.CodeAny = locs
	return s
}

func loc(file, symbol string) spec.Code {
	var c spec.Code
	c.File = file
	c.Symbol = symbol
	c.Rule.Calls = "eval"
	return c
}

// multiSource serves different bytes per path, so a spec can span files.
type multiSource struct {
	files map[string]string
	// missing paths report file_absent rather than empty contents.
	asked []string
}

func (m *multiSource) Resolve(string) (string, string, taggity.Reason) {
	return "abc123", "v1.2.3", taggity.ReasonNone
}

func (m *multiSource) FileAt(_, path string) ([]byte, taggity.Reason) {
	m.asked = append(m.asked, path)
	body, ok := m.files[path]
	if !ok {
		return nil, taggity.ReasonFileAbsent
	}
	return []byte(body), taggity.ReasonNone
}

const clean = "def safe(data):\n    return json.loads(data)\n"
const dirty = "def unsafe(data):\n    return eval(data)\n"

// A fix can span files: the sink in one module, the guard in another. Under
// `any` the construct is present if it is found anywhere.
func TestVersionAnyMatchesInEitherFile(t *testing.T) {
	src := &multiSource{files: map[string]string{"a.py": clean, "b.py": dirty}}
	sig := (&check.Checker{Source: src}).Version(
		multiSpec(loc("a.py", "safe"), loc("b.py", "unsafe")), "1.2.3")

	if sig.Overall() != taggity.Vulnerable {
		t.Fatalf("verdict = %v, want VULNERABLE: the construct is in the second file",
			sig.Overall())
	}
	if len(sig.Evidence) != 2 {
		t.Errorf("evidence records = %d, want one per location", len(sig.Evidence))
	}
	// Both locations must be readable from the evidence, or a reader cannot
	// re-derive which one matched.
	if sig.Evidence[0].File != "a.py" || sig.Evidence[1].File != "b.py" {
		t.Errorf("evidence lost the locations: %q, %q",
			sig.Evidence[0].File, sig.Evidence[1].File)
	}
}

func TestVersionAnyReportsAbsenceOnlyWhenAllAreClean(t *testing.T) {
	src := &multiSource{files: map[string]string{"a.py": clean, "b.py": clean}}
	sig := (&check.Checker{Source: src}).Version(
		multiSpec(loc("a.py", "safe"), loc("b.py", "safe")), "1.2.3")

	if sig.Overall() != taggity.NotVulnerable {
		t.Fatalf("verdict = %v, want NOT_VULNERABLE: every location was read and "+
			"none matched", sig.Overall())
	}
}

// The combinator's dangerous case. An UNKNOWN means a location was never really
// examined, so with no match anywhere the answer cannot be NOT_VULNERABLE: that
// would report safety the engine did not establish.
func TestVersionAnyUnknownDoesNotBecomeSafe(t *testing.T) {
	cases := []struct {
		name  string
		files map[string]string
		locs  []spec.Code
		want  taggity.Reason
	}{
		{
			name:  "one file missing",
			files: map[string]string{"a.py": clean},
			locs:  []spec.Code{loc("a.py", "safe"), loc("b.py", "unsafe")},
			want:  taggity.ReasonFileAbsent,
		},
		{
			name:  "one symbol refactored away",
			files: map[string]string{"a.py": clean, "b.py": clean},
			locs:  []spec.Code{loc("a.py", "safe"), loc("b.py", "gone")},
			want:  taggity.ReasonSymbolNotFound,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := &multiSource{files: c.files}
			sig := (&check.Checker{Source: src}).Version(multiSpec(c.locs...), "1.2.3")

			if sig.Overall() != taggity.Unknown {
				t.Fatalf("verdict = %v, want UNKNOWN: a location that could not be "+
					"read is not a location found clean", sig.Overall())
			}
			if sig.Reason != c.want {
				t.Errorf("reason = %q, want %q", sig.Reason, c.want)
			}
		})
	}
}

// A match anywhere is decisive, so one location's UNKNOWN must not suppress
// another's VULNERABLE. Suppressing it would narrow the reported range, which
// is the direction that leaves someone unwarned.
func TestVersionAnyMatchBeatsUnknown(t *testing.T) {
	src := &multiSource{files: map[string]string{"b.py": dirty}}
	sig := (&check.Checker{Source: src}).Version(
		multiSpec(loc("missing.py", "whatever"), loc("b.py", "unsafe")), "1.2.3")

	if sig.Overall() != taggity.Vulnerable {
		t.Fatalf("verdict = %v, want VULNERABLE: an unreadable location cannot "+
			"cancel a construct that was found", sig.Overall())
	}
	if sig.Reason != taggity.ReasonNone {
		t.Errorf("reason = %q, want none: the verdict was decided", sig.Reason)
	}
}

// A single-location spec keeps working unchanged, and reads exactly one file.
func TestVersionSingleLocationIsUnchanged(t *testing.T) {
	src := &multiSource{files: map[string]string{"a.py": dirty}}
	s := testSpec("a.py", "unsafe")

	sig := (&check.Checker{Source: src}).Version(s, "1.2.3")
	if sig.Overall() != taggity.Vulnerable {
		t.Fatalf("verdict = %v, want VULNERABLE", sig.Overall())
	}
	if len(src.asked) != 1 || src.asked[0] != "a.py" {
		t.Errorf("read %v, want exactly the spec's one file", src.asked)
	}
}

// A missing symbol is either a typo in the spec or a version that genuinely
// lacks the code. The message has to separate those: the first is fixed by
// editing one line, the second is a real finding about the version.
func TestSymbolNotFoundSuggestsACorrection(t *testing.T) {
	// Long structured names are the realistic case and the one the prefix and
	// suffix matching is tuned for.
	const file = `
def build_resource_descriptor_cache_keys(config, registry):
    return []

def read_configuration_defaults(path):
    return None
`
	cases := []struct {
		name    string
		symbol  string
		want    string
		notWant string
	}{
		{
			name:   "a trailing typo names the real symbol",
			symbol: "build_resource_descriptor_cache_key",
			want:   "did you mean build_resource_descriptor_cache_keys",
		},
		{
			name:    "an unrelated symbol gets no guess",
			symbol:  "RegistryClient._fetch_manifest",
			notWant: "did you mean",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			src := &fakeSource{commit: "abc123", tag: "v1.0.0", src: file}
			sig := (&check.Checker{Source: src}).Version(testSpec("a.py", c.symbol), "1.0.0")

			if sig.Overall() != taggity.Unknown {
				t.Fatalf("verdict = %v, want UNKNOWN", sig.Overall())
			}
			got := sig.Deciding().Detail
			if c.want != "" && !strings.Contains(got, c.want) {
				t.Errorf("detail = %q, want it to contain %q", got, c.want)
			}
			if c.notWant != "" && strings.Contains(got, c.notWant) {
				t.Errorf("detail = %q, must not guess: a wrong suggestion sends\n"+
					"the reader to fix a spec that was already correct", got)
			}
		})
	}
}

// aliasSpec names a symbol with one alias pinned to versions below until.
func aliasSpec(symbol, alias, until string) *spec.Spec {
	s := testSpec("a.py", symbol)
	s.Signal.Code.Aliases = []spec.Alias{{
		Symbol:   alias,
		Versions: spec.Range{Until: until},
		Source:   spec.SourceHuman,
	}}
	return s
}

// The case aliases exist for: a guard renamed at some release, where the old
// name has to answer for versions below it.
func TestAliasResolvesARenamedSymbol(t *testing.T) {
	const old = `
def _validate_ks_template_path(path):
    return eval(path)
`
	const renamed = `
def _validate_autoinstall_template_path(path):
    return eval(path)
`
	s := aliasSpec("_validate_autoinstall_template_path",
		"_validate_ks_template_path", "3.3.7")

	// Below the rename the alias answers.
	src := &fakeSource{commit: "abc", tag: "v2.1.0", src: old}
	sig := (&check.Checker{Source: src}).Version(s, "2.1.0")
	if sig.Overall() != taggity.Vulnerable {
		t.Fatalf("verdict = %v, want VULNERABLE via the alias", sig.Overall())
	}

	// A verdict reached through an alias has to be visibly different from one
	// reached directly, or the provenance overstates what was checked.
	ev := sig.Deciding()
	if ev.Source != "alias" {
		t.Errorf("Source = %q, want \"alias\"", ev.Source)
	}
	if ev.Symbol != "_validate_ks_template_path" {
		t.Errorf("Symbol = %q, want the name that actually resolved", ev.Symbol)
	}
	if !strings.Contains(ev.Detail, "alias for") {
		t.Errorf("detail = %q, want it to say an alias answered", ev.Detail)
	}

	// At and above the rename the real name answers and nothing says alias.
	src = &fakeSource{commit: "def", tag: "v3.3.7", src: renamed}
	sig = (&check.Checker{Source: src}).Version(s, "3.3.7")
	if sig.Overall() != taggity.Vulnerable {
		t.Fatalf("verdict = %v, want VULNERABLE via the real name", sig.Overall())
	}
	if ev := sig.Deciding(); ev.Source != "static" {
		t.Errorf("Source = %q, want \"static\": the spec's own symbol resolved", ev.Source)
	}
}

// An alias out of range must not answer. Applying a rename to releases it was
// never pinned to is how an alias stops fixing a missing symbol and starts
// matching unrelated code.
func TestAliasOutsideItsRangeIsNotUsed(t *testing.T) {
	const old = `
def old_name(data):
    return eval(data)
`
	s := aliasSpec("new_name", "old_name", "2.0.0")
	src := &fakeSource{commit: "abc", tag: "v3.0.0", src: old}

	sig := (&check.Checker{Source: src}).Version(s, "3.0.0")
	if sig.Overall() != taggity.Unknown {
		t.Errorf("verdict = %v, want UNKNOWN: the alias does not cover 3.0.0 "+
			"and the real name is absent", sig.Overall())
	}
	if sig.Overall() == taggity.NotVulnerable {
		t.Error("an out-of-range alias must never produce NOT_VULNERABLE")
	}
}

// An alias that resolves nothing leaves the answer UNKNOWN. Adding a name that
// is not there cannot turn a gap into evidence of safety.
func TestAliasThatResolvesNothingStaysUnknown(t *testing.T) {
	const unrelated = `
def something_else(data):
    return data
`
	s := aliasSpec("new_name", "old_name", "9.0.0")
	src := &fakeSource{commit: "abc", tag: "v1.0.0", src: unrelated}

	sig := (&check.Checker{Source: src}).Version(s, "1.0.0")
	if sig.Overall() != taggity.Unknown {
		t.Errorf("verdict = %v, want UNKNOWN", sig.Overall())
	}
	if sig.Reason != taggity.ReasonSymbolNotFound {
		t.Errorf("reason = %q, want symbol_not_found", sig.Reason)
	}
}

// The spec's own symbol is tried first, so adding an alias cannot change a
// version that already had an answer. Both names exist here and the real one
// must win.
func TestSpecSymbolWinsOverAnAlias(t *testing.T) {
	const both = `
def old_name(data):
    return eval(data)

def new_name(data):
    return json.loads(data)
`
	s := aliasSpec("new_name", "old_name", "9.0.0")
	src := &fakeSource{commit: "abc", tag: "v1.0.0", src: both}

	sig := (&check.Checker{Source: src}).Version(s, "1.0.0")
	if sig.Overall() != taggity.NotVulnerable {
		t.Fatalf("verdict = %v, want NOT_VULNERABLE: new_name resolved and does "+
			"not call eval, so the alias must never have been consulted",
			sig.Overall())
	}
	if ev := sig.Deciding(); ev.Source != "static" {
		t.Errorf("Source = %q, want \"static\"", ev.Source)
	}
}

// A version that does not parse cannot be placed in any range, so a bounded
// alias must not apply to it.
func TestAliasIsNotUsedForAnUnparseableVersion(t *testing.T) {
	const old = `
def old_name(data):
    return eval(data)
`
	s := aliasSpec("new_name", "old_name", "2.0.0")
	src := &fakeSource{commit: "abc", tag: "nightly", src: old}

	sig := (&check.Checker{Source: src}).Version(s, "nightly")
	if sig.Overall() == taggity.Vulnerable {
		t.Error("a bounded alias answered for a version that cannot be placed " +
			"in its range")
	}
}

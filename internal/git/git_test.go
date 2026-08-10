package git

import "testing"

func TestNormalizeRepoURL(t *testing.T) {
	cases := []struct{ in, want string }{
		// Real declared PyPI URLs, none of these are clone targets as-is.
		{"https://github.com/psf/requests", "https://github.com/psf/requests"},
		{"https://github.com/pallets/flask/", "https://github.com/pallets/flask"},
		{"https://github.com/yaml/pyyaml/issues", "https://github.com/yaml/pyyaml"},
		{"https://github.com/python-pillow/Pillow/releases", "https://github.com/python-pillow/Pillow"},
		{"https://github.com/urllib3/urllib3/blob/main/CHANGES.rst", "https://github.com/urllib3/urllib3"},
		{"https://github.com/sqlalchemy/sqlalchemy.git", "https://github.com/sqlalchemy/sqlalchemy"},
		{"http://github.com/pyca/cryptography", "https://github.com/pyca/cryptography"},
	}
	for _, c := range cases {
		got, err := NormalizeRepoURL(c.in)
		if err != nil {
			t.Errorf("%s: unexpected error %v", c.in, err)
			continue
		}
		if got != c.want {
			t.Errorf("%s\n got %s\nwant %s", c.in, got, c.want)
		}
	}
	if _, err := NormalizeRepoURL("https://gitlab.com/foo/bar"); err == nil {
		t.Error("expected error for non-github URL")
	}
}

func TestStripTagPrefixAndParse(t *testing.T) {
	// Left column is a real tag spelling observed in these repos.
	cases := []struct {
		tag     string
		wantKey string
		ok      bool
	}{
		{"v2.34.2", "0!2.34.2", true},     // requests
		{"3.1.3", "0!3.1.3", true},        // flask
		{"v2.0.5", "0!2.0.5", true},       // urllib3 (old style)
		{"2.7.0", "0!2.7", true},          // urllib3 (new style)
		{"rel_2_0_51", "0!2.0.51", true},  // sqlalchemy
		{"rel_2_1_0b3", "0!2.1-b3", true}, // sqlalchemy prerelease
		{"6.0.2rc1", "0!6.0.2-rc1", true}, // pyyaml prerelease
		{"v2.34.0.dev1", "0!2.34.dev1", true},
		{"release-1.2.3", "0!1.2.3", true},
		{"dec-11", "", false}, // pyyaml junk tag
		{"nightly", "", false},
		{"", "", false},
	}
	for _, c := range cases {
		v, ok := ParseVersion(stripTagPrefix(c.tag))
		if ok != c.ok {
			t.Errorf("%q: parsed=%v want=%v", c.tag, ok, c.ok)
			continue
		}
		if ok && v.Key() != c.wantKey {
			t.Errorf("%q: key=%s want=%s", c.tag, v.Key(), c.wantKey)
		}
	}
}

// The whole point of backward matching: a PyPI version string and the repo's
// own tag spelling must land on the same key.
func TestVersionMatchesTagSpelling(t *testing.T) {
	cases := []struct{ pypiVersion, tag string }{
		{"2.34.2", "v2.34.2"},
		{"3.1.3", "3.1.3"},
		{"2.0.5", "v2.0.5"},
		{"2.7.0", "2.7.0"},
		{"2.0.51", "rel_2_0_51"}, // sqlalchemy: forward guessing fails here
		{"6.0.2rc1", "6.0.2rc1"},
		{"2.0", "2.0.0"}, // trailing-zero equivalence
	}
	for _, c := range cases {
		pv, ok1 := ParseVersion(c.pypiVersion)
		tv, ok2 := ParseVersion(stripTagPrefix(c.tag))
		if !ok1 || !ok2 {
			t.Errorf("%s / %s: parse failed", c.pypiVersion, c.tag)
			continue
		}
		if pv.Key() != tv.Key() {
			t.Errorf("%s vs tag %s: keys differ (%s != %s)",
				c.pypiVersion, c.tag, pv.Key(), tv.Key())
		}
	}
}

func TestVersionOrdering(t *testing.T) {
	// String comparison gets these wrong; PEP 440 must not.
	cases := []struct {
		a, b string
		want int
	}{
		{"1.9.9", "1.9.10", -1}, // the classic string-compare trap
		{"2.0.0", "2.0.1", -1},
		{"1.0", "1.0.0", 0},
		{"2.1.0b3", "2.1.0", -1}, // prerelease < release
		{"2.1.0", "2.1.0.post1", -1},
		{"1.0.dev1", "1.0", -1},
		{"10.0.0", "9.0.0", 1},
	}
	for _, c := range cases {
		a, _ := ParseVersion(c.a)
		b, _ := ParseVersion(c.b)
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s: got %d want %d", c.a, c.b, got, c.want)
		}
	}
}

func TestPrereleaseDetection(t *testing.T) {
	for _, s := range []string{"2.1.0b3", "6.0.2rc1", "1.0.dev1", "2.34.0.dev1"} {
		if v, _ := ParseVersion(s); !v.IsPrerelease() {
			t.Errorf("%s should be prerelease", s)
		}
	}
	for _, s := range []string{"2.1.0", "1.0", "2.0.51"} {
		if v, _ := ParseVersion(s); v.IsPrerelease() {
			t.Errorf("%s should NOT be prerelease", s)
		}
	}
}

// Pre-release numbers compare numerically, not as text.
//
// These failed before splitPre existed: "rc10" sorts before "rc9" as a string,
// which puts a release candidate ahead of the one it supersedes. Advisory
// claims are routinely written against a pre-release, so this reaches boundary
// selection through the version below an introduced version.
func TestPrereleaseNumbersCompareNumerically(t *testing.T) {
	cases := []struct {
		a, b string
		want int
	}{
		{"1.0.0rc9", "1.0.0rc10", -1},
		{"1.0.0b2", "1.0.0b10", -1},
		{"1.0.0a9", "1.0.0a10", -1},
		{"3.0.0rc0", "3.0.0rc1", -1},       // MLflow claims introduced: 3.0.0rc0
		{"13.0.0.0rc1", "13.0.0.0rc9", -1}, // vitrage, four release components
		{"1.0.0rc10", "1.0.0rc10", 0},

		// Kind dominates number: every b comes after every a.
		{"1.0.0a1", "1.0.0b1", -1},
		{"1.0.0b1", "1.0.0rc1", -1},
		{"1.0.0rc9", "1.0.0b10", 1},

		// Spellings that normalise to the same kind must order together.
		{"1.0.0alpha1", "1.0.0b1", -1},
		{"1.0.0c1", "1.0.0rc1", 0},
		{"1.0.0pre1", "1.0.0rc1", 0},
		{"1.0.0preview1", "1.0.0rc1", 0},
	}
	for _, c := range cases {
		a, aok := ParseVersion(c.a)
		b, bok := ParseVersion(c.b)
		if !aok || !bok {
			t.Fatalf("test setup: %s or %s does not parse", c.a, c.b)
		}
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s: got %d want %d", c.a, c.b, got, c.want)
		}
	}
}

// Compare is handed to sort.Slice in two places. An inconsistent comparator
// there produces a silently wrong order rather than an error, so the relation
// itself is checked rather than only a list of pairs.
func TestCompareIsATotalOrder(t *testing.T) {
	raw := []string{
		"1!1.0", "1!2.0", "0.9", "1.0", "1.0.0", "1.0.1", "1.0.0a1", "1.0.0b1",
		"1.0.0b10", "1.0.0rc1", "1.0.0rc9", "1.0.0rc10", "1.0.dev1", "1.0.dev2",
		"1.0.post1", "1.0.post1.dev1", "2.0", "10.0", "9.0",
	}
	versions := make([]Version, 0, len(raw))
	for _, s := range raw {
		v, ok := ParseVersion(s)
		if !ok {
			t.Fatalf("test setup: %s does not parse", s)
		}
		versions = append(versions, v)
	}

	for _, a := range versions {
		for _, b := range versions {
			if a.Compare(b) != -b.Compare(a) {
				t.Errorf("not antisymmetric: %s vs %s", a.Original, b.Original)
			}
		}
	}
	for _, a := range versions {
		for _, b := range versions {
			for _, c := range versions {
				if a.Compare(b) <= 0 && b.Compare(c) <= 0 && a.Compare(c) > 0 {
					t.Errorf("not transitive: %s <= %s <= %s but %s > %s",
						a.Original, b.Original, c.Original, a.Original, c.Original)
				}
			}
		}
	}
}

// An epoch outranks the release entirely, which is what it exists for.
func TestEpochOrdering(t *testing.T) {
	for _, c := range []struct {
		a, b string
		want int
	}{
		{"1!1.0", "2.0", 1},
		{"1!1.0", "1!2.0", -1},
		{"0!1.0", "1.0", 0},
	} {
		a, _ := ParseVersion(c.a)
		b, _ := ParseVersion(c.b)
		if got := a.Compare(b); got != c.want {
			t.Errorf("%s vs %s: got %d want %d", c.a, c.b, got, c.want)
		}
	}
}

// A bare "v" prefixes a version only when a digit follows it. Stripping it
// unconditionally truncated tags like "version-1.2.3" to "ersion-1.2.3", which
// then failed to parse, so a tag that was present resolved as no_tag.
func TestStripTagPrefixKeepsWordsBeginningWithV(t *testing.T) {
	for _, s := range []string{"version-1.2.3", "valid-1.2.3", "varnish-1.0"} {
		if got := stripTagPrefix(s); got != s {
			t.Errorf("stripTagPrefix(%q) = %q, want it unchanged", s, got)
		}
	}
	// Real version prefixes still come off.
	for _, c := range []struct{ in, want string }{
		{"v2.34.2", "2.34.2"},
		{"V2.0", "2.0"},
		{"v.1.2", "1.2"},
		{"release-1.0", "1.0"},
		{"rel_2_0_51", "2.0.51"},
	} {
		if got := stripTagPrefix(c.in); got != c.want {
			t.Errorf("stripTagPrefix(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

// Duplicate spellings of one version are resolved by rule, not by whichever
// the tag walk reached first.
//
// Byte order alone picks "release-2.0.5" over "v2.0.5" because 'r' sorts before
// 'v', which is arbitrary. The name lands in evidence, and a reader checking a
// verdict by hand is best served by the plainest spelling.
func TestPlainerTag(t *testing.T) {
	cases := []struct {
		a, b string
		want bool
		why  string
	}{
		{"2.0.5", "v2.0.5", true, "no prefix beats a v prefix"},
		{"v2.0.5", "release-2.0.5", true, "the shorter prefix wins"},
		{"release-2.0.5", "v2.0.5", false, "byte order alone would pick this one"},
		{"rel_2_0_5", "release-2.0.5", true, "shorter wins on equal-ish spellings"},
		// Equal lengths still have to settle deterministically, since the tag
		// walk does not guarantee an order.
		{"a1.0.0", "b1.0.0", true, "equal length falls back to byte order"},
		{"b1.0.0", "a1.0.0", false, "and is antisymmetric"},
	}
	for _, c := range cases {
		if got := plainerTag(c.a, c.b); got != c.want {
			t.Errorf("plainerTag(%q, %q) = %v, want %v: %s", c.a, c.b, got, c.want, c.why)
		}
	}
}

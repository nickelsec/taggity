package git

import "testing"

func TestNormalizeRepoURL(t *testing.T) {
	cases := []struct{ in, want string }{
		// Real declared PyPI URLs — none of these are clone targets as-is.
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

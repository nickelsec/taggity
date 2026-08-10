package git

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/nickelsec/taggity/internal/taggity"
)

// fixedWhen keeps commit hashes stable across runs. A verdict cites the commit
// it read, so a repository built for a test has to be as reproducible as the
// evidence it produces.
var fixedWhen = time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC)

// testRepo builds a small repository on disk and returns it alongside the
// commit each file version landed in.
//
// Building a real repository rather than faking the interface is the point:
// Tags, Resolve and FileAt are thin wrappers over go-git, and a fake would test
// the wrapper against itself.
func testRepo(t *testing.T) (*Repo, map[string]string) {
	t.Helper()

	dir := t.TempDir()
	r, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("init: %v", err)
	}
	wt, err := r.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}

	commits := map[string]string{}
	commit := func(label, body string) plumbing.Hash {
		t.Helper()
		if err := os.WriteFile(filepath.Join(dir, "app.py"), []byte(body), 0o600); err != nil {
			t.Fatalf("write: %v", err)
		}
		if _, err := wt.Add("app.py"); err != nil {
			t.Fatalf("add: %v", err)
		}
		h, err := wt.Commit(label, &git.CommitOptions{
			Author: &object.Signature{Name: "t", Email: "t@example.com", When: fixedWhen},
		})
		if err != nil {
			t.Fatalf("commit: %v", err)
		}
		commits[label] = h.String()
		return h
	}

	first := commit("first", "def f():\n    return 1\n")
	second := commit("second", "def f():\n    return 2\n")

	// Lightweight and annotated tags reach FileAt by different paths: an
	// annotated tag's ref points at a tag object, not a commit, and Tags has to
	// peel it. Missing that would hand FileAt a hash it cannot read.
	lightweight := map[string]plumbing.Hash{
		"1.0.0":         first,
		"v1.0.0":        first,
		"release-1.0.0": first,
		"rel_2_0_51":    second,
		"2.1.0rc1":      second,
		"dec-11":        second,
		"nightly":       second,
	}
	for name, h := range lightweight {
		if _, err := r.CreateTag(name, h, nil); err != nil {
			t.Fatalf("tag %s: %v", name, err)
		}
	}
	if _, err := r.CreateTag("v3.0.0", second, &git.CreateTagOptions{
		Tagger:  &object.Signature{Name: "t", Email: "t@example.com", When: fixedWhen},
		Message: "annotated",
	}); err != nil {
		t.Fatalf("annotated tag: %v", err)
	}

	return &Repo{Dir: dir, repo: r}, commits
}

// An unparseable tag is discarded rather than failing the walk. One junk tag in
// a repository must not cost the audit every other version.
func TestTagsDiscardsUnparseableTags(t *testing.T) {
	repo, _ := testRepo(t)

	byKey, all, err := repo.Tags()
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	for _, tag := range all {
		if tag.Name == "dec-11" || tag.Name == "nightly" {
			t.Errorf("unparseable tag %q was kept", tag.Name)
		}
	}
	// The parseable ones survive, including the repo's own spellings.
	for _, want := range []string{"1.0.0", "2.0.51", "2.1.0rc1", "3.0.0"} {
		v, _ := ParseVersion(want)
		if _, ok := byKey[v.Key()]; !ok {
			t.Errorf("version %s was not indexed", want)
		}
	}
}

// An annotated tag's ref names a tag object. Tags has to peel it to the commit,
// or FileAt is handed a hash with no tree behind it and every read fails.
func TestTagsPeelsAnnotatedTags(t *testing.T) {
	repo, commits := testRepo(t)

	byKey, _, err := repo.Tags()
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	v, _ := ParseVersion("3.0.0")
	got, ok := byKey[v.Key()]
	if !ok {
		t.Fatal("annotated tag was not indexed")
	}
	if got.Commit != commits["second"] {
		t.Errorf("commit = %s, want the commit the tag points at (%s)",
			got.Commit, commits["second"])
	}
}

// Two spellings of one version must resolve the same way on every run, and the
// name that lands in evidence should be the one a reader can check most easily.
func TestTagsPrefersThePlainestSpelling(t *testing.T) {
	repo, _ := testRepo(t)
	v, _ := ParseVersion("1.0.0")

	for range 20 {
		byKey, _, err := repo.Tags()
		if err != nil {
			t.Fatalf("tags: %v", err)
		}
		if got := byKey[v.Key()].Name; got != "1.0.0" {
			t.Fatalf("name = %q, want 1.0.0: ForEach order is not guaranteed, so "+
				"the winner has to be chosen by rule", got)
		}
	}
}

func TestTagsSortsAscending(t *testing.T) {
	repo, _ := testRepo(t)

	_, all, err := repo.Tags()
	if err != nil {
		t.Fatalf("tags: %v", err)
	}
	for i := 1; i < len(all); i++ {
		if all[i-1].Ver.Compare(all[i].Ver) > 0 {
			t.Errorf("tags out of order: %s before %s", all[i-1].Name, all[i].Name)
		}
	}
}

func TestResolve(t *testing.T) {
	repo, commits := testRepo(t)

	cases := []struct {
		version string
		commit  string
		reason  taggity.Reason
		why     string
	}{
		{
			version: "1.0.0", commit: commits["first"],
			why: "a plain tag resolves",
		},
		{
			// The reason the package normalises tags backwards rather than
			// guessing a spelling forwards.
			version: "2.0.51", commit: commits["second"],
			why: "rel_2_0_51 is the repo's own spelling of this version",
		},
		{
			version: "3.0.0", commit: commits["second"],
			why: "an annotated tag resolves to its commit",
		},
		{
			version: "99.0.0", reason: taggity.ReasonNoTag,
			why: "a version with no tag is not a version found safe",
		},
		{
			version: "not-a-version", reason: taggity.ReasonUnparseableVersion,
			why: "an unparseable version is reported as such, not as a missing tag",
		},
	}

	for _, c := range cases {
		t.Run(c.version, func(t *testing.T) {
			commit, tag, reason := repo.Resolve(c.version)
			if reason != c.reason {
				t.Fatalf("reason = %q, want %q: %s", reason, c.reason, c.why)
			}
			if c.reason != taggity.ReasonNone {
				// A failed resolve must not also look like a successful one.
				if commit != "" || tag != "" {
					t.Errorf("failed resolve returned commit=%q tag=%q", commit, tag)
				}
				return
			}
			if commit != c.commit {
				t.Errorf("commit = %s, want %s: %s", commit, c.commit, c.why)
			}
			if tag == "" {
				t.Error("a successful resolve must name the tag it used")
			}
		})
	}
}

// Trailing zeros do not change a version, so 2.0 and 2.0.0 index together.
func TestResolveTreatsTrailingZerosAsEqual(t *testing.T) {
	repo, commits := testRepo(t)

	for _, v := range []string{"1.0", "1.0.0", "1.0.0.0"} {
		commit, _, reason := repo.Resolve(v)
		if reason != taggity.ReasonNone {
			t.Errorf("%s: reason = %q, want none", v, reason)
			continue
		}
		if commit != commits["first"] {
			t.Errorf("%s: commit = %s, want %s", v, commit, commits["first"])
		}
	}
}

func TestFileAt(t *testing.T) {
	repo, commits := testRepo(t)

	body, reason := repo.FileAt(commits["second"], "app.py")
	if reason != taggity.ReasonNone {
		t.Fatalf("reason = %q, want none", reason)
	}
	if !strings.Contains(string(body), "return 2") {
		t.Errorf("read the wrong commit's contents: %q", body)
	}

	// The same path at an earlier commit is a different file. Reading the
	// wrong commit would answer a question about a version nobody asked about.
	body, reason = repo.FileAt(commits["first"], "app.py")
	if reason != taggity.ReasonNone || !strings.Contains(string(body), "return 1") {
		t.Errorf("first commit gave reason=%q body=%q", reason, body)
	}
}

// Each failure names what actually went wrong. The reason codes exist so the
// distribution of Unknowns across a corpus can be read, and a misattributed one
// sends a researcher looking in the wrong place.
func TestFileAtReasons(t *testing.T) {
	repo, commits := testRepo(t)

	cases := []struct {
		name   string
		commit string
		path   string
		want   taggity.Reason
		why    string
	}{
		{
			name: "missing path", commit: commits["first"], path: "nope.py",
			want: taggity.ReasonFileAbsent,
			why:  "the commit read fine and the file is not in it",
		},
		{
			name:   "well-formed hash that names nothing",
			commit: "0123456789abcdef0123456789abcdef01234567",
			path:   "app.py",
			want:   taggity.ReasonCommitUnreadable,
			why:    "the tag resolved, so no_tag would describe the wrong failure",
		},
		{
			name: "malformed hash", commit: "not-a-hash", path: "app.py",
			want: taggity.ReasonCommitUnreadable,
			why:  "an unreadable object is not a missing tag",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			body, reason := repo.FileAt(c.commit, c.path)
			if reason != c.want {
				t.Errorf("reason = %q, want %q: %s", reason, c.want, c.why)
			}
			// Partial content must never accompany a failure.
			if body != nil {
				t.Errorf("failed read returned %d bytes", len(body))
			}
		})
	}
}

func TestCacheDir(t *testing.T) {
	a := CacheDir("https://github.com/psf/requests")
	b := CacheDir("https://github.com/psf/requests")
	if a != b {
		t.Errorf("not deterministic: %q then %q", a, b)
	}
	if c := CacheDir("https://github.com/pallets/flask"); c == a {
		t.Error("different repositories share a cache directory")
	}
	// The scheme is not a path component. Leaving it in produces a directory
	// named "https:" on disk.
	if strings.Contains(a, "https:") {
		t.Errorf("cache path kept the URL scheme: %q", a)
	}
	if !strings.Contains(a, "taggity") {
		t.Errorf("cache path is not namespaced to this tool: %q", a)
	}
}

// A repository that cannot be named is a hard failure. Returning a Repo with no
// inner repository would panic on first use instead.
func TestOpenOrCloneRejectsUnusableURL(t *testing.T) {
	repo, err := OpenOrClone("https://gitlab.com/foo/bar")
	if err == nil {
		t.Fatal("a non-github URL was accepted")
	}
	if repo != nil {
		t.Error("a failed clone returned a repository")
	}
}

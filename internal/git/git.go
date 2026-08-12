// Package git resolves published versions to commits and reads source at those
// commits. It is the only source of bytes: there is no artifact fallback, so a
// version that cannot be resolved yields a reason rather than a verdict.
package git

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/nickelsec/taggity/internal/taggity"
)

// ---------- repo URL normalization ----------

// NormalizeRepoURL reduces any GitHub URL to its canonical clone target.
//
// Declared PyPI URLs are frequently NOT clone targets: observed in the wild are
// .../issues, .../releases, and .../blob/main/CHANGES.rst.
func NormalizeRepoURL(raw string) (string, error) {
	s := strings.TrimSpace(raw)
	s = strings.TrimSuffix(s, ".git")
	i := strings.Index(strings.ToLower(s), "github.com")
	if i < 0 {
		return "", fmt.Errorf("not a github url: %q", raw)
	}
	parts := strings.Split(strings.Trim(s[i:], "/"), "/")
	if len(parts) < 3 {
		return "", fmt.Errorf("no owner/repo in %q", raw)
	}
	owner, repo := parts[1], parts[2]
	if owner == "" || repo == "" {
		return "", fmt.Errorf("no owner/repo in %q", raw)
	}
	return "https://github.com/" + owner + "/" + repo, nil
}

// ---------- PEP 440 (the subset that matters for tag matching) ----------

// Version is the subset of PEP 440 needed to order and match release tags.
type Version struct {
	Epoch    int
	Release  []int
	Pre      string // a|b|rc + number, empty if none
	Post     int    // -1 if none
	Dev      int    // -1 if none
	Original string
}

var verRe = regexp.MustCompile(
	`^(?:(\d+)!)?(\d+(?:\.\d+)*)` +
		`(?:[-_.]?(a|b|c|rc|alpha|beta|pre|preview)[-_.]?(\d*))?` +
		`(?:[-_.]?(post|rev|r)[-_.]?(\d*))?` +
		`(?:[-_.]?(dev)[-_.]?(\d*))?$`)

// ParseVersion parses a PEP 440 version string, reporting whether it is valid.
func ParseVersion(s string) (Version, bool) {
	v := Version{Post: -1, Dev: -1, Original: s}
	t := strings.ToLower(strings.TrimSpace(s))
	t = strings.TrimPrefix(t, "v")
	m := verRe.FindStringSubmatch(t)
	if m == nil {
		return v, false
	}
	if m[1] != "" {
		v.Epoch, _ = strconv.Atoi(m[1])
	}
	for p := range strings.SplitSeq(m[2], ".") {
		n, err := strconv.Atoi(p)
		if err != nil {
			return v, false
		}
		v.Release = append(v.Release, n)
	}
	if m[3] != "" {
		kind := map[string]string{"alpha": "a", "beta": "b", "c": "rc", "pre": "rc", "preview": "rc"}[m[3]]
		if kind == "" {
			kind = m[3]
		}
		n := m[4]
		if n == "" {
			n = "0"
		}
		v.Pre = kind + n
	}
	if m[5] != "" {
		n, _ := strconv.Atoi(orZero(m[6]))
		v.Post = n
	}
	if m[7] != "" {
		n, _ := strconv.Atoi(orZero(m[8]))
		v.Dev = n
	}
	return v, true
}

func orZero(s string) string {
	if s == "" {
		return "0"
	}
	return s
}

// Key is the canonical form used to index tags. Two spellings of the same
// version ("v2.0.5", "rel_2_0_5") must produce the same key.
func (v Version) Key() string {
	rel := make([]string, len(v.Release))
	for i, n := range v.Release {
		rel[i] = strconv.Itoa(n)
	}
	// Trim trailing zeros so 2.0 and 2.0.0 agree.
	for len(rel) > 1 && rel[len(rel)-1] == "0" {
		rel = rel[:len(rel)-1]
	}
	k := strconv.Itoa(v.Epoch) + "!" + strings.Join(rel, ".")
	if v.Pre != "" {
		k += "-" + v.Pre
	}
	if v.Post >= 0 {
		k += ".post" + strconv.Itoa(v.Post)
	}
	if v.Dev >= 0 {
		k += ".dev" + strconv.Itoa(v.Dev)
	}
	return k
}

// IsPrerelease reports whether v is a pre-release or development version.
func (v Version) IsPrerelease() bool { return v.Pre != "" || v.Dev >= 0 }

// Compare returns -1, 0, or 1 as v sorts before, with, or after other.
func (v Version) Compare(other Version) int {
	a, b := v, other
	if a.Epoch != b.Epoch {
		return sign(a.Epoch - b.Epoch)
	}
	n := max(len(a.Release), len(b.Release))
	for i := range n {
		if at(a.Release, i) != at(b.Release, i) {
			return sign(at(a.Release, i) - at(b.Release, i))
		}
	}
	// release > pre-release
	if (a.Pre == "") != (b.Pre == "") {
		if a.Pre == "" {
			return 1
		}
		return -1
	}
	if a.Pre != b.Pre {
		aKind, aNum := splitPre(a.Pre)
		bKind, bNum := splitPre(b.Pre)
		// PEP 440 orders the kinds a < b < rc, which is their alphabetical order
		// once ParseVersion has normalised alpha, beta, c, pre and preview down
		// to those three spellings.
		if aKind != bKind {
			return strings.Compare(aKind, bKind)
		}
		return sign(aNum - bNum)
	}
	if a.Post != b.Post {
		return sign(a.Post - b.Post)
	}
	if a.Dev != b.Dev {
		// no dev > dev
		if a.Dev < 0 {
			return 1
		}
		if b.Dev < 0 {
			return -1
		}
		return sign(a.Dev - b.Dev)
	}
	return 0
}

// plainerTag reports whether a is the better spelling of a version than b.
//
// Shortest wins, since every recognised prefix only adds characters, so "2.0.5"
// beats "v2.0.5" beats "release-2.0.5". Equal lengths fall back to byte order
// so the choice stays reproducible across runs.
func plainerTag(a, b string) bool {
	if len(a) != len(b) {
		return len(a) < len(b)
	}
	return a < b
}

// splitPre separates a pre-release marker like "rc10" into its kind and number.
//
// The number has to compare numerically. As a string "rc10" sorts before "rc9",
// which would place a release candidate ahead of the one it supersedes, and
// advisory claims are frequently written against a pre-release: MLflow's names
// 3.0.0rc0 as its introduced version.
func splitPre(p string) (kind string, num int) {
	i := strings.IndexFunc(p, func(r rune) bool { return r >= '0' && r <= '9' })
	if i < 0 {
		return p, 0
	}
	n, err := strconv.Atoi(p[i:])
	if err != nil {
		// Unreachable for anything ParseVersion produced, but Version is an
		// exported struct a caller can build by hand, and Compare runs inside
		// sort.Slice where a panic would abort an audit mid-run.
		return p, 0
	}
	return p[:i], n
}

func at(s []int, i int) int {
	if i < len(s) {
		return s[i]
	}
	return 0
}
func sign(n int) int {
	if n > 0 {
		return 1
	}
	if n < 0 {
		return -1
	}
	return 0
}

// ---------- repo ----------

// Repo is a bare clone of a package's source repository.
type Repo struct {
	Dir  string
	repo *git.Repository
}

// CacheDir returns the on-disk location of the bare clone for normURL.
func CacheDir(normURL string) string {
	base, err := os.UserCacheDir()
	if err != nil {
		base = os.TempDir()
	}
	p := strings.TrimPrefix(normURL, "https://")
	return filepath.Join(base, "taggity", "repos", filepath.FromSlash(p))
}

// OpenOrClone clones bare into the cache, or reuses an existing clone.
func OpenOrClone(rawURL string) (*Repo, error) {
	norm, err := NormalizeRepoURL(rawURL)
	if err != nil {
		return nil, err
	}
	dir := CacheDir(norm)
	if r, err := git.PlainOpen(dir); err == nil {
		return &Repo{Dir: dir, repo: r}, nil
	}
	// 0o750: the cache holds clones of public repositories, but it lives under
	// the user's home directory and nothing else needs to read it.
	if err := os.MkdirAll(filepath.Dir(dir), 0o750); err != nil {
		return nil, fmt.Errorf("creating cache directory: %w", err)
	}
	r, err := git.PlainClone(dir, true, &git.CloneOptions{URL: norm, Tags: git.AllTags})
	if err != nil {
		return nil, fmt.Errorf("clone %s: %w", norm, err)
	}
	return &Repo{Dir: dir, repo: r}, nil
}

// TagRef is one repository tag with its resolved commit and parsed version.
type TagRef struct {
	Name   string
	Commit string
	Ver    Version
}

// Tags resolves every tag, normalizing its name backwards into a version.
// Unparseable tags (e.g. "dec-11") are discarded, never an error.
func (r *Repo) Tags() (map[string]TagRef, []TagRef, error) {
	iter, err := r.repo.Tags()
	if err != nil {
		return nil, nil, fmt.Errorf("listing tags: %w", err)
	}
	byKey := map[string]TagRef{}
	var all []TagRef
	err = iter.ForEach(func(ref *plumbing.Reference) error {
		name := ref.Name().Short()
		// Peel annotated tags to the commit they point at.
		commit := ref.Hash()
		if to, err := r.repo.TagObject(ref.Hash()); err == nil {
			if c, err := to.Commit(); err == nil {
				commit = c.Hash
			}
		}
		v, ok := ParseVersion(stripTagPrefix(name))
		if !ok {
			return nil
		}
		t := TagRef{Name: name, Commit: commit.String(), Ver: v}
		all = append(all, t)
		// A repo may tag the same version twice (urllib3 has BOTH "v2.0.5" and
		// "2.0.5", same commit). ForEach order is not guaranteed, so the winner
		// is chosen by rule rather than by whichever arrived first: the name
		// lands in evidence, and a reader checking it by hand is best served by
		// the plainest spelling.
		if prev, dup := byKey[v.Key()]; !dup || plainerTag(name, prev.Name) {
			byKey[v.Key()] = t
		}
		return nil
	})
	if err != nil {
		return nil, nil, fmt.Errorf("walking tags: %w", err)
	}
	sort.Slice(all, func(i, j int) bool { return all[i].Ver.Compare(all[j].Ver) < 0 })
	return byKey, all, nil
}

var tagPrefixes = []string{
	"release-", "release_", "release/", "rel_", "rel-", "rel/", "v.",
}

// stripTagPrefix turns a repo's own tag spelling into something PEP 440 can
// parse: rel_2_0_51 -> 2.0.51, v2.34.2 -> 2.34.2, 3.1.3 -> 3.1.3.
func stripTagPrefix(tag string) string {
	s := strings.TrimSpace(tag)
	low := strings.ToLower(s)
	stripped := false
	for _, p := range tagPrefixes {
		if strings.HasPrefix(low, p) {
			s = s[len(p):]
			stripped = true
			break
		}
	}
	// A bare "v" only prefixes a version when a digit follows it. Stripping it
	// unconditionally turned "version-1.2.3" into "ersion-1.2.3", which then
	// failed to parse and was discarded, so a tag that was really there
	// resolved as no_tag.
	if !stripped && len(s) > 1 && (s[0] == 'v' || s[0] == 'V') && s[1] >= '0' && s[1] <= '9' {
		s = s[1:]
	}
	// Underscore-separated numerics (sqlalchemy) become dotted.
	if strings.Count(s, "_") > 0 && !strings.Contains(s, ".") {
		s = strings.ReplaceAll(s, "_", ".")
	}
	return s
}

// Resolve maps a published version string to a commit, or reports why not.
func (r *Repo) Resolve(version string) (commit, tag string, reason taggity.Reason) {
	v, ok := ParseVersion(version)
	if !ok {
		return "", "", taggity.ReasonUnparseableVersion
	}
	byKey, _, err := r.Tags()
	if err != nil {
		// The iterator failed rather than the version being absent.
		return "", "", taggity.ReasonCommitUnreadable
	}
	t, ok := byKey[v.Key()]
	if !ok {
		return "", "", taggity.ReasonNoTag
	}
	return t.Commit, t.Name, taggity.ReasonNone
}

// TreePaths lists repository-relative paths at a commit, filtered by suffix.
//
// The engine never needs this: a spec names a path and FileAt reads it. It
// exists so that when a check fails to find something, a reader can be shown
// where the file went rather than left to guess. Passing an empty suffix
// returns everything.
func (r *Repo) TreePaths(commitHash, suffix string) ([]string, error) {
	c, err := r.repo.CommitObject(plumbing.NewHash(commitHash))
	if err != nil {
		return nil, fmt.Errorf("reading commit %s: %w", commitHash, err)
	}
	tree, err := c.Tree()
	if err != nil {
		return nil, fmt.Errorf("reading tree at %s: %w", commitHash, err)
	}

	var out []string
	err = tree.Files().ForEach(func(f *object.File) error {
		if suffix == "" || strings.HasSuffix(f.Name, suffix) {
			out = append(out, f.Name)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walking tree at %s: %w", commitHash, err)
	}
	return out, nil
}

// FileAt reads a file's contents at a commit.
func (r *Repo) FileAt(commitHash, path string) ([]byte, taggity.Reason) {
	h := plumbing.NewHash(commitHash)
	c, err := r.repo.CommitObject(h)
	if err != nil {
		// The tag resolved to this hash, so reporting no_tag here would send a
		// reader looking for a tag that is present.
		return nil, taggity.ReasonCommitUnreadable
	}
	f, err := c.File(path)
	if err != nil {
		return nil, taggity.ReasonFileAbsent
	}
	s, err := f.Contents()
	if err != nil {
		// The tree entry exists, so the file is not absent. A blob that cannot
		// be read belongs with the other object store faults.
		return nil, taggity.ReasonCommitUnreadable
	}
	return []byte(s), taggity.ReasonNone
}

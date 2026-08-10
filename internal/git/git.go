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

	"github.com/nickelsec/taggity/internal/taggity"
)

// ---------- repo URL normalization ----------

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
	for _, p := range strings.Split(m[2], ".") {
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

func (v Version) IsPrerelease() bool { return v.Pre != "" || v.Dev >= 0 }

// Compare returns -1, 0, or 1.
func (a Version) Compare(b Version) int {
	if a.Epoch != b.Epoch {
		return sign(a.Epoch - b.Epoch)
	}
	n := len(a.Release)
	if len(b.Release) > n {
		n = len(b.Release)
	}
	for i := 0; i < n; i++ {
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
		return strings.Compare(a.Pre, b.Pre)
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

type Repo struct {
	Dir  string
	repo *git.Repository
}

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
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		return nil, err
	}
	r, err := git.PlainClone(dir, true, &git.CloneOptions{URL: norm, Tags: git.AllTags})
	if err != nil {
		return nil, fmt.Errorf("clone %s: %w", norm, err)
	}
	return &Repo{Dir: dir, repo: r}, nil
}

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
		return nil, nil, err
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
		// "2.0.5", same commit). ForEach order is not guaranteed, so break ties
		// deterministically by tag name — evidence must be reproducible.
		if prev, dup := byKey[v.Key()]; !dup || name < prev.Name {
			byKey[v.Key()] = t
		}
		return nil
	})
	sort.Slice(all, func(i, j int) bool { return all[i].Ver.Compare(all[j].Ver) < 0 })
	return byKey, all, err
}

var tagPrefixes = []string{
	"release-", "release_", "release/", "rel_", "rel-", "rel/", "v.", "v",
}

// stripTagPrefix turns a repo's own tag spelling into something PEP 440 can
// parse: rel_2_0_51 -> 2.0.51, v2.34.2 -> 2.34.2, 3.1.3 -> 3.1.3.
func stripTagPrefix(tag string) string {
	s := strings.TrimSpace(tag)
	low := strings.ToLower(s)
	for _, p := range tagPrefixes {
		if strings.HasPrefix(low, p) {
			s = s[len(p):]
			break
		}
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
		return "", "", taggity.ReasonNoTag
	}
	t, ok := byKey[v.Key()]
	if !ok {
		return "", "", taggity.ReasonNoTag
	}
	return t.Commit, t.Name, taggity.ReasonNone
}

// FileAt reads a file's contents at a commit.
func (r *Repo) FileAt(commitHash, path string) ([]byte, taggity.Reason) {
	h := plumbing.NewHash(commitHash)
	c, err := r.repo.CommitObject(h)
	if err != nil {
		return nil, taggity.ReasonNoTag
	}
	f, err := c.File(path)
	if err != nil {
		return nil, taggity.ReasonFileAbsent
	}
	s, err := f.Contents()
	if err != nil {
		return nil, taggity.ReasonFileAbsent
	}
	return []byte(s), taggity.ReasonNone
}

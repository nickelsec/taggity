// Package audit compares an advisory's claimed affected range against what the
// source actually contains.
//
// It does not verify a whole range. It probes the edges where a claim would be
// wrong: the version below each introduced, each fixed version, and the newest
// release on branches the advisory never mentions. Six checks answer the
// question that fifty would, which is what makes auditing at scale possible.
package audit

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/nickelsec/taggity/internal/git"
)

// Advisory is the subset of the OSV schema this package reads.
type Advisory struct {
	ID       string     `json:"id"`
	Summary  string     `json:"summary"`
	Affected []Affected `json:"affected"`
}

// Affected is one package's claimed ranges.
type Affected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Ranges   []Range  `json:"ranges"`
	Versions []string `json:"versions,omitempty"`
}

// Range is a sequence of introduced/fixed events.
type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

// Event is a single boundary in a range.
type Event struct {
	Introduced string `json:"introduced,omitempty"`
	Fixed      string `json:"fixed,omitempty"`
	LastAffec  string `json:"last_affected,omitempty"`
}

// LoadAdvisory reads an OSV JSON document.
func LoadAdvisory(path string) (*Advisory, error) {
	// #nosec G304 -- the path is the advisory the user asked to audit.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading advisory: %w", err)
	}
	var a Advisory
	if err := json.Unmarshal(b, &a); err != nil {
		return nil, fmt.Errorf("parsing advisory: %w", err)
	}
	if a.ID == "" {
		return nil, errors.New("advisory has no id")
	}
	return &a, nil
}

// ErrAdvisoryMismatch reports that a spec names a different advisory than the
// one it is being run against.
var ErrAdvisoryMismatch = errors.New("spec and advisory disagree")

// CheckAdvisoryMatch reports whether a spec may be run against this advisory.
// A spec naming no advisory matches anything; a spec that names one must name
// this one.
//
// This is an error rather than a warning because the result of ignoring it is a
// confident report about the wrong advisory. In export it is worse: a
// machine-readable OSV document carrying one advisory's ID over another's
// findings. A warning on
// stderr is invisible in a pipeline, which is where these commands run.
func CheckAdvisoryMatch(specAdvisory, advisoryID string) error {
	if specAdvisory == "" || specAdvisory == advisoryID {
		return nil
	}
	return fmt.Errorf("%w: spec names %s, --advisory is %s",
		ErrAdvisoryMismatch, specAdvisory, advisoryID)
}

// Claim is one asserted range for a package, flattened into an
// introduced/fixed pair. An open range (introduced with no fixed) yields an
// empty Fixed.
type Claim struct {
	Introduced string
	Fixed      string
}

// Claims extracts the introduced/fixed pairs for a package name.
func (a *Advisory) Claims(pkg string) []Claim {
	var out []Claim
	for _, af := range a.Affected {
		if af.Package.Name != pkg {
			continue
		}
		for _, r := range af.Ranges {
			var cur Claim
			open := false
			for _, e := range r.Events {
				switch {
				case e.Introduced != "":
					if open {
						out = append(out, cur)
					}
					cur = Claim{Introduced: e.Introduced}
					open = true
				case e.Fixed != "":
					cur.Fixed = e.Fixed
					out = append(out, cur)
					open = false
				case e.LastAffec != "":
					cur.Fixed = "" // last_affected is inclusive; treat as open
					out = append(out, cur)
					open = false
				}
			}
			if open {
				out = append(out, cur)
			}
		}
	}
	return out
}

// covers reports whether version falls inside the claim, half-open as the
// advisory writes it: introduced is inclusive, fixed is exclusive.
//
// A version that does not parse is not covered. Guessing would place a probe
// inside a claim it may have nothing to do with.
func (c Claim) covers(version string) bool {
	v, ok := git.ParseVersion(version)
	if !ok {
		return false
	}
	if c.Introduced != "" && c.Introduced != "0" {
		lo, ok := git.ParseVersion(c.Introduced)
		if !ok || v.Compare(lo) < 0 {
			return false
		}
	}
	if c.Fixed != "" {
		hi, ok := git.ParseVersion(c.Fixed)
		if !ok || v.Compare(hi) >= 0 {
			return false
		}
	}
	return true
}

// String renders the claims for a report header.
func (c Claim) String() string {
	if c.Fixed == "" {
		return ">= " + c.Introduced
	}
	if c.Introduced == "0" || c.Introduced == "" {
		return "< " + c.Fixed
	}
	return ">= " + c.Introduced + ", < " + c.Fixed
}

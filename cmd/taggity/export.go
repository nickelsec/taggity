package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nickelsec/taggity/internal/audit"
	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/git"
	"github.com/nickelsec/taggity/internal/predicate"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// osvDoc is the subset of the OSV schema this tool emits. It carries only what
// was actually established, with provenance in database_specific so a reader
// can tell how the ranges were derived.
type osvDoc struct {
	SchemaVersion string        `json:"schema_version"`
	ID            string        `json:"id"`
	Affected      []osvAffected `json:"affected"`
}

type osvAffected struct {
	Package struct {
		Ecosystem string `json:"ecosystem"`
		Name      string `json:"name"`
	} `json:"package"`
	Versions        []string       `json:"versions,omitempty"`
	DatabaseSpecifc map[string]any `json:"database_specific,omitempty"`
}

func runExport(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("export", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "path to a taggity.yaml spec (required)")
	advPath := fs.String("advisory", "", "path to an OSV JSON advisory (required)")
	out := fs.String("out", "", "write to this path instead of stdout")
	fs.Usage = func() {
		fmt.Fprint(stderr, `
Usage: taggity export --spec <file> --advisory <file>

Emits OSV JSON for the versions an audit established as affected.

Only versions the engine positively determined are included. UNKNOWN versions
are excluded rather than assumed safe: a machine-readable claim should carry
what was proven, and a gap in coverage is not evidence of absence. The gaps are
reported separately so they are visible rather than silently dropped.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return errUsage
	}
	if *specPath == "" || *advPath == "" {
		fs.Usage()
		return errors.New("--spec and --advisory are both required")
	}

	sp, err := spec.Load(*specPath)
	if err != nil {
		return err
	}
	adv, err := audit.LoadAdvisory(*advPath)
	if err != nil {
		return err
	}
	repo, err := git.OpenOrClone(sp.Repo)
	if err != nil {
		return fmt.Errorf("repository is required: %w", err)
	}
	_, tags, err := repo.Tags()
	if err != nil {
		return fmt.Errorf("listing tags: %w", err)
	}

	claims := adv.Claims(sp.Package.Name)
	boundaries := audit.SelectBoundaries(claims, tags)
	rep := audit.Run(&check.Checker{Source: repo}, sp, adv, boundaries)

	doc := buildOSV(rep, sp)

	b, err := json.MarshalIndent(doc, "", "  ")
	if err != nil {
		return fmt.Errorf("rendering OSV: %w", err)
	}
	b = append(b, '\n')

	if *out == "" {
		_, err = stdout.Write(b)
		return err
	}
	if err := os.WriteFile(*out, b, 0o600); err != nil {
		return fmt.Errorf("writing OSV: %w", err)
	}
	fmt.Fprintf(stdout, "wrote %s\n", *out)
	return nil
}

func buildOSV(rep *audit.Report, sp *spec.Spec) osvDoc {
	matchMeansVuln := sp.Signal.Code.Rule.MatchMeansVulnerable()

	var affected []string
	var gaps []string
	var disputed []string

	for _, res := range rep.Results {
		version := res.Boundary.Version

		// A disagreement is an unreviewed observation, not an established
		// fact. Emitting one as an affected version would publish exactly the
		// claim the design warns against: on redis-py the disagreements looked
		// like unpatched releases and turned out to be a guard that had been
		// deliberately replaced. They are recorded separately so a human can
		// resolve them before anything is filed.
		if res.Outcome == audit.Disagreement {
			disputed = append(disputed, version)
			continue
		}

		switch res.Signals.Overall() {
		case taggity.Vulnerable:
			if matchMeansVuln {
				affected = append(affected, version)
			}
		case taggity.NotVulnerable:
			if !matchMeansVuln {
				affected = append(affected, version)
			}
		default:
			// Excluded from the claim, recorded in provenance. A version the
			// engine could not read is not a version it found safe.
			gaps = append(gaps, version)
		}
	}

	doc := osvDoc{SchemaVersion: "1.6.0", ID: rep.AdvisoryID}
	a := osvAffected{Versions: affected}
	a.Package.Ecosystem = sp.Package.Ecosystem
	a.Package.Name = sp.Package.Name
	a.DatabaseSpecifc = map[string]any{
		"taggity": map[string]any{
			"method":                "static-predicate-boundary-probe",
			"rule":                  sp.RuleString(),
			"symbol":                sp.Signal.Code.Symbol,
			"file":                  sp.Signal.Code.File,
			"matcher":               predicate.MatcherName,
			"matcher_version":       predicate.MatcherVersion,
			"probed_versions":       len(rep.Results),
			"indeterminate":         gaps,
			"disputed_unreviewed":   disputed,
			"authoring_mode":        sp.Authoring.Mode,
			"partial":               len(gaps) > 0 || len(disputed) > 0,
			"boundary_probe_only":   true,
			"not_a_full_range_scan": true,
		},
	}
	doc.Affected = []osvAffected{a}
	return doc
}

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/nickelsec/taggity/internal/audit"
	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/git"
	"github.com/nickelsec/taggity/internal/spec"
)

func runAudit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "path to a taggity.yaml spec (required)")
	advPath := fs.String("advisory", "", "path to an OSV JSON advisory (required)")
	verbose := fs.Bool("verbose", false, "show every probed version, not just findings")
	fs.Usage = func() {
		fmt.Fprint(stderr, `
Usage: taggity audit --spec <file> --advisory <file>

Probes the versions where an advisory's claimed range would be wrong: the
release below each introduced version, each fixed version, the release below
it, and the newest release on any line the advisory never mentions.

A range is an assertion about its edges, so the interior is not probed. That is
what keeps an audit to a handful of checks rather than dozens.

A DISAGREEMENT is a reading assignment, not a conclusion. It means the advisory
implies a version is safe and the construct is present, which is worth a
human's attention — not a correction to file unread.

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
	// Before the clone, so a mismatch fails immediately rather than after a
	// network fetch.
	if err := audit.CheckAdvisoryMatch(sp.Advisory, adv.ID); err != nil {
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
	if len(claims) == 0 {
		return fmt.Errorf("advisory %s claims nothing about package %q",
			adv.ID, sp.Package.Name)
	}

	boundaries := audit.SelectBoundaries(claims, tags)
	if len(boundaries) == 0 {
		return fmt.Errorf("no boundaries selected from %d tags", len(tags))
	}

	rep := audit.Run(&check.Checker{Source: repo}, sp, adv, boundaries)
	printAudit(stdout, rep, sp, len(tags), *verbose)
	return nil
}

func printAudit(w io.Writer, rep *audit.Report, sp *spec.Spec, tagCount int, verbose bool) {
	fmt.Fprintf(w, "\n%s  %s\n", rep.AdvisoryID, rep.Package)
	for _, c := range rep.Claims {
		fmt.Fprintf(w, "  claims  %s\n", c)
	}
	fmt.Fprintf(w, "  rule    %s in %s\n", sp.RuleString(), sp.Signal.Code.Symbol)
	if sp.Signal.Code.Rule.Indicates == spec.IndicatesFixed {
		fmt.Fprintln(w, "          (matches the FIX; a match means the fix is present)")
	}
	fmt.Fprintf(w, "  probed  %d of %d tags\n", len(rep.Results), tagCount)

	if verbose {
		fmt.Fprintf(w, "\n  %-10s %-15s %-20s %s\n", "version", "verdict", "rule", "outcome")
		for _, res := range rep.Results {
			fmt.Fprintln(w, res.Describe())
		}
	}

	// Findings are grouped by structural change. One edit to a file shows up at
	// every release after it, so counting per version would inflate a report by
	// however many releases happened to be probed.
	findings := rep.Findings()
	if len(findings) > 0 {
		fmt.Fprintf(w, "\n  DISAGREEMENTS\n")
		for _, f := range findings {
			fmt.Fprintf(w, "    %-16s %-15s %v\n", f.Span(), f.Verdict, f.Rules)
		}
	}

	// Shown, but kept out of DISAGREEMENTS and out of export: this direction
	// says the advisory claims more than the engine can see, which is usually
	// the spec's blind spot rather than the advisory's error. It still has to be
	// visible — with an inverted-polarity rule this is where a genuine
	// over-claim lands, and a bare count in the summary reads as nothing found.
	if over := rep.Overclaims(); len(over) > 0 {
		fmt.Fprintf(w, "\n  CLAIMED BUT NOT OBSERVED (needs review, not a finding)\n")
		for _, o := range over {
			fmt.Fprintf(w, "    %-16s %-15s %v\n", o.Span(), o.Verdict, o.Rules)
		}
	}

	if gaps := rep.Unknowns(); len(gaps) > 0 {
		fmt.Fprintf(w, "\n  GAPS (could not answer)\n")
		for _, g := range gaps {
			fmt.Fprintf(w, "    %-16s [%s]\n", g.Span(), g.Reason)
		}
	}

	n, consistent, narrower, unknown := rep.Counts()
	rawDis, _, _, rawUnk := rep.VersionCounts()
	fmt.Fprintf(w, "\n  %d finding(s) across %d versions · %d consistent · "+
		"%d narrower · %d gap(s) across %d versions\n",
		n, rawDis, consistent, narrower, unknown, rawUnk)

	if len(findings) > 0 || len(rep.Overclaims()) > 0 {
		fmt.Fprintf(w, "\n  Each line above is a version worth reading, not a\n"+
			"  correction to file. Confirm against the project's history first.\n")
	}
	fmt.Fprintln(w)
}

package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nickelsec/taggity/internal/audit"
	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/git"
	"github.com/nickelsec/taggity/internal/llm"
	"github.com/nickelsec/taggity/internal/spec"
)

func runAudit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("audit", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "path to a taggity.yaml spec (required)")
	advPath := fs.String("advisory", "", "path to an OSV JSON advisory (required)")
	verbose := fs.Bool("verbose", false, "show every probed version, not just findings")
	useLLM := fs.Bool("llm", false, "explain the versions that could not be checked")
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
human's attention, not a correction to file unread.

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

	// One call per grouped gap, not per version: gaps are already grouped by
	// cause, so six consecutive releases that share one share a single call.
	var gaps map[string]*resolved
	if *useLLM {
		gaps, err = explainGaps(rep, sp, repo, *specPath)
		if err != nil {
			return err
		}
	}

	printAudit(stdout, rep, sp, len(tags), *verbose, gaps)
	return nil
}

// explainGaps asks the model about every version the engine could not answer,
// and re-checks anywhere it points at.
//
// Keyed by the gap's span rather than by version, so the renderer can attach an
// explanation to the line it already prints.
func explainGaps(rep *audit.Report, sp *spec.Spec, repo *git.Repo, specPath string) (
	map[string]*resolved, error,
) {
	unknowns := rep.Unknowns()
	if len(unknowns) == 0 {
		// Nothing to explain is an ordinary outcome, and an empty map renders
		// as no annotations at all.
		return map[string]*resolved{}, nil
	}

	provider, err := llm.FromConfig("", "")
	if err != nil {
		return nil, err
	}
	// #nosec G304 -- the spec the user asked to audit, already read once above.
	raw, err := os.ReadFile(specPath)
	if err != nil {
		return nil, fmt.Errorf("reading spec: %w", err)
	}

	r := &resolver{provider: provider, repo: repo, spec: sp, specYAML: string(raw)}
	out := make(map[string]*resolved, len(unknowns))
	for _, gap := range unknowns {
		// The first version in the span stands for it: they share a cause,
		// which is why they were grouped.
		out[gap.Span()] = r.resolve(gap.From, gap.Reason)
	}
	return out, nil
}

func printAudit(w io.Writer, rep *audit.Report, sp *spec.Spec, tagCount int,
	verbose bool, gaps map[string]*resolved,
) {
	fmt.Fprintf(w, "\n%s  %s\n", rep.AdvisoryID, rep.Package)
	for _, c := range rep.Claims {
		fmt.Fprintf(w, "  claims  %s\n", c)
	}
	fmt.Fprintf(w, "  looking for  %s in %s\n", sp.RuleString(), sp.Primary().Symbol)
	if !sp.MatchMeansVulnerable() {
		fmt.Fprintln(w, "               this matches the FIX, so finding it means the version is patched")
	}
	fmt.Fprintf(w, "  checked      %d of %d releases\n", len(rep.Results), tagCount)

	if verbose {
		fmt.Fprintf(w, "\n  %-10s %-15s %-20s %s\n", "version", "verdict", "rule", "outcome")
		for _, res := range rep.Results {
			fmt.Fprintln(w, res.Describe())
		}
	}

	// Findings are grouped by structural change. One edit to a file shows up at
	// every release after it, so counting per version would inflate a report by
	// however many releases happened to be probed.
	//
	// Section headings and per-line detail are written for someone who has just
	// found a bug, not for someone who has read this codebase. The rule and
	// reason codes stay available behind --verbose.
	findings := rep.Findings()
	if len(findings) > 0 {
		fmt.Fprintf(w, "\n  THE ADVISORY SAYS SAFE, THE CODE SAYS VULNERABLE\n")
		for _, f := range findings {
			fmt.Fprintf(w, "    %-16s %s\n", f.Span(), whyProbed(f.Rules, verbose))
		}
	}

	// Shown, but kept out of the findings section and out of export: this
	// direction says the advisory claims more than the engine can see, which is
	// usually the spec's blind spot rather than the advisory's error. It still
	// has to be visible, since with an inverted-polarity rule this is where a
	// genuine over-claim lands, and a bare count in the summary reads as nothing
	// found.
	if over := rep.Overclaims(); len(over) > 0 {
		fmt.Fprintf(w, "\n  THE ADVISORY SAYS AFFECTED, THE CODE SAYS OTHERWISE\n")
		fmt.Fprintf(w, "  (usually the spec looking in the wrong place, not an advisory error)\n")
		for _, o := range over {
			fmt.Fprintf(w, "    %-16s %s\n", o.Span(), whyProbed(o.Rules, verbose))
		}
	}

	// A claim whose edges are all pre-releases gets no probe at all, because
	// boundary selection only considers released versions. Left unsaid, the
	// remaining boundaries count as consistent and the report reads as
	// agreement with an advisory whose second branch was never examined.
	if unprobed := rep.UnprobedClaims(); len(unprobed) > 0 {
		fmt.Fprintf(w, "\n  NOT CHECKED AT ALL\n")
		fmt.Fprintf(w, "  (no released version at either edge of these ranges)\n")
		for _, c := range unprobed {
			fmt.Fprintf(w, "    %s\n", c)
		}
	}

	if unknowns := rep.Unknowns(); len(unknowns) > 0 {
		fmt.Fprintf(w, "\n  COULD NOT CHECK\n")
		for _, g := range unknowns {
			detail := g.Reason.Describe()
			if verbose {
				detail = fmt.Sprintf("%s [%s]", detail, g.Reason)
			}
			fmt.Fprintf(w, "    %-16s %s\n", g.Span(), detail)

			// With --llm, the explanation lands under the line it explains
			// rather than in a separate command run against the same versions.
			if r := gaps[g.Span()]; r != nil {
				fmt.Fprint(w, r.describe("      "))
			}
		}
	}

	n, consistent, narrower, unknown := rep.Counts()
	rawDis, _, _, rawUnk := rep.VersionCounts()
	// One line, in the order a reader cares about: what to act on, what was
	// fine, what could not be answered.
	fmt.Fprintf(w, "\n  %d to look at · %d agree with the advisory · %d could not be checked\n",
		n+narrower, consistent, unknown)
	if verbose {
		fmt.Fprintf(w, "  (%d disagreements across %d versions, %d narrower, "+
			"%d gaps across %d versions)\n",
			n, rawDis, narrower, unknown, rawUnk)
	}

	if len(findings) > 0 || len(rep.Overclaims()) > 0 {
		fmt.Fprintf(w, "\n  Each line above is a version worth reading, not a\n"+
			"  correction to file. Confirm against the project's history first.\n")
	}
	fmt.Fprintln(w)
}

// whyProbed renders the selection rules that picked a version, as the reason
// the version was worth probing at all.
//
// Several rules can apply to one span when it covers versions chosen for
// different reasons, so they are joined rather than reduced to one.
func whyProbed(rules []string, verbose bool) string {
	if len(rules) == 0 {
		return ""
	}
	parts := make([]string, 0, len(rules))
	for _, r := range rules {
		if verbose {
			parts = append(parts, fmt.Sprintf("%s [%s]", audit.DescribeRule(r), r))
			continue
		}
		parts = append(parts, audit.DescribeRule(r))
	}
	return strings.Join(parts, "; ")
}

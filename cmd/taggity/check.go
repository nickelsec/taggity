package main

import (
	"errors"
	"flag"
	"fmt"
	"io"
	"strings"

	"github.com/nickelsec/taggity/internal/check"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

func runCheck(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("check", flag.ContinueOnError)
	fs.SetOutput(stderr)
	specPath := fs.String("spec", "", "path to a taggity.yaml spec (required)")
	quiet := fs.Bool("quiet", false, "print only the verdict")
	fs.Usage = func() {
		fmt.Fprint(stderr, `
Usage: taggity check <pkg>@<version> --spec <file>

Reports whether one version contains the construct described by the spec.

  VULNERABLE      the construct is present
  NOT_VULNERABLE  the symbol was found and the construct is not present
  UNKNOWN         the question could not be answered; a reason is given

An UNKNOWN is an answer, not a failure. It marks where a human still has to
look, and is never treated as evidence that a version is safe.

Flags:
`)
		fs.PrintDefaults()
	}
	// Go's flag package stops parsing at the first non-flag argument, so
	// "check redis@4.5.4 --spec x" would leave --spec unparsed. Lift the
	// positional argument out first and let the rest parse normally, so flags
	// may appear on either side of it.
	target, flagArgs := extractPositional(args)
	if err := fs.Parse(flagArgs); err != nil {
		return errUsage
	}

	if target == "" || fs.NArg() > 0 {
		fs.Usage()
		return errors.New("expected exactly one <pkg>@<version> argument")
	}
	if *specPath == "" {
		fs.Usage()
		return errors.New("--spec is required")
	}

	pkg, wantVersion, err := splitTarget(target)
	if err != nil {
		return err
	}

	sp, err := spec.Load(*specPath)
	if err != nil {
		return err
	}
	if pkg != "" && pkg != sp.Package.Name {
		return fmt.Errorf("spec describes package %q, not %q", sp.Package.Name, pkg)
	}

	// The repository is a precondition rather than a best-effort input: without
	// it there is no way to answer anything, so fail here instead of emitting a
	// run of UNKNOWNs that look like results.
	c, err := check.New(sp.Repo)
	if err != nil {
		return err
	}

	sig := c.Version(sp, wantVersion)
	printCheck(stdout, sp, wantVersion, sig, *quiet)

	// Exit status reports whether the run succeeded, not what the verdict was.
	// A tool that exits non-zero on VULNERABLE would be unusable in a loop over
	// versions, where finding the construct is the expected outcome.
	return nil
}

// extractPositional pulls the first bare argument out of args, returning it
// alongside everything else in original order.
//
// Flags that take a value are skipped over so that "--spec x.yaml" is not
// mistaken for a positional. Only the boolean flags this command defines are
// treated as valueless.
func extractPositional(args []string) (positional string, rest []string) {
	valueless := map[string]bool{"-quiet": true, "--quiet": true}

	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case strings.HasPrefix(a, "-"):
			rest = append(rest, a)
			// A flag written as --spec=x carries its value already.
			if !strings.Contains(a, "=") && !valueless[a] && i+1 < len(args) {
				i++
				rest = append(rest, args[i])
			}
		case positional == "":
			positional = a
		default:
			rest = append(rest, a)
		}
	}
	return positional, rest
}

// splitTarget accepts "pkg@version" or a bare version, so that a spec already
// naming the package does not have to be repeated on the command line.
func splitTarget(arg string) (pkg, version string, err error) {
	if i := strings.LastIndex(arg, "@"); i > 0 {
		return arg[:i], arg[i+1:], nil
	}
	if rest, ok := strings.CutPrefix(arg, "@"); ok {
		return "", rest, nil
	}
	if arg == "" {
		return "", "", errors.New("empty version")
	}
	return "", arg, nil
}

func printCheck(w io.Writer, sp *spec.Spec, version string, sig taggity.Signals, quiet bool) {
	overall := sig.Overall()
	if quiet {
		fmt.Fprintln(w, overall)
		return
	}

	// Every summary line describes the location that produced the verdict, not
	// the one the spec happens to list first. Under `any` those differ whenever
	// a symbol moved between files, which is most tags of a long-lived project.
	ev := sig.Deciding()

	fmt.Fprintf(w, "\n%s@%s\n", sp.Package.Name, version)
	fmt.Fprintf(w, "  rule    %s in %s\n", ruleLine(sp, sig, ev), decidingSymbol(sp, ev))

	// Unevaluated signals render as an em dash. A signal that never ran must
	// never look like a pass.
	fmt.Fprintf(w, "\n  present    %-15s %s\n", sig.Present, ev.Detail)
	fmt.Fprintf(w, "  reachable  %-15s not evaluated\n", sig.Reachable)
	fmt.Fprintf(w, "  triggers   %-15s not evaluated\n", sig.Triggers)

	// With several locations the summary line alone does not say which one
	// decided the verdict, and under `any` that is the whole question. The
	// arrow marks the deciding row so the breakdown and the summary visibly
	// agree rather than leaving the reader to infer it.
	if len(sig.Evidence) > 1 {
		fmt.Fprintln(w)
		for _, e := range sig.Evidence {
			mark := "  "
			if e == ev {
				mark = "* "
			}
			fmt.Fprintf(w, "  %s%-15s %s  %s\n", mark, e.Verdict, e.File, e.Detail)
		}
	}

	fmt.Fprintf(w, "\n  → %s", overall)
	if sig.Reason != taggity.ReasonNone {
		fmt.Fprintf(w, " [%s]", sig.Reason)
	}
	fmt.Fprintln(w)

	if ev.Commit != "" {
		fmt.Fprintf(w, "  at %s (%s) %s\n", ev.Tag, short(ev.Commit), ev.File)
	}
	if !sp.MatchMeansVulnerable() {
		fmt.Fprintln(w, "\n  note: this spec matches the FIX, not the danger."+
			"\n        VULNERABLE here means the fix is present.")
	}
	fmt.Fprintln(w)
}

// ruleLine describes the rule that produced the verdict.
//
// A single-location spec has one rule and the spec renders it. With several,
// the spec-level string can only say "any of N", which names a rule that may
// not be the one that fired, so the deciding record's own rule is used and the
// count is kept as a prefix to show the others were considered.
func ruleLine(sp *spec.Spec, sig taggity.Signals, ev taggity.Evidence) string {
	if len(sig.Evidence) < 2 || ev.Rule == "" {
		return sp.RuleString()
	}
	return fmt.Sprintf("any of %d, matched: %s", len(sig.Evidence), ev.Rule)
}

// decidingSymbol names the symbol that was examined. Evidence carries no symbol
// when the file could not be read at all, so the spec's own symbol stands in
// rather than leaving the line blank.
func decidingSymbol(sp *spec.Spec, ev taggity.Evidence) string {
	if ev.Symbol != "" {
		return ev.Symbol
	}
	return sp.Primary().Symbol
}

func short(commit string) string {
	if len(commit) > 12 {
		return commit[:12]
	}
	return commit
}

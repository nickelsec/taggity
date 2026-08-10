package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/nickelsec/taggity/internal/spec"
	"gopkg.in/yaml.v3"
)

func runInit(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("init", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		repo      = fs.String("repo", "", "upstream repository URL (required)")
		pkg       = fs.String("package", "", "package name on the registry (required)")
		ecosystem = fs.String("ecosystem", "PyPI", "registry the package is published to")
		file      = fs.String("file", "", "repository-relative path to the source file (required)")
		symbol    = fs.String("symbol", "", "definition to examine, Class.method to disambiguate (required)")
		calls     = fs.String("calls", "", "call target the rule looks for (required)")
		indicates = fs.String("indicates", "", "vulnerable (default) or fixed, if the rule matches the guard")
		advisory  = fs.String("advisory", "", "advisory this spec tests against")
		out       = fs.String("out", "", "write to this path instead of stdout")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, `
Usage: taggity init --repo <url> --package <name> --file <path> \
                    --symbol <name> --calls <target>

Writes a spec describing one vulnerable construct. The spec is the portable
artifact: it is what makes a verdict reproducible by someone else, so it is
meant to be reviewed and committed rather than generated on the fly.

Use --indicates fixed when the rule matches a guard the fix added rather than
the danger itself. Verdicts then read inverted, and a report says so.

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	missing := map[string]string{
		"--repo": *repo, "--package": *pkg, "--file": *file,
		"--symbol": *symbol, "--calls": *calls,
	}
	for flagName, v := range missing {
		if v == "" {
			fs.Usage()
			return fmt.Errorf("%s is required", flagName)
		}
	}

	sp := &spec.Spec{
		Repo:     *repo,
		Advisory: *advisory,
		Authoring: spec.Authoring{
			Mode: "manual",
		},
	}
	sp.Package.Ecosystem = *ecosystem
	sp.Package.Name = *pkg
	sp.Signal.Code.File = *file
	sp.Signal.Code.Symbol = *symbol
	sp.Signal.Code.Rule.Calls = *calls
	sp.Signal.Code.Rule.Indicates = *indicates

	// Validate before writing: a spec that cannot be evaluated is worse than no
	// spec, because it looks like work that was done.
	if err := sp.Validate(); err != nil {
		return err
	}

	b, err := yaml.Marshal(sp)
	if err != nil {
		return fmt.Errorf("rendering spec: %w", err)
	}

	if *out == "" {
		fmt.Fprint(stdout, string(b))
		return nil
	}
	if err := os.WriteFile(*out, b, 0o600); err != nil {
		return fmt.Errorf("writing spec: %w", err)
	}
	fmt.Fprintf(stdout, "wrote %s\n", *out)
	return nil
}

package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nickelsec/taggity/internal/git"
	"github.com/nickelsec/taggity/internal/llm"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
	"gopkg.in/yaml.v3"
)

func runDraft(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("draft", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		repo      = fs.String("repo", "", "upstream repository URL (required)")
		pkg       = fs.String("package", "", "package name on the registry")
		ecosystem = fs.String("ecosystem", "PyPI", "registry the package is published to")
		advisory  = fs.String("advisory", "", "advisory ID, recorded in the spec")
		provider  = fs.String("provider", "", "anthropic or openrouter, overriding the configured one")
		model     = fs.String("model", "", "model to draft with, overriding the configured one")
		out       = fs.String("out", "", "write to this path instead of stdout")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, `
Usage: taggity draft --repo <url> "<what the vulnerability is>"

Writes a spec from your description of a bug. Say what goes wrong, in which
file, and ideally at which line:

  taggity draft --repo github.com/foo/bar \
    "SSRF in proxy_handler at server.py:43, the url param reaches
     requests.get without validation"

The more precise the description, the better the spec. Read what comes back
before you rely on a verdict from it.

Run `+"`taggity configure`"+` first, or set an API key in the environment.
check, audit and export never read one.

Flags:
`)
		fs.PrintDefaults()
	}

	describe, flagArgs := extractPositional(args)
	if err := fs.Parse(flagArgs); err != nil {
		return errUsage
	}
	// Everything left over is part of the description: a shell will split an
	// unquoted sentence into words, and rejecting that would be a papercut on
	// the first command anyone runs.
	if fs.NArg() > 0 {
		describe = strings.TrimSpace(describe + " " + strings.Join(fs.Args(), " "))
	}

	if describe == "" {
		fs.Usage()
		return errors.New("describe the vulnerability in your own words")
	}
	if *repo == "" {
		fs.Usage()
		return errors.New("--repo is required: the model reads the real source, " +
			"not its memory of the package")
	}

	prov, err := llm.FromConfig(*provider, *model)
	if err != nil {
		return err
	}

	// Real source at HEAD, not the model's recollection of the package. Any
	// path the description mentions is fetched; unreadable ones are skipped
	// rather than fatal, since a description may name a file that has moved.
	repository, err := git.OpenOrClone(*repo)
	if err != nil {
		return fmt.Errorf("repository is required: %w", err)
	}
	sources := gatherSources(repository, describe)

	sp, err := prov.Draft(context.Background(), llm.DraftRequest{
		Describe:  describe,
		Repo:      *repo,
		Package:   *pkg,
		Ecosystem: *ecosystem,
		Advisory:  *advisory,
		Sources:   sources,
	})
	if err != nil {
		return err
	}

	return emitSpec(stdout, sp, *out, fmt.Sprintf(
		"# Drafted by %s/%s. Check the file, symbol and rule against the source\n"+
			"# before you rely on a verdict from this.\n",
		prov.Name(), prov.Model()))
}

// gatherSources reads whatever files the description names.
//
// Paths are taken from the description rather than searched for, because
// internal/git reads a path it is given and cannot enumerate a tree. That is
// also why the description matters: naming the file is most of the work.
func gatherSources(repo *git.Repo, describe string) map[string]string {
	head, _, reason := repo.Resolve("HEAD")
	if reason != taggity.ReasonNone {
		return nil
	}

	out := map[string]string{}
	for _, path := range pathsIn(describe) {
		src, reason := repo.FileAt(head, path)
		if reason == taggity.ReasonNone {
			out[path] = string(src)
		}
	}
	return out
}

// pathsIn picks source paths out of a description.
//
// Deliberately loose: a false positive costs one failed read, and a missed path
// costs the model the file it needed. A trailing :43 is stripped, since a line
// number is where to look rather than part of the name.
func pathsIn(describe string) []string {
	var out []string
	for field := range strings.FieldsSeq(describe) {
		field = strings.Trim(field, ",;:()[]\"'`")
		if i := strings.IndexByte(field, ':'); i > 0 {
			field = field[:i]
		}
		if strings.HasSuffix(field, ".py") {
			out = append(out, field)
		}
	}
	return out
}

// emitSpec renders a spec to stdout or a file, with a note above it.
//
// Shared with init so both commands write the same shape. The note is a
// comment, so the output stays a loadable spec whether it is read or piped.
func emitSpec(stdout io.Writer, sp *spec.Spec, out, note string) error {
	b, err := yaml.Marshal(sp)
	if err != nil {
		return fmt.Errorf("rendering spec: %w", err)
	}
	body := string(b)
	if note != "" {
		body = note + "\n" + body
	}

	if out == "" {
		fmt.Fprint(stdout, body)
		return nil
	}
	if err := os.WriteFile(out, []byte(body), 0o600); err != nil {
		return fmt.Errorf("writing spec: %w", err)
	}
	fmt.Fprintf(stdout, "wrote %s\n", out)
	return nil
}

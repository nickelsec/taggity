// Command taggity audits published vulnerability advisories and reports where
// their affected version ranges disagree with the source.
//
// This file does wiring only: flag parsing, dependency construction, and exit
// codes. All logic lives in internal packages so that it can be tested without
// spawning a process.
package main

import (
	"errors"
	"fmt"
	"io"
	"os"
)

// version is injected at build time via
// -ldflags "-X main.version=$(git describe --tags)".
var version = "dev"

const banner = `
  ◇──◇──◆──◆──◇
     [ TAGGITY ]
       └─ hunt the tags

  testing where it breaks.
`

const usage = `
Usage:
  taggity check <pkg>@<version> --spec <file>   check one version
  taggity audit --spec <file> --advisory <file> audit an advisory's boundaries
  taggity init --repo <url> --package <name> --file <f> --symbol <s>
               --calls <t> [--indicates fixed]  scaffold a spec
  taggity export --spec <file> --advisory <f>   emit OSV JSON
  taggity version                               print version

Run "taggity <command> -h" for command flags.
`

// errUsage marks a failure that has already printed its own guidance, so main
// does not repeat it as an error line.
var errUsage = errors.New("usage")

func main() {
	if err := run(os.Args[1:], os.Stdout, os.Stderr); err != nil {
		if !errors.Is(err, errUsage) {
			fmt.Fprintln(os.Stderr, "taggity:", err)
		}
		os.Exit(1)
	}
}

// run dispatches a command. Writers are parameters so the CLI can be tested
// without capturing process output.
func run(args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		fmt.Fprint(stdout, banner)
		fmt.Fprint(stdout, usage)
		return nil
	}

	cmd, rest := args[0], args[1:]

	switch cmd {
	case "version", "--version", "-v":
		fmt.Fprintln(stdout, version)
		return nil

	case "help", "--help", "-h":
		fmt.Fprint(stdout, banner)
		fmt.Fprint(stdout, usage)
		return nil

	case "check":
		return runCheck(rest, stdout, stderr)
	case "audit":
		return runAudit(rest, stdout, stderr)
	case "init":
		return runInit(rest, stdout, stderr)
	case "export":
		return runExport(rest, stdout, stderr)

	default:
		fmt.Fprint(stderr, usage)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

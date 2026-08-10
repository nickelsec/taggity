// Command taggity audits published vulnerability advisories and reports where
// their affected version ranges disagree with the source.
//
// This file does wiring only: flag parsing, dependency construction, and exit
// codes. All logic lives in internal packages so that it can be tested without
// spawning a process.
package main

import (
	"fmt"
	"os"
)

// version is injected at build time via
// -ldflags "-X main.version=$(git describe --tags)".
var version = "dev"

const usage = `taggity %s

Determine whether a specific version of a package contains a known vulnerable
construct, and audit published advisories for ranges that disagree.

Usage:
  taggity check <pkg>@<version> --spec <file>   check one version
  taggity audit --spec <file>                   audit one advisory
  taggity init --repo <dir> --vuln-at <f:line>  scaffold a spec
  taggity export --osv --spec <file>            emit OSV JSON
  taggity version                               print version

Run "taggity <command> -h" for command flags.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "taggity:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		fmt.Printf(usage, version)
		return nil
	}

	switch cmd := args[0]; cmd {
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil

	case "help", "--help", "-h":
		fmt.Printf(usage, version)
		return nil

	case "check", "audit", "init", "export":
		// Commands land in later commits. Failing loudly is better than a
		// silent no-op that looks like a working tool.
		return fmt.Errorf("%s: not implemented yet", cmd)

	default:
		fmt.Fprintf(os.Stderr, usage, version)
		return fmt.Errorf("unknown command %q", cmd)
	}
}

# Security policy

## Reporting

Report privately through
[GitHub Security Advisories](https://github.com/nickelsec/taggity/security/advisories/new).
Please don't open a public issue for an unfixed vulnerability.

Include the affected version or commit, and a proof of concept if you have one.
Expect a first reply within a week.

## In scope

taggity reads untrusted input: repository contents, advisory files, and specs
that may come from someone else. In scope:

- Code execution, path traversal, or writes outside the cache directory,
  triggered by a crafted repository, spec, or advisory
- Resource exhaustion from a crafted source file
- Cache poisoning that attributes one package's results to another

A wrong `NOT_VULNERABLE` verdict counts too. If taggity clears a version that
does contain the construct its spec describes, a scanner downstream stays quiet
and nobody gets told to upgrade. Report that through the same channel.

Verdicts wrong the other way, `VULNERABLE` or `UNKNOWN` where the truth is safe,
are ordinary bugs. Open a public issue with a fixture that reproduces it.

## Out of scope

- Vulnerabilities in the packages taggity analyzes. Report those to their
  maintainers.
- Vulnerability shapes the spec vocabulary can't express. Those are documented
  limitations.

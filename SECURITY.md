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

## Out of scope

- Vulnerabilities in the packages taggity analyzes. Report those to their
  maintainers.
- Vulnerability shapes the spec vocabulary can't express. Those are documented
  limitations.

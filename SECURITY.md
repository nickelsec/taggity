# Security Policy

## Reporting a vulnerability in taggity

Report privately through
[GitHub Security Advisories](https://github.com/nickelsec/taggity/security/advisories/new).
Please do not open a public issue for an unfixed vulnerability.

Include a proof of concept where possible, and the affected version or commit.
An initial response should arrive within a week.

## What counts as a vulnerability here

taggity reads untrusted input: repository contents, advisory files, and spec
files that may come from third parties. The following are in scope:

- Code execution, path traversal, or file writes outside the cache directory
  triggered by a crafted repository, spec, or advisory
- Resource exhaustion from a crafted source file that survives parsing limits
- Cache poisoning that causes one package's results to be attributed to another

**Incorrect verdicts are treated as security bugs**, not merely defects. A
version wrongly reported as `NOT_VULNERABLE` means a scanner stays silent and
users are never told to upgrade. If you can construct a case where taggity
clears a version that genuinely contains the construct in the spec, report it
through the same channel.

Verdicts that are wrong in the other direction — reporting `VULNERABLE` or
`UNKNOWN` where the truth is safe — are ordinary bugs. Please open a public
issue with a reproducing fixture.

## Out of scope

- Vulnerabilities in the packages taggity analyzes. Report those to their
  maintainers; that is what this tool exists to help with.
- Missing coverage for a vulnerability shape the spec vocabulary cannot express.
  These are documented limitations, not defects.

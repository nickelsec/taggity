package taggity

// Signals is the result of checking one version. All three slots exist from the
// first release so that later signals add implementations rather than reshaping
// this type; unimplemented ones stay Unevaluated and render as "—".
//
// A signal that was never run must never look like evidence of safety, which is
// why there is no boolean anywhere in this type.
type Signals struct {
	// Present reports whether the vulnerable construct exists in the source.
	Present Verdict

	// Reachable reports whether the construct can be reached from a public
	// entry point. Not implemented yet.
	//
	// When implemented it may assert reachable (which widens the affected set,
	// the safe direction) but must never assert unreachable, which would narrow
	// it on the strength of an analysis that cannot see dynamic dispatch,
	// getattr, plugin registration, or framework magic.
	Reachable Verdict

	// Triggers reports whether a proof-of-concept fires. Not implemented yet.
	//
	// When implemented, a PoC that fires proves Vulnerable, but a PoC that
	// fails yields Unknown, never NotVulnerable: exploits are brittle across
	// versions, and a failure usually means the exploit no longer applies
	// rather than that the vulnerability is gone.
	Triggers Verdict

	// Reason explains an Unknown overall verdict.
	Reason Reason

	// Evidence records how each verdict was reached.
	Evidence []Evidence
}

// Overall collapses the signal vector into a single verdict.
//
// Any signal finding the vulnerability wins, because each is independent
// positive evidence. NotVulnerable requires Present to have positively
// established absence; nothing else can produce it.
func (s Signals) Overall() Verdict {
	if s.Present == Vulnerable || s.Reachable == Vulnerable || s.Triggers == Vulnerable {
		return Vulnerable
	}
	if s.Present == NotVulnerable {
		return NotVulnerable
	}
	return Unknown
}

// Evidence records why a verdict was reached, in enough detail that someone
// with only the repository URL and this record can re-derive the same verdict
// by hand. That is the standard: if a field would be needed to reproduce the
// result, it belongs here.
type Evidence struct {
	// Signal names which signal produced this record, e.g. "present".
	Signal string

	// Verdict is what this signal concluded.
	Verdict Verdict

	// Commit is the full 40-character hash of the tree that was examined.
	Commit string

	// Tag is the tag that resolved to Commit, recording how the version was
	// interpreted. Repositories spell versions inconsistently, so the mapping
	// itself is part of the evidence.
	Tag string

	// File is the repository-relative path that was read, using forward
	// slashes on every platform.
	File string

	// Symbol is the definition that was examined, qualified as Class.method
	// where the spec needed to disambiguate.
	Symbol string

	// StartByte and EndByte bound the matched definition, so the exact bytes
	// behind the verdict can be recovered.
	StartByte, EndByte uint32

	// Rule is the spec rule that was evaluated, e.g. "calls: eval".
	Rule string

	// Matcher and MatcherVersion identify the analysis engine. Parser upgrades
	// can change verdicts, so a verdict is only reproducible alongside the
	// version that produced it.
	Matcher        string
	MatcherVersion string

	// Source records provenance: "static" for direct matching, "alias" for a
	// pinned rename, "llm" for a model-proposed artifact that a human approved.
	Source string

	// Detail is a human-readable summary for terminal output. It is a
	// convenience for reading, never a field that other code parses.
	Detail string
}

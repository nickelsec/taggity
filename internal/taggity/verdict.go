// Package taggity holds the core domain types. It is a leaf package: it must
// never import any other taggity package, so that verdict semantics stay
// independent of how sources are fetched or parsed.
package taggity

// Verdict is the outcome of evaluating one signal against one version.
//
// The zero value is Unevaluated on purpose. A partially populated Signals must
// never look like evidence of safety: any other zero value would mean that
// forgetting to set a field silently claims something about a version.
type Verdict uint8

const (
	// Unevaluated means the signal was never run. It renders as "," and is
	// never a pass.
	Unevaluated Verdict = iota

	// Vulnerable means positive evidence that the vulnerable construct is
	// present.
	Vulnerable

	// NotVulnerable means positive evidence of absence. Only the code-presence
	// signal may produce it, and only when the symbol was found and the
	// construct was not. See the package invariant in doc.go.
	NotVulnerable

	// Unknown means the question could not be answered. It is a first-class
	// answer, never a failure: it tells the researcher exactly where their
	// judgement is still required. Unknown versions are excluded from exported
	// OSV rather than guessed at.
	Unknown
)

// String renders a Verdict for terminal output.
func (v Verdict) String() string {
	switch v {
	case Vulnerable:
		return "VULNERABLE"
	case NotVulnerable:
		return "NOT_VULNERABLE"
	case Unknown:
		return "UNKNOWN"
	default:
		return "—"
	}
}

// Reason explains why a Verdict is Unknown. Reasons are machine-readable so
// that the distribution of Unknowns across a corpus can be measured: a corpus
// dominated by NoTag needs artifact inspection, whereas one dominated by
// SymbolNotFound needs alias repair. Guessing which of those to build is how
// effort gets spent in the wrong place.
type Reason string

const (
	// ReasonNone is the absence of a reason: the verdict is not Unknown.
	ReasonNone Reason = ""

	// ReasonNoTag means the version exists upstream but no git tag resolves to
	// it. This is a resolution failure, never evidence of safety.
	ReasonNoTag Reason = "no_tag"

	// ReasonUnparseableVersion means the version string is not PEP 440.
	ReasonUnparseableVersion Reason = "unparseable_version"

	// ReasonFileAbsent means the spec's file does not exist at that commit.
	ReasonFileAbsent Reason = "file_absent"

	// ReasonSymbolNotFound means no definition matched the spec's symbol,
	// typically because the code was refactored or renamed.
	ReasonSymbolNotFound Reason = "symbol_not_found"

	// ReasonAmbiguousSymbol means several definitions share the spec's symbol
	// name. Answering for either one would be a confident answer to a question
	// the spec did not ask, so the spec must qualify it (Class.method).
	ReasonAmbiguousSymbol Reason = "ambiguous_symbol"

	// ReasonParseFailed means the source could not be parsed.
	ReasonParseFailed Reason = "parse_failed"

	// ReasonUnsupportedRule means the spec asks for a rule kind this build does
	// not implement. A spec written for a newer version must not be evaluated
	// as though its question had been answered.
	ReasonUnsupportedRule Reason = "unsupported_rule"
)

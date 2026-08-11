// Package check implements the primitive: given a spec and a version, decide
// whether that version contains the vulnerable construct, and record enough
// evidence for someone else to re-derive the answer.
package check

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nickelsec/taggity/internal/git"
	"github.com/nickelsec/taggity/internal/predicate"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

// Source supplies the bytes to examine. It is an interface so tests can run
// without a network or a working tree.
type Source interface {
	// Resolve maps a published version to a commit and the tag that produced
	// it, or explains why it could not.
	Resolve(version string) (commit, tag string, reason taggity.Reason)
	// FileAt reads a repository-relative path at a commit.
	FileAt(commit, path string) ([]byte, taggity.Reason)
}

// Checker evaluates specs against versions.
type Checker struct {
	Source Source
}

// New returns a Checker reading from a git repository. The repository is a hard
// precondition: if it cannot be cloned there is no way to answer anything, so
// this fails immediately rather than producing a run of Unknowns.
func New(repoURL string) (*Checker, error) {
	repo, err := git.OpenOrClone(repoURL)
	if err != nil {
		return nil, fmt.Errorf("repository is required: %w", err)
	}
	return &Checker{Source: repo}, nil
}

// Version evaluates one version and returns its signals.
//
// Every early return is Unknown with a reason. Only the predicate may conclude
// that a version is unaffected, and only from positive evidence that the
// construct is absent.
func (c *Checker) Version(s *spec.Spec, version string) taggity.Signals {
	commit, tag, reason := c.Source.Resolve(version)
	if reason != taggity.ReasonNone {
		return unknown(reason, taggity.Evidence{
			Signal:  "present",
			Verdict: taggity.Unknown,
			Rule:    s.RuleString(),
			Detail:  fmt.Sprintf("version %s did not resolve to a tag", version),
		})
	}

	locations := s.Signal.Locations()
	evidence := make([]taggity.Evidence, 0, len(locations))
	verdicts := make([]taggity.Verdict, 0, len(locations))
	reasons := make([]taggity.Reason, 0, len(locations))

	for _, loc := range locations {
		src, reason := c.Source.FileAt(commit, loc.File)
		if reason != taggity.ReasonNone {
			verdicts = append(verdicts, taggity.Unknown)
			reasons = append(reasons, reason)
			evidence = append(evidence, taggity.Evidence{
				Signal:  "present",
				Verdict: taggity.Unknown,
				Commit:  commit,
				Tag:     tag,
				File:    loc.File,
				Rule:    loc.Rule.String(),
				Detail:  fmt.Sprintf("%s not present at %s", loc.File, tag),
			})
			continue
		}

		res := evaluate(src, loc, version)

		// Evidence names the symbol that was examined, not the one the spec
		// asked for, and says so when they differ. A verdict reached through an
		// alias rests on a human's claim that two names are the same construct,
		// which a reader has to be able to see and disagree with.
		symbol, source := loc.Symbol, "static"
		if res.MatchedSymbol != "" && res.MatchedSymbol != loc.Symbol {
			symbol, source = res.MatchedSymbol, "alias"
		}

		verdicts = append(verdicts, res.Verdict)
		reasons = append(reasons, res.Reason)
		evidence = append(evidence, taggity.Evidence{
			Signal:         "present",
			Verdict:        res.Verdict,
			Commit:         commit,
			Tag:            tag,
			File:           loc.File,
			Symbol:         symbol,
			StartByte:      res.Definition.Start,
			EndByte:        res.Definition.End,
			Rule:           loc.Rule.String(),
			Matcher:        predicate.MatcherName,
			MatcherVersion: predicate.MatcherVersion,
			Source:         source,
			Detail:         detail(res, loc),
		})
	}

	verdict, reason := combineAny(verdicts, reasons)
	return taggity.Signals{
		Present:  verdict,
		Reason:   reason,
		Evidence: evidence,
	}
}

// combineAny reduces per-location verdicts under "any": the construct is
// present if it was found anywhere.
//
// The three-valued part is the whole point. A match anywhere is decisive, so
// one location's UNKNOWN cannot suppress another's VULNERABLE. But with no
// match, an UNKNOWN means some location was never really examined, and calling
// that NOT_VULNERABLE would report safety the engine did not establish.
func combineAny(verdicts []taggity.Verdict, reasons []taggity.Reason) (taggity.Verdict, taggity.Reason) {
	if len(verdicts) == 0 {
		return taggity.Unknown, taggity.ReasonUnsupportedRule
	}

	firstUnknown := -1
	for i, v := range verdicts {
		if v == taggity.Vulnerable {
			return taggity.Vulnerable, taggity.ReasonNone
		}
		if v != taggity.NotVulnerable && firstUnknown < 0 {
			firstUnknown = i
		}
	}
	if firstUnknown >= 0 {
		return taggity.Unknown, reasons[firstUnknown]
	}
	// Every location was examined and none matched. The verdict is whatever the
	// predicate already concluded for them, which keeps the sole assignment of
	// NotVulnerable inside internal/predicate.
	return verdicts[0], taggity.ReasonNone
}

// evaluate runs the rule kind the spec asks for.
//
// A rule kind this build does not implement yields Unknown rather than falling
// through to any verdict. Validate rejects such a spec before it reaches here,
// so this is the second of two guards on the same failure.
func evaluate(src []byte, code spec.Code, version string) predicate.Result {
	symbols := symbolsFor(code, version)
	switch code.Rule.Kind() {
	case "calls":
		return predicate.Calls(src, symbols, code.Rule.Calls)
	case "defaults":
		param, value, ok := code.Rule.Default()
		if !ok {
			return predicate.Result{
				Verdict: taggity.Unknown,
				Reason:  taggity.ReasonUnsupportedRule,
			}
		}
		return predicate.Defaults(src, symbols, param, value)
	default:
		return predicate.Result{
			Verdict: taggity.Unknown,
			Reason:  taggity.ReasonUnsupportedRule,
		}
	}
}

// symbolsFor builds the ordered candidate names for one version: the spec's
// symbol first, then any alias whose range covers it.
//
// Order matters and is not an optimisation. Trying the real name first means an
// alias can only answer where the name found nothing, so adding one to a spec
// cannot change a version that already had an answer.
//
// A range naming a version that does not parse covers nothing. Applying a
// rename to releases it was never pinned to is how an alias stops being a fix
// for a missing symbol and starts being a way to match unrelated code.
func symbolsFor(code spec.Code, version string) []string {
	symbols := []string{code.Symbol}
	if len(code.Aliases) == 0 {
		return symbols
	}

	v, ok := git.ParseVersion(version)
	for _, a := range code.Aliases {
		if a.Versions.Unbounded() {
			symbols = append(symbols, a.Symbol)
			continue
		}
		if !ok {
			continue
		}
		if covers(a.Versions, v) {
			symbols = append(symbols, a.Symbol)
		}
	}
	return symbols
}

// covers reports whether v falls in the half-open range [Introduced, Until).
func covers(r spec.Range, v git.Version) bool {
	if r.Introduced != "" {
		lo, ok := git.ParseVersion(r.Introduced)
		if !ok || v.Compare(lo) < 0 {
			return false
		}
	}
	if r.Until != "" {
		hi, ok := git.ParseVersion(r.Until)
		if !ok || v.Compare(hi) >= 0 {
			return false
		}
	}
	return true
}

func detail(res predicate.Result, code spec.Code) string {
	switch res.Reason {
	case taggity.ReasonSymbolNotFound:
		// A symbol goes missing for two very different reasons: the spec has a
		// typo, or the code moved and this version genuinely lacks it. Naming
		// the closest definitions in the file separates them at a glance, which
		// is the difference between fixing a spec and investigating a version.
		if near := nearest(code.Symbol, res.Candidates); len(near) > 0 {
			return fmt.Sprintf("symbol %s not found; did you mean %s?",
				code.Symbol, strings.Join(near, ", "))
		}
		return fmt.Sprintf("symbol %s not found", code.Symbol)
	case taggity.ReasonAmbiguousSymbol:
		return fmt.Sprintf("symbol %s is defined %d times; qualify it as Class.method",
			code.Symbol, len(res.Candidates))
	case taggity.ReasonParseFailed:
		return "source did not parse"
	case taggity.ReasonUnsupportedRule:
		return "this build does not implement the rule kind the spec asks for"
	default:
		// The name that resolved leads the line. When an alias answered it is
		// not the spec's symbol, and reporting the spec's name would describe
		// code that was never read at this version.
		symbol := code.Symbol
		via := ""
		if res.MatchedSymbol != "" && res.MatchedSymbol != code.Symbol {
			symbol = res.MatchedSymbol
			via = fmt.Sprintf(" (alias for %s)", code.Symbol)
		}
		if param, value, ok := code.Rule.Default(); ok {
			return fmt.Sprintf("%s declares %s=%s%s", symbol, param, value, via)
		}
		return fmt.Sprintf("%s calls %s%s", symbol, code.Rule.Calls, via)
	}
}

// nearest picks the candidate names closest to want, so a not-found message can
// suggest a correction instead of listing every definition in the file.
//
// Closeness is prefix and suffix overlap rather than an edit distance. The
// names that matter here are long and structured: a typo shares a long prefix,
// and a private method promoted to a module function shares everything but the
// leading underscore. Nothing is suggested when no name shares a meaningful run
// with want, because a wrong guess sends the reader off to fix a spec that was
// already correct.
func nearest(want string, candidates []string) []string {
	const (
		minOverlap  = 4
		maxSuggest  = 3
		strongMatch = 8
	)

	type scored struct {
		name    string
		overlap int
	}

	// Compare on the bare name: a spec says Class.method, the file may define
	// the same method under a class that was renamed.
	bare := want
	if i := strings.LastIndex(want, "."); i >= 0 {
		bare = want[i+1:]
	}

	var found []scored
	for _, c := range candidates {
		if c == want {
			continue
		}
		n := max(commonPrefix(bare, c), commonSuffix(bare, c))
		if n >= minOverlap {
			found = append(found, scored{c, n})
		}
	}

	sort.SliceStable(found, func(i, j int) bool {
		return found[i].overlap > found[j].overlap
	})

	// A single strong match is a likely typo and worth naming alone. Several
	// weak ones are a list of everything vaguely similar, which is noise.
	if len(found) > 1 && found[0].overlap >= strongMatch && found[1].overlap < strongMatch {
		found = found[:1]
	}
	if len(found) > maxSuggest {
		found = found[:maxSuggest]
	}

	out := make([]string, 0, len(found))
	for _, f := range found {
		out = append(out, f.name)
	}
	return out
}

func commonPrefix(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[n] == b[n] {
		n++
	}
	return n
}

func commonSuffix(a, b string) int {
	n := 0
	for n < len(a) && n < len(b) && a[len(a)-1-n] == b[len(b)-1-n] {
		n++
	}
	return n
}

func unknown(r taggity.Reason, ev taggity.Evidence) taggity.Signals {
	return taggity.Signals{
		Present:  taggity.Unknown,
		Reason:   r,
		Evidence: []taggity.Evidence{ev},
	}
}

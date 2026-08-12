package taggity

import "testing"

// Affected is the only place a verdict is allowed to change meaning, so what it
// may and may not do is pinned here rather than left to the display code.
//
// The bug it exists to prevent: `check` printed the engine's raw verdict as its
// headline, so on a guard-shaped spec a genuinely vulnerable version reported
// NOT_VULNERABLE, in green, with a note underneath asking the reader to invert
// it themselves. Seven of the sixteen corpus specs are guard-shaped.
func TestAffectedReadsVerdictAgainstPolarity(t *testing.T) {
	cases := []struct {
		name                 string
		in                   Verdict
		matchMeansVulnerable bool
		want                 Verdict
	}{
		// A rule matching the danger asks the same question the reader asked,
		// so nothing moves. This is 9 of the 16 corpus specs and every spec
		// that omits `indicates`.
		{"danger-shaped, found", Vulnerable, true, Vulnerable},
		{"danger-shaped, absent", NotVulnerable, true, NotVulnerable},

		// A rule matching the guard asks the opposite question. Finding the
		// fix means the version is patched.
		{"guard-shaped, fix found", Vulnerable, false, NotVulnerable},
		{"guard-shaped, fix absent", NotVulnerable, false, Vulnerable},

		// The invariant. An unanswered question stays unanswered under either
		// polarity: inverting it would turn "the file was not there" into a
		// claim about safety.
		{"unknown stays unknown", Unknown, true, Unknown},
		{"unknown stays unknown when inverted", Unknown, false, Unknown},
		{"unevaluated stays unevaluated", Unevaluated, true, Unevaluated},
		{"unevaluated stays unevaluated when inverted", Unevaluated, false, Unevaluated},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.Affected(c.matchMeansVulnerable); got != c.want {
				t.Errorf("%v.Affected(%v) = %v, want %v",
					c.in, c.matchMeansVulnerable, got, c.want)
			}
		})
	}
}

// Applying the reading twice must return the original. A verdict that drifted
// under repeated reads would make the same version report differently depending
// on how many display layers it passed through.
func TestAffectedIsSelfInverse(t *testing.T) {
	for _, v := range []Verdict{Unevaluated, Vulnerable, NotVulnerable, Unknown} {
		if got := v.Affected(false).Affected(false); got != v {
			t.Errorf("%v read twice = %v, want %v", v, got, v)
		}
		if got := v.Affected(true); got != v {
			t.Errorf("%v under danger-shaped polarity = %v, want unchanged", v, got)
		}
	}
}

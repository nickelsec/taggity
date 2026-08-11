package taggity

import "testing"

// TestDecidingNamesTheLocationThatAnswered covers the case a multi-location
// spec hits constantly: the symbol moved between files across the version
// range, so at any one tag the listed-first location is absent and a later one
// carries the verdict.
func TestDecidingNamesTheLocationThatAnswered(t *testing.T) {
	cases := []struct {
		name string
		in   Signals
		want string // File of the expected record, "" for the zero Evidence
	}{
		{
			"no evidence at all",
			Signals{},
			"",
		},
		{
			"single location decides alone",
			Signals{
				Present:  Vulnerable,
				Evidence: []Evidence{{File: "only.py", Verdict: Vulnerable}},
			},
			"only.py",
		},
		{
			"a later match wins over an earlier file_absent",
			Signals{
				Present: Vulnerable,
				Evidence: []Evidence{
					{File: "moved_to.py", Verdict: Unknown},
					{File: "lives_here.py", Verdict: Vulnerable},
					{File: "old.py", Verdict: Unknown},
				},
			},
			"lives_here.py",
		},
		{
			"first match wins when several match",
			Signals{
				Present: Vulnerable,
				Evidence: []Evidence{
					{File: "a.py", Verdict: Vulnerable},
					{File: "b.py", Verdict: Vulnerable},
				},
			},
			"a.py",
		},
		{
			"every location unreadable reports one of them, not a match",
			Signals{
				Present: Unknown,
				Evidence: []Evidence{
					{File: "a.py", Verdict: Unknown},
					{File: "b.py", Verdict: Unknown},
				},
			},
			"a.py",
		},
		{
			"proved absence reports the location that was actually read",
			Signals{
				Present: NotVulnerable,
				Evidence: []Evidence{
					{File: "absent.py", Verdict: Unknown},
					{File: "read.py", Verdict: NotVulnerable},
				},
			},
			"read.py",
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := c.in.Deciding().File; got != c.want {
				t.Errorf("Deciding().File = %q, want %q", got, c.want)
			}
		})
	}
}

// A match is decisive even when Present disagrees, which is what separates the
// two selection passes. Present can be Unknown while one location matched:
// combineAny returns Vulnerable on any match, and a future signal may set the
// verdict independently. Reporting a "not present" record next to a VULNERABLE
// verdict is the contradiction this guards.
func TestDecidingPrefersAMatchOverAgreementWithPresent(t *testing.T) {
	s := Signals{
		Present: Unknown,
		Evidence: []Evidence{
			{File: "absent.py", Verdict: Unknown},
			{File: "matched.py", Verdict: Vulnerable},
		},
	}
	if got := s.Deciding().File; got != "matched.py" {
		t.Errorf("Deciding().File = %q, want matched.py: a location that found\n"+
			"the construct outranks one that merely agrees with Present", got)
	}
}

// TestDecidingCarriesTheConcludedVerdict is the property that matters: when
// Present was established from the locations, the reported record must carry
// that verdict rather than some other location's. A summary line pairing a
// VULNERABLE verdict with a different location's failure text is how this bug
// first surfaced.
//
// This holds whenever Present came from combineAny. It does not hold when a
// signal outside the location set decides, which
// TestDecidingPrefersAMatchOverAgreementWithPresent covers.
func TestDecidingCarriesTheConcludedVerdict(t *testing.T) {
	cases := []Signals{
		{
			Present: Vulnerable,
			Evidence: []Evidence{
				{File: "a.py", Verdict: Unknown},
				{File: "b.py", Verdict: Vulnerable},
			},
		},
		{
			Present: NotVulnerable,
			Evidence: []Evidence{
				{File: "a.py", Verdict: Unknown},
				{File: "b.py", Verdict: NotVulnerable},
			},
		},
		{
			Present:  Unknown,
			Evidence: []Evidence{{File: "a.py", Verdict: Unknown}},
		},
	}

	for _, s := range cases {
		if got := s.Deciding().Verdict; got != s.Present {
			t.Errorf("Deciding().Verdict = %v, but Present = %v: the reported\n"+
				"record must be the one that produced the verdict", got, s.Present)
		}
	}
}

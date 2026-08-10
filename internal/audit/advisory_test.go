package audit_test

import (
	"errors"
	"strings"
	"testing"

	"github.com/nickelsec/taggity/internal/audit"
)

// Auditing a spec against an advisory it does not name produces a confident
// report about the wrong thing — and in export, an OSV document stamped with
// one advisory's ID over another's findings. That has to fail, not warn.
func TestCheckAdvisoryMatch(t *testing.T) {
	cases := []struct {
		name         string
		specAdvisory string
		advisoryID   string
		wantErr      bool
	}{
		{
			name:         "match",
			specAdvisory: "GHSA-8fww-64cx-x8p5",
			advisoryID:   "GHSA-8fww-64cx-x8p5",
		},
		{
			// The field is optional, so a spec may be reused across advisories.
			name:         "spec names no advisory",
			specAdvisory: "",
			advisoryID:   "GHSA-8fww-64cx-x8p5",
		},
		{
			name:         "mismatch",
			specAdvisory: "GHSA-8fww-64cx-x8p5",
			advisoryID:   "PYSEC-2026-564",
			wantErr:      true,
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := audit.CheckAdvisoryMatch(c.specAdvisory, c.advisoryID)
			if (err != nil) != c.wantErr {
				t.Fatalf("err = %v, wantErr %v", err, c.wantErr)
			}
			if err == nil {
				return
			}
			if !errors.Is(err, audit.ErrAdvisoryMismatch) {
				t.Errorf("error does not wrap ErrAdvisoryMismatch: %v", err)
			}
			// A reader has to be able to see which two disagreed.
			for _, want := range []string{c.specAdvisory, c.advisoryID} {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("error should name %q, got: %v", want, err)
				}
			}
		})
	}
}

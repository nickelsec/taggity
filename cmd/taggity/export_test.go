package main

import (
	"testing"

	"github.com/nickelsec/taggity/internal/audit"
	"github.com/nickelsec/taggity/internal/spec"
	"github.com/nickelsec/taggity/internal/taggity"
)

func testSpec(indicates string) *spec.Spec {
	sp := &spec.Spec{Repo: "https://github.com/x/y"}
	sp.Package.Ecosystem = "PyPI"
	sp.Package.Name = "foo"
	sp.Signal.Code.File = "a.py"
	sp.Signal.Code.Symbol = "f"
	sp.Signal.Code.Rule.Calls = "eval"
	sp.Signal.Code.Rule.Indicates = indicates
	return sp
}

func result(version string, outcome audit.Outcome, v taggity.Verdict, reason taggity.Reason) audit.Result {
	return audit.Result{
		Boundary: audit.Boundary{Version: version},
		Signals:  taggity.Signals{Present: v, Reason: reason},
		Outcome:  outcome,
	}
}

// An unreviewed disagreement must never be published as an affected version.
//
// On redis-py the disagreements looked like unpatched releases and turned out
// to be a guard that had been deliberately replaced. Emitting them here would
// have produced a machine-readable claim that was wrong, which is the exact
// failure the design warns about.
func TestExportExcludesUnreviewedDisagreements(t *testing.T) {
	rep := &audit.Report{
		AdvisoryID: "GHSA-test",
		Results: []audit.Result{
			result("4.4.3", audit.Consistent, taggity.Vulnerable, ""),
			result("5.3.1", audit.Disagreement, taggity.Vulnerable, ""),
			result("2.1.0", audit.Indeterminate, taggity.Unknown, taggity.ReasonFileAbsent),
		},
	}

	doc := buildOSV(rep, testSpec(""))
	a := doc.Affected[0]

	if len(a.Versions) != 1 || a.Versions[0] != "4.4.3" {
		t.Errorf("affected = %v, want only the established version", a.Versions)
	}

	ts, ok := a.DatabaseSpecific["taggity"].(map[string]any)
	if !ok {
		t.Fatal("provenance block missing")
	}
	disputed, _ := ts["disputed_unreviewed"].([]string)
	if len(disputed) != 1 || disputed[0] != "5.3.1" {
		t.Errorf("disputed = %v, want the disagreement recorded but not claimed", disputed)
	}
	gaps, _ := ts["indeterminate"].([]string)
	if len(gaps) != 1 || gaps[0] != "2.1.0" {
		t.Errorf("indeterminate = %v, want the unreadable version recorded", gaps)
	}
	if ts["partial"] != true {
		t.Error("a run with gaps or disputes must be marked partial")
	}
}

// An UNKNOWN is not evidence of safety, so it is excluded from the claim and
// recorded where a reader can see it.
func TestExportNeverClaimsUnknownVersions(t *testing.T) {
	rep := &audit.Report{
		AdvisoryID: "GHSA-test",
		Results: []audit.Result{
			result("1.0.0", audit.Indeterminate, taggity.Unknown, taggity.ReasonNoTag),
			result("2.0.0", audit.Indeterminate, taggity.Unknown, taggity.ReasonSymbolNotFound),
		},
	}

	doc := buildOSV(rep, testSpec(""))
	if got := doc.Affected[0].Versions; len(got) != 0 {
		t.Errorf("affected = %v, want empty: nothing was established", got)
	}
}

// With inverted polarity the absence of the guard is what marks a version
// affected, so the mapping from verdict to claim flips.
func TestExportRespectsPolarity(t *testing.T) {
	rep := &audit.Report{
		AdvisoryID: "GHSA-test",
		Results: []audit.Result{
			// Guard present: fixed, so not affected.
			result("2.0.0", audit.Consistent, taggity.Vulnerable, ""),
			// Guard absent within the claimed range: affected.
			result("1.9.0", audit.Consistent, taggity.NotVulnerable, ""),
		},
	}

	doc := buildOSV(rep, testSpec(spec.IndicatesFixed))
	got := doc.Affected[0].Versions
	if len(got) != 1 || got[0] != "1.9.0" {
		t.Errorf("affected = %v, want only the version missing the guard", got)
	}
}

func TestExportRecordsMatcherVersion(t *testing.T) {
	rep := &audit.Report{AdvisoryID: "GHSA-test"}
	doc := buildOSV(rep, testSpec(""))

	ts, ok := doc.Affected[0].DatabaseSpecific["taggity"].(map[string]any)
	if !ok {
		t.Fatal("provenance block missing")
	}
	// A parser upgrade can change verdicts, so a verdict is only reproducible
	// alongside the version that produced it.
	if ts["matcher_version"] == "" || ts["matcher"] == "" {
		t.Error("provenance must name the matcher and its version")
	}
	if ts["not_a_full_range_scan"] != true {
		t.Error("output must not imply every version was examined")
	}
}

// Provenance lists every location a spec named, not one of them.
//
// Across a version range the answering location changes as code moves between
// files, so no single file and symbol describes the report. Naming one puts a
// path into machine-readable output that need not exist in every tree probed,
// and unlike terminal output nobody reads this before it is consumed.
func TestExportRecordsEveryLocation(t *testing.T) {
	sp := &spec.Spec{Repo: "https://github.com/x/y"}
	sp.Package.Ecosystem = "PyPI"
	sp.Package.Name = "foo"
	for _, loc := range []struct{ file, symbol, calls string }{
		{"new/place.py", "build_urls", "urls.append"},
		{"old/place.py", "Client._discover", "httpx.Request"},
	} {
		c := spec.Code{File: loc.file, Symbol: loc.symbol}
		c.Rule.Calls = loc.calls
		sp.Signal.CodeAny = append(sp.Signal.CodeAny, c)
	}

	doc := buildOSV(&audit.Report{AdvisoryID: "GHSA-test"}, sp)
	ts, ok := doc.Affected[0].DatabaseSpecific["taggity"].(map[string]any)
	if !ok {
		t.Fatal("provenance block missing")
	}

	locs, ok := ts["locations"].([]map[string]string)
	if !ok {
		t.Fatalf("locations = %T, want a list of every location probed", ts["locations"])
	}
	if len(locs) != 2 {
		t.Fatalf("locations = %d, want 2: every location the spec named", len(locs))
	}

	seen := map[string]bool{}
	for _, l := range locs {
		seen[l["file"]] = true
		if l["symbol"] == "" || l["rule"] == "" {
			t.Errorf("location %q lost its symbol or rule: %v", l["file"], l)
		}
	}
	if !seen["new/place.py"] || !seen["old/place.py"] {
		t.Errorf("locations = %v, want both files", locs)
	}
}

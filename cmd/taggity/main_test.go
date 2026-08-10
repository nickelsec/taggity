package main

import (
	"bytes"
	"reflect"
	"strings"
	"testing"
)

func TestBannerOnBareInvocation(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run(nil, &out, &errOut); err != nil {
		t.Fatalf("bare invocation returned %v", err)
	}
	for _, want := range []string{"TAGGITY", "hunt the tags", "taggity check", "taggity audit"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("banner output missing %q", want)
		}
	}
	if errOut.Len() != 0 {
		t.Errorf("bare invocation wrote to stderr: %q", errOut.String())
	}
}

func TestUnknownCommandFailsWithUsage(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"nonsense"}, &out, &errOut)
	if err == nil {
		t.Fatal("unknown command should fail")
	}
	if !strings.Contains(errOut.String(), "taggity check") {
		t.Error("usage should go to stderr so it does not pollute piped output")
	}
}

func TestVersionGoesToStdout(t *testing.T) {
	var out, errOut bytes.Buffer
	if err := run([]string{"version"}, &out, &errOut); err != nil {
		t.Fatalf("version returned %v", err)
	}
	if strings.TrimSpace(out.String()) == "" {
		t.Error("version printed nothing")
	}
}

// Go's flag package stops parsing at the first non-flag argument, so a naive
// implementation drops every flag written after the positional. That is the
// natural way to type the command, and it silently ignored --spec.
func TestExtractPositionalAcceptsFlagsOnEitherSide(t *testing.T) {
	cases := []struct {
		name     string
		args     []string
		wantPos  string
		wantRest []string
	}{
		{
			name:     "flags after positional",
			args:     []string{"redis@4.5.4", "--spec", "s.yaml"},
			wantPos:  "redis@4.5.4",
			wantRest: []string{"--spec", "s.yaml"},
		},
		{
			name:     "flags before positional",
			args:     []string{"--spec", "s.yaml", "redis@4.5.4"},
			wantPos:  "redis@4.5.4",
			wantRest: []string{"--spec", "s.yaml"},
		},
		{
			name:     "equals form carries its own value",
			args:     []string{"--spec=s.yaml", "redis@4.5.4"},
			wantPos:  "redis@4.5.4",
			wantRest: []string{"--spec=s.yaml"},
		},
		{
			name:     "boolean flag consumes nothing",
			args:     []string{"--quiet", "redis@4.5.4"},
			wantPos:  "redis@4.5.4",
			wantRest: []string{"--quiet"},
		},
		{
			name:     "boolean flag between value flag and positional",
			args:     []string{"--quiet", "--spec", "s.yaml", "redis@4.5.4"},
			wantPos:  "redis@4.5.4",
			wantRest: []string{"--quiet", "--spec", "s.yaml"},
		},
		{
			name:     "no positional",
			args:     []string{"--spec", "s.yaml"},
			wantPos:  "",
			wantRest: []string{"--spec", "s.yaml"},
		},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			pos, rest := extractPositional(c.args)
			if pos != c.wantPos {
				t.Errorf("positional = %q, want %q", pos, c.wantPos)
			}
			if !reflect.DeepEqual(rest, c.wantRest) {
				t.Errorf("rest = %v, want %v", rest, c.wantRest)
			}
		})
	}
}

func TestSplitTarget(t *testing.T) {
	cases := []struct {
		in       string
		pkg, ver string
		wantErr  bool
	}{
		{in: "redis@4.5.4", pkg: "redis", ver: "4.5.4"},
		{in: "4.5.4", pkg: "", ver: "4.5.4"},
		{in: "@4.5.4", pkg: "", ver: "4.5.4"},
		// Local versions contain '+', and the split must take the last '@' so
		// package names are never confused with version metadata.
		{in: "foo@1.0.0+local", pkg: "foo", ver: "1.0.0+local"},
		{in: "", wantErr: true},
	}
	for _, c := range cases {
		pkg, ver, err := splitTarget(c.in)
		if (err != nil) != c.wantErr {
			t.Errorf("%q: err = %v, wantErr %v", c.in, err, c.wantErr)
			continue
		}
		if err != nil {
			continue
		}
		if pkg != c.pkg || ver != c.ver {
			t.Errorf("%q: got (%q, %q), want (%q, %q)", c.in, pkg, ver, c.pkg, c.ver)
		}
	}
}

func TestCheckRequiresSpec(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"check", "redis@4.5.4"}, &out, &errOut)
	if err == nil {
		t.Fatal("check without --spec should fail rather than guess")
	}
	if !strings.Contains(err.Error(), "spec") {
		t.Errorf("error should name the missing flag, got %v", err)
	}
}

func TestAuditRequiresBothInputs(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"audit", "--spec", "s.yaml"}, &out, &errOut)
	if err == nil {
		t.Fatal("audit without --advisory should fail")
	}
}

func TestInitRejectsIncompleteSpec(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{"init", "--repo", "https://github.com/x/y"}, &out, &errOut)
	if err == nil {
		t.Fatal("init should refuse to write a spec that cannot be evaluated")
	}
	if out.Len() != 0 {
		t.Error("a rejected init must not emit a partial spec")
	}
}

func TestInitProducesLoadableSpec(t *testing.T) {
	var out, errOut bytes.Buffer
	err := run([]string{
		"init",
		"--repo", "https://github.com/example/foo",
		"--package", "foo",
		"--file", "src/parser.py",
		"--symbol", "Alpha.parse",
		"--calls", "eval",
	}, &out, &errOut)
	if err != nil {
		t.Fatalf("init returned %v", err)
	}
	for _, want := range []string{"repo:", "symbol: Alpha.parse", "calls: eval", "mode: manual"} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("generated spec missing %q\n%s", want, out.String())
		}
	}
}

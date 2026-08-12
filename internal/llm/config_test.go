package llm

import (
	"errors"
	"os"
	"strings"
	"testing"
)

// The config file holds an API key, so the key must never appear in anything
// printed. A tool whose subject is supply-chain metadata should not be the one
// leaking credentials into a terminal or a log.
func TestRedactedNeverShowsTheKey(t *testing.T) {
	cfg := &Config{
		Provider: ProviderOpenRouter,
		Model:    "anthropic/claude-sonnet-4.5",
		// #nosec G101 -- not a credential, a marker this test greps for.
		APIKey: "sk-or-v1-" + "secret-value",
	}

	got := cfg.Redacted()
	if strings.Contains(got, "secret-value") {
		t.Errorf("the key appears in printed output:\n%s", got)
	}
	if !strings.Contains(got, "set") {
		t.Errorf("output should say whether a key is present:\n%s", got)
	}
	// The parts that are safe to show still have to be shown, or the command
	// tells the user nothing.
	for _, want := range []string{ProviderOpenRouter, "claude-sonnet-4.5"} {
		if !strings.Contains(got, want) {
			t.Errorf("output dropped %q:\n%s", want, got)
		}
	}
}

func TestRedactedSaysWhenNoKeyIsStored(t *testing.T) {
	cfg := &Config{Provider: ProviderAnthropic}
	if got := cfg.Redacted(); !strings.Contains(got, "not set") {
		t.Errorf("a missing key should say so:\n%s", got)
	}
}

// The environment always wins. CI must not depend on a file that is not in the
// repository, and overriding one run without editing a file has to stay
// possible.
func TestFromConfigPrefersTheEnvironment(t *testing.T) {
	t.Setenv(OpenRouterKeyEnv, "from-the-environment")
	t.Setenv(KeyEnv, "")

	// No config file in the test environment, so the provider is picked from
	// whichever key is set. A scripted run needs no config at all.
	p, err := FromConfig("", "")
	if err != nil {
		t.Fatalf("no provider from an environment key alone: %v", err)
	}
	if p.Name() != ProviderOpenRouter {
		t.Errorf("provider = %q, want %q: the key in the environment decides",
			p.Name(), ProviderOpenRouter)
	}

	or, ok := p.(*OpenRouter)
	if !ok {
		t.Fatalf("provider is %T, want *OpenRouter", p)
	}
	if or.APIKey != "from-the-environment" {
		t.Error("the environment key was not used")
	}
}

func TestFromConfigRejectsAnUnknownProvider(t *testing.T) {
	t.Setenv(KeyEnv, "x")
	if _, err := FromConfig("hermes", ""); err == nil {
		t.Error("accepted an unknown provider")
	} else if !strings.Contains(err.Error(), "hermes") {
		t.Errorf("error should name the provider, got: %v", err)
	}
}

// Drafting needs a key; checking never does. The error has to say which,
// because "no API key" on a check would send someone hunting for a setting that
// does not exist.
func TestNoKeyIsAClearError(t *testing.T) {
	t.Setenv(KeyEnv, "")
	t.Setenv(OpenRouterKeyEnv, "")

	_, err := NewAnthropicWithKey("", "")
	if err == nil {
		t.Fatal("built a provider with no key")
	}
	for _, want := range []string{"configure", KeyEnv} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error should mention %q, got: %v", want, err)
		}
	}

	if _, err := NewOpenRouter("", ""); err == nil {
		t.Error("built an OpenRouter provider with no key")
	}
}

// A stored model is a default, not a lock: one run should be overridable
// without editing a file.
func TestFromConfigModelOverride(t *testing.T) {
	t.Setenv(KeyEnv, "x")

	p, err := FromConfig(ProviderAnthropic, "claude-opus-4-20250514")
	if err != nil {
		t.Fatalf("FromConfig: %v", err)
	}
	if p.Model() != "claude-opus-4-20250514" {
		t.Errorf("model = %q, want the override", p.Model())
	}
}

func TestLoadConfigReportsAbsenceDistinctly(t *testing.T) {
	// The config directory is per-user and this test must not write to it, so
	// this only asserts on the sentinel when nothing is there.
	if _, err := os.Stat(mustConfigPath(t)); err == nil {
		t.Skip("a real config exists on this machine")
	}

	_, err := LoadConfig()
	if !errors.Is(err, ErrNoConfig) {
		t.Errorf("err = %v, want ErrNoConfig: a missing file is not a failure, "+
			"it is the ordinary state before configure runs", err)
	}
}

func mustConfigPath(t *testing.T) string {
	t.Helper()
	p, err := ConfigPath()
	if err != nil {
		t.Fatalf("ConfigPath: %v", err)
	}
	return p
}

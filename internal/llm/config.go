package llm

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"gopkg.in/yaml.v3"
)

// Provider names, as written in the config file and in a spec's authoring
// block.
const (
	ProviderAnthropic  = "anthropic"
	ProviderOpenRouter = "openrouter"
)

// Config is what `taggity configure` writes.
//
// It holds a key, so it is written 0600 and refused if the permissions are
// looser. That is the standard ssh holds for a private key, and a tool whose
// subject is supply-chain metadata should not be the one leaving credentials
// group-readable.
type Config struct {
	Provider string `yaml:"provider"`
	Model    string `yaml:"model,omitempty"`
	APIKey   string `yaml:"api_key,omitempty"`
}

// ConfigPath is where the config lives.
func ConfigPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", fmt.Errorf("finding the config directory: %w", err)
	}
	return filepath.Join(dir, "taggity", "config.yaml"), nil
}

// ErrNoConfig reports that no config file exists.
var ErrNoConfig = errors.New("no taggity config")

// LoadConfig reads the config file, if there is one.
func LoadConfig() (*Config, error) {
	path, err := ConfigPath()
	if err != nil {
		return nil, err
	}

	info, err := os.Stat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, ErrNoConfig
	}
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	// Windows permission bits do not mean what they mean elsewhere, so the
	// check would reject every valid file there.
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return nil, fmt.Errorf(
			"%s is readable by other users (mode %04o): it holds an API key.\n"+
				"Fix it with: chmod 600 %s",
			path, info.Mode().Perm(), path)
	}

	// #nosec G304 -- the path is this tool's own config, in the user's config
	// directory.
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("reading %s: %w", path, err)
	}

	var c Config
	if err := yaml.Unmarshal(b, &c); err != nil {
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	return &c, nil
}

// Save writes the config with owner-only permissions.
func (c *Config) Save() (string, error) {
	path, err := ConfigPath()
	if err != nil {
		return "", err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return "", fmt.Errorf("creating %s: %w", filepath.Dir(path), err)
	}

	// #nosec G117 -- storing the key is the point of this file, which is why it
	// is written 0600 and refused when the permissions loosen. Redacted is what
	// prints it, and never shows the key.
	b, err := yaml.Marshal(c)
	if err != nil {
		return "", fmt.Errorf("rendering config: %w", err)
	}
	if err := os.WriteFile(path, b, 0o600); err != nil {
		return "", fmt.Errorf("writing %s: %w", path, err)
	}
	return path, nil
}

// Redacted renders the config for printing. The key never appears.
func (c *Config) Redacted() string {
	key := "not set"
	if c.APIKey != "" {
		key = "set"
	}
	model := c.Model
	if model == "" {
		model = "(provider default)"
	}
	return fmt.Sprintf("provider: %s\nmodel:    %s\napi key:  %s",
		c.Provider, model, key)
}

// keyEnvFor names the environment variable that overrides a provider's stored
// key.
func keyEnvFor(provider string) string {
	if provider == ProviderOpenRouter {
		return OpenRouterKeyEnv
	}
	return KeyEnv
}

// FromConfig builds a provider from the config file and the environment.
//
// The environment always wins. A stored key is a convenience; CI must not
// depend on a file that is not in the repository, and overriding one run
// without editing a file has to stay possible.
//
// provider and model override both when non-empty, so a single --model flag can
// change one run.
func FromConfig(provider, model string) (Provider, error) {
	cfg, err := LoadConfig()
	if err != nil && !errors.Is(err, ErrNoConfig) {
		// A permissions problem is worth reporting rather than falling back to
		// the environment: silently ignoring it would leave the file exposed.
		return nil, err
	}
	if cfg == nil {
		cfg = &Config{}
	}

	if provider == "" {
		provider = cfg.Provider
	}
	if model == "" {
		model = cfg.Model
	}

	// No provider anywhere: pick whichever key is in the environment, so a
	// scripted run needs no config at all.
	if provider == "" {
		switch {
		case os.Getenv(OpenRouterKeyEnv) != "":
			provider = ProviderOpenRouter
		default:
			provider = ProviderAnthropic
		}
	}

	key := os.Getenv(keyEnvFor(provider))
	if key == "" {
		key = cfg.APIKey
	}

	switch provider {
	case ProviderOpenRouter:
		return NewOpenRouter(key, model)
	case ProviderAnthropic:
		return NewAnthropicWithKey(key, model)
	default:
		return nil, fmt.Errorf("unknown provider %q: use %q or %q",
			provider, ProviderAnthropic, ProviderOpenRouter)
	}
}

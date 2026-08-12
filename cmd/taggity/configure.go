package main

import (
	"bufio"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/nickelsec/taggity/internal/llm"
)

// providerChoices are what the prompt offers, in order.
var providerChoices = []struct {
	name  string
	label string
	env   string
}{
	{llm.ProviderAnthropic, "Anthropic", llm.KeyEnv},
	{llm.ProviderOpenRouter, "OpenRouter (many models behind one key)", llm.OpenRouterKeyEnv},
}

func runConfigure(args []string, stdout, stderr io.Writer) error {
	fs := flag.NewFlagSet("configure", flag.ContinueOnError)
	fs.SetOutput(stderr)
	var (
		provider = fs.String("provider", "", "anthropic or openrouter")
		model    = fs.String("model", "", "model to draft with")
		show     = fs.Bool("show", false, "print the current settings and exit")
	)
	fs.Usage = func() {
		fmt.Fprint(stderr, `
Usage: taggity configure

Asks which model to draft with and stores the answer, so `+"`taggity draft`"+`
works without an environment variable.

The file is written owner-only and taggity refuses to read it if that changes.
An environment variable always wins over the stored key, so CI needs no file
and a single run can override one.

Non-interactive:
  taggity configure --provider openrouter --model anthropic/claude-sonnet-4.5

Flags:
`)
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return errUsage
	}

	if *show {
		return showConfig(stdout)
	}

	// Flags given: write them without prompting, so this is scriptable. The key
	// comes from the environment in that case rather than from an argument,
	// because a key on a command line lands in shell history.
	if *provider != "" || *model != "" {
		return writeConfig(stdout, *provider, *model, "")
	}
	return promptConfigure(stdout, stderr)
}

func showConfig(stdout io.Writer) error {
	cfg, err := llm.LoadConfig()
	if errors.Is(err, llm.ErrNoConfig) {
		path, _ := llm.ConfigPath()
		fmt.Fprintf(stdout, "no config at %s\nrun `taggity configure`\n", path)
		return nil
	}
	if err != nil {
		return err
	}
	path, _ := llm.ConfigPath()
	fmt.Fprintf(stdout, "%s\n\n%s\n", path, cfg.Redacted())
	return nil
}

// promptConfigure walks through the settings.
//
// The only interactive command in the tool. Everything else is flags in, text
// out, and --provider keeps it that way for anything scripted.
func promptConfigure(stdout, _ io.Writer) error {
	in := bufio.NewReader(os.Stdin)

	fmt.Fprintln(stdout, "\nWhich model should taggity draft with?")
	for i, c := range providerChoices {
		fmt.Fprintf(stdout, "  %d) %s\n", i+1, c.label)
	}
	fmt.Fprint(stdout, "\nChoice [1]: ")

	line, err := in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading your choice: %w", err)
	}
	choice := providerChoices[0]
	switch strings.TrimSpace(line) {
	case "", "1":
	case "2":
		choice = providerChoices[1]
	default:
		return fmt.Errorf("pick 1 or 2, got %q", strings.TrimSpace(line))
	}

	fmt.Fprintf(stdout, "\nModel [%s]: ", defaultModelFor(choice.name))
	line, err = in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading the model: %w", err)
	}
	model := strings.TrimSpace(line)

	// An already-set environment variable wins anyway, so asking for a key
	// would store one that never gets used.
	if os.Getenv(choice.env) != "" {
		fmt.Fprintf(stdout, "\n%s is already set; using it.\n", choice.env)
		return writeConfig(stdout, choice.name, model, "")
	}

	fmt.Fprintf(stdout, "\nAPI key (leave blank to keep using %s): ", choice.env)
	line, err = in.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return fmt.Errorf("reading the key: %w", err)
	}
	return writeConfig(stdout, choice.name, model, strings.TrimSpace(line))
}

func defaultModelFor(provider string) string {
	if provider == llm.ProviderOpenRouter {
		return llm.DefaultOpenRouterModel
	}
	return llm.DefaultModel
}

// writeConfig saves the settings, keeping any key already stored when the
// caller supplied none.
func writeConfig(stdout io.Writer, provider, model, key string) error {
	cfg, err := llm.LoadConfig()
	if err != nil && !errors.Is(err, llm.ErrNoConfig) {
		return err
	}
	if cfg == nil {
		cfg = &llm.Config{}
	}

	if provider != "" {
		cfg.Provider = provider
	}
	if cfg.Provider == "" {
		cfg.Provider = llm.ProviderAnthropic
	}
	if model != "" {
		cfg.Model = model
	}
	if key != "" {
		cfg.APIKey = key
	}

	path, err := cfg.Save()
	if err != nil {
		return err
	}

	// The key is never echoed, here or anywhere else.
	fmt.Fprintf(stdout, "\nwrote %s\n\n%s\n", path, cfg.Redacted())
	return nil
}

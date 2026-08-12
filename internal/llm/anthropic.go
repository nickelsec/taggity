package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/nickelsec/taggity/internal/spec"
)

// DefaultModel is what Anthropic drafts with unless told otherwise.
const DefaultModel = "claude-sonnet-4-5-20250929"

const (
	anthropicURL     = "https://api.anthropic.com/v1/messages"
	anthropicVersion = "2023-06-01"
	maxTokens        = 2048
)

// KeyEnv is the environment variable holding the API key. The key is read here
// and nowhere else: it is never written to a spec and never logged.
const KeyEnv = "ANTHROPIC_API_KEY"

// Anthropic calls the Messages API directly.
//
// No SDK. go.mod carries three direct dependencies and this is one POST against
// a documented JSON endpoint, in a tool whose subject is supply-chain metadata.
type Anthropic struct {
	APIKey  string
	ModelID string
	HTTP    *http.Client
}

// NewAnthropic builds a provider from the environment.
func NewAnthropic(model string) (*Anthropic, error) {
	return NewAnthropicWithKey(os.Getenv(KeyEnv), model)
}

// NewAnthropicWithKey builds a provider from a key the caller already has,
// which is how a key stored by `taggity configure` reaches it.
func NewAnthropicWithKey(key, model string) (*Anthropic, error) {
	if key == "" {
		return nil, fmt.Errorf("no Anthropic API key: run `taggity configure` "+
			"or set %s. Only drafting and --llm read one", KeyEnv)
	}
	if model == "" {
		model = DefaultModel
	}
	return &Anthropic{
		APIKey:  key,
		ModelID: model,
		// Generous: a large diff against a slow model is still one call, and a
		// timeout mid-draft wastes the whole request.
		HTTP: &http.Client{Timeout: 3 * time.Minute},
	}, nil
}

// Name identifies the provider for a spec's authoring block.
func (a *Anthropic) Name() string { return "anthropic" }

// Model identifies the model for a spec's authoring block.
func (a *Anthropic) Model() string { return a.ModelID }

// Draft proposes a spec from a description of a vulnerability.
func (a *Anthropic) Draft(ctx context.Context, req DraftRequest) (*spec.Spec, error) {
	return draft(ctx, a, req)
}

// Locate proposes somewhere else to look for a construct.
func (a *Anthropic) Locate(ctx context.Context, req LocateRequest) (*Suggestion, error) {
	return locate(ctx, a, req)
}

type anthropicRequest struct {
	Model     string             `json:"model"`
	MaxTokens int                `json:"max_tokens"`
	System    string             `json:"system"`
	Messages  []anthropicMessage `json:"messages"`
}

type anthropicMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type anthropicResponse struct {
	Content []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	} `json:"content"`
	Error *struct {
		Type    string `json:"type"`
		Message string `json:"message"`
	} `json:"error"`
}

// complete makes the one call this package ever makes.
func (a *Anthropic) complete(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(anthropicRequest{
		Model:     a.ModelID,
		MaxTokens: maxTokens,
		System:    system,
		Messages:  []anthropicMessage{{Role: "user", Content: user}},
	})
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicURL,
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("X-Api-Key", a.APIKey)
	httpReq.Header.Set("Anthropic-Version", anthropicVersion)

	resp, err := a.HTTP.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("calling the model: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Bounded: a runaway response should not exhaust memory.
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("reading the reply: %w", err)
	}

	var parsed anthropicResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("the reply was not JSON (HTTP %d): %s",
			resp.StatusCode, truncate(string(raw), 400))
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("the model refused (HTTP %d, %s): %s",
			resp.StatusCode, parsed.Error.Type, parsed.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from the model: %s",
			resp.StatusCode, truncate(string(raw), 400))
	}

	var text bytes.Buffer
	for _, c := range parsed.Content {
		if c.Type == "text" {
			text.WriteString(c.Text)
		}
	}
	if text.Len() == 0 {
		return "", errors.New("the model returned an empty reply")
	}
	return text.String(), nil
}

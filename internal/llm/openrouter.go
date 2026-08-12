package llm

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/nickelsec/taggity/internal/spec"
)

// OpenRouterKeyEnv holds the API key when one is not configured on disk.
const OpenRouterKeyEnv = "OPENROUTER_API_KEY"

// DefaultOpenRouterModel is a reasonable default when none is configured.
//
// OpenRouter fronts many models and the choice matters more here than the
// provider does: drafting needs a model that can read a diff and pick the token
// that changed, which small models do badly.
const DefaultOpenRouterModel = "anthropic/claude-sonnet-4.5"

const openRouterURL = "https://openrouter.ai/api/v1/chat/completions"

// OpenRouter calls the chat-completions API.
//
// A separate implementation rather than a variant of Anthropic: different URL,
// different auth header, and a different response body. Draft and Locate are
// shared through the completer interface, so only the round trip lives here.
type OpenRouter struct {
	APIKey  string
	ModelID string
	HTTP    *http.Client
}

// NewOpenRouter builds a provider from a key and a model.
func NewOpenRouter(key, model string) (*OpenRouter, error) {
	if key == "" {
		return nil, fmt.Errorf("no OpenRouter API key: run `taggity configure` "+
			"or set %s. Only drafting and --llm read one", OpenRouterKeyEnv)
	}
	if model == "" {
		model = DefaultOpenRouterModel
	}
	return &OpenRouter{
		APIKey:  key,
		ModelID: model,
		HTTP:    &http.Client{Timeout: 3 * time.Minute},
	}, nil
}

// Name identifies the provider for a spec's authoring block.
func (o *OpenRouter) Name() string { return "openrouter" }

// Model identifies the model for a spec's authoring block.
func (o *OpenRouter) Model() string { return o.ModelID }

// Draft proposes a spec from a description of a vulnerability.
func (o *OpenRouter) Draft(ctx context.Context, req DraftRequest) (*spec.Spec, error) {
	return draft(ctx, o, req)
}

// Locate proposes somewhere else to look for a construct.
func (o *OpenRouter) Locate(ctx context.Context, req LocateRequest) (*Suggestion, error) {
	return locate(ctx, o, req)
}

type openRouterRequest struct {
	Model     string              `json:"model"`
	MaxTokens int                 `json:"max_tokens"`
	Messages  []openRouterMessage `json:"messages"`
}

type openRouterMessage struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type openRouterResponse struct {
	Choices []struct {
		Message struct {
			Content string `json:"content"`
		} `json:"message"`
	} `json:"choices"`
	Error *struct {
		Message string `json:"message"`
		Code    any    `json:"code"`
	} `json:"error"`
}

// complete makes the one call this provider ever makes.
//
// The system prompt is a message with role "system" rather than a top-level
// field, which is the one shape difference from Anthropic that matters.
func (o *OpenRouter) complete(ctx context.Context, system, user string) (string, error) {
	body, err := json.Marshal(openRouterRequest{
		Model:     o.ModelID,
		MaxTokens: maxTokens,
		Messages: []openRouterMessage{
			{Role: "system", Content: system},
			{Role: "user", Content: user},
		},
	})
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}

	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, openRouterURL,
		bytes.NewReader(body))
	if err != nil {
		return "", fmt.Errorf("building request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+o.APIKey)
	// OpenRouter attributes requests by these. Harmless to send and useful to
	// whoever is looking at an account's usage.
	httpReq.Header.Set("Http-Referer", "https://github.com/nickelsec/taggity")
	httpReq.Header.Set("X-Title", "taggity")

	resp, err := o.HTTP.Do(httpReq)
	if err != nil {
		return "", fmt.Errorf("calling the model: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	raw, err := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if err != nil {
		return "", fmt.Errorf("reading the reply: %w", err)
	}

	var parsed openRouterResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return "", fmt.Errorf("the reply was not JSON (HTTP %d): %s",
			resp.StatusCode, truncate(string(raw), 400))
	}
	if parsed.Error != nil {
		return "", fmt.Errorf("the model refused (HTTP %d): %s",
			resp.StatusCode, parsed.Error.Message)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("HTTP %d from the model: %s",
			resp.StatusCode, truncate(string(raw), 400))
	}
	if len(parsed.Choices) == 0 {
		return "", errors.New("the model returned no choices")
	}

	text := parsed.Choices[0].Message.Content
	if text == "" {
		return "", errors.New("the model returned an empty reply")
	}
	return text, nil
}

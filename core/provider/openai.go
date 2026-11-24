package provider

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"
)

// OpenAI is a minimal OpenAI-compatible chat-completions adapter.
type OpenAI struct {
	baseURL string
	model   string
	keyEnv  string
	client  *http.Client
}

func NewOpenAI(baseURL, model, keyEnv string) *OpenAI {
	if baseURL == "" {
		baseURL = "https://api.openai.com/v1"
	}
	if keyEnv == "" {
		keyEnv = "PAT_API_KEY"
	}
	return &OpenAI{baseURL: strings.TrimRight(baseURL, "/"), model: model, keyEnv: keyEnv, client: &http.Client{Timeout: 90 * time.Second}}
}

func (o *OpenAI) Name() string { return "openai:" + o.model }

type chatRequest struct {
	Model    string          `json:"model"`
	Messages []Message       `json:"messages"`
	Tools    []chatTool      `json:"tools,omitempty"`
}

type chatTool struct {
	Type     string       `json:"type"`
	Function chatFunction `json:"function"`
}

type chatFunction struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type chatResponse struct {
	Choices []struct {
		Message struct {
			Content   string `json:"content"`
			ToolCalls []struct {
				Function struct {
					Name      string `json:"name"`
					Arguments string `json:"arguments"`
				} `json:"function"`
			} `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

func (o *OpenAI) Complete(ctx context.Context, messages []Message, tools []string) (*Response, error) {
	key := os.Getenv(o.keyEnv)
	if key == "" {
		return nil, fmt.Errorf("API key environment variable %s is not set", o.keyEnv)
	}
	reqBody := chatRequest{Model: o.model, Messages: messages}
	for _, name := range tools {
		reqBody.Tools = append(reqBody.Tools, chatTool{
			Type: "function",
			Function: chatFunction{
				Name: name, Description: "PAT registered tool: " + name,
				Parameters: map[string]any{"type": "object", "properties": map[string]any{}},
			},
		})
	}
	body, err := json.Marshal(reqBody)
	if err != nil {
		return nil, err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, o.baseURL+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := o.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(resp.Body, 2<<20))
	if err != nil {
		return nil, err
	}
	if resp.StatusCode >= 300 {
		return nil, fmt.Errorf("LLM HTTP %d: %s", resp.StatusCode, strings.TrimSpace(string(raw)))
	}
	var parsed chatResponse
	if err := json.Unmarshal(raw, &parsed); err != nil {
		return nil, err
	}
	if len(parsed.Choices) == 0 {
		return nil, fmt.Errorf("LLM returned no choices")
	}
	msg := parsed.Choices[0].Message
	out := &Response{Text: msg.Content}
	allowed := make(map[string]bool, len(tools))
	for _, t := range tools {
		allowed[t] = true
	}
	for _, call := range msg.ToolCalls {
		name := call.Function.Name
		if !allowed[name] {
			continue // model tried to invent a tool: ignore it
		}
		args := map[string]string{}
		var obj map[string]any
		if err := json.Unmarshal([]byte(call.Function.Arguments), &obj); err == nil {
			for k, v := range obj {
				switch val := v.(type) {
				case string:
					args[k] = val
				default:
					b, _ := json.Marshal(val)
					args[k] = string(b)
				}
			}
		}
		out.Calls = append(out.Calls, ToolCall{Name: name, Args: args})
	}
	return out, nil
}

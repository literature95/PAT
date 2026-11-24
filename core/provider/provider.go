// Package provider abstracts LLM access. The fake provider is the default so
// the demo and CI need no API key; external providers require consent.
package provider

import (
	"context"
	"fmt"
	"regexp"
	"strings"

	"github.com/pat-toolkit/pat/config"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type ToolCall struct {
	Name string            `json:"name"`
	Args map[string]string `json:"args"`
}

type Response struct {
	Text  string     `json:"text"`
	Calls []ToolCall `json:"calls,omitempty"`
}

type Provider interface {
	Name() string
	Complete(ctx context.Context, messages []Message, tools []string) (*Response, error)
}

// New selects a provider. External data egress is gated by explicit consent.
func New(cfg *config.Config) (Provider, error) {
	switch strings.ToLower(cfg.Model.Provider) {
	case "fake", "":
		return &Fake{}, nil
	case "openai":
		if !cfg.Model.ConsentExternalLLM {
			return nil, fmt.Errorf("external LLM egress requires consent: set model.consent_external_llm=true in config")
		}
		return NewOpenAI(cfg.Model.BaseURL, cfg.Model.Name, cfg.Model.APIKeyEnv), nil
	default:
		return nil, fmt.Errorf("unsupported model provider %q (openai or fake supported in this build)", cfg.Model.Provider)
	}
}

// Fake is a deterministic rule-based stand-in for a model. It only emits
// calls from the registered tool vocabulary; it never executes arbitrary text.
type Fake struct{}

func (f *Fake) Name() string { return "fake" }

var (
	ipRe   = regexp.MustCompile(`(?:\d{1,3}\.){3}\d{1,3}(?:/\d{1,2})?`)
	portRe = regexp.MustCompile(`(?:port|端口)\s*[:=为]?\s*(\d{1,5})|(?:\d{1,3}\.){3}\d{1,3}\s+的\s*(\d{1,5})|(\d{1,3}(?:,\d{1,3}){0,20})`)
)

func lastUser(messages []Message) string {
	for i := len(messages) - 1; i >= 0; i-- {
		if messages[i].Role == "user" {
			return messages[i].Content
		}
	}
	return ""
}

func (f *Fake) Complete(_ context.Context, messages []Message, tools []string) (*Response, error) {
	text := lastUser(messages)
	has := func(names ...string) bool {
		for _, n := range names {
			for _, t := range tools {
				if t == n {
					return true
				}
			}
		}
		return false
	}
	targets := ipRe.FindAllString(text, -1)
	var ports string
	if m := portRe.FindStringSubmatch(text); m != nil {
		for _, g := range m[1:] {
			if g != "" {
				ports = g
				break
			}
		}
	}
	lower := strings.ToLower(text)

	switch {
	case strings.Contains(lower, "session") || strings.Contains(text, "会话"):
		if has("session_list") {
			return &Response{Text: "计划：session_list()", Calls: []ToolCall{{Name: "session_list", Args: map[string]string{}}}}, nil
		}
	case strings.Contains(text, "扫") || strings.Contains(lower, "scan") || strings.Contains(lower, "nmap") || strings.Contains(text, "端口"):
		if len(targets) == 0 {
			return &Response{Text: "未识别到目标 IP；请在实验清单内给出目标，或用 /set RHOSTS 设置。"}, nil
		}
		if has("nmap_scan") {
			return &Response{
				Text: fmt.Sprintf("计划：nmap_scan(RHOSTS=%s, ports=%s)", targets[0], ports),
				Calls: []ToolCall{{Name: "nmap_scan", Args: map[string]string{
					"RHOSTS": targets[0], "ports": ports,
				}}},
			}, nil
		}
		if has("module_execute") {
			return &Response{
				Text: fmt.Sprintf("计划：module_execute(auxiliary/scanner/portscan/tcp, RHOSTS=%s)", targets[0]),
				Calls: []ToolCall{{Name: "module_execute", Args: map[string]string{
					"module": "auxiliary/scanner/portscan/tcp", "RHOSTS": targets[0], "PORTS": ports,
				}}},
			}, nil
		}
	case strings.Contains(lower, "capabilit") || strings.Contains(text, "能力"):
		if has("get_capabilities") {
			return &Response{Text: "计划：get_capabilities()", Calls: []ToolCall{{Name: "get_capabilities"}}}, nil
		}
	default:
		if has("module_search") {
			kw := strings.TrimSpace(text)
			if len([]rune(kw)) > 32 {
				kw = string([]rune(kw)[:32])
			}
			return &Response{Text: "计划：module_search(" + kw + ")", Calls: []ToolCall{{
				Name: "module_search", Args: map[string]string{"keyword": kw},
			}}}, nil
		}
	}
	return &Response{Text: "没有可用工具完成该请求。可用 /help 查看命令。"}, nil
}

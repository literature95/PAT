package perm

import (
	"fmt"
	"regexp"
	"strings"

	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/event"
)

// Decision is the outcome of the permission engine.
type Decision string

const (
	Allow Decision = "allow"
	Ask   Decision = "ask"
	Deny  Decision = "deny"
)

// CheckRequest is the single input to the permission engine. Both human
// commands and model tool calls must build one of these: there is no path that
// bypasses the engine.
type CheckRequest struct {
	Actor      event.Actor
	Tool       string
	Sub        string // module path or subcommand, e.g. exploit/windows/smb/ms17_010
	Args       map[string]string
	Targets    []string
	Command    string // set for external process tools
	Write      bool
	Capability string // capability required by this tool
}

// CheckResult records which layer decided, for auditability.
type CheckResult struct {
	Decision Decision
	Layer    string // env | capability | scope | exec | rule | default
	Reason   string
	Warnings []string
}

type Engine struct {
	cfg   *config.Config
	scope *Scope
}

func NewEngine(cfg *config.Config) (*Engine, error) {
	scope, err := NewScope(cfg.Lab)
	if err != nil {
		return nil, err
	}
	return &Engine{cfg: cfg, scope: scope}, nil
}

func (e *Engine) Scope() *Scope { return e.scope }

// Check runs all four layers in order. First denial wins; default is deny.
func (e *Engine) Check(req CheckRequest) CheckResult {
	if req.Actor == "" {
		req.Actor = event.ActorAgent
	}

	// Layer 1 — environment authorization gate.
	if req.Write && e.cfg.Safety.RequireEnvAuth && !config.Authorized() {
		return CheckResult{Decision: Deny, Layer: "env",
			Reason: "write operations require PAT_AUTHORIZED=1 (session is read-only)"}
	}

	// Layer 2 — capability gate. Disabled capabilities mean the tool is not
	// even registered; this check is defence in depth for direct calls.
	if req.Capability != "" && !e.capabilityEnabled(req.Capability) {
		return CheckResult{Decision: Deny, Layer: "capability",
			Reason: fmt.Sprintf("capability %q is disabled; tool should not be registered", req.Capability)}
	}

	// Layer 3 — experiment scope, then exec-policy guardrails.
	warnings, err := e.scope.Check(req.Targets)
	if err != nil {
		return CheckResult{Decision: Deny, Layer: "scope", Reason: err.Error(), Warnings: warnings}
	}
	if req.Command != "" {
		if _, err := CheckExecPolicy(req.Command, e.cfg.Exec); err != nil {
			return CheckResult{Decision: Deny, Layer: "exec", Reason: err.Error(), Warnings: warnings}
		}
	}

	// Layer 4 — ordered allow/deny/ask rules; first match wins.
	call := CallName(req.Tool, req.Sub)
	for _, rule := range e.cfg.Permission.Rules {
		if matchPattern(rule.Pattern, call) {
			switch rule.Action {
			case "allow":
				return CheckResult{Decision: Allow, Layer: "rule", Reason: rule.Note, Warnings: warnings}
			case "ask":
				return CheckResult{Decision: Ask, Layer: "rule", Reason: rule.Note, Warnings: warnings}
			default:
				return CheckResult{Decision: Deny, Layer: "rule", Reason: rule.Note, Warnings: warnings}
			}
		}
	}
	return CheckResult{Decision: Deny, Layer: "default", Reason: "no matching permission rule; default deny", Warnings: warnings}
}

func (e *Engine) capabilityEnabled(name string) bool {
	c := e.cfg.Capabilities
	switch strings.ToLower(name) {
	case "execution":
		return c.Execution
	case "mutations":
		return c.Mutations
	case "batch":
		return c.Execution && c.Batch
	case "credential_injection":
		return c.CredentialInjection
	case "credential_reveal":
		return c.CredentialReveal
	case "mcp":
		return c.MCP
	default:
		return false
	}
}

// CapabilitySnapshot is returned by get_capabilities / /capabilities.
func (e *Engine) CapabilitySnapshot() map[string]any {
	c := e.cfg.Capabilities
	return map[string]any{
		"execution": c.Execution,
		"mutations": c.Mutations,
		"batch":     c.Execution && c.Batch,
		"credential_injection": c.CredentialInjection,
		"credential_reveal":    c.CredentialReveal,
		"mcp":                  c.MCP,
		"environment_mode":     e.cfg.Lab.EnvironmentMode,
		"authorized":           config.Authorized(),
		"backend":              e.cfg.MSF.Backend,
		"scope":                e.scope.Summary(),
		"exec_allowlist":       e.cfg.Exec.Allowlist,
		"exec_denylist":        e.cfg.Exec.Denylist,
	}
}

// CallName builds the canonical pattern key, e.g.
// module_execute(exploit/windows/smb/ms17_010) or module_search(*).
func CallName(tool, sub string) string {
	if sub == "" {
		sub = "*"
	}
	return tool + "(" + sub + ")"
}

// matchPattern compiles a glob pattern (e.g. module_execute(exploit/*)) to a
// case-sensitive regular expression.
func matchPattern(pattern, call string) bool {
	quoted := regexp.QuoteMeta(pattern)
	quoted = strings.ReplaceAll(quoted, `\*`, `.*`)
	re, err := regexp.Compile("^" + quoted + "$")
	if err != nil {
		return false
	}
	return re.MatchString(call)
}

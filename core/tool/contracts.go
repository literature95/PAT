// Package tool defines the tool registry and executor. Tools are registered
// at startup behind capability gates: a disabled capability means the tool is
// absent from the registry, so a model never even gets a chance to call it.
package tool

import (
	"context"

	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/event"
	"github.com/pat-toolkit/pat/core/loop"
	"github.com/pat-toolkit/pat/core/perm"
)

// MSFBackend is the gateway contract implemented by CLI / mock / RPC backends.
type MSFBackend interface {
	Name() string
	Search(ctx context.Context, keyword string) ([]string, error)
	Execute(ctx context.Context, module string, opts map[string]string) (string, error)
	Sessions(ctx context.Context) ([]string, error)
	Console(ctx context.Context, command string) (string, error)
	Payload(ctx context.Context, typ string, opts map[string]string) (string, error)
}

// NmapRunner is the embedded nmap CLI contract.
type NmapRunner interface {
	Name() string
	Scan(ctx context.Context, target, ports string) (string, error)
}

// Context carries durable, shared dependencies into every tool.
type Context struct {
	Ctx          context.Context
	SessionID    string
	ExperimentID string
	Actor        event.Actor
	Emitter      *event.Emitter
	Store        *event.SQLiteStore
	Perm         *perm.Engine
	Approvals    *loop.Manager
	Registry     *Registry
	MSF          MSFBackend
	Nmap         NmapRunner
	ArtifactDir  string
}

// Result is the uniform tool result.
type Result struct {
	Preview     string   `json:"preview,omitempty"`
	Output      string   `json:"output,omitempty"`
	ExecutionID string   `json:"execution_id,omitempty"`
	Artifacts   []string `json:"artifacts,omitempty"`
	Warnings    []string `json:"warnings,omitempty"`
	RequestID   string   `json:"request_id,omitempty"`
}

// Spec is immutable tool metadata used by both the registry and /capabilities.
type Spec struct {
	Name        string `json:"name"`
	Description string `json:"description"`
	Capability  string `json:"capability"` // empty = always registered
	Risk        string `json:"risk"`
	Write       bool   `json:"write"`
	Execution   bool   `json:"execution"`
}

// Tool pairs metadata with its plan/execute functions.
type Tool struct {
	Spec
	PlanFunc    func(*Context, map[string]string) (*Result, error)
	ExecuteFunc func(*Context, map[string]string) (*Result, error)
	TargetsFunc func(map[string]string) []string
	CommandFunc func(map[string]string) string
	SubFunc     func(map[string]string) string
}

// Targets returns the target tokens declared by this tool for this call.
// Exported so app frontends can render scope previews at planning time.
func (t *Tool) Targets(a map[string]string) []string {
	if t.TargetsFunc == nil {
		return nil
	}
	return t.TargetsFunc(a)
}

func (t *Tool) sub(a map[string]string) string {
	if t.SubFunc == nil {
		return ""
	}
	return t.SubFunc(a)
}

func (t *Tool) command(a map[string]string) string {
	if t.CommandFunc == nil {
		return ""
	}
	return t.CommandFunc(a)
}

// Registry holds all specs plus the subset enabled by capability gates.
type Registry struct {
	all     map[string]*Tool
	enabled map[string]*Tool
}

func NewRegistry(cfg *config.Config, msf MSFBackend, nmap NmapRunner) *Registry {
	r := &Registry{all: make(map[string]*Tool), enabled: make(map[string]*Tool)}
	for _, t := range builtins(msf, nmap) {
		r.all[t.Name] = t
		if t.Capability == "" || capabilityOn(cfg, t.Capability) {
			r.enabled[t.Name] = t
		}
	}
	return r
}

func capabilityOn(cfg *config.Config, name string) bool {
	c := cfg.Capabilities
	switch name {
	case "execution":
		return c.Execution
	case "mutations":
		return c.Mutations
	case "batch":
		return c.Execution && c.Batch
	default:
		return false
	}
}

// Get returns an enabled tool only. Gated tools are indistinguishable from
// non-existent ones to callers.
func (r *Registry) Get(name string) (*Tool, bool) {
	t, ok := r.enabled[name]
	return t, ok
}

// PlanSpec is always available, even for tools whose execution capability is
// disabled: planning is read-only and has no side effects.
func (r *Registry) PlanSpec(name string) (*Tool, bool) {
	t, ok := r.all[name]
	return t, ok
}

func (r *Registry) Enabled() []Spec {
	out := make([]Spec, 0, len(r.enabled))
	for _, t := range r.enabled {
		out = append(out, t.Spec)
	}
	return out
}

func (r *Registry) Names() []string {
	out := make([]string, 0, len(r.enabled))
	for name := range r.enabled {
		out = append(out, name)
	}
	return out
}

// Gated reports tools that exist but were not registered, for diagnostics.
func (r *Registry) Gated(cfg *config.Config) []Spec {
	var out []Spec
	for _, t := range r.all {
		if t.Capability != "" && !capabilityOn(cfg, t.Capability) {
			out = append(out, t.Spec)
		}
	}
	return out
}

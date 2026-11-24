// Package app wires the core into a single shared instance used by every
// frontend (CLI, TUI, HTTP/SSE). Frontends never talk to gateways directly.
package app

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/agent"
	"github.com/pat-toolkit/pat/core/event"
	"github.com/pat-toolkit/pat/core/loop"
	"github.com/pat-toolkit/pat/core/perm"
	"github.com/pat-toolkit/pat/core/provider"
	"github.com/pat-toolkit/pat/core/session"
	"github.com/pat-toolkit/pat/core/tool"
	"github.com/pat-toolkit/pat/core/util"
	"github.com/pat-toolkit/pat/gateway/msf"
	"github.com/pat-toolkit/pat/gateway/nmap"
)

type App struct {
	Config    *config.Config
	Store     *event.SQLiteStore
	Bus       *event.Bus
	Emitter   *event.Emitter
	Perm      *perm.Engine
	Registry  *tool.Registry
	Executor  *tool.Executor
	Approvals *loop.Manager
	Loop      *loop.Loop
	Sessions  *session.Manager
	Provider  provider.Provider
	MSF       msf.Backend
	Nmap      nmap.Runner
	Role      agent.Role

	CurrentModule string
	CurrentArgs   map[string]string
	LastPlan      *PendingPlan
	Messages      []provider.Message
	BackendInfo   string
}

type PendingPlan struct {
	Tool      string            `json:"tool"`
	Args      map[string]string `json:"args"`
	Preview   string            `json:"preview"`
	RequestID string            `json:"request_id,omitempty"`
}

func New(cfg *config.Config) (*App, error) {
	if cfg.Lab.DBPath == "" {
		cfg.Lab.DBPath = ".pat/events.db"
	}
	if cfg.Lab.ArtifactDir == "" {
		cfg.Lab.ArtifactDir = ".pat/artifacts"
	}
	if err := os.MkdirAll(filepath.Dir(cfg.Lab.DBPath), 0o755); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.Lab.ArtifactDir, 0o755); err != nil {
		return nil, err
	}
	store, err := event.OpenSQLite(cfg.Lab.DBPath)
	if err != nil {
		return nil, err
	}
	bus := event.NewBus()
	em := &event.Emitter{Store: store, Bus: bus}
	p, err := perm.NewEngine(cfg)
	if err != nil {
		store.Close()
		return nil, err
	}
	pr, err := provider.New(cfg)
	if err != nil {
		store.Close()
		return nil, err
	}
	timeout := time.Duration(cfg.Exec.TimeoutSeconds) * time.Second
	msfBackend, backendInfo := msf.Select(cfg, timeout)
	nmapBackend := nmap.Select(cfg)
	role, _ := agent.Get("operator")
	a := &App{
		Config: cfg, Store: store, Bus: bus, Emitter: em, Perm: p,
		Registry: tool.NewRegistry(cfg, msfBackend, nmapBackend),
		Executor: tool.NewExecutor(), Approvals: loop.NewManager(em), Loop: loop.New(em),
		Sessions: session.NewManager(store, em), Provider: pr, MSF: msfBackend, Nmap: nmapBackend,
		Role: role, CurrentArgs: map[string]string{}, BackendInfo: backendInfo,
	}
	return a, nil
}

func (a *App) Close() error { return a.Store.Close() }

func (a *App) StartSession(ctx context.Context, experimentID string) error {
	_, err := a.Sessions.Start(ctx, experimentID)
	return err
}

func (a *App) Context(ctx context.Context, actor event.Actor) *tool.Context {
	s := a.Sessions.Current()
	var sid, eid string
	if s != nil {
		sid, eid = s.ID, s.ExperimentID
	}
	return &tool.Context{
		Ctx: ctx, SessionID: sid, ExperimentID: eid, Actor: actor,
		Emitter: a.Emitter, Store: a.Store, Perm: a.Perm, Approvals: a.Approvals,
		Registry: a.Registry, MSF: a.MSF, Nmap: a.Nmap, ArtifactDir: a.Config.Lab.ArtifactDir,
	}
}

func (a *App) VisibleTools() []string {
	return a.Role.VisibleTools(a.Registry.Names())
}

// HandleMessage runs one agent-loop turn. Planning is always free; write
// operations stop at the approval gate and are not auto-executed.
func (a *App) HandleMessage(ctx context.Context, text string) (string, error) {
	s := a.Sessions.Current()
	if s == nil {
		return "", fmt.Errorf("no active session")
	}
	if err := a.Emitter.Emit(ctx, event.NewEvent(s.ID, s.ExperimentID, event.ActorHuman, event.UserMessage, map[string]any{"text": text})); err != nil {
		return "", err
	}
	if err := a.Loop.Transition(loop.Planning); err != nil {
		return "", err
	}
	a.Messages = append(a.Messages, provider.Message{Role: "user", Content: text})
	resp, err := a.Provider.Complete(ctx, a.Messages, a.VisibleTools())
	if err != nil {
		return "", err
	}
	a.Messages = append(a.Messages, provider.Message{Role: "assistant", Content: resp.Text})
	var steps []string
	for _, call := range resp.Calls {
		steps = append(steps, call.Name)
	}
	if err := a.Emitter.Emit(ctx, event.NewEvent(s.ID, s.ExperimentID, event.ActorAgent, event.PlanCreated, map[string]any{"steps": steps})); err != nil {
		return "", err
	}
	var out []string
	out = append(out, resp.Text)
	c := a.Context(ctx, event.ActorAgent)
	for _, call := range resp.Calls {
		if !a.Role.Allows(call.Name) {
			out = append(out, fmt.Sprintf("▸ %s：当前角色 %s 不允许该工具", call.Name, a.Role.Name))
			continue
		}
		t, ok := a.Registry.PlanSpec(call.Name)
		if !ok {
			out = append(out, fmt.Sprintf("▸ %s：工具未注册", call.Name))
			continue
		}
		plan, err := a.Executor.Plan(c, call.Name, call.Args)
		if err != nil {
			out = append(out, "▸ 规划失败: "+err.Error())
			continue
		}
		out = append(out, "▸ "+plan.Preview)
		if targets := t.Targets(call.Args); len(targets) > 0 {
			warnings, err := a.Perm.Scope().Check(targets)
			if err != nil {
				out = append(out, "✗ 作用域校验失败："+err.Error())
				continue
			}
			out = append(out, fmt.Sprintf("▸ 作用域：%s ✓（在实验清单内）", strings.Join(targets, ", ")))
			for _, warning := range warnings {
				out = append(out, "⚠ "+warning)
			}
		}
		a.LastPlan = &PendingPlan{Tool: call.Name, Args: call.Args, Preview: plan.Preview}
		if t.Write || t.Execution {
			// Planning is free. The approval request is created here, but the
			// environment/capability/scope gates are still enforced at run time.
			if err := a.Loop.Transition(loop.AwaitingApproval); err == nil {
				approval, err := a.Approvals.Request(c.Ctx, c.SessionID, c.ExperimentID, call.Name, call.Args, t.Risk)
				if err != nil {
					out = append(out, "⚠ "+err.Error())
					continue
				}
				a.LastPlan.RequestID = approval.RequestID
				out = append(out, fmt.Sprintf("⚠ approval required: /approve %s then /run %s", approval.RequestID, call.Name))
			}
		} else if _, err := a.Executor.Run(c, call.Name, call.Args, ""); err == nil {
			if t.Name == "get_capabilities" {
				// introspection output is printed by the caller on request
			}
		}
	}
	_ = a.Loop.Transition(loop.Observing)
	_ = a.Loop.Transition(loop.Done)
	return util.SafeText(strings.Join(out, "\n"), 8000), nil
}

// RunPlan executes the most recent plan, optionally with an approved requestId.
func (a *App) RunPlan(ctx context.Context, requestID string, actor event.Actor) (string, error) {
	p := a.LastPlan
	if p == nil {
		return "", fmt.Errorf("没有待执行的计划；先用 /plan 或自然语言生成计划")
	}
	if requestID != "" {
		p.RequestID = requestID
	}
	c := a.Context(ctx, actor)
	// A second /run after a completed turn starts a fresh planning step.
	switch a.Loop.State() {
	case loop.Done, loop.Failed, loop.Cancelled:
		_ = a.Loop.Transition(loop.Idle)
		_ = a.Loop.Transition(loop.Planning)
	}
	if err := a.Loop.Transition(loop.Executing); err != nil {
		return "", err
	}
	res, err := a.Executor.Run(c, p.Tool, p.Args, p.RequestID)
	if err != nil {
		_ = a.Loop.Transition(loop.Failed)
		return "", err
	}
	_ = a.Loop.Transition(loop.Observing)
	_ = a.Loop.Transition(loop.Done)
	if res.RequestID != "" {
		p.RequestID = res.RequestID
		return res.Preview, nil
	}
	out := res.Output
	if out == "" {
		out = res.Preview
	}
	return util.SafeText(out, 8000), nil
}

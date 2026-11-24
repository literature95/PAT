package tool

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/event"
	"github.com/pat-toolkit/pat/core/loop"
	"github.com/pat-toolkit/pat/core/perm"
)

type countingMSF struct{ calls int }

func (m *countingMSF) Name() string { return "msf-test" }
func (m *countingMSF) Search(context.Context, string) ([]string, error) {
	m.calls++
	return []string{"auxiliary/scanner/portscan/tcp"}, nil
}
func (m *countingMSF) Execute(context.Context, string, map[string]string) (string, error) {
	m.calls++
	return "mock execute", nil
}
func (m *countingMSF) Sessions(context.Context) ([]string, error) {
	m.calls++
	return []string{"no sessions"}, nil
}
func (m *countingMSF) Console(context.Context, string) (string, error) {
	m.calls++
	return "", nil
}
func (m *countingMSF) Payload(context.Context, string, map[string]string) (string, error) {
	m.calls++
	return "mock payload", nil
}

type countingNmap struct{ calls int }

func (n *countingNmap) Name() string { return "nmap-test" }
func (n *countingNmap) Scan(_ context.Context, target, ports string) (string, error) {
	n.calls++
	return "Nmap scan report for " + target + " port=" + ports, nil
}

type harness struct {
	ctx      *Context
	store    *event.SQLiteStore
	msf      *countingMSF
	nmap     *countingNmap
	approvals *loop.Manager
}

func newHarness(t *testing.T, execCap bool) *harness {
	t.Helper()
	cfg := config.Default()
	cfg.Capabilities.Execution = execCap
	cfg.Capabilities.Mutations = execCap
	cfg.Lab.Scope = []string{"192.168.56.0/24"}
	store, err := event.OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { store.Close() })
	em := &event.Emitter{Store: store, Bus: event.NewBus()}
	p, err := perm.NewEngine(cfg)
	if err != nil {
		t.Fatal(err)
	}
	msf, nmap := &countingMSF{}, &countingNmap{}
	approvals := loop.NewManager(em)
	return &harness{
		ctx: &Context{
			Ctx: context.Background(), SessionID: "ses_test", ExperimentID: "PAT_test",
			Actor: event.ActorHuman, Emitter: em, Store: store, Perm: p, Approvals: approvals,
			Registry: NewRegistry(cfg, msf, nmap), MSF: msf, Nmap: nmap,
		},
		store: store, msf: msf, nmap: nmap, approvals: approvals,
	}
}

func TestPlanIsFreeAndExecutionNeedsApproval(t *testing.T) {
	h := newHarness(t, true)
	args := map[string]string{"RHOSTS": "192.168.56.10", "ports": "445"}
	x := NewExecutor()

	plan, err := x.Plan(h.ctx, "nmap_scan", args)
	if err != nil || !strings.Contains(plan.Preview, "dry-run") {
		t.Fatalf("plan: %+v %v", plan, err)
	}
	if h.nmap.calls != 0 {
		t.Fatal("plan must have no side effects")
	}
	events, _ := h.store.List(context.Background(), "ses_test")
	if !event.ContainsType(events, event.ToolPlanned) {
		t.Fatal("tool.planned event missing")
	}

	// Env gate blocks before any backend call.
	t.Setenv("PAT_AUTHORIZED", "0")
	if _, err := x.Run(h.ctx, "nmap_scan", args, ""); err == nil || !strings.Contains(err.Error(), "PAT_AUTHORIZED") {
		t.Fatalf("env gate: %v", err)
	}
	if h.nmap.calls != 0 {
		t.Fatal("denied execution still called the gateway")
	}

	t.Setenv("PAT_AUTHORIZED", "1")
	res, err := x.Run(h.ctx, "nmap_scan", args, "")
	if err != nil {
		t.Fatal(err)
	}
	if res.RequestID == "" || !strings.Contains(res.Preview, "/approve") {
		t.Fatalf("expected approval request: %+v", res)
	}
	if h.nmap.calls != 0 {
		t.Fatal("ask must not execute before approval")
	}
	if a, ok := h.approvals.Get(res.RequestID); !ok || a.Tool != "nmap_scan" {
		t.Fatalf("approval not bound to tool: %+v %v", a, ok)
	}

	if err := h.approvals.Resolve(context.Background(), res.RequestID, true, event.ActorHuman); err != nil {
		t.Fatal(err)
	}
	out, err := x.Run(h.ctx, "nmap_scan", args, res.RequestID)
	if err != nil || !strings.Contains(out.Output, "192.168.56.10") {
		t.Fatalf("run: %+v %v", out, err)
	}
	if h.nmap.calls != 1 {
		t.Fatalf("expected exactly 1 gateway call, got %d", h.nmap.calls)
	}
	events, _ = h.store.List(context.Background(), "ses_test")
	if !event.ContainsType(events, event.ApprovalRequested) || !event.ContainsType(events, event.ApprovalResolved) ||
		!event.ContainsType(events, event.ToolExecuted) || !event.ContainsType(events, event.ToolResult) {
		t.Fatal("missing lifecycle events")
	}
}

func TestApprovalCannotBeReusedForAnotherTool(t *testing.T) {
	h := newHarness(t, true)
	t.Setenv("PAT_AUTHORIZED", "1")
	x := NewExecutor()
	res, err := x.Run(h.ctx, "nmap_scan", map[string]string{"RHOSTS": "192.168.56.10"}, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := h.approvals.Resolve(context.Background(), res.RequestID, true, event.ActorHuman); err != nil {
		t.Fatal(err)
	}
	if _, err := x.Run(h.ctx, "cleanup", nil, res.RequestID); err == nil || !strings.Contains(err.Error(), "does not belong") {
		t.Fatalf("cross-tool approval reuse: %v", err)
	}
}

func TestCapabilityGatingUnregistersTool(t *testing.T) {
	h := newHarness(t, false)
	if _, ok := h.ctx.Registry.Get("nmap_scan"); ok {
		t.Fatal("gated tool must not be registered")
	}
	if _, ok := h.ctx.Registry.PlanSpec("nmap_scan"); !ok {
		t.Fatal("planning must remain available")
	}
	for _, name := range h.ctx.Registry.Names() {
		if name == "nmap_scan" || name == "module_execute" || name == "payload_generate" {
			t.Fatalf("gated tool %s leaked into registry", name)
		}
	}
	x := NewExecutor()
	if _, err := x.Run(h.ctx, "nmap_scan", nil, ""); err == nil || !strings.Contains(err.Error(), "not registered") {
		t.Fatalf("gated tool was callable: %v", err)
	}
}

func TestReadOnlyToolNeedsNoApproval(t *testing.T) {
	h := newHarness(t, true)
	t.Setenv("PAT_AUTHORIZED", "0")
	res, err := NewExecutor().Run(h.ctx, "module_search", map[string]string{"keyword": "smb"}, "")
	if err != nil || h.msf.calls != 1 || strings.Contains(res.Output, "approval") {
		t.Fatalf("read tool should run without auth/approval: %+v %v", res, err)
	}
}

func TestEventChainIntegrity(t *testing.T) {
	h := newHarness(t, true)
	t.Setenv("PAT_AUTHORIZED", "0")
	_, _ = NewExecutor().Run(h.ctx, "module_search", map[string]string{"keyword": "smb"}, "")
	if err := h.store.VerifyChain(context.Background()); err != nil {
		t.Fatalf("event chain broken: %v", err)
	}
}

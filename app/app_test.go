package app_test

import (
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pat-toolkit/pat/app"
	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/event"
)

type countingNmap struct{ calls int }

func (n *countingNmap) Name() string { return "nmap-counting" }
func (n *countingNmap) Scan(_ context.Context, target, ports string) (string, error) {
	n.calls++
	return "[mock nmap] " + target + ":" + ports + " open", nil
}

func newTestApp(t *testing.T) (*app.App, *countingNmap) {
	t.Helper()
	cfg := config.Default()
	cfg.Capabilities.Execution = true
	cfg.Capabilities.Mutations = true
	cfg.Lab.DBPath = filepath.Join(t.TempDir(), "events.db")
	cfg.Lab.ArtifactDir = filepath.Join(t.TempDir(), "artifacts")
	cfg.MSF.Backend = "mock"
	a, err := app.New(cfg)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { a.Close() })
	n := &countingNmap{}
	a.Nmap = n
	if err := a.StartSession(context.Background(), "PAT_test"); err != nil {
		t.Fatal(err)
	}
	return a, n
}

func TestNaturalLanguageScanStopsAtApproval(t *testing.T) {
	a, nmap := newTestApp(t)
	t.Setenv("PAT_AUTHORIZED", "0")
	ctx := context.Background()

	reply, err := a.HandleMessage(ctx, "扫一下 192.168.56.10 的 445")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, "approval required") {
		t.Fatalf("expected approval prompt, got: %s", reply)
	}
	if nmap.calls != 0 {
		t.Fatal("unapproved natural language request executed a scan")
	}
	if a.LastPlan == nil || a.LastPlan.RequestID == "" {
		t.Fatal("no requestId bound to the plan")
	}
	id := a.LastPlan.RequestID
	events, _ := a.Store.List(ctx, a.Sessions.Current().ID)
	if !event.ContainsType(events, event.PlanCreated) || !event.ContainsType(events, event.ApprovalRequested) {
		t.Fatal("plan/approval events missing")
	}

	// Even with authorization set, execution must wait for human approval.
	t.Setenv("PAT_AUTHORIZED", "1")
	res, err := a.RunPlan(ctx, id, event.ActorHuman)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(res, "approval required") {
		// A pending (unresolved) request must not execute; a fresh approval is created.
		t.Fatalf("pending approval unexpectedly executed: %q", res)
	}
	if nmap.calls != 0 {
		t.Fatal("scan executed before approval")
	}

	// New approval from the retry, then approve and run.
	id = a.LastPlan.RequestID
	if err := a.Approvals.Resolve(ctx, id, true, event.ActorHuman); err != nil {
		t.Fatal(err)
	}
	out, err := a.RunPlan(ctx, id, event.ActorHuman)
	if err != nil || !strings.Contains(out, "192.168.56.10") {
		t.Fatalf("run: %q %v", out, err)
	}
	if nmap.calls != 1 {
		t.Fatalf("expected 1 scan, got %d", nmap.calls)
	}
	if err := a.Store.VerifyChain(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestCommandModeAndAudit(t *testing.T) {
	a, _ := newTestApp(t)
	ctx := context.Background()
	help, err := a.Command(ctx, "/help")
	if err != nil || !strings.Contains(help, "/approve") {
		t.Fatalf("help: %q %v", help, err)
	}
	caps, err := a.Command(ctx, "/capabilities")
	if err != nil || !strings.Contains(caps, "nmap_scan") {
		t.Fatalf("capabilities: %q %v", caps, err)
	}
	if !strings.Contains(caps, "payload_generate") {
		t.Fatal("mutations-enabled tool missing from capabilities")
	}
	audit, err := a.Command(ctx, "/audit md")
	if err != nil || !strings.Contains(audit, "session.started") {
		t.Fatalf("audit: %q %v", audit, err)
	}
	events, err := a.Command(ctx, "/events")
	if err != nil || !strings.Contains(events, "session.started") {
		t.Fatalf("events: %q %v", events, err)
	}
}

func TestRoleDeniesTools(t *testing.T) {
	a, _ := newTestApp(t)
	ctx := context.Background()
	reply, err := a.HandleMessage(ctx, "扫一下 192.168.56.10 的 445")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(reply, "approval required") {
		t.Fatalf("operator should see scan plan: %s", reply)
	}
	// Switch to recon: scan tool is filtered from the model's vocabulary.
	if _, err := a.Command(ctx, "/role recon"); err != nil {
		t.Fatal(err)
	}
	for _, name := range a.VisibleTools() {
		if name == "nmap_scan" {
			t.Fatal("recon role must not see write tools")
		}
	}
}

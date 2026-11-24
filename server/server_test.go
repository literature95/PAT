package server_test

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/pat-toolkit/pat/app"
	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/event"
	"github.com/pat-toolkit/pat/server"
)

func newServer(t *testing.T) *app.App {
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
	if err := a.StartSession(context.Background(), "PAT_contract"); err != nil {
		t.Fatal(err)
	}
	return a
}

func do(mux http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, req)
	return w
}

// EXPECTED_ROUTES freezes the Server API contract. Adding/removing a route
// must be accompanied by an api/openapi.json change in the same commit.
var expectedRoutes = map[string]string{
	"GET /api/v1/health":                         "GET /api/v1/health",
	"POST /api/v1/sessions":                       "POST /api/v1/sessions",
	"GET /api/v1/sessions/{id}/events":            "GET /api/v1/sessions/{id}/events",
	"GET /api/v1/sessions/{id}/events/list":       "GET /api/v1/sessions/{id}/events/list",
	"POST /api/v1/sessions/{id}/messages":         "POST /api/v1/sessions/{id}/messages",
	"POST /api/v1/tools/{name}/plan":              "POST /api/v1/tools/{name}/plan",
	"POST /api/v1/tools/{name}/execute":           "POST /api/v1/tools/{name}/execute",
	"GET /api/v1/approvals/{requestId}":           "GET /api/v1/approvals/{requestId}",
	"POST /api/v1/approvals/{requestId}":          "POST /api/v1/approvals/{requestId}",
	"GET /api/v1/capabilities":                    "GET /api/v1/capabilities",
	"GET /api/v1/scope":                           "GET /api/v1/scope",
	"GET /api/v1/permissions/rules":               "GET /api/v1/permissions/rules",
	"POST /api/v1/permissions/rules":              "POST /api/v1/permissions/rules",
	"GET /api/v1/audit":                           "GET /api/v1/audit",
	"POST /api/v1/experiments/{id}/cleanup":       "POST /api/v1/experiments/{id}/cleanup",
}

func TestContractSentinel(t *testing.T) {
	a := newServer(t)
	mux := server.NewMux(a)
	for route, pattern := range expectedRoutes {
		parts := strings.SplitN(route, " ", 2)
		path := strings.ReplaceAll(strings.ReplaceAll(parts[1], "{id}", "x"), "{name}", "get_capabilities")
		path = strings.ReplaceAll(path, "{requestId}", "req_x")
		req := httptest.NewRequest(parts[0], path, nil)
		_, got := mux.Handler(req)
		if got != pattern {
			t.Errorf("route %s: pattern = %q, want %q", route, got, pattern)
		}
	}

	raw, err := os.ReadFile(filepath.Join("..", "api", "openapi.json"))
	if err != nil {
		t.Fatal(err)
	}
	var spec struct {
		Paths map[string]map[string]any `json:"paths"`
	}
	if err := json.Unmarshal(raw, &spec); err != nil {
		t.Fatal(err)
	}
	for route := range expectedRoutes {
		parts := strings.SplitN(route, " ", 2)
		methods, ok := spec.Paths[parts[1]]
		if !ok {
			t.Errorf("openapi.json missing path %s", parts[1])
			continue
		}
		if _, ok := methods[strings.ToLower(parts[0])]; !ok {
			t.Errorf("openapi.json missing %s %s", parts[0], parts[1])
		}
	}
	if len(spec.Paths) != 13 {
		t.Errorf("openapi path count drifted: got %d, want 13", len(spec.Paths))
	}
}

func TestHealthCapabilitiesScope(t *testing.T) {
	a := newServer(t)
	mux := server.NewMux(a)
	w := do(mux, http.MethodGet, "/api/v1/health", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "ok") {
		t.Fatalf("health: %d %s", w.Code, w.Body.String())
	}
	w = do(mux, http.MethodGet, "/api/v1/capabilities", "")
	if w.Code != 200 {
		t.Fatalf("capabilities: %d %s", w.Code, w.Body.String())
	}
	var caps map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &caps); err != nil {
		t.Fatal(err)
	}
	names, _ := caps["registered_tools"].([]any)
	found := false
	for _, n := range names {
		if n == "nmap_scan" {
			found = true
		}
	}
	if !found {
		t.Fatalf("nmap_scan not registered: %v", names)
	}
	w = do(mux, http.MethodGet, "/api/v1/scope", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "192.168.56.0/24") {
		t.Fatalf("scope: %d %s", w.Code, w.Body.String())
	}
}

func TestApprovalEndpoints(t *testing.T) {
	a := newServer(t)
	t.Setenv("PAT_AUTHORIZED", "1")
	ctx := context.Background()
	c := a.Context(ctx, event.ActorHuman)
	res, err := a.Executor.Run(c, "nmap_scan", map[string]string{"RHOSTS": "192.168.56.10"}, "")
	if err != nil || res.RequestID == "" {
		t.Fatalf("setup approval: %+v %v", res, err)
	}
	mux := server.NewMux(a)
	path := "/api/v1/approvals/" + res.RequestID
	w := do(mux, http.MethodGet, path, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "pending") {
		t.Fatalf("get approval: %d %s", w.Code, w.Body.String())
	}
	w = do(mux, http.MethodPost, path, `{"decision":"approve"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "true") {
		t.Fatalf("resolve approval: %d %s", w.Code, w.Body.String())
	}
	w = do(mux, http.MethodGet, path, "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "approved") {
		t.Fatalf("approval state: %d %s", w.Code, w.Body.String())
	}
}

func TestPlanExecuteAndAuditEndpoints(t *testing.T) {
	a := newServer(t)
	mux := server.NewMux(a)
	w := do(mux, http.MethodPost, "/api/v1/tools/nmap_scan/plan", `{"RHOSTS":"192.168.56.10","ports":"445"}`)
	if w.Code != 200 || !strings.Contains(w.Body.String(), "dry-run") {
		t.Fatalf("plan: %d %s", w.Code, w.Body.String())
	}
	w = do(mux, http.MethodGet, "/api/v1/audit?format=md", "")
	if w.Code != 200 || !strings.Contains(w.Body.String(), "session.started") {
		t.Fatalf("audit: %d %s", w.Code, w.Body.String())
	}
	w = do(mux, http.MethodGet, "/api/v1/sessions/x/events/list", "")
	if w.Code != 200 {
		t.Fatalf("events list: %d %s", w.Code, w.Body.String())
	}
}

func TestExecuteDeniedReturnsForbidden(t *testing.T) {
	a := newServer(t)
	t.Setenv("PAT_AUTHORIZED", "0")
	mux := server.NewMux(a)
	body, _ := json.Marshal(map[string]any{"args": map[string]string{"RHOSTS": "192.168.56.10"}})
	w := do(mux, http.MethodPost, "/api/v1/tools/nmap_scan/execute", string(body))
	if w.Code != http.StatusForbidden {
		t.Fatalf("expected 403, got %d %s", w.Code, w.Body.String())
	}
	if !bytes.Contains(w.Body.Bytes(), []byte("PAT_AUTHORIZED")) {
		t.Fatalf("missing reason: %s", w.Body.String())
	}
}

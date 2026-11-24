package docs_test

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/pat-toolkit/pat/core/event"
)

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestDocumentationAnchors(t *testing.T) {
	readme := read(t, "../README.md")
	for _, anchor := range []string{
		"## 0. 现状与定位", "## 3. 框架设计", "## 8. 从靶场骨架继承的安全不变量",
		"## 9. 威胁模型", "## 11. 从 Cerno 借鉴的工程约定", "## 14. License",
	} {
		if !strings.Contains(readme, anchor) {
			t.Errorf("README.md missing anchor %q", anchor)
		}
	}
	arch := read(t, "architecture.md")
	if !strings.Contains(arch, "core/") || !strings.Contains(arch, "gateway/") {
		t.Fatal("architecture.md must describe core/gateway boundary")
	}
	sec := read(t, "security-model.md")
	if !strings.Contains(sec, "PAT_AUTHORIZED") || !strings.Contains(sec, "requestId") {
		t.Fatal("security-model.md missing authorization invariants")
	}
}

func TestEventCatalogMatchesCode(t *testing.T) {
	catalog := read(t, "../api/events.md")
	types := []string{
		event.SessionStarted, event.SessionEnded, event.UserMessage, event.PlanCreated,
		event.ToolPlanned, event.ApprovalRequested, event.ApprovalResolved, event.ToolExecuted,
		event.ToolResult, event.ArtifactRegistered, event.VerdictRecorded, event.AuditExported,
		event.ErrorRaised,
	}
	for _, typ := range types {
		if !strings.Contains(catalog, "`"+typ+"`") {
			t.Errorf("api/events.md missing event type %q", typ)
		}
	}
}

func TestReferenceSchemaMatchesCode(t *testing.T) {
	code := read(t, "../core/event/store.go")
	ref := read(t, "schema.sql")
	objectRe := regexp.MustCompile(`(?im)^\s*CREATE\s+(?:TABLE|VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	codeObjects := map[string]bool{}
	for _, m := range objectRe.FindAllStringSubmatch(code, -1) {
		codeObjects[strings.ToLower(m[1])] = true
	}
	for _, m := range objectRe.FindAllStringSubmatch(ref, -1) {
		name := strings.ToLower(m[1])
		if !codeObjects[name] {
			t.Errorf("docs/schema.sql defines %q which is absent from core/event/store.go", name)
		}
		delete(codeObjects, name)
	}
	for name := range codeObjects {
		t.Errorf("core/event/store.go defines %q which is absent from docs/schema.sql", name)
	}
}

func TestApiContractIsValidJSON(t *testing.T) {
	raw := read(t, "../api/openapi.json")
	if !strings.Contains(raw, `"openapi": "3.0.3"`) {
		t.Fatal("openapi.json must declare OpenAPI 3.0.3")
	}
	if !strings.Contains(raw, "/api/v1/tools/{name}/execute") {
		t.Fatal("openapi.json missing execute endpoint")
	}
}

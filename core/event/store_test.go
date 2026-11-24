package event

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

func TestAppendListAndHashChain(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	for i := 0; i < 3; i++ {
		e := NewEvent("ses_1", "PAT_lab", ActorHuman, UserMessage, map[string]any{"text": "hello", "i": i})
		if err := store.Append(ctx, e); err != nil {
			t.Fatal(err)
		}
	}
	events, err := store.List(ctx, "ses_1")
	if err != nil || len(events) != 3 {
		t.Fatalf("list: %d %v", len(events), err)
	}
	if events[0].PrevHash != "" || events[1].PrevHash != events[0].Hash {
		t.Fatal("broken hash chain links")
	}
	if err := store.VerifyChain(ctx); err != nil {
		t.Fatalf("verify: %v", err)
	}
	events2, err := store.List(ctx, "")
	if err != nil || len(events2) != 3 {
		t.Fatalf("global list: %d %v", len(events2), err)
	}
}

func TestTamperDetection(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	e := NewEvent("ses_1", "PAT_lab", ActorAgent, ToolPlanned, map[string]any{"preview": "safe"})
	if err := store.Append(ctx, e); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`UPDATE events SET payload = '{"preview":"tampered"}' WHERE seq = 1`); err != nil {
		t.Fatal(err)
	}
	if err := store.VerifyChain(ctx); err == nil {
		t.Fatal("tampered payload must break chain verification")
	}
}

func TestViewRecreationAndSchemaParity(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	// Simulate a stale view: the initializer must replace it.
	if _, err := store.db.Exec(`DROP VIEW IF EXISTS v_tool_counts`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`CREATE VIEW v_tool_counts AS SELECT 1 AS stale`); err != nil {
		t.Fatal(err)
	}
	if err := store.init(); err != nil {
		t.Fatal(err)
	}
	var sqlText string
	if err := store.db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='view' AND name='v_tool_counts'`).Scan(&sqlText); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(sqlText, "stale") {
		t.Fatalf("stale view survived re-init: %s", sqlText)
	}

	// Reference schema must declare the same tables and views.
	ref, err := os.ReadFile(filepath.Join("..", "..", "docs", "schema.sql"))
	if err != nil {
		t.Fatal(err)
	}
	objectRe := regexp.MustCompile(`(?i)CREATE\s+(?:TABLE|VIEW)\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-z_][a-z0-9_]*)`)
	refObjects := map[string]bool{}
	for _, m := range objectRe.FindAllStringSubmatch(string(ref), -1) {
		refObjects[strings.ToLower(m[1])] = true
	}
	rows, err := store.db.Query(`SELECT name FROM sqlite_master WHERE type IN ('table','view') AND name NOT LIKE 'sqlite_%'`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			t.Fatal(err)
		}
		if !refObjects[strings.ToLower(name)] {
			t.Fatalf("database object %q missing from docs/schema.sql", name)
		}
	}
}

func TestOldSchemaVersionRejected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "old.db")
	store, err := OpenSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec("PRAGMA user_version = 99"); err != nil {
		t.Fatal(err)
	}
	store.Close()
	if _, err := OpenSQLite(path); err == nil || !strings.Contains(err.Error(), "unsupported") {
		t.Fatalf("old schema should be rejected: %v", err)
	}
}

func TestVerdictAndArtifacts(t *testing.T) {
	store, err := OpenSQLite(filepath.Join(t.TempDir(), "events.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	ctx := context.Background()
	if err := store.RegisterArtifact(ctx, "exec_1", "ses_1", "/tmp/PAT_lab_x.txt", "abc123"); err != nil {
		t.Fatal(err)
	}
	arts, err := store.Artifacts(ctx, "ses_1")
	if err != nil || len(arts) != 1 || arts[0].SHA256 != "abc123" {
		t.Fatalf("artifacts: %+v %v", arts, err)
	}
	if err := store.DeleteArtifact(ctx, "/tmp/PAT_lab_x.txt"); err != nil {
		t.Fatal(err)
	}
	arts, _ = store.Artifacts(ctx, "ses_1")
	if len(arts) != 0 {
		t.Fatal("artifact should be deleted")
	}
	if _, err := store.RecordVerdict(ctx, "ses_1", "exec_1", ActorHuman, "bogus", "", nil); err == nil {
		t.Fatal("invalid verdict label accepted")
	}
	if _, err := store.RecordVerdict(ctx, "ses_1", "exec_1", ActorHuman, "confirmed", "yes", []string{"exec_1"}); err != nil {
		t.Fatal(err)
	}
	v, err := store.Verdicts(ctx, "ses_1")
	if err != nil || len(v) != 1 || v[0].Actor != ActorHuman {
		t.Fatalf("verdicts: %+v %v", v, err)
	}
}

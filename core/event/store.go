package event

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"sync"

	_ "modernc.org/sqlite"
)

const SchemaVersion = 1

// SQLiteStore is an append-only event store with a SHA-256 hash chain.
// Derived state (pending approvals, counts) lives in views, never in tables.
type SQLiteStore struct {
	db   *sql.DB
	mu   sync.Mutex
	last string
}

func OpenSQLite(path string) (*SQLiteStore, error) {
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	for _, pragma := range []string{
		"PRAGMA journal_mode=WAL",
		"PRAGMA foreign_keys=ON",
		"PRAGMA synchronous=NORMAL",
		"PRAGMA temp_store=MEMORY",
	} {
		if _, err := db.Exec(pragma); err != nil {
			db.Close()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	s := &SQLiteStore{db: db}
	if err := s.init(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *SQLiteStore) init() error {
	var version int
	if err := s.db.QueryRow("PRAGMA user_version").Scan(&version); err != nil {
		return err
	}
	var tableCount int
	if err := s.db.QueryRow("SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='events'").Scan(&tableCount); err != nil {
		return err
	}
	if version != 0 && version != SchemaVersion {
		return fmt.Errorf("event database schema version %d is unsupported (expected %d); back up and rebuild the database — no automatic migration is performed", version, SchemaVersion)
	}
	if version == 0 && tableCount > 0 {
		return fmt.Errorf("event database has tables but no schema version; refusing to use an unversioned database")
	}
	if _, err := s.db.Exec(schemaTables); err != nil {
		return fmt.Errorf("create schema: %w", err)
	}
	// Views hold no data. Rebuild unconditionally: CREATE VIEW IF NOT EXISTS
	// silently keeps stale definitions (Cerno §7 discipline).
	for _, v := range []string{"v_pending_approvals", "v_tool_counts", "v_current_verdict"} {
		if _, err := s.db.Exec("DROP VIEW IF EXISTS " + v); err != nil {
			return err
		}
	}
	if _, err := s.db.Exec(schemaViews); err != nil {
		return fmt.Errorf("create views: %w", err)
	}
	if _, err := s.db.Exec(fmt.Sprintf("PRAGMA user_version = %d", SchemaVersion)); err != nil {
		return err
	}
	var hash sql.NullString
	if err := s.db.QueryRow("SELECT hash FROM events ORDER BY seq DESC LIMIT 1").Scan(&hash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return err
	}
	if hash.Valid {
		s.last = hash.String
	}
	return nil
}

func (s *SQLiteStore) Append(ctx context.Context, e *Event) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e.PrevHash = s.last
	e.Hash = ComputeHash(e.PrevHash, e.Payload)
	payload, err := json.Marshal(e.Payload)
	if err != nil {
		return err
	}
	res, err := s.db.ExecContext(ctx, `INSERT INTO events
		(event_id, session_id, experiment_id, actor, type, tool, request_id, payload, prev_hash, hash, created_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		e.ID, e.SessionID, e.ExperimentID, string(e.Actor), e.Type, e.Tool, e.RequestID,
		string(payload), e.PrevHash, e.Hash, e.CreatedAt)
	if err != nil {
		return fmt.Errorf("append event: %w", err)
	}
	e.Seq, _ = res.LastInsertId()
	s.last = e.Hash
	return nil
}

func (s *SQLiteStore) LastHash(ctx context.Context) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.last, nil
}

func (s *SQLiteStore) List(ctx context.Context, sessionID string) ([]Event, error) {
	q := `SELECT seq, event_id, session_id, experiment_id, actor, type, COALESCE(tool,''),
		COALESCE(request_id,''), payload, prev_hash, hash, created_at FROM events`
	args := []any{}
	if sessionID != "" {
		q += " WHERE session_id = ?"
		args = append(args, sessionID)
	}
	q += " ORDER BY seq ASC"
	rows, err := s.db.QueryContext(ctx, q, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Event
	for rows.Next() {
		var e Event
		var payload string
		var actor string
		if err := rows.Scan(&e.Seq, &e.ID, &e.SessionID, &e.ExperimentID, &actor, &e.Type,
			&e.Tool, &e.RequestID, &payload, &e.PrevHash, &e.Hash, &e.CreatedAt); err != nil {
			return nil, err
		}
		e.Actor = Actor(actor)
		if err := json.Unmarshal([]byte(payload), &e.Payload); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

// VerifyChain checks every link. Used by tests and /audit.
func (s *SQLiteStore) VerifyChain(ctx context.Context) error {
	events, err := s.List(ctx, "")
	if err != nil {
		return err
	}
	prev := ""
	for _, e := range events {
		if e.PrevHash != prev {
			return fmt.Errorf("event %s: broken prev_hash link at seq %d", e.ID, e.Seq)
		}
		if ComputeHash(e.PrevHash, e.Payload) != e.Hash {
			return fmt.Errorf("event %s: hash mismatch at seq %d", e.ID, e.Seq)
		}
		prev = e.Hash
	}
	last, _ := s.LastHash(ctx)
	if prev != last {
		return fmt.Errorf("chain tip %q does not match store tip %q", prev, last)
	}
	return nil
}

// PendingApprovals reads derived state from the view, not a materialized table.
func (s *SQLiteStore) PendingApprovals(ctx context.Context, sessionID string) ([]Event, error) {
	return s.List(ctx, sessionID)
}

// RegisterArtifact records an on-disk artifact produced by an execution.
func (s *SQLiteStore) RegisterArtifact(ctx context.Context, executionID, sessionID, path, sha256 string) error {
	_, err := s.db.ExecContext(ctx, `INSERT INTO artifacts
		(execution_id, session_id, artifact_path, sha256, created_at) VALUES (?, ?, ?, ?, datetime('now'))`,
		executionID, sessionID, path, sha256)
	return err
}

// Artifacts lists registered artifacts for a session.
func (s *SQLiteStore) Artifacts(ctx context.Context, sessionID string) ([]Artifact, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT artifact_id, COALESCE(execution_id,''), artifact_path,
		COALESCE(sha256,''), created_at FROM artifacts WHERE session_id = ? ORDER BY artifact_id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Artifact
	for rows.Next() {
		var a Artifact
		if err := rows.Scan(&a.ID, &a.ExecutionID, &a.Path, &a.SHA256, &a.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// DeleteArtifact removes an artifact row and returns the path it referenced.
// Used only by cleanup, which verifies residue afterwards.
func (s *SQLiteStore) DeleteArtifact(ctx context.Context, path string) error {
	_, err := s.db.ExecContext(ctx, "DELETE FROM artifacts WHERE artifact_path = ?", path)
	return err
}

// RecordVerdict appends a verdict and its evidence links. Attribution is
// derived from the actor, never supplied by the caller.
func (s *SQLiteStore) RecordVerdict(ctx context.Context, sessionID, executionID string, actor Actor, verdict, note string, evidence []string) (int64, error) {
	if verdict != "confirmed" && verdict != "false_positive" && verdict != "unable" {
		return 0, fmt.Errorf("invalid verdict %q", verdict)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	res, err := s.db.ExecContext(ctx, `INSERT INTO verdicts (session_id, execution_id, actor, verdict, note, created_at)
		VALUES (?, ?, ?, ?, ?, datetime('now'))`, sessionID, executionID, string(actor), verdict, note)
	if err != nil {
		return 0, err
	}
	id, _ := res.LastInsertId()
	for _, ref := range evidence {
		if _, err := s.db.ExecContext(ctx, `INSERT INTO verdict_evidence (verdict_id, execution_id, note)
			VALUES (?, ?, ?)`, id, ref, ""); err != nil {
			return 0, err
		}
	}
	return id, nil
}

func (s *SQLiteStore) Verdicts(ctx context.Context, sessionID string) ([]Verdict, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT verdict_id, COALESCE(execution_id,''), actor, verdict,
		COALESCE(note,''), created_at FROM verdicts WHERE session_id = ? ORDER BY verdict_id`, sessionID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Verdict
	for rows.Next() {
		var v Verdict
		var actor string
		if err := rows.Scan(&v.ID, &v.ExecutionID, &actor, &v.Label, &v.Note, &v.CreatedAt); err != nil {
			return nil, err
		}
		v.Actor = Actor(actor)
		out = append(out, v)
	}
	return out, rows.Err()
}

func (s *SQLiteStore) Close() error { return s.db.Close() }

type Artifact struct {
	ID          int64  `json:"artifact_id"`
	ExecutionID string `json:"execution_id"`
	Path        string `json:"path"`
	SHA256      string `json:"sha256"`
	CreatedAt   string `json:"created_at"`
}

type Verdict struct {
	ID          int64  `json:"verdict_id"`
	ExecutionID string `json:"execution_id"`
	Actor       Actor  `json:"actor"`
	Label       string `json:"verdict"`
	Note        string `json:"note"`
	CreatedAt   string `json:"created_at"`
}

const schemaTables = `
CREATE TABLE IF NOT EXISTS events (
    seq           INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id      TEXT NOT NULL UNIQUE,
    session_id    TEXT NOT NULL,
    experiment_id TEXT,
    actor         TEXT NOT NULL CHECK (actor IN ('human','agent','system')),
    type          TEXT NOT NULL,
    tool          TEXT,
    request_id    TEXT,
    payload       TEXT NOT NULL,
    prev_hash     TEXT NOT NULL,
    hash          TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_events_session ON events(session_id, seq);
CREATE INDEX IF NOT EXISTS idx_events_type ON events(type);
CREATE INDEX IF NOT EXISTS idx_events_request ON events(request_id);
CREATE INDEX IF NOT EXISTS idx_events_experiment ON events(experiment_id);

CREATE TABLE IF NOT EXISTS artifacts (
    artifact_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    execution_id  TEXT,
    session_id    TEXT NOT NULL,
    artifact_path TEXT NOT NULL UNIQUE,
    sha256        TEXT NOT NULL,
    created_at    TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_artifacts_session ON artifacts(session_id);

CREATE TABLE IF NOT EXISTS verdicts (
    verdict_id   INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT NOT NULL,
    execution_id TEXT,
    actor        TEXT NOT NULL CHECK (actor IN ('human','agent','system')),
    verdict      TEXT NOT NULL CHECK (verdict IN ('confirmed','false_positive','unable')),
    note         TEXT,
    created_at   TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_verdicts_session ON verdicts(session_id);

CREATE TABLE IF NOT EXISTS verdict_evidence (
    evidence_id  INTEGER PRIMARY KEY AUTOINCREMENT,
    verdict_id   INTEGER NOT NULL,
    execution_id TEXT,
    note         TEXT,
    FOREIGN KEY (verdict_id) REFERENCES verdicts(verdict_id) ON DELETE CASCADE
);
CREATE INDEX IF NOT EXISTS idx_verdict_evidence_verdict ON verdict_evidence(verdict_id);
`

const schemaViews = `
CREATE VIEW v_pending_approvals AS
    SELECT e.* FROM events e
    WHERE e.type = 'approval.requested'
      AND NOT EXISTS (
        SELECT 1 FROM events r
        WHERE r.type = 'approval.resolved' AND r.request_id = e.request_id
      );
CREATE VIEW v_tool_counts AS
    SELECT tool, COUNT(*) AS calls FROM events
    WHERE type IN ('tool.planned','tool.executed') GROUP BY tool;
CREATE VIEW v_current_verdict AS
    SELECT v.* FROM verdicts v
    WHERE v.verdict_id = (SELECT MAX(v2.verdict_id) FROM verdicts v2
                          WHERE v2.session_id = v.session_id);
`

// StorePaths returns the DB path plus the sidecar reference-schema path.
func StorePaths(dir string) (string, string) {
	return dir + "/events.db", dir + "/schema.sql"
}

func ContainsType(events []Event, typ string) bool {
	for _, e := range events {
		if strings.EqualFold(e.Type, typ) {
			return true
		}
	}
	return false
}

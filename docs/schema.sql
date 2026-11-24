-- Reference copy of the PAT event-store schema (schema version 1).
-- Authoritative DDL: core/event/store.go (schemaTables + schemaViews).
-- tests/event_store_test.go checks that this file defines the same tables/views.
-- Old databases (user_version != 0 and != 1) are rejected; no migrations.

PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
PRAGMA synchronous=NORMAL;
PRAGMA temp_store=MEMORY;

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

PRAGMA user_version = 1;

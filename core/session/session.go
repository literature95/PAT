// Package session owns session lifecycle and event replay.
package session

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/pat-toolkit/pat/core/event"
)

type Session struct {
	ID           string `json:"session_id"`
	ExperimentID string `json:"experiment_id"`
	StartedAt    string `json:"started_at"`
	EndedAt      string `json:"ended_at,omitempty"`
}

type Manager struct {
	mu      sync.Mutex
	current *Session
	store   *event.SQLiteStore
	emitter *event.Emitter
}

func NewManager(store *event.SQLiteStore, emitter *event.Emitter) *Manager {
	return &Manager{store: store, emitter: emitter}
}

func (m *Manager) Start(ctx context.Context, experimentID string) (*Session, error) {
	if experimentID == "" {
		experimentID = fmt.Sprintf("PAT_%s", time.Now().UTC().Format("20060102_150405"))
	}
	s := &Session{
		ID:           fmt.Sprintf("ses_%d", time.Now().UnixNano()),
		ExperimentID: experimentID,
		StartedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
	m.mu.Lock()
	m.current = s
	m.mu.Unlock()
	if err := m.emitter.Emit(ctx, event.NewEvent(s.ID, experimentID, event.ActorSystem, event.SessionStarted, map[string]any{
		"session_id": s.ID, "experiment_id": experimentID,
	})); err != nil {
		return nil, err
	}
	return s, nil
}

func (m *Manager) Current() *Session {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.current
}

func (m *Manager) End(ctx context.Context) error {
	s := m.Current()
	if s == nil {
		return nil
	}
	s.EndedAt = time.Now().UTC().Format(time.RFC3339Nano)
	if err := m.emitter.Emit(ctx, event.NewEvent(s.ID, s.ExperimentID, event.ActorSystem, event.SessionEnded, map[string]any{
		"session_id": s.ID,
	})); err != nil {
		return err
	}
	m.mu.Lock()
	m.current = nil
	m.mu.Unlock()
	return nil
}

// Replay reconstructs derived state from the append-only event log.
func (m *Manager) Replay(ctx context.Context, id string) ([]event.Event, error) {
	return m.store.List(ctx, id)
}

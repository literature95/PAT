// Package event defines the append-only event catalog and event bus.
package event

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

var eventCounter atomic.Uint64

// Actor distinguishes human assertions from model assertions (§11.6).
type Actor string

const (
	ActorHuman  Actor = "human"
	ActorAgent  Actor = "agent"
	ActorSystem Actor = "system"
)

// Event type catalog (api/events.md).
const (
	SessionStarted    = "session.started"
	SessionEnded      = "session.ended"
	UserMessage       = "user.message"
	PlanCreated       = "plan.created"
	ToolPlanned       = "tool.planned"
	ApprovalRequested = "approval.requested"
	ApprovalResolved  = "approval.resolved"
	ToolExecuted      = "tool.executed"
	ToolResult        = "tool.result"
	ArtifactRegistered = "artifact.registered"
	VerdictRecorded   = "verdict.recorded"
	AuditExported     = "audit.exported"
	ErrorRaised       = "error.raised"
)

// Event is one append-only record. Hash chains to the previous event.
type Event struct {
	Seq          int64          `json:"seq"`
	ID           string         `json:"event_id"`
	SessionID    string         `json:"session_id"`
	ExperimentID string         `json:"experiment_id"`
	Actor        Actor          `json:"actor"`
	Type         string         `json:"type"`
	Tool         string         `json:"tool,omitempty"`
	RequestID    string         `json:"request_id,omitempty"`
	Payload      map[string]any `json:"payload"`
	PrevHash     string         `json:"prev_hash"`
	Hash         string         `json:"hash"`
	CreatedAt    string         `json:"created_at"`
}

// NewEvent builds an event with a generated ID and timestamp. Hash fields are
// filled by Store.Append so the chain stays authoritative.
func NewEvent(sessionID, experimentID string, actor Actor, typ string, payload map[string]any) *Event {
	if payload == nil {
		payload = map[string]any{}
	}
	return &Event{
		ID:           fmt.Sprintf("evt_%d_%d", time.Now().UnixNano(), eventCounter.Add(1)),
		SessionID:    sessionID,
		ExperimentID: experimentID,
		Actor:        actor,
		Type:         typ,
		Payload:      payload,
		CreatedAt:    time.Now().UTC().Format(time.RFC3339Nano),
	}
}

// ComputeHash returns sha256(prevHash + canonicalJSON(payload)).
func ComputeHash(prevHash string, payload map[string]any) string {
	keys := make([]string, 0, len(payload))
	for k := range payload {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	var b strings.Builder
	b.WriteString(prevHash)
	for _, k := range keys {
		b.WriteString(k)
		b.WriteByte('=')
		raw, _ := json.Marshal(payload[k])
		b.Write(raw)
		b.WriteByte(';')
	}
	sum := sha256.Sum256([]byte(b.String()))
	return hex.EncodeToString(sum[:])
}

// Store is the append-only event storage contract. No Update or Delete.
type Store interface {
	Append(ctx context.Context, e *Event) error
	List(ctx context.Context, sessionID string) ([]Event, error)
	LastHash(ctx context.Context) (string, error)
	Close() error
}

// Bus fans events out to per-session subscribers (and SSE consumers).
type Bus struct {
	mu   sync.RWMutex
	subs map[string]map[chan Event]struct{}
}

func NewBus() *Bus {
	return &Bus{subs: make(map[string]map[chan Event]struct{})}
}

func (b *Bus) Subscribe(sessionID string) (<-chan Event, func()) {
	ch := make(chan Event, 64)
	b.mu.Lock()
	if b.subs[sessionID] == nil {
		b.subs[sessionID] = make(map[chan Event]struct{})
	}
	b.subs[sessionID][ch] = struct{}{}
	b.mu.Unlock()
	return ch, func() {
		b.mu.Lock()
		delete(b.subs[sessionID], ch)
		if len(b.subs[sessionID]) == 0 {
			delete(b.subs, sessionID)
		}
		b.mu.Unlock()
		close(ch)
	}
}

func (b *Bus) Publish(e Event) {
	b.mu.RLock()
	defer b.mu.RUnlock()
	for ch := range b.subs[e.SessionID] {
		select {
		case ch <- e:
		default: // slow subscriber: drop rather than block the kernel
		}
	}
}

// Emitter appends to the store first, then publishes to the bus.
type Emitter struct {
	Store Store
	Bus   *Bus
}

func (em *Emitter) Emit(ctx context.Context, e *Event) error {
	if err := em.Store.Append(ctx, e); err != nil {
		return err
	}
	if em.Bus != nil {
		em.Bus.Publish(*e)
	}
	return nil
}

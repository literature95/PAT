// Package loop implements the explicit agent-loop state machine and the
// approval manager that binds requestId to exactly one tool call.
package loop

import (
	"context"
	"fmt"
	"sync"

	"github.com/pat-toolkit/pat/core/event"
)

type State string

const (
	Idle             State = "idle"
	Planning         State = "planning"
	AwaitingApproval State = "awaiting_approval"
	Executing        State = "executing"
	Observing        State = "observing"
	Done             State = "done"
	Cancelled        State = "cancelled"
	Failed           State = "failed"
)

var allowed = map[State][]State{
	Idle:             {Planning, Cancelled},
	Planning:         {AwaitingApproval, Executing, Done, Failed, Cancelled},
	AwaitingApproval: {Executing, Cancelled, Failed},
	Executing:        {Observing, Failed, Cancelled},
	Observing:        {Done, Planning, Failed, Cancelled},
	Done:             {Planning, Idle},
	Failed:           {Planning, Idle},
	Cancelled:        {Planning, Idle},
}

// Loop is a small, observable state machine. Stop/continue are transitions,
// not ad-hoc flags.
type Loop struct {
	mu    sync.Mutex
	state State
	em    *event.Emitter
}

func New(em *event.Emitter) *Loop { return &Loop{state: Idle, em: em} }

func (l *Loop) State() State {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.state
}

func (l *Loop) Transition(to State) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	valid := false
	for _, next := range allowed[l.state] {
		if next == to {
			valid = true
			break
		}
	}
	if !valid {
		return fmt.Errorf("invalid loop transition %s -> %s", l.state, to)
	}
	l.state = to
	return nil
}

func (l *Loop) Reset() error {
	l.mu.Lock()
	current := l.state
	l.mu.Unlock()
	if current == Idle {
		return nil
	}
	if err := l.Transition(Idle); err != nil {
		// Cancelled/Failed/Done -> Idle is allowed; other states go via Reset.
		l.mu.Lock()
		l.state = Idle
		l.mu.Unlock()
	}
	return nil
}

// Approval binds one requestId to one tool call across frontends.
type Approval struct {
	RequestID string            `json:"request_id"`
	SessionID string            `json:"session_id"`
	Tool      string            `json:"tool"`
	Args      map[string]string `json:"args"`
	Risk      string            `json:"risk"`
	State     string            `json:"state"` // pending | approved | denied
	CreatedAt string            `json:"created_at"`
}

type Manager struct {
	mu      sync.Mutex
	byID    map[string]*Approval
	emitter *event.Emitter
	counter int
	last    map[string]string
}

func NewManager(em *event.Emitter) *Manager {
	return &Manager{byID: make(map[string]*Approval), emitter: em, last: make(map[string]string)}
}

func (m *Manager) Request(ctx context.Context, sessionID, experimentID, tool string, args map[string]string, risk string) (*Approval, error) {
	m.mu.Lock()
	m.counter++
	id := fmt.Sprintf("req_%s_%04d", sessionID, m.counter)
	a := &Approval{RequestID: id, SessionID: sessionID, Tool: tool, Args: args, Risk: risk, State: "pending"}
	m.byID[id] = a
	m.last[sessionID] = id
	m.mu.Unlock()
	if m.emitter != nil {
		if err := m.emitter.Emit(ctx, event.NewEvent(sessionID, experimentID, event.ActorSystem, event.ApprovalRequested, map[string]any{
			"request_id": id, "tool": tool, "args": args, "risk": risk,
		})); err != nil {
			return nil, err
		}
	}
	return a, nil
}

func (m *Manager) Resolve(ctx context.Context, id string, approve bool, actor event.Actor) error {
	m.mu.Lock()
	a, ok := m.byID[id]
	if !ok {
		m.mu.Unlock()
		return fmt.Errorf("unknown requestId %q", id)
	}
	if a.State != "pending" {
		m.mu.Unlock()
		return fmt.Errorf("request %q is already %s", id, a.State)
	}
	if approve {
		a.State = "approved"
	} else {
		a.State = "denied"
	}
	m.mu.Unlock()
	if m.emitter != nil {
		decision := "denied"
		if approve {
			decision = "approved"
		}
		return m.emitter.Emit(ctx, event.NewEvent(a.SessionID, "", actor, event.ApprovalResolved, map[string]any{
			"request_id": id, "decision": decision, "tool": a.Tool,
		}))
	}
	return nil
}

func (m *Manager) Get(id string) (*Approval, bool) {
	m.mu.Lock()
	defer m.mu.Unlock()
	a, ok := m.byID[id]
	return a, ok
}

func (m *Manager) Approved(id string) bool {
	a, ok := m.Get(id)
	return ok && a.State == "approved"
}

func (m *Manager) Last(sessionID string) *Approval {
	m.mu.Lock()
	defer m.mu.Unlock()
	id, ok := m.last[sessionID]
	if !ok {
		return nil
	}
	return m.byID[id]
}

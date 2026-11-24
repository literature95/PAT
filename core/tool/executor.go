package tool

import (
	"fmt"
	"strings"

	"github.com/pat-toolkit/pat/core/event"
	"github.com/pat-toolkit/pat/core/perm"
)

// Executor is the only path to tool execution. Planning is always free;
// execution goes through the permission engine and, when required, an
// approval bound to a single requestId.
type Executor struct{}

func NewExecutor() *Executor { return &Executor{} }

// Plan has no side effects beyond the tool.planned event.
func (x *Executor) Plan(c *Context, name string, args map[string]string) (*Result, error) {
	t, ok := c.Registry.PlanSpec(name)
	if !ok {
		return nil, fmt.Errorf("unknown tool %q", name)
	}
	res, err := t.PlanFunc(c, args)
	if err != nil {
		return nil, err
	}
	if err := c.Emitter.Emit(c.Ctx, event.NewEvent(c.SessionID, c.ExperimentID, c.Actor, event.ToolPlanned, map[string]any{
		"tool": name, "args": args, "preview": res.Preview,
	})); err != nil {
		return nil, err
	}
	return res, nil
}

// Run executes a tool. approvedID is the requestId returned by a prior Run
// when the permission engine answered "ask".
func (x *Executor) Run(c *Context, name string, args map[string]string, approvedID string) (*Result, error) {
	t, ok := c.Registry.Get(name)
	if !ok {
		return nil, fmt.Errorf("tool %q is not registered (disabled capability or unknown name)", name)
	}
	req := perm.CheckRequest{
		Actor:      c.Actor,
		Tool:       t.Name,
		Sub:        t.sub(args),
		Args:       args,
		Targets:    t.Targets(args),
		Command:    t.command(args),
		Write:      t.Write,
		Capability: t.Capability,
	}
	check := c.Perm.Check(req)
	switch check.Decision {
	case perm.Deny:
		if err := c.Emitter.Emit(c.Ctx, event.NewEvent(c.SessionID, c.ExperimentID, c.Actor, event.ErrorRaised, map[string]any{
			"code": "permission_denied", "layer": check.Layer, "message": check.Reason, "tool": name,
		})); err != nil {
			return nil, err
		}
		return nil, fmt.Errorf("permission denied [%s]: %s", check.Layer, check.Reason)
	case perm.Ask:
		if c.Approvals == nil {
			return nil, fmt.Errorf("tool %q needs approval but no approval manager is configured", name)
		}
		if approvedID == "" || !c.Approvals.Approved(approvedID) {
			a, err := c.Approvals.Request(c.Ctx, c.SessionID, c.ExperimentID, name, args, t.Risk)
			if err != nil {
				return nil, err
			}
			return &Result{
				Preview:   fmt.Sprintf("approval required: /approve %s then /run %s", a.RequestID, name),
				RequestID: a.RequestID,
				Warnings:  append([]string{}, check.Warnings...),
			}, nil
		}
		a, ok := c.Approvals.Get(approvedID)
		if !ok || a.Tool != name {
			return nil, fmt.Errorf("requestId %q does not belong to tool %q", approvedID, name)
		}
	}

	backend := "core"
	if strings.Contains(name, "module") || name == "console" || name == "payload_generate" || name == "session_list" {
		backend = c.MSF.Name()
	} else if name == "nmap_scan" {
		backend = c.Nmap.Name()
	}
	if err := c.Emitter.Emit(c.Ctx, event.NewEvent(c.SessionID, c.ExperimentID, c.Actor, event.ToolExecuted, map[string]any{
		"tool": name, "backend": backend, "args": args, "approved_by": approvedID,
	})); err != nil {
		return nil, err
	}

	res, err := t.ExecuteFunc(c, args)
	if err != nil {
		if emitErr := c.Emitter.Emit(c.Ctx, event.NewEvent(c.SessionID, c.ExperimentID, c.Actor, event.ErrorRaised, map[string]any{
			"code": "tool_failed", "tool": name, "message": err.Error(),
		})); emitErr != nil {
			return nil, emitErr
		}
		return nil, err
	}
	for _, p := range res.Artifacts {
		if err := c.Emitter.Emit(c.Ctx, event.NewEvent(c.SessionID, c.ExperimentID, c.Actor, event.ArtifactRegistered, map[string]any{
			"path": p, "tool": name,
		})); err != nil {
			return nil, err
		}
	}
	if err := c.Emitter.Emit(c.Ctx, event.NewEvent(c.SessionID, c.ExperimentID, c.Actor, event.ToolResult, map[string]any{
		"tool": name, "execution_id": res.ExecutionID, "summary": utilSummary(res.Output), "warnings": res.Warnings,
	})); err != nil {
		return nil, err
	}
	return res, nil
}

func utilSummary(s string) string {
	s = strings.TrimSpace(s)
	if len(s) > 400 {
		return s[:400] + "…"
	}
	return s
}

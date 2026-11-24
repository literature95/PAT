package tool

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/pat-toolkit/pat/core/event"
	"github.com/pat-toolkit/pat/core/util"
)

const maxToolOutput = 4096

func firstArg(a map[string]string, keys ...string) string {
	for _, k := range keys {
		if v := strings.TrimSpace(a[k]); v != "" {
			return v
		}
	}
	return ""
}

func targetArgs(a map[string]string) []string {
	raw := firstArg(a, "RHOSTS", "target", "targets", "host")
	if raw == "" {
		return nil
	}
	return strings.FieldsFunc(raw, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' })
}

func optsFrom(a map[string]string) map[string]string {
	out := make(map[string]string, len(a))
	for k, v := range a {
		if k != "RHOSTS" && k != "target" && k != "targets" && k != "host" && k != "module" && k != "type" && k != "cmd" {
			out[k] = v
		}
	}
	return out
}

func builtins(msf MSFBackend, nmap NmapRunner) []*Tool {
	return []*Tool{
		{
			Spec: Spec{Name: "get_capabilities", Description: "Show enabled capabilities, backend and scope", Capability: "", Risk: "none"},
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: "get_capabilities() — read-only introspection"}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				b, err := json.MarshalIndent(c.Perm.CapabilitySnapshot(), "", "  ")
				if err != nil {
					return nil, err
				}
				return &Result{Output: string(b)}, nil
			},
		},
		{
			Spec: Spec{Name: "module_search", Description: "Search MSF modules", Capability: "", Risk: "none"},
			TargetsFunc: targetArgs,
			SubFunc: func(a map[string]string) string { return firstArg(a, "keyword") },
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: fmt.Sprintf("module_search(keyword=%q) — read-only", firstArg(a, "keyword", "module"))}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				kw := firstArg(a, "keyword", "module")
				mods, err := c.MSF.Search(c.Ctx, kw)
				if err != nil {
					return nil, err
				}
				return &Result{Output: util.SafeText(strings.Join(mods, "\n"), maxToolOutput)}, nil
			},
		},
		{
			Spec: Spec{Name: "session_list", Description: "List MSF sessions", Capability: "", Risk: "none"},
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: "session_list() — read-only"}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				sessions, err := c.MSF.Sessions(c.Ctx)
				if err != nil {
					return nil, err
				}
				return &Result{Output: util.SafeText(strings.Join(sessions, "\n"), maxToolOutput)}, nil
			},
		},
		{
			Spec: Spec{Name: "audit_export", Description: "Export events as CSV or Markdown", Capability: "", Risk: "none"},
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: fmt.Sprintf("audit_export(format=%s) — read-only", firstArg(a, "format", "csv"))}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				return exportAudit(c, firstArg(a, "format", "csv"), firstArg(a, "path"))
			},
		},
		{
			Spec: Spec{Name: "nmap_scan", Description: "Run embedded nmap CLI scan", Capability: "execution", Risk: "network scan", Write: true, Execution: true},
			TargetsFunc: targetArgs,
			SubFunc: func(a map[string]string) string { return "scan" },
			CommandFunc: func(a map[string]string) string {
				return "nmap " + firstArg(a, "RHOSTS", "target", "targets", "host") + " " + firstArg(a, "ports")
			},
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: fmt.Sprintf("nmap_scan(RHOSTS=%s, ports=%s) — dry-run, no side effects",
					firstArg(a, "RHOSTS", "target", "targets", "host"), firstArg(a, "ports"))}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				out, err := c.Nmap.Scan(c.Ctx, firstArg(a, "RHOSTS", "target", "targets", "host"), firstArg(a, "ports"))
				if err != nil {
					return nil, err
				}
				return &Result{Output: util.SafeText(out, maxToolOutput)}, nil
			},
		},
		{
			Spec: Spec{Name: "module_execute", Description: "Execute an MSF module", Capability: "execution", Risk: "module execution", Write: true, Execution: true},
			TargetsFunc: targetArgs,
			SubFunc: func(a map[string]string) string { return firstArg(a, "module") },
			CommandFunc: func(a map[string]string) string { return "msfconsole " + firstArg(a, "module") },
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				// §9: preview resolved module name, RHOSTS and LHOST/LPORT.
				return &Result{Preview: fmt.Sprintf("module_execute(module=%s, RHOSTS=%s, LHOST=%s, LPORT=%s) — dry-run, no side effects",
					firstArg(a, "module"), firstArg(a, "RHOSTS"), firstArg(a, "LHOST"), firstArg(a, "LPORT"))}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				out, err := c.MSF.Execute(c.Ctx, firstArg(a, "module"), optsFrom(a))
				if err != nil {
					return nil, err
				}
				return &Result{Output: util.SafeText(out, maxToolOutput)}, nil
			},
		},
		{
			Spec: Spec{Name: "console", Description: "MSF console passthrough", Capability: "execution", Risk: "console command", Write: true, Execution: true},
			SubFunc: func(a map[string]string) string { return "console" },
			CommandFunc: func(a map[string]string) string { return "msfconsole " + firstArg(a, "cmd") },
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: fmt.Sprintf("console(cmd=%q) — only pre-rendered resource scripts are executed", firstArg(a, "cmd"))}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				out, err := c.MSF.Console(c.Ctx, firstArg(a, "cmd"))
				if err != nil {
					return nil, err
				}
				return &Result{Output: util.SafeText(out, maxToolOutput)}, nil
			},
		},
		{
			Spec: Spec{Name: "payload_generate", Description: "Generate a payload (dangerous)", Capability: "mutations", Risk: "payload generation", Write: true},
			SubFunc: func(a map[string]string) string { return firstArg(a, "type") },
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: fmt.Sprintf("payload_generate(type=%s, LHOST=%s, LPORT=%s) — dry-run, no side effects",
					firstArg(a, "type"), firstArg(a, "LHOST"), firstArg(a, "LPORT"))}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				out, err := c.MSF.Payload(c.Ctx, firstArg(a, "type"), optsFrom(a))
				if err != nil {
					return nil, err
				}
				return &Result{Output: util.SafeText(out, maxToolOutput)}, nil
			},
		},
		{
			Spec: Spec{Name: "cleanup", Description: "Remove experiment artifacts and verify zero residue", Capability: "mutations", Risk: "cleanup", Write: true},
			SubFunc: func(a map[string]string) string { return "experiment" },
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: fmt.Sprintf("cleanup(experiment=%s) — dry-run, no side effects", c.ExperimentID)}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				return cleanupArtifacts(c)
			},
		},
		{
			Spec: Spec{Name: "verdict_record", Description: "Record a verdict with evidence links", Capability: "mutations", Risk: "verdict", Write: true},
			SubFunc: func(a map[string]string) string { return firstArg(a, "verdict") },
			PlanFunc: func(c *Context, a map[string]string) (*Result, error) {
				return &Result{Preview: fmt.Sprintf("verdict_record(verdict=%s) — dry-run, no side effects", firstArg(a, "verdict"))}, nil
			},
			ExecuteFunc: func(c *Context, a map[string]string) (*Result, error) {
				evidence := strings.FieldsFunc(firstArg(a, "evidence"), func(r rune) bool { return r == ',' || r == ' ' })
				id, err := c.Store.RecordVerdict(c.Ctx, c.SessionID, firstArg(a, "execution_id"), c.Actor,
					firstArg(a, "verdict"), firstArg(a, "note"), evidence)
				if err != nil {
					return nil, err
				}
				if err := c.Emitter.Emit(c.Ctx, event.NewEvent(c.SessionID, c.ExperimentID, c.Actor, event.VerdictRecorded, map[string]any{
					"verdict": firstArg(a, "verdict"), "verdict_id": id, "execution_id": firstArg(a, "execution_id"),
				})); err != nil {
					return nil, err
				}
				return &Result{Output: fmt.Sprintf("verdict_id=%d", id), ExecutionID: firstArg(a, "execution_id")}, nil
			},
		},
	}
}

func exportAudit(c *Context, format, path string) (*Result, error) {
	events, err := c.Store.List(c.Ctx, "")
	if err != nil {
		return nil, err
	}
	format = strings.ToLower(format)
	if format != "csv" && format != "markdown" && format != "md" {
		return nil, fmt.Errorf("audit format must be csv or markdown, got %q", format)
	}
	var body string
	if format == "csv" {
		body = auditCSV(events)
	} else {
		body = auditMarkdown(events)
	}
	if path != "" {
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			return nil, err
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			return nil, err
		}
	}
	if err := c.Emitter.Emit(c.Ctx, event.NewEvent(c.SessionID, c.ExperimentID, c.Actor, event.AuditExported, map[string]any{
		"format": format, "row_count": len(events), "path": path,
	})); err != nil {
		return nil, err
	}
	return &Result{Output: util.SafeText(body, maxToolOutput)}, nil
}

func auditCSV(events []event.Event) string {
	var b strings.Builder
	b.WriteString("seq,event_id,session_id,experiment_id,actor,type,tool,request_id,payload,created_at\n")
	for _, e := range events {
		payload, _ := json.Marshal(e.Payload)
		row := []string{
			fmt.Sprint(e.Seq), e.ID, e.SessionID, e.ExperimentID, string(e.Actor), e.Type, e.Tool,
			e.RequestID, strings.ReplaceAll(string(payload), "\"", `""`), e.CreatedAt,
		}
		for i, cell := range row {
			if i > 0 {
				b.WriteByte(',')
			}
			b.WriteByte('"')
			b.WriteString(strings.ReplaceAll(cell, "\n", " "))
			b.WriteByte('"')
		}
		b.WriteByte('\n')
	}
	return b.String()
}

func auditMarkdown(events []event.Event) string {
	var b strings.Builder
	b.WriteString("# PAT 审计台账\n\n")
	b.WriteString("## 实验编号\n\n")
	if len(events) > 0 {
		b.WriteString(events[0].ExperimentID + "\n\n")
	}
	b.WriteString("## 前置快照 / 变更内容 / 运行现象 / 检出表现 / 清理确认\n\n")
	b.WriteString("详见下列事件流水（payload 已脱敏，actor 区分人工与模型）。\n\n")
	b.WriteString("| seq | actor | type | tool | request_id | payload |\n|---|---|---|---|---|---|\n")
	for _, e := range events {
		payload, _ := json.Marshal(e.Payload)
		b.WriteString(fmt.Sprintf("| %d | %s | %s | %s | %s | `%s` |\n", e.Seq, e.Actor, e.Type,
			e.Tool, e.RequestID, util.SafeText(string(payload), 200)))
	}
	return b.String()
}

// cleanupArtifacts is idempotent: it deletes registered artifacts whose path
// belongs to this experiment, then re-queries and returns a residue report.
func cleanupArtifacts(c *Context) (*Result, error) {
	artifacts, err := c.Store.Artifacts(c.Ctx, c.SessionID)
	if err != nil {
		return nil, err
	}
	var removed []string
	var residue []string
	for _, a := range artifacts {
		tag := "PAT_" + c.ExperimentID + "_"
		if c.ExperimentID != "" && !strings.Contains(filepath.Base(a.Path), tag) {
			continue
		}
		if err := os.Remove(a.Path); err != nil && !os.IsNotExist(err) {
			residue = append(residue, a.Path+": "+err.Error())
			continue
		}
		if err := c.Store.DeleteArtifact(c.Ctx, a.Path); err != nil {
			return nil, err
		}
		removed = append(removed, a.Path)
	}
	remaining, err := c.Store.Artifacts(c.Ctx, c.SessionID)
	if err != nil {
		return nil, err
	}
	for _, a := range remaining {
		if c.ExperimentID == "" || strings.Contains(filepath.Base(a.Path), "PAT_"+c.ExperimentID+"_") {
			residue = append(residue, a.Path)
		}
	}
	if len(residue) > 0 {
		return nil, fmt.Errorf("cleanup incomplete, residue: %s", strings.Join(residue, ", "))
	}
	return &Result{Output: fmt.Sprintf("cleanup ok: removed=%d, residue=0", len(removed)), Warnings: residue}, nil
}

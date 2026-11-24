// Package server exposes the shared core over REST + SSE. It is an adapter:
// all authorization happens in core/perm, never here.
package server

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/pat-toolkit/pat/app"
	"github.com/pat-toolkit/pat/config"
	"github.com/pat-toolkit/pat/core/event"
)

type Handler struct{ app *app.App }

func NewMux(a *app.App) *http.ServeMux {
	h := &Handler{app: a}
	m := http.NewServeMux()
	m.HandleFunc("POST /api/v1/sessions", h.createSession)
	m.HandleFunc("GET /api/v1/sessions/{id}/events", h.streamEvents)
	m.HandleFunc("GET /api/v1/sessions/{id}/events/list", h.listEvents)
	m.HandleFunc("POST /api/v1/sessions/{id}/messages", h.postMessage)
	m.HandleFunc("POST /api/v1/tools/{name}/plan", h.planTool)
	m.HandleFunc("POST /api/v1/tools/{name}/execute", h.executeTool)
	m.HandleFunc("GET /api/v1/approvals/{requestId}", h.getApproval)
	m.HandleFunc("POST /api/v1/approvals/{requestId}", h.resolveApproval)
	m.HandleFunc("GET /api/v1/capabilities", h.capabilities)
	m.HandleFunc("GET /api/v1/scope", h.scope)
	m.HandleFunc("GET /api/v1/permissions/rules", h.getRules)
	m.HandleFunc("POST /api/v1/permissions/rules", h.setRules)
	m.HandleFunc("GET /api/v1/audit", h.audit)
	m.HandleFunc("POST /api/v1/experiments/{id}/cleanup", h.cleanup)
	m.HandleFunc("GET /api/v1/health", h.health)
	return m
}

func Serve(ctx context.Context, a *app.App, listen string) error {
	srv := &http.Server{
		Addr:              listen,
		Handler:           NewMux(a),
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = srv.Shutdown(shutdownCtx)
	}()
	return srv.ListenAndServe()
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, status int, err error) {
	writeJSON(w, status, map[string]any{"error": err.Error()})
}

func decode(r *http.Request, dst any) error {
	defer r.Body.Close()
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 1<<20))
	return dec.Decode(dst)
}

func (h *Handler) health(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{"status": "ok", "service": "patd"})
}

func (h *Handler) createSession(w http.ResponseWriter, r *http.Request) {
	var body struct{ ExperimentID string `json:"experiment_id"` }
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if err := h.app.StartSession(r.Context(), body.ExperimentID); err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	s := h.app.Sessions.Current()
	writeJSON(w, http.StatusCreated, s)
}

func (h *Handler) streamEvents(w http.ResponseWriter, r *http.Request) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		fail(w, http.StatusInternalServerError, fmt.Errorf("streaming unsupported"))
		return
	}
	id := r.PathValue("id")
	ch, cancel := h.app.Bus.Subscribe(id)
	defer cancel()
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	w.Header().Set("Connection", "keep-alive")
	fmt.Fprint(w, ": patd event stream connected\n\n")
	flusher.Flush()
	for {
		select {
		case <-r.Context().Done():
			return
		case e, ok := <-ch:
			if !ok {
				return
			}
			raw, _ := json.Marshal(e)
			fmt.Fprintf(w, "event: %s\ndata: %s\n\n", e.Type, raw)
			flusher.Flush()
		}
	}
}

func (h *Handler) listEvents(w http.ResponseWriter, r *http.Request) {
	events, err := h.app.Store.List(r.Context(), r.PathValue("id"))
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, events)
}

func (h *Handler) postMessage(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Text  string `json:"text"`
		Actor string `json:"actor"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	reply, err := h.app.HandleMessage(r.Context(), body.Text)
	if err != nil {
		fail(w, http.StatusInternalServerError, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"reply": reply})
}

func (h *Handler) planTool(w http.ResponseWriter, r *http.Request) {
	var args map[string]string
	if err := decode(r, &args); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	c := h.app.Context(r.Context(), event.ActorHuman)
	res, err := h.app.Executor.Plan(c, r.PathValue("name"), args)
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) executeTool(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Args      map[string]string `json:"args"`
		RequestID string            `json:"request_id"`
		Actor     string            `json:"actor"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	actor := event.ActorHuman
	if body.Actor == "agent" {
		actor = event.ActorAgent
	}
	c := h.app.Context(r.Context(), actor)
	res, err := h.app.Executor.Run(c, r.PathValue("name"), body.Args, body.RequestID)
	if err != nil {
		if strings.Contains(err.Error(), "permission denied") {
			fail(w, http.StatusForbidden, err)
		} else {
			fail(w, http.StatusBadRequest, err)
		}
		return
	}
	writeJSON(w, http.StatusOK, res)
}

func (h *Handler) getApproval(w http.ResponseWriter, r *http.Request) {
	a, ok := h.app.Approvals.Get(r.PathValue("requestId"))
	if !ok {
		fail(w, http.StatusNotFound, fmt.Errorf("unknown requestId"))
		return
	}
	writeJSON(w, http.StatusOK, a)
}

func (h *Handler) resolveApproval(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Decision string `json:"decision"` // approve | deny
		Actor    string `json:"actor"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	approve := strings.EqualFold(body.Decision, "approve") || strings.EqualFold(body.Decision, "yes")
	actor := event.ActorHuman
	if body.Actor == "agent" {
		actor = event.ActorAgent
	}
	if err := h.app.Approvals.Resolve(r.Context(), r.PathValue("requestId"), approve, actor); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"request_id": r.PathValue("requestId"), "approved": approve})
}

func (h *Handler) capabilities(w http.ResponseWriter, r *http.Request) {
	snap := h.app.Perm.CapabilitySnapshot()
	snap["backend_info"] = h.app.BackendInfo
	snap["registered_tools"] = h.app.Registry.Names()
	snap["gated_tools"] = h.app.Registry.Gated(h.app.Config)
	snap["schema_version"] = event.SchemaVersion
	writeJSON(w, http.StatusOK, snap)
}

func (h *Handler) scope(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"scope":       h.app.Config.Lab.Scope,
		"scope_extra": h.app.Config.Lab.ScopeExtra,
		"details":     h.app.Perm.Scope().Summary(),
	})
}

func (h *Handler) getRules(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, h.app.Config.Permission.Rules)
}

func (h *Handler) setRules(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Rules []config.PermissionRule `json:"rules"`
	}
	if err := decode(r, &body); err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	h.app.Config.Permission.Rules = body.Rules // in-memory for this process only
	writeJSON(w, http.StatusOK, h.app.Config.Permission.Rules)
}

func (h *Handler) audit(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "csv"
	}
	c := h.app.Context(r.Context(), event.ActorHuman)
	res, err := h.app.Executor.Run(c, "audit_export", map[string]string{"format": format}, "")
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	if format == "csv" {
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
	} else {
		w.Header().Set("Content-Type", "text/markdown; charset=utf-8")
	}
	_, _ = w.Write([]byte(res.Output))
}

func (h *Handler) cleanup(w http.ResponseWriter, r *http.Request) {
	c := h.app.Context(r.Context(), event.ActorHuman)
	res, err := h.app.Executor.Run(c, "cleanup", nil, "")
	if err != nil {
		fail(w, http.StatusBadRequest, err)
		return
	}
	writeJSON(w, http.StatusOK, res)
}

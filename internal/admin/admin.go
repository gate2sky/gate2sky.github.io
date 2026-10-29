// Package admin exposes management operations on a local Unix socket, for
// `gate2net config` and `gate2net status`. Access is controlled by the
// socket's file permissions: only the service user and root can connect.
package admin

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"strconv"
	"time"

	"github.com/gate2net/gate2net.github.io/internal/api"
	"github.com/gate2net/gate2net.github.io/internal/config"
	"github.com/gate2net/gate2net.github.io/internal/manage"
	"github.com/gate2net/gate2net.github.io/internal/store"
)

// Status describes the running server.
type Status struct {
	Version       string    `json:"version"`
	PID           int       `json:"pid"`
	StartedAt     time.Time `json:"started_at"`
	DashboardURL  string    `json:"dashboard_url"`
	SSH           string    `json:"ssh"`
	Subdomains    int       `json:"subdomains"`
	TunnelsOnline int       `json:"tunnels_online"`
	Users         int       `json:"users"`
}

// The shapes the socket answers with are the dashboard API's.
type (
	Subdomain       = api.Subdomain
	Key             = api.Key
	SubdomainDetail = api.SubdomainDetail
	User            = api.User
	KeysResult      = api.KeysResult
)

// CreateSubdomainRequest registers a subdomain for Owner (created if new).
type CreateSubdomainRequest struct {
	Name   string       `json:"name"`
	Owner  string       `json:"owner"`
	Access store.Access `json:"access"`
	Keys   string       `json:"keys"`
}

// KeysRequest adds keys in authorized_keys format.
type KeysRequest struct {
	Keys string `json:"keys"`
	Name string `json:"name"`
}

const actor = "local admin"

// Handler serves the admin API.
type Handler struct {
	cfg     *config.Config
	store   *store.Store
	manage  *manage.Service
	log     *slog.Logger
	version string
	started time.Time
	mux     *http.ServeMux
}

// NewHandler returns the admin API handler.
func NewHandler(cfg *config.Config, st *store.Store, svc *manage.Service, log *slog.Logger, version string) *Handler {
	h := &Handler{cfg: cfg, store: st, manage: svc, log: log, version: version, started: time.Now(), mux: http.NewServeMux()}
	h.mux.HandleFunc("GET /v1/status", h.status)
	h.mux.HandleFunc("GET /v1/subdomains", h.listSubdomains)
	h.mux.HandleFunc("POST /v1/subdomains", h.createSubdomain)
	h.mux.HandleFunc("GET /v1/subdomains/{name}", h.getSubdomain)
	h.mux.HandleFunc("POST /v1/subdomains/{name}/access", h.setAccess)
	h.mux.HandleFunc("POST /v1/subdomains/{name}/keys", h.addKeys)
	h.mux.HandleFunc("DELETE /v1/subdomains/{name}/keys/{id}", h.removeKey)
	h.mux.HandleFunc("POST /v1/subdomains/{name}/disconnect", h.disconnect)
	h.mux.HandleFunc("DELETE /v1/subdomains/{name}", h.deleteSubdomain)
	h.mux.HandleFunc("GET /v1/users", h.listUsers)
	h.mux.HandleFunc("POST /v1/users", h.createUser)
	h.mux.HandleFunc("POST /v1/users/{id}/disable", h.setDisabled(true))
	h.mux.HandleFunc("POST /v1/users/{id}/enable", h.setDisabled(false))
	return h
}

func (h *Handler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	h.mux.ServeHTTP(w, r)
}

// Serve listens on the configured socket until ctx ends.
func (h *Handler) Serve(ctx context.Context) error {
	path := h.cfg.Admin.Socket
	// A socket left behind by a crash would block Listen; remove it unless
	// another server is answering on it.
	if c, err := net.DialTimeout("unix", path, time.Second); err == nil {
		c.Close()
		return fmt.Errorf("admin socket %s is in use: is gate2net already running?", path)
	}
	os.Remove(path)
	ln, err := net.Listen("unix", path)
	if err != nil {
		return fmt.Errorf("admin socket: %w", err)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		ln.Close()
		return err
	}
	defer os.Remove(path)
	srv := &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second}
	stop := context.AfterFunc(ctx, func() { srv.Close() })
	defer stop()
	if err := srv.Serve(ln); err != nil && !errors.Is(err, http.ErrServerClosed) {
		return err
	}
	return nil
}

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

func (h *Handler) fail(w http.ResponseWriter, err error) {
	var me *manage.Error
	switch {
	case errors.As(err, &me):
		writeJSON(w, http.StatusBadRequest, map[string]string{"error": me.Error()})
	case errors.Is(err, store.ErrNotFound):
		writeJSON(w, http.StatusNotFound, map[string]string{"error": "not found"})
	default:
		h.log.Error("admin request", "err", err)
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "internal error: " + err.Error()})
	}
}

func decode(r *http.Request, v any) error {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		return manage.Errorf("invalid request: %v", err)
	}
	return nil
}

func (h *Handler) status(w http.ResponseWriter, r *http.Request) {
	subs, err := h.store.AllSubdomains(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	online := 0
	for _, d := range subs {
		if h.manage.Tunnel(d.Name) != nil {
			online++
		}
	}
	writeJSON(w, http.StatusOK, Status{
		Version:       h.version,
		PID:           os.Getpid(),
		StartedAt:     h.started,
		DashboardURL:  h.cfg.DashboardURL("/"),
		SSH:           fmt.Sprintf("%s:%d", h.cfg.SSHHost(), h.cfg.SSHPort()),
		Subdomains:    len(subs),
		TunnelsOnline: online,
		Users:         len(users),
	})
}

func (h *Handler) subdomain(d *store.Subdomain) Subdomain {
	return api.NewSubdomain(h.cfg, d, h.manage.Tunnel(d.Name))
}

func (h *Handler) listSubdomains(w http.ResponseWriter, r *http.Request) {
	subs, err := h.store.AllSubdomains(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]Subdomain, len(subs))
	for i, d := range subs {
		out[i] = h.subdomain(d)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) load(w http.ResponseWriter, r *http.Request) *store.Subdomain {
	d, err := h.store.SubdomainByName(r.Context(), r.PathValue("name"))
	if err != nil {
		h.fail(w, err)
		return nil
	}
	return d
}

func (h *Handler) getSubdomain(w http.ResponseWriter, r *http.Request) {
	d := h.load(w, r)
	if d == nil {
		return
	}
	keys, err := h.store.KeysBySubdomain(r.Context(), d.ID)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, SubdomainDetail{Subdomain: h.subdomain(d), KeyList: api.NewKeys(keys)})
}

func (h *Handler) createSubdomain(w http.ResponseWriter, r *http.Request) {
	var req CreateSubdomainRequest
	if err := decode(r, &req); err != nil {
		h.fail(w, err)
		return
	}
	if req.Access == "" {
		req.Access = store.AccessPublic
	}
	// Check the name first, so a failed request creates no account.
	if err := h.manage.CheckName(r.Context(), req.Name); err != nil {
		h.fail(w, err)
		return
	}
	owner, err := h.manage.EnsureUser(r.Context(), req.Owner, actor)
	if err != nil {
		h.fail(w, err)
		return
	}
	d, res, err := h.manage.CreateSubdomain(r.Context(), owner, req.Name, req.Access, req.Keys, true, actor)
	if err != nil {
		h.fail(w, err)
		return
	}
	d, err = h.store.SubdomainByName(r.Context(), d.Name)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		Subdomain Subdomain  `json:"subdomain"`
		Keys      KeysResult `json:"keys"`
	}{h.subdomain(d), KeysResult{Added: res.Added, Problems: res.Problems}})
}

func (h *Handler) setAccess(w http.ResponseWriter, r *http.Request) {
	d := h.load(w, r)
	if d == nil {
		return
	}
	var req struct {
		Access store.Access `json:"access"`
	}
	if err := decode(r, &req); err != nil {
		h.fail(w, err)
		return
	}
	if err := h.manage.SetAccess(r.Context(), d, req.Access, actor); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) addKeys(w http.ResponseWriter, r *http.Request) {
	d := h.load(w, r)
	if d == nil {
		return
	}
	var req KeysRequest
	if err := decode(r, &req); err != nil {
		h.fail(w, err)
		return
	}
	res, err := h.manage.AddKeys(r.Context(), d, req.Keys, req.Name, actor)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusOK, KeysResult{Added: res.Added, Problems: res.Problems})
}

func (h *Handler) removeKey(w http.ResponseWriter, r *http.Request) {
	d := h.load(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := h.manage.RemoveKey(r.Context(), d, id, actor); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) disconnect(w http.ResponseWriter, r *http.Request) {
	d := h.load(w, r)
	if d == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"disconnected": h.manage.Disconnect(d, actor)})
}

func (h *Handler) deleteSubdomain(w http.ResponseWriter, r *http.Request) {
	d := h.load(w, r)
	if d == nil {
		return
	}
	if err := h.manage.DeleteSubdomain(r.Context(), d, actor); err != nil {
		h.fail(w, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *Handler) listUsers(w http.ResponseWriter, r *http.Request) {
	users, err := h.store.ListUsers(r.Context())
	if err != nil {
		h.fail(w, err)
		return
	}
	out := make([]User, len(users))
	for i, u := range users {
		out[i] = api.NewUser(h.cfg, u)
	}
	writeJSON(w, http.StatusOK, out)
}

func (h *Handler) createUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if err := decode(r, &req); err != nil {
		h.fail(w, err)
		return
	}
	u, err := h.manage.CreateUser(r.Context(), req.Email, actor)
	if err != nil {
		h.fail(w, err)
		return
	}
	writeJSON(w, http.StatusCreated, api.NewUser(h.cfg, store.UserSummary{User: *u}))
}

func (h *Handler) setDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if err := h.manage.SetUserDisabled(r.Context(), id, disabled, actor); err != nil {
			h.fail(w, err)
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

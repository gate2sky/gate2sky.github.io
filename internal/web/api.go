package web

import (
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"time"

	"github.com/gate2sky/gate2sky.github.io/internal/api"
	"github.com/gate2sky/gate2sky.github.io/internal/manage"
	"github.com/gate2sky/gate2sky.github.io/internal/store"
)

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(v)
}

// apiError is the body of every error the API answers with.
type apiError struct {
	Error string `json:"error"`
	// Expired tells the sign-in form to start over and ask for a new code.
	Expired bool `json:"expired,omitempty"`
}

func jsonError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, apiError{Error: msg})
}

// decode reads a JSON request body into v, answering a 400 if it can't.
func decode(w http.ResponseWriter, r *http.Request, v any) bool {
	if err := json.NewDecoder(r.Body).Decode(v); err != nil {
		jsonError(w, http.StatusBadRequest, "Invalid request.")
		return false
	}
	return true
}

func (s *Server) internalError(w http.ResponseWriter, what string, err error) {
	s.log.Error(what, "err", err)
	jsonError(w, http.StatusInternalServerError, msgInternal)
}

// fail answers err as a 400 the user can act on when it is one, and as an
// internal error otherwise.
func (s *Server) fail(w http.ResponseWriter, what string, err error) {
	var me *manage.Error
	if errors.As(err, &me) {
		jsonError(w, http.StatusBadRequest, capitalize(me.Error())+".")
		return
	}
	s.internalError(w, what, err)
}

func capitalize(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

func (s *Server) view(d *store.Subdomain) api.Subdomain {
	return api.NewSubdomain(s.cfg, d, s.manage.Tunnel(d.Name))
}

func (s *Server) views(subs []*store.Subdomain) []api.Subdomain {
	out := make([]api.Subdomain, len(subs))
	for i, d := range subs {
		out[i] = s.view(d)
	}
	return out
}

func (s *Server) handleListSubdomains(w http.ResponseWriter, r *http.Request) {
	subs, err := s.store.SubdomainsByUser(r.Context(), currentAuth(r).User.ID)
	if err != nil {
		s.internalError(w, "list subdomains", err)
		return
	}
	writeJSON(w, http.StatusOK, s.views(subs))
}

func (s *Server) handleCreateSubdomain(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	var req struct {
		Name   string       `json:"name"`
		Access store.Access `json:"access"`
		Keys   string       `json:"keys"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Access == "" {
		req.Access = store.AccessPublic
	}
	d, res, err := s.manage.CreateSubdomain(r.Context(), a.User, req.Name, req.Access, req.Keys, a.Admin, a.User.Email)
	if d == nil {
		s.fail(w, "create subdomain", err)
		return
	}
	if err != nil {
		s.log.Error("add keys", "err", err)
		res.Problems = append(res.Problems, "an internal error occurred")
	}
	// Read back for the key count.
	if d, err = s.store.SubdomainByName(r.Context(), d.Name); err != nil {
		s.internalError(w, "load subdomain", err)
		return
	}
	writeJSON(w, http.StatusCreated, struct {
		Subdomain api.Subdomain  `json:"subdomain"`
		Keys      api.KeysResult `json:"keys"`
	}{s.view(d), api.KeysResult{Added: res.Added, Problems: res.Problems}})
}

// loadSubdomain returns the subdomain in the URL if the user may manage
// it. Others get a 404, so names of private subdomains don't leak.
func (s *Server) loadSubdomain(w http.ResponseWriter, r *http.Request) *store.Subdomain {
	a := currentAuth(r)
	d, err := s.store.SubdomainByName(r.Context(), r.PathValue("name"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, "load subdomain", err)
		return nil
	}
	if d == nil || (d.UserID != a.User.ID && !a.Admin) {
		jsonError(w, http.StatusNotFound, "Subdomain not found.")
		return nil
	}
	return d
}

func (s *Server) handleSubdomain(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	keys, err := s.store.KeysBySubdomain(r.Context(), d.ID)
	if err != nil {
		s.internalError(w, "list keys", err)
		return
	}
	writeJSON(w, http.StatusOK, struct {
		api.SubdomainDetail
		SSHCommand string `json:"ssh_command"`
		Mine       bool   `json:"mine"`
	}{
		SubdomainDetail: api.SubdomainDetail{Subdomain: s.view(d), KeyList: api.NewKeys(keys)},
		SSHCommand:      s.sshCommand(d.Name),
		Mine:            d.UserID == currentAuth(r).User.ID,
	})
}

func (s *Server) handleUpdateSubdomain(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	var req struct {
		Access store.Access `json:"access"`
	}
	if !decode(w, r, &req) {
		return
	}
	if err := s.manage.SetAccess(r.Context(), d, req.Access, currentAuth(r).User.Email); err != nil {
		s.fail(w, "set access", err)
		return
	}
	d.Access = req.Access
	writeJSON(w, http.StatusOK, s.view(d))
}

func (s *Server) handleAddKeys(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	var req struct {
		Keys string `json:"keys"`
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	res, err := s.manage.AddKeys(r.Context(), d, req.Keys, req.Name, currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, "add keys", err)
		return
	}
	writeJSON(w, http.StatusOK, api.KeysResult{Added: res.Added, Problems: res.Problems})
}

func (s *Server) handleRenameKey(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &req) {
		return
	}
	name, err := s.manage.RenameKey(r.Context(), d, id, req.Name, currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, "rename key", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"name": name})
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	if _, err := s.manage.RemoveKey(r.Context(), d, id, currentAuth(r).User.Email); err != nil {
		s.fail(w, "delete key", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	writeJSON(w, http.StatusOK, map[string]bool{"disconnected": s.manage.Disconnect(d, currentAuth(r).User.Email)})
}

func (s *Server) handleDeleteSubdomain(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	if err := s.manage.DeleteSubdomain(r.Context(), d, currentAuth(r).User.Email); err != nil {
		s.internalError(w, "delete subdomain", err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// passkey describes a passkey to its owner.
type passkey struct {
	ID         int64     `json:"id"`
	Name       string    `json:"name"`
	CreatedAt  time.Time `json:"created_at"`
	LastUsedAt time.Time `json:"last_used_at"`
}

func passkeyView(p *store.Passkey) passkey {
	return passkey{p.ID, p.Name, p.CreatedAt, p.LastUsedAt}
}

func (s *Server) handleAccount(w http.ResponseWriter, r *http.Request) {
	keys := []passkey{}
	if s.webauthn != nil {
		list, err := s.store.PasskeysByUser(r.Context(), currentAuth(r).User.ID)
		if err != nil {
			s.internalError(w, "list passkeys", err)
			return
		}
		for _, p := range list {
			keys = append(keys, passkeyView(p))
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{"passkeys": keys})
}

func (s *Server) handleAdminSubdomains(w http.ResponseWriter, r *http.Request) {
	subs, err := s.store.AllSubdomains(r.Context())
	if err != nil {
		s.internalError(w, "list subdomains", err)
		return
	}
	writeJSON(w, http.StatusOK, s.views(subs))
}

func (s *Server) handleAdminUsers(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.internalError(w, "list users", err)
		return
	}
	out := make([]api.User, len(users))
	for i, u := range users {
		out[i] = api.NewUser(s.cfg, u)
	}
	writeJSON(w, http.StatusOK, out)
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	u, err := s.manage.CreateUser(r.Context(), req.Email, currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, "create user", err)
		return
	}
	writeJSON(w, http.StatusCreated, api.NewUser(s.cfg, store.UserSummary{User: *u}))
}

func (s *Server) handleAdminUpdateUser(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	var req struct {
		Disabled *bool `json:"disabled"`
		Admin    *bool `json:"admin"`
	}
	if !decode(w, r, &req) {
		return
	}
	if req.Disabled == nil && req.Admin == nil {
		jsonError(w, http.StatusBadRequest, "Nothing to change.")
		return
	}
	if id == a.User.ID && req.Disabled != nil && *req.Disabled {
		jsonError(w, http.StatusBadRequest, "You can't disable your own account.")
		return
	}
	// Another administrator has to take the role away, so there is always one.
	if id == a.User.ID && req.Admin != nil && !*req.Admin {
		jsonError(w, http.StatusBadRequest, "You can't remove your own administrator role.")
		return
	}
	if req.Disabled != nil {
		if err := s.manage.SetUserDisabled(r.Context(), id, *req.Disabled, a.User.Email); err != nil {
			s.fail(w, "set user disabled", err)
			return
		}
	}
	if req.Admin != nil {
		if err := s.manage.SetUserAdmin(r.Context(), id, *req.Admin, a.User.Email); err != nil {
			s.fail(w, "set user admin", err)
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}

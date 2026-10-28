package web

import (
	"errors"
	"net/http"
	"strconv"

	"github.com/jgermade/securegate/internal/manage"
	"github.com/jgermade/securegate/internal/store"
	"github.com/jgermade/securegate/internal/tunnel"
)

// subdomainRow is a subdomain with its live tunnel, if connected.
type subdomainRow struct {
	*store.Subdomain
	Tunnel *tunnel.Stats
}

func (s *Server) withTunnel(d *store.Subdomain) subdomainRow {
	return subdomainRow{Subdomain: d, Tunnel: s.manage.Tunnel(d.Name)}
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	if a == nil {
		s.renderLogin(w, r, http.StatusOK, "/", "")
		return
	}
	subs, err := s.store.SubdomainsByUser(r.Context(), a.User.ID)
	if err != nil {
		s.internalError(w, r, "list subdomains", err)
		return
	}
	rows := make([]subdomainRow, len(subs))
	for i, d := range subs {
		rows[i] = s.withTunnel(d)
	}
	s.render(w, r, http.StatusOK, "dashboard", "Subdomains", struct {
		Subdomains []subdomainRow
		Limit      int
	}{rows, s.cfg.Limits.SubdomainsPerUser})
}

func (s *Server) internalError(w http.ResponseWriter, r *http.Request, what string, err error) {
	s.log.Error(what, "err", err)
	s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
}

// fail reports err as a flash message on redirect if the user can act on
// it, or as an internal error otherwise.
func (s *Server) fail(w http.ResponseWriter, r *http.Request, redirect, what string, err error) {
	var me *manage.Error
	if errors.As(err, &me) {
		s.setFlash(w, "error", "%s.", capitalize(me.Error()))
		http.Redirect(w, r, redirect, http.StatusSeeOther)
		return
	}
	s.internalError(w, r, what, err)
}

func capitalize(s string) string {
	if s == "" || s[0] < 'a' || s[0] > 'z' {
		return s
	}
	return string(s[0]-'a'+'A') + s[1:]
}

func (s *Server) handleCreateSubdomain(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	d, res, err := s.manage.CreateSubdomain(r.Context(), a.User, r.PostFormValue("name"),
		store.Access(r.PostFormValue("access")), r.PostFormValue("keys"), a.Admin, a.User.Email)
	if d == nil {
		s.fail(w, r, "/", "create subdomain", err)
		return
	}
	if err != nil {
		s.log.Error("add keys", "err", err)
		res.Problems = append(res.Problems, "an internal error occurred")
	}
	if msg := res.Message(); msg != "" {
		s.setFlash(w, "error", "%s.%s registered, but some keys were not added: %s", d.Name, s.cfg.Domain(), msg)
	} else {
		s.setFlash(w, "ok", "%s.%s registered with %d SSH key(s).", d.Name, s.cfg.Domain(), res.Added)
	}
	http.Redirect(w, r, subdomainPath(d), http.StatusSeeOther)
}

// loadSubdomain returns the subdomain in the URL if the user may manage
// it. Others get a 404, so names of private subdomains don't leak.
func (s *Server) loadSubdomain(w http.ResponseWriter, r *http.Request) *store.Subdomain {
	a := currentAuth(r)
	d, err := s.store.SubdomainByName(r.Context(), r.PathValue("name"))
	if err != nil && !errors.Is(err, store.ErrNotFound) {
		s.internalError(w, r, "load subdomain", err)
		return nil
	}
	if d == nil || (d.UserID != a.User.ID && !a.Admin) {
		s.renderError(w, r, http.StatusNotFound, "Subdomain not found.")
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
		s.internalError(w, r, "list keys", err)
		return
	}
	s.render(w, r, http.StatusOK, "subdomain", d.Name, struct {
		subdomainRow
		Keys     []*store.Key
		KeyLimit int
		NotOwner bool
	}{
		subdomainRow: s.withTunnel(d),
		Keys:         keys,
		KeyLimit:     s.cfg.Limits.KeysPerSubdomain,
		NotOwner:     d.UserID != currentAuth(r).User.ID,
	})
}

func subdomainPath(d *store.Subdomain) string { return "/subdomains/" + d.Name }

func (s *Server) back(w http.ResponseWriter, r *http.Request, d *store.Subdomain, kind, format string, args ...any) {
	s.setFlash(w, kind, format, args...)
	http.Redirect(w, r, subdomainPath(d), http.StatusSeeOther)
}

func (s *Server) handleSetAccess(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	access := store.Access(r.PostFormValue("access"))
	if err := s.manage.SetAccess(r.Context(), d, access, currentAuth(r).User.Email); err != nil {
		s.fail(w, r, subdomainPath(d), "set access", err)
		return
	}
	s.back(w, r, d, "ok", "Access set to %s.", access)
}

func (s *Server) handleAddKeys(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	res, err := s.manage.AddKeys(r.Context(), d, r.PostFormValue("keys"), r.PostFormValue("name"), currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, r, subdomainPath(d), "add keys", err)
		return
	}
	if msg := res.Message(); msg != "" {
		s.back(w, r, d, "error", "Added %d key(s), but: %s", res.Added, msg)
		return
	}
	s.back(w, r, d, "ok", "Added %d key(s).", res.Added)
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	k, err := s.manage.RemoveKey(r.Context(), d, id, currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, r, subdomainPath(d), "delete key", err)
		return
	}
	s.back(w, r, d, "ok", "Removed key %q.", k.Name)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	s.manage.Disconnect(d, currentAuth(r).User.Email)
	s.back(w, r, d, "ok", "Disconnected.")
}

func (s *Server) handleDeleteSubdomain(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	if r.PostFormValue("confirm") != d.Name {
		s.back(w, r, d, "error", "Type %q to confirm the deletion.", d.Name)
		return
	}
	if err := s.manage.DeleteSubdomain(r.Context(), d, currentAuth(r).User.Email); err != nil {
		s.internalError(w, r, "delete subdomain", err)
		return
	}
	s.setFlash(w, "ok", "Deleted %s.%s.", d.Name, s.cfg.Domain())
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

func (s *Server) handleAdmin(w http.ResponseWriter, r *http.Request) {
	users, err := s.store.ListUsers(r.Context())
	if err != nil {
		s.internalError(w, r, "list users", err)
		return
	}
	subs, err := s.store.AllSubdomains(r.Context())
	if err != nil {
		s.internalError(w, r, "list subdomains", err)
		return
	}
	rows := make([]subdomainRow, len(subs))
	online := 0
	for i, d := range subs {
		rows[i] = s.withTunnel(d)
		if rows[i].Tunnel != nil {
			online++
		}
	}
	s.render(w, r, http.StatusOK, "admin", "Admin", struct {
		Users      []store.UserSummary
		Subdomains []subdomainRow
		Online     int
		Me         int64
	}{users, rows, online, currentAuth(r).User.ID})
}

func (s *Server) handleAdminCreateUser(w http.ResponseWriter, r *http.Request) {
	u, err := s.manage.CreateUser(r.Context(), r.PostFormValue("email"), currentAuth(r).User.Email)
	if err != nil {
		s.fail(w, r, "/admin", "create user", err)
		return
	}
	s.setFlash(w, "ok", "Added %s. They can now sign in with their email.", u.Email)
	http.Redirect(w, r, "/admin", http.StatusSeeOther)
}

func (s *Server) handleSetUserDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := currentAuth(r)
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if id == a.User.ID {
			s.setFlash(w, "error", "You can't disable your own account.")
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		if err := s.manage.SetUserDisabled(r.Context(), id, disabled, a.User.Email); err != nil {
			s.fail(w, r, "/admin", "set user disabled", err)
			return
		}
		verb := "Enabled"
		if disabled {
			verb = "Disabled"
		}
		s.setFlash(w, "ok", "%s user #%d.", verb, id)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
}

package web

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"unicode/utf8"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/securegate/internal/names"
	"github.com/jgermade/securegate/internal/store"
	"github.com/jgermade/securegate/internal/tunnel"
)

// subdomainRow is a subdomain with its live tunnel, if connected.
type subdomainRow struct {
	*store.Subdomain
	Tunnel *tunnel.Stats
}

func (s *Server) withTunnel(d *store.Subdomain) subdomainRow {
	row := subdomainRow{Subdomain: d}
	if t := s.registry.Get(d.Name); t != nil {
		st := t.Stats()
		row.Tunnel = &st
	}
	return row
}

func (s *Server) handleHome(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	if a == nil {
		s.renderLogin(w, r, http.StatusOK, "/")
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

func (s *Server) handleCreateSubdomain(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	name := names.Normalize(r.PostFormValue("name"))
	access := store.Access(r.PostFormValue("access"))
	if !access.Valid() {
		access = store.AccessPublic
	}
	fail := func(format string, args ...any) {
		s.setFlash(w, "error", format, args...)
		http.Redirect(w, r, "/", http.StatusSeeOther)
	}
	if err := s.names.Check(name); err != nil {
		fail("%q can't be used: %v.", name, err)
		return
	}
	owned, err := s.store.SubdomainsByUser(r.Context(), a.User.ID)
	if err != nil {
		s.internalError(w, r, "list subdomains", err)
		return
	}
	if len(owned) >= s.cfg.Limits.SubdomainsPerUser && !a.Admin {
		fail("You can register at most %d subdomains.", s.cfg.Limits.SubdomainsPerUser)
		return
	}
	// Parse keys before creating anything, so a typo doesn't leave a
	// half-configured subdomain behind.
	keys, err := parseKeys(r.PostFormValue("keys"))
	if err != nil {
		fail("%v", err)
		return
	}
	d, err := s.store.CreateSubdomain(r.Context(), a.User.ID, name, access)
	if errors.Is(err, store.ErrConflict) {
		fail("%s.%s is already taken.", name, s.cfg.Domain())
		return
	}
	if err != nil {
		s.internalError(w, r, "create subdomain", err)
		return
	}
	s.log.Info("subdomain created", "subdomain", name, "user_id", a.User.ID)
	added, msg := s.addKeys(r, d, keys)
	if msg != "" {
		s.setFlash(w, "error", "%s.%s registered, but: %s", name, s.cfg.Domain(), msg)
	} else {
		s.setFlash(w, "ok", "%s.%s registered with %d SSH key(s).", name, s.cfg.Domain(), added)
	}
	http.Redirect(w, r, "/subdomains/"+name, http.StatusSeeOther)
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
		Accesses []store.Access
	}{
		subdomainRow: s.withTunnel(d),
		Keys:         keys,
		KeyLimit:     s.cfg.Limits.KeysPerSubdomain,
		NotOwner:     d.UserID != currentAuth(r).User.ID,
		Accesses:     []store.Access{store.AccessPublic, store.AccessUsers, store.AccessPrivate},
	})
}

func (s *Server) back(w http.ResponseWriter, r *http.Request, d *store.Subdomain, kind, format string, args ...any) {
	s.setFlash(w, kind, format, args...)
	http.Redirect(w, r, "/subdomains/"+d.Name, http.StatusSeeOther)
}

func (s *Server) handleSetAccess(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	access := store.Access(r.PostFormValue("access"))
	if !access.Valid() {
		s.back(w, r, d, "error", "Unknown access level.")
		return
	}
	if err := s.store.SetSubdomainAccess(r.Context(), d.ID, access); err != nil {
		s.internalError(w, r, "set access", err)
		return
	}
	if t := s.registry.Get(d.Name); t != nil {
		t.SetAccess(access)
	}
	s.log.Info("access changed", "subdomain", d.Name, "access", access, "by", currentAuth(r).User.Email)
	s.back(w, r, d, "ok", "Access set to %s.", access)
}

func (s *Server) handleAddKeys(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	keys, err := parseKeys(r.PostFormValue("keys"))
	if err == nil && len(keys) == 0 {
		err = errors.New("paste at least one public key")
	}
	if err != nil {
		s.back(w, r, d, "error", "%v", err)
		return
	}
	if name := strings.TrimSpace(r.PostFormValue("name")); name != "" && len(keys) == 1 {
		keys[0].name = name
	}
	added, msg := s.addKeys(r, d, keys)
	if msg != "" {
		s.back(w, r, d, "error", "Added %d key(s), but: %s", added, msg)
		return
	}
	s.back(w, r, d, "ok", "Added %d key(s).", added)
}

// addKeys stores keys on d and returns how many were added plus a message
// describing any that were skipped.
func (s *Server) addKeys(r *http.Request, d *store.Subdomain, keys []parsedKey) (int, string) {
	existing, err := s.store.KeysBySubdomain(r.Context(), d.ID)
	if err != nil {
		s.log.Error("list keys", "err", err)
		return 0, "an internal error occurred"
	}
	added, count := 0, len(existing)
	var problems []string
	for _, k := range keys {
		if count >= s.cfg.Limits.KeysPerSubdomain {
			problems = append(problems, fmt.Sprintf("a subdomain can have at most %d keys", s.cfg.Limits.KeysPerSubdomain))
			break
		}
		_, err := s.store.AddKey(r.Context(), d.ID, k.name, k.key)
		switch {
		case errors.Is(err, store.ErrConflict):
			problems = append(problems, fmt.Sprintf("%s is already registered", ssh.FingerprintSHA256(k.key)))
		case err != nil:
			s.log.Error("add key", "err", err)
			problems = append(problems, "an internal error occurred")
		default:
			added++
			count++
			s.log.Info("ssh key added", "subdomain", d.Name, "fingerprint", ssh.FingerprintSHA256(k.key), "by", currentAuth(r).User.Email)
		}
	}
	return added, strings.Join(problems, "; ")
}

type parsedKey struct {
	key  ssh.PublicKey
	name string
}

// parseKeys reads public keys in authorized_keys format, one per line, as
// found in ~/.ssh/id_*.pub or https://github.com/<user>.keys.
func parseKeys(text string) ([]parsedKey, error) {
	var out []parsedKey
	for i, line := range strings.Split(text, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, comment, _, _, err := ssh.ParseAuthorizedKey([]byte(line))
		if err != nil {
			return nil, fmt.Errorf("line %d is not an SSH public key (paste the contents of a .pub file)", i+1)
		}
		if err := checkKeyStrength(key); err != nil {
			return nil, fmt.Errorf("line %d: %v", i+1, err)
		}
		name := strings.TrimSpace(comment)
		if name == "" {
			name = key.Type()
		}
		if utf8.RuneCountInString(name) > 64 {
			name = string([]rune(name)[:64])
		}
		out = append(out, parsedKey{key: key, name: name})
		if len(out) > 100 {
			return nil, errors.New("too many keys at once")
		}
	}
	return out, nil
}

func checkKeyStrength(key ssh.PublicKey) error {
	switch key.Type() {
	case ssh.KeyAlgoED25519, ssh.KeyAlgoSKED25519, ssh.KeyAlgoECDSA256, ssh.KeyAlgoECDSA384,
		ssh.KeyAlgoECDSA521, ssh.KeyAlgoSKECDSA256:
		return nil
	case ssh.KeyAlgoRSA:
		ck, ok := key.(ssh.CryptoPublicKey)
		if !ok {
			return errors.New("unreadable RSA key")
		}
		if rk, ok := ck.CryptoPublicKey().(*rsa.PublicKey); !ok || rk.N.BitLen() < 2048 {
			return errors.New("RSA keys must have at least 2048 bits")
		}
		return nil
	}
	return fmt.Errorf("%s keys are not supported; use ed25519 (ssh-keygen -t ed25519)", key.Type())
}

func (s *Server) handleDeleteKey(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	k, err := s.store.DeleteKey(r.Context(), d.ID, id)
	if errors.Is(err, store.ErrNotFound) {
		s.back(w, r, d, "error", "That key no longer exists.")
		return
	}
	if err != nil {
		s.internalError(w, r, "delete key", err)
		return
	}
	s.registry.CloseKey(d.Name, k.ID, "its SSH key was removed")
	s.log.Info("ssh key removed", "subdomain", d.Name, "fingerprint", k.Fingerprint, "by", currentAuth(r).User.Email)
	s.back(w, r, d, "ok", "Removed key %q.", k.Name)
}

func (s *Server) handleDisconnect(w http.ResponseWriter, r *http.Request) {
	d := s.loadSubdomain(w, r)
	if d == nil {
		return
	}
	if t := s.registry.Get(d.Name); t != nil {
		t.Close("disconnected from the dashboard")
		s.log.Info("tunnel disconnected", "subdomain", d.Name, "by", currentAuth(r).User.Email)
	}
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
	if err := s.store.DeleteSubdomain(r.Context(), d.ID); err != nil {
		s.internalError(w, r, "delete subdomain", err)
		return
	}
	if t := s.registry.Get(d.Name); t != nil {
		t.Close("the subdomain was deleted")
	}
	s.log.Info("subdomain deleted", "subdomain", d.Name, "by", currentAuth(r).User.Email)
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

func (s *Server) handleSetUserDisabled(disabled bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		a := currentAuth(r)
		id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
		if id == a.User.ID {
			s.setFlash(w, "error", "You can't disable your own account.")
			http.Redirect(w, r, "/admin", http.StatusSeeOther)
			return
		}
		err := s.store.SetUserDisabled(r.Context(), id, disabled)
		if errors.Is(err, store.ErrNotFound) {
			s.renderError(w, r, http.StatusNotFound, "User not found.")
			return
		}
		if err != nil {
			s.internalError(w, r, "set user disabled", err)
			return
		}
		verb := "Enabled"
		if disabled {
			verb = "Disabled"
			for _, t := range s.registry.List() {
				if t.OwnerID == id {
					t.Close("the owner's account was disabled")
				}
			}
		}
		s.log.Info("user "+strings.ToLower(verb), "user_id", id, "by", a.User.Email)
		s.setFlash(w, "ok", "%s user #%d.", verb, id)
		http.Redirect(w, r, "/admin", http.StatusSeeOther)
	}
}

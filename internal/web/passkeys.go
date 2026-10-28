package web

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/gate2sky/gate2sky.github.io/internal/store"
)

const passkeyCeremonyTTL = 5 * time.Minute

// passkeyUser adapts a user and their passkeys to the webauthn library.
type passkeyUser struct {
	user  *store.User
	creds []webauthn.Credential
}

func (p *passkeyUser) WebAuthnID() []byte                         { return p.user.WebAuthnID }
func (p *passkeyUser) WebAuthnName() string                       { return p.user.Email }
func (p *passkeyUser) WebAuthnDisplayName() string                { return p.user.DisplayName() }
func (p *passkeyUser) WebAuthnCredentials() []webauthn.Credential { return p.creds }

func (s *Server) passkeyUser(ctx context.Context, u *store.User) (*passkeyUser, error) {
	keys, err := s.store.PasskeysByUser(ctx, u.ID)
	if err != nil {
		return nil, err
	}
	pu := &passkeyUser{user: u}
	for _, k := range keys {
		var c webauthn.Credential
		if err := json.Unmarshal(k.Credential, &c); err != nil {
			return nil, fmt.Errorf("decode passkey %d: %w", k.ID, err)
		}
		pu.creds = append(pu.creds, c)
	}
	return pu, nil
}

// passkeyCeremony is kept in a signed cookie between the options and the
// response of a WebAuthn ceremony.
type passkeyCeremony struct {
	Session  webauthn.SessionData `json:"s"`
	Redirect string               `json:"r,omitempty"`
}

func (s *Server) startCeremony(w http.ResponseWriter, purpose string, c passkeyCeremony) {
	s.setCookie(w, s.cookies.passkey, s.signer.sign(purpose, c, passkeyCeremonyTTL), time.Now().Add(passkeyCeremonyTTL))
}

// finishCeremony returns the ceremony started in this browser. Each
// challenge can only be answered once.
func (s *Server) finishCeremony(w http.ResponseWriter, r *http.Request, purpose string) (*passkeyCeremony, bool) {
	c, err := r.Cookie(s.cookies.passkey)
	if err != nil {
		return nil, false
	}
	s.clearCookie(w, s.cookies.passkey)
	var pc passkeyCeremony
	if s.signer.verify(purpose, c.Value, &pc) != nil || !s.nonces.use(purpose+":"+pc.Session.Challenge, time.Now().Add(passkeyCeremonyTTL)) {
		return nil, false
	}
	return &pc, true
}

func (s *Server) handlePasskeyLoginOptions(w http.ResponseWriter, r *http.Request) {
	assertion, session, err := s.webauthn.BeginDiscoverableLogin(webauthn.WithUserVerification(protocol.VerificationRequired))
	if err != nil {
		s.log.Error("begin passkey login", "err", err)
		jsonError(w, http.StatusInternalServerError, "Passkey sign-in is not available right now.")
		return
	}
	s.startCeremony(w, "passkey-login", passkeyCeremony{Session: *session, Redirect: localPath(r.URL.Query().Get("rd"))})
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Server) handlePasskeyLogin(w http.ResponseWriter, r *http.Request) {
	pc, ok := s.finishCeremony(w, r, "passkey-login")
	if !ok {
		jsonError(w, http.StatusBadRequest, "This sign-in attempt expired. Please try again.")
		return
	}
	findUser := func(_, userHandle []byte) (webauthn.User, error) {
		u, err := s.store.UserByWebAuthnID(r.Context(), userHandle)
		if err != nil {
			return nil, err
		}
		return s.passkeyUser(r.Context(), u)
	}
	wu, cred, err := s.webauthn.FinishPasskeyLogin(findUser, pc.Session, r)
	if err != nil {
		s.log.Info("passkey sign-in failed", "ip", s.clientIP(r), "err", err)
		jsonError(w, http.StatusUnauthorized, "This passkey is not registered here. Sign in with your email and add it from your account page.")
		return
	}
	if cred.Authenticator.CloneWarning {
		s.log.Warn("passkey sign-in refused: signature counter went backwards (cloned authenticator?)", "credential", cred.ID)
		jsonError(w, http.StatusUnauthorized, "This passkey looks cloned and was refused.")
		return
	}
	user := wu.(*passkeyUser).user
	if data, err := json.Marshal(cred); err == nil {
		if err := s.store.UpdatePasskeyUse(r.Context(), cred.ID, data); err != nil {
			s.log.Error("update passkey", "err", err)
		}
	}
	if msg, ok := s.startSession(w, r, user, "passkey"); !ok {
		jsonError(w, http.StatusForbidden, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": pc.Redirect})
}

func (s *Server) handlePasskeyRegisterOptions(w http.ResponseWriter, r *http.Request) {
	pu, err := s.passkeyUser(r.Context(), currentAuth(r).User)
	if err != nil {
		s.log.Error("load passkeys", "err", err)
		jsonError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	exclude := make([]protocol.CredentialDescriptor, len(pu.creds))
	for i, c := range pu.creds {
		exclude[i] = c.Descriptor()
	}
	creation, session, err := s.webauthn.BeginRegistration(pu,
		webauthn.WithAuthenticatorSelection(protocol.AuthenticatorSelection{
			ResidentKey:        protocol.ResidentKeyRequirementRequired,
			RequireResidentKey: protocol.ResidentKeyRequired(),
			UserVerification:   protocol.VerificationRequired,
		}),
		webauthn.WithExclusions(exclude),
	)
	if err != nil {
		s.log.Error("begin passkey registration", "err", err)
		jsonError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	s.startCeremony(w, "passkey-register", passkeyCeremony{Session: *session})
	writeJSON(w, http.StatusOK, creation)
}

func (s *Server) handlePasskeyRegister(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	pc, ok := s.finishCeremony(w, r, "passkey-register")
	if !ok {
		jsonError(w, http.StatusBadRequest, "This attempt expired. Please try again.")
		return
	}
	pu, err := s.passkeyUser(r.Context(), a.User)
	if err != nil {
		s.log.Error("load passkeys", "err", err)
		jsonError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	cred, err := s.webauthn.FinishRegistration(pu, pc.Session, r)
	if err != nil {
		s.log.Info("passkey registration failed", "user_id", a.User.ID, "err", err)
		jsonError(w, http.StatusBadRequest, "The passkey could not be verified. Please try again.")
		return
	}
	name := strings.TrimSpace(r.URL.Query().Get("name"))
	if name == "" {
		name = "Passkey added " + time.Now().UTC().Format("2006-01-02")
	}
	if len([]rune(name)) > 64 {
		name = string([]rune(name)[:64])
	}
	data, err := json.Marshal(cred)
	if err != nil {
		jsonError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	pk, err := s.store.AddPasskey(r.Context(), a.User.ID, name, cred.ID, data)
	if errors.Is(err, store.ErrConflict) {
		jsonError(w, http.StatusConflict, "This passkey is already registered.")
		return
	}
	if err != nil {
		s.log.Error("save passkey", "err", err)
		jsonError(w, http.StatusInternalServerError, msgInternal)
		return
	}
	s.log.Info("passkey added", "user_id", a.User.ID, "name", name)
	writeJSON(w, http.StatusOK, passkeyView(pk))
}

func (s *Server) handleDeletePasskey(w http.ResponseWriter, r *http.Request) {
	a := currentAuth(r)
	id, _ := strconv.ParseInt(r.PathValue("id"), 10, 64)
	err := s.store.DeletePasskey(r.Context(), a.User.ID, id)
	switch {
	case errors.Is(err, store.ErrNotFound):
		jsonError(w, http.StatusNotFound, "That passkey no longer exists.")
	case err != nil:
		s.internalError(w, "delete passkey", err)
	default:
		s.log.Info("passkey removed", "user_id", a.User.ID, "passkey_id", id)
		w.WriteHeader(http.StatusNoContent)
	}
}

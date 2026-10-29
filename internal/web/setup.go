package web

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/mail"
	"strings"
	"time"

	g2smail "github.com/jgermade/intergate/internal/mail"
	"github.com/jgermade/intergate/internal/settings"
	"github.com/jgermade/intergate/internal/store"
)

// The dashboard's setup: while intergate has no way to send sign-in codes,
// or nobody may sign in, the dashboard asks for email delivery (SMTP) and
// then for the owner's address, which it confirms with a code. Only a
// browser that opened the one-time link from `intergate setup-url` (or the
// server's log) can do it.

const msgSetupLink = "Run intergate setup-url on the server for a new link."

// bootSetup is the setup's state, for the page.
type bootSetup struct {
	// Email and Owner are the steps left.
	Email bool `json:"email"`
	Owner bool `json:"owner"`
	// Session is set when this browser has the setup open; only then does
	// the page get what was entered so far.
	Session bool      `json:"session"`
	SMTP    *bootSMTP `json:"smtp,omitempty"`
	// OwnerFlow is the address a code was sent to, in this browser.
	OwnerFlow string `json:"owner_flow,omitempty"`
}

// bootSMTP is email delivery as set up from the dashboard, without its
// password.
type bootSMTP struct {
	Host     string `json:"host"`
	Port     int    `json:"port"`
	TLS      string `json:"tls"`
	Username string `json:"username"`
	From     string `json:"from"`
	Password bool   `json:"password"`
}

// setupState returns the setup's state for r, or nil when it is done.
func (s *Server) setupState(r *http.Request) (*bootSetup, error) {
	email, owner, err := s.settings.Pending(r.Context())
	if err != nil || !email && !owner {
		return nil, err
	}
	st := &bootSetup{Email: email, Owner: owner, Session: s.inSetup(r)}
	if !st.Session {
		return st, nil
	}
	if e := s.settings.Email(); e != nil {
		st.SMTP = &bootSMTP{Host: e.Host, Port: e.Port, TLS: e.TLS, Username: e.Username, From: e.From, Password: e.HasPassword()}
	}
	if f, ok := s.ownerFlow(r); ok {
		st.OwnerFlow = f.Email
	}
	return st, nil
}

// inSetup reports whether r comes from the browser that has the setup open.
func (s *Server) inSetup(r *http.Request) bool {
	c, err := r.Cookie(s.cookies.setup)
	return err == nil && s.settings.SetupSession(c.Value)
}

// setupCall guards the setup's API: same origin, while the setup is not
// done, and (but for start) from the browser that has it open.
func (s *Server) setupCall(start bool, next http.HandlerFunc) http.Handler {
	return s.sameOrigin(func(w http.ResponseWriter, r *http.Request) {
		pending, err := s.settings.SetupPending(r.Context())
		if err != nil {
			s.internalError(w, "setup state", err)
			return
		}
		if !pending {
			jsonError(w, http.StatusConflict, "intergate is already set up.")
			return
		}
		if !start && !s.inSetup(r) {
			writeJSON(w, http.StatusForbidden, apiError{Error: "Your setup session has ended. " + msgSetupLink, Expired: true})
			return
		}
		next(w, r)
	})
}

func (s *Server) writeSetupState(w http.ResponseWriter, r *http.Request) {
	st, err := s.setupState(r)
	if err != nil {
		s.internalError(w, "setup state", err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"setup": st})
}

// handleSetupStart trades the link's one-time token for a setup session
// in this browser.
func (s *Server) handleSetupStart(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Token string `json:"token"`
	}
	if !decode(w, r, &req) {
		return
	}
	session, ok := s.settings.RedeemSetupToken(strings.TrimSpace(req.Token))
	if !ok {
		s.log.Warn("setup link refused: used, replaced or wrong", "ip", s.clientIP(r))
		writeJSON(w, http.StatusForbidden, apiError{Error: "This setup link has already been used or was replaced. " + msgSetupLink, Expired: true})
		return
	}
	s.log.Info("setup opened", "ip", s.clientIP(r))
	s.setCookie(w, s.cookies.setup, session, time.Time{})
	// The state is this browser's now that it has the setup open.
	r.AddCookie(&http.Cookie{Name: s.cookies.setup, Value: session})
	s.writeSetupState(w, r)
}

// handleSetupEmail checks and saves email delivery.
func (s *Server) handleSetupEmail(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Host     string `json:"host"`
		Port     int    `json:"port"`
		TLS      string `json:"tls"`
		Username string `json:"username"`
		Password string `json:"password"`
		From     string `json:"from"`
	}
	if !decode(w, r, &req) {
		return
	}
	if s.settings.EmailSource() == settings.SourceConfig {
		jsonError(w, http.StatusConflict, "Email delivery is set in the configuration file (auth.email).")
		return
	}
	e := settings.Email{
		Host:     strings.ToLower(strings.TrimSpace(req.Host)),
		Port:     req.Port,
		TLS:      req.TLS,
		Username: strings.TrimSpace(req.Username),
		From:     strings.TrimSpace(req.From),
	}
	ctx, cancel := context.WithTimeout(r.Context(), 45*time.Second)
	defer cancel()
	var smtpErr *settings.SMTPError
	var inputErr *settings.InputError
	switch err := s.settings.SaveEmail(ctx, e, req.Password); {
	case errors.As(err, &inputErr):
		jsonError(w, http.StatusBadRequest, err.Error())
		return
	case errors.As(err, &smtpErr):
		s.log.Info("setup: SMTP server refused", "host", e.Host, "err", err)
		jsonError(w, http.StatusBadRequest, "The SMTP server could not be used: "+strings.TrimPrefix(err.Error(), "smtp: ")+".")
		return
	case err != nil:
		s.internalError(w, "save email settings", err)
		return
	}
	s.log.Info("setup: email delivery saved", "host", e.Host, "port", e.Port, "tls", e.TLS)
	s.writeSetupState(w, r)
}

func (s *Server) ownerFlow(r *http.Request) (*emailFlow, bool) {
	c, err := r.Cookie(s.cookies.setupOwner)
	if err != nil {
		return nil, false
	}
	var f emailFlow
	if s.signer.verify("setup-owner", c.Value, &f) != nil {
		return nil, false
	}
	return &f, true
}

// handleSetupOwner emails the owner a code that confirms their address.
// Unlike a sign-in code, it is sent at once, so a failure shows.
func (s *Server) handleSetupOwner(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email string `json:"email"`
	}
	if !decode(w, r, &req) {
		return
	}
	if _, owner, _ := s.settings.Pending(r.Context()); !owner {
		jsonError(w, http.StatusConflict, "intergate already has an owner.")
		return
	}
	if !s.settings.EmailEnabled() {
		jsonError(w, http.StatusConflict, "Set up email delivery first.")
		return
	}
	addr, err := mail.ParseAddress(strings.TrimSpace(req.Email))
	if err != nil || addr.Name != "" {
		jsonError(w, http.StatusBadRequest, "Enter a valid email address.")
		return
	}
	email := store.NormalizeEmail(addr.Address)
	if !s.codes.byIP.allow(s.clientIP(r)) || !s.codes.byEmail.allow(email) {
		jsonError(w, http.StatusTooManyRequests, "Too many codes requested. Wait a few minutes and try again.")
		return
	}
	ttl := s.cfg.Auth.Email.CodeTTL
	flow := emailFlow{ID: randomString(16), Email: email}
	code := sixDigits()
	msg := g2smail.Message{
		To:      email,
		Subject: "Your intergate setup code: " + code,
		Body: fmt.Sprintf("Your code to finish setting up intergate at %s is:\n\n    %s\n\n"+
			"It expires in %d minutes and works once. With it, %s becomes intergate's owner.\n\n"+
			"If you are not setting up intergate, you can ignore this email.\n",
			s.cfg.DashboardURL("/"), code, int(ttl.Minutes()), email),
	}
	ctx, cancel := context.WithTimeout(r.Context(), emailSendDeadline)
	defer cancel()
	if err := s.mailer.Send(ctx, msg); err != nil {
		s.log.Error("setup: send the owner's code", "to", email, "err", err)
		jsonError(w, http.StatusBadGateway, "The code could not be sent: "+strings.TrimPrefix(err.Error(), "smtp: ")+". Check the email settings.")
		return
	}
	s.codes.add(flow.ID, code, ttl)
	s.setCookie(w, s.cookies.setupOwner, s.signer.sign("setup-owner", flow, ttl), time.Now().Add(ttl))
	writeJSON(w, http.StatusOK, map[string]string{"email": email})
}

// handleSetupOwnerCancel forgets the code this browser is waiting for, to
// use another address.
func (s *Server) handleSetupOwnerCancel(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, s.cookies.setupOwner)
	w.WriteHeader(http.StatusNoContent)
}

// handleSetupOwnerCode makes whoever enters the code the owner, signs them
// in and ends the setup.
func (s *Server) handleSetupOwnerCode(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	f, ok := s.ownerFlow(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "The code has expired. Ask for a new one.", Expired: true})
		return
	}
	switch s.codes.check(f.ID, strings.Join(strings.Fields(req.Code), "")) {
	case codeWrong:
		jsonError(w, http.StatusUnauthorized, "That code is not right. Check the email and try again.")
		return
	case codeExpired:
		s.clearCookie(w, s.cookies.setupOwner)
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "That code has expired or was tried too many times. Ask for a new one.", Expired: true})
		return
	}
	ctx := r.Context()
	user, err := s.store.EnsureUser(ctx, f.Email)
	if err == nil {
		err = s.store.SetUserRole(ctx, user.ID, store.RoleOwner)
	}
	if err == nil {
		user, err = s.store.UserByID(ctx, user.ID)
	}
	if err != nil {
		s.internalError(w, "setup: make the owner", err)
		return
	}
	s.clearCookie(w, s.cookies.setupOwner)
	s.clearCookie(w, s.cookies.setup)
	s.settings.EndSetup()
	s.log.Info("setup done", "owner", user.Email, "ip", s.clientIP(r))
	if msg, ok := s.startSession(w, r, user, "setup"); !ok {
		jsonError(w, http.StatusForbidden, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": s.afterLogin(r, user, "/")})
}

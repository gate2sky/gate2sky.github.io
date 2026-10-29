package web

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"fmt"
	"math/big"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	g2smail "github.com/jgermade/intergate/internal/mail"
	"github.com/jgermade/intergate/internal/store"
)

const (
	maxCodeAttempts   = 5
	codesPerEmail     = 5 // per codeEmailWindow
	codeEmailWindow   = 15 * time.Minute
	codesPerIP        = 20 // per codeIPWindow
	codeIPWindow      = time.Hour
	emailSendDeadline = time.Minute
)

// emailFlow is kept in a signed cookie between asking for a code and
// entering it, so a code only works in the browser that asked for it.
type emailFlow struct {
	ID       string `json:"i"`
	Email    string `json:"e"`
	Redirect string `json:"r"`
}

type pendingCode struct {
	hash     [32]byte
	expires  time.Time
	attempts int
}

// codeStore keeps pending sign-in codes in memory and rate-limits how many
// are sent. Codes do not survive a restart; users just ask for a new one.
type codeStore struct {
	mu      sync.Mutex
	pending map[string]*pendingCode
	byEmail *limiter
	byIP    *limiter
}

func newCodeStore() *codeStore {
	return &codeStore{
		pending: map[string]*pendingCode{},
		byEmail: newLimiter(codesPerEmail, codeEmailWindow),
		byIP:    newLimiter(codesPerIP, codeIPWindow),
	}
}

func hashCode(flowID, code string) [32]byte {
	return sha256.Sum256([]byte(flowID + ":" + code))
}

func (c *codeStore) add(flowID, code string, ttl time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := time.Now()
	for id, p := range c.pending {
		if now.After(p.expires) {
			delete(c.pending, id)
		}
	}
	c.pending[flowID] = &pendingCode{hash: hashCode(flowID, code), expires: now.Add(ttl)}
}

type codeResult int

const (
	codeOK codeResult = iota
	codeWrong
	codeExpired
)

// check verifies a code. A code is single use, and too many wrong guesses
// burn it.
func (c *codeStore) check(flowID, code string) codeResult {
	c.mu.Lock()
	defer c.mu.Unlock()
	p := c.pending[flowID]
	if p == nil || time.Now().After(p.expires) {
		delete(c.pending, flowID)
		return codeExpired
	}
	want := hashCode(flowID, code)
	if subtle.ConstantTimeCompare(p.hash[:], want[:]) == 1 {
		delete(c.pending, flowID)
		return codeOK
	}
	p.attempts++
	if p.attempts >= maxCodeAttempts {
		delete(c.pending, flowID)
		return codeExpired
	}
	return codeWrong
}

// limiter allows max events per key within a sliding window.
type limiter struct {
	mu     sync.Mutex
	max    int
	window time.Duration
	hits   map[string][]time.Time
}

func newLimiter(max int, window time.Duration) *limiter {
	return &limiter{max: max, window: window, hits: map[string][]time.Time{}}
}

func (l *limiter) allow(key string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.hits) > 10000 {
		for k, hs := range l.hits {
			if len(hs) == 0 || now.Sub(hs[len(hs)-1]) > l.window {
				delete(l.hits, k)
			}
		}
	}
	hs := l.hits[key]
	for len(hs) > 0 && now.Sub(hs[0]) > l.window {
		hs = hs[1:]
	}
	if len(hs) >= l.max {
		l.hits[key] = hs
		return false
	}
	l.hits[key] = append(hs, now)
	return true
}

func sixDigits() string {
	n, err := rand.Int(rand.Reader, big.NewInt(1_000_000))
	if err != nil {
		panic(err)
	}
	return fmt.Sprintf("%06d", n.Int64())
}

// withEmail answers email sign-in calls with a 404 while no email
// delivery is set up.
func (s *Server) withEmail(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if !s.settings.EmailEnabled() {
			jsonError(w, http.StatusNotFound, "Not found.")
			return
		}
		next(w, r)
	}
}

// handleEmailLogin sends a sign-in code. The response is the same whether
// or not the address may sign in, so it reveals nothing about accounts,
// and addresses that may not sign in get no email at all.
func (s *Server) handleEmailLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Email    string `json:"email"`
		Redirect string `json:"rd"`
	}
	if !decode(w, r, &req) {
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

	flow := emailFlow{ID: randomString(16), Email: email, Redirect: localPath(req.Redirect)}
	ttl := s.cfg.Auth.Email.CodeTTL
	if s.mayUseEmail(r.Context(), email) {
		code := sixDigits()
		s.codes.add(flow.ID, code, ttl)
		msg := g2smail.Message{
			To:      email,
			Subject: "Your intergate sign-in code: " + code,
			Body: fmt.Sprintf("Your sign-in code for %s is:\n\n    %s\n\nIt expires in %d minutes and works once.\n\n"+
				"If you did not try to sign in, you can ignore this email: nobody can sign in without the code.\n",
				s.cfg.DashboardURL("/"), code, int(ttl.Minutes())),
		}
		// Send in the background so the response time doesn't tell
		// whether an email was sent.
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), emailSendDeadline)
			defer cancel()
			if err := s.mailer.Send(ctx, msg); err != nil {
				s.log.Error("send sign-in code", "to", email, "err", err)
			}
		}()
	} else {
		s.log.Info("sign-in code not sent: address may not sign in", "email", email, "ip", s.clientIP(r))
	}
	s.setCookie(w, s.cookies.emailLogin, s.signer.sign("email-login", flow, ttl), time.Now().Add(ttl))
	writeJSON(w, http.StatusOK, map[string]string{"email": email})
}

// handleEmailCancel forgets the code this browser is waiting for, to ask
// for one at another address.
func (s *Server) handleEmailCancel(w http.ResponseWriter, r *http.Request) {
	s.clearCookie(w, s.cookies.emailLogin)
	w.WriteHeader(http.StatusNoContent)
}

// mayUseEmail reports whether a code should be sent to email.
func (s *Server) mayUseEmail(ctx context.Context, email string) bool {
	u, err := s.store.UserByEmail(ctx, email)
	return s.emailAllowed(ctx, email) && (err != nil || !u.Disabled)
}

// emailAllowed reports whether whoever proves they own email may sign in:
// the configuration allows it, or its account was added by an
// administrator or made one.
func (s *Server) emailAllowed(ctx context.Context, email string) bool {
	if u, err := s.store.UserByEmail(ctx, email); err == nil {
		return s.cfg.UserAllowed(u.Email, u.Added, string(u.Role))
	}
	return s.cfg.EmailAllowed(email)
}

func (s *Server) emailFlow(r *http.Request) (*emailFlow, bool) {
	c, err := r.Cookie(s.cookies.emailLogin)
	if err != nil {
		return nil, false
	}
	var f emailFlow
	if s.signer.verify("email-login", c.Value, &f) != nil {
		return nil, false
	}
	return &f, true
}

func (s *Server) handleCodeLogin(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Code string `json:"code"`
	}
	if !decode(w, r, &req) {
		return
	}
	f, ok := s.emailFlow(r)
	if !ok {
		writeJSON(w, http.StatusBadRequest, apiError{Error: "Your sign-in attempt expired. Ask for a new code.", Expired: true})
		return
	}
	code := strings.Join(strings.Fields(req.Code), "")
	switch s.codes.check(f.ID, code) {
	case codeWrong:
		jsonError(w, http.StatusUnauthorized, "That code is not right. Check the email and try again.")
		return
	case codeExpired:
		s.clearCookie(w, s.cookies.emailLogin)
		writeJSON(w, http.StatusUnauthorized, apiError{Error: "That code has expired or was tried too many times. Ask for a new one.", Expired: true})
		return
	}
	s.clearCookie(w, s.cookies.emailLogin)
	user, err := s.store.EnsureUser(r.Context(), f.Email)
	if err != nil {
		s.internalError(w, "load user", err)
		return
	}
	if msg, ok := s.startSession(w, r, user, "email"); !ok {
		jsonError(w, http.StatusForbidden, msg)
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"redirect": s.afterLogin(r, user, f.Redirect)})
}

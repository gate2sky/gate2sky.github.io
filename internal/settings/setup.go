package settings

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"sync"
	"time"
)

// SetupIdle is how long a setup session lasts without being used.
const SetupIdle = time.Hour

// setup is the dashboard's setup in progress: the link's one-time token,
// then the session it was traded for. Both live in memory only: after a
// restart, `intergate setup-url` gives a new link.
type setup struct {
	mu           sync.Mutex
	token        [32]byte // hash of the link's token; zero when none
	session      [32]byte // hash of the session; zero when none
	sessionUntil time.Time
}

// Pending tells which steps of the setup are left: email delivery, to send
// sign-in codes, and an owner, when nobody may sign in. Email is only
// asked for when there is no OAuth provider to sign in with, or for the
// owner to confirm their address.
func (s *Settings) Pending(ctx context.Context) (email, owner bool, err error) {
	if s.cfg.NobodyAllowed() {
		managers, err := s.store.HasManagers(ctx)
		if err != nil {
			return false, false, err
		}
		owner = !managers
	}
	email = !s.EmailEnabled() && (len(s.cfg.Auth.Providers) == 0 || owner)
	return email, owner, nil
}

// SetupPending reports whether the setup has steps left.
func (s *Settings) SetupPending(ctx context.Context) (bool, error) {
	email, owner, err := s.Pending(ctx)
	return email || owner, err
}

// SetupURL returns a new link that opens the setup. It replaces the
// previous link and ends a setup in progress, so whoever used the old one
// is out.
func (s *Settings) SetupURL() string {
	return s.cfg.DashboardURL("/?setup=" + s.newSetupToken())
}

func (s *Settings) newSetupToken() string {
	token := randomToken()
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	s.setup.token = sha256.Sum256([]byte(token))
	s.setup.session = [32]byte{}
	return token
}

// RedeemSetupToken trades the link's token, once, for a setup session.
func (s *Settings) RedeemSetupToken(token string) (session string, ok bool) {
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	h := sha256.Sum256([]byte(token))
	if s.setup.token == ([32]byte{}) || subtle.ConstantTimeCompare(h[:], s.setup.token[:]) != 1 {
		return "", false
	}
	s.setup.token = [32]byte{}
	session = randomToken()
	s.setup.session = sha256.Sum256([]byte(session))
	s.setup.sessionUntil = time.Now().Add(SetupIdle)
	return session, true
}

// SetupSession reports whether session is the setup in progress, and
// keeps it alive.
func (s *Settings) SetupSession(session string) bool {
	if session == "" {
		return false
	}
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	h := sha256.Sum256([]byte(session))
	if s.setup.session == ([32]byte{}) || subtle.ConstantTimeCompare(h[:], s.setup.session[:]) != 1 {
		return false
	}
	if time.Now().After(s.setup.sessionUntil) {
		s.setup.session = [32]byte{}
		return false
	}
	s.setup.sessionUntil = time.Now().Add(SetupIdle)
	return true
}

// EndSetup forgets the link and the session, once the setup is done.
func (s *Settings) EndSetup() {
	s.setup.mu.Lock()
	defer s.setup.mu.Unlock()
	s.setup.token, s.setup.session = [32]byte{}, [32]byte{}
}

func randomToken() string {
	b := make([]byte, 24)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

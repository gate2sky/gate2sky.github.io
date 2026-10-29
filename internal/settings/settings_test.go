package settings

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/store"
)

func open(t *testing.T, yaml string, st *store.Store, secret string) (*Settings, *[]config.SMTPConfig) {
	t.Helper()
	cfg, err := config.Parse([]byte("public_url: https://gate.example.com\n" + yaml))
	if err != nil {
		t.Fatal(err)
	}
	s, err := Open(context.Background(), cfg, st, []byte(secret))
	if err != nil {
		t.Fatal(err)
	}
	var checked []config.SMTPConfig
	s.CheckSMTP = func(_ context.Context, c config.SMTPConfig) error {
		checked = append(checked, c)
		if c.Password == "wrong" {
			return errors.New("smtp: authenticate: 535 authentication failed")
		}
		return nil
	}
	return s, &checked
}

func openStore(t *testing.T) *store.Store {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

const secret = "0123456789abcdef0123456789abcdef"

var gmail = Email{From: "intergate <no-reply@example.com>", Host: "smtp.example.com", Port: 587, TLS: "starttls", Username: "me"}

func TestSaveEmail(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	s, checked := open(t, "", st, secret)
	if s.EmailSource() != SourceNone || s.EmailEnabled() {
		t.Fatal("email enabled before the setup")
	}
	if _, err := s.EmailConfig(); !errors.Is(err, ErrNoEmail) {
		t.Fatalf("EmailConfig = %v", err)
	}

	bad := gmail
	bad.From = "not an address"
	if err := s.SaveEmail(ctx, bad, "pw"); err == nil || len(*checked) > 0 {
		t.Errorf("invalid sender: %v, checked %d", err, len(*checked))
	}
	var smtpErr *SMTPError
	if err := s.SaveEmail(ctx, gmail, "wrong"); !errors.As(err, &smtpErr) || s.Email() != nil {
		t.Fatalf("refused password saved: %v", err)
	}
	if err := s.SaveEmail(ctx, gmail, "s3cret"); err != nil {
		t.Fatal(err)
	}
	e := s.Email()
	if s.EmailSource() != SourceDashboard || e.PasswordSource() != "stored" || strings.Contains(e.Sealed, "s3cret") {
		t.Fatalf("saved %+v", e)
	}
	raw, _ := st.Setting(ctx, emailKey)
	if strings.Contains(raw, "s3cret") {
		t.Fatalf("the password is in the database in the clear: %s", raw)
	}
	cfg, err := s.EmailConfig()
	if err != nil || cfg.SMTP.Password != "s3cret" || cfg.SMTP.Host != "smtp.example.com" || cfg.From != gmail.From || cfg.CodeTTL != 10*time.Minute {
		t.Fatalf("EmailConfig = %+v, %v", cfg, err)
	}

	// Saving again with no password keeps it, for the same server and user.
	again := gmail
	again.Port = 465
	again.TLS = "tls"
	if err := s.SaveEmail(ctx, again, ""); err != nil {
		t.Fatal(err)
	}
	if last := (*checked)[len(*checked)-1]; last.Password != "s3cret" || last.Port != 465 {
		t.Errorf("checked %+v", last)
	}
	other := gmail
	other.Username = "someone-else"
	if err := s.SaveEmail(ctx, other, ""); err != nil || s.Email().HasPassword() {
		t.Errorf("another user kept the password: %v %+v", err, s.Email())
	}
	if err := s.SaveEmail(ctx, gmail, "s3cret"); err != nil {
		t.Fatal(err)
	}

	// The settings survive a restart; another secret key can't read the
	// password.
	s2, _ := open(t, "", st, secret)
	if cfg, err := s2.EmailConfig(); err != nil || cfg.SMTP.Password != "s3cret" {
		t.Errorf("after reopening: %+v, %v", cfg, err)
	}
	s3, _ := open(t, "", st, strings.Repeat("x", 32))
	if _, err := s3.EmailConfig(); err == nil || !strings.Contains(err.Error(), "enter it again") {
		t.Errorf("another key: %v", err)
	}

	// The configuration file wins.
	s4, _ := open(t, "auth:\n  email:\n    log_only: true\n", st, secret)
	if cfg, err := s4.EmailConfig(); s4.EmailSource() != SourceConfig || err != nil || !cfg.LogOnly {
		t.Errorf("configuration file: %s %+v %v", s4.EmailSource(), cfg, err)
	}
	if err := s4.SetPassword(ctx, "env:X", ""); err == nil || !strings.Contains(err.Error(), "configuration file") {
		t.Errorf("SetPassword over the configuration file: %v", err)
	}
}

func TestSetPassword(t *testing.T) {
	ctx := context.Background()
	s, _ := open(t, "", openStore(t), secret)
	if err := s.SetPassword(ctx, "env:SMTP_PASSWORD", ""); !errors.Is(err, ErrNoEmail) {
		t.Fatalf("no email yet: %v", err)
	}
	if err := s.SaveEmail(ctx, gmail, "s3cret"); err != nil {
		t.Fatal(err)
	}

	t.Setenv("INTERGATE_TEST_SMTP", "")
	if err := s.SetPassword(ctx, "env:INTERGATE_TEST_SMTP", ""); err == nil || s.Email().PasswordSource() != "stored" {
		t.Errorf("unset variable: %v", err)
	}
	t.Setenv("INTERGATE_TEST_SMTP", "wrong")
	if err := s.SetPassword(ctx, "env:INTERGATE_TEST_SMTP", ""); err == nil || s.Email().PasswordSource() != "stored" {
		t.Errorf("refused password: %v", err)
	}
	t.Setenv("INTERGATE_TEST_SMTP", "from-env")
	if err := s.SetPassword(ctx, "env:INTERGATE_TEST_SMTP", ""); err != nil {
		t.Fatal(err)
	}
	if e := s.Email(); e.PasswordSource() != "env:INTERGATE_TEST_SMTP" || e.Sealed != "" {
		t.Errorf("after env: %+v", e)
	}
	t.Setenv("INTERGATE_TEST_SMTP", "rotated")
	if cfg, _ := s.EmailConfig(); cfg.SMTP.Password != "rotated" {
		t.Errorf("password read once only: %q", cfg.SMTP.Password)
	}

	file := filepath.Join(t.TempDir(), "smtp_password")
	os.WriteFile(file, []byte("from-file\n"), 0o600)
	if err := s.SetPassword(ctx, "file:"+file, ""); err != nil {
		t.Fatal(err)
	}
	if cfg, _ := s.EmailConfig(); cfg.SMTP.Password != "from-file" {
		t.Errorf("file password = %q", cfg.SMTP.Password)
	}
	if err := s.SetPassword(ctx, "", ""); err == nil {
		t.Error("stored an empty password")
	}
	if err := s.SetPassword(ctx, "", "typed"); err != nil {
		t.Fatal(err)
	}
	if e := s.Email(); e.PasswordSource() != "stored" || e.PasswordRef != "" {
		t.Errorf("back to stored: %+v", e)
	}
}

func TestResolvePassword(t *testing.T) {
	t.Setenv("INTERGATE_TEST_PW", "pw")
	file := filepath.Join(t.TempDir(), "pw")
	os.WriteFile(file, []byte("pw\r\n"), 0o600)
	empty := filepath.Join(t.TempDir(), "empty")
	os.WriteFile(empty, []byte("\n"), 0o600)
	for ref, want := range map[string]string{
		"env:INTERGATE_TEST_PW":     "pw",
		"file:" + file:              "pw",
		"env:INTERGATE_TEST_UNSET":  "",
		"env:":                      "",
		"file:relative/path":        "",
		"file:" + empty:             "",
		"file:" + file + ".missing": "",
		"vault:secret/smtp":         "",
		"pw":                        "",
	} {
		got, err := ResolvePassword(ref)
		if got != want || (want == "") != (err != nil) {
			t.Errorf("ResolvePassword(%q) = %q, %v", ref, got, err)
		}
	}
}

func TestPending(t *testing.T) {
	ctx := context.Background()
	st := openStore(t)
	for _, c := range []struct {
		name, yaml   string
		email, owner bool
	}{
		{"nothing", "", true, true},
		{"admins and smtp", "auth:\n  admins: [a@example.com]\n  email:\n    log_only: true\n", false, false},
		{"email, nobody", "auth:\n  email:\n    log_only: true\n", false, true},
		{"admins, no email", "auth:\n  admins: [a@example.com]\n", true, false},
		{"github, allowed domain", "auth:\n  allowed_domains: [example.com]\n  providers:\n    - {id: github, type: github, client_id: a, client_secret: b}\n", false, false},
		{"github, nobody", "auth:\n  providers:\n    - {id: github, type: github, client_id: a, client_secret: b}\n", true, true},
	} {
		s, _ := open(t, c.yaml, st, secret)
		email, owner, err := s.Pending(ctx)
		if err != nil || email != c.email || owner != c.owner {
			t.Errorf("%s: email %v owner %v (%v), want %v %v", c.name, email, owner, err, c.email, c.owner)
		}
	}

	s, _ := open(t, "", st, secret)
	s.SaveEmail(ctx, gmail, "pw")
	if email, owner, _ := s.Pending(ctx); email || !owner {
		t.Errorf("after the email step: %v %v", email, owner)
	}
	u, _ := st.CreateUser(ctx, "owner@example.com", "")
	st.SetUserRole(ctx, u.ID, store.RoleOwner)
	if pending, _ := s.SetupPending(ctx); pending {
		t.Error("still pending with an owner")
	}
}

func TestSetupLink(t *testing.T) {
	s, _ := open(t, "", openStore(t), secret)
	if _, ok := s.RedeemSetupToken(""); ok {
		t.Fatal("redeemed an empty token with no link")
	}
	link := s.SetupURL()
	token := strings.TrimPrefix(link, "https://gate.example.com/?setup=")
	if token == link || len(token) < 32 {
		t.Fatalf("link %s", link)
	}
	if _, ok := s.RedeemSetupToken(token + "x"); ok {
		t.Error("redeemed a wrong token")
	}
	session, ok := s.RedeemSetupToken(token)
	if !ok || !s.SetupSession(session) || s.SetupSession(session+"x") || s.SetupSession("") {
		t.Fatal("redeem the link")
	}
	if _, ok := s.RedeemSetupToken(token); ok {
		t.Error("the link worked twice")
	}

	// A new link ends the session and replaces the old link.
	old := strings.TrimPrefix(s.SetupURL(), "https://gate.example.com/?setup=")
	newer := strings.TrimPrefix(s.SetupURL(), "https://gate.example.com/?setup=")
	if s.SetupSession(session) {
		t.Error("the session outlived a new link")
	}
	if _, ok := s.RedeemSetupToken(old); ok {
		t.Error("a replaced link worked")
	}
	session, ok = s.RedeemSetupToken(newer)
	if !ok {
		t.Fatal("redeem the newest link")
	}

	// Sessions end after an hour without use, and with the setup.
	s.setup.sessionUntil = time.Now().Add(-time.Second)
	if s.SetupSession(session) {
		t.Error("an idle session lived on")
	}
	session, _ = s.RedeemSetupToken(strings.TrimPrefix(s.SetupURL(), "https://gate.example.com/?setup="))
	s.EndSetup()
	if s.SetupSession(session) {
		t.Error("the session outlived the setup")
	}
}

package e2e

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
	"testing"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/mail"
	"github.com/jgermade/intergate/internal/store"
)

// newSetupHarness runs a server with nothing set up: no email delivery and
// nobody who may sign in. Its SMTP servers take any password but "wrong".
func newSetupHarness(t *testing.T) (*harness, *[]config.SMTPConfig) {
	t.Helper()
	h := &harness{t: t, idp: newFakeIDP(t), mail: &mailbox{ch: make(chan mail.Message, 10)}}
	h.yaml = fmt.Appendf(nil, "public_url: http://%s\ndata_dir: %s\n", domain, t.TempDir())
	h.start()
	var checked []config.SMTPConfig
	h.srv.Settings().CheckSMTP = func(_ context.Context, c config.SMTPConfig) error {
		checked = append(checked, c)
		if c.Password == "wrong" {
			return errors.New("smtp: authenticate: 535 5.7.8 authentication failed")
		}
		return nil
	}
	return h, &checked
}

func setupLink(t *testing.T, ctx context.Context, h *harness) string {
	t.Helper()
	link, err := h.serveAdminOnce().SetupURL(ctx)
	if err != nil {
		t.Fatal(err)
	}
	token, ok := strings.CutPrefix(link, "http://"+domain+"/?setup=")
	if !ok || len(token) < 32 {
		t.Fatalf("setup link %s", link)
	}
	return token
}

func TestSetup(t *testing.T) {
	h, checked := newSetupHarness(t)
	ctx := t.Context()
	admin := h.serveAdminOnce()
	if st, err := admin.Status(ctx); err != nil || !st.Setup {
		t.Fatalf("status before the setup: %+v, %v", st, err)
	}

	// A visitor sees that intergate is being set up, and nothing else.
	visitor := h.browser(true)
	_, b := page(t, visitor, "/")
	if b.Setup == nil || !b.Setup.Email || !b.Setup.Owner || b.Setup.Session || b.Email {
		t.Fatalf("boot before the setup: %+v email=%v", b.Setup, b.Email)
	}
	if resp, _ := send(t, visitor, "POST", "/api/login/email", map[string]string{"email": "a@example.com"}, ""); resp.StatusCode != http.StatusNotFound {
		t.Errorf("email sign-in without email delivery: %d", resp.StatusCode)
	}
	smtp := map[string]any{"host": "smtp.example.com", "port": 587, "tls": "starttls", "username": "me", "password": "s3cret", "from": "intergate <no-reply@gate.test>"}
	if resp, _ := send(t, visitor, "POST", "/api/setup/email", smtp, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("setup without the link: %d", resp.StatusCode)
	}

	// The link's token works once, from the dashboard's origin.
	token := setupLink(t, ctx, h)
	if resp, _ := send(t, visitor, "POST", "/api/setup/start", map[string]string{"token": token + "x"}, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("wrong token: %d", resp.StatusCode)
	}
	if resp, _ := sendFrom(t, visitor, "http://evil.test", "POST", "/api/setup/start", map[string]string{"token": token}, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin start: %d", resp.StatusCode)
	}
	owner := h.browser(true)
	resp, body := send(t, owner, "POST", "/api/setup/start", map[string]string{"token": token}, "")
	if st := decode[struct{ Setup setupState }](t, body).Setup; resp.StatusCode != http.StatusOK || !st.Session || !st.Email || !st.Owner {
		t.Fatalf("start: %d %s", resp.StatusCode, body)
	}
	if resp, _ := send(t, visitor, "POST", "/api/setup/start", map[string]string{"token": token}, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("the link worked twice: %d", resp.StatusCode)
	}
	if _, b := page(t, visitor, "/"); b.Setup == nil || b.Setup.Session {
		t.Errorf("another browser shares the setup: %+v", b.Setup)
	}

	// Email delivery first: checked with the SMTP server, then saved.
	if resp, body := send(t, owner, "POST", "/api/setup/owner", map[string]string{"email": "boss@example.org"}, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("owner before email: %d %s", resp.StatusCode, body)
	}
	bad := map[string]any{"host": "smtp.example.com", "port": 587, "tls": "starttls", "from": "nobody"}
	if resp, body := send(t, owner, "POST", "/api/setup/email", bad, ""); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "sender") {
		t.Errorf("bad sender: %d %s", resp.StatusCode, body)
	}
	smtp["password"] = "wrong"
	if resp, body := send(t, owner, "POST", "/api/setup/email", smtp, ""); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "535") {
		t.Errorf("refused password: %d %s", resp.StatusCode, body)
	}
	smtp["password"] = "s3cret"
	resp, body = send(t, owner, "POST", "/api/setup/email", smtp, "")
	st := decode[struct{ Setup setupState }](t, body).Setup
	if resp.StatusCode != http.StatusOK || st.Email || !st.Owner || st.SMTP == nil || st.SMTP.Host != "smtp.example.com" || !st.SMTP.Password {
		t.Fatalf("save email: %d %s", resp.StatusCode, body)
	}
	if last := (*checked)[len(*checked)-1]; last.Password != "s3cret" || last.Username != "me" || last.Port != 587 {
		t.Errorf("checked %+v", last)
	}
	if raw, err := h.store.Setting(ctx, "email"); err != nil || strings.Contains(raw, "s3cret") || strings.Contains(body, "s3cret") {
		t.Errorf("the password shows: %s %s %v", raw, body, err)
	}
	if _, b := page(t, owner, "/"); !b.Email || b.Setup == nil || b.Setup.SMTP == nil || b.Setup.SMTP.From != "intergate <no-reply@gate.test>" {
		t.Errorf("boot after the email step: email=%v %+v", b.Email, b.Setup)
	}
	if _, b := page(t, visitor, "/"); b.Setup == nil || b.Setup.SMTP != nil {
		t.Errorf("a visitor sees the email settings: %+v", b.Setup)
	}

	// A new link ends this session and keeps what was saved.
	token = setupLink(t, ctx, h)
	if resp, body := send(t, owner, "POST", "/api/setup/owner", map[string]string{"email": "boss@example.org"}, ""); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "expired") {
		t.Errorf("old session after a new link: %d %s", resp.StatusCode, body)
	}
	resp, body = send(t, owner, "POST", "/api/setup/start", map[string]string{"token": token}, "")
	if st := decode[struct{ Setup setupState }](t, body).Setup; resp.StatusCode != http.StatusOK || st.Email || !st.Owner {
		t.Fatalf("restart the setup: %d %s", resp.StatusCode, body)
	}

	// The owner confirms their address with a code.
	if resp, _ := send(t, owner, "POST", "/api/setup/owner", map[string]string{"email": "not an address"}, ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("bad owner address: %d", resp.StatusCode)
	}
	if resp, body := send(t, owner, "POST", "/api/setup/owner", map[string]string{"email": "Boss@Example.org"}, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("send the owner's code: %d %s", resp.StatusCode, body)
	}
	code := h.mail.code(t, "boss@example.org")
	if _, b := page(t, owner, "/"); b.Setup == nil || b.Setup.OwnerFlow != "boss@example.org" {
		t.Errorf("boot while waiting for the code: %+v", b.Setup)
	}
	if resp, _ := send(t, visitor, "POST", "/api/setup/owner/code", map[string]string{"code": code}, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("code from another browser: %d", resp.StatusCode)
	}
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if resp, _ := send(t, owner, "POST", "/api/setup/owner/code", map[string]string{"code": wrong}, ""); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("wrong code: %d", resp.StatusCode)
	}
	resp, body = send(t, owner, "POST", "/api/setup/owner/code", map[string]string{"code": code[:3] + " " + code[3:]}, "")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "/account?welcome=1") {
		t.Fatalf("enter the owner's code: %d %s", resp.StatusCode, body)
	}

	// Done: the owner is signed in, and the setup is gone.
	_, b = page(t, owner, "/")
	if b.Setup != nil || b.User == nil || b.User.Email != "boss@example.org" || b.User.Role != string(store.RoleOwner) || !b.User.Admin {
		t.Fatalf("after the setup: %+v %+v", b.Setup, b.User)
	}
	if _, b := page(t, visitor, "/"); b.Setup != nil || !b.Email {
		t.Errorf("a visitor after the setup: %+v", b.Setup)
	}
	if resp, _ := send(t, visitor, "POST", "/api/setup/start", map[string]string{"token": token}, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("start after the setup: %d", resp.StatusCode)
	}
	if _, err := admin.SetupURL(ctx); err == nil || !strings.Contains(err.Error(), "already set up") {
		t.Errorf("setup link after the setup: %v", err)
	}
	if st, _ := admin.Status(ctx); st.Setup {
		t.Error("status still says not set up")
	}
	if e, err := admin.Email(ctx); err != nil || e.Source != "dashboard" || e.Host != "smtp.example.com" || e.Password != "stored" {
		t.Errorf("admin email = %+v, %v", e, err)
	}

	// The owner signs in again with email codes, through the SMTP server
	// set up.
	again := h.browser(true)
	if code := h.emailLogin(again, "boss@example.org", "/"); code == "" {
		t.Fatal("no sign-in code")
	}
}

// TestSetupOwnerOnly checks a configuration with email delivery and nobody
// allowed: the setup only asks for the owner.
func TestSetupOwnerOnly(t *testing.T) {
	h := &harness{t: t, idp: newFakeIDP(t), mail: &mailbox{ch: make(chan mail.Message, 10)}}
	h.yaml = fmt.Appendf(nil, "public_url: http://%s\ndata_dir: %s\nauth:\n  email:\n    log_only: true\n", domain, t.TempDir())
	h.start()
	ctx := t.Context()
	browser := h.browser(true)
	_, b := page(t, browser, "/")
	if b.Setup == nil || b.Setup.Email || !b.Setup.Owner || !b.Email {
		t.Fatalf("boot: %+v", b.Setup)
	}
	token := setupLink(t, ctx, h)
	send(t, browser, "POST", "/api/setup/start", map[string]string{"token": token}, "")
	if resp, body := send(t, browser, "POST", "/api/setup/email", map[string]any{"host": "smtp.example.com", "port": 25, "tls": "none", "from": "a@b.c"}, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("email over the configuration file: %d %s", resp.StatusCode, body)
	}
	send(t, browser, "POST", "/api/setup/owner", map[string]string{"email": "boss@example.org"}, "")
	code := h.mail.code(t, "boss@example.org")
	if resp, body := send(t, browser, "POST", "/api/setup/owner/code", map[string]string{"code": code}, ""); resp.StatusCode != http.StatusOK {
		t.Fatalf("owner code: %d %s", resp.StatusCode, body)
	}
	if _, b := page(t, browser, "/"); b.Setup != nil || b.User == nil || b.User.Role != "owner" {
		t.Errorf("after: %+v %+v", b.Setup, b.User)
	}
}

// TestNoSetupWhenConfigured checks that a configuration that lets people
// sign in never shows the setup.
func TestNoSetupWhenConfigured(t *testing.T) {
	h := newHarness(t)
	if _, b := page(t, h.browser(true), "/"); b.Setup != nil {
		t.Errorf("setup shown: %+v", b.Setup)
	}
	if _, err := h.serveAdminOnce().SetupURL(t.Context()); err == nil {
		t.Error("setup link for a configured server")
	}
	if resp, _ := send(t, h.browser(true), "POST", "/api/setup/start", map[string]string{"token": "x"}, ""); resp.StatusCode != http.StatusConflict {
		t.Errorf("setup start: %d", resp.StatusCode)
	}
}

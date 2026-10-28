package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// postFrom submits a form like a dashboard page would, with its Origin.
func postFrom(t *testing.T, c *http.Client, path string, form url.Values) (*http.Response, string) {
	t.Helper()
	req, _ := http.NewRequest("POST", "http://"+domain+path, strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+domain)
	resp, err := c.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	return resp, readBody(t, resp)
}

// emailLogin signs in with a code and returns the final page.
func (h *harness) emailLogin(c *http.Client, email, rd string) (*http.Response, string) {
	h.t.Helper()
	resp, body := postFrom(h.t, c, "/login/email", url.Values{"email": {email}, "rd": {rd}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Check your email") {
		h.t.Fatalf("request code: %d\n%s", resp.StatusCode, body)
	}
	return postFrom(h.t, c, "/login/code", url.Values{"code": {h.mail.code(h.t, strings.ToLower(email))}})
}

func TestEmailLogin(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)

	// The first sign-in creates the account and suggests a passkey.
	resp, body := h.emailLogin(b, "Alice@Example.com", "/subdomains/x")
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/account" || !strings.Contains(body, "Sign in faster next time") {
		t.Fatalf("after login: %d %s\n%s", resp.StatusCode, resp.Request.URL, body)
	}
	if !strings.Contains(body, `href="/subdomains/x"`) {
		t.Error("the skip link does not lead to the requested page")
	}
	if _, body := get(t, b, "http://"+domain+"/"); !strings.Contains(body, "alice@example.com") || !strings.Contains(body, "Your subdomains") {
		t.Fatalf("not signed in:\n%s", body)
	}
	if u, err := h.store.UserByEmail(t.Context(), "alice@example.com"); err != nil || u.LastLoginAt.IsZero() {
		t.Fatalf("user = %+v, %v", u, err)
	}
}

func TestEmailCodeRules(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)

	// Wrong codes are rejected; the right one works once.
	postFrom(t, b, "/login/email", url.Values{"email": {"bob@example.com"}})
	code := h.mail.code(t, "bob@example.com")
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if resp, body := postFrom(t, b, "/login/code", url.Values{"code": {wrong}}); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "not right") {
		t.Fatalf("wrong code: %d\n%s", resp.StatusCode, body)
	}
	if resp, _ := postFrom(t, b, "/login/code", url.Values{"code": {code[:3] + " " + code[3:]}}); resp.Request.URL.Path != "/account" {
		t.Fatalf("right code with a space: ended on %s", resp.Request.URL)
	}

	// A code only works in the browser that asked for it.
	other := h.browser(true)
	post(t, b, "/", "/logout", url.Values{})
	postFrom(t, b, "/login/email", url.Values{"email": {"bob@example.com"}})
	code = h.mail.code(t, "bob@example.com")
	if resp, _ := postFrom(t, other, "/login/code", url.Values{"code": {code}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("code used from another browser: %d", resp.StatusCode)
	}

	// Five wrong guesses burn the code.
	for range 5 {
		postFrom(t, b, "/login/code", url.Values{"code": {wrong}})
	}
	if resp, body := postFrom(t, b, "/login/code", url.Values{"code": {code}}); resp.StatusCode < 400 || !strings.Contains(body, "expired") {
		t.Errorf("code after 5 wrong guesses: %d\n%s", resp.StatusCode, body)
	}
	if _, body := get(t, b, "http://"+domain+"/"); strings.Contains(body, "Your subdomains") {
		t.Error("signed in with a burned code")
	}
}

func TestEmailLoginRefusals(t *testing.T) {
	h := newHarness(t)

	// Addresses that may not sign in get the same page but no email.
	b := h.browser(true)
	resp, body := postFrom(t, b, "/login/email", url.Values{"email": {"mallory@evil.test"}})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "Check your email") {
		t.Fatalf("disallowed address: %d\n%s", resp.StatusCode, body)
	}
	h.mail.none(t)

	// Disabled users get no email either.
	u, _ := h.store.EnsureUser(t.Context(), "carol@example.com")
	h.store.SetUserDisabled(t.Context(), u.ID, true)
	postFrom(t, b, "/login/email", url.Values{"email": {"carol@example.com"}})
	h.mail.none(t)

	// Garbage is rejected.
	if resp, _ := postFrom(t, b, "/login/email", url.Values{"email": {"not-an-email"}}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid address: %d", resp.StatusCode)
	}

	// Requests from other origins (such as a tunnel page) are refused.
	req, _ := http.NewRequest("POST", "http://"+domain+"/login/email", strings.NewReader("email=dave%40example.com"))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil."+domain)
	if resp, err := b.Do(req); err != nil || resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin code request: %v %v", resp.StatusCode, err)
	}

	// Rate limit per address.
	for i := range 6 {
		resp, _ := postFrom(t, h.browser(true), "/login/email", url.Values{"email": {"erin@example.com"}})
		if i < 5 {
			h.mail.code(t, "erin@example.com")
			continue
		}
		if resp.StatusCode != http.StatusTooManyRequests {
			t.Errorf("6th code request: %d", resp.StatusCode)
		}
	}
	h.mail.none(t)
}

func TestOAuthLinksToEmailAccount(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)
	h.emailLogin(b, "alice@example.com", "/")
	before, _ := h.store.UserByEmail(t.Context(), "alice@example.com")

	// Signing in with an OAuth account with the same verified email lands
	// on the same account.
	other := h.browser(true)
	h.login(other, "alice@example.com")
	users, _ := h.store.ListUsers(t.Context())
	if len(users) != 1 || users[0].ID != before.ID || users[0].Providers != "test" {
		t.Fatalf("users = %+v", users)
	}
}

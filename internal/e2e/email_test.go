package e2e

import (
	"net/http"
	"net/url"
	"strings"
	"testing"
)

// requestCode asks for a sign-in code as the sign-in form does.
func requestCode(t *testing.T, c *http.Client, email, rd string) (*http.Response, string) {
	t.Helper()
	return send(t, c, "POST", "/api/login/email", map[string]string{"email": email, "rd": rd}, "")
}

func enterCode(t *testing.T, c *http.Client, code string) (*http.Response, string) {
	t.Helper()
	return send(t, c, "POST", "/api/login/code", map[string]string{"code": code}, "")
}

// emailLogin signs in with a code and returns where the app goes next.
func (h *harness) emailLogin(c *http.Client, email, rd string) string {
	h.t.Helper()
	resp, body := requestCode(h.t, c, email, rd)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, strings.ToLower(email)) {
		h.t.Fatalf("request code: %d\n%s", resp.StatusCode, body)
	}
	resp, body = enterCode(h.t, c, h.mail.code(h.t, strings.ToLower(email)))
	if resp.StatusCode != http.StatusOK {
		h.t.Fatalf("enter code: %d\n%s", resp.StatusCode, body)
	}
	return decode[struct {
		Redirect string `json:"redirect"`
	}](h.t, body).Redirect
}

func TestEmailLogin(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)

	// The first sign-in creates the account and suggests a passkey, then
	// goes where the visitor was going.
	if next := h.emailLogin(b, "Alice@Example.com", "/subdomains/x"); next != "/account?welcome=1&rd="+url.QueryEscape("/subdomains/x") {
		t.Fatalf("after login the app goes to %q", next)
	}
	if _, boot := page(t, b, "/"); boot.User == nil || boot.User.Email != "alice@example.com" {
		t.Fatalf("not signed in: %+v", boot)
	}
	if u, err := h.store.UserByEmail(t.Context(), "alice@example.com"); err != nil || u.LastLoginAt.IsZero() {
		t.Fatalf("user = %+v, %v", u, err)
	}
	// Redirects stay on the dashboard.
	if next := h.emailLogin(h.browser(true), "alice@example.com", "https://evil.test/"); next != "/account?welcome=1&rd=%2F" {
		t.Errorf("foreign redirect: %q", next)
	}
}

func TestEmailCodeRules(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)

	// The browser remembers which address it waits for a code for.
	requestCode(t, b, "bob@example.com", "/")
	code := h.mail.code(t, "bob@example.com")
	if _, boot := page(t, b, "/login"); boot.EmailFlow != "bob@example.com" {
		t.Errorf("email flow in the page: %q", boot.EmailFlow)
	}

	// Wrong codes are rejected; the right one works once.
	wrong := "000000"
	if code == wrong {
		wrong = "111111"
	}
	if resp, body := enterCode(t, b, wrong); resp.StatusCode != http.StatusUnauthorized || !strings.Contains(body, "not right") || strings.Contains(body, "expired") {
		t.Fatalf("wrong code: %d\n%s", resp.StatusCode, body)
	}
	if resp, body := enterCode(t, b, code[:3]+" "+code[3:]); resp.StatusCode != http.StatusOK {
		t.Fatalf("right code with a space: %d %s", resp.StatusCode, body)
	}
	if resp, _ := enterCode(t, b, code); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("code used twice: %d", resp.StatusCode)
	}

	// A code only works in the browser that asked for it.
	other := h.browser(true)
	call(t, b, "POST", "/api/logout", nil)
	requestCode(t, b, "bob@example.com", "/")
	code = h.mail.code(t, "bob@example.com")
	if resp, body := enterCode(t, other, code); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, `"expired":true`) {
		t.Errorf("code used from another browser: %d %s", resp.StatusCode, body)
	}

	// Five wrong guesses burn the code.
	for range 5 {
		enterCode(t, b, wrong)
	}
	if resp, body := enterCode(t, b, code); resp.StatusCode < 400 || !strings.Contains(body, `"expired":true`) {
		t.Errorf("code after 5 wrong guesses: %d\n%s", resp.StatusCode, body)
	}
	if _, boot := page(t, b, "/"); boot.User != nil || boot.EmailFlow != "" {
		t.Errorf("after a burned code: %+v", boot)
	}

	// Asking for a code at another address forgets the first.
	requestCode(t, b, "bob@example.com", "/")
	h.mail.code(t, "bob@example.com")
	if resp, _ := send(t, b, "DELETE", "/api/login/email", nil, ""); resp.StatusCode != http.StatusNoContent {
		t.Errorf("cancel: %d", resp.StatusCode)
	}
	if _, boot := page(t, b, "/login"); boot.EmailFlow != "" {
		t.Errorf("email flow after cancelling: %q", boot.EmailFlow)
	}
}

func TestEmailLoginRefusals(t *testing.T) {
	h := newHarness(t)

	// Addresses that may not sign in get the same answer but no email.
	b := h.browser(true)
	resp, body := requestCode(t, b, "mallory@evil.test", "/")
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, "mallory@evil.test") {
		t.Fatalf("disallowed address: %d\n%s", resp.StatusCode, body)
	}
	h.mail.none(t)

	// Disabled users get no email either.
	u, _ := h.store.EnsureUser(t.Context(), "carol@example.com")
	h.store.SetUserDisabled(t.Context(), u.ID, true)
	requestCode(t, b, "carol@example.com", "/")
	h.mail.none(t)

	// Garbage is rejected.
	for _, bad := range []string{"not-an-email", "Dave <dave@example.com>"} {
		if resp, _ := requestCode(t, b, bad, "/"); resp.StatusCode != http.StatusBadRequest {
			t.Errorf("invalid address %q: %d", bad, resp.StatusCode)
		}
	}
	if resp, _ := send(t, b, "POST", "/api/login/email", []byte("email=x"), ""); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("form body: %d", resp.StatusCode)
	}

	// Requests from other origins (such as a tunnel page) are refused.
	if resp, _ := sendFrom(t, b, "http://evil."+domain, "POST", "/api/login/email", map[string]string{"email": "dave@example.com"}, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin code request: %d", resp.StatusCode)
	}
	h.mail.none(t)

	// Rate limit per address.
	for i := range 6 {
		resp, _ := requestCode(t, h.browser(true), "erin@example.com", "/")
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

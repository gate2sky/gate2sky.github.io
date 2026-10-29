package e2e

import (
	"net/http"
	"strings"
	"testing"

	"github.com/jgermade/intergate/internal/store"
)

func TestRenameSubdomain(t *testing.T) {
	h := newHarness(t)
	_, _, key := h.setup("alice@example.com", "demo", store.AccessPrivate)
	h.setup("bob@example.com", "taken", store.AccessPublic)
	c, err := h.dial(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !c.forward(t, "demo", 80, backend(t)) {
		t.Fatal("forward rejected")
	}
	waitFor(t, func() bool { return h.registry.Get("demo") != nil })

	alice := h.loggedIn("alice@example.com")
	bob := h.loggedIn("bob@example.com")
	if resp, _ := call(t, bob, "PATCH", "/api/subdomains/demo", map[string]string{"name": "bobs"}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("someone else's subdomain: %d", resp.StatusCode)
	}
	for name, want := range map[string]string{
		"taken": "already taken",
		"admin": "can't be used",
		"Demo":  "already has that name",
		"a.b":   "can't be used",
	} {
		resp, body := call(t, alice, "PATCH", "/api/subdomains/demo", map[string]string{"name": name})
		if resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, want) {
			t.Errorf("rename to %q: %d %s", name, resp.StatusCode, body)
		}
	}
	if resp, _ := call(t, alice, "PATCH", "/api/subdomains/demo", map[string]string{}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("empty change: %d", resp.StatusCode)
	}

	resp, body := call(t, alice, "PATCH", "/api/subdomains/demo", map[string]string{"name": "Web"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"name":"web"`) || !strings.Contains(body, `"access":"private"`) {
		t.Fatalf("rename: %d %s", resp.StatusCode, body)
	}
	// The tunnel closes; the keys and access stay with the new name, and
	// the old name is free.
	waitFor(t, func() bool { return h.registry.Get("demo") == nil })
	if resp, _ := call(t, alice, "GET", "/api/subdomains/demo", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("old name: %d", resp.StatusCode)
	}
	resp, body = call(t, alice, "GET", "/api/subdomains/web", nil)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"keys":1`) {
		t.Errorf("new name: %d %s", resp.StatusCode, body)
	}
	c, _ = h.dial(key, "alice")
	if c.forward(t, "demo", 80, nil) {
		t.Error("the old name still forwards")
	}
	if !c.forward(t, "web", 80, backend(t)) {
		t.Error("the new name does not forward")
	}
	if resp, body := call(t, bob, "POST", "/api/subdomains", map[string]any{"name": "demo"}); resp.StatusCode != http.StatusCreated {
		t.Errorf("register the freed name: %d %s", resp.StatusCode, body)
	}

	// Name and access can change together.
	resp, body = call(t, alice, "PATCH", "/api/subdomains/web", map[string]string{"name": "site", "access": "public"})
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, `"name":"site"`) || !strings.Contains(body, `"access":"public"`) {
		t.Errorf("rename and set access: %d %s", resp.StatusCode, body)
	}
}

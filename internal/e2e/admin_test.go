package e2e

import (
	"context"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gate2net/gate2net.github.io/internal/admin"
	"github.com/gate2net/gate2net.github.io/internal/store"
)

// serveAdmin starts the admin socket and returns a client for it.
func (h *harness) serveAdmin() *admin.Client {
	h.t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		defer close(done)
		if err := h.srv.Admin().Serve(ctx); err != nil {
			h.t.Error(err)
		}
	}()
	h.t.Cleanup(func() { cancel(); <-done })
	c := admin.NewClient(h.cfg.Admin.Socket)
	waitFor(h.t, func() bool { _, err := c.Status(ctx); return err == nil })
	return c
}

func TestAdminSocket(t *testing.T) {
	h := newHarness(t)
	c := h.serveAdmin()
	ctx := t.Context()

	if fi, err := os.Stat(h.cfg.Admin.Socket); err != nil || fi.Mode().Perm() != 0o600 {
		t.Fatalf("socket mode: %v %v", fi.Mode(), err)
	}
	st, err := c.Status(ctx)
	if err != nil || st.Version != "test" || st.PID != os.Getpid() {
		t.Fatalf("status = %+v, %v", st, err)
	}

	// Register a subdomain for a new user, with a key.
	key := newSigner(t)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))) + " laptop"
	sd, res, err := c.CreateSubdomain(ctx, admin.CreateSubdomainRequest{Name: "Tools", Owner: "dev@example.com", Keys: pub})
	if err != nil || sd.Name != "tools" || sd.Owner != "dev@example.com" || sd.Access != store.AccessPublic || res.Added != 1 {
		t.Fatalf("create = %+v %+v %v", sd, res, err)
	}
	if _, _, err := c.CreateSubdomain(ctx, admin.CreateSubdomainRequest{Name: "tools", Owner: "x@example.com"}); err == nil || !strings.Contains(err.Error(), "already taken") {
		t.Errorf("duplicate subdomain: %v", err)
	}
	if _, _, err := c.CreateSubdomain(ctx, admin.CreateSubdomainRequest{Name: "ok", Owner: "not an email"}); err == nil {
		t.Error("invalid owner accepted")
	}

	// The key opens the tunnel; changes apply to it live.
	sc, err := h.dial(key, "x")
	if err != nil {
		t.Fatal(err)
	}
	sc.forward(t, "tools", 80, backend(t))
	detail, err := c.Subdomain(ctx, "tools")
	if err != nil || detail.Tunnel == nil || len(detail.KeyList) != 1 || detail.KeyList[0].Name != "laptop" {
		t.Fatalf("detail = %+v, %v", detail, err)
	}
	if err := c.SetAccess(ctx, "tools", store.AccessPrivate); err != nil {
		t.Fatal(err)
	}
	if resp, _ := get(t, h.browser(false), "http://tools."+domain+"/"); resp.StatusCode != http.StatusFound {
		t.Errorf("anonymous visit after making it private: %d", resp.StatusCode)
	}
	if err := c.RemoveKey(ctx, "tools", detail.KeyList[0].ID); err != nil {
		t.Fatal(err)
	}
	waitFor(t, func() bool { return h.registry.Get("tools") == nil })

	// Users.
	u, err := c.CreateUser(ctx, "New@Example.com")
	if err != nil || u.Email != "new@example.com" || !u.Allowed {
		t.Fatalf("create user = %+v, %v", u, err)
	}
	// Added users may sign in whatever auth.allowed_* says.
	if out, _ := c.CreateUser(ctx, "outsider@other.test"); out == nil || !out.Allowed {
		t.Errorf("outsider = %+v", out)
	}
	if err := c.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	users, err := c.Users(ctx)
	if err != nil || len(users) != 3 {
		t.Fatalf("users = %+v, %v", users, err)
	}
	for _, x := range users {
		if x.ID == u.ID && !x.Disabled {
			t.Error("user not disabled")
		}
	}
	if err := c.DeleteSubdomain(ctx, "tools"); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Subdomain(ctx, "tools"); err == nil {
		t.Error("deleted subdomain still there")
	}
}

func TestAdminClientNotRunning(t *testing.T) {
	c := admin.NewClient(t.TempDir() + "/nothing.sock")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if _, err := c.Status(ctx); err == nil || !strings.Contains(err.Error(), "not running") {
		t.Errorf("err = %v", err)
	}
}

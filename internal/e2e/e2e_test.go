// Package e2e runs securegate end to end: a real SSH server and HTTP
// handler, SSH clients that open tunnels, browsers that sign in through a
// fake OpenID Connect provider.
package e2e

import (
	"bufio"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/http/cookiejar"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/securegate/internal/config"
	"github.com/jgermade/securegate/internal/names"
	"github.com/jgermade/securegate/internal/sshd"
	"github.com/jgermade/securegate/internal/store"
	"github.com/jgermade/securegate/internal/tunnel"
	"github.com/jgermade/securegate/internal/web"
)

const domain = "gate.test"

type harness struct {
	t        *testing.T
	cfg      *config.Config
	store    *store.Store
	registry *tunnel.Registry
	idp      *fakeIDP
	web      *httptest.Server
	sshAddr  string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	h := &harness{t: t, idp: newFakeIDP(t)}
	dir := t.TempDir()
	var err error
	h.cfg, err = config.Parse(fmt.Appendf(nil, `
public_url: http://%s
data_dir: %s
ssh:
  keepalive_interval: 1s
auth:
  admins: [admin@example.com]
  allowed_domains: [example.com]
  providers:
    - id: test
      type: oidc
      name: Test IdP
      issuer: %s
      client_id: %s
      client_secret: %s
`, domain, dir, h.idp.URL, idpClientID, idpClientSecret))
	if err != nil {
		t.Fatal(err)
	}
	h.store, err = store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.store.Close() })
	h.registry = tunnel.NewRegistry()
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}

	_, hostPriv, _ := ed25519.GenerateKey(rand.Reader)
	hostKey, _ := ssh.NewSignerFromKey(hostPriv)
	sshSrv := sshd.New(h.cfg, h.store, h.registry, hostKey, log)
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.sshAddr = ln.Addr().String()
	go sshSrv.Serve(ln)
	t.Cleanup(func() { sshSrv.Close() })

	handler, err := web.New(web.Options{
		Config:   h.cfg,
		Store:    h.store,
		Registry: h.registry,
		Names:    names.NewChecker(nil),
		Secret:   []byte(strings.Repeat("s", 32)),
		Logger:   log,
	})
	if err != nil {
		t.Fatal(err)
	}
	h.web = httptest.NewServer(handler)
	t.Cleanup(h.web.Close)
	return h
}

type testWriter struct{ t *testing.T }

func (w testWriter) Write(p []byte) (int, error) {
	w.t.Log(strings.TrimSpace(string(p)))
	return len(p), nil
}

// browser returns an HTTP client with a cookie jar that resolves
// gate.test and its subdomains to the test server.
func (h *harness) browser(follow bool) *http.Client {
	jar, _ := cookiejar.New(nil)
	webAddr := h.web.Listener.Addr().String()
	c := &http.Client{
		Jar:     jar,
		Timeout: 10 * time.Second,
		Transport: &http.Transport{DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			if host, _, _ := net.SplitHostPort(addr); host == domain || strings.HasSuffix(host, "."+domain) {
				addr = webAddr
			}
			return (&net.Dialer{}).DialContext(ctx, network, addr)
		}},
	}
	if !follow {
		c.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	}
	return c
}

// login signs the browser in through the fake provider.
func (h *harness) login(c *http.Client, email string) {
	h.t.Helper()
	h.idp.SetUser(email)
	resp, err := c.Get("http://" + domain + "/auth/test/login?rd=/")
	if err != nil {
		h.t.Fatal(err)
	}
	body := readBody(h.t, resp)
	if resp.StatusCode != http.StatusOK || !strings.Contains(body, email) {
		h.t.Fatalf("login as %s: status %d\n%s", email, resp.StatusCode, body)
	}
}

func readBody(t *testing.T, resp *http.Response) string {
	t.Helper()
	defer resp.Body.Close()
	b, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func get(t *testing.T, c *http.Client, u string) (*http.Response, string) {
	t.Helper()
	resp, err := c.Get(u)
	if err != nil {
		t.Fatal(err)
	}
	return resp, readBody(t, resp)
}

var csrfRE = regexp.MustCompile(`name="csrf_token" value="([^"]+)"`)

// post submits a dashboard form with the CSRF token of the given page.
func post(t *testing.T, c *http.Client, page, action string, form url.Values) (*http.Response, string) {
	t.Helper()
	_, body := get(t, c, "http://"+domain+page)
	m := csrfRE.FindStringSubmatch(body)
	if m == nil {
		t.Fatalf("no CSRF token on %s", page)
	}
	form.Set("csrf_token", m[1])
	resp, err := c.PostForm("http://"+domain+action, form)
	if err != nil {
		t.Fatal(err)
	}
	return resp, readBody(t, resp)
}

func newSigner(t *testing.T) ssh.Signer {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	s, err := ssh.NewSignerFromKey(priv)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// setup creates a user owning a subdomain whose only key is returned.
func (h *harness) setup(email, name string, access store.Access) (*store.User, *store.Subdomain, ssh.Signer) {
	h.t.Helper()
	ctx := context.Background()
	u, err := h.store.UpsertUser(ctx, store.Identity{Provider: "test", Subject: "sub-" + email, Email: email})
	if err != nil {
		h.t.Fatal(err)
	}
	d, err := h.store.CreateSubdomain(ctx, u.ID, name, access)
	if err != nil {
		h.t.Fatal(err)
	}
	key := newSigner(h.t)
	if _, err := h.store.AddKey(ctx, d.ID, "test key", key.PublicKey()); err != nil {
		h.t.Fatal(err)
	}
	return u, d, key
}

type sshClient struct {
	*ssh.Client
	forwards <-chan ssh.NewChannel
}

func (h *harness) dial(key ssh.Signer, user string) (*sshClient, error) {
	c, err := ssh.Dial("tcp", h.sshAddr, &ssh.ClientConfig{
		User:            user,
		Auth:            []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         5 * time.Second,
	})
	if err != nil {
		return nil, err
	}
	h.t.Cleanup(func() { c.Close() })
	return &sshClient{Client: c, forwards: c.HandleChannelOpen("forwarded-tcpip")}, nil
}

// forward asks for a remote forward like `ssh -R bind:port:...` and pipes
// incoming streams to backend, like the OpenSSH client does.
func (c *sshClient) forward(t *testing.T, bind string, port uint32, backend *httptest.Server) bool {
	t.Helper()
	ok, _, err := c.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{bind, port}))
	if err != nil {
		t.Fatal(err)
	}
	if ok && backend != nil {
		go serveForwards(t, c.forwards, bind, effectivePort(port), backend.Listener.Addr().String())
	}
	return ok
}

func effectivePort(p uint32) uint32 {
	if p == 0 {
		return 80
	}
	return p
}

func serveForwards(t *testing.T, chans <-chan ssh.NewChannel, bind string, port uint32, backend string) {
	for nch := range chans {
		var p struct {
			Addr       string
			Port       uint32
			OriginAddr string
			OriginPort uint32
		}
		if err := ssh.Unmarshal(nch.ExtraData(), &p); err != nil || p.Addr != bind || p.Port != port {
			t.Errorf("forwarded-tcpip payload %+v (%v), want %s:%d", p, err, bind, port)
			nch.Reject(ssh.ConnectionFailed, "unexpected forward")
			continue
		}
		ch, reqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			defer ch.Close()
			conn, err := net.Dial("tcp", backend)
			if err != nil {
				return
			}
			defer conn.Close()
			go func() {
				io.Copy(conn, ch)
				conn.(*net.TCPConn).CloseWrite()
			}()
			io.Copy(ch, conn)
		}()
	}
}

// backend is the "local service" behind tunnels. It echoes what it saw.
func backend(t *testing.T) *httptest.Server {
	s := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Upgrade") == "echo" {
			conn, rw, err := http.NewResponseController(w).Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			defer conn.Close()
			rw.WriteString("HTTP/1.1 101 Switching Protocols\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n")
			rw.Flush()
			io.Copy(conn, rw)
			return
		}
		fmt.Fprintf(w, "backend %s %s host=%s proto=%s cookie=%q", r.Method, r.URL.RequestURI(),
			r.Host, r.Header.Get("X-Forwarded-Proto"), r.Header.Get("Cookie"))
	}))
	t.Cleanup(s.Close)
	return s
}

func TestPublicTunnel(t *testing.T) {
	h := newHarness(t)
	_, _, key := h.setup("alice@example.com", "demo", store.AccessPublic)
	c, err := h.dial(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if !c.forward(t, "demo", 80, backend(t)) {
		t.Fatal("forward rejected")
	}

	resp, body := get(t, h.browser(false), "http://demo."+domain+"/path?q=1")
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status %d: %s", resp.StatusCode, body)
	}
	want := `backend GET /path?q=1 host=demo.gate.test proto=http cookie=""`
	if body != want {
		t.Fatalf("body = %q, want %q", body, want)
	}
	tun := h.registry.Get("demo")
	if tun == nil || tun.Stats().Requests != 1 || tun.Stats().BytesOut == 0 {
		t.Fatalf("tunnel stats: %+v", tun)
	}

	// Unregistered and offline subdomains get securegate's error pages.
	if resp, _ := get(t, h.browser(false), "http://nope."+domain+"/"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("unregistered subdomain: %d", resp.StatusCode)
	}
	c.Close()
	waitFor(t, func() bool { return h.registry.Get("demo") == nil })
	if resp, body := get(t, h.browser(false), "http://demo."+domain+"/"); resp.StatusCode != http.StatusBadGateway || !strings.Contains(body, "Tunnel offline") {
		t.Errorf("offline subdomain: %d %s", resp.StatusCode, body)
	}
}

func TestUpgradeThroughTunnel(t *testing.T) {
	h := newHarness(t)
	_, _, key := h.setup("alice@example.com", "ws", store.AccessPublic)
	c, err := h.dial(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	c.forward(t, "ws", 80, backend(t))

	conn, err := net.Dial("tcp", h.web.Listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))
	fmt.Fprintf(conn, "GET / HTTP/1.1\r\nHost: ws.%s\r\nConnection: Upgrade\r\nUpgrade: echo\r\n\r\n", domain)
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil || resp.StatusCode != http.StatusSwitchingProtocols {
		t.Fatalf("upgrade: %v %v", resp, err)
	}
	fmt.Fprint(conn, "ping\n")
	line, err := br.ReadString('\n')
	if err != nil || line != "ping\n" {
		t.Fatalf("echo = %q, %v", line, err)
	}
}

func TestSSHAuthorization(t *testing.T) {
	h := newHarness(t)
	_, _, aliceKey := h.setup("alice@example.com", "alice-app", store.AccessPublic)
	h.setup("bob@example.com", "bob-app", store.AccessPublic)

	if _, err := h.dial(newSigner(t), "x"); err == nil {
		t.Fatal("unregistered key was accepted")
	}

	c, err := h.dial(aliceKey, "whoever")
	if err != nil {
		t.Fatal(err)
	}
	if c.forward(t, "bob-app", 80, nil) {
		t.Error("forward to another user's subdomain accepted")
	}
	if c.forward(t, "alice-app", 2222, nil) {
		t.Error("non-HTTP port accepted")
	}
	if c.forward(t, "x.y", 80, nil) {
		t.Error("foreign domain accepted")
	}
	// Without a name, the key's only subdomain is used. Port 0 is
	// answered as 80.
	if !c.forward(t, "localhost", 0, backend(t)) {
		t.Fatal("implicit forward rejected")
	}
	if resp, _ := get(t, h.browser(false), "http://alice-app."+domain+"/"); resp.StatusCode != http.StatusOK {
		t.Errorf("implicit tunnel: %d", resp.StatusCode)
	}
	if h.registry.Get("bob-app") != nil {
		t.Error("bob-app should not be online")
	}
}

func TestKeyOnSeveralSubdomains(t *testing.T) {
	h := newHarness(t)
	u, _, key := h.setup("alice@example.com", "one", store.AccessPublic)
	two, _ := h.store.CreateSubdomain(context.Background(), u.ID, "two", store.AccessPublic)
	h.store.AddKey(context.Background(), two.ID, "same key", key.PublicKey())

	c, _ := h.dial(key, "alice")
	if c.forward(t, "", 80, nil) {
		t.Error("ambiguous forward accepted")
	}
	// The SSH user name picks the subdomain.
	c2, _ := h.dial(key, "two")
	if !c2.forward(t, "", 80, backend(t)) {
		t.Fatal("forward chosen by user name rejected")
	}
	if h.registry.Get("two") == nil {
		t.Error("two should be online")
	}
}

func TestNewConnectionReplacesOld(t *testing.T) {
	h := newHarness(t)
	_, _, key := h.setup("alice@example.com", "demo", store.AccessPublic)
	first, _ := h.dial(key, "alice")
	first.forward(t, "demo", 80, backend(t))
	second, _ := h.dial(key, "alice")
	second.forward(t, "demo", 80, backend(t))

	// The first connection lost its only tunnel and is closed.
	done := make(chan error, 1)
	go func() { done <- first.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("replaced connection was not closed")
	}
	if resp, _ := get(t, h.browser(false), "http://demo."+domain+"/"); resp.StatusCode != http.StatusOK {
		t.Errorf("status after takeover: %d", resp.StatusCode)
	}
}

func TestLogin(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)

	// Anonymous visitors see the provider list.
	if _, body := get(t, b, "http://"+domain+"/"); !strings.Contains(body, "Continue with Test IdP") {
		t.Fatalf("login page:\n%s", body)
	}
	h.login(b, "alice@example.com")
	if _, body := get(t, b, "http://"+domain+"/"); !strings.Contains(body, "Your subdomains") || strings.Contains(body, `href="/admin"`) {
		t.Fatalf("dashboard:\n%s", body)
	}

	admin := h.browser(true)
	h.login(admin, "admin@example.com")
	if resp, _ := get(t, admin, "http://"+domain+"/admin"); resp.StatusCode != http.StatusOK {
		t.Errorf("admin page: %d", resp.StatusCode)
	}
	if resp, _ := get(t, b, "http://"+domain+"/admin"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("admin page for non-admin: %d", resp.StatusCode)
	}

	// Accounts outside the allow list are refused.
	h.idp.SetUser("mallory@evil.test")
	resp, body := get(t, h.browser(true), "http://"+domain+"/auth/test/login")
	if resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "not allowed") {
		t.Errorf("disallowed login: %d\n%s", resp.StatusCode, body)
	}

	// A callback without the matching state cookie is rejected.
	resp, _ = get(t, h.browser(true), "http://"+domain+"/auth/test/callback?code=x&state=y")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("forged callback: %d", resp.StatusCode)
	}

	// Signing out ends the session.
	post(t, b, "/", "/logout", url.Values{})
	if _, body := get(t, b, "http://"+domain+"/"); !strings.Contains(body, "Continue with") {
		t.Error("still signed in after logout")
	}
}

func TestDashboardManagesSubdomains(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)
	h.login(b, "alice@example.com")
	key := newSigner(t)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))) + " alice@laptop"

	resp, body := post(t, b, "/", "/subdomains", url.Values{"name": {"MyApp"}, "access": {"private"}, "keys": {pub}})
	if resp.StatusCode != http.StatusOK || resp.Request.URL.Path != "/subdomains/myapp" || !strings.Contains(body, "alice@laptop") {
		t.Fatalf("create: %d %s\n%s", resp.StatusCode, resp.Request.URL, body)
	}
	d, err := h.store.SubdomainByName(context.Background(), "myapp")
	if err != nil || d.Access != store.AccessPrivate || d.Keys != 1 {
		t.Fatalf("stored subdomain %+v, %v", d, err)
	}

	// Reserved and taken names are refused.
	_, body = post(t, b, "/", "/subdomains", url.Values{"name": {"www"}})
	if !strings.Contains(body, "reserved") {
		t.Error("reserved name accepted")
	}
	other := h.browser(true)
	h.login(other, "bob@example.com")
	_, body = post(t, other, "/", "/subdomains", url.Values{"name": {"myapp"}})
	if !strings.Contains(body, "already taken") {
		t.Error("taken name accepted")
	}
	// Other users can't see or change it.
	if resp, _ := get(t, other, "http://"+domain+"/subdomains/myapp"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("other user sees subdomain: %d", resp.StatusCode)
	}

	// Forms need the CSRF token and a same-origin Origin.
	resp, _ = b.PostForm("http://"+domain+"/subdomains/myapp/access", url.Values{"access": {"public"}})
	if resp.StatusCode != http.StatusForbidden {
		t.Errorf("POST without CSRF token: %d", resp.StatusCode)
	}
	_, page := get(t, b, "http://"+domain+"/subdomains/myapp")
	req, _ := http.NewRequest("POST", "http://"+domain+"/subdomains/myapp/access",
		strings.NewReader(url.Values{"access": {"public"}, "csrf_token": {csrfRE.FindStringSubmatch(page)[1]}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://evil.gate.test")
	if resp, _ := b.Do(req); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin POST: %d", resp.StatusCode)
	}

	// Connect, then change access live and remove the key.
	c, err := h.dial(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	c.forward(t, "myapp", 80, backend(t))
	post(t, b, "/subdomains/myapp", "/subdomains/myapp/access", url.Values{"access": {"public"}})
	if resp, _ := get(t, h.browser(false), "http://myapp."+domain+"/"); resp.StatusCode != http.StatusOK {
		t.Errorf("public after change: %d", resp.StatusCode)
	}
	keys, _ := h.store.KeysBySubdomain(context.Background(), d.ID)
	post(t, b, "/subdomains/myapp", fmt.Sprintf("/subdomains/myapp/keys/%d/delete", keys[0].ID), url.Values{})
	waitFor(t, func() bool { return h.registry.Get("myapp") == nil })
	if _, err := h.dial(key, "alice"); err == nil {
		t.Error("removed key can still connect")
	}

	// Deleting needs the name typed in.
	post(t, b, "/subdomains/myapp", "/subdomains/myapp/delete", url.Values{"confirm": {"nope"}})
	if _, err := h.store.SubdomainByName(context.Background(), "myapp"); err != nil {
		t.Fatal("deleted without confirmation")
	}
	post(t, b, "/subdomains/myapp", "/subdomains/myapp/delete", url.Values{"confirm": {"myapp"}})
	if _, err := h.store.SubdomainByName(context.Background(), "myapp"); err == nil {
		t.Fatal("not deleted")
	}
}

func TestProtectedTunnels(t *testing.T) {
	h := newHarness(t)
	alice, _, aliceKey := h.setup("alice@example.com", "secret", store.AccessPrivate)
	_, _, teamKey := h.setup("bob@example.com", "team", store.AccessUsers)
	for _, k := range []struct {
		key  ssh.Signer
		name string
	}{{aliceKey, "secret"}, {teamKey, "team"}} {
		c, err := h.dial(k.key, "x")
		if err != nil {
			t.Fatal(err)
		}
		c.forward(t, k.name, 80, backend(t))
	}
	_ = alice

	// Anonymous visitors are sent to the dashboard to sign in.
	anon := h.browser(false)
	resp, _ := get(t, anon, "http://secret."+domain+"/page?x=1")
	loc := resp.Header.Get("Location")
	if resp.StatusCode != http.StatusFound || !strings.HasPrefix(loc, "http://"+domain+"/tunnel-auth?rd=") {
		t.Fatalf("anonymous: %d %s", resp.StatusCode, loc)
	}
	if resp, _ := anon.Post("http://secret."+domain+"/api", "text/plain", nil); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous POST: %d", resp.StatusCode)
	}

	// The owner gets through after signing in, landing on the page they
	// asked for. The service never sees the access cookie.
	owner := h.browser(true)
	h.login(owner, "alice@example.com")
	ownerURL, _ := url.Parse("http://secret." + domain + "/")
	owner.Jar.SetCookies(ownerURL, []*http.Cookie{{Name: "app", Value: "1"}})
	resp, body := get(t, owner, "http://secret."+domain+"/page?x=1")
	if resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, `backend GET /page?x=1 `) || !strings.Contains(body, `cookie="app=1"`) {
		t.Fatalf("owner: %d %s", resp.StatusCode, body)
	}
	if resp.Request.URL.String() != "http://secret."+domain+"/page?x=1" {
		t.Errorf("owner landed on %s", resp.Request.URL)
	}

	// Other signed-in users may open "users" tunnels but not private ones.
	bob := h.browser(true)
	h.login(bob, "bob@example.com")
	if resp, body := get(t, bob, "http://secret."+domain+"/"); resp.StatusCode != http.StatusForbidden || !strings.Contains(body, "does not have access") {
		t.Errorf("bob on private tunnel: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, owner, "http://team."+domain+"/"); resp.StatusCode != http.StatusOK {
		t.Errorf("alice on users tunnel: %d", resp.StatusCode)
	}

	// Hand-off links are single use and bound to their host.
	noFollow := h.browser(false)
	noFollow.Jar = owner.Jar
	resp, _ = get(t, noFollow, "http://"+domain+"/tunnel-auth?rd="+url.QueryEscape("http://secret."+domain+"/"))
	handoff := resp.Header.Get("Location")
	if !strings.HasPrefix(handoff, "http://secret."+domain+"/__securegate/auth?") {
		t.Fatalf("hand-off location %q", handoff)
	}
	stolen := strings.Replace(handoff, "secret.", "team.", 1)
	if resp, _ := get(t, h.browser(false), stolen); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("hand-off replayed on another host: %d", resp.StatusCode)
	}
	if resp, _ := get(t, h.browser(false), handoff); resp.StatusCode != http.StatusFound {
		t.Errorf("first use of hand-off: %d", resp.StatusCode)
	}
	if resp, _ := get(t, h.browser(false), handoff); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("hand-off reused: %d", resp.StatusCode)
	}
	// tunnel-auth only redirects to tunnels of this securegate.
	if resp, _ := get(t, noFollow, "http://"+domain+"/tunnel-auth?rd="+url.QueryEscape("http://evil.com/")); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("tunnel-auth to foreign host: %d", resp.StatusCode)
	}

	// Signing out of the dashboard also revokes tunnel access.
	post(t, owner, "/", "/logout", url.Values{})
	noFollow = h.browser(false)
	noFollow.Jar = owner.Jar
	if resp, _ := get(t, noFollow, "http://secret."+domain+"/"); resp.StatusCode != http.StatusFound {
		t.Errorf("after logout: %d", resp.StatusCode)
	}
}

func TestDisableUserClosesTunnels(t *testing.T) {
	h := newHarness(t)
	alice, _, key := h.setup("alice@example.com", "demo", store.AccessPublic)
	c, _ := h.dial(key, "alice")
	c.forward(t, "demo", 80, backend(t))

	admin := h.browser(true)
	h.login(admin, "admin@example.com")
	post(t, admin, "/admin", fmt.Sprintf("/admin/users/%d/disable", alice.ID), url.Values{})
	waitFor(t, func() bool { return h.registry.Get("demo") == nil })
	if _, err := h.dial(key, "alice"); err == nil {
		t.Error("disabled user's key still connects")
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatal("condition not met in time")
		}
		time.Sleep(10 * time.Millisecond)
	}
}

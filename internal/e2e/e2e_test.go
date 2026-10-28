// Package e2e runs gate2sky end to end: a real SSH server and HTTP
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
	"regexp"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gate2sky/gate2sky.github.io/internal/api"
	"github.com/gate2sky/gate2sky.github.io/internal/config"
	"github.com/gate2sky/gate2sky.github.io/internal/mail"
	"github.com/gate2sky/gate2sky.github.io/internal/server"
	"github.com/gate2sky/gate2sky.github.io/internal/store"
	"github.com/gate2sky/gate2sky.github.io/internal/tunnel"
)

const domain = "gate.test"

type harness struct {
	t        *testing.T
	cfg      *config.Config
	yaml     []byte
	srv      *server.Server
	store    *store.Store
	registry *tunnel.Registry
	idp      *fakeIDP
	mail     *mailbox
	web      *httptest.Server
	sshAddr  string
}

// mailbox captures sign-in emails.
type mailbox struct{ ch chan mail.Message }

func (m *mailbox) Send(_ context.Context, msg mail.Message) error {
	m.ch <- msg
	return nil
}

// code waits for the next email to addr and returns the code in it.
func (m *mailbox) code(t *testing.T, addr string) string {
	t.Helper()
	select {
	case msg := <-m.ch:
		if msg.To != addr {
			t.Fatalf("email went to %s, want %s", msg.To, addr)
		}
		code := regexp.MustCompile(`\b\d{6}\b`).FindString(msg.Body)
		if code == "" {
			t.Fatalf("no code in email:\n%s", msg.Body)
		}
		return code
	case <-time.After(5 * time.Second):
		t.Fatalf("no email to %s", addr)
	}
	return ""
}

// none checks that no email is sent.
func (m *mailbox) none(t *testing.T) {
	t.Helper()
	select {
	case msg := <-m.ch:
		t.Fatalf("unexpected email to %s", msg.To)
	case <-time.After(200 * time.Millisecond):
	}
}

func newHarness(t *testing.T, extraConfig ...string) *harness {
	t.Helper()
	h := &harness{t: t, idp: newFakeIDP(t), mail: &mailbox{ch: make(chan mail.Message, 10)}}
	dir := t.TempDir()
	h.yaml = fmt.Appendf(nil, `
public_url: http://%s
data_dir: %s
ssh:
  keepalive_interval: 1s
auth:
  admins: [admin@example.com]
  allowed_domains: [example.com]
  email:
    log_only: true
  providers:
    - id: test
      type: oidc
      name: Test IdP
      issuer: %s
      client_id: %s
      client_secret: %s
%s`, domain, dir, h.idp.URL, idpClientID, idpClientSecret, strings.Join(extraConfig, "\n"))
	var err error
	h.cfg, err = config.Parse(h.yaml)
	if err != nil {
		t.Fatal(err)
	}
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	if testing.Verbose() {
		log = slog.New(slog.NewTextHandler(testWriter{t}, &slog.HandlerOptions{Level: slog.LevelDebug}))
	}
	h.srv, err = server.New(h.cfg, log, server.Options{Version: "test", Mailer: h.mail})
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { h.srv.Close() })
	h.store, h.registry = h.srv.Store(), h.srv.Registry()

	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	h.sshAddr = ln.Addr().String()
	go h.srv.SSH().Serve(ln)
	t.Cleanup(func() { h.srv.SSH().Close() })

	h.web = httptest.NewServer(h.srv.Handler())
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

// loggedIn returns a browser signed in as email.
func (h *harness) loggedIn(email string) *http.Client {
	c := h.browser(true)
	h.login(c, email)
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
	u, err := h.store.EnsureUser(ctx, email)
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

	// Unregistered and offline subdomains get gate2sky's error pages.
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

	// Anonymous visitors get the sign-in methods.
	_, boot := page(t, b, "/")
	if boot.User != nil || !boot.Email || !boot.Passkeys || len(boot.Providers) != 1 ||
		boot.Providers[0].Name != "Test IdP" || boot.Providers[0].URL != "/auth/test/login" {
		t.Fatalf("anonymous boot data: %+v", boot)
	}
	if resp, _ := get(t, b, "http://"+domain+"/api/subdomains"); resp.StatusCode != http.StatusUnauthorized {
		t.Errorf("anonymous API call: %d", resp.StatusCode)
	}

	h.login(b, "alice@example.com")
	if _, boot := page(t, b, "/"); boot.User == nil || boot.User.Email != "alice@example.com" || boot.User.Admin || boot.CSRF == "" {
		t.Fatalf("signed-in boot data: %+v", boot)
	}

	admin := h.browser(true)
	h.login(admin, "admin@example.com")
	if resp, boot := page(t, admin, "/admin"); resp.StatusCode != http.StatusOK || !boot.User.Admin {
		t.Errorf("admin page: %d %+v", resp.StatusCode, boot.User)
	}
	if resp, _ := get(t, b, "http://"+domain+"/admin"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("admin page for non-admin: %d", resp.StatusCode)
	}
	if resp, _ := get(t, b, "http://"+domain+"/api/admin/users"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("admin API for non-admin: %d", resp.StatusCode)
	}

	// Accounts outside the allow list are refused.
	h.idp.SetUser("mallory@evil.test")
	resp, body := get(t, h.browser(true), "http://"+domain+"/auth/test/login")
	if boot := parseBoot(t, body); resp.StatusCode != http.StatusForbidden || boot.Error == nil || !strings.Contains(boot.Error.Message, "not allowed") {
		t.Errorf("disallowed login: %d\n%s", resp.StatusCode, body)
	}

	// A callback without the matching state cookie is rejected.
	resp, _ = get(t, h.browser(true), "http://"+domain+"/auth/test/callback?code=x&state=y")
	if resp.StatusCode != http.StatusBadRequest {
		t.Errorf("forged callback: %d", resp.StatusCode)
	}

	// Signing out ends the session.
	if resp, _ := call(t, b, "POST", "/api/logout", nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("logout: %d", resp.StatusCode)
	}
	if _, boot := page(t, b, "/"); boot.User != nil {
		t.Error("still signed in after logout")
	}

	// Unknown pages are a 404 the app shows.
	if resp, boot := page(t, b, "/nope"); resp.StatusCode != http.StatusNotFound || boot.Error == nil || boot.Error.Status != 404 {
		t.Errorf("unknown page: %d %+v", resp.StatusCode, boot.Error)
	}
}

func TestPageSecurity(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)

	// Each page carries a fresh nonce, and the CSP admits scripts by it
	// and from the dashboard itself, never eval.
	nonces := map[string]bool{}
	for range 2 {
		resp, body := get(t, b, "http://"+domain+"/")
		policy := resp.Header.Get("Content-Security-Policy")
		m := regexp.MustCompile(`script-src 'self' 'nonce-([A-Za-z0-9_-]{24})';`).FindStringSubmatch(policy)
		if m == nil || strings.Contains(policy, "unsafe") {
			t.Fatalf("CSP %q", policy)
		}
		if !strings.Contains(body, `<script type="module" nonce="`+m[1]+`">`) {
			t.Fatalf("the page's script does not carry the CSP's nonce:\n%s", body)
		}
		nonces[m[1]] = true
	}
	if len(nonces) != 2 {
		t.Error("the nonce did not change between responses")
	}

	// The app's files are revalidated by ETag.
	resp, _ := get(t, b, "http://"+domain+"/ui/app.html")
	etag := resp.Header.Get("ETag")
	if resp.StatusCode != http.StatusOK || etag == "" || resp.Header.Get("Cache-Control") != "no-cache" {
		t.Fatalf("app.html: %d %q %q", resp.StatusCode, etag, resp.Header.Get("Cache-Control"))
	}
	req, _ := http.NewRequest("GET", "http://"+domain+"/ui/app.html", nil)
	req.Header.Set("If-None-Match", etag)
	if resp, err := b.Do(req); err != nil || resp.StatusCode != http.StatusNotModified {
		t.Errorf("revalidation: %v %v", resp.StatusCode, err)
	}
	for _, f := range []string{"/ui/vendor/jq79.js", "/ui/lib/store.js", "/ui/views/login.html", "/ui/app.css"} {
		if resp, _ := get(t, b, "http://"+domain+f); resp.StatusCode != http.StatusOK {
			t.Errorf("%s: %d", f, resp.StatusCode)
		}
	}
	if resp, _ := get(t, b, "http://"+domain+"/ui/nope.js"); resp.StatusCode != http.StatusNotFound {
		t.Errorf("missing file: %d", resp.StatusCode)
	}
}

func TestDashboardManagesSubdomains(t *testing.T) {
	h := newHarness(t)
	b := h.browser(true)
	h.login(b, "alice@example.com")
	key := newSigner(t)
	pub := strings.TrimSpace(string(ssh.MarshalAuthorizedKey(key.PublicKey()))) + " alice@laptop"

	resp, body := call(t, b, "POST", "/api/subdomains", map[string]string{"name": "MyApp", "access": "private", "keys": pub})
	created := decode[struct {
		Subdomain api.Subdomain  `json:"subdomain"`
		Keys      api.KeysResult `json:"keys"`
	}](t, body)
	if resp.StatusCode != http.StatusCreated || created.Subdomain.Name != "myapp" || created.Subdomain.Keys != 1 || created.Keys.Added != 1 {
		t.Fatalf("create: %d %s", resp.StatusCode, body)
	}
	d, err := h.store.SubdomainByName(context.Background(), "myapp")
	if err != nil || d.Access != store.AccessPrivate || d.Keys != 1 {
		t.Fatalf("stored subdomain %+v, %v", d, err)
	}
	_, body = call(t, b, "GET", "/api/subdomains/myapp", nil)
	detail := decode[struct {
		api.SubdomainDetail
		SSHCommand string `json:"ssh_command"`
		Mine       bool   `json:"mine"`
	}](t, body)
	if len(detail.KeyList) != 1 || detail.KeyList[0].Name != "alice@laptop" || !detail.Mine || !strings.Contains(detail.SSHCommand, "-R myapp:80:localhost:3000") {
		t.Fatalf("detail: %s", body)
	}

	// Reserved and taken names are refused.
	if resp, body := call(t, b, "POST", "/api/subdomains", map[string]string{"name": "www"}); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "reserved") {
		t.Errorf("reserved name: %d %s", resp.StatusCode, body)
	}
	other := h.browser(true)
	h.login(other, "bob@example.com")
	if _, body := call(t, other, "POST", "/api/subdomains", map[string]string{"name": "myapp"}); !strings.Contains(body, "already taken") {
		t.Errorf("taken name accepted: %s", body)
	}
	// Other users can't see or change it.
	if resp, _ := call(t, other, "GET", "/api/subdomains/myapp", nil); resp.StatusCode != http.StatusNotFound {
		t.Errorf("other user sees subdomain: %d", resp.StatusCode)
	}
	if resp, _ := call(t, other, "PATCH", "/api/subdomains/myapp", map[string]string{"access": "public"}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("other user changes subdomain: %d", resp.StatusCode)
	}

	// Changes need the CSRF token and a same-origin Origin.
	_, boot := page(t, b, "/")
	if resp, _ := send(t, b, "PATCH", "/api/subdomains/myapp", map[string]string{"access": "public"}, ""); resp.StatusCode != http.StatusForbidden {
		t.Errorf("PATCH without CSRF token: %d", resp.StatusCode)
	}
	if resp, _ := send(t, b, "PATCH", "/api/subdomains/myapp", map[string]string{"access": "public"}, "wrong"); resp.StatusCode != http.StatusForbidden {
		t.Errorf("PATCH with a wrong CSRF token: %d", resp.StatusCode)
	}
	if resp, _ := sendFrom(t, b, "http://evil."+domain, "PATCH", "/api/subdomains/myapp", map[string]string{"access": "public"}, boot.CSRF); resp.StatusCode != http.StatusForbidden {
		t.Errorf("cross-origin PATCH: %d", resp.StatusCode)
	}
	if d, _ := h.store.SubdomainByName(context.Background(), "myapp"); d.Access != store.AccessPrivate {
		t.Fatal("a refused request changed the access")
	}

	// Connect: the list shows the tunnel. Then change access live and
	// remove the key.
	c, err := h.dial(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	c.forward(t, "myapp", 80, backend(t))
	_, body = call(t, b, "GET", "/api/subdomains", nil)
	list := decode[[]api.Subdomain](t, body)
	if len(list) != 1 || list[0].Tunnel == nil || list[0].Tunnel.KeyName != "alice@laptop" {
		t.Fatalf("list while connected: %s", body)
	}
	if resp, body := call(t, b, "PATCH", "/api/subdomains/myapp", map[string]string{"access": "public"}); resp.StatusCode != http.StatusOK || decode[api.Subdomain](t, body).Access != store.AccessPublic {
		t.Fatalf("set access: %d %s", resp.StatusCode, body)
	}
	if resp, _ := get(t, h.browser(false), "http://myapp."+domain+"/"); resp.StatusCode != http.StatusOK {
		t.Errorf("public after change: %d", resp.StatusCode)
	}
	if resp, body := call(t, b, "PATCH", "/api/subdomains/myapp", map[string]string{"access": "everyone"}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("invalid access: %d %s", resp.StatusCode, body)
	}
	// Renaming the key renames it on the live tunnel too.
	keyPath := fmt.Sprintf("/api/subdomains/myapp/keys/%d", detail.KeyList[0].ID)
	if resp, body := call(t, b, "PATCH", keyPath, map[string]string{"name": "  work laptop "}); resp.StatusCode != http.StatusOK || !strings.Contains(body, `"work laptop"`) {
		t.Errorf("rename key: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, b, "PATCH", keyPath, map[string]string{"name": " "}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("rename key to nothing: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, other, "PATCH", keyPath, map[string]string{"name": "mine"}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("other user renames key: %d", resp.StatusCode)
	}
	if tun := h.registry.Get("myapp"); tun == nil || tun.Stats().KeyName != "work laptop" {
		t.Errorf("live tunnel key name not updated")
	}
	if resp, _ := call(t, b, "DELETE", fmt.Sprintf("/api/subdomains/myapp/keys/%d", detail.KeyList[0].ID), nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("remove key: %d", resp.StatusCode)
	}
	waitFor(t, func() bool { return h.registry.Get("myapp") == nil })
	if _, err := h.dial(key, "alice"); err == nil {
		t.Error("removed key can still connect")
	}

	// Add a key back, then delete the subdomain.
	if resp, body := call(t, b, "POST", "/api/subdomains/myapp/keys", map[string]string{"keys": pub + "\nnot a key"}); resp.StatusCode != http.StatusBadRequest || !strings.Contains(body, "Line 2") {
		t.Errorf("add a bad key: %d %s", resp.StatusCode, body)
	}
	if resp, body := call(t, b, "POST", "/api/subdomains/myapp/keys", map[string]string{"keys": pub, "name": "again"}); resp.StatusCode != http.StatusOK || decode[api.KeysResult](t, body).Added != 1 {
		t.Errorf("add keys: %d %s", resp.StatusCode, body)
	}
	if resp, _ := call(t, b, "DELETE", "/api/subdomains/myapp", nil); resp.StatusCode != http.StatusNoContent {
		t.Errorf("delete: %d", resp.StatusCode)
	}
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
	if !strings.HasPrefix(handoff, "http://secret."+domain+"/__gate2sky/auth?") {
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
	// tunnel-auth only redirects to tunnels of this gate2sky.
	if resp, _ := get(t, noFollow, "http://"+domain+"/tunnel-auth?rd="+url.QueryEscape("http://evil.com/")); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("tunnel-auth to foreign host: %d", resp.StatusCode)
	}

	// Signing out of the dashboard also revokes tunnel access.
	call(t, owner, "POST", "/api/logout", nil)
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

	// Only administrators may, and not on themselves.
	if resp, _ := call(t, h.loggedIn("bob@example.com"), "PATCH", fmt.Sprintf("/api/admin/users/%d", alice.ID), map[string]bool{"disabled": true}); resp.StatusCode != http.StatusNotFound {
		t.Errorf("non-admin disables a user: %d", resp.StatusCode)
	}
	admin := h.loggedIn("admin@example.com")
	_, body := call(t, admin, "GET", "/api/admin/users", nil)
	var me int64
	for _, u := range decode[[]api.User](t, body) {
		if u.Email == "admin@example.com" {
			me = u.ID
		}
	}
	if resp, _ := call(t, admin, "PATCH", fmt.Sprintf("/api/admin/users/%d", me), map[string]bool{"disabled": true}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("admin disables themselves: %d", resp.StatusCode)
	}
	if resp, _ := call(t, admin, "PATCH", fmt.Sprintf("/api/admin/users/%d", alice.ID), map[string]bool{"disabled": true}); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("disable: %d", resp.StatusCode)
	}
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

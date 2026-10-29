package e2e

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gate2net/gate2net.github.io/internal/clientapp"
	"github.com/gate2net/gate2net.github.io/internal/store"
)

// writeKey makes a key and saves it as an OpenSSH private key file, for
// the app.
func writeKey(t *testing.T) (ssh.Signer, string) {
	t.Helper()
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	signer, _ := ssh.NewSignerFromKey(priv)
	path := filepath.Join(t.TempDir(), "id_ed25519")
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		t.Fatal(err)
	}
	return signer, path
}

func TestApp(t *testing.T) {
	first := freeRange(t, 2)
	h := newHarness(t, fmt.Sprintf("tcp:\n  ports: %d-%d\n  listen_host: 127.0.0.1", first, first+1))
	_, d, _ := h.setup("alice@example.com", "app", store.AccessPublic)
	signer, keyFile := writeKey(t)
	if _, err := h.store.AddKey(context.Background(), d.ID, "app key", signer.PublicKey()); err != nil {
		t.Fatal(err)
	}
	alice := h.loggedIn("alice@example.com")
	resp, b := call(t, alice, "POST", "/api/subdomains/app/ports", map[string]any{"name": "mc", "protocol": "udp", "local_port": 19132})
	if resp.StatusCode != http.StatusCreated {
		t.Fatalf("add port: %s", b)
	}

	app, err := clientapp.Open(filepath.Join(t.TempDir(), "gate2net", "app.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := app.Connect(); err == nil {
		t.Error("connected with no settings")
	}
	// The dashboard's address is enough to find the server.
	if err := app.Discover(context.Background(), "http://"+domain, h.browser(false)); err != nil {
		t.Fatal(err)
	}
	s := app.Settings()
	if s.Server != domain+":2222" || s.HostKey != ssh.FingerprintSHA256(h.srv.HostKey()) || s.Domain != domain {
		t.Fatalf("discovered %+v", s)
	}
	// The test's SSH server listens elsewhere than the configured port.
	s.Server = h.sshAddr
	s.Subdomain, s.KeyFile = " App ", keyFile
	s.Forwards = []clientapp.Forward{
		{Kind: "http", Local: backend(t).Listener.Addr().String()},
		{Kind: "udp", Name: "MC", Local: udpEcho(t)},
		{Kind: "tcp", Name: "nope", Local: "5432"},
	}
	if err := app.SetSettings(s); err != nil {
		t.Fatal(err)
	}
	if err := app.Connect(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(app.Disconnect)
	var st clientapp.State
	waitFor(t, func() bool {
		st = app.State()
		return st.Status == clientapp.Connected && st.Forwards[0].State == "open" && st.Forwards[1].State == "open" && st.Forwards[2].State == "refused"
	})
	if st.Forwards[0].Address != "http://app."+domain || !strings.HasPrefix(st.Forwards[1].Address, "udp://") {
		t.Errorf("addresses: %+v", st.Forwards)
	}
	if resp, body := get(t, h.browser(true), "http://app."+domain+"/"); resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "backend GET /") {
		t.Errorf("HTTP through the app: %d %s", resp.StatusCode, body)
	}
	var port int
	fmt.Sscanf(st.Forwards[1].Address[strings.LastIndex(st.Forwards[1].Address, ":")+1:], "%d", &port)
	if got := udpAsk(t, port, "hi"); got != "echo:hi" {
		t.Errorf("UDP through the app: %q", got)
	}
	if !strings.Contains(strings.Join(st.Log, "\n"), "is now forwarding") {
		t.Errorf("log: %v", st.Log)
	}
	app.Disconnect()
	if st := app.State(); st.Status != clientapp.Disconnected || st.Forwards[0].State != "pending" {
		t.Errorf("after disconnect: %s %+v", st.Status, st.Forwards)
	}
}

func TestAppUI(t *testing.T) {
	dir := t.TempDir()
	app, _ := clientapp.Open(filepath.Join(dir, "app.json"))
	ui, ln, err := clientapp.NewUI(app)
	if err != nil {
		t.Fatal(err)
	}
	shown := make(chan bool, 1)
	ui.Show = func() { shown <- true }
	go http.Serve(ln, ui)
	base := "http://" + ln.Addr().String()
	do := func(method, path, token, host string, body string) (int, string) {
		req, _ := http.NewRequest(method, base+path, strings.NewReader(body))
		if token != "" {
			req.Header.Set("X-Token", token)
		}
		if host != "" {
			req.Host = host
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatal(err)
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		return resp.StatusCode, string(b)
	}
	if code, _ := do("GET", "/api/state", "", "", ""); code != http.StatusForbidden {
		t.Errorf("no token: %d", code)
	}
	if code, _ := do("GET", "/api/state", ui.Token(), "evil.example:1234", ""); code != http.StatusForbidden {
		t.Errorf("another Host: %d", code)
	}
	if code, page := do("GET", "/?t="+ui.Token(), "", "", ""); code != http.StatusOK || !strings.Contains(page, `const TOKEN = "`+ui.Token()+`"`) {
		t.Errorf("page: %d", code)
	}
	if code, _ := do("POST", "/api/connect?t="+ui.Token(), "", "", ""); code != http.StatusForbidden {
		t.Errorf("a change without the header: %d", code)
	}
	code, body := do("PUT", "/api/settings", ui.Token(), "", `{"subdomain":"Demo","forwards":[{"kind":"tcp","name":"db","local":"5432"}]}`)
	var st clientapp.State
	json.Unmarshal([]byte(body), &st)
	if code != http.StatusOK || st.Settings.Subdomain != "demo" {
		t.Errorf("settings: %d %s", code, body)
	}
	if code, body := do("POST", "/api/connect", ui.Token(), "", ""); code != http.StatusBadRequest || !strings.Contains(body, "look it up") {
		t.Errorf("connect without a server: %d %s", code, body)
	}
	if b, err := os.ReadFile(filepath.Join(dir, "app.json")); err != nil || !strings.Contains(string(b), `"subdomain": "demo"`) {
		t.Errorf("saved: %s %v", b, err)
	}

	// A second start shows this instance's window.
	lock := filepath.Join(dir, "app.instance")
	unpublish, _ := ui.Publish(lock)
	if !clientapp.ShowRunning(lock) {
		t.Error("ShowRunning found no instance")
	}
	select {
	case <-shown:
	case <-time.After(time.Second):
		t.Error("window not shown")
	}
	unpublish()
	if clientapp.ShowRunning(lock) {
		t.Error("ShowRunning after the instance left")
	}
}

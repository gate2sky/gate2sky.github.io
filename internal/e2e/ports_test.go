package e2e

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gate2net/gate2net.github.io/internal/api"
	"github.com/gate2net/gate2net.github.io/internal/store"
)

// freeRange finds n consecutive ports nobody listens on, for tcp.ports.
func freeRange(t *testing.T, n int) int {
	t.Helper()
	for range 50 {
		ln, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		first := ln.Addr().(*net.TCPAddr).Port
		ln.Close()
		if first+n > 65535 {
			continue
		}
		ok := true
		for p := first; p < first+n && ok; p++ {
			l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", p))
			if err != nil {
				ok = false
				continue
			}
			l.Close()
		}
		if ok {
			return first
		}
	}
	t.Fatal("no free port range")
	return 0
}

// remoteForward asks for `ssh -R bind:port:...` and returns whether the
// server accepted, and the port it allocated when port is 0.
func (c *sshClient) remoteForward(t *testing.T, bind string, port uint32) (bool, uint32) {
	t.Helper()
	ok, reply, err := c.SendRequest("tcpip-forward", true, ssh.Marshal(struct {
		Addr string
		Port uint32
	}{bind, port}))
	if err != nil {
		t.Fatal(err)
	}
	var allocated struct{ Port uint32 }
	if ok && port == 0 {
		if err := ssh.Unmarshal(reply, &allocated); err != nil {
			t.Fatalf("forward reply: %v", err)
		}
	}
	return ok, allocated.Port
}

// echoStreams answers every forwarded stream with a line naming the
// forward it came for, then echoes, like a local service behind ssh -R.
func echoStreams(chans <-chan ssh.NewChannel) {
	for nch := range chans {
		var p struct {
			Addr       string
			Port       uint32
			OriginAddr string
			OriginPort uint32
		}
		ssh.Unmarshal(nch.ExtraData(), &p)
		ch, reqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go ssh.DiscardRequests(reqs)
		go func() {
			defer ch.Close()
			fmt.Fprintf(ch, "%s:%d from %s\n", p.Addr, p.Port, p.OriginAddr)
			io.Copy(ch, ch)
		}()
	}
}

// visit connects to a public port, says hello and returns what came back:
// the forward's line and the echo, or "" when the port refused.
func visit(t *testing.T, port uint32) string {
	t.Helper()
	c, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 2*time.Second)
	if err != nil {
		return ""
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprintf(c, "hello\n")
	r := bufio.NewReader(c)
	first, err := r.ReadString('\n')
	if err != nil {
		return ""
	}
	echo, _ := r.ReadString('\n')
	return strings.TrimSpace(first) + " | " + strings.TrimSpace(echo)
}

func TestTCPPorts(t *testing.T) {
	first := freeRange(t, 3)
	h := newHarness(t, fmt.Sprintf("tcp:\n  ports: %d-%d\n  max_ports: 2\n  listen_host: 127.0.0.1\n  public_host: tcp.test", first, first+2))
	_, _, key := h.setup("alice@example.com", "app", store.AccessPrivate)
	h.setup("bob@example.com", "other", store.AccessPublic)
	alice := h.loggedIn("alice@example.com")
	bob := h.loggedIn("bob@example.com")

	add := func(c *http.Client, sub string, body map[string]any) (int, api.Port) {
		t.Helper()
		resp, b := call(t, c, "POST", "/api/subdomains/"+sub+"/ports", body)
		var p api.Port
		if resp.StatusCode == http.StatusCreated {
			p = decode[api.Port](t, b)
		}
		return resp.StatusCode, p
	}
	code, db := add(alice, "app", map[string]any{"name": "DB", "preset": "postgresql", "local_port": 5432})
	if code != http.StatusCreated || db.Name != "db" || db.Port != first || db.Address != fmt.Sprintf("tcp://tcp.test:%d", first) || len(db.Allow) != 0 {
		t.Fatalf("add db: %d %+v", code, db)
	}
	_, shell := add(alice, "app", map[string]any{"name": "ssh", "local_port": 22, "allow": []string{"192.0.2.1", "10.0.0.0/8"}})
	_, other := add(bob, "other", map[string]any{"name": "db", "local_port": 5432})
	for _, bad := range []map[string]any{
		{"name": "db", "local_port": 1},                         // limit of 2 per subdomain
		{"name": "x", "local_port": 1, "protocol": "sctp"},      // unknown protocol
		{"name": "bad name", "local_port": 1},                   // not a label
		{"name": "x", "local_port": 0},                          // no local port
		{"name": "x", "local_port": 1, "allow": []string{"me"}}, // not an address
	} {
		if code, _ := add(alice, "app", bad); code != http.StatusBadRequest {
			t.Errorf("add %v: %d", bad, code)
		}
	}
	if code, _ := add(bob, "app", map[string]any{"name": "x", "local_port": 1}); code != http.StatusNotFound {
		t.Errorf("bob adds a port to alice's subdomain: %d", code)
	}

	c, err := h.dial(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	go echoStreams(c.forwards)

	// By name with port 0: the server answers with the public port.
	ok, got := c.remoteForward(t, "db.app", 0)
	if !ok || got != uint32(db.Port) {
		t.Fatalf("forward db.app:0 = %v, %d", ok, got)
	}
	if v := visit(t, uint32(db.Port)); v != fmt.Sprintf("db.app:%d from 127.0.0.1 | hello", db.Port) {
		t.Errorf("visit db: %q", v)
	}
	// By public number, without the subdomain. The allow list keeps
	// 127.0.0.1 out until it is added.
	if ok, _ := c.remoteForward(t, "", uint32(shell.Port)); !ok {
		t.Fatal("forward by public port refused")
	}
	if v := visit(t, uint32(shell.Port)); v != "" {
		t.Errorf("visit from outside the allow list: %q", v)
	}
	resp, b := call(t, alice, "PATCH", fmt.Sprintf("/api/subdomains/app/ports/%d", shell.ID), map[string]any{"name": "shell", "local_port": 2222, "allow": []string{"127.0.0.1"}})
	if p := decode[api.Port](t, b); resp.StatusCode != http.StatusOK || p.Name != "shell" || p.Allow[0] != "127.0.0.1" || p.Forward == nil {
		t.Fatalf("update: %d %s", resp.StatusCode, b)
	}
	if v := visit(t, uint32(shell.Port)); !strings.HasSuffix(v, "| hello") {
		t.Errorf("visit after allowing: %q", v)
	}

	// Forwards that don't name a port of the key's subdomains.
	for _, f := range []struct {
		bind string
		port uint32
	}{
		{"nope.app", 0},                 // no such port
		{"db.app", uint32(db.Port) + 1}, // wrong number for db
		{"app", uint32(other.Port)},     // bob's port
		{"", uint32(other.Port)},        // bob's port, by number only
		{"db.app", 80},                  // a port over HTTP
		{"x.y.app", 0},                  // not a port name
		{"app", uint32(first + 10)},     // outside the range
		{"db.other", 0},                 // a subdomain the key can't use
	} {
		if ok, _ := c.remoteForward(t, f.bind, f.port); ok {
			t.Errorf("forward %s:%d accepted", f.bind, f.port)
		}
	}

	// The dashboard shows them online, with the command that opens them.
	_, b = call(t, alice, "GET", "/api/subdomains/app", nil)
	detail := decode[struct {
		api.SubdomainDetail
		PortsCommand string `json:"ports_command"`
		ClientIP     string `json:"client_ip"`
	}](t, b)
	if len(detail.PortList) != 2 || detail.PortsOnline != 2 || detail.PortList[0].Forward == nil || detail.PortList[0].Forward.Connections != 1 {
		t.Errorf("detail: %+v", detail.SubdomainDetail)
	}
	if !strings.Contains(detail.PortsCommand, "-R db.app:0:localhost:5432 -R shell.app:0:localhost:2222 ") || detail.ClientIP != "127.0.0.1" {
		t.Errorf("command %q, client ip %q", detail.PortsCommand, detail.ClientIP)
	}

	// Deleting a port closes it; disconnecting closes the rest, and then
	// the connection, which has nothing left to do.
	if resp, _ := call(t, alice, "DELETE", fmt.Sprintf("/api/subdomains/app/ports/%d", shell.ID), nil); resp.StatusCode != http.StatusNoContent {
		t.Fatalf("delete: %d", resp.StatusCode)
	}
	waitFor(t, func() bool { return h.srv.Ports().Get(shell.Port) == nil })
	if v := visit(t, uint32(shell.Port)); v != "" {
		t.Errorf("deleted port still answers: %q", v)
	}
	if resp, _ := call(t, alice, "POST", "/api/subdomains/app/disconnect", nil); resp.StatusCode != http.StatusOK {
		t.Fatalf("disconnect: %d", resp.StatusCode)
	}
	waitFor(t, func() bool { return h.srv.Ports().Get(db.Port) == nil })
	done := make(chan error, 1)
	go func() { done <- c.Wait() }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Error("connection still open without forwards")
	}

	// The freed number is reused by the next port.
	if code, p := add(alice, "app", map[string]any{"name": "redis", "local_port": 6379}); code != http.StatusCreated || p.Port != shell.Port {
		t.Errorf("reuse: %d %+v", code, p)
	}
}

func TestTCPPortsDisabled(t *testing.T) {
	h := newHarness(t)
	_, _, key := h.setup("alice@example.com", "app", store.AccessPublic)
	if resp, _ := call(t, h.loggedIn("alice@example.com"), "POST", "/api/subdomains/app/ports", map[string]any{"name": "db", "local_port": 5432}); resp.StatusCode != http.StatusBadRequest {
		t.Errorf("add port without tcp.ports: %d", resp.StatusCode)
	}
	c, err := h.dial(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.remoteForward(t, "db.app", 0); ok {
		t.Error("TCP forward accepted without tcp.ports")
	}
	if ok, _ := c.remoteForward(t, "app", 0); !ok {
		t.Error("-R app:0 no longer opens the HTTP tunnel")
	}
}

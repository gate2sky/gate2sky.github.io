package e2e

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/api"
	"github.com/jgermade/intergate/internal/client"
	"github.com/jgermade/intergate/internal/store"
)

// udpEcho answers every datagram with "echo:" and the datagram.
func udpEcho(t *testing.T) string {
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { pc.Close() })
	go func() {
		buf := make([]byte, 65535)
		for {
			n, addr, err := pc.ReadFrom(buf)
			if err != nil {
				return
			}
			pc.WriteTo(append([]byte("echo:"), buf[:n]...), addr)
		}
	}()
	return pc.LocalAddr().String()
}

// tcpEcho echoes every connection.
func tcpEcho(t *testing.T) string {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				io.Copy(c, c)
			}()
		}
	}()
	return ln.Addr().String()
}

// udpAsk sends msg to a public UDP port and returns the answer, or "".
func udpAsk(t *testing.T, port int, msg string) string {
	t.Helper()
	c, err := net.Dial("udp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	buf := make([]byte, 1024)
	// The first datagram may wait for the stream to the client to open.
	for range 3 {
		c.Write([]byte(msg))
		c.SetReadDeadline(time.Now().Add(700 * time.Millisecond))
		if n, err := c.Read(buf); err == nil {
			return string(buf[:n])
		}
	}
	return ""
}

// syncBuffer collects the client's output.
type syncBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (s *syncBuffer) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.Write(p)
}

func (s *syncBuffer) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.b.String()
}

func TestClientForwardsHTTPTCPAndUDP(t *testing.T) {
	first := freeRange(t, 4)
	h := newHarness(t, fmt.Sprintf("tcp:\n  ports: %d-%d\n  listen_host: 127.0.0.1", first, first+3))
	_, _, key := h.setup("alice@example.com", "app", store.AccessPublic)
	alice := h.loggedIn("alice@example.com")
	add := func(body map[string]any) api.Port {
		t.Helper()
		resp, b := call(t, alice, "POST", "/api/subdomains/app/ports", body)
		if resp.StatusCode != http.StatusCreated {
			t.Fatalf("add %v: %d %s", body, resp.StatusCode, b)
		}
		return decode[api.Port](t, b)
	}
	db := add(map[string]any{"name": "db", "local_port": 5432})
	mc := add(map[string]any{"name": "mc", "protocol": "udp", "preset": "minecraft-bedrock", "local_port": 19132})
	closed := add(map[string]any{"name": "dns", "protocol": "udp", "local_port": 53, "allow": []string{"192.0.2.1"}})

	// Plain ssh -R can't forward a UDP port.
	c, err := h.dial(key, "alice")
	if err != nil {
		t.Fatal(err)
	}
	if ok, _ := c.remoteForward(t, "mc.app", 0); ok {
		t.Error("tcpip-forward accepted for a UDP port")
	}
	c.Close()

	out := &syncBuffer{}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() {
		done <- client.Run(ctx, client.Options{
			Server:    h.sshAddr,
			Subdomain: "app",
			Forwards: []client.Forward{
				{Kind: client.HTTP, Local: backend(t).Listener.Addr().String()},
				{Kind: client.TCP, Name: "db", Local: tcpEcho(t)},
				{Kind: client.UDP, Name: "mc", Local: udpEcho(t)},
				{Kind: client.UDP, Name: "dns", Local: udpEcho(t)},
			},
			Auth:    []ssh.AuthMethod{ssh.PublicKeys(key)},
			HostKey: ssh.InsecureIgnoreHostKey(),
			Out:     out,
		})
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	waitFor(t, func() bool { return h.srv.Ports().Get(closed.Port) != nil })

	if resp, body := get(t, h.browser(true), "http://app."+domain+"/x"); resp.StatusCode != http.StatusOK || !strings.HasPrefix(body, "backend GET /x") {
		t.Errorf("HTTP: %d %s", resp.StatusCode, body)
	}
	tc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", db.Port))
	if err != nil {
		t.Fatal(err)
	}
	tc.SetDeadline(time.Now().Add(3 * time.Second))
	fmt.Fprint(tc, "ping")
	buf := make([]byte, 4)
	if _, err := io.ReadFull(tc, buf); err != nil || string(buf) != "ping" {
		t.Errorf("TCP: %q %v", buf, err)
	}
	tc.Close()
	if got := udpAsk(t, mc.Port, "hello"); got != "echo:hello" {
		t.Errorf("UDP: %q", got)
	}
	if got := udpAsk(t, closed.Port, "hello"); got != "" {
		t.Errorf("UDP from outside the allow list answered: %q", got)
	}
	for _, want := range []string{"udp://", "(mc.app) is now forwarding", "(db.app) is now forwarding", "http://app." + domain} {
		if !strings.Contains(out.String(), want) {
			t.Errorf("client output lacks %q:\n%s", want, out.String())
		}
	}

	// Disconnected from the dashboard, the client comes back on its own.
	call(t, alice, "POST", "/api/subdomains/app/disconnect", nil)
	waitFor(t, func() bool { return h.srv.Ports().Get(mc.Port) == nil })
	deadline := time.Now().Add(10 * time.Second)
	for h.srv.Ports().Get(mc.Port) == nil && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if got := udpAsk(t, mc.Port, "again"); got != "echo:again" {
		t.Errorf("UDP after reconnecting: %q\n%s", got, out.String())
	}
}

func TestClientRefusedForwards(t *testing.T) {
	h := newHarness(t)
	_, _, key := h.setup("alice@example.com", "app", store.AccessPublic)
	err := client.Run(context.Background(), client.Options{
		Server:    h.sshAddr,
		Subdomain: "app",
		Forwards:  []client.Forward{{Kind: client.UDP, Name: "mc", Local: "localhost:1"}},
		Auth:      []ssh.AuthMethod{ssh.PublicKeys(key)},
		HostKey:   ssh.InsecureIgnoreHostKey(),
		Out:       io.Discard,
	})
	if err != client.ErrRejected {
		t.Errorf("Run = %v, want ErrRejected", err)
	}
	err = client.Run(context.Background(), client.Options{
		Server:    h.sshAddr,
		Subdomain: "app",
		Forwards:  []client.Forward{{Kind: client.HTTP, Local: "localhost:1"}},
		Auth:      []ssh.AuthMethod{ssh.PublicKeys(newSigner(t))},
		HostKey:   ssh.InsecureIgnoreHostKey(),
		Out:       io.Discard,
	})
	if err == nil || !strings.Contains(err.Error(), "unable to authenticate") {
		t.Errorf("unknown key: %v", err)
	}
}

package sshd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/securegate/internal/tunnel"
)

// clientConn is one authenticated SSH connection.
type clientConn struct {
	srv         *Server
	conn        *ssh.ServerConn
	fingerprint string
	publicKey   string
	console     *console
	log         *slog.Logger
	done        chan struct{}

	mu       sync.Mutex
	forwards map[string]*tunnel.Tunnel // by bind address and port
	closing  bool
}

// RFC 4254 section 7.1.
type forwardRequest struct {
	BindAddr string
	BindPort uint32
}

// RFC 4254 section 7.2.
type forwardedTCPPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func (c *clientConn) handleGlobalRequests(reqs <-chan *ssh.Request) {
	for req := range reqs {
		switch req.Type {
		case "tcpip-forward":
			c.handleForward(req)
		case "cancel-tcpip-forward":
			c.handleCancel(req)
		default:
			req.Reply(false, nil)
		}
	}
}

func forwardKey(addr string, port uint32) string {
	return net.JoinHostPort(addr, strconv.FormatUint(uint64(port), 10))
}

// effectivePort is the port a forward is served as. Port 0 asks the server
// to choose; HTTP tunnels always answer 80.
func effectivePort(p uint32) uint32 {
	if p == 0 {
		return 80
	}
	return p
}

func (c *clientConn) handleForward(req *ssh.Request) {
	var fr forwardRequest
	if err := ssh.Unmarshal(req.Payload, &fr); err != nil {
		req.Reply(false, nil)
		return
	}
	t, err := c.openTunnel(fr)
	if err != nil {
		c.log.Info("forward rejected", "bind", forwardKey(fr.BindAddr, fr.BindPort), "err", err)
		c.console.Printf("✖ cannot forward %s: %v", forwardKey(fr.BindAddr, fr.BindPort), err)
		req.Reply(false, nil)
		return
	}
	var reply []byte
	if fr.BindPort == 0 {
		reply = ssh.Marshal(struct{ Port uint32 }{effectivePort(0)})
	}
	req.Reply(true, reply)

	cfg := c.srv.cfg
	c.log.Info("tunnel opened", "subdomain", t.Subdomain, "key", t.KeyName)
	c.console.Printf("✔ %s is now forwarding to this connection", cfg.TunnelURL(t.Subdomain))
	c.console.Printf("  access: %s — manage it at %s", t.Access(), cfg.DashboardURL("/subdomains/"+t.Subdomain))
}

func (c *clientConn) openTunnel(fr forwardRequest) (*tunnel.Tunnel, error) {
	switch fr.BindPort {
	case 0, 80, 443:
	default:
		return nil, fmt.Errorf("only HTTP tunnels are supported; use port 80, e.g. -R myapp:80:localhost:%d", fr.BindPort)
	}
	requested, err := c.srv.subdomainFromBind(fr.BindAddr)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	grants, err := c.srv.grants(ctx, c.fingerprint, c.publicKey)
	if err != nil {
		c.log.Error("load grants", "err", err)
		return nil, errors.New("internal error, please retry")
	}
	g, err := pickGrant(grants, requested, c.conn.User())
	if err != nil {
		return nil, err
	}

	port := effectivePort(fr.BindPort)
	key := forwardKey(fr.BindAddr, port)
	c.mu.Lock()
	switch {
	case c.closing:
		err = errors.New("connection is closing")
	case c.forwards[key] != nil:
		err = errors.New("already forwarding this address")
	case len(c.forwards) >= c.srv.cfg.Limits.TunnelsPerConnection:
		err = fmt.Errorf("at most %d tunnels per connection", c.srv.cfg.Limits.TunnelsPerConnection)
	}
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}

	var t *tunnel.Tunnel
	t = tunnel.New(tunnel.Options{
		Subdomain:     g.Subdomain,
		SubdomainID:   g.SubdomainID,
		OwnerID:       g.OwnerID,
		Access:        g.Access,
		KeyID:         g.KeyID,
		KeyName:       g.KeyName,
		ClientAddr:    c.conn.RemoteAddr().String(),
		ClientVersion: string(c.conn.ClientVersion()),
		Dial:          c.dialer(fr.BindAddr, port),
		Logf:          c.console.Printf,
		OnClose:       func(reason string) { c.tunnelClosed(key, t, reason) },
	})
	c.mu.Lock()
	c.forwards[key] = t
	c.mu.Unlock()
	c.srv.registry.Add(t)

	if err := c.srv.store.TouchKey(ctx, g.KeyID); err != nil {
		c.log.Warn("record key use", "err", err)
	}
	return t, nil
}

// tunnelClosed runs when a tunnel is closed from outside this connection:
// replaced by another client, disconnected from the dashboard, or its key
// was revoked. Without tunnels left, the connection has no purpose.
func (c *clientConn) tunnelClosed(key string, t *tunnel.Tunnel, reason string) {
	c.mu.Lock()
	owned := c.forwards[key] == t
	if owned {
		delete(c.forwards, key)
	}
	remaining, closing := len(c.forwards), c.closing
	c.mu.Unlock()
	if !owned || closing {
		return
	}
	c.log.Info("tunnel closed", "subdomain", t.Subdomain, "reason", reason)
	c.console.Printf("✖ %s closed: %s", c.srv.cfg.TunnelURL(t.Subdomain), reason)
	if remaining == 0 {
		// Give the console a moment to deliver the message.
		time.AfterFunc(time.Second, func() { c.conn.Close() })
	}
}

func (c *clientConn) handleCancel(req *ssh.Request) {
	var fr forwardRequest
	if err := ssh.Unmarshal(req.Payload, &fr); err != nil {
		req.Reply(false, nil)
		return
	}
	key := forwardKey(fr.BindAddr, effectivePort(fr.BindPort))
	c.mu.Lock()
	t := c.forwards[key]
	delete(c.forwards, key)
	c.mu.Unlock()
	if t == nil {
		req.Reply(false, nil)
		return
	}
	t.Close("cancelled by client")
	c.log.Info("tunnel cancelled", "subdomain", t.Subdomain)
	req.Reply(true, nil)
}

// closeAll closes every tunnel of this connection once it has ended.
func (c *clientConn) closeAll() {
	c.mu.Lock()
	c.closing = true
	ts := make([]*tunnel.Tunnel, 0, len(c.forwards))
	for _, t := range c.forwards {
		ts = append(ts, t)
	}
	c.forwards = map[string]*tunnel.Tunnel{}
	c.mu.Unlock()
	for _, t := range ts {
		t.Close("client disconnected")
		c.log.Info("tunnel closed", "subdomain", t.Subdomain)
	}
}

// dialer opens forwarded-tcpip channels back to the client. bindAddr and
// port must echo the forward request so the client can match it.
func (c *clientConn) dialer(bindAddr string, port uint32) tunnel.DialFunc {
	return func(ctx context.Context, origin string) (net.Conn, error) {
		p := forwardedTCPPayload{Addr: bindAddr, Port: port, OriginAddr: "0.0.0.0"}
		if host, sport, err := net.SplitHostPort(origin); err == nil {
			op, _ := strconv.ParseUint(sport, 10, 16)
			p.OriginAddr, p.OriginPort = host, uint32(op)
		}
		type result struct {
			ch   ssh.Channel
			reqs <-chan *ssh.Request
			err  error
		}
		res := make(chan result, 1)
		go func() {
			ch, reqs, err := c.conn.OpenChannel("forwarded-tcpip", ssh.Marshal(p))
			res <- result{ch, reqs, err}
		}()
		select {
		case r := <-res:
			if r.err != nil {
				return nil, r.err
			}
			go ssh.DiscardRequests(r.reqs)
			return &channelConn{Channel: r.ch, local: c.conn.LocalAddr(), remote: c.conn.RemoteAddr()}, nil
		case <-ctx.Done():
			go func() {
				if r := <-res; r.err == nil {
					go ssh.DiscardRequests(r.reqs)
					r.ch.Close()
				}
			}()
			return nil, ctx.Err()
		}
	}
}

func (c *clientConn) handleChannels(chans <-chan ssh.NewChannel) {
	for nch := range chans {
		if nch.ChannelType() != "session" {
			// Notably direct-tcpip (ssh -L): clients must never reach the
			// server's own network.
			nch.Reject(ssh.Prohibited, "securegate only supports remote forwarding (ssh -R)")
			continue
		}
		ch, reqs, err := nch.Accept()
		if err != nil {
			continue
		}
		go c.handleSession(ch, reqs)
	}
}

func (c *clientConn) handleSession(ch ssh.Channel, reqs <-chan *ssh.Request) {
	defer ch.Close()
	pty := false
	for req := range reqs {
		switch req.Type {
		case "pty-req":
			pty = true
			req.Reply(true, nil)
		case "shell", "exec":
			req.Reply(true, nil)
			welcome := fmt.Sprintf("securegate: connected with key %s\r\n", c.fingerprint)
			if req.Type == "exec" {
				welcome += "securegate: commands are not supported; manage your subdomains at " + c.srv.cfg.DashboardURL("/") + "\r\n"
			}
			if pty {
				welcome += "securegate: press Ctrl-C to close the connection\r\n"
			}
			c.console.Attach(ch, welcome)
			go c.readInput(ch, pty)
		case "env", "window-change":
			req.Reply(true, nil)
		default:
			req.Reply(false, nil)
		}
	}
}

// readInput closes the connection on Ctrl-C or Ctrl-D in interactive
// sessions and discards everything else.
func (c *clientConn) readInput(ch ssh.Channel, pty bool) {
	buf := make([]byte, 256)
	for {
		n, err := ch.Read(buf)
		for _, b := range buf[:n] {
			if pty && (b == 0x03 || b == 0x04) {
				c.conn.Close()
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// keepalive drops connections whose client stopped answering.
func (c *clientConn) keepalive(interval time.Duration) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
		case <-c.done:
			return
		}
		errc := make(chan error, 1)
		go func() {
			_, _, err := c.conn.SendRequest("keepalive@openssh.com", true, nil)
			errc <- err
		}()
		select {
		case err := <-errc:
			if err != nil {
				c.conn.Close()
				return
			}
		case <-time.After(interval):
			c.log.Info("ssh keepalive timed out")
			c.conn.Close()
			return
		case <-c.done:
			return
		}
	}
}

// channelConn adapts an SSH channel to net.Conn for http.Transport.
// Deadlines are not supported by SSH channels and are ignored; requests are
// bounded by their context instead.
type channelConn struct {
	ssh.Channel
	local, remote net.Addr
}

func (c *channelConn) LocalAddr() net.Addr              { return c.local }
func (c *channelConn) RemoteAddr() net.Addr             { return c.remote }
func (c *channelConn) SetDeadline(time.Time) error      { return nil }
func (c *channelConn) SetReadDeadline(time.Time) error  { return nil }
func (c *channelConn) SetWriteDeadline(time.Time) error { return nil }

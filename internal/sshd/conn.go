package sshd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gate2sky/gate2sky.github.io/internal/ports"
	"github.com/gate2sky/gate2sky.github.io/internal/store"
	"github.com/gate2sky/gate2sky.github.io/internal/tunnel"
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
	forwards map[string]*tunnel.Tunnel // HTTP, by bind address and port
	ports    map[string]*ports.Forward // TCP, by bind address and public port
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
	reject := func(err error) {
		c.log.Info("forward rejected", "bind", forwardKey(fr.BindAddr, fr.BindPort), "err", err)
		c.console.Printf("✖ cannot forward %s: %v", forwardKey(fr.BindAddr, fr.BindPort), err)
		req.Reply(false, nil)
	}
	portName, requested, err := c.srv.parseBind(fr.BindAddr)
	if err != nil {
		reject(err)
		return
	}
	if portName != "" || !isHTTPPort(fr.BindPort) {
		f, err := c.openPort(fr, portName, requested)
		if err != nil {
			reject(err)
			return
		}
		var reply []byte
		if fr.BindPort == 0 {
			// OpenSSH prints "Allocated port N for remote forward".
			reply = ssh.Marshal(struct{ Port uint32 }{uint32(f.Port.Port)})
		}
		req.Reply(true, reply)
		cfg := c.srv.cfg
		c.log.Info("port opened", "subdomain", f.Port.Subdomain, "port", f.Port.Port, "name", f.Port.Name, "key", f.KeyName)
		c.console.Printf("✔ %s (%s.%s) is now forwarding to this connection", f.Address, f.Port.Name, f.Port.Subdomain)
		c.console.Printf("  access: %s — manage it at %s", describeAllow(f.Port.Allow), cfg.DashboardURL("/subdomains/"+f.Port.Subdomain))
		return
	}
	t, err := c.openTunnel(fr, requested)
	if err != nil {
		reject(err)
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

// isHTTPPort reports whether a forward to port is an HTTP tunnel, unless
// its bind address names a TCP port.
func isHTTPPort(p uint32) bool { return p == 0 || p == 80 || p == 443 }

func describeAllow(allow []string) string {
	if len(allow) == 0 {
		return "anyone"
	}
	return "only " + strings.Join(allow, ", ")
}

// reserve checks that the connection can take one more forward under key.
func (c *clientConn) reserve(key string) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	switch {
	case c.closing:
		return errors.New("connection is closing")
	case c.forwards[key] != nil || c.ports[key] != nil:
		return errors.New("already forwarding this address")
	case len(c.forwards)+len(c.ports) >= c.srv.cfg.Limits.TunnelsPerConnection:
		return fmt.Errorf("at most %d tunnels per connection", c.srv.cfg.Limits.TunnelsPerConnection)
	}
	return nil
}

func (c *clientConn) loadGrants(ctx context.Context) ([]store.Grant, error) {
	grants, err := c.srv.grants(ctx, c.fingerprint, c.publicKey)
	if err != nil {
		c.log.Error("load grants", "err", err)
		return nil, errors.New("internal error, please retry")
	}
	return grants, nil
}

func (c *clientConn) openTunnel(fr forwardRequest, requested string) (*tunnel.Tunnel, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	grants, err := c.loadGrants(ctx)
	if err != nil {
		return nil, err
	}
	g, err := pickGrant(grants, requested, c.conn.User())
	if err != nil {
		return nil, err
	}

	port := effectivePort(fr.BindPort)
	key := forwardKey(fr.BindAddr, port)
	if err := c.reserve(key); err != nil {
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

// openPort starts forwarding one of a subdomain's TCP ports, named in the
// bind address (db.myapp, port 0 or its public number) or given by its
// public number (myapp:30042, or without the subdomain).
func (c *clientConn) openPort(fr forwardRequest, name, requested string) (*ports.Forward, error) {
	cfg := c.srv.cfg
	if !cfg.TCP.Enabled() {
		return nil, fmt.Errorf("this server only has HTTP tunnels; use port 80, e.g. -R %s:80:localhost:3000", orName(requested, "myapp"))
	}
	if name != "" && (fr.BindPort == 80 || fr.BindPort == 443) {
		return nil, fmt.Errorf("%s names a TCP port; use port 0, e.g. -R %s:0:localhost:<port>", fr.BindAddr, fr.BindAddr)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	grants, err := c.loadGrants(ctx)
	if err != nil {
		return nil, err
	}

	var p *store.Port
	var g store.Grant
	if requested == "" {
		// -R 30042:localhost:5432: the port says which subdomain.
		p, err = c.srv.store.PortByNumber(ctx, int(fr.BindPort))
		if errors.Is(err, store.ErrNotFound) {
			return nil, fmt.Errorf("port %d is not a TCP port of your subdomains", fr.BindPort)
		}
		if err != nil {
			c.log.Error("load port", "err", err)
			return nil, errors.New("internal error, please retry")
		}
		found := false
		for _, gr := range grants {
			if gr.SubdomainID == p.SubdomainID {
				g, found = gr, true
			}
		}
		if !found {
			return nil, fmt.Errorf("port %d is not a TCP port of your subdomains", fr.BindPort)
		}
	} else {
		if g, err = pickGrant(grants, requested, c.conn.User()); err != nil {
			return nil, err
		}
		list, err := c.srv.store.PortsBySubdomain(ctx, g.SubdomainID)
		if err != nil {
			c.log.Error("load ports", "err", err)
			return nil, errors.New("internal error, please retry")
		}
		for _, q := range list {
			if (name != "" && q.Name == name) || (name == "" && q.Port == int(fr.BindPort)) {
				p = q
			}
		}
		switch {
		case p == nil && name != "":
			return nil, fmt.Errorf("%s has no TCP port named %q; add it at %s", g.Subdomain, name, cfg.DashboardURL("/subdomains/"+g.Subdomain))
		case p == nil:
			return nil, fmt.Errorf("port %d is not a TCP port of %s; add one at %s", fr.BindPort, g.Subdomain, cfg.DashboardURL("/subdomains/"+g.Subdomain))
		case fr.BindPort != 0 && p.Port != int(fr.BindPort):
			return nil, fmt.Errorf("%s.%s is port %d, not %d; use -R %s.%s:0:localhost:<port>", p.Name, g.Subdomain, p.Port, fr.BindPort, p.Name, g.Subdomain)
		}
	}
	switch {
	case p.Protocol != store.ProtocolTCP:
		return nil, fmt.Errorf("%s.%s is a %s port, which plain ssh can't forward", p.Name, p.Subdomain, strings.ToUpper(string(p.Protocol)))
	case !cfg.TCP.InRange(p.Port):
		return nil, fmt.Errorf("port %d is outside the server's TCP range (%s)", p.Port, cfg.TCP.Ports)
	}

	// The client matches incoming streams by what it asked for, so they
	// echo its bind address and the port it was told.
	key := forwardKey(fr.BindAddr, uint32(p.Port))
	if err := c.reserve(key); err != nil {
		return nil, err
	}
	var f *ports.Forward
	f, err = c.srv.ports.Open(ports.Options{
		Port:          *p,
		Address:       cfg.TCPAddress(p.Port),
		KeyID:         g.KeyID,
		KeyName:       g.KeyName,
		ClientAddr:    c.conn.RemoteAddr().String(),
		ClientVersion: string(c.conn.ClientVersion()),
		Dial:          c.dialer(fr.BindAddr, uint32(p.Port)),
		Logf:          c.console.Printf,
		OnClose:       func(reason string) { c.portClosed(key, f, reason) },
	})
	if err != nil {
		return nil, err
	}
	c.mu.Lock()
	if c.closing {
		c.mu.Unlock()
		f.Close("client disconnected")
		return nil, errors.New("connection is closing")
	}
	c.ports[key] = f
	c.mu.Unlock()

	if err := c.srv.store.TouchKey(ctx, g.KeyID); err != nil {
		c.log.Warn("record key use", "err", err)
	}
	return f, nil
}

func orName(name, fallback string) string {
	if name == "" {
		return fallback
	}
	return name
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
	c.mu.Unlock()
	if owned {
		c.log.Info("tunnel closed", "subdomain", t.Subdomain, "reason", reason)
		c.closed(c.srv.cfg.TunnelURL(t.Subdomain), reason)
	}
}

// portClosed is tunnelClosed for TCP ports.
func (c *clientConn) portClosed(key string, f *ports.Forward, reason string) {
	c.mu.Lock()
	owned := f != nil && c.ports[key] == f
	if owned {
		delete(c.ports, key)
	}
	c.mu.Unlock()
	if owned {
		c.log.Info("port closed", "subdomain", f.Port.Subdomain, "port", f.Port.Port, "reason", reason)
		c.closed(f.Address+" ("+f.Name()+")", reason)
	}
}

func (c *clientConn) closed(what, reason string) {
	c.mu.Lock()
	remaining, closing := len(c.forwards)+len(c.ports), c.closing
	c.mu.Unlock()
	if closing {
		return
	}
	c.console.Printf("✖ %s closed: %s", what, reason)
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
	c.mu.Lock()
	key := forwardKey(fr.BindAddr, fr.BindPort)
	f := c.ports[key]
	if f == nil && fr.BindPort == 0 {
		// A port asked for with port 0, cancelled the same way.
		for k, pf := range c.ports {
			if h, _, _ := net.SplitHostPort(k); h == fr.BindAddr {
				key, f = k, pf
			}
		}
	}
	var t *tunnel.Tunnel
	if f != nil {
		delete(c.ports, key)
	} else {
		key = forwardKey(fr.BindAddr, effectivePort(fr.BindPort))
		t = c.forwards[key]
		delete(c.forwards, key)
	}
	c.mu.Unlock()
	switch {
	case f != nil:
		f.Close("cancelled by client")
		c.log.Info("port cancelled", "subdomain", f.Port.Subdomain, "port", f.Port.Port)
	case t != nil:
		t.Close("cancelled by client")
		c.log.Info("tunnel cancelled", "subdomain", t.Subdomain)
	default:
		req.Reply(false, nil)
		return
	}
	req.Reply(true, nil)
}

// closeAll closes every tunnel and port of this connection once it has
// ended.
func (c *clientConn) closeAll() {
	c.mu.Lock()
	c.closing = true
	ts := make([]*tunnel.Tunnel, 0, len(c.forwards))
	for _, t := range c.forwards {
		ts = append(ts, t)
	}
	fs := make([]*ports.Forward, 0, len(c.ports))
	for _, f := range c.ports {
		fs = append(fs, f)
	}
	c.forwards = map[string]*tunnel.Tunnel{}
	c.ports = map[string]*ports.Forward{}
	c.mu.Unlock()
	for _, t := range ts {
		t.Close("client disconnected")
		c.log.Info("tunnel closed", "subdomain", t.Subdomain)
	}
	for _, f := range fs {
		f.Close("client disconnected")
		c.log.Info("port closed", "subdomain", f.Port.Subdomain, "port", f.Port.Port)
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
			nch.Reject(ssh.Prohibited, "gate2sky only supports remote forwarding (ssh -R)")
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
			welcome := fmt.Sprintf("gate2sky: connected with key %s\r\n", c.fingerprint)
			if req.Type == "exec" {
				welcome += "gate2sky: commands are not supported; manage your subdomains at " + c.srv.cfg.DashboardURL("/") + "\r\n"
			}
			if pty {
				welcome += "gate2sky: press Ctrl-C to close the connection\r\n"
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

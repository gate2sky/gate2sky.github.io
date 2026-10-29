// Package sshd accepts SSH connections and turns remote forwards into HTTP
// tunnels (ssh -R name:80:localhost:3000) and TCP ports
// (ssh -R db.name:0:localhost:5432).
package sshd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/names"
	"github.com/jgermade/intergate/internal/ports"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/tunnel"
)

const (
	extFingerprint = "intergate-fingerprint"
	extPublicKey   = "intergate-public-key"

	handshakeTimeout = 30 * time.Second
)

// Server is the SSH endpoint clients open tunnels through.
type Server struct {
	cfg      *config.Config
	store    *store.Store
	registry *tunnel.Registry
	ports    *ports.Registry
	log      *slog.Logger
	sshCfg   *ssh.ServerConfig

	// hinted holds clients (by remote address) already told that their
	// key is unknown, during their handshake.
	hinted sync.Map

	mu     sync.Mutex
	ln     net.Listener
	conns  map[*clientConn]struct{}
	closed bool
}

// New returns a Server that authenticates with hostKey.
func New(cfg *config.Config, st *store.Store, reg *tunnel.Registry, pr *ports.Registry, hostKey ssh.Signer, log *slog.Logger) *Server {
	s := &Server{
		cfg:      cfg,
		store:    st,
		registry: reg,
		ports:    pr,
		log:      log,
		conns:    map[*clientConn]struct{}{},
	}
	s.sshCfg = &ssh.ServerConfig{
		ServerVersion:               "SSH-2.0-intergate",
		MaxAuthTries:                6,
		PublicKeyCallback:           s.authenticate,
		KeyboardInteractiveCallback: s.explainUnknownKey,
	}
	s.sshCfg.AddHostKey(hostKey)
	return s
}

var errNoKey = errors.New("no registered key")

// explainUnknownKey is only reached once the client has run out of keys:
// it tells the user how to register one instead of a bare "Permission
// denied". Clients retry keyboard-interactive, so the hint is sent once.
func (s *Server) explainUnknownKey(meta ssh.ConnMetadata, _ ssh.KeyboardInteractiveChallenge) (*ssh.Permissions, error) {
	if _, sent := s.hinted.LoadOrStore(meta.RemoteAddr().String(), true); sent {
		return nil, errNoKey
	}
	return nil, &ssh.BannerError{Err: errNoKey, Message: fmt.Sprintf(
		"intergate: none of your SSH keys is registered.\r\n"+
			"Add your public key (e.g. ~/.ssh/id_ed25519.pub) to a subdomain at\r\n  %s\r\nthen try again.\r\n",
		s.cfg.DashboardURL("/"))}
}

func (s *Server) authenticate(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	fp := ssh.FingerprintSHA256(key)
	pub := authorizedKey(key)
	grants, err := s.grants(ctx, fp, pub)
	if err != nil {
		s.log.Error("ssh auth: load grants", "err", err)
		return nil, errors.New("internal error")
	}
	if len(grants) == 0 {
		s.log.Debug("ssh auth: unknown key", "remote", meta.RemoteAddr().String(), "fingerprint", fp)
		return nil, fmt.Errorf("key %s is not registered", fp)
	}
	return &ssh.Permissions{Extensions: map[string]string{extFingerprint: fp, extPublicKey: pub}}, nil
}

// grants returns the subdomains a key may use right now: the owner must
// still be enabled, and allowed by the auth configuration or added by an
// administrator.
func (s *Server) grants(ctx context.Context, fingerprint, publicKey string) ([]store.Grant, error) {
	all, err := s.store.GrantsForKey(ctx, fingerprint)
	if err != nil {
		return nil, err
	}
	out := all[:0]
	for _, g := range all {
		if g.PublicKey == publicKey && s.cfg.UserAllowed(g.OwnerEmail, g.OwnerAdded, string(g.OwnerRole)) {
			out = append(out, g)
		}
	}
	return out, nil
}

func authorizedKey(k ssh.PublicKey) string {
	return strings.TrimSpace(string(ssh.MarshalAuthorizedKey(k)))
}

// Serve accepts connections on ln until Close is called.
func (s *Server) Serve(ln net.Listener) error {
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return net.ErrClosed
	}
	s.ln = ln
	s.mu.Unlock()

	var backoff time.Duration
	for {
		nc, err := ln.Accept()
		if err != nil {
			s.mu.Lock()
			closed := s.closed
			s.mu.Unlock()
			if closed || errors.Is(err, net.ErrClosed) {
				return nil
			}
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			s.log.Warn("ssh accept failed", "err", err)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		go s.handleConn(nc)
	}
}

// Close stops accepting connections and drops every client.
func (s *Server) Close() error {
	s.mu.Lock()
	s.closed = true
	ln := s.ln
	conns := make([]*clientConn, 0, len(s.conns))
	for c := range s.conns {
		conns = append(conns, c)
	}
	s.mu.Unlock()
	var err error
	if ln != nil {
		err = ln.Close()
	}
	for _, c := range conns {
		c.conn.Close()
	}
	return err
}

func (s *Server) handleConn(nc net.Conn) {
	defer nc.Close()
	nc.SetDeadline(time.Now().Add(handshakeTimeout))
	sconn, chans, reqs, err := ssh.NewServerConn(nc, s.sshCfg)
	s.hinted.Delete(nc.RemoteAddr().String())
	if err != nil {
		s.log.Debug("ssh handshake failed", "remote", nc.RemoteAddr().String(), "err", err)
		return
	}
	nc.SetDeadline(time.Time{})

	c := &clientConn{
		srv:         s,
		conn:        sconn,
		fingerprint: sconn.Permissions.Extensions[extFingerprint],
		publicKey:   sconn.Permissions.Extensions[extPublicKey],
		console:     newConsole(),
		forwards:    map[string]*tunnel.Tunnel{},
		ports:       map[string]*ports.Forward{},
		done:        make(chan struct{}),
	}
	c.log = s.log.With("remote", sconn.RemoteAddr().String(), "fingerprint", c.fingerprint)

	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		sconn.Close()
		return
	}
	s.conns[c] = struct{}{}
	s.mu.Unlock()

	c.log.Info("ssh client connected", "user", sconn.User(), "client", string(sconn.ClientVersion()))
	go c.keepalive(s.cfg.SSH.KeepaliveInterval)
	go c.handleGlobalRequests(reqs)
	go c.handleChannels(chans)

	err = sconn.Wait()
	close(c.done)
	c.closeAll()
	c.console.Close()

	s.mu.Lock()
	delete(s.conns, c)
	s.mu.Unlock()
	c.log.Info("ssh client disconnected", "err", err)
}

// parseBind reads the bind address of `ssh -R <bind>:<port>:...`: a
// subdomain (myapp), or a TCP port of one by name (db.myapp), with or
// without the domain. Both are "" when the client named none.
func (s *Server) parseBind(addr string) (port, subdomain string, err error) {
	h := names.Normalize(addr)
	switch h {
	case "", "localhost", "*", "0.0.0.0", "::", "127.0.0.1", "::1":
		return "", "", nil
	}
	h = strings.TrimSuffix(h, "."+s.cfg.Domain())
	labels := strings.Split(h, ".")
	switch {
	case len(labels) == 1:
		return "", h, nil
	case len(labels) == 2 && labels[0] != "" && labels[1] != "":
		return labels[0], labels[1], nil
	}
	return "", "", fmt.Errorf("%q is not a subdomain of %s, nor a port of one (<port>.<subdomain>)", addr, s.cfg.Domain())
}

// pickGrant chooses the subdomain for a forward: the one in the bind
// address, else the SSH user name, else the key's only subdomain.
func pickGrant(grants []store.Grant, requested, user string) (store.Grant, error) {
	if len(grants) == 0 {
		return store.Grant{}, errors.New("this key is no longer registered for any subdomain")
	}
	if requested != "" {
		for _, g := range grants {
			if g.Subdomain == requested {
				return g, nil
			}
		}
		return store.Grant{}, fmt.Errorf("this key is not authorized for %q", requested)
	}
	for _, g := range grants {
		if g.Subdomain == user {
			return g, nil
		}
	}
	if len(grants) == 1 {
		return grants[0], nil
	}
	list := make([]string, len(grants))
	for i, g := range grants {
		list[i] = g.Subdomain
	}
	return store.Grant{}, fmt.Errorf("this key is registered for several subdomains (%s); choose one with -R <subdomain>:80:localhost:<port>",
		strings.Join(list, ", "))
}

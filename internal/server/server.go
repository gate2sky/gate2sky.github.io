// Package server wires intergate together and runs its listeners.
package server

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	proxyproto "github.com/pires/go-proxyproto"
	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"

	"github.com/jgermade/intergate/internal/admin"
	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/mail"
	"github.com/jgermade/intergate/internal/manage"
	"github.com/jgermade/intergate/internal/names"
	"github.com/jgermade/intergate/internal/ports"
	"github.com/jgermade/intergate/internal/sshd"
	"github.com/jgermade/intergate/internal/store"
	"github.com/jgermade/intergate/internal/tunnel"
	"github.com/jgermade/intergate/internal/web"
)

// Options customize a Server, mostly for tests.
type Options struct {
	Version string
	// Mailer replaces the configured email sender.
	Mailer mail.Sender
	// HTTPClient is used to reach OAuth providers.
	HTTPClient *http.Client
}

// Server is a configured intergate instance.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	version  string
	store    *store.Store
	registry *tunnel.Registry
	ports    *ports.Registry
	manage   *manage.Service
	hostKey  ssh.Signer
	ssh      *sshd.Server
	web      *web.Server
	admin    *admin.Handler
}

// New opens the data directory and builds every component.
func New(cfg *config.Config, log *slog.Logger, opts Options) (*Server, error) {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return nil, err
	}
	s := &Server{cfg: cfg, log: log, version: opts.Version, registry: tunnel.NewRegistry(), ports: ports.NewRegistry(cfg.TCP.ListenHost)}
	var err error
	if err := adoptLegacyDatabase(cfg.DataDir); err != nil {
		return nil, err
	}
	if s.store, err = store.Open(filepath.Join(cfg.DataDir, "intergate.db")); err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	secret, err := loadOrCreateSecret(filepath.Join(cfg.DataDir, "secret.key"))
	if err != nil {
		s.store.Close()
		return nil, fmt.Errorf("load secret: %w", err)
	}
	hostKeyPath := cfg.SSH.HostKeyFile
	if hostKeyPath == "" {
		hostKeyPath = filepath.Join(cfg.DataDir, "ssh_host_ed25519_key")
	}
	if s.hostKey, err = loadOrCreateHostKey(hostKeyPath); err != nil {
		s.store.Close()
		return nil, fmt.Errorf("load SSH host key: %w", err)
	}
	s.manage = manage.New(cfg, s.store, s.registry, s.ports, names.NewChecker(cfg.ReservedSubdomains), log.With("component", "manage"))
	s.ssh = sshd.New(cfg, s.store, s.registry, s.ports, s.hostKey, log.With("component", "ssh"))
	s.web, err = web.New(web.Options{
		Config:     cfg,
		Store:      s.store,
		Registry:   s.registry,
		Manage:     s.manage,
		Mailer:     opts.Mailer,
		Secret:     secret,
		Logger:     log.With("component", "web"),
		HTTPClient: opts.HTTPClient,
		Version:    opts.Version,
		HostKey:    ssh.FingerprintSHA256(s.hostKey.PublicKey()),
	})
	if err != nil {
		s.store.Close()
		return nil, err
	}
	s.admin = admin.NewHandler(cfg, s.store, s.manage, log.With("component", "admin"), opts.Version)
	return s, nil
}

// Close releases the database.
func (s *Server) Close() error { return s.store.Close() }

// Store returns the database.
func (s *Server) Store() *store.Store { return s.store }

// Registry returns the live tunnels.
func (s *Server) Registry() *tunnel.Registry { return s.registry }

// HostKey returns the SSH host key.
func (s *Server) HostKey() ssh.PublicKey { return s.hostKey.PublicKey() }

// Ports returns the forwarded TCP ports.
func (s *Server) Ports() *ports.Registry { return s.ports }

// SSH returns the SSH server.
func (s *Server) SSH() *sshd.Server { return s.ssh }

// Handler serves the dashboard and the tunnels.
func (s *Server) Handler() http.Handler { return s.web }

// Admin serves the admin API.
func (s *Server) Admin() *admin.Handler { return s.admin }

// Run serves until ctx is done or a listener fails.
func (s *Server) Run(ctx context.Context) error {
	cfg, log := s.cfg, s.log
	pidFile, err := writePIDFile(cfg.DataDir)
	if err != nil {
		return err
	}
	defer os.Remove(pidFile)

	// Open every listener before serving, so a bad port or certificate
	// stops startup cleanly.
	var listeners []net.Listener
	listen := func(addr string) (net.Listener, error) {
		ln, err := net.Listen("tcp", addr)
		if err == nil {
			listeners = append(listeners, ln)
		}
		return ln, err
	}
	closeAll := func() {
		for _, ln := range listeners {
			ln.Close()
		}
	}
	sshLn, err := listen(cfg.SSH.Listen)
	if err != nil {
		return err
	}
	httpLn, err := listen(cfg.HTTP.Listen)
	if err != nil {
		closeAll()
		return err
	}

	httpLog := slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	newServer := func(h http.Handler) *http.Server {
		// No write timeout: tunnels carry long downloads and websockets.
		return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: httpLog}
	}
	httpSrv := newServer(s.web)
	var httpsSrv *http.Server
	var httpsLn net.Listener
	if tlsCfg := cfg.HTTP.TLS; tlsCfg.Enabled() {
		redirect := redirectToHTTPS(cfg)
		httpsSrv = newServer(s.web)
		if tlsCfg.ACME.Enabled {
			m := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "acme")),
				Email:      tlsCfg.ACME.Email,
				HostPolicy: hostPolicy(cfg, s.store),
				Client:     &acme.Client{DirectoryURL: tlsCfg.ACME.DirectoryURL},
			}
			httpsSrv.TLSConfig = m.TLSConfig()
			redirect = m.HTTPHandler(redirect)
		} else {
			cert, err := tls.LoadX509KeyPair(tlsCfg.CertFile, tlsCfg.KeyFile)
			if err != nil {
				closeAll()
				return fmt.Errorf("load TLS certificate: %w", err)
			}
			httpsSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		httpSrv.Handler = redirect
		if httpsLn, err = listen(tlsCfg.Listen); err != nil {
			closeAll()
			return err
		}
	}
	if cfg.SSH.ProxyProtocol {
		sshLn = &proxyproto.Listener{Listener: sshLn, ReadHeaderTimeout: 10 * time.Second}
	}

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 4)
	adminDone := make(chan struct{})
	go func() {
		defer close(adminDone)
		if err := s.admin.Serve(ctx); err != nil {
			errc <- err
		}
	}()
	go func() { errc <- s.ssh.Serve(sshLn) }()
	go func() { errc <- httpSrv.Serve(httpLn) }()
	servers := []*http.Server{httpSrv}
	if httpsSrv != nil {
		servers = append(servers, httpsSrv)
		go func() { errc <- httpsSrv.ServeTLS(httpsLn, "", "") }()
		log.Info("listening", "https", httpsLn.Addr().String(), "http", httpLn.Addr().String()+" (redirects to https)")
	} else {
		log.Info("listening", "http", httpLn.Addr().String())
	}

	var methods []string
	if cfg.Auth.Email.Enabled() {
		methods = append(methods, "email")
	}
	if cfg.PasskeysEnabled() {
		methods = append(methods, "passkeys")
	}
	for _, p := range cfg.Auth.Providers {
		methods = append(methods, p.ID)
	}
	log.Info("intergate started",
		"version", s.version,
		"dashboard", cfg.DashboardURL("/"),
		"tunnels", cfg.TunnelURL("*"),
		"ssh", sshLn.Addr().String(),
		"ssh_host_key", ssh.FingerprintSHA256(s.hostKey.PublicKey()),
		"sign_in", strings.Join(methods, ","),
		"admin_socket", cfg.Admin.Socket)
	if cfg.TCP.Enabled() {
		log.Info("tcp ports enabled", "range", cfg.TCP.Ports, "per_subdomain", cfg.TCP.MaxPorts, "address", cfg.TCPAddress(0))
	}
	if cfg.Auth.Email.LogOnly {
		log.Warn("auth.email.log_only is set: sign-in codes are written to this log instead of being emailed")
	}

	go cleanSessions(ctx, s.store, log)

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	cancel()
	<-adminDone
	s.ssh.Close()
	s.ports.Close()
	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	for _, srv := range servers {
		srv.Shutdown(shutdownCtx)
	}
	return runErr
}

// adoptLegacyDatabase renames the database of gate2net or gate2sky,
// intergate's former names (the newer first), when the data directory has
// it and no intergate.db yet.
func adoptLegacyDatabase(dir string) error {
	db := filepath.Join(dir, "intergate.db")
	if _, err := os.Stat(db); err == nil {
		return nil
	}
	for _, name := range []string{"gate2net", "gate2sky"} {
		old := filepath.Join(dir, name+".db")
		if _, err := os.Stat(old); err != nil {
			continue
		}
		// SQLite's write-ahead log and index go with it.
		for _, suffix := range []string{"-wal", "-shm", ""} {
			if err := os.Rename(old+suffix, db+suffix); err != nil && !errors.Is(err, os.ErrNotExist) {
				return fmt.Errorf("rename %s: %w", old+suffix, err)
			}
		}
		return nil
	}
	return nil
}

// PIDFile is where a running server writes its process ID.
func PIDFile(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "intergate.pid") }

// RunningPID returns the PID of a server running on this data directory,
// or 0.
func RunningPID(cfg *config.Config) int {
	b, err := os.ReadFile(PIDFile(cfg))
	if err != nil {
		return 0
	}
	pid, err := strconv.Atoi(strings.TrimSpace(string(b)))
	if err != nil || pid <= 0 || !processAlive(pid) {
		return 0
	}
	return pid
}

func writePIDFile(dataDir string) (string, error) {
	path := filepath.Join(dataDir, "intergate.pid")
	if b, err := os.ReadFile(path); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid != os.Getpid() && processAlive(pid) {
			return "", fmt.Errorf("intergate is already running with PID %d (%s)", pid, path)
		}
	}
	return path, os.WriteFile(path, []byte(strconv.Itoa(os.Getpid())+"\n"), 0o644)
}

func processAlive(pid int) bool {
	p, err := os.FindProcess(pid)
	if err != nil {
		return false
	}
	err = p.Signal(syscall.Signal(0))
	return err == nil || errors.Is(err, syscall.EPERM)
}

// hostPolicy only lets ACME issue certificates for the dashboard and for
// registered subdomains, so random Host headers can't burn rate limits.
func hostPolicy(cfg *config.Config, st *store.Store) autocert.HostPolicy {
	return func(ctx context.Context, host string) error {
		host = strings.ToLower(host)
		if host == cfg.Domain() {
			return nil
		}
		name, ok := strings.CutSuffix(host, "."+cfg.Domain())
		if !ok || strings.Contains(name, ".") {
			return fmt.Errorf("acme: host %q is not served by intergate", host)
		}
		if _, err := st.SubdomainByName(ctx, name); err != nil {
			return fmt.Errorf("acme: subdomain %q is not registered", name)
		}
		return nil
	}
}

func redirectToHTTPS(cfg *config.Config) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/healthz" {
			w.Write([]byte("ok\n"))
			return
		}
		host := strings.ToLower(r.Host)
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		}
		var target string
		if host == cfg.Domain() {
			target = cfg.DashboardURL(r.URL.RequestURI())
		} else if name, ok := strings.CutSuffix(host, "."+cfg.Domain()); ok && !strings.Contains(name, ".") {
			target = cfg.TunnelURL(name) + r.URL.RequestURI()
		} else {
			http.NotFound(w, r)
			return
		}
		http.Redirect(w, r, target, http.StatusMovedPermanently)
	})
}

func cleanSessions(ctx context.Context, st *store.Store, log *slog.Logger) {
	t := time.NewTicker(time.Hour)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if err := st.DeleteExpiredSessions(ctx); err != nil {
				log.Warn("delete expired sessions", "err", err)
			}
		}
	}
}

// loadOrCreateSecret returns the key that signs cookies and tokens.
func loadOrCreateSecret(path string) ([]byte, error) {
	if b, err := os.ReadFile(path); err == nil {
		return hex.DecodeString(strings.TrimSpace(string(b)))
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	secret := make([]byte, 32)
	rand.Read(secret)
	return secret, os.WriteFile(path, []byte(hex.EncodeToString(secret)+"\n"), 0o600)
}

func loadOrCreateHostKey(path string) (ssh.Signer, error) {
	if b, err := os.ReadFile(path); err == nil {
		return ssh.ParsePrivateKey(b)
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}
	block, err := ssh.MarshalPrivateKey(priv, "intergate host key")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

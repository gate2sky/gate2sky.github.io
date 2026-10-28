// Package server wires securegate together and runs its listeners.
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

	"github.com/jgermade/securegate/internal/admin"
	"github.com/jgermade/securegate/internal/config"
	"github.com/jgermade/securegate/internal/mail"
	"github.com/jgermade/securegate/internal/manage"
	"github.com/jgermade/securegate/internal/names"
	"github.com/jgermade/securegate/internal/sshd"
	"github.com/jgermade/securegate/internal/store"
	"github.com/jgermade/securegate/internal/tunnel"
	"github.com/jgermade/securegate/internal/web"
)

// Options customize a Server, mostly for tests.
type Options struct {
	Version string
	// Mailer replaces the configured email sender.
	Mailer mail.Sender
	// HTTPClient is used to reach OAuth providers.
	HTTPClient *http.Client
}

// Server is a configured securegate instance.
type Server struct {
	cfg      *config.Config
	log      *slog.Logger
	version  string
	store    *store.Store
	registry *tunnel.Registry
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
	s := &Server{cfg: cfg, log: log, version: opts.Version, registry: tunnel.NewRegistry()}
	var err error
	if s.store, err = store.Open(filepath.Join(cfg.DataDir, "securegate.db")); err != nil {
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
	s.manage = manage.New(cfg, s.store, s.registry, names.NewChecker(cfg.ReservedSubdomains), log.With("component", "manage"))
	s.ssh = sshd.New(cfg, s.store, s.registry, s.hostKey, log.With("component", "ssh"))
	s.web, err = web.New(web.Options{
		Config:     cfg,
		Store:      s.store,
		Registry:   s.registry,
		Manage:     s.manage,
		Mailer:     opts.Mailer,
		Secret:     secret,
		Logger:     log.With("component", "web"),
		HTTPClient: opts.HTTPClient,
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

	ctx, cancel := context.WithCancel(ctx)
	defer cancel()
	errc := make(chan error, 5)

	sshLn, err := net.Listen("tcp", cfg.SSH.Listen)
	if err != nil {
		return err
	}
	if cfg.SSH.ProxyProtocol {
		sshLn = &proxyproto.Listener{Listener: sshLn, ReadHeaderTimeout: 10 * time.Second}
	}
	httpLn, err := net.Listen("tcp", cfg.HTTP.Listen)
	if err != nil {
		sshLn.Close()
		return err
	}
	go func() { errc <- s.ssh.Serve(sshLn) }()
	go func() {
		if err := s.admin.Serve(ctx); err != nil {
			errc <- err
		}
	}()

	httpLog := slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	newServer := func(h http.Handler) *http.Server {
		// No write timeout: tunnels carry long downloads and websockets.
		return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: httpLog}
	}
	var servers []*http.Server
	if tlsCfg := cfg.HTTP.TLS; tlsCfg.Enabled() {
		httpsLn, err := net.Listen("tcp", tlsCfg.Listen)
		if err != nil {
			return err
		}
		redirect := redirectToHTTPS(cfg)
		httpsSrv := newServer(s.web)
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
				return fmt.Errorf("load TLS certificate: %w", err)
			}
			httpsSrv.TLSConfig = &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12}
		}
		httpSrv := newServer(redirect)
		servers = append(servers, httpsSrv, httpSrv)
		go func() { errc <- httpsSrv.ServeTLS(httpsLn, "", "") }()
		go func() { errc <- httpSrv.Serve(httpLn) }()
		log.Info("listening", "https", httpsLn.Addr().String(), "http", httpLn.Addr().String()+" (redirects to https)")
	} else {
		httpSrv := newServer(s.web)
		servers = append(servers, httpSrv)
		go func() { errc <- httpSrv.Serve(httpLn) }()
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
	log.Info("securegate started",
		"version", s.version,
		"dashboard", cfg.DashboardURL("/"),
		"tunnels", cfg.TunnelURL("*"),
		"ssh", sshLn.Addr().String(),
		"ssh_host_key", ssh.FingerprintSHA256(s.hostKey.PublicKey()),
		"sign_in", strings.Join(methods, ","),
		"admin_socket", cfg.Admin.Socket)
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
	s.ssh.Close()
	shutdownCtx, done := context.WithTimeout(context.Background(), 5*time.Second)
	defer done()
	for _, srv := range servers {
		srv.Shutdown(shutdownCtx)
	}
	return runErr
}

// PIDFile is where a running server writes its process ID.
func PIDFile(cfg *config.Config) string { return filepath.Join(cfg.DataDir, "securegate.pid") }

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
	path := filepath.Join(dataDir, "securegate.pid")
	if b, err := os.ReadFile(path); err == nil {
		if pid, err := strconv.Atoi(strings.TrimSpace(string(b))); err == nil && pid != os.Getpid() && processAlive(pid) {
			return "", fmt.Errorf("securegate is already running with PID %d (%s)", pid, path)
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
			return fmt.Errorf("acme: host %q is not served by securegate", host)
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
	block, err := ssh.MarshalPrivateKey(priv, "securegate host key")
	if err != nil {
		return nil, err
	}
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}
	return ssh.NewSignerFromKey(priv)
}

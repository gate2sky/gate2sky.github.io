// Command securegate exposes local HTTP services on subdomains through SSH
// remote forwarding, managed from a web dashboard with OAuth sign-in.
package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/tls"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"golang.org/x/crypto/acme"
	"golang.org/x/crypto/acme/autocert"
	"golang.org/x/crypto/ssh"

	"github.com/jgermade/securegate/internal/config"
	"github.com/jgermade/securegate/internal/names"
	"github.com/jgermade/securegate/internal/sshd"
	"github.com/jgermade/securegate/internal/store"
	"github.com/jgermade/securegate/internal/tunnel"
	"github.com/jgermade/securegate/internal/web"
)

// version is set at build time with -ldflags "-X main.version=...".
var version = "dev"

func main() {
	configPath := flag.String("config", "securegate.yaml", "path to the configuration file")
	debug := flag.Bool("debug", false, "enable debug logging")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()
	if *showVersion {
		fmt.Println("securegate", version)
		return
	}

	level := slog.LevelInfo
	if *debug {
		level = slog.LevelDebug
	}
	log := slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: level}))

	cfg, err := config.Load(*configPath)
	if err != nil {
		log.Error("load configuration", "path", *configPath, "err", err)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, cfg, log); err != nil {
		log.Error("securegate stopped", "err", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, cfg *config.Config, log *slog.Logger) error {
	if err := os.MkdirAll(cfg.DataDir, 0o700); err != nil {
		return err
	}
	st, err := store.Open(filepath.Join(cfg.DataDir, "securegate.db"))
	if err != nil {
		return fmt.Errorf("open database: %w", err)
	}
	defer st.Close()

	secret, err := loadOrCreateSecret(filepath.Join(cfg.DataDir, "secret.key"))
	if err != nil {
		return fmt.Errorf("load secret: %w", err)
	}
	hostKeyPath := cfg.SSH.HostKeyFile
	if hostKeyPath == "" {
		hostKeyPath = filepath.Join(cfg.DataDir, "ssh_host_ed25519_key")
	}
	hostKey, err := loadOrCreateHostKey(hostKeyPath)
	if err != nil {
		return fmt.Errorf("load SSH host key: %w", err)
	}

	registry := tunnel.NewRegistry()
	sshSrv := sshd.New(cfg, st, registry, hostKey, log.With("component", "ssh"))
	handler, err := web.New(web.Options{
		Config:   cfg,
		Store:    st,
		Registry: registry,
		Names:    names.NewChecker(cfg.ReservedSubdomains),
		Secret:   secret,
		Logger:   log.With("component", "web"),
	})
	if err != nil {
		return err
	}

	sshLn, err := net.Listen("tcp", cfg.SSH.Listen)
	if err != nil {
		return err
	}
	httpLn, err := net.Listen("tcp", cfg.HTTP.Listen)
	if err != nil {
		return err
	}
	httpLog := slog.NewLogLogger(log.Handler(), slog.LevelDebug)
	newServer := func(h http.Handler) *http.Server {
		// No write timeout: tunnels carry long downloads and websockets.
		return &http.Server{Handler: h, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute, ErrorLog: httpLog}
	}

	servers := []*http.Server{}
	errc := make(chan error, 3)
	go func() { errc <- sshSrv.Serve(sshLn) }()

	if tlsCfg := cfg.HTTP.TLS; tlsCfg.Enabled() {
		httpsLn, err := net.Listen("tcp", tlsCfg.Listen)
		if err != nil {
			return err
		}
		redirect := redirectToHTTPS(cfg)
		httpsSrv := newServer(handler)
		if tlsCfg.ACME.Enabled {
			m := &autocert.Manager{
				Prompt:     autocert.AcceptTOS,
				Cache:      autocert.DirCache(filepath.Join(cfg.DataDir, "acme")),
				Email:      tlsCfg.ACME.Email,
				HostPolicy: hostPolicy(cfg, st),
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
		httpSrv := newServer(handler)
		servers = append(servers, httpSrv)
		go func() { errc <- httpSrv.Serve(httpLn) }()
		log.Info("listening", "http", httpLn.Addr().String())
	}
	log.Info("securegate started",
		"version", version,
		"dashboard", cfg.DashboardURL("/"),
		"tunnels", cfg.TunnelURL("*"),
		"ssh", sshLn.Addr().String(),
		"ssh_host_key", ssh.FingerprintSHA256(hostKey.PublicKey()))

	go cleanSessions(ctx, st, log)

	var runErr error
	select {
	case <-ctx.Done():
		log.Info("shutting down")
	case err := <-errc:
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			runErr = err
		}
	}
	sshSrv.Close()
	shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, s := range servers {
		s.Shutdown(shutdownCtx)
	}
	return runErr
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

// Package web serves the dashboard on the main host and proxies every
// subdomain to its SSH tunnel.
package web

import (
	"bytes"
	"context"
	"crypto/subtle"
	"embed"
	"errors"
	"fmt"
	"html/template"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"

	"github.com/jgermade/securegate/internal/config"
	"github.com/jgermade/securegate/internal/mail"
	"github.com/jgermade/securegate/internal/manage"
	"github.com/jgermade/securegate/internal/store"
	"github.com/jgermade/securegate/internal/tunnel"
)

//go:embed templates static
var assets embed.FS

// Options configure a Server.
type Options struct {
	Config   *config.Config
	Store    *store.Store
	Registry *tunnel.Registry
	Manage   *manage.Service
	// Mailer sends sign-in codes. Defaults to the configured SMTP server.
	Mailer mail.Sender
	// Secret signs OAuth state and tunnel access cookies. Keep it stable
	// across restarts so visitors stay signed in to private tunnels.
	Secret []byte
	Logger *slog.Logger
	// HTTPClient talks to OAuth providers. Defaults to a client with a
	// 15 second timeout.
	HTTPClient *http.Client
}

// Server is the HTTP handler for the dashboard and all tunnels.
type Server struct {
	cfg       *config.Config
	store     *store.Store
	registry  *tunnel.Registry
	manage    *manage.Service
	mailer    mail.Sender
	log       *slog.Logger
	signer    signer
	nonces    *nonceSet
	codes     *codeStore
	webauthn  *webauthn.WebAuthn
	cookies   cookieNames
	providers []provider
	pages     map[string]*template.Template
	dashboard http.Handler
	proxy     *httputil.ReverseProxy
}

type cookieNames struct {
	session, oauth, flash, access, emailLogin, passkey string
}

// New builds the handler.
func New(o Options) (*Server, error) {
	if len(o.Secret) < 32 {
		return nil, errors.New("web: secret must be at least 32 bytes")
	}
	client := o.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: 15 * time.Second}
	}
	s := &Server{
		cfg:      o.Config,
		store:    o.Store,
		registry: o.Registry,
		manage:   o.Manage,
		mailer:   o.Mailer,
		log:      o.Logger,
		signer:   signer{key: o.Secret},
		nonces:   newNonceSet(),
		codes:    newCodeStore(),
	}
	if s.mailer == nil {
		s.mailer = mail.New(s.cfg.Auth.Email, s.log)
	}
	// The __Host- prefix stops tunnel subdomains, which serve arbitrary
	// content, from planting cookies for the dashboard (or each other).
	prefix := ""
	if s.cfg.Secure() {
		prefix = "__Host-"
	}
	s.cookies = cookieNames{
		session:    prefix + "securegate",
		oauth:      prefix + "securegate-oauth",
		flash:      prefix + "securegate-flash",
		access:     prefix + "securegate-access",
		emailLogin: prefix + "securegate-email",
		passkey:    prefix + "securegate-passkey",
	}
	if s.cfg.PasskeysEnabled() {
		wa, err := webauthn.New(&webauthn.Config{
			RPID:          s.cfg.Domain(),
			RPDisplayName: "securegate",
			// Tunnel subdomains may claim this RP ID too, so assertions
			// are only accepted from the dashboard's exact origin.
			RPOrigins: []string{s.cfg.DashboardURL("")},
		})
		if err != nil {
			return nil, fmt.Errorf("web: passkeys: %w", err)
		}
		s.webauthn = wa
	}
	for _, pc := range s.cfg.Auth.Providers {
		redirect := s.cfg.DashboardURL("/auth/" + pc.ID + "/callback")
		switch pc.Type {
		case "github":
			s.providers = append(s.providers, newGitHubProvider(pc, redirect, client))
		case "oidc":
			s.providers = append(s.providers, newOIDCProvider(pc, redirect, client))
		}
	}
	var err error
	if s.pages, err = s.parseTemplates(); err != nil {
		return nil, err
	}
	s.dashboard = s.routes()
	s.proxy = s.newProxy()
	return s, nil
}

// ServeHTTP dispatches on the Host header: the dashboard lives on the
// configured domain, tunnels on its direct subdomains.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	host := strings.ToLower(r.Host)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSuffix(host, ".")
	domain := s.cfg.Domain()
	switch {
	case host == domain:
		s.dashboard.ServeHTTP(w, r)
	case strings.HasSuffix(host, "."+domain) && !strings.Contains(strings.TrimSuffix(host, "."+domain), "."):
		s.serveTunnel(w, r, strings.TrimSuffix(host, "."+domain))
	case r.URL.Path == "/healthz":
		// Load balancer health checks often use the bare IP as Host.
		w.Write([]byte("ok\n"))
	default:
		http.Error(w, "unknown host", http.StatusMisdirectedRequest)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()
	static, _ := fs.Sub(assets, "static")
	mux.Handle("GET /static/", http.StripPrefix("/static/", http.FileServerFS(static)))
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ok\n")) })

	mux.HandleFunc("GET /{$}", s.handleHome)
	mux.HandleFunc("GET /login", s.handleLoginPage)
	mux.HandleFunc("GET /auth/{provider}/login", s.handleOAuthLogin)
	mux.HandleFunc("GET /auth/{provider}/callback", s.handleOAuthCallback)
	mux.HandleFunc("GET /tunnel-auth", s.handleTunnelAuth)
	if s.cfg.Auth.Email.Enabled() {
		mux.Handle("POST /login/email", s.sameOrigin(s.handleEmailLogin))
		mux.HandleFunc("GET /login/code", s.handleCodePage)
		mux.Handle("POST /login/code", s.sameOrigin(s.handleCodeLogin))
	}
	if s.webauthn != nil {
		mux.Handle("POST /login/passkey/options", s.sameOrigin(s.handlePasskeyLoginOptions))
		mux.Handle("POST /login/passkey", s.sameOrigin(s.handlePasskeyLogin))
	}

	user := s.requireUser
	mux.Handle("POST /logout", user(s.handleLogout))
	mux.Handle("GET /account", user(s.handleAccount))
	if s.webauthn != nil {
		mux.Handle("POST /account/passkeys/options", user(s.handlePasskeyRegisterOptions))
		mux.Handle("POST /account/passkeys", user(s.handlePasskeyRegister))
		mux.Handle("POST /account/passkeys/{id}/delete", user(s.handleDeletePasskey))
	}
	mux.Handle("POST /subdomains", user(s.handleCreateSubdomain))
	mux.Handle("GET /subdomains/{name}", user(s.handleSubdomain))
	mux.Handle("POST /subdomains/{name}/access", user(s.handleSetAccess))
	mux.Handle("POST /subdomains/{name}/keys", user(s.handleAddKeys))
	mux.Handle("POST /subdomains/{name}/keys/{id}/delete", user(s.handleDeleteKey))
	mux.Handle("POST /subdomains/{name}/disconnect", user(s.handleDisconnect))
	mux.Handle("POST /subdomains/{name}/delete", user(s.handleDeleteSubdomain))

	admin := func(h http.HandlerFunc) http.Handler { return s.requireUser(s.requireAdmin(h)) }
	mux.Handle("GET /admin", admin(s.handleAdmin))
	mux.Handle("POST /admin/users", admin(s.handleAdminCreateUser))
	mux.Handle("POST /admin/users/{id}/disable", admin(s.handleSetUserDisabled(true)))
	mux.Handle("POST /admin/users/{id}/enable", admin(s.handleSetUserDisabled(false)))

	return s.securityHeaders(s.withSession(mux))
}

func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' https: data:; "+
			"connect-src 'self'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Cross-Origin-Opener-Policy", "same-origin")
		if s.cfg.Secure() {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		next.ServeHTTP(w, r)
	})
}

type ctxKey int

const authKey ctxKey = iota

// authInfo is the signed-in user of a dashboard request.
type authInfo struct {
	Session *store.Session
	User    *store.User
	Admin   bool
}

func currentAuth(r *http.Request) *authInfo {
	a, _ := r.Context().Value(authKey).(*authInfo)
	return a
}

func (s *Server) withSession(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie(s.cookies.session); err == nil && c.Value != "" {
			sess, user, err := s.store.SessionByToken(r.Context(), c.Value)
			switch {
			case err == nil && s.cfg.EmailAllowed(user.Email):
				a := &authInfo{Session: sess, User: user, Admin: s.cfg.IsAdmin(user.Email)}
				r = r.WithContext(context.WithValue(r.Context(), authKey, a))
			case err != nil && !errors.Is(err, store.ErrNotFound):
				s.log.Error("load session", "err", err)
				s.renderError(w, r, http.StatusInternalServerError, "Something went wrong. Please try again.")
				return
			default:
				s.clearCookie(w, s.cookies.session)
			}
		}
		next.ServeHTTP(w, r)
	})
}

// requireUser redirects anonymous visitors to the login page and checks
// the CSRF token of state-changing requests.
func (s *Server) requireUser(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		a := currentAuth(r)
		if r.Method == http.MethodGet || r.Method == http.MethodHead {
			if a == nil {
				http.Redirect(w, r, "/login?rd="+url.QueryEscape(r.URL.RequestURI()), http.StatusFound)
				return
			}
			next(w, r)
			return
		}
		r.Body = http.MaxBytesReader(w, r.Body, 256<<10)
		if a == nil {
			s.renderError(w, r, http.StatusUnauthorized, "Your session has expired. Please sign in again.")
			return
		}
		// Tunnel subdomains are same-site with the dashboard, so SameSite
		// cookies do not stop them from submitting forms here: check both
		// the origin and a per-session token (a header for fetch requests).
		if !s.fromDashboard(r) {
			s.renderError(w, r, http.StatusForbidden, "Cross-origin request blocked.")
			return
		}
		token := r.Header.Get("X-CSRF-Token")
		if token == "" {
			token = r.PostFormValue("csrf_token")
		}
		if subtle.ConstantTimeCompare([]byte(token), []byte(a.Session.CSRFToken)) != 1 {
			s.renderError(w, r, http.StatusForbidden, "Invalid form token. Reload the page and try again.")
			return
		}
		next(w, r)
	})
}

// fromDashboard reports whether a request was sent by a dashboard page,
// going by its Origin (or, for older browsers, Referer) header.
func (s *Server) fromDashboard(r *http.Request) bool {
	origin := s.cfg.DashboardURL("")
	if o := r.Header.Get("Origin"); o != "" {
		return o == origin
	}
	ref := r.Header.Get("Referer")
	return ref == "" || ref == origin || strings.HasPrefix(ref, origin+"/")
}

// sameOrigin guards the sign-in forms and calls, which have no session to
// carry a CSRF token yet.
func (s *Server) sameOrigin(next http.HandlerFunc) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r.Body = http.MaxBytesReader(w, r.Body, 64<<10)
		if r.Header.Get("Origin") == "" && r.Header.Get("Referer") == "" || !s.fromDashboard(r) {
			s.renderError(w, r, http.StatusForbidden, "Cross-origin request blocked.")
			return
		}
		next(w, r)
	})
}

// clientIP is the visitor's address, for rate limiting and logs.
func (s *Server) clientIP(r *http.Request) string {
	if s.cfg.HTTP.TrustProxyHeaders {
		// The last entry was added by the proxy we trust.
		if xff := r.Header.Values("X-Forwarded-For"); len(xff) > 0 {
			parts := strings.Split(xff[len(xff)-1], ",")
			if ip := strings.TrimSpace(parts[len(parts)-1]); ip != "" {
				return ip
			}
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func (s *Server) requireAdmin(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if a := currentAuth(r); a == nil || !a.Admin {
			s.renderError(w, r, http.StatusNotFound, "Page not found.")
			return
		}
		next(w, r)
	}
}

func (s *Server) setCookie(w http.ResponseWriter, name, value string, expires time.Time) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    value,
		Path:     "/",
		Expires:  expires,
		HttpOnly: true,
		Secure:   s.cfg.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
}

func (s *Server) clearCookie(w http.ResponseWriter, name string) {
	http.SetCookie(w, &http.Cookie{
		Name:     name,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   s.cfg.Secure(),
		SameSite: http.SameSiteLaxMode,
	})
}

// flash is a one-time message shown after a redirect.
type flash struct {
	Kind string // "ok" or "error"
	Msg  string
}

func (s *Server) setFlash(w http.ResponseWriter, kind, format string, args ...any) {
	v := s.signer.sign("flash", flash{Kind: kind, Msg: fmt.Sprintf(format, args...)}, time.Minute)
	s.setCookie(w, s.cookies.flash, v, time.Now().Add(time.Minute))
}

func (s *Server) takeFlash(w http.ResponseWriter, r *http.Request) *flash {
	c, err := r.Cookie(s.cookies.flash)
	if err != nil {
		return nil
	}
	s.clearCookie(w, s.cookies.flash)
	var f flash
	if s.signer.verify("flash", c.Value, &f) != nil {
		return nil
	}
	return &f
}

// view is the data every dashboard template receives.
type view struct {
	Title    string
	Auth     *authInfo
	Flash    *flash
	Domain   string
	Passkeys bool
	Page     any
}

func (s *Server) render(w http.ResponseWriter, r *http.Request, status int, page, title string, data any) {
	v := view{Title: title, Auth: currentAuth(r), Domain: s.cfg.Domain(), Passkeys: s.webauthn != nil, Page: data}
	v.Flash = s.takeFlash(w, r)
	var buf bytes.Buffer
	if err := s.pages[page].Execute(&buf, v); err != nil {
		s.log.Error("render template", "page", page, "err", err)
		http.Error(w, "internal error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	w.Write(buf.Bytes())
}

func (s *Server) renderError(w http.ResponseWriter, r *http.Request, status int, msg string) {
	s.render(w, r, status, "error", http.StatusText(status), struct {
		Status int
		Msg    string
	}{status, msg})
}

func (s *Server) parseTemplates() (map[string]*template.Template, error) {
	funcs := template.FuncMap{
		"tunnelURL":  s.cfg.TunnelURL,
		"sshCommand": s.sshCommand,
		"ago":        ago,
		"datetime":   func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04 UTC") },
		"bytes":      humanBytes,
	}
	pages := map[string]*template.Template{}
	for _, p := range []string{"login", "login_code", "account", "dashboard", "subdomain", "admin", "error"} {
		t, err := template.New("layout.html").Funcs(funcs).ParseFS(assets, "templates/layout.html", "templates/"+p+".html")
		if err != nil {
			return nil, fmt.Errorf("parse template %s: %w", p, err)
		}
		pages[p] = t
	}
	t, err := template.New("tunnel_error.html").Funcs(funcs).ParseFS(assets, "templates/tunnel_error.html")
	if err != nil {
		return nil, fmt.Errorf("parse template tunnel_error: %w", err)
	}
	pages["tunnel_error"] = t
	return pages, nil
}

// sshCommand is the command a user runs to expose localhost:3000.
func (s *Server) sshCommand(name string) string {
	cmd := "ssh"
	if p := s.cfg.SSHPort(); p != 22 {
		cmd += fmt.Sprintf(" -p %d", p)
	}
	return fmt.Sprintf("%s -R %s:80:localhost:3000 %s", cmd, name, s.cfg.SSHHost())
}

func ago(t time.Time) string {
	if t.IsZero() {
		return "never"
	}
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		return fmt.Sprintf("%dm ago", int(d.Minutes()))
	case d < 48*time.Hour:
		return fmt.Sprintf("%dh ago", int(d.Hours()))
	}
	return fmt.Sprintf("%dd ago", int(d.Hours()/24))
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return fmt.Sprintf("%d B", n)
	}
	div, exp := int64(unit), 0
	for m := n / unit; m >= unit; m /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %ciB", float64(n)/float64(div), "KMGTPE"[exp])
}

// localPath returns rd if it is a path on this host, else "/". It stops
// redirects to other sites after login.
func localPath(rd string) string {
	if !strings.HasPrefix(rd, "/") || strings.HasPrefix(rd, "//") || strings.HasPrefix(rd, "/\\") {
		return "/"
	}
	u, err := url.Parse(rd)
	if err != nil || u.Scheme != "" || u.Host != "" {
		return "/"
	}
	return rd
}

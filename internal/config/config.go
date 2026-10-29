// Package config loads and validates the gate2sky configuration file.
package config

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

// Config is the top-level configuration.
type Config struct {
	// PublicURL is the external URL of the web dashboard, e.g.
	// https://gate.example.com. Tunnels are served on subdomains of its host:
	// https://<name>.gate.example.com.
	PublicURL string `yaml:"public_url"`
	// DataDir holds the SQLite database, the SSH host key and other state.
	DataDir string `yaml:"data_dir"`

	HTTP   HTTPConfig  `yaml:"http"`
	SSH    SSHConfig   `yaml:"ssh"`
	Auth   AuthConfig  `yaml:"auth"`
	Admin  AdminConfig `yaml:"admin"`
	Limits Limits      `yaml:"limits"`

	// ReservedSubdomains are names nobody can register, on top of the
	// built-in list (www, admin, api, ...).
	ReservedSubdomains []string `yaml:"reserved_subdomains"`

	publicURL *url.URL
}

type HTTPConfig struct {
	// Listen is the plain HTTP listen address. When TLS is enabled it only
	// redirects to HTTPS (and answers ACME HTTP-01 challenges).
	Listen string    `yaml:"listen"`
	TLS    TLSConfig `yaml:"tls"`
	// TrustProxyHeaders keeps incoming X-Forwarded-For headers. Enable it
	// only when gate2sky runs behind a reverse proxy you control.
	TrustProxyHeaders bool `yaml:"trust_proxy_headers"`
}

type TLSConfig struct {
	Listen string `yaml:"listen"`
	// CertFile and KeyFile point to a certificate valid for both the
	// dashboard host and *.host (a wildcard certificate).
	CertFile string     `yaml:"cert_file"`
	KeyFile  string     `yaml:"key_file"`
	ACME     ACMEConfig `yaml:"acme"`
}

// Enabled reports whether gate2sky terminates TLS itself.
func (t TLSConfig) Enabled() bool { return t.ACME.Enabled || t.CertFile != "" }

type ACMEConfig struct {
	// Enabled obtains certificates from Let's Encrypt on demand, for the
	// dashboard host and for every registered subdomain.
	Enabled      bool   `yaml:"enabled"`
	Email        string `yaml:"email"`
	DirectoryURL string `yaml:"directory_url"`
}

type SSHConfig struct {
	Listen      string `yaml:"listen"`
	HostKeyFile string `yaml:"host_key_file"`
	// PublicHost and PublicPort are what users type in `ssh -p PORT HOST`.
	// They default to the dashboard host and the listen port.
	PublicHost        string        `yaml:"public_host"`
	PublicPort        int           `yaml:"public_port"`
	KeepaliveInterval time.Duration `yaml:"keepalive_interval"`
	// ProxyProtocol expects a PROXY protocol header (v1 or v2) on every
	// SSH connection, e.g. from Traefik or HAProxy, to learn client IPs.
	ProxyProtocol bool `yaml:"proxy_protocol"`
}

type AdminConfig struct {
	// Socket is the Unix socket `gate2sky config` and `gate2sky status`
	// use to manage the running server. Defaults to <data_dir>/admin.sock.
	Socket string `yaml:"socket"`
}

type AuthConfig struct {
	SessionTTL time.Duration `yaml:"session_ttl"`
	// AllowEveryone lets any account with a verified email sign in. When
	// false, only AllowedEmails, AllowedDomains and Admins can sign in.
	AllowEveryone  bool     `yaml:"allow_everyone"`
	AllowedEmails  []string `yaml:"allowed_emails"`
	AllowedDomains []string `yaml:"allowed_domains"`
	Admins         []string `yaml:"admins"`

	// Email enables sign-in with a one-time code sent by email.
	Email EmailConfig `yaml:"email"`
	// DisablePasskeys turns off passkey (WebAuthn) sign-in.
	DisablePasskeys bool `yaml:"disable_passkeys"`
	// Providers are optional OAuth sign-in providers.
	Providers []ProviderConfig `yaml:"providers"`
}

type EmailConfig struct {
	// From is the sender, e.g. "gate2sky <no-reply@gate.example.com>".
	From    string        `yaml:"from"`
	CodeTTL time.Duration `yaml:"code_ttl"`
	SMTP    SMTPConfig    `yaml:"smtp"`
	// LogOnly writes emails to the log instead of sending them. Only for
	// local development: anyone reading the log can sign in.
	LogOnly bool `yaml:"log_only"`
}

// Enabled reports whether email sign-in is configured.
func (e EmailConfig) Enabled() bool { return e.SMTP.Host != "" || e.LogOnly }

type SMTPConfig struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
	// TLS is "starttls" (default), "tls" (implicit, usually port 465) or
	// "none" (only for a relay on localhost).
	TLS string `yaml:"tls"`
}

type ProviderConfig struct {
	// ID appears in the callback URL: <public_url>/auth/<id>/callback.
	ID string `yaml:"id"`
	// Type is "github" or "oidc".
	Type         string   `yaml:"type"`
	Name         string   `yaml:"name"`
	ClientID     string   `yaml:"client_id"`
	ClientSecret string   `yaml:"client_secret"`
	Scopes       []string `yaml:"scopes"`

	// Issuer is the OIDC issuer URL (type oidc).
	Issuer string `yaml:"issuer"`
	// AssumeEmailVerified accepts ID tokens without an email_verified claim.
	// Only enable it for identity providers that verify emails themselves.
	AssumeEmailVerified bool `yaml:"assume_email_verified"`

	// AuthURL, TokenURL and APIURL override the GitHub endpoints, e.g. for
	// GitHub Enterprise Server (type github).
	AuthURL  string `yaml:"auth_url"`
	TokenURL string `yaml:"token_url"`
	APIURL   string `yaml:"api_url"`
}

type Limits struct {
	SubdomainsPerUser    int `yaml:"subdomains_per_user"`
	KeysPerSubdomain     int `yaml:"keys_per_subdomain"`
	TunnelsPerConnection int `yaml:"tunnels_per_connection"`
}

// Load reads the YAML file at path. ${VAR} references are replaced with
// environment variables before parsing, so secrets can stay out of the file.
// Relative paths in the file are resolved against the file's directory.
func Load(path string) (*Config, error) {
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg, err := parse(raw, filepath.Dir(path))
	if err != nil {
		return nil, err
	}
	return cfg, nil
}

var envRef = regexp.MustCompile(`\$\{([A-Za-z_][A-Za-z0-9_]*)\}`)

// Parse parses and validates a configuration document. Relative paths are
// left as they are, relative to the working directory.
func Parse(raw []byte) (*Config, error) { return parse(raw, "") }

func parse(raw []byte, base string) (*Config, error) {
	// Expand ${VAR} in values only, so comments may mention variables
	// that are not set.
	var doc yaml.Node
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	var missing []string
	expandEnv(&doc, &missing)
	if len(missing) > 0 {
		return nil, fmt.Errorf("config references unset environment variables: %s", strings.Join(missing, ", "))
	}
	expanded, err := yaml.Marshal(&doc)
	if err != nil {
		return nil, fmt.Errorf("parse config: %w", err)
	}

	cfg := &Config{}
	dec := yaml.NewDecoder(bytes.NewReader(expanded))
	dec.KnownFields(true)
	if err := dec.Decode(cfg); err != nil && !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.setDefaults()
	if base != "" {
		cfg.resolvePaths(base)
	}
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func expandEnv(n *yaml.Node, missing *[]string) {
	if n.Kind == yaml.ScalarNode && envRef.MatchString(n.Value) {
		n.Value = envRef.ReplaceAllStringFunc(n.Value, func(m string) string {
			name := envRef.FindStringSubmatch(m)[1]
			v, ok := os.LookupEnv(name)
			if !ok {
				*missing = append(*missing, name)
			}
			return v
		})
		if n.Style&(yaml.SingleQuotedStyle|yaml.DoubleQuotedStyle) == 0 {
			n.Tag = "" // unquoted: resolve the type from the new value
		}
	}
	for _, c := range n.Content {
		expandEnv(c, missing)
	}
}

func (c *Config) setDefaults() {
	if c.DataDir == "" {
		c.DataDir = "./data"
	}
	if c.HTTP.Listen == "" {
		c.HTTP.Listen = ":8080"
	}
	if c.HTTP.TLS.Listen == "" {
		c.HTTP.TLS.Listen = ":8443"
	}
	if c.HTTP.TLS.ACME.DirectoryURL == "" {
		c.HTTP.TLS.ACME.DirectoryURL = "https://acme-v02.api.letsencrypt.org/directory"
	}
	if c.SSH.Listen == "" {
		c.SSH.Listen = ":2222"
	}
	if c.SSH.KeepaliveInterval == 0 {
		c.SSH.KeepaliveInterval = 30 * time.Second
	}
	if c.Auth.SessionTTL == 0 {
		c.Auth.SessionTTL = 7 * 24 * time.Hour
	}
	if c.Admin.Socket == "" {
		c.Admin.Socket = filepath.Join(c.DataDir, "admin.sock")
	}
	if c.Auth.Email.CodeTTL == 0 {
		c.Auth.Email.CodeTTL = 10 * time.Minute
	}
	if c.Auth.Email.SMTP.TLS == "" {
		c.Auth.Email.SMTP.TLS = "starttls"
	}
	if c.Auth.Email.SMTP.Port == 0 {
		switch c.Auth.Email.SMTP.TLS {
		case "tls":
			c.Auth.Email.SMTP.Port = 465
		case "none":
			c.Auth.Email.SMTP.Port = 25
		default:
			c.Auth.Email.SMTP.Port = 587
		}
	}
	if c.Limits.SubdomainsPerUser == 0 {
		c.Limits.SubdomainsPerUser = 10
	}
	if c.Limits.KeysPerSubdomain == 0 {
		c.Limits.KeysPerSubdomain = 20
	}
	if c.Limits.TunnelsPerConnection == 0 {
		c.Limits.TunnelsPerConnection = 5
	}
	for i := range c.Auth.Providers {
		p := &c.Auth.Providers[i]
		if p.Name == "" {
			switch p.Type {
			case "github":
				p.Name = "GitHub"
			default:
				p.Name = p.ID
			}
		}
	}
	c.Auth.AllowedEmails = lowerAll(c.Auth.AllowedEmails)
	c.Auth.AllowedDomains = lowerAll(c.Auth.AllowedDomains)
	c.Auth.Admins = lowerAll(c.Auth.Admins)
}

func (c *Config) resolvePaths(base string) {
	for _, p := range []*string{&c.DataDir, &c.HTTP.TLS.CertFile, &c.HTTP.TLS.KeyFile, &c.SSH.HostKeyFile, &c.Admin.Socket} {
		if *p != "" && !filepath.IsAbs(*p) {
			*p = filepath.Join(base, *p)
		}
	}
}

var providerID = regexp.MustCompile(`^[a-z0-9][a-z0-9_-]{0,31}$`)

func (c *Config) validate() error {
	if c.PublicURL == "" {
		return errors.New("public_url is required")
	}
	u, err := url.Parse(c.PublicURL)
	if err != nil {
		return fmt.Errorf("public_url: %w", err)
	}
	if u.Scheme != "http" && u.Scheme != "https" {
		return errors.New("public_url must start with http:// or https://")
	}
	if u.Hostname() == "" || (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.User != nil {
		return errors.New("public_url must be a bare origin like https://gate.example.com")
	}
	if net.ParseIP(u.Hostname()) != nil {
		return errors.New("public_url must use a hostname, not an IP address: tunnels live on its subdomains")
	}
	u.Path = ""
	u.Host = strings.ToLower(u.Host)
	c.publicURL = u

	tls := c.HTTP.TLS
	if (tls.CertFile == "") != (tls.KeyFile == "") {
		return errors.New("http.tls: cert_file and key_file must be set together")
	}
	if tls.CertFile != "" && tls.ACME.Enabled {
		return errors.New("http.tls: use either cert_file/key_file or acme, not both")
	}
	if tls.Enabled() && u.Scheme != "https" {
		return errors.New("public_url must use https:// when http.tls is enabled")
	}

	if !c.Auth.Email.Enabled() && len(c.Auth.Providers) == 0 {
		return errors.New("auth: configure email sign-in (auth.email.smtp) or at least one OAuth provider (auth.providers)")
	}
	if smtp := c.Auth.Email.SMTP; smtp.Host != "" {
		if c.Auth.Email.From == "" {
			return errors.New("auth.email.from is required to send sign-in codes")
		}
		if _, err := mail.ParseAddress(c.Auth.Email.From); err != nil {
			return fmt.Errorf("auth.email.from: %w", err)
		}
		switch smtp.TLS {
		case "starttls", "tls", "none":
		default:
			return errors.New("auth.email.smtp.tls must be starttls, tls or none")
		}
	}
	if c.Auth.Email.CodeTTL < time.Minute || c.Auth.Email.CodeTTL > time.Hour {
		return errors.New("auth.email.code_ttl must be between 1m and 1h")
	}
	seen := map[string]bool{}
	for i, p := range c.Auth.Providers {
		where := fmt.Sprintf("auth.providers[%d]", i)
		if !providerID.MatchString(p.ID) {
			return fmt.Errorf("%s.id must match %s", where, providerID)
		}
		if seen[p.ID] {
			return fmt.Errorf("%s: duplicate id %q", where, p.ID)
		}
		seen[p.ID] = true
		if p.ClientID == "" || p.ClientSecret == "" {
			return fmt.Errorf("%s: client_id and client_secret are required", where)
		}
		switch p.Type {
		case "github":
		case "oidc":
			if p.Issuer == "" {
				return fmt.Errorf("%s: issuer is required for oidc providers", where)
			}
		default:
			return fmt.Errorf("%s.type must be github or oidc", where)
		}
	}
	if !c.Auth.AllowEveryone && len(c.Auth.AllowedEmails)+len(c.Auth.AllowedDomains)+len(c.Auth.Admins) == 0 {
		return errors.New("auth: nobody can sign in; set admins, allowed_emails, allowed_domains or allow_everyone")
	}
	return nil
}

// PasskeysEnabled reports whether users can sign in with passkeys.
func (c *Config) PasskeysEnabled() bool { return !c.Auth.DisablePasskeys }

// Domain is the dashboard host without port; tunnels are its subdomains.
func (c *Config) Domain() string { return c.publicURL.Hostname() }

// Scheme is the scheme of the public URL, "http" or "https".
func (c *Config) Scheme() string { return c.publicURL.Scheme }

// Secure reports whether the public URL uses HTTPS.
func (c *Config) Secure() bool { return c.publicURL.Scheme == "https" }

// DashboardURL returns an absolute URL on the dashboard for path.
func (c *Config) DashboardURL(path string) string {
	return c.publicURL.Scheme + "://" + c.publicURL.Host + path
}

// TunnelHost returns the host (with port, if the public URL has one) that
// serves the given subdomain.
func (c *Config) TunnelHost(name string) string {
	h := name + "." + c.Domain()
	if p := c.publicURL.Port(); p != "" {
		h += ":" + p
	}
	return h
}

// TunnelURL returns the public URL of a subdomain.
func (c *Config) TunnelURL(name string) string {
	return c.publicURL.Scheme + "://" + c.TunnelHost(name)
}

// SSHHost is the host users connect to with ssh.
func (c *Config) SSHHost() string {
	if c.SSH.PublicHost != "" {
		return c.SSH.PublicHost
	}
	return c.Domain()
}

// SSHPort is the port users connect to with ssh.
func (c *Config) SSHPort() int {
	if c.SSH.PublicPort != 0 {
		return c.SSH.PublicPort
	}
	_, p, err := net.SplitHostPort(c.SSH.Listen)
	if err != nil {
		return 22
	}
	n, err := strconv.Atoi(p)
	if err != nil || n == 0 {
		return 22
	}
	return n
}

// IsAdmin reports whether email belongs to an administrator.
func (c *Config) IsAdmin(email string) bool {
	return contains(c.Auth.Admins, strings.ToLower(email))
}

// EmailAllowed reports whether a user with this (verified) email may sign
// in and keep using gate2sky.
func (c *Config) EmailAllowed(email string) bool {
	email = strings.ToLower(email)
	if email == "" {
		return false
	}
	if c.Auth.AllowEveryone || c.IsAdmin(email) || contains(c.Auth.AllowedEmails, email) {
		return true
	}
	at := strings.LastIndexByte(email, '@')
	return at >= 0 && contains(c.Auth.AllowedDomains, email[at+1:])
}

// UserRole is an account's role: "owner" for addresses in auth.admins,
// otherwise the one stored for it ("user", "admin" or "owner").
func (c *Config) UserRole(email, stored string) string {
	if c.IsAdmin(email) {
		return "owner"
	}
	if stored == "" {
		return "user"
	}
	return stored
}

// UserAllowed reports whether an account may sign in and keep using
// gate2sky: the configuration allows its email, or an administrator added
// it or gave it a role.
func (c *Config) UserAllowed(email string, added bool, stored string) bool {
	return added || c.UserRole(email, stored) != "user" || c.EmailAllowed(email)
}

func contains(list []string, v string) bool {
	for _, s := range list {
		if s == v {
			return true
		}
	}
	return false
}

func lowerAll(in []string) []string {
	out := make([]string, 0, len(in))
	for _, s := range in {
		if s = strings.ToLower(strings.TrimSpace(s)); s != "" {
			out = append(out, strings.TrimPrefix(s, "@"))
		}
	}
	return out
}

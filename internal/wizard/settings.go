package wizard

import (
	"fmt"
	"net"
	"net/mail"
	"net/url"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// TLS modes offered by the setup.
const (
	tlsACME  = "acme"
	tlsFiles = "files"
	tlsProxy = "proxy"
	tlsNone  = "none"
)

// Email sign-in modes.
const (
	// emailDashboard leaves email delivery to the dashboard's setup.
	emailDashboard = "dashboard"
	emailSMTP      = "smtp"
	emailLog       = "log"
	emailOff       = "off"
)

// settings are the server options the wizard edits.
type settings struct {
	PublicURL string
	DataDir   string

	TLSMode     string
	ACMEEmail   string
	CertFile    string
	KeyFile     string
	HTTPListen  string
	HTTPSListen string
	SSHListen   string

	Admins         string
	AllowedDomains string
	AllowedEmails  string
	AllowEveryone  bool

	EmailMode    string
	EmailFrom    string
	SMTPHost     string
	SMTPPort     string
	SMTPTLS      string
	SMTPUsername string
	SMTPPassword string

	Passkeys     bool
	GitHub       bool
	GitHubID     string
	GitHubSecret string
}

func joinList(l []string) string { return strings.Join(l, ", ") }

func splitList(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool { return r == ',' || r == ' ' || r == '\n' || r == ';' }) {
		if f = strings.TrimSpace(f); f != "" {
			out = append(out, f)
		}
	}
	return out
}

// load reads the current settings from d.
func (s *settings) load(d *doc) {
	s.PublicURL = d.str("public_url")
	s.DataDir = d.str("data_dir")
	s.HTTPListen = d.str("http", "listen")
	s.HTTPSListen = d.str("http", "tls", "listen")
	s.SSHListen = d.str("ssh", "listen")
	s.ACMEEmail = d.str("http", "tls", "acme", "email")
	s.CertFile = d.str("http", "tls", "cert_file")
	s.KeyFile = d.str("http", "tls", "key_file")
	switch {
	case d.boolean("http", "tls", "acme", "enabled"):
		s.TLSMode = tlsACME
	case s.CertFile != "":
		s.TLSMode = tlsFiles
	case strings.HasPrefix(s.PublicURL, "https://"):
		s.TLSMode = tlsProxy
	default:
		s.TLSMode = tlsNone
	}

	s.Admins = joinList(d.list("auth", "admins"))
	s.AllowedDomains = joinList(d.list("auth", "allowed_domains"))
	s.AllowedEmails = joinList(d.list("auth", "allowed_emails"))
	s.AllowEveryone = d.boolean("auth", "allow_everyone")

	s.EmailFrom = d.str("auth", "email", "from")
	s.SMTPHost = d.str("auth", "email", "smtp", "host")
	s.SMTPPort = d.str("auth", "email", "smtp", "port")
	s.SMTPTLS = d.str("auth", "email", "smtp", "tls")
	s.SMTPUsername = d.str("auth", "email", "smtp", "username")
	s.SMTPPassword = d.str("auth", "email", "smtp", "password")
	switch {
	case s.SMTPHost != "":
		s.EmailMode = emailSMTP
	case d.boolean("auth", "email", "log_only"):
		s.EmailMode = emailLog
	case d.value("auth", "email") == nil && d.value("auth", "providers") == nil:
		s.EmailMode = emailDashboard // a new configuration, or set up there
	default:
		s.EmailMode = emailOff
	}
	s.Passkeys = !d.boolean("auth", "disable_passkeys")
	if p := d.provider("github"); p != nil {
		s.GitHub = true
		s.GitHubID = mapStr(p, "client_id")
		s.GitHubSecret = mapStr(p, "client_secret")
	}
}

// defaultDataDir picks where data lives for a configuration file at path.
func defaultDataDir(path string) string {
	for _, env := range []string{"INTERGATE_DATA_DIR", "GATE2NET_DATA_DIR", "GATE2SKY_DATA_DIR"} {
		if d := os.Getenv(env); d != "" {
			return d
		}
	}
	if abs, err := filepath.Abs(path); err == nil && strings.HasPrefix(abs, "/etc/") {
		return "/var/lib/intergate"
	}
	return "data"
}

// fillDefaults sets defaults for empty fields that depend on the TLS mode.
func (s *settings) fillDefaults() {
	tls := s.TLSMode == tlsACME || s.TLSMode == tlsFiles
	if s.HTTPListen == "" {
		s.HTTPListen = ":8080"
		if tls {
			s.HTTPListen = ":80"
		} else if u, err := url.Parse(s.PublicURL); err == nil && u.Port() != "" && s.TLSMode == tlsNone {
			// Without a proxy in front, browsers connect to this port.
			s.HTTPListen = ":" + u.Port()
		}
	}
	if s.HTTPSListen == "" {
		s.HTTPSListen = ":443"
	}
	if s.SSHListen == "" {
		s.SSHListen = ":2222"
	}
	if s.SMTPPort == "" {
		s.SMTPPort = "587"
	}
	if s.SMTPTLS == "" {
		s.SMTPTLS = "starttls"
	}
	if s.EmailFrom == "" {
		if u, err := url.Parse(s.PublicURL); err == nil && u.Hostname() != "" {
			s.EmailFrom = "intergate <no-reply@" + u.Hostname() + ">"
		}
	}
	if s.ACMEEmail == "" {
		if admins := splitList(s.Admins); len(admins) > 0 {
			s.ACMEEmail = admins[0]
		}
	}
}

// apply writes the settings into d.
func (s *settings) apply(d *doc) {
	d.setStr(strings.TrimRight(strings.TrimSpace(s.PublicURL), "/"), "public_url")
	d.setStr(s.DataDir, "data_dir")
	d.setStr(s.HTTPListen, "http", "listen")
	d.setStr(s.SSHListen, "ssh", "listen")

	switch s.TLSMode {
	case tlsACME:
		d.setStr(s.HTTPSListen, "http", "tls", "listen")
		d.setBool(true, "http", "tls", "acme", "enabled")
		d.setStr(s.ACMEEmail, "http", "tls", "acme", "email")
		d.del("http", "tls", "cert_file")
		d.del("http", "tls", "key_file")
		d.del("http", "trust_proxy_headers")
	case tlsFiles:
		d.setStr(s.HTTPSListen, "http", "tls", "listen")
		d.setStr(s.CertFile, "http", "tls", "cert_file")
		d.setStr(s.KeyFile, "http", "tls", "key_file")
		d.del("http", "tls", "acme")
		d.del("http", "trust_proxy_headers")
	case tlsProxy:
		d.del("http", "tls")
		d.setBool(true, "http", "trust_proxy_headers")
	default:
		d.del("http", "tls")
		d.del("http", "trust_proxy_headers")
	}

	setOrDelList(d, splitList(s.Admins), "auth", "admins")
	setOrDelList(d, splitList(s.AllowedDomains), "auth", "allowed_domains")
	setOrDelList(d, splitList(s.AllowedEmails), "auth", "allowed_emails")
	if s.AllowEveryone {
		d.setBool(true, "auth", "allow_everyone")
	} else {
		d.del("auth", "allow_everyone")
	}

	switch s.EmailMode {
	case emailSMTP:
		d.setStr(s.EmailFrom, "auth", "email", "from")
		d.setStr(s.SMTPHost, "auth", "email", "smtp", "host")
		if port, err := strconv.Atoi(s.SMTPPort); err == nil {
			d.setInt(port, "auth", "email", "smtp", "port")
		}
		d.setStr(s.SMTPTLS, "auth", "email", "smtp", "tls")
		setOrDel(d, s.SMTPUsername, "auth", "email", "smtp", "username")
		setOrDel(d, s.SMTPPassword, "auth", "email", "smtp", "password")
		d.del("auth", "email", "log_only")
	case emailLog:
		d.del("auth", "email", "smtp")
		d.setBool(true, "auth", "email", "log_only")
	default:
		d.del("auth", "email")
	}
	if s.Passkeys {
		d.del("auth", "disable_passkeys")
	} else {
		d.setBool(true, "auth", "disable_passkeys")
	}
	if s.GitHub {
		d.setProvider("github", [][2]string{{"type", "github"}, {"client_id", s.GitHubID}, {"client_secret", s.GitHubSecret}})
	} else {
		d.delProvider("github")
	}
}

func setOrDel(d *doc, v string, path ...string) {
	if v == "" {
		d.del(path...)
		return
	}
	d.setStr(v, path...)
}

func setOrDelList(d *doc, v []string, path ...string) {
	if len(v) == 0 {
		d.del(path...)
		return
	}
	d.setList(v, path...)
}

func validateURL(s string) error {
	u, err := url.Parse(strings.TrimSpace(s))
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" || (u.Path != "" && u.Path != "/") {
		return fmt.Errorf("enter a URL like https://gate.example.com")
	}
	return nil
}

func validateEmails(required bool) func(string) error {
	return func(s string) error {
		list := splitList(s)
		if required && len(list) == 0 {
			return fmt.Errorf("enter at least one email address")
		}
		for _, e := range list {
			if a, err := mail.ParseAddress(e); err != nil || a.Address != e {
				return fmt.Errorf("%q is not an email address", e)
			}
		}
		return nil
	}
}

func validateListen(s string) error {
	_, port, err := net.SplitHostPort(strings.TrimSpace(s))
	n, perr := strconv.Atoi(port)
	if err != nil || perr != nil || n < 1 || n > 65535 {
		return fmt.Errorf("enter an address like :8080 or 0.0.0.0:8080")
	}
	return nil
}

func required(what string) func(string) error {
	return func(s string) error {
		if strings.TrimSpace(s) == "" {
			return fmt.Errorf("%s is required", what)
		}
		return nil
	}
}

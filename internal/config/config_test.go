package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const base = `
public_url: https://gate.example.com
ssh:
  listen: ":2222"
auth:
  admins: [Root@Example.com]
  allowed_domains: ["@corp.example"]
  providers:
    - id: github
      type: github
      client_id: id
      client_secret: ${TEST_SECRET}
`

func TestParse(t *testing.T) {
	t.Setenv("TEST_SECRET", "s3cr$t")
	cfg, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.Auth.Providers[0].ClientSecret; got != "s3cr$t" {
		t.Errorf("secret = %q", got)
	}
	if got := cfg.Auth.Providers[0].Name; got != "GitHub" {
		t.Errorf("default provider name = %q", got)
	}
	checks := map[string]string{
		cfg.Domain():                 "gate.example.com",
		cfg.DashboardURL("/x"):       "https://gate.example.com/x",
		cfg.TunnelURL("app"):         "https://app.gate.example.com",
		cfg.SSHHost():                "gate.example.com",
		cfg.Auth.AllowedDomains[0]:   "corp.example",
		cfg.HTTP.Listen:              ":8080",
		cfg.Auth.SessionTTL.String(): "168h0m0s",
	}
	for got, want := range checks {
		if got != want {
			t.Errorf("got %q, want %q", got, want)
		}
	}
	if cfg.SSHPort() != 2222 {
		t.Errorf("SSHPort = %d", cfg.SSHPort())
	}
}

func TestTunnelURLKeepsPort(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	cfg, err := Parse([]byte(strings.Replace(base, "https://gate.example.com", "http://localhost:8080", 1)))
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.TunnelURL("app"); got != "http://app.localhost:8080" {
		t.Errorf("TunnelURL = %q", got)
	}
	if cfg.Secure() {
		t.Error("http URL reported as secure")
	}
}

func TestEmailAllowed(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	cfg, err := Parse([]byte(base))
	if err != nil {
		t.Fatal(err)
	}
	for email, want := range map[string]bool{
		"root@example.com":     true,
		"ROOT@example.com":     true,
		"dev@corp.example":     true,
		"dev@evilcorp.example": false,
		"dev@corp.example.org": false,
		"":                     false,
	} {
		if got := cfg.EmailAllowed(email); got != want {
			t.Errorf("EmailAllowed(%q) = %v, want %v", email, got, want)
		}
	}
	if !cfg.IsAdmin("root@example.com") || cfg.IsAdmin("dev@corp.example") {
		t.Error("IsAdmin mismatch")
	}
}

func TestParseErrors(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	cases := map[string]string{
		"missing env":     strings.Replace(base, "TEST_SECRET", "SECUREGATE_UNSET_VAR", 1),
		"unknown field":   base + "bogus: 1\n",
		"ip public_url":   strings.Replace(base, "gate.example.com", "10.0.0.1", 1),
		"path public_url": strings.Replace(base, "gate.example.com", "gate.example.com/x", 1),
		"bad type":        strings.Replace(base, "type: github", "type: saml", 1),
		"tls without https": strings.Replace(base, "https://", "http://", 1) +
			"http:\n  tls:\n    cert_file: a\n    key_file: b\n",
		"nobody allowed": strings.Replace(strings.Replace(base, "admins: [Root@Example.com]", "", 1),
			`allowed_domains: ["@corp.example"]`, "", 1),
	}
	for name, doc := range cases {
		if _, err := Parse([]byte(doc)); err == nil {
			t.Errorf("%s: expected an error", name)
		}
	}
}

func TestExampleConfig(t *testing.T) {
	t.Setenv("GITHUB_CLIENT_ID", "id")
	t.Setenv("GITHUB_CLIENT_SECRET", "secret")
	if _, err := Load("../../securegate.example.yaml"); err != nil {
		t.Fatal(err)
	}
}

func TestEnvOnlyInValues(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	if _, err := Parse([]byte("# uses ${NOT_SET_ANYWHERE}\n" + base)); err != nil {
		t.Fatal(err)
	}
}

func TestEnvValues(t *testing.T) {
	t.Setenv("SSH_PORT", "2200")
	doc := strings.Replace(base, "ssh:\n", "ssh:\n  public_port: ${SSH_PORT}\n", 1)
	for _, secret := range []string{"a: b # c 'd\" ${X}", "123456", "true", "  spaced  ", "multi\nline"} {
		t.Setenv("TEST_SECRET", secret)
		cfg, err := Parse([]byte(doc))
		if err != nil {
			t.Errorf("%q: %v", secret, err)
			continue
		}
		if got := cfg.Auth.Providers[0].ClientSecret; got != secret {
			t.Errorf("secret = %q, want %q", got, secret)
		}
		if cfg.SSHPort() != 2200 {
			t.Errorf("port = %d", cfg.SSHPort())
		}
	}
}

func TestLoadResolvesRelativePaths(t *testing.T) {
	t.Setenv("TEST_SECRET", "x")
	dir := t.TempDir()
	path := filepath.Join(dir, "securegate.yaml")
	if err := os.WriteFile(path, []byte(base+"data_dir: state\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := Load(path)
	if err != nil {
		t.Fatal(err)
	}
	if want := filepath.Join(dir, "state"); cfg.DataDir != want || cfg.Admin.Socket != filepath.Join(want, "admin.sock") {
		t.Errorf("DataDir = %q, socket = %q; want under %q", cfg.DataDir, cfg.Admin.Socket, want)
	}
}

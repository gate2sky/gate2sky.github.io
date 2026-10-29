package sshd

import (
	"strings"
	"testing"

	"github.com/jgermade/intergate/internal/config"
	"github.com/jgermade/intergate/internal/store"
)

func TestPickGrant(t *testing.T) {
	one := []store.Grant{{Subdomain: "app"}}
	two := []store.Grant{{Subdomain: "api"}, {Subdomain: "app"}}
	cases := []struct {
		grants          []store.Grant
		requested, user string
		want, wantErr   string
	}{
		{one, "", "joshua", "app", ""},
		{one, "app", "", "app", ""},
		{one, "other", "", "", "not authorized"},
		{two, "", "app", "app", ""},
		{two, "", "joshua", "", "several subdomains (api, app)"},
		{two, "api", "app", "api", ""},
		{nil, "", "", "", "no longer registered"},
	}
	for _, c := range cases {
		g, err := pickGrant(c.grants, c.requested, c.user)
		if c.wantErr != "" {
			if err == nil || !strings.Contains(err.Error(), c.wantErr) {
				t.Errorf("pickGrant(%v, %q, %q) error = %v, want %q", c.grants, c.requested, c.user, err, c.wantErr)
			}
			continue
		}
		if err != nil || g.Subdomain != c.want {
			t.Errorf("pickGrant(%v, %q, %q) = %q, %v; want %q", c.grants, c.requested, c.user, g.Subdomain, err, c.want)
		}
	}
}

func TestParseBind(t *testing.T) {
	cfg, err := config.Parse([]byte("public_url: https://gate.example.com\nauth:\n  admins: [a@example.com]\n  email:\n    log_only: true\n"))
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{cfg: cfg}
	cases := []struct{ bind, port, sub, err string }{
		{"", "", "", ""},
		{"localhost", "", "", ""},
		{"MyApp", "", "myapp", ""},
		{"myapp.gate.example.com", "", "myapp", ""},
		{"db.myapp", "db", "myapp", ""},
		{"db.myapp.gate.example.com", "db", "myapp", ""},
		{"a.b.myapp", "", "", "not a subdomain"},
		{".myapp", "", "", "not a subdomain"},
		{"example.org", "", "", ""},
	}
	for _, c := range cases {
		port, sub, err := s.parseBind(c.bind)
		if c.err != "" {
			if err == nil || !strings.Contains(err.Error(), c.err) {
				t.Errorf("parseBind(%q) error = %v, want %q", c.bind, err, c.err)
			}
			continue
		}
		if c.bind == "example.org" {
			// Two labels: read as a port of a subdomain, which then
			// doesn't exist.
			if port != "example" || sub != "org" {
				t.Errorf("parseBind(%q) = %q, %q", c.bind, port, sub)
			}
			continue
		}
		if err != nil || port != c.port || sub != c.sub {
			t.Errorf("parseBind(%q) = %q, %q, %v; want %q, %q", c.bind, port, sub, err, c.port, c.sub)
		}
	}
}

package sshd

import (
	"strings"
	"testing"

	"github.com/gate2sky/gate2sky.github.io/internal/store"
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

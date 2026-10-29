// Package api holds the JSON shapes that both the dashboard's API and the
// admin socket answer with, and their conversions from stored records, so
// the browser and `gate2sky config` read the same thing.
package api

import (
	"time"

	"github.com/gate2sky/gate2sky.github.io/internal/config"
	"github.com/gate2sky/gate2sky.github.io/internal/store"
	"github.com/gate2sky/gate2sky.github.io/internal/tunnel"
)

// Subdomain is a registered subdomain and its live tunnel, if any.
type Subdomain struct {
	Name      string        `json:"name"`
	URL       string        `json:"url"`
	Owner     string        `json:"owner"`
	Access    store.Access  `json:"access"`
	Keys      int           `json:"keys"`
	CreatedAt time.Time     `json:"created_at"`
	Tunnel    *tunnel.Stats `json:"tunnel,omitempty"`
}

// NewSubdomain describes d; t is its tunnel, or nil when offline.
func NewSubdomain(cfg *config.Config, d *store.Subdomain, t *tunnel.Stats) Subdomain {
	return Subdomain{
		Name:      d.Name,
		URL:       cfg.TunnelURL(d.Name),
		Owner:     d.OwnerEmail,
		Access:    d.Access,
		Keys:      d.Keys,
		CreatedAt: d.CreatedAt,
		Tunnel:    t,
	}
}

// Key is an SSH key authorized on a subdomain.
type Key struct {
	ID          int64     `json:"id"`
	Name        string    `json:"name"`
	Type        string    `json:"type"`
	Fingerprint string    `json:"fingerprint"`
	CreatedAt   time.Time `json:"created_at"`
	LastUsedAt  time.Time `json:"last_used_at"`
}

// NewKey describes k, without the key itself.
func NewKey(k *store.Key) Key {
	return Key{ID: k.ID, Name: k.Name, Type: k.Type(), Fingerprint: k.Fingerprint, CreatedAt: k.CreatedAt, LastUsedAt: k.LastUsedAt}
}

// NewKeys describes keys; never nil, so it encodes as [].
func NewKeys(keys []*store.Key) []Key {
	out := make([]Key, len(keys))
	for i, k := range keys {
		out[i] = NewKey(k)
	}
	return out
}

// SubdomainDetail is a subdomain with its keys.
type SubdomainDetail struct {
	Subdomain
	KeyList []Key `json:"key_list"`
}

// User is an account.
type User struct {
	ID       int64  `json:"id"`
	Email    string `json:"email"`
	Name     string `json:"name"`
	Disabled bool   `json:"disabled"`
	Admin    bool   `json:"admin"`
	// ConfigAdmin is set when auth.admins makes the user an administrator,
	// which the dashboard cannot take away.
	ConfigAdmin bool      `json:"config_admin"`
	Allowed     bool      `json:"allowed"`
	Subdomains  int       `json:"subdomains"`
	Passkeys    int       `json:"passkeys"`
	Providers   string    `json:"providers"`
	LastLoginAt time.Time `json:"last_login_at"`
}

// NewUser describes u as an administrator sees it.
func NewUser(cfg *config.Config, u store.UserSummary) User {
	return User{
		ID: u.ID, Email: u.Email, Name: u.Name, Disabled: u.Disabled,
		Admin: cfg.UserAdmin(u.Email, u.Admin), ConfigAdmin: cfg.IsAdmin(u.Email), Allowed: cfg.UserAllowed(u.Email, u.Added, u.Admin),
		Subdomains: u.Subdomains, Passkeys: u.Passkeys, Providers: u.Providers, LastLoginAt: u.LastLoginAt,
	}
}

// KeysResult reports keys added in authorized_keys format: how many, and
// why the others were not.
type KeysResult struct {
	Added    int      `json:"added"`
	Problems []string `json:"problems,omitempty"`
}

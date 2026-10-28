// Package names validates subdomain names.
package names

import (
	"errors"
	"regexp"
	"strings"
)

var label = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)

// builtin are names that could be mistaken for the service itself or that
// commonly carry special meaning (mail, ACME, ...).
var builtin = []string{
	"_acme-challenge", "admin", "api", "app", "assets", "auth", "cdn", "dashboard",
	"docs", "ftp", "imap", "login", "mail", "mx", "ns", "ns1", "ns2", "oauth",
	"pop", "pop3", "root", "securegate", "smtp", "sso", "ssh", "static",
	"status", "support", "webmail", "www",
}

var (
	ErrInvalid  = errors.New("use 1-63 lowercase letters, digits or hyphens, not starting or ending with a hyphen")
	ErrPunycode = errors.New("internationalized (xn--) names are not allowed")
	ErrReserved = errors.New("this name is reserved")
)

// Checker validates subdomain names against syntax rules and a reserved list.
type Checker struct {
	reserved map[string]bool
}

// NewChecker returns a Checker that also rejects the extra names.
func NewChecker(extra []string) *Checker {
	c := &Checker{reserved: map[string]bool{}}
	for _, n := range append(builtin, extra...) {
		c.reserved[Normalize(n)] = true
	}
	return c
}

// Normalize lowercases and trims a user-provided name.
func Normalize(s string) string { return strings.ToLower(strings.TrimSpace(s)) }

// Check returns nil if name (already normalized) can be registered.
func (c *Checker) Check(name string) error {
	if !label.MatchString(name) {
		return ErrInvalid
	}
	if strings.HasPrefix(name, "xn--") {
		return ErrPunycode
	}
	if c.reserved[name] {
		return ErrReserved
	}
	return nil
}

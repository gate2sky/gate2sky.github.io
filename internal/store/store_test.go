package store

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func openTest(t *testing.T) *Store {
	t.Helper()
	s, err := Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { s.Close() })
	return s
}

func newKey(t *testing.T) ssh.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ssh.NewPublicKey(pub)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func TestUsersAndSessions(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u, err := s.CreateUser(ctx, " A@X.com ", "A")
	if err != nil || u.Email != "a@x.com" || len(u.WebAuthnID) != 32 {
		t.Fatalf("CreateUser = %+v, %v", u, err)
	}
	if _, err := s.CreateUser(ctx, "a@x.com", ""); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate email: %v", err)
	}
	if again, err := s.EnsureUser(ctx, "A@x.com"); err != nil || again.ID != u.ID {
		t.Fatalf("EnsureUser = %+v, %v", again, err)
	}
	if byHandle, err := s.UserByWebAuthnID(ctx, u.WebAuthnID); err != nil || byHandle.ID != u.ID {
		t.Fatalf("UserByWebAuthnID = %+v, %v", byHandle, err)
	}

	token, sess, err := s.CreateSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, gotUser, err := s.SessionByToken(ctx, token)
	if err != nil || got.ID != sess.ID || gotUser.ID != u.ID || got.CSRFToken == "" || gotUser.LastLoginAt.IsZero() {
		t.Fatalf("SessionByToken = %+v, %+v, %v", got, gotUser, err)
	}
	if _, _, err := s.SessionByToken(ctx, token+"x"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("wrong token: %v", err)
	}
	if _, _, err := s.SessionByID(ctx, sess.ID); err != nil {
		t.Fatal(err)
	}

	// Disabling a user ends their sessions.
	if err := s.SetUserDisabled(ctx, u.ID, true); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.SessionByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("session survived disabling: %v", err)
	}

	// Expired sessions are not returned.
	s.SetUserDisabled(ctx, u.ID, false)
	token, _, _ = s.CreateSession(ctx, u.ID, time.Hour)
	s.now = func() time.Time { return time.Now().Add(2 * time.Hour) }
	if _, _, err := s.SessionByToken(ctx, token); !errors.Is(err, ErrNotFound) {
		t.Fatalf("expired session returned: %v", err)
	}
}

func TestLoginOAuthLinksByEmail(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	existing, _ := s.CreateUser(ctx, "dev@x.com", "")

	// A new identity with a known email joins that account and fills in
	// missing profile details.
	u, err := s.LoginOAuth(ctx, Identity{Provider: "github", Subject: "42", Email: "DEV@x.com", Name: "Dev", Username: "dev", AvatarURL: "https://a/x.png"})
	if err != nil || u.ID != existing.ID || u.Name != "Dev" || u.AvatarURL != "https://a/x.png" {
		t.Fatalf("LoginOAuth = %+v, %v", u, err)
	}
	// The identity stays linked even if the provider's email changes.
	u2, err := s.LoginOAuth(ctx, Identity{Provider: "github", Subject: "42", Email: "other@x.com", Name: "Renamed"})
	if err != nil || u2.ID != existing.ID || u2.Name != "Dev" {
		t.Fatalf("second LoginOAuth = %+v, %v", u2, err)
	}
	// Unknown identity and email: a new account.
	u3, err := s.LoginOAuth(ctx, Identity{Provider: "google", Subject: "g1", Email: "new@x.com"})
	if err != nil || u3.ID == existing.ID || u3.Email != "new@x.com" {
		t.Fatalf("new LoginOAuth = %+v, %v", u3, err)
	}
	users, _ := s.ListUsers(ctx)
	if len(users) != 2 {
		t.Fatalf("users = %+v", users)
	}
	for _, us := range users {
		if us.ID == existing.ID && us.Providers != "github" {
			t.Errorf("providers = %q", us.Providers)
		}
	}
}

func TestPasskeys(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u, _ := s.CreateUser(ctx, "a@x.com", "")
	other, _ := s.CreateUser(ctx, "b@x.com", "")
	p, err := s.AddPasskey(ctx, u.ID, "laptop", []byte("cred-1"), []byte(`{"v":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddPasskey(ctx, other.ID, "dup", []byte("cred-1"), []byte("{}")); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate credential: %v", err)
	}
	if err := s.UpdatePasskeyUse(ctx, []byte("cred-1"), []byte(`{"v":2}`)); err != nil {
		t.Fatal(err)
	}
	list, err := s.PasskeysByUser(ctx, u.ID)
	if err != nil || len(list) != 1 || string(list[0].Credential) != `{"v":2}` || list[0].LastUsedAt.IsZero() {
		t.Fatalf("PasskeysByUser = %+v, %v", list, err)
	}
	if err := s.RenamePasskey(ctx, other.ID, p.ID, "stolen"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("renamed another user's passkey: %v", err)
	}
	if err := s.RenamePasskey(ctx, u.ID, p.ID, "work laptop"); err != nil {
		t.Fatal(err)
	}
	if list, _ := s.PasskeysByUser(ctx, u.ID); list[0].Name != "work laptop" {
		t.Fatalf("name after rename = %q", list[0].Name)
	}
	if err := s.DeletePasskey(ctx, other.ID, p.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted another user's passkey: %v", err)
	}
	if err := s.DeletePasskey(ctx, u.ID, p.ID); err != nil {
		t.Fatal(err)
	}
}

func TestSubdomainsAndGrants(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	alice, _ := s.CreateUser(ctx, "alice@x.com", "")
	bob, _ := s.CreateUser(ctx, "bob@x.com", "")

	app, err := s.CreateSubdomain(ctx, alice.ID, "app", AccessPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.CreateSubdomain(ctx, bob.ID, "app", AccessPublic); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate name: %v", err)
	}
	api, _ := s.CreateSubdomain(ctx, bob.ID, "api", AccessPublic)

	shared := newKey(t)
	k1, err := s.AddKey(ctx, app.ID, "laptop", shared)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := s.AddKey(ctx, app.ID, "again", shared); !errors.Is(err, ErrConflict) {
		t.Fatalf("duplicate key: %v", err)
	}
	// The same key may be authorized on several subdomains.
	if _, err := s.AddKey(ctx, api.ID, "ci", shared); err != nil {
		t.Fatal(err)
	}

	grants, err := s.GrantsForKey(ctx, ssh.FingerprintSHA256(shared))
	if err != nil || len(grants) != 2 {
		t.Fatalf("grants = %+v, %v", grants, err)
	}
	if grants[0].Subdomain != "api" || grants[1].Subdomain != "app" || grants[1].Access != AccessPrivate || grants[1].OwnerEmail != "alice@x.com" {
		t.Fatalf("unexpected grants %+v", grants)
	}

	// Disabled owners grant nothing.
	s.SetUserDisabled(ctx, bob.ID, true)
	grants, _ = s.GrantsForKey(ctx, ssh.FingerprintSHA256(shared))
	if len(grants) != 1 || grants[0].Subdomain != "app" {
		t.Fatalf("grants after disabling bob = %+v", grants)
	}

	if d, _ := s.SubdomainByName(ctx, "app"); d.Keys != 1 {
		t.Fatalf("key count = %d", d.Keys)
	}
	if err := s.SetSubdomainAccess(ctx, app.ID, AccessUsers); err != nil {
		t.Fatal(err)
	}
	if _, err := s.DeleteKey(ctx, api.ID, k1.ID); !errors.Is(err, ErrNotFound) {
		t.Fatalf("deleted a key through another subdomain: %v", err)
	}
	if err := s.RenameKey(ctx, api.ID, k1.ID, "stolen"); !errors.Is(err, ErrNotFound) {
		t.Fatalf("renamed a key through another subdomain: %v", err)
	}
	if err := s.RenameKey(ctx, app.ID, k1.ID, "work laptop"); err != nil {
		t.Fatal(err)
	}
	if k, err := s.DeleteKey(ctx, app.ID, k1.ID); err != nil || k.Name != "work laptop" {
		t.Fatalf("DeleteKey = %+v, %v", k, err)
	}

	// Deleting a subdomain removes its keys.
	if err := s.DeleteSubdomain(ctx, api.ID); err != nil {
		t.Fatal(err)
	}
	if grants, _ := s.GrantsForKey(ctx, ssh.FingerprintSHA256(shared)); len(grants) != 0 {
		t.Fatalf("grants after delete = %+v", grants)
	}
	users, err := s.ListUsers(ctx)
	if err != nil || len(users) != 2 {
		t.Fatalf("ListUsers = %+v, %v", users, err)
	}
}

func TestPorts(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	u, _ := s.CreateUser(ctx, "a@x.com", "")
	app, _ := s.CreateSubdomain(ctx, u.ID, "app", AccessPublic)
	db, _ := s.CreateSubdomain(ctx, u.ID, "db", AccessPublic)

	add := func(d *Subdomain, name string) (*Port, error) {
		p := &Port{SubdomainID: d.ID, Name: name, Allow: []string{"10.0.0.0/8", "192.0.2.1/32"}, Preset: "postgresql", LocalPort: 5432}
		return p, s.CreatePort(ctx, p, 30000, 30002)
	}
	p1, err := add(app, "pg")
	if err != nil || p1.Port != 30000 || p1.Protocol != ProtocolTCP {
		t.Fatalf("first port = %+v, %v", p1, err)
	}
	if _, err := add(app, "pg"); !errors.Is(err, ErrConflict) {
		t.Errorf("duplicate name: %v", err)
	}
	p2, _ := add(db, "pg")
	p3, _ := add(app, "ssh")
	if p2.Port != 30001 || p3.Port != 30002 {
		t.Errorf("ports %d, %d", p2.Port, p3.Port)
	}
	if _, err := add(db, "full"); !errors.Is(err, ErrFull) {
		t.Errorf("full range: %v", err)
	}

	// A deleted port's number is reused; the others keep theirs.
	if err := s.DeletePort(ctx, app.ID, p1.ID); err != nil {
		t.Fatal(err)
	}
	if err := s.DeletePort(ctx, app.ID, p2.ID); !errors.Is(err, ErrNotFound) {
		t.Errorf("deleted another subdomain's port: %v", err)
	}
	p4, err := add(db, "redis")
	if err != nil || p4.Port != 30000 {
		t.Fatalf("reused port = %+v, %v", p4, err)
	}

	got, err := s.PortByNumber(ctx, 30000)
	if err != nil || got.Subdomain != "db" || got.Name != "redis" || got.OwnerID != u.ID || len(got.Allow) != 2 || got.LocalPort != 5432 {
		t.Fatalf("PortByNumber = %+v, %v", got, err)
	}
	got.Name, got.Allow, got.LocalPort = "cache", nil, 6379
	if err := s.UpdatePort(ctx, got); err != nil {
		t.Fatal(err)
	}
	got.Name = "pg"
	if err := s.UpdatePort(ctx, got); !errors.Is(err, ErrConflict) {
		t.Errorf("rename to a taken name: %v", err)
	}
	list, _ := s.PortsBySubdomain(ctx, db.ID)
	if len(list) != 2 || list[0].Name != "cache" || len(list[0].Allow) != 0 || list[0].LocalPort != 6379 || list[1].Name != "pg" {
		t.Errorf("PortsBySubdomain = %+v %+v", list[0], list[1])
	}
	if d, _ := s.SubdomainByName(ctx, "db"); d.Ports != 2 {
		t.Errorf("port count = %d", d.Ports)
	}

	// Ports go with their subdomain.
	if err := s.DeleteSubdomain(ctx, db.ID); err != nil {
		t.Fatal(err)
	}
	if _, err := s.PortByNumber(ctx, 30001); !errors.Is(err, ErrNotFound) {
		t.Errorf("port of a deleted subdomain: %v", err)
	}
}

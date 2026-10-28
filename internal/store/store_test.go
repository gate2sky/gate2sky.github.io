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
	u, err := s.UpsertUser(ctx, Identity{Provider: "gh", Subject: "1", Email: "a@x.com", Name: "A"})
	if err != nil {
		t.Fatal(err)
	}
	u2, err := s.UpsertUser(ctx, Identity{Provider: "gh", Subject: "1", Email: "new@x.com"})
	if err != nil {
		t.Fatal(err)
	}
	if u2.ID != u.ID || u2.Email != "new@x.com" {
		t.Fatalf("upsert did not update the same user: %+v", u2)
	}

	token, sess, err := s.CreateSession(ctx, u.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	got, gotUser, err := s.SessionByToken(ctx, token)
	if err != nil || got.ID != sess.ID || gotUser.ID != u.ID || got.CSRFToken == "" {
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

func TestSubdomainsAndGrants(t *testing.T) {
	ctx := context.Background()
	s := openTest(t)
	alice, _ := s.UpsertUser(ctx, Identity{Provider: "gh", Subject: "1", Email: "alice@x.com"})
	bob, _ := s.UpsertUser(ctx, Identity{Provider: "gh", Subject: "2", Email: "bob@x.com"})

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
	if k, err := s.DeleteKey(ctx, app.ID, k1.ID); err != nil || k.Name != "laptop" {
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

package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/base64"
	"errors"
	"strings"
	"time"
)

// User is an account, identified by a verified email address. Users sign in
// with a code sent to that address, a passkey, or a linked OAuth identity.
type User struct {
	ID         int64
	Email      string
	Name       string
	AvatarURL  string
	WebAuthnID []byte
	Disabled   bool
	// Added is set for accounts an administrator added: they may sign in
	// whatever auth.allowed_* says. Role is the one given from the
	// dashboard; auth.admins makes owners whatever it says.
	Added       bool
	Role        Role
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// Role is what a user may do. Admins manage every subdomain and account but
// owners'; owners manage everything.
type Role string

const (
	RoleUser  Role = "user"
	RoleAdmin Role = "admin"
	RoleOwner Role = "owner"
)

// Valid reports whether r is a known role.
func (r Role) Valid() bool { return r == RoleUser || r == RoleAdmin || r == RoleOwner }

// DisplayName is the best human-readable name for the user.
func (u *User) DisplayName() string {
	if u.Name != "" {
		return u.Name
	}
	return u.Email
}

// Identity is what an OAuth provider tells us about a user.
type Identity struct {
	Provider  string
	Subject   string
	Email     string
	Name      string
	Username  string
	AvatarURL string
}

const userColumns = `id, email, name, avatar_url, webauthn_id, disabled, added, role, created_at, last_login_at`

type scanner interface{ Scan(dest ...any) error }

func scanUser(row scanner) (*User, error) {
	var u User
	var created, lastLogin int64
	if err := row.Scan(&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.WebAuthnID, &u.Disabled, &u.Added, &u.Role, &created, &lastLogin); err != nil {
		return nil, notFound(err)
	}
	u.CreatedAt, u.LastLoginAt = fromUnix(created), fromUnix(lastLogin)
	return &u, nil
}

// NormalizeEmail lowercases and trims an email address.
func NormalizeEmail(email string) string { return strings.ToLower(strings.TrimSpace(email)) }

func newWebAuthnID() []byte {
	b := make([]byte, 32)
	rand.Read(b)
	return b
}

type execer interface {
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

func (s *Store) createUser(ctx context.Context, db execer, email, name, avatar string) (*User, error) {
	u, err := scanUser(db.QueryRowContext(ctx, `
		INSERT INTO users (email, name, avatar_url, webauthn_id, created_at) VALUES (?, ?, ?, ?, ?)
		RETURNING `+userColumns,
		NormalizeEmail(email), name, avatar, newWebAuthnID(), unix(s.now())))
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	return u, err
}

// CreateUser adds an account for a (verified) email address. It returns
// ErrConflict if one exists.
func (s *Store) CreateUser(ctx context.Context, email, name string) (*User, error) {
	return s.createUser(ctx, s.db, email, name, "")
}

// EnsureUser returns the account for email, creating it if needed.
func (s *Store) EnsureUser(ctx context.Context, email string) (*User, error) {
	u, err := s.UserByEmail(ctx, email)
	if errors.Is(err, ErrNotFound) {
		u, err = s.CreateUser(ctx, email, "")
		if errors.Is(err, ErrConflict) {
			return s.UserByEmail(ctx, email)
		}
	}
	return u, err
}

// UserByID returns a user.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// UserByEmail returns the user with this email address.
func (s *Store) UserByEmail(ctx context.Context, email string) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE email = ?`, NormalizeEmail(email)))
}

// UserByWebAuthnID returns the user with this WebAuthn user handle.
func (s *Store) UserByWebAuthnID(ctx context.Context, id []byte) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE webauthn_id = ?`, id))
}

// LoginOAuth returns the user for an OAuth identity. A new identity is
// linked to the account with the same (verified) email, or to a new one.
func (s *Store) LoginOAuth(ctx context.Context, id Identity) (*User, error) {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return nil, err
	}
	defer tx.Rollback()
	var userID int64
	err = tx.QueryRowContext(ctx, `SELECT user_id FROM identities WHERE provider = ? AND subject = ?`, id.Provider, id.Subject).Scan(&userID)
	switch {
	case err == nil:
		if _, err := tx.ExecContext(ctx, `UPDATE identities SET username = ? WHERE provider = ? AND subject = ?`, id.Username, id.Provider, id.Subject); err != nil {
			return nil, err
		}
	case errors.Is(err, sql.ErrNoRows):
		u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE email = ?`, NormalizeEmail(id.Email)))
		if errors.Is(err, ErrNotFound) {
			u, err = s.createUser(ctx, tx, id.Email, id.Name, id.AvatarURL)
		}
		if err != nil {
			return nil, err
		}
		userID = u.ID
		if _, err := tx.ExecContext(ctx, `INSERT INTO identities (provider, subject, user_id, username, created_at) VALUES (?, ?, ?, ?, ?)`,
			id.Provider, id.Subject, userID, id.Username, unix(s.now())); err != nil {
			return nil, err
		}
	default:
		return nil, err
	}
	// Fill in profile details the user doesn't have yet.
	if _, err := tx.ExecContext(ctx, `
		UPDATE users SET
			name = CASE WHEN name = '' THEN ? ELSE name END,
			avatar_url = CASE WHEN ? != '' THEN ? ELSE avatar_url END
		WHERE id = ?`, id.Name, id.AvatarURL, id.AvatarURL, userID); err != nil {
		return nil, err
	}
	u, err := scanUser(tx.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, userID))
	if err != nil {
		return nil, err
	}
	return u, tx.Commit()
}

// UserSummary is a user plus counts for the admin views.
type UserSummary struct {
	User
	Subdomains int
	Passkeys   int
	Providers  string
}

// ListUsers returns every user, most recently active first.
func (s *Store) ListUsers(ctx context.Context) ([]UserSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+userColumns+`,
			(SELECT COUNT(*) FROM subdomains d WHERE d.user_id = users.id),
			(SELECT COUNT(*) FROM passkeys p WHERE p.user_id = users.id),
			COALESCE((SELECT GROUP_CONCAT(provider, ', ') FROM identities i WHERE i.user_id = users.id), '')
		FROM users ORDER BY last_login_at DESC, id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserSummary
	for rows.Next() {
		var us UserSummary
		var created, lastLogin int64
		if err := rows.Scan(&us.ID, &us.Email, &us.Name, &us.AvatarURL, &us.WebAuthnID, &us.Disabled, &us.Added, &us.Role, &created, &lastLogin,
			&us.Subdomains, &us.Passkeys, &us.Providers); err != nil {
			return nil, err
		}
		us.CreatedAt, us.LastLoginAt = fromUnix(created), fromUnix(lastLogin)
		out = append(out, us)
	}
	return out, rows.Err()
}

// TouchLogin records a successful sign-in.
func (s *Store) TouchLogin(ctx context.Context, userID int64) error {
	_, err := s.db.ExecContext(ctx, `UPDATE users SET last_login_at = ? WHERE id = ?`, unix(s.now()), userID)
	return err
}

// SetUserDisabled blocks or unblocks a user. Disabling also ends their
// sessions.
func (s *Store) SetUserDisabled(ctx context.Context, id int64, disabled bool) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	res, err := tx.ExecContext(ctx, `UPDATE users SET disabled = ? WHERE id = ?`, disabled, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	if disabled {
		if _, err := tx.ExecContext(ctx, `DELETE FROM sessions WHERE user_id = ?`, id); err != nil {
			return err
		}
	}
	return tx.Commit()
}

// DeleteUser removes an account with everything it owns: subdomains and
// their keys, passkeys, linked identities and sessions.
func (s *Store) DeleteUser(ctx context.Context, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM users WHERE id = ?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// HasManagers reports whether an enabled account is an owner or an admin.
func (s *Store) HasManagers(ctx context.Context) (bool, error) {
	var ok bool
	err := s.db.QueryRowContext(ctx, `SELECT EXISTS(SELECT 1 FROM users WHERE role IN (?, ?) AND disabled = 0)`, RoleOwner, RoleAdmin).Scan(&ok)
	return ok, err
}

// SetUserAdded records that an administrator added the user, which lets
// them sign in whatever auth.allowed_* says.
func (s *Store) SetUserAdded(ctx context.Context, id int64) error {
	return s.setUser(ctx, id, "added", true)
}

// SetUserRole changes a user's role. auth.admins still makes its addresses
// owners whatever it is.
func (s *Store) SetUserRole(ctx context.Context, id int64, role Role) error {
	return s.setUser(ctx, id, "role", role)
}

func (s *Store) setUser(ctx context.Context, id int64, column string, v any) error {
	res, err := s.db.ExecContext(ctx, `UPDATE users SET `+column+` = ? WHERE id = ?`, v, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Passkey is a WebAuthn credential. Credential holds the library's
// serialized credential record; the store treats it as opaque.
type Passkey struct {
	ID           int64
	UserID       int64
	CredentialID []byte
	Name         string
	Credential   []byte
	CreatedAt    time.Time
	LastUsedAt   time.Time
}

// AddPasskey stores a new credential for a user.
func (s *Store) AddPasskey(ctx context.Context, userID int64, name string, credentialID, credential []byte) (*Passkey, error) {
	p := &Passkey{UserID: userID, CredentialID: credentialID, Name: name, Credential: credential, CreatedAt: s.now().Truncate(time.Second)}
	err := s.db.QueryRowContext(ctx, `
		INSERT INTO passkeys (user_id, credential_id, name, credential, created_at) VALUES (?, ?, ?, ?, ?) RETURNING id`,
		userID, credentialID, name, credential, unix(p.CreatedAt)).Scan(&p.ID)
	if isUniqueViolation(err) {
		return nil, ErrConflict
	}
	if err != nil {
		return nil, err
	}
	return p, nil
}

// PasskeysByUser lists a user's passkeys, oldest first.
func (s *Store) PasskeysByUser(ctx context.Context, userID int64) ([]*Passkey, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT id, user_id, credential_id, name, credential, created_at, last_used_at
		FROM passkeys WHERE user_id = ? ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Passkey
	for rows.Next() {
		var p Passkey
		var created, used int64
		if err := rows.Scan(&p.ID, &p.UserID, &p.CredentialID, &p.Name, &p.Credential, &created, &used); err != nil {
			return nil, err
		}
		p.CreatedAt, p.LastUsedAt = fromUnix(created), fromUnix(used)
		out = append(out, &p)
	}
	return out, rows.Err()
}

// UpdatePasskeyUse stores the credential record after a successful
// sign-in (it carries the authenticator's signature counter).
func (s *Store) UpdatePasskeyUse(ctx context.Context, credentialID, credential []byte) error {
	_, err := s.db.ExecContext(ctx, `UPDATE passkeys SET credential = ?, last_used_at = ? WHERE credential_id = ?`,
		credential, unix(s.now()), credentialID)
	return err
}

// RenamePasskey changes the name of one of a user's passkeys.
func (s *Store) RenamePasskey(ctx context.Context, userID, id int64, name string) error {
	res, err := s.db.ExecContext(ctx, `UPDATE passkeys SET name = ? WHERE id = ? AND user_id = ?`, name, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// DeletePasskey removes one of a user's passkeys.
func (s *Store) DeletePasskey(ctx context.Context, userID, id int64) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM passkeys WHERE id = ? AND user_id = ?`, id, userID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Session is a signed-in browser.
type Session struct {
	ID        string
	UserID    int64
	CSRFToken string
	CreatedAt time.Time
	ExpiresAt time.Time
}

func randomToken(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func hashToken(token string) []byte {
	h := sha256.Sum256([]byte(token))
	return h[:]
}

// CreateSession starts a session and returns its secret cookie token. Only
// a hash of the token is stored.
func (s *Store) CreateSession(ctx context.Context, userID int64, ttl time.Duration) (string, *Session, error) {
	now := s.now()
	token := randomToken(32)
	sess := &Session{
		ID:        randomToken(16),
		UserID:    userID,
		CSRFToken: randomToken(32),
		CreatedAt: now.Truncate(time.Second),
		ExpiresAt: now.Add(ttl).Truncate(time.Second),
	}
	_, err := s.db.ExecContext(ctx, `
		INSERT INTO sessions (id, token_hash, user_id, csrf_token, created_at, expires_at)
		VALUES (?, ?, ?, ?, ?, ?)`,
		sess.ID, hashToken(token), userID, sess.CSRFToken, unix(sess.CreatedAt), unix(sess.ExpiresAt))
	if err != nil {
		return "", nil, err
	}
	if err := s.TouchLogin(ctx, userID); err != nil {
		return "", nil, err
	}
	return token, sess, nil
}

const sessionUserQuery = `
	SELECT s.id, s.user_id, s.csrf_token, s.created_at, s.expires_at,
		u.id, u.email, u.name, u.avatar_url, u.webauthn_id, u.disabled, u.added, u.role, u.created_at, u.last_login_at
	FROM sessions s JOIN users u ON u.id = s.user_id `

func (s *Store) scanSessionUser(row scanner) (*Session, *User, error) {
	var sess Session
	var u User
	var sCreated, sExpires, uCreated, uLogin int64
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &sCreated, &sExpires,
		&u.ID, &u.Email, &u.Name, &u.AvatarURL, &u.WebAuthnID, &u.Disabled, &u.Added, &u.Role, &uCreated, &uLogin); err != nil {
		return nil, nil, notFound(err)
	}
	sess.CreatedAt, sess.ExpiresAt = fromUnix(sCreated), fromUnix(sExpires)
	u.CreatedAt, u.LastLoginAt = fromUnix(uCreated), fromUnix(uLogin)
	if !s.now().Before(sess.ExpiresAt) || u.Disabled {
		return nil, nil, ErrNotFound
	}
	return &sess, &u, nil
}

// SessionByToken looks up a live session by its cookie token.
func (s *Store) SessionByToken(ctx context.Context, token string) (*Session, *User, error) {
	return s.scanSessionUser(s.db.QueryRowContext(ctx, sessionUserQuery+`WHERE s.token_hash = ?`, hashToken(token)))
}

// SessionByID looks up a live session by its public ID.
func (s *Store) SessionByID(ctx context.Context, id string) (*Session, *User, error) {
	return s.scanSessionUser(s.db.QueryRowContext(ctx, sessionUserQuery+`WHERE s.id = ?`, id))
}

// DeleteSession ends a session.
func (s *Store) DeleteSession(ctx context.Context, id string) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE id = ?`, id)
	return err
}

// DeleteExpiredSessions removes sessions past their expiry.
func (s *Store) DeleteExpiredSessions(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `DELETE FROM sessions WHERE expires_at <= ?`, unix(s.now()))
	return err
}

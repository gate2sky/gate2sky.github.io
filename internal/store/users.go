package store

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"time"
)

// User is an account created on first OAuth sign-in.
type User struct {
	ID          int64
	Provider    string
	Subject     string
	Email       string
	Name        string
	Username    string
	AvatarURL   string
	Disabled    bool
	CreatedAt   time.Time
	LastLoginAt time.Time
}

// DisplayName is the best human-readable name for the user.
func (u *User) DisplayName() string {
	switch {
	case u.Name != "":
		return u.Name
	case u.Username != "":
		return u.Username
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

const userColumns = `id, provider, subject, email, name, username, avatar_url, disabled, created_at, last_login_at`

type scanner interface{ Scan(dest ...any) error }

func scanUser(row scanner) (*User, error) {
	var u User
	var created, lastLogin int64
	if err := row.Scan(&u.ID, &u.Provider, &u.Subject, &u.Email, &u.Name, &u.Username,
		&u.AvatarURL, &u.Disabled, &created, &lastLogin); err != nil {
		return nil, notFound(err)
	}
	u.CreatedAt, u.LastLoginAt = fromUnix(created), fromUnix(lastLogin)
	return &u, nil
}

// UpsertUser creates the user for this identity, or refreshes its profile.
func (s *Store) UpsertUser(ctx context.Context, id Identity) (*User, error) {
	now := unix(s.now())
	row := s.db.QueryRowContext(ctx, `
		INSERT INTO users (provider, subject, email, name, username, avatar_url, created_at, last_login_at)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?)
		ON CONFLICT (provider, subject) DO UPDATE SET
			email = excluded.email, name = excluded.name, username = excluded.username,
			avatar_url = excluded.avatar_url, last_login_at = excluded.last_login_at
		RETURNING `+userColumns,
		id.Provider, id.Subject, id.Email, id.Name, id.Username, id.AvatarURL, now, now)
	return scanUser(row)
}

// UserByID returns a user.
func (s *Store) UserByID(ctx context.Context, id int64) (*User, error) {
	return scanUser(s.db.QueryRowContext(ctx, `SELECT `+userColumns+` FROM users WHERE id = ?`, id))
}

// UserSummary is a user plus the number of subdomains they own.
type UserSummary struct {
	User
	Subdomains int
}

// ListUsers returns every user, most recently active first.
func (s *Store) ListUsers(ctx context.Context) ([]UserSummary, error) {
	rows, err := s.db.QueryContext(ctx, `
		SELECT `+userColumns+`, (SELECT COUNT(*) FROM subdomains d WHERE d.user_id = users.id)
		FROM users ORDER BY last_login_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []UserSummary
	for rows.Next() {
		var us UserSummary
		var created, lastLogin int64
		if err := rows.Scan(&us.ID, &us.Provider, &us.Subject, &us.Email, &us.Name, &us.Username,
			&us.AvatarURL, &us.Disabled, &created, &lastLogin, &us.Subdomains); err != nil {
			return nil, err
		}
		us.CreatedAt, us.LastLoginAt = fromUnix(created), fromUnix(lastLogin)
		out = append(out, us)
	}
	return out, rows.Err()
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
	return token, sess, nil
}

const sessionUserQuery = `
	SELECT s.id, s.user_id, s.csrf_token, s.created_at, s.expires_at,
		u.id, u.provider, u.subject, u.email, u.name, u.username, u.avatar_url, u.disabled, u.created_at, u.last_login_at
	FROM sessions s JOIN users u ON u.id = s.user_id `

func (s *Store) scanSessionUser(row scanner) (*Session, *User, error) {
	var sess Session
	var u User
	var sCreated, sExpires, uCreated, uLogin int64
	if err := row.Scan(&sess.ID, &sess.UserID, &sess.CSRFToken, &sCreated, &sExpires,
		&u.ID, &u.Provider, &u.Subject, &u.Email, &u.Name, &u.Username, &u.AvatarURL, &u.Disabled, &uCreated, &uLogin); err != nil {
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

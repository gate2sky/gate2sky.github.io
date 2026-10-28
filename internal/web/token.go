package web

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"strings"
	"sync"
	"time"
)

var errBadToken = errors.New("invalid or expired token")

// signer issues tamper-proof, expiring tokens. The purpose is part of the
// MAC, so a token minted for one use cannot be replayed as another.
type signer struct {
	key []byte
}

type envelope struct {
	Exp  int64           `json:"exp"`
	Data json.RawMessage `json:"data"`
}

func (s signer) mac(purpose, payload string) []byte {
	m := hmac.New(sha256.New, s.key)
	m.Write([]byte(purpose))
	m.Write([]byte{0})
	m.Write([]byte(payload))
	return m.Sum(nil)
}

func (s signer) sign(purpose string, v any, ttl time.Duration) string {
	return s.signUntil(purpose, v, time.Now().Add(ttl))
}

func (s signer) signUntil(purpose string, v any, exp time.Time) string {
	data, err := json.Marshal(v)
	if err != nil {
		panic(err) // only called with plain structs
	}
	env, _ := json.Marshal(envelope{Exp: exp.Unix(), Data: data})
	payload := base64.RawURLEncoding.EncodeToString(env)
	return payload + "." + base64.RawURLEncoding.EncodeToString(s.mac(purpose, payload))
}

func (s signer) verify(purpose, token string, v any) error {
	payload, sig, ok := strings.Cut(token, ".")
	if !ok {
		return errBadToken
	}
	got, err := base64.RawURLEncoding.DecodeString(sig)
	if err != nil || !hmac.Equal(got, s.mac(purpose, payload)) {
		return errBadToken
	}
	raw, err := base64.RawURLEncoding.DecodeString(payload)
	if err != nil {
		return errBadToken
	}
	var env envelope
	if err := json.Unmarshal(raw, &env); err != nil || time.Now().Unix() >= env.Exp {
		return errBadToken
	}
	if err := json.Unmarshal(env.Data, v); err != nil {
		return errBadToken
	}
	return nil
}

// nonceSet remembers single-use nonces until they expire.
type nonceSet struct {
	mu   sync.Mutex
	seen map[string]time.Time
}

func newNonceSet() *nonceSet { return &nonceSet{seen: map[string]time.Time{}} }

// use marks nonce as used and reports whether it was fresh.
func (n *nonceSet) use(nonce string, expires time.Time) bool {
	n.mu.Lock()
	defer n.mu.Unlock()
	now := time.Now()
	if len(n.seen) > 1024 {
		for k, exp := range n.seen {
			if now.After(exp) {
				delete(n.seen, k)
			}
		}
	}
	if _, ok := n.seen[nonce]; ok {
		return false
	}
	n.seen[nonce] = expires
	return true
}

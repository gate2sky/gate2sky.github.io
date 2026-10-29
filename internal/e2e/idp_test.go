package e2e

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"sync"
	"testing"
	"time"

	jose "github.com/go-jose/go-jose/v4"
)

// fakeIDP is a minimal OpenID Connect provider that signs in whoever
// SetUser names, without a login form. It checks PKCE and the client
// secret like a real provider would.
type fakeIDP struct {
	*httptest.Server
	t      *testing.T
	key    *rsa.PrivateKey
	signer jose.Signer

	mu    sync.Mutex
	email string
	codes map[string]idpCode
}

type idpCode struct {
	nonce, challenge, email, redirectURI string
}

const (
	idpClientID     = "gate2net-test"
	idpClientSecret = "test-secret"
)

func newFakeIDP(t *testing.T) *fakeIDP {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	signer, err := jose.NewSigner(jose.SigningKey{Algorithm: jose.RS256, Key: jose.JSONWebKey{Key: key, KeyID: "k1"}},
		(&jose.SignerOptions{}).WithType("JWT"))
	if err != nil {
		t.Fatal(err)
	}
	f := &fakeIDP{t: t, key: key, signer: signer, codes: map[string]idpCode{}}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /.well-known/openid-configuration", f.discovery)
	mux.HandleFunc("GET /authorize", f.authorize)
	mux.HandleFunc("POST /token", f.token)
	mux.HandleFunc("GET /jwks", f.jwks)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)
	return f
}

// SetUser chooses who the next sign-in authenticates as.
func (f *fakeIDP) SetUser(email string) {
	f.mu.Lock()
	f.email = email
	f.mu.Unlock()
}

func (f *fakeIDP) discovery(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(map[string]any{
		"issuer":                                f.URL,
		"authorization_endpoint":                f.URL + "/authorize",
		"token_endpoint":                        f.URL + "/token",
		"jwks_uri":                              f.URL + "/jwks",
		"response_types_supported":              []string{"code"},
		"subject_types_supported":               []string{"public"},
		"id_token_signing_alg_values_supported": []string{"RS256"},
	})
}

func (f *fakeIDP) authorize(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	if q.Get("client_id") != idpClientID || q.Get("response_type") != "code" || q.Get("code_challenge_method") != "S256" {
		http.Error(w, "bad authorize request", http.StatusBadRequest)
		return
	}
	code := rand.Text()
	f.mu.Lock()
	f.codes[code] = idpCode{nonce: q.Get("nonce"), challenge: q.Get("code_challenge"), email: f.email, redirectURI: q.Get("redirect_uri")}
	f.mu.Unlock()
	back, _ := url.Parse(q.Get("redirect_uri"))
	back.RawQuery = url.Values{"code": {code}, "state": {q.Get("state")}}.Encode()
	http.Redirect(w, r, back.String(), http.StatusFound)
}

func (f *fakeIDP) token(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	id, secret, ok := r.BasicAuth()
	if !ok {
		id, secret = r.PostForm.Get("client_id"), r.PostForm.Get("client_secret")
	}
	if id != idpClientID || secret != idpClientSecret {
		http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
		return
	}
	f.mu.Lock()
	c, ok := f.codes[r.PostForm.Get("code")]
	delete(f.codes, r.PostForm.Get("code"))
	f.mu.Unlock()
	sum := sha256.Sum256([]byte(r.PostForm.Get("code_verifier")))
	if !ok || base64.RawURLEncoding.EncodeToString(sum[:]) != c.challenge || r.PostForm.Get("redirect_uri") != c.redirectURI {
		http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
		return
	}
	now := time.Now()
	claims, _ := json.Marshal(map[string]any{
		"iss":            f.URL,
		"sub":            "sub-" + c.email,
		"aud":            idpClientID,
		"iat":            now.Unix(),
		"exp":            now.Add(time.Hour).Unix(),
		"nonce":          c.nonce,
		"email":          c.email,
		"email_verified": true,
		"name":           "Test " + c.email,
	})
	jws, err := f.signer.Sign(claims)
	if err != nil {
		f.t.Error(err)
		return
	}
	idToken, _ := jws.CompactSerialize()
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]any{
		"access_token": rand.Text(),
		"token_type":   "Bearer",
		"expires_in":   3600,
		"id_token":     idToken,
	})
}

func (f *fakeIDP) jwks(w http.ResponseWriter, r *http.Request) {
	json.NewEncoder(w).Encode(jose.JSONWebKeySet{Keys: []jose.JSONWebKey{
		{Key: &f.key.PublicKey, KeyID: "k1", Algorithm: "RS256", Use: "sig"},
	}})
}

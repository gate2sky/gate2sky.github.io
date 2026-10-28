package web

import (
	"context"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/github"

	"github.com/gate2sky/gate2sky.github.io/internal/config"
	"github.com/gate2sky/gate2sky.github.io/internal/store"
)

// provider is an OAuth 2.0 identity provider.
type provider interface {
	ID() string
	Name() string
	// AuthCodeURL is where the browser goes to sign in.
	AuthCodeURL(ctx context.Context, state, nonce, verifier string) (string, error)
	// Identify redeems the authorization code and returns who signed in.
	// The returned email must be verified by the provider.
	Identify(ctx context.Context, code, nonce, verifier string) (*store.Identity, error)
}

// oauthFlow is kept in a signed cookie between login and callback.
type oauthFlow struct {
	Provider string `json:"p"`
	State    string `json:"s"`
	Nonce    string `json:"n"`
	Verifier string `json:"v"`
	Redirect string `json:"r"`
}

const oauthFlowTTL = 10 * time.Minute

func randomString(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

func (s *Server) provider(id string) provider {
	for _, p := range s.providers {
		if p.ID() == id {
			return p
		}
	}
	return nil
}

// startSession signs user in on this browser. It returns a message for
// the user when they may not sign in.
func (s *Server) startSession(w http.ResponseWriter, r *http.Request, user *store.User, method string) (string, bool) {
	if user.Disabled {
		return "Your account has been disabled by an administrator.", false
	}
	if !s.cfg.EmailAllowed(user.Email) {
		s.log.Info("sign-in denied", "method", method, "email", user.Email)
		return fmt.Sprintf("The account %s is not allowed to use this gate2sky.", user.Email), false
	}
	token, sess, err := s.store.CreateSession(r.Context(), user.ID, s.cfg.Auth.SessionTTL)
	if err != nil {
		s.log.Error("create session", "err", err)
		return msgInternal, false
	}
	s.log.Info("signed in", "method", method, "email", user.Email, "user_id", user.ID, "ip", s.clientIP(r))
	s.setCookie(w, s.cookies.session, token, sess.ExpiresAt)
	return "", true
}

// afterLogin is where a new session goes: straight to rd, or first to the
// account page to suggest a passkey when the user has none.
func (s *Server) afterLogin(r *http.Request, user *store.User, rd string) string {
	if s.webauthn == nil {
		return rd
	}
	keys, err := s.store.PasskeysByUser(r.Context(), user.ID)
	if err != nil || len(keys) > 0 {
		return rd
	}
	return "/account?welcome=1&rd=" + url.QueryEscape(rd)
}

func (s *Server) handleOAuthLogin(w http.ResponseWriter, r *http.Request) {
	p := s.provider(r.PathValue("provider"))
	if p == nil {
		s.pageError(w, r, http.StatusNotFound, "Unknown sign-in provider.")
		return
	}
	flow := oauthFlow{
		Provider: p.ID(),
		State:    randomString(24),
		Nonce:    randomString(24),
		Verifier: oauth2.GenerateVerifier(),
		Redirect: localPath(r.URL.Query().Get("rd")),
	}
	authURL, err := p.AuthCodeURL(r.Context(), flow.State, flow.Nonce, flow.Verifier)
	if err != nil {
		s.log.Error("start oauth login", "provider", p.ID(), "err", err)
		s.pageError(w, r, http.StatusBadGateway, p.Name()+" is not reachable right now. Please try again later.")
		return
	}
	s.setCookie(w, s.cookies.oauth, s.signer.sign("oauth", flow, oauthFlowTTL), time.Now().Add(oauthFlowTTL))
	http.Redirect(w, r, authURL, http.StatusFound)
}

func (s *Server) handleOAuthCallback(w http.ResponseWriter, r *http.Request) {
	p := s.provider(r.PathValue("provider"))
	if p == nil {
		s.pageError(w, r, http.StatusNotFound, "Unknown sign-in provider.")
		return
	}
	var flow oauthFlow
	c, err := r.Cookie(s.cookies.oauth)
	if err != nil || s.signer.verify("oauth", c.Value, &flow) != nil {
		s.pageError(w, r, http.StatusBadRequest, "Your sign-in attempt expired. Please try again.")
		return
	}
	s.clearCookie(w, s.cookies.oauth)
	q := r.URL.Query()
	if flow.Provider != p.ID() || subtle.ConstantTimeCompare([]byte(q.Get("state")), []byte(flow.State)) != 1 {
		s.pageError(w, r, http.StatusBadRequest, "Sign-in state mismatch. Please try again.")
		return
	}
	if e := q.Get("error"); e != "" {
		msg := q.Get("error_description")
		if msg == "" {
			msg = e
		}
		s.pageError(w, r, http.StatusForbidden, p.Name()+" did not sign you in: "+msg)
		return
	}

	id, err := p.Identify(r.Context(), q.Get("code"), flow.Nonce, flow.Verifier)
	if err != nil {
		s.log.Warn("oauth callback", "provider", p.ID(), "err", err)
		s.pageError(w, r, http.StatusForbidden, "Sign-in with "+p.Name()+" failed: "+err.Error())
		return
	}
	if !strings.HasPrefix(id.AvatarURL, "https://") {
		id.AvatarURL = "" // the dashboard's CSP only loads HTTPS images
	}
	// Check before creating an account for someone who may not sign in.
	if !s.cfg.EmailAllowed(id.Email) {
		s.log.Info("sign-in denied", "method", p.ID(), "email", id.Email)
		s.pageError(w, r, http.StatusForbidden, fmt.Sprintf("The account %s is not allowed to use this gate2sky.", id.Email))
		return
	}
	user, err := s.store.LoginOAuth(r.Context(), *id)
	if err != nil {
		s.log.Error("save user", "err", err)
		s.pageError(w, r, http.StatusInternalServerError, msgInternal)
		return
	}
	if msg, ok := s.startSession(w, r, user, p.ID()); !ok {
		s.pageError(w, r, http.StatusForbidden, msg)
		return
	}
	http.Redirect(w, r, s.afterLogin(r, user, flow.Redirect), http.StatusFound)
}

func (s *Server) handleLogout(w http.ResponseWriter, r *http.Request) {
	if err := s.store.DeleteSession(r.Context(), currentAuth(r).Session.ID); err != nil {
		s.log.Error("delete session", "err", err)
	}
	s.clearCookie(w, s.cookies.session)
	w.WriteHeader(http.StatusNoContent)
}

// githubProvider signs users in with GitHub (or GitHub Enterprise Server).
type githubProvider struct {
	cfg    config.ProviderConfig
	oauth  *oauth2.Config
	apiURL string
	client *http.Client
}

func newGitHubProvider(pc config.ProviderConfig, redirectURL string, client *http.Client) *githubProvider {
	endpoint := github.Endpoint
	if pc.AuthURL != "" {
		endpoint.AuthURL = pc.AuthURL
	}
	if pc.TokenURL != "" {
		endpoint.TokenURL = pc.TokenURL
	}
	scopes := pc.Scopes
	if len(scopes) == 0 {
		scopes = []string{"read:user", "user:email"}
	}
	api := strings.TrimSuffix(pc.APIURL, "/")
	if api == "" {
		api = "https://api.github.com"
	}
	return &githubProvider{
		cfg:    pc,
		apiURL: api,
		client: client,
		oauth: &oauth2.Config{
			ClientID:     pc.ClientID,
			ClientSecret: pc.ClientSecret,
			Endpoint:     endpoint,
			RedirectURL:  redirectURL,
			Scopes:       scopes,
		},
	}
}

func (g *githubProvider) ID() string   { return g.cfg.ID }
func (g *githubProvider) Name() string { return g.cfg.Name }

func (g *githubProvider) AuthCodeURL(_ context.Context, state, _, verifier string) (string, error) {
	return g.oauth.AuthCodeURL(state, oauth2.S256ChallengeOption(verifier)), nil
}

func (g *githubProvider) Identify(ctx context.Context, code, _, verifier string) (*store.Identity, error) {
	ctx = context.WithValue(ctx, oauth2.HTTPClient, g.client)
	tok, err := g.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	client := g.oauth.Client(ctx, tok)

	var user struct {
		ID        int64  `json:"id"`
		Login     string `json:"login"`
		Name      string `json:"name"`
		AvatarURL string `json:"avatar_url"`
	}
	if err := g.get(ctx, client, "/user", &user); err != nil {
		return nil, err
	}
	var emails []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	if err := g.get(ctx, client, "/user/emails", &emails); err != nil {
		return nil, err
	}
	email := ""
	for _, e := range emails {
		if e.Verified && (e.Primary || email == "") {
			email = e.Email
		}
	}
	if email == "" {
		return nil, errors.New("your GitHub account has no verified email address")
	}
	return &store.Identity{
		Provider:  g.cfg.ID,
		Subject:   strconv.FormatInt(user.ID, 10),
		Email:     strings.ToLower(email),
		Name:      user.Name,
		Username:  user.Login,
		AvatarURL: user.AvatarURL,
	}, nil
}

func (g *githubProvider) get(ctx context.Context, client *http.Client, path string, v any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, g.apiURL+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("github %s: %w", path, err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return fmt.Errorf("github %s: %w", path, err)
	}
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("github %s: %s", path, resp.Status)
	}
	return json.Unmarshal(body, v)
}

// oidcProvider signs users in with any OpenID Connect provider (Google,
// GitLab, Microsoft Entra ID, Keycloak, Authentik, ...). Discovery runs on
// first use, so gate2sky starts even if the provider is down.
type oidcProvider struct {
	cfg         config.ProviderConfig
	redirectURL string
	client      *http.Client

	mu       sync.Mutex
	provider *oidc.Provider
	oauth    *oauth2.Config
	verifier *oidc.IDTokenVerifier
}

func newOIDCProvider(pc config.ProviderConfig, redirectURL string, client *http.Client) *oidcProvider {
	return &oidcProvider{cfg: pc, redirectURL: redirectURL, client: client}
}

func (o *oidcProvider) ID() string   { return o.cfg.ID }
func (o *oidcProvider) Name() string { return o.cfg.Name }

func (o *oidcProvider) init() error {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.provider != nil {
		return nil
	}
	// Key refreshes outlive any request, so they get a background context.
	p, err := oidc.NewProvider(oidc.ClientContext(context.Background(), o.client), o.cfg.Issuer)
	if err != nil {
		return fmt.Errorf("oidc discovery for %s: %w", o.cfg.Issuer, err)
	}
	scopes := o.cfg.Scopes
	if len(scopes) == 0 {
		scopes = []string{oidc.ScopeOpenID, "email", "profile"}
	}
	o.provider = p
	o.oauth = &oauth2.Config{
		ClientID:     o.cfg.ClientID,
		ClientSecret: o.cfg.ClientSecret,
		Endpoint:     p.Endpoint(),
		RedirectURL:  o.redirectURL,
		Scopes:       scopes,
	}
	o.verifier = p.Verifier(&oidc.Config{ClientID: o.cfg.ClientID})
	return nil
}

func (o *oidcProvider) AuthCodeURL(_ context.Context, state, nonce, verifier string) (string, error) {
	if err := o.init(); err != nil {
		return "", err
	}
	return o.oauth.AuthCodeURL(state, oidc.Nonce(nonce), oauth2.S256ChallengeOption(verifier)), nil
}

// flexBool accepts both true and "true": some providers send
// email_verified as a string.
type flexBool bool

func (b *flexBool) UnmarshalJSON(data []byte) error {
	switch strings.Trim(string(data), `"`) {
	case "true":
		*b = true
	case "false", "null":
		*b = false
	default:
		return fmt.Errorf("invalid boolean %s", data)
	}
	return nil
}

type oidcClaims struct {
	Email             string    `json:"email"`
	EmailVerified     *flexBool `json:"email_verified"`
	Name              string    `json:"name"`
	PreferredUsername string    `json:"preferred_username"`
	Picture           string    `json:"picture"`
}

func (o *oidcProvider) Identify(ctx context.Context, code, nonce, verifier string) (*store.Identity, error) {
	if err := o.init(); err != nil {
		return nil, err
	}
	ctx = oidc.ClientContext(context.WithValue(ctx, oauth2.HTTPClient, o.client), o.client)
	tok, err := o.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, fmt.Errorf("exchange code: %w", err)
	}
	rawID, _ := tok.Extra("id_token").(string)
	if rawID == "" {
		return nil, errors.New("provider returned no id_token")
	}
	idt, err := o.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, fmt.Errorf("verify id_token: %w", err)
	}
	if subtle.ConstantTimeCompare([]byte(idt.Nonce), []byte(nonce)) != 1 {
		return nil, errors.New("id_token nonce mismatch")
	}
	var claims oidcClaims
	if err := idt.Claims(&claims); err != nil {
		return nil, fmt.Errorf("decode id_token: %w", err)
	}
	if claims.Email == "" && o.provider.UserInfoEndpoint() != "" {
		info, err := o.provider.UserInfo(ctx, oauth2.StaticTokenSource(tok))
		if err != nil {
			return nil, fmt.Errorf("userinfo: %w", err)
		}
		if info.Subject != idt.Subject {
			return nil, errors.New("userinfo subject mismatch")
		}
		if err := info.Claims(&claims); err != nil {
			return nil, fmt.Errorf("decode userinfo: %w", err)
		}
	}
	if claims.Email == "" {
		return nil, errors.New("provider did not share an email address (is the email scope allowed?)")
	}
	verified := o.cfg.AssumeEmailVerified
	if claims.EmailVerified != nil {
		verified = bool(*claims.EmailVerified)
	}
	if !verified {
		return nil, errors.New("your email address is not verified by " + o.cfg.Name)
	}
	return &store.Identity{
		Provider:  o.cfg.ID,
		Subject:   idt.Subject,
		Email:     strings.ToLower(claims.Email),
		Name:      claims.Name,
		Username:  claims.PreferredUsername,
		AvatarURL: claims.Picture,
	}, nil
}

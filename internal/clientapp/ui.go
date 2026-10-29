package clientapp

import (
	"bytes"
	"context"
	"crypto/rand"
	"crypto/subtle"
	"embed"
	"encoding/hex"
	"encoding/json"
	"html/template"
	"net"
	"net/http"
	"time"
)

//go:embed ui
var uiFiles embed.FS

var page = template.Must(template.ParseFS(uiFiles, "ui/index.html"))

// UI serves the app's window as a local web page. Only requests to its
// own address carrying its token get in: other local programs and web
// pages can't drive it.
type UI struct {
	app   *App
	token string
	addr  string
	hc    *http.Client
	// Show is called when another instance of the app asks for the
	// window.
	Show func()
}

// NewUI listens on a random port of 127.0.0.1.
func NewUI(app *App) (*UI, net.Listener, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, nil, err
	}
	b := make([]byte, 16)
	rand.Read(b)
	return &UI{
		app:   app,
		token: hex.EncodeToString(b),
		addr:  ln.Addr().String(),
		hc:    &http.Client{Timeout: 15 * time.Second},
	}, ln, nil
}

// URL opens the window's page.
func (u *UI) URL() string { return "http://" + u.addr + "/?t=" + u.token }

// Token authorizes requests, for another instance asking to show the
// window.
func (u *UI) Token() string { return u.token }

func (u *UI) authorized(r *http.Request) bool {
	if r.Host != u.addr {
		return false // DNS rebinding
	}
	t := r.Header.Get("X-Token")
	if t == "" {
		t = r.URL.Query().Get("t")
	}
	if t == "" {
		if c, err := r.Cookie("t"); err == nil {
			t = c.Value
		}
	}
	return subtle.ConstantTimeCompare([]byte(t), []byte(u.token)) == 1
}

// ServeHTTP implements http.Handler.
func (u *UI) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Frame-Options", "DENY")
	if !u.authorized(r) {
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	if r.URL.Path != "/" && r.Method != http.MethodGet && r.Header.Get("X-Token") == "" {
		// Changes come from the page's fetch(), which sends the header: a
		// form posted from elsewhere can't.
		http.Error(w, "forbidden", http.StatusForbidden)
		return
	}
	switch r.Method + " " + r.URL.Path {
	case "GET /":
		http.SetCookie(w, &http.Cookie{Name: "t", Value: u.token, Path: "/", HttpOnly: true, SameSite: http.SameSiteStrictMode})
		var buf bytes.Buffer
		page.Execute(&buf, struct{ Token string }{u.token})
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self' 'unsafe-inline'; style-src 'unsafe-inline'; img-src 'self' data:; connect-src 'self'")
		w.Write(buf.Bytes())
	case "GET /logo.svg":
		b, _ := uiFiles.ReadFile("ui/logo.svg")
		w.Header().Set("Content-Type", "image/svg+xml")
		w.Write(b)
	case "GET /api/state":
		// With ?wait, answer at the next change (or after 25s).
		if r.URL.Query().Has("wait") {
			select {
			case <-u.app.Changed():
			case <-time.After(25 * time.Second):
			case <-r.Context().Done():
				return
			}
		}
		writeJSON(w, u.app.State())
	case "PUT /api/settings":
		var s Settings
		if json.NewDecoder(http.MaxBytesReader(w, r.Body, 64<<10)).Decode(&s) != nil {
			fail(w, "invalid settings")
			return
		}
		if err := u.app.SetSettings(s); err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, u.app.State())
	case "POST /api/discover":
		var req struct {
			Dashboard string `json:"dashboard"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 4<<10)).Decode(&req)
		ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
		defer cancel()
		if err := u.app.Discover(ctx, req.Dashboard, u.hc); err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, u.app.State())
	case "POST /api/connect":
		if err := u.app.Connect(); err != nil {
			fail(w, err.Error())
			return
		}
		writeJSON(w, u.app.State())
	case "POST /api/disconnect":
		u.app.Disconnect()
		writeJSON(w, u.app.State())
	case "PUT /api/autostart":
		var req struct {
			On bool `json:"on"`
		}
		json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<10)).Decode(&req)
		if err := SetAutostart(req.On); err != nil {
			fail(w, err.Error())
			return
		}
		u.app.mu.Lock()
		u.app.notify()
		u.app.mu.Unlock()
		writeJSON(w, u.app.State())
	case "POST /api/show":
		if u.Show != nil {
			u.Show()
		}
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func fail(w http.ResponseWriter, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusBadRequest)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

// Package clientapp is the intergate app: the client of package client with
// its settings saved, its state kept for a window to show, a local web UI
// that window shows, and starting with the system. It holds no platform
// code but autostart's; the tray and the window live in cmd/intergate-gui.
package clientapp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/jgermade/intergate/internal/client"
)

// Forward is a forward as saved and shown.
type Forward struct {
	Kind  string `json:"kind"` // http, tcp or udp
	Name  string `json:"name"`
	Local string `json:"local"`
}

// Settings are what the app remembers.
type Settings struct {
	Dashboard string    `json:"dashboard"`
	Server    string    `json:"server"`
	HostKey   string    `json:"host_key"`
	Domain    string    `json:"domain"`
	Subdomain string    `json:"subdomain"`
	KeyFile   string    `json:"key_file"`
	Forwards  []Forward `json:"forwards"`
	// ConnectOnStart connects as soon as the app starts.
	ConnectOnStart bool `json:"connect_on_start"`
}

// Check reports what keeps the settings from connecting.
func (s Settings) Check() error {
	switch {
	case s.Server == "" || s.HostKey == "":
		return errors.New("enter your intergate's address and look it up first")
	case s.Subdomain == "":
		return errors.New("enter the subdomain")
	case len(s.Forwards) == 0:
		return errors.New("add something to forward")
	}
	_, err := s.forwards()
	return err
}

func (s Settings) forwards() ([]client.Forward, error) {
	var out []client.Forward
	for _, f := range s.Forwards {
		spec := f.Local
		if f.Kind != client.HTTP {
			spec = f.Name + "=" + f.Local
		}
		cf, err := client.ParseForward(f.Kind, spec)
		if err != nil {
			return nil, errors.New(strings.TrimPrefix(err.Error(), "--"))
		}
		out = append(out, cf)
	}
	return out, nil
}

// Status is the connection's state.
type Status string

const (
	Disconnected Status = "disconnected"
	Connecting   Status = "connecting"
	Connected    Status = "connected"
	Waiting      Status = "waiting" // to reconnect
	Failed       Status = "failed"  // stopped for good
)

// ForwardState is how one forward fares.
type ForwardState struct {
	Forward
	// State is "pending", "open" or "refused".
	State   string `json:"state"`
	Address string `json:"address"`
}

// State is what the window shows.
type State struct {
	Status    Status         `json:"status"`
	Error     string         `json:"error"`
	Since     time.Time      `json:"since"`
	Forwards  []ForwardState `json:"forwards"`
	Settings  Settings       `json:"settings"`
	Autostart bool           `json:"autostart"`
	// CanAutostart is false where starting with the system isn't
	// supported.
	CanAutostart bool     `json:"can_autostart"`
	Log          []string `json:"log"`
}

// App runs the client with the saved settings.
type App struct {
	path string

	mu       sync.Mutex
	settings Settings
	state    State
	cancel   context.CancelFunc
	done     chan struct{}
	log      []string
	// changed is closed and replaced on every change, for watchers.
	changed chan struct{}

	// run replaces client.Run, for tests.
	run func(context.Context, client.Options) error
}

const maxLog = 300

// Open loads the settings saved at path, if any.
func Open(path string) (*App, error) {
	a := &App{path: path, changed: make(chan struct{}), run: client.Run}
	a.state.Status = Disconnected
	b, err := os.ReadFile(path)
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err == nil {
		if err := json.Unmarshal(b, &a.settings); err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
	}
	return a, nil
}

// DefaultPath is where the settings live: %APPDATA%\intergate\app.json on
// Windows, ~/.config/intergate/app.json on Linux. Settings saved under
// gate2net, the app's former name, move there.
func DefaultPath() (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	path := filepath.Join(dir, "intergate", "app.json")
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		old := filepath.Join(dir, "gate2net", "app.json")
		if _, err := os.Stat(old); err == nil && os.MkdirAll(filepath.Dir(path), 0o700) == nil {
			os.Rename(old, path)
		}
	}
	return path, nil
}

// Settings returns the saved settings.
func (a *App) Settings() Settings {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.settings
}

// SetSettings saves new settings. They apply on the next connection.
func (a *App) SetSettings(s Settings) error {
	s.Subdomain = strings.ToLower(strings.TrimSpace(s.Subdomain))
	for i := range s.Forwards {
		s.Forwards[i].Name = strings.ToLower(strings.TrimSpace(s.Forwards[i].Name))
		s.Forwards[i].Local = strings.TrimSpace(s.Forwards[i].Local)
	}
	b, err := json.MarshalIndent(s, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(a.path), 0o700); err != nil {
		return err
	}
	if err := os.WriteFile(a.path, b, 0o600); err != nil {
		return err
	}
	a.mu.Lock()
	a.settings = s
	a.notify()
	a.mu.Unlock()
	return nil
}

// Discover asks a intergate dashboard where its SSH endpoint is and which
// host key it has, and saves the answer.
func (a *App) Discover(ctx context.Context, dashboard string, hc *http.Client) error {
	dashboard = strings.TrimSpace(dashboard)
	if !strings.Contains(dashboard, "://") {
		dashboard = "https://" + dashboard
	}
	u, err := url.Parse(dashboard)
	if err != nil || u.Host == "" {
		return fmt.Errorf("%q is not an address like gate.example.com", dashboard)
	}
	u.Path, u.RawQuery, u.Fragment = "/client.json", "", ""
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	resp, err := hc.Do(req)
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", u.Host, err)
	}
	defer resp.Body.Close()
	var info struct {
		Server    string `json:"server"`
		HostKey   string `json:"host_key"`
		Domain    string `json:"domain"`
		Dashboard string `json:"dashboard"`
	}
	if resp.StatusCode != http.StatusOK || json.NewDecoder(io.LimitReader(resp.Body, 64<<10)).Decode(&info) != nil ||
		info.Server == "" || !strings.HasPrefix(info.HostKey, "SHA256:") {
		return fmt.Errorf("%s doesn't look like a intergate (no /client.json)", u.Host)
	}
	s := a.Settings()
	s.Dashboard, s.Server, s.HostKey, s.Domain = strings.TrimSuffix(info.Dashboard, "/"), info.Server, info.HostKey, info.Domain
	return a.SetSettings(s)
}

// Logf adds a line to the log.
func (a *App) Logf(format string, args ...any) {
	a.mu.Lock()
	a.addLog(fmt.Sprintf(format, args...))
	a.mu.Unlock()
}

func (a *App) addLog(line string) {
	line = time.Now().Format("15:04:05") + "  " + strings.TrimRight(line, "\r\n")
	a.log = append(a.log, line)
	if len(a.log) > maxLog {
		a.log = a.log[len(a.log)-maxLog:]
	}
	a.notify()
}

// notify wakes watchers; a.mu is held.
func (a *App) notify() {
	close(a.changed)
	a.changed = make(chan struct{})
}

// Changed returns a channel closed at the next change.
func (a *App) Changed() <-chan struct{} {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.changed
}

// State returns a snapshot for the window.
func (a *App) State() State {
	a.mu.Lock()
	defer a.mu.Unlock()
	st := a.state
	st.Forwards = append([]ForwardState(nil), a.state.Forwards...)
	st.Settings = a.settings
	st.Log = append([]string(nil), a.log...)
	st.Autostart, st.CanAutostart = AutostartEnabled(), AutostartSupported()
	return st
}

// Running reports whether the app is connected or trying to.
func (a *App) Running() bool {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.cancel != nil
}

// logWriter turns the client's output into log lines.
type logWriter struct {
	a   *App
	buf []byte
}

func (w *logWriter) Write(p []byte) (int, error) {
	w.buf = append(w.buf, p...)
	for {
		i := strings.IndexByte(string(w.buf), '\n')
		if i < 0 {
			break
		}
		if line := strings.TrimSpace(string(w.buf[:i])); line != "" {
			w.a.Logf("%s", line)
		}
		w.buf = w.buf[i+1:]
	}
	return len(p), nil
}

// Connect starts forwarding with the saved settings, until Disconnect.
func (a *App) Connect() error {
	s := a.Settings()
	if err := s.Check(); err != nil {
		return err
	}
	forwards, _ := s.forwards()
	var files []string
	if s.KeyFile != "" {
		files = []string{s.KeyFile}
	}
	auth, err := client.AuthMethods(files)
	if err != nil {
		return err
	}
	check, _ := client.HostKeyCheck(s.HostKey)
	server := s.Server
	if _, _, err := net.SplitHostPort(server); err != nil {
		server = net.JoinHostPort(server, "22")
	}

	a.mu.Lock()
	if a.cancel != nil {
		a.mu.Unlock()
		return nil
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	a.cancel, a.done = cancel, done
	a.state = State{Status: Connecting, Since: time.Now()}
	for _, f := range s.Forwards {
		a.state.Forwards = append(a.state.Forwards, ForwardState{Forward: f, State: "pending"})
	}
	a.addLog("connecting to " + s.Server + " as " + s.Subdomain)
	a.mu.Unlock()

	go func() {
		defer close(done)
		err := a.run(ctx, client.Options{
			Server:    server,
			Subdomain: s.Subdomain,
			Forwards:  forwards,
			Auth:      auth,
			HostKey:   check,
			Out:       &logWriter{a: a},
			OnEvent:   func(e client.Event) { a.event(s, e) },
		})
		a.mu.Lock()
		a.cancel = nil
		if err != nil && ctx.Err() == nil {
			a.state.Status, a.state.Error = Failed, err.Error()
			a.addLog("stopped: " + err.Error())
		} else {
			a.state.Status, a.state.Error = Disconnected, ""
			a.addLog("disconnected")
		}
		for i := range a.state.Forwards {
			if a.state.Forwards[i].State == "open" {
				a.state.Forwards[i].State, a.state.Forwards[i].Address = "pending", ""
			}
		}
		a.state.Since = time.Now()
		a.notify()
		a.mu.Unlock()
	}()
	return nil
}

// event updates the state from the client's events.
func (a *App) event(s Settings, e client.Event) {
	a.mu.Lock()
	defer a.mu.Unlock()
	find := func() *ForwardState {
		for i := range a.state.Forwards {
			f := &a.state.Forwards[i]
			if f.Kind == e.Forward.Kind && f.Name == e.Forward.Name {
				return f
			}
		}
		return nil
	}
	switch e.Kind {
	case client.Connecting:
		a.state.Status = Connecting
	case client.Connected:
		a.state.Status, a.state.Error, a.state.Since = Connected, "", time.Now()
	case client.Forwarded:
		if f := find(); f != nil {
			f.State = "open"
			host, _, _ := net.SplitHostPort(s.Server)
			switch {
			case e.Forward.Kind == client.HTTP && s.Dashboard != "" && s.Domain != "":
				scheme := "https"
				if strings.HasPrefix(s.Dashboard, "http://") {
					scheme = "http"
				}
				f.Address = scheme + "://" + s.Subdomain + "." + s.Domain
			case e.Forward.Kind != client.HTTP && host != "":
				f.Address = fmt.Sprintf("%s://%s", e.Forward.Kind, net.JoinHostPort(host, fmt.Sprint(e.Port)))
			}
		}
	case client.Refused:
		if f := find(); f != nil {
			f.State = "refused"
		}
	case client.Disconnected:
		for i := range a.state.Forwards {
			if a.state.Forwards[i].State == "open" {
				a.state.Forwards[i].State, a.state.Forwards[i].Address = "pending", ""
			}
		}
	case client.Retrying:
		a.state.Status = Waiting
		if e.Err != nil {
			a.state.Error = e.Err.Error()
		}
	}
	a.notify()
}

// Disconnect stops forwarding and waits for the client to stop.
func (a *App) Disconnect() {
	a.mu.Lock()
	cancel, done := a.cancel, a.done
	a.mu.Unlock()
	if cancel == nil {
		return
	}
	cancel()
	<-done
}

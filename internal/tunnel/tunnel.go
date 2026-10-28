// Package tunnel keeps track of the HTTP tunnels currently open over SSH.
package tunnel

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"errors"
	"net"
	"net/http"
	"sort"
	"sync"
	"sync/atomic"
	"time"

	"github.com/jgermade/securegate/internal/store"
)

// ErrClosed is returned when dialing a tunnel that has gone away.
var ErrClosed = errors.New("tunnel closed")

// DialFunc opens a new stream to the client's local service. origin is the
// address of the visitor, passed along for the client's information.
type DialFunc func(ctx context.Context, origin string) (net.Conn, error)

// Options describe a new tunnel.
type Options struct {
	Subdomain     string
	SubdomainID   int64
	OwnerID       int64
	Access        store.Access
	KeyID         int64
	KeyName       string
	ClientAddr    string
	ClientVersion string
	Dial          DialFunc
	// Logf receives one line per proxied request, for the SSH console.
	Logf func(format string, args ...any)
	// OnClose runs once when the tunnel closes, with the reason.
	OnClose func(reason string)
}

// Tunnel is one open forward from a subdomain to an SSH client.
type Tunnel struct {
	Options
	ID        string
	CreatedAt time.Time

	access    atomic.Value // store.Access
	transport *http.Transport
	registry  *Registry
	done      chan struct{}
	closeOnce sync.Once

	requests    atomic.Int64
	bytesIn     atomic.Int64
	bytesOut    atomic.Int64
	activeConns atomic.Int64
}

// New creates a tunnel. It starts serving once added to a Registry.
func New(opts Options) *Tunnel {
	t := &Tunnel{
		Options:   opts,
		ID:        randomID(),
		CreatedAt: time.Now(),
		done:      make(chan struct{}),
	}
	t.access.Store(opts.Access)
	t.transport = &http.Transport{
		DialContext:           t.dialContext,
		MaxIdleConnsPerHost:   16,
		IdleConnTimeout:       90 * time.Second,
		ExpectContinueTimeout: time.Second,
		DisableCompression:    true,
		// Visitors' proxy settings must never leak into tunnel traffic.
		Proxy: nil,
	}
	return t
}

// Access returns the current access level.
func (t *Tunnel) Access() store.Access { return t.access.Load().(store.Access) }

// SetAccess changes the access level of a live tunnel.
func (t *Tunnel) SetAccess(a store.Access) { t.access.Store(a) }

// Transport sends HTTP requests through the tunnel.
func (t *Tunnel) Transport() http.RoundTripper { return t.transport }

// Done is closed when the tunnel closes.
func (t *Tunnel) Done() <-chan struct{} { return t.done }

// CountRequest records a proxied request.
func (t *Tunnel) CountRequest() { t.requests.Add(1) }

// Log writes a line to the client's SSH console, if any.
func (t *Tunnel) Log(format string, args ...any) {
	if t.Logf != nil {
		t.Logf(format, args...)
	}
}

// Close shuts the tunnel down and removes it from its registry.
func (t *Tunnel) Close(reason string) {
	t.closeOnce.Do(func() {
		close(t.done)
		if t.registry != nil {
			t.registry.remove(t)
		}
		t.transport.CloseIdleConnections()
		if t.OnClose != nil {
			t.OnClose(reason)
		}
	})
}

type originKey struct{}

// WithOrigin attaches the visitor address to ctx, for DialFunc.
func WithOrigin(ctx context.Context, origin string) context.Context {
	return context.WithValue(ctx, originKey{}, origin)
}

func (t *Tunnel) dialContext(ctx context.Context, _, _ string) (net.Conn, error) {
	select {
	case <-t.done:
		return nil, ErrClosed
	default:
	}
	origin, _ := ctx.Value(originKey{}).(string)
	c, err := t.Dial(ctx, origin)
	if err != nil {
		return nil, err
	}
	t.activeConns.Add(1)
	return &countingConn{Conn: c, t: t}, nil
}

func randomID() string {
	b := make([]byte, 8)
	rand.Read(b)
	return hex.EncodeToString(b)
}

// Stats is a snapshot of a tunnel for display.
type Stats struct {
	ID            string       `json:"id"`
	Subdomain     string       `json:"subdomain"`
	OwnerID       int64        `json:"owner_id"`
	Access        store.Access `json:"access"`
	KeyName       string       `json:"key_name"`
	ClientAddr    string       `json:"client_addr"`
	ClientVersion string       `json:"client_version"`
	CreatedAt     time.Time    `json:"created_at"`
	Requests      int64        `json:"requests"`
	BytesIn       int64        `json:"bytes_in"`
	BytesOut      int64        `json:"bytes_out"`
	ActiveConns   int64        `json:"active_conns"`
}

// Stats returns a snapshot of the tunnel.
func (t *Tunnel) Stats() Stats {
	return Stats{
		ID:            t.ID,
		Subdomain:     t.Subdomain,
		OwnerID:       t.OwnerID,
		Access:        t.Access(),
		KeyName:       t.KeyName,
		ClientAddr:    t.ClientAddr,
		ClientVersion: t.ClientVersion,
		CreatedAt:     t.CreatedAt,
		Requests:      t.requests.Load(),
		BytesIn:       t.bytesIn.Load(),
		BytesOut:      t.bytesOut.Load(),
		ActiveConns:   t.activeConns.Load(),
	}
}

// countingConn tracks traffic through the tunnel. Reads are bytes coming
// back from the client (responses); writes are bytes sent to it (requests).
type countingConn struct {
	net.Conn
	t         *Tunnel
	closeOnce sync.Once
}

func (c *countingConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.t.bytesOut.Add(int64(n))
	return n, err
}

func (c *countingConn) Write(p []byte) (int, error) {
	n, err := c.Conn.Write(p)
	c.t.bytesIn.Add(int64(n))
	return n, err
}

func (c *countingConn) Close() error {
	c.closeOnce.Do(func() { c.t.activeConns.Add(-1) })
	return c.Conn.Close()
}

// Registry maps subdomains to their open tunnel. A subdomain has at most one
// tunnel; a newer connection replaces the older one, so clients that
// reconnect (e.g. after a network change) take over immediately.
type Registry struct {
	mu     sync.RWMutex
	byName map[string]*Tunnel
}

// NewRegistry returns an empty registry.
func NewRegistry() *Registry {
	return &Registry{byName: map[string]*Tunnel{}}
}

// Add starts serving t, closing any tunnel it replaces.
func (r *Registry) Add(t *Tunnel) {
	r.mu.Lock()
	old := r.byName[t.Subdomain]
	t.registry = r
	r.byName[t.Subdomain] = t
	r.mu.Unlock()
	if old != nil {
		old.Close("replaced by a newer connection from " + t.ClientAddr)
	}
}

func (r *Registry) remove(t *Tunnel) {
	r.mu.Lock()
	if r.byName[t.Subdomain] == t {
		delete(r.byName, t.Subdomain)
	}
	r.mu.Unlock()
}

// Get returns the tunnel serving a subdomain, or nil.
func (r *Registry) Get(subdomain string) *Tunnel {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.byName[subdomain]
}

// List returns all open tunnels sorted by subdomain.
func (r *Registry) List() []*Tunnel {
	r.mu.RLock()
	out := make([]*Tunnel, 0, len(r.byName))
	for _, t := range r.byName {
		out = append(out, t)
	}
	r.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Subdomain < out[j].Subdomain })
	return out
}

// CloseKey closes the tunnel on subdomain if it was opened with keyID.
func (r *Registry) CloseKey(subdomain string, keyID int64, reason string) {
	if t := r.Get(subdomain); t != nil && t.KeyID == keyID {
		t.Close(reason)
	}
}

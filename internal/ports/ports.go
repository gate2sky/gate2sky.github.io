// Package ports serves the TCP and UDP ports of subdomains: while an SSH
// client forwards one, it listens on its public number and hands every
// connection (or, for UDP, every remote address) its allow list lets in
// to that client.
package ports

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gate2net/gate2net.github.io/internal/store"
	"github.com/gate2net/gate2net.github.io/internal/tunnel"
)

// dialTimeout bounds how long a visitor waits for the client to open a
// stream to its local service.
const dialTimeout = 10 * time.Second

// Options describe a new forward.
type Options struct {
	Port          store.Port
	Address       string // tcp://host:port, for messages
	KeyID         int64
	KeyName       string
	ClientAddr    string
	ClientVersion string
	Dial          tunnel.DialFunc
	// Logf receives a line per refused or failed connection, for the SSH
	// console.
	Logf func(format string, args ...any)
	// OnClose runs once when the forward closes, with the reason.
	OnClose func(reason string)
}

// Forward is one port being forwarded to an SSH client.
type Forward struct {
	Options
	CreatedAt time.Time

	name     atomic.Value // string
	allow    atomic.Pointer[[]netip.Prefix]
	keyName  atomic.Value   // string
	ln       net.Listener   // TCP
	pc       net.PacketConn // UDP
	registry *Registry
	done     chan struct{}

	closeOnce sync.Once
	mu        sync.Mutex
	conns     map[net.Conn]struct{}
	sessions  map[netip.AddrPort]*udpSession

	total    atomic.Int64
	active   atomic.Int64
	refused  atomic.Int64
	bytesIn  atomic.Int64
	bytesOut atomic.Int64
}

// ParseAllow reads an allow list: addresses or CIDRs, in any order. It
// returns the prefixes in canonical form.
func ParseAllow(list []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(list))
	for _, s := range list {
		s = strings.TrimSpace(s)
		if s == "" {
			continue
		}
		var p netip.Prefix
		if strings.Contains(s, "/") {
			var err error
			if p, err = netip.ParsePrefix(s); err != nil {
				return nil, fmt.Errorf("%q is not an address or a CIDR range", s)
			}
		} else {
			a, err := netip.ParseAddr(s)
			if err != nil {
				return nil, fmt.Errorf("%q is not an address or a CIDR range", s)
			}
			p = netip.PrefixFrom(a, a.BitLen())
		}
		if p.Addr().Is4In6() {
			p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
		}
		out = append(out, p.Masked())
	}
	return out, nil
}

// FormatAllow writes prefixes back, single addresses without their /32
// or /128.
func FormatAllow(prefixes []netip.Prefix) []string {
	out := make([]string, len(prefixes))
	for i, p := range prefixes {
		if p.IsSingleIP() {
			out[i] = p.Addr().String()
		} else {
			out[i] = p.String()
		}
	}
	return out
}

func mustAllow(list []string) []netip.Prefix {
	// Stored lists were checked when saved; a bad entry lets nobody in
	// rather than everyone.
	p, err := ParseAllow(list)
	if err != nil {
		return []netip.Prefix{}
	}
	return p
}

// Name is the port's current name.
func (f *Forward) Name() string { return f.name.Load().(string) }

// Allow returns the allow list; empty means anyone.
func (f *Forward) Allow() []netip.Prefix { return *f.allow.Load() }

// Allowed reports whether a visitor from addr may connect.
func (f *Forward) Allowed(addr netip.Addr) bool {
	list := f.Allow()
	if len(list) == 0 {
		return true
	}
	addr = addr.Unmap()
	for _, p := range list {
		if p.Contains(addr) {
			return true
		}
	}
	return false
}

// Done is closed when the forward closes.
func (f *Forward) Done() <-chan struct{} { return f.done }

// Close stops listening, drops every connection and removes the forward
// from its registry.
func (f *Forward) Close(reason string) {
	f.closeOnce.Do(func() {
		close(f.done)
		if f.ln != nil {
			f.ln.Close()
		}
		if f.pc != nil {
			f.pc.Close()
		}
		f.mu.Lock()
		for c := range f.conns {
			c.Close()
		}
		for _, s := range f.sessions {
			s.close()
		}
		f.mu.Unlock()
		f.registry.remove(f)
		if f.OnClose != nil {
			f.OnClose(reason)
		}
	})
}

func (f *Forward) logf(format string, args ...any) {
	if f.Logf != nil {
		f.Logf(format, args...)
	}
}

func (f *Forward) serve() {
	var backoff time.Duration
	for {
		c, err := f.ln.Accept()
		if err != nil {
			select {
			case <-f.done:
				return
			default:
			}
			if errors.Is(err, net.ErrClosed) {
				f.Close("the port stopped listening")
				return
			}
			backoff = min(max(2*backoff, 5*time.Millisecond), time.Second)
			time.Sleep(backoff)
			continue
		}
		backoff = 0
		go f.handle(c)
	}
}

func (f *Forward) handle(c net.Conn) {
	origin := c.RemoteAddr().String()
	ap, err := netip.ParseAddrPort(origin)
	if err != nil || !f.Allowed(ap.Addr()) {
		f.refused.Add(1)
		c.Close()
		f.logf("✖ %s (%s): refused %s, not in the allow list", f.Address, f.Name(), ap.Addr().Unmap())
		return
	}
	if !f.track(c, true) {
		c.Close()
		return
	}
	defer f.track(c, false)
	defer c.Close()

	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	stream, err := f.Dial(ctx, origin)
	cancel()
	if err != nil {
		f.logf("✖ %s (%s): could not reach the local service for %s: %v", f.Address, f.Name(), ap.Addr().Unmap(), err)
		return
	}
	defer stream.Close()
	f.total.Add(1)
	f.active.Add(1)
	defer f.active.Add(-1)

	done := make(chan struct{})
	go func() {
		n, _ := io.Copy(stream, c)
		f.bytesIn.Add(n)
		// Let the service see the end of the request and answer it.
		if cw, ok := stream.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		close(done)
	}()
	n, _ := io.Copy(c, stream)
	f.bytesOut.Add(n)
	if tc, ok := c.(*net.TCPConn); ok {
		tc.CloseWrite()
	}
	select {
	case <-done:
	case <-f.done:
	}
}

// track adds or removes an open connection, so Close can drop it. It
// reports false when the forward has closed.
func (f *Forward) track(c net.Conn, open bool) bool {
	f.mu.Lock()
	defer f.mu.Unlock()
	if !open {
		delete(f.conns, c)
		return true
	}
	select {
	case <-f.done:
		return false
	default:
	}
	f.conns[c] = struct{}{}
	return true
}

// Stats is a snapshot of a forward for display.
type Stats struct {
	Port          int       `json:"port"`
	Name          string    `json:"name"`
	KeyName       string    `json:"key_name"`
	ClientAddr    string    `json:"client_addr"`
	ClientVersion string    `json:"client_version"`
	CreatedAt     time.Time `json:"created_at"`
	Connections   int64     `json:"connections"`
	ActiveConns   int64     `json:"active_conns"`
	Refused       int64     `json:"refused"`
	BytesIn       int64     `json:"bytes_in"`
	BytesOut      int64     `json:"bytes_out"`
}

// Stats returns a snapshot of the forward.
func (f *Forward) Stats() Stats {
	return Stats{
		Port:          f.Port.Port,
		Name:          f.Name(),
		KeyName:       f.keyName.Load().(string),
		ClientAddr:    f.ClientAddr,
		ClientVersion: f.ClientVersion,
		CreatedAt:     f.CreatedAt,
		Connections:   f.total.Load(),
		ActiveConns:   f.active.Load(),
		Refused:       f.refused.Load(),
		BytesIn:       f.bytesIn.Load(),
		BytesOut:      f.bytesOut.Load(),
	}
}

// Registry holds the forwarded ports by public number. A port has at most
// one forward; a newer connection replaces the older one, as for HTTP
// tunnels.
type Registry struct {
	listenHost string

	mu     sync.Mutex
	byPort map[int]*Forward
}

// NewRegistry returns an empty registry whose ports listen on host (all
// interfaces when empty).
func NewRegistry(listenHost string) *Registry {
	return &Registry{listenHost: listenHost, byPort: map[int]*Forward{}}
}

// Open starts listening on the port of opts, closing the forward it
// replaces.
func (r *Registry) Open(opts Options) (*Forward, error) {
	port := opts.Port.Port
	if old := r.Get(port); old != nil {
		old.Close("replaced by a newer connection from " + opts.ClientAddr)
	}
	f := &Forward{
		Options:   opts,
		CreatedAt: time.Now(),
		registry:  r,
		done:      make(chan struct{}),
		conns:     map[net.Conn]struct{}{},
		sessions:  map[netip.AddrPort]*udpSession{},
	}
	addr := net.JoinHostPort(r.listenHost, strconv.Itoa(port))
	var err error
	if opts.Port.Protocol == store.ProtocolUDP {
		f.pc, err = net.ListenPacket("udp", addr)
	} else {
		f.ln, err = net.Listen("tcp", addr)
	}
	if err != nil {
		return nil, fmt.Errorf("port %d can't be opened on the server right now", port)
	}
	f.name.Store(opts.Port.Name)
	f.keyName.Store(opts.KeyName)
	allow := mustAllow(opts.Port.Allow)
	f.allow.Store(&allow)

	r.mu.Lock()
	old := r.byPort[port]
	r.byPort[port] = f
	r.mu.Unlock()
	if old != nil {
		old.Close("replaced by a newer connection from " + opts.ClientAddr)
	}
	if f.pc != nil {
		go f.serveUDP()
		go f.expireSessions()
	} else {
		go f.serve()
	}
	return f, nil
}

func (r *Registry) remove(f *Forward) {
	r.mu.Lock()
	if r.byPort[f.Port.Port] == f {
		delete(r.byPort, f.Port.Port)
	}
	r.mu.Unlock()
}

// Get returns the forward on a public port, or nil.
func (r *Registry) Get(port int) *Forward {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.byPort[port]
}

// List returns every forward, by port.
func (r *Registry) List() []*Forward {
	r.mu.Lock()
	out := make([]*Forward, 0, len(r.byPort))
	for _, f := range r.byPort {
		out = append(out, f)
	}
	r.mu.Unlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Port.Port < out[j].Port.Port })
	return out
}

// Subdomain returns the forwards of a subdomain, by port.
func (r *Registry) Subdomain(subdomainID int64) []*Forward {
	var out []*Forward
	for _, f := range r.List() {
		if f.Port.SubdomainID == subdomainID {
			out = append(out, f)
		}
	}
	return out
}

// byID returns the forward of a stored port, or nil.
func (r *Registry) byID(portID int64) *Forward {
	for _, f := range r.List() {
		if f.Port.ID == portID {
			return f
		}
	}
	return nil
}

// Update applies a port's new name and allow list to its forward, if
// open. Connections already in keep going.
func (r *Registry) Update(p *store.Port) {
	if f := r.byID(p.ID); f != nil {
		f.name.Store(p.Name)
		allow := mustAllow(p.Allow)
		f.allow.Store(&allow)
	}
}

// ClosePort closes the forward of a stored port, if open.
func (r *Registry) ClosePort(portID int64, reason string) {
	if f := r.byID(portID); f != nil {
		f.Close(reason)
	}
}

// CloseSubdomain closes every forward of a subdomain and reports how many
// there were.
func (r *Registry) CloseSubdomain(subdomainID int64, reason string) int {
	fs := r.Subdomain(subdomainID)
	for _, f := range fs {
		f.Close(reason)
	}
	return len(fs)
}

// CloseKey closes the forwards of a subdomain opened with keyID.
func (r *Registry) CloseKey(subdomainID, keyID int64, reason string) {
	for _, f := range r.Subdomain(subdomainID) {
		if f.KeyID == keyID {
			f.Close(reason)
		}
	}
}

// RenameKey renames the key of the forwards of a subdomain opened with
// keyID.
func (r *Registry) RenameKey(subdomainID, keyID int64, name string) {
	for _, f := range r.Subdomain(subdomainID) {
		if f.KeyID == keyID {
			f.keyName.Store(name)
		}
	}
}

// CloseOwner closes every forward of a user's subdomains.
func (r *Registry) CloseOwner(ownerID int64, reason string) {
	for _, f := range r.List() {
		if f.Port.OwnerID == ownerID {
			f.Close(reason)
		}
	}
}

// Close closes every forward, when the server stops.
func (r *Registry) Close() {
	for _, f := range r.List() {
		f.Close("the server is stopping")
	}
}

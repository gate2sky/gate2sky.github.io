// Package client is the gate2sky client: it connects to a gate2sky server
// with SSH, like `ssh -R`, and forwards a subdomain's HTTP tunnel, TCP
// ports and UDP ports — UDP being what plain OpenSSH can't carry. It
// reconnects when the connection drops.
package client

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/ssh"

	"github.com/gate2sky/gate2sky.github.io/internal/udpframe"
)

// Kinds of forward.
const (
	HTTP = "http"
	TCP  = "tcp"
	UDP  = "udp"
)

// Forward is one thing to forward: the subdomain's HTTP tunnel, or one of
// its ports by name, to a local address.
type Forward struct {
	Kind  string
	Name  string // the port's name; empty for HTTP
	Local string // host:port
}

func (f Forward) String() string {
	if f.Kind == HTTP {
		return "http → " + f.Local
	}
	return fmt.Sprintf("%s %s → %s", f.Kind, f.Name, f.Local)
}

// ParseForward reads NAME=PORT or NAME=HOST:PORT (or, for HTTP, PORT or
// HOST:PORT) into a forward of kind.
func ParseForward(kind, s string) (Forward, error) {
	f := Forward{Kind: kind}
	local := s
	if kind != HTTP {
		name, rest, ok := strings.Cut(s, "=")
		if !ok || name == "" {
			return f, fmt.Errorf("--%s %q: write it as NAME=PORT, e.g. db=5432", kind, s)
		}
		f.Name, local = strings.ToLower(name), rest
	}
	if _, err := strconv.Atoi(local); err == nil {
		local = "localhost:" + local
	}
	host, port, err := net.SplitHostPort(local)
	if n, perr := strconv.Atoi(port); err != nil || perr != nil || n < 1 || n > 65535 || host == "" {
		return f, fmt.Errorf("--%s %q: the local port must be a number from 1 to 65535, or HOST:PORT", kind, s)
	}
	f.Local = local
	return f, nil
}

// Options configure a client.
type Options struct {
	// Server is host:port of the gate2sky SSH endpoint.
	Server    string
	Subdomain string
	Forwards  []Forward
	Auth      []ssh.AuthMethod
	HostKey   ssh.HostKeyCallback
	// Out receives the server's messages and the client's own.
	Out io.Writer
	// Dial connects to local services; net.Dialer by default (tests).
	Dial func(ctx context.Context, network, addr string) (net.Conn, error)
}

// ErrRejected is returned when the server refused every forward: retrying
// would not help.
var ErrRejected = errors.New("the server refused every forward")

// Run forwards until ctx is done, reconnecting when the connection drops.
// It returns at once if the first connection fails to authenticate or every
// forward is refused.
func Run(ctx context.Context, o Options) error {
	if o.Dial == nil {
		o.Dial = (&net.Dialer{}).DialContext
	}
	backoff := time.Second
	for attempt := 0; ; attempt++ {
		started := time.Now()
		err := runOnce(ctx, o)
		if ctx.Err() != nil {
			return nil
		}
		var authErr *authError
		if errors.Is(err, ErrRejected) || (attempt == 0 && errors.As(err, &authErr)) {
			return err
		}
		if time.Since(started) > time.Minute {
			backoff = time.Second
		}
		fmt.Fprintf(o.Out, "gate2sky: %v; reconnecting in %s\n", err, backoff)
		select {
		case <-time.After(backoff):
		case <-ctx.Done():
			return nil
		}
		backoff = min(2*backoff, 30*time.Second)
	}
}

type authError struct{ err error }

func (e *authError) Error() string { return e.err.Error() }

// route is where streams for a forward go.
type route struct {
	kind  string
	local string
}

func runOnce(ctx context.Context, o Options) error {
	d := net.Dialer{Timeout: 15 * time.Second}
	nc, err := d.DialContext(ctx, "tcp", o.Server)
	if err != nil {
		return err
	}
	cc, chans, reqs, err := ssh.NewClientConn(nc, o.Server, &ssh.ClientConfig{
		User:            o.Subdomain,
		Auth:            o.Auth,
		HostKeyCallback: o.HostKey,
		Timeout:         15 * time.Second,
	})
	if err != nil {
		nc.Close()
		if strings.Contains(err.Error(), "unable to authenticate") || strings.Contains(err.Error(), "host key") {
			return &authError{err}
		}
		return err
	}
	conn := ssh.NewClient(cc, nil, reqs)
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()

	// Routes are filled before any stream can arrive for them: the server
	// opens streams only after it accepted the forward.
	var mu sync.Mutex
	routes := map[string]route{}
	lookup := func(addr string, port uint32) (route, bool) {
		mu.Lock()
		defer mu.Unlock()
		r, ok := routes[net.JoinHostPort(addr, strconv.Itoa(int(port)))]
		return r, ok
	}
	go handleStreams(chans, lookup, o)

	// The session shows what the server says, as `ssh` would.
	if sess, err := conn.NewSession(); err == nil {
		if out, err := sess.StdoutPipe(); err == nil && sess.Shell() == nil {
			go copyLines(o.Out, out)
		}
	}

	accepted := 0
	for _, f := range o.Forwards {
		bind, reqType, port := o.Subdomain, "tcpip-forward", uint32(80)
		if f.Kind != HTTP {
			bind, port = f.Name+"."+o.Subdomain, 0
			if f.Kind == UDP {
				reqType = udpframe.ForwardRequest
			}
		}
		ok, reply, err := conn.SendRequest(reqType, true, ssh.Marshal(struct {
			Addr string
			Port uint32
		}{bind, port}))
		if err != nil {
			return err
		}
		if !ok {
			continue // the server says why on the session
		}
		if port == 0 {
			var r struct{ Port uint32 }
			if ssh.Unmarshal(reply, &r) != nil {
				continue
			}
			port = r.Port
		}
		mu.Lock()
		routes[net.JoinHostPort(bind, strconv.Itoa(int(port)))] = route{f.Kind, f.Local}
		mu.Unlock()
		accepted++
	}
	if accepted == 0 {
		// Let the server's reasons reach the terminal.
		time.Sleep(500 * time.Millisecond)
		return ErrRejected
	}
	return conn.Wait()
}

// copyLines writes the server's console to out, without its \r.
func copyLines(out io.Writer, r io.Reader) {
	s := bufio.NewScanner(r)
	for s.Scan() {
		fmt.Fprintln(out, strings.TrimRight(s.Text(), "\r"))
	}
}

// RFC 4254 section 7.2, also used by udp@gate2sky.
type forwardedPayload struct {
	Addr       string
	Port       uint32
	OriginAddr string
	OriginPort uint32
}

func handleStreams(chans <-chan ssh.NewChannel, lookup func(string, uint32) (route, bool), o Options) {
	for nch := range chans {
		var p forwardedPayload
		if ssh.Unmarshal(nch.ExtraData(), &p) != nil {
			nch.Reject(ssh.ConnectionFailed, "bad payload")
			continue
		}
		r, ok := lookup(p.Addr, p.Port)
		wantType := "forwarded-tcpip"
		if r.kind == UDP {
			wantType = udpframe.ChannelType
		}
		if !ok || nch.ChannelType() != wantType {
			nch.Reject(ssh.Prohibited, "not forwarded")
			continue
		}
		go serveStream(nch, r, o)
	}
}

func serveStream(nch ssh.NewChannel, r route, o Options) {
	network := "tcp"
	if r.kind == UDP {
		network = "udp"
	}
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	local, err := o.Dial(ctx, network, r.local)
	cancel()
	if err != nil {
		nch.Reject(ssh.ConnectionFailed, err.Error())
		fmt.Fprintf(o.Out, "gate2sky: %s is not answering: %v\n", r.local, err)
		return
	}
	ch, reqs, err := nch.Accept()
	if err != nil {
		local.Close()
		return
	}
	go ssh.DiscardRequests(reqs)
	defer ch.Close()
	defer local.Close()

	if r.kind == UDP {
		// Datagrams from the stream to the service, and its answers back.
		go func() {
			buf := make([]byte, udpframe.MaxDatagram)
			for {
				n, err := local.Read(buf)
				if err != nil {
					ch.Close()
					return
				}
				if udpframe.Write(ch, buf[:n]) != nil {
					return
				}
			}
		}()
		fr := udpframe.NewReader(ch)
		for {
			d, err := fr.Read()
			if err != nil {
				return
			}
			local.Write(d)
		}
	}

	done := make(chan struct{})
	go func() {
		io.Copy(local, ch)
		if cw, ok := local.(interface{ CloseWrite() error }); ok {
			cw.CloseWrite()
		}
		close(done)
	}()
	io.Copy(ch, local)
	ch.CloseWrite()
	<-done
}

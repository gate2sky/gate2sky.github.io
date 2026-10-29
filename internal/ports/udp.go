package ports

import (
	"context"
	"errors"
	"net"
	"net/netip"
	"sync"
	"sync/atomic"
	"time"

	"github.com/gate2sky/gate2sky.github.io/internal/udpframe"
)

const (
	// udpIdle is how long a remote address keeps its stream to the client
	// without sending anything.
	udpIdle = 2 * time.Minute
	// maxSessions bounds the remote addresses a port serves at once.
	maxSessions = 512
	// queued is how many datagrams wait for a stream being opened.
	queued = 64
	// Replies to an address may add up to replyFactor times what it sent,
	// plus replyAllowance: a spoofed source can't turn the port into an
	// amplifier.
	replyFactor    = 10
	replyAllowance = 64 << 10
)

// udpSession is one remote address of a UDP port and its stream to the
// client.
type udpSession struct {
	remote   netip.AddrPort
	in       chan []byte
	done     chan struct{}
	once     sync.Once
	mu       sync.Mutex
	stream   net.Conn
	last     atomic.Int64 // unix nanoseconds
	received atomic.Int64
	sent     atomic.Int64
}

func (s *udpSession) close() {
	s.once.Do(func() {
		close(s.done)
		s.mu.Lock()
		if s.stream != nil {
			s.stream.Close()
		}
		s.mu.Unlock()
	})
}

func (f *Forward) serveUDP() {
	buf := make([]byte, udpframe.MaxDatagram+1)
	refusedLogged := map[netip.Addr]time.Time{}
	for {
		n, addr, err := f.pc.ReadFrom(buf)
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
			continue
		}
		ua, ok := addr.(*net.UDPAddr)
		if !ok || n > udpframe.MaxDatagram {
			continue
		}
		remote := ua.AddrPort()
		remote = netip.AddrPortFrom(remote.Addr().Unmap(), remote.Port())

		f.mu.Lock()
		s := f.sessions[remote]
		f.mu.Unlock()
		if s == nil {
			if !f.Allowed(remote.Addr()) {
				f.refused.Add(1)
				// Once a minute per address: datagrams come in floods.
				if t, seen := refusedLogged[remote.Addr()]; !seen || time.Since(t) > time.Minute {
					refusedLogged[remote.Addr()] = time.Now()
					f.logf("✖ %s (%s): refused %s, not in the allow list", f.Address, f.Name(), remote.Addr())
				}
				continue
			}
			if s = f.newSession(remote); s == nil {
				continue
			}
		}
		s.last.Store(time.Now().UnixNano())
		s.received.Add(int64(n))
		f.bytesIn.Add(int64(n))
		select {
		case s.in <- append([]byte(nil), buf[:n]...):
		default: // the client is behind: drop, as UDP may
		}
	}
}

// newSession starts serving a remote address, or returns nil when the port
// serves too many already.
func (f *Forward) newSession(remote netip.AddrPort) *udpSession {
	f.mu.Lock()
	defer f.mu.Unlock()
	select {
	case <-f.done:
		return nil
	default:
	}
	if len(f.sessions) >= maxSessions {
		return nil
	}
	s := &udpSession{remote: remote, in: make(chan []byte, queued), done: make(chan struct{})}
	s.last.Store(time.Now().UnixNano())
	f.sessions[remote] = s
	f.total.Add(1)
	f.active.Add(1)
	go f.runSession(s)
	return s
}

func (f *Forward) endSession(s *udpSession) {
	s.close()
	f.mu.Lock()
	if f.sessions[s.remote] == s {
		delete(f.sessions, s.remote)
		f.active.Add(-1)
	}
	f.mu.Unlock()
}

// runSession opens the stream to the client, then sends it the address's
// datagrams and sends back its replies.
func (f *Forward) runSession(s *udpSession) {
	defer f.endSession(s)
	ctx, cancel := context.WithTimeout(context.Background(), dialTimeout)
	stream, err := f.Dial(ctx, s.remote.String())
	cancel()
	if err != nil {
		f.logf("✖ %s (%s): could not reach the local service for %s: %v", f.Address, f.Name(), s.remote.Addr(), err)
		return
	}
	s.mu.Lock()
	s.stream = stream
	s.mu.Unlock()
	select {
	case <-s.done:
		stream.Close()
		return
	default:
	}

	go func() {
		defer s.close()
		r := udpframe.NewReader(stream)
		to := net.UDPAddrFromAddrPort(s.remote)
		for {
			d, err := r.Read()
			if err != nil {
				return
			}
			if s.sent.Load()+int64(len(d)) > replyFactor*s.received.Load()+replyAllowance {
				continue
			}
			if _, err := f.pc.WriteTo(d, to); err == nil {
				s.sent.Add(int64(len(d)))
				f.bytesOut.Add(int64(len(d)))
			}
		}
	}()
	for {
		select {
		case d := <-s.in:
			if udpframe.Write(stream, d) != nil {
				return
			}
		case <-s.done:
			return
		}
	}
}

// expireSessions ends the streams of addresses that went quiet.
func (f *Forward) expireSessions() {
	t := time.NewTicker(udpIdle / 8)
	defer t.Stop()
	for {
		select {
		case <-f.done:
			return
		case <-t.C:
		}
		cutoff := time.Now().Add(-udpIdle).UnixNano()
		f.mu.Lock()
		var idle []*udpSession
		for _, s := range f.sessions {
			if s.last.Load() < cutoff {
				idle = append(idle, s)
			}
		}
		f.mu.Unlock()
		for _, s := range idle {
			f.endSession(s)
		}
	}
}

package sshd

import (
	"fmt"
	"io"
	"strings"
	"sync"
	"sync/atomic"
)

// console delivers messages to the client's terminal. Messages printed
// before the client opens a session are queued; when the client is slow or
// never opens one (ssh -N), extra messages are dropped rather than
// blocking the tunnel.
type console struct {
	lines     chan string
	attach    chan attachment
	attached  atomic.Bool
	done      chan struct{}
	closeOnce sync.Once
}

type attachment struct {
	w      io.Writer
	header string
}

func newConsole() *console {
	c := &console{
		lines:  make(chan string, 256),
		attach: make(chan attachment, 1),
		done:   make(chan struct{}),
	}
	go c.run()
	return c
}

// Printf queues one line.
func (c *console) Printf(format string, args ...any) {
	line := strings.ReplaceAll(fmt.Sprintf(format, args...), "\n", "\r\n") + "\r\n"
	select {
	case c.lines <- line:
	default:
	}
}

// Attach starts writing to w, header first. Only the first call has effect.
func (c *console) Attach(w io.Writer, header string) {
	if c.attached.CompareAndSwap(false, true) {
		c.attach <- attachment{w, header}
	}
}

// Close stops the console.
func (c *console) Close() { c.closeOnce.Do(func() { close(c.done) }) }

func (c *console) run() {
	var a attachment
	select {
	case a = <-c.attach:
	case <-c.done:
		return
	}
	if _, err := io.WriteString(a.w, a.header); err != nil {
		return
	}
	for {
		select {
		case line := <-c.lines:
			if _, err := io.WriteString(a.w, line); err != nil {
				return
			}
		case <-c.done:
			return
		}
	}
}

// Package udpframe is how UDP travels over SSH between the intergate server
// and the intergate client, which plain OpenSSH can't do: the client asks
// for a port with a global request like tcpip-forward, and the server
// opens a channel per remote address, carrying its datagrams each after
// its length. The names keep gate2net, intergate's former name, so clients
// and servers released under it still understand each other.
package udpframe

import (
	"encoding/binary"
	"errors"
	"io"
)

const (
	// ForwardRequest asks the server to forward a UDP port, with the
	// payload of tcpip-forward (RFC 4254 section 7.1).
	ForwardRequest = "udp-forward@gate2net"
	// CancelRequest stops it.
	CancelRequest = "cancel-udp-forward@gate2net"
	// ChannelType carries the datagrams of one remote address, with the
	// payload of forwarded-tcpip (RFC 4254 section 7.2).
	ChannelType = "udp@gate2net"

	// MaxDatagram is the largest datagram carried.
	MaxDatagram = 65507
)

var errTooLarge = errors.New("datagram too large")

// Write sends one datagram.
func Write(w io.Writer, b []byte) error {
	if len(b) > MaxDatagram {
		return errTooLarge
	}
	frame := make([]byte, 2+len(b))
	binary.BigEndian.PutUint16(frame, uint16(len(b)))
	copy(frame[2:], b)
	_, err := w.Write(frame)
	return err
}

// Reader reads datagrams from a stream.
type Reader struct {
	r   io.Reader
	buf []byte
}

// NewReader reads datagrams from r.
func NewReader(r io.Reader) *Reader {
	return &Reader{r: r, buf: make([]byte, 2+MaxDatagram)}
}

// Read returns the next datagram, valid until the next call.
func (r *Reader) Read() ([]byte, error) {
	if _, err := io.ReadFull(r.r, r.buf[:2]); err != nil {
		return nil, err
	}
	n := int(binary.BigEndian.Uint16(r.buf))
	if n > MaxDatagram {
		return nil, errTooLarge
	}
	if _, err := io.ReadFull(r.r, r.buf[2:2+n]); err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return nil, err
	}
	return r.buf[2 : 2+n], nil
}

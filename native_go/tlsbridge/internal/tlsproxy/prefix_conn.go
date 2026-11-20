// Prefix replay (TLS-207, design §6.2).
//
// A probe has to read before it can decide, and the bytes it read are the start
// of the application stream: the ClientHello the proxy must hand to crypto/tls,
// or the first bytes of a passthrough copy. PrefixConn puts those bytes back in
// front of the connection, so every consumer downstream of the probe — a TLS
// handshake, a plain relay — reads the stream as if nothing had been consumed.

package tlsproxy

import (
	"errors"
	"io"
	"net"
	"time"
)

// ErrHalfCloseUnsupported is returned by CloseWrite when the wrapped connection
// cannot half-close. It is a typed answer and not a silent success: the relay
// (TLS-211) must be able to tell "the peer saw my FIN" from "no FIN was sent".
var ErrHalfCloseUnsupported = errors.New("tlsproxy: connection cannot half-close")

// PrefixConn is a net.Conn whose first bytes were already read by a probe. Read
// returns that prefix first and then continues on the underlying connection;
// everything else is delegated unchanged, so wrapping does not change how the
// transport behaves for the layer above.
//
// It has a single reader: the prefix is stream state, not a buffer that may be
// replayed twice.
type PrefixConn struct {
	conn     net.Conn
	prefix   []byte
	consumed int
	released func()
}

var _ net.Conn = (*PrefixConn)(nil)

// NewPrefixConn wraps conn with the bytes a probe already consumed. The prefix
// is taken over, not copied, and is released as soon as it has been replayed.
func NewPrefixConn(conn net.Conn, prefix []byte) *PrefixConn {
	return &PrefixConn{conn: conn, prefix: prefix}
}

// Buffered reports how many prefix bytes are still to be replayed.
func (c *PrefixConn) Buffered() int { return len(c.prefix) - c.consumed }

// Read drains the prefix before touching the underlying connection, so bytes
// that arrived during probing are not lost and do not have to be re-fetched.
func (c *PrefixConn) Read(p []byte) (int, error) {
	if c.consumed < len(c.prefix) {
		n := copy(p, c.prefix[c.consumed:])
		c.consumed += n
		if c.consumed == len(c.prefix) {
			// Fully replayed: drop the probe buffer instead of holding a copy
			// of the ClientHello for the life of the connection.
			c.prefix = nil
			if c.released != nil {
				c.released()
			}
			c.consumed = 0
		}
		return n, nil
	}
	if c.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return c.conn.Read(p)
}

func (c *PrefixConn) Write(p []byte) (int, error) {
	if c.conn == nil {
		return 0, io.ErrClosedPipe
	}
	return c.conn.Write(p)
}

func (c *PrefixConn) Close() error {
	if c.conn == nil {
		return nil
	}
	return c.conn.Close()
}

func (c *PrefixConn) LocalAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.LocalAddr()
}

func (c *PrefixConn) RemoteAddr() net.Addr {
	if c.conn == nil {
		return nil
	}
	return c.conn.RemoteAddr()
}

func (c *PrefixConn) SetDeadline(t time.Time) error {
	if c.conn == nil {
		return io.ErrClosedPipe
	}
	return c.conn.SetDeadline(t)
}

func (c *PrefixConn) SetReadDeadline(t time.Time) error {
	if c.conn == nil {
		return io.ErrClosedPipe
	}
	return c.conn.SetReadDeadline(t)
}

func (c *PrefixConn) SetWriteDeadline(t time.Time) error {
	if c.conn == nil {
		return io.ErrClosedPipe
	}
	return c.conn.SetWriteDeadline(t)
}

// CloseWrite forwards the transport's half-close. A wrapper that swallowed it
// would turn a clean upload-then-read exchange into a hung connection, so the
// method exists here even though only TLS-211 uses it.
func (c *PrefixConn) CloseWrite() error {
	if half, ok := c.conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return ErrHalfCloseUnsupported
}

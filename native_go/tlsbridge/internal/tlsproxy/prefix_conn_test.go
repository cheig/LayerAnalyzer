package tlsproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"testing"
	"time"
)

// halfCloser records a forwarded half-close.
type halfCloser struct {
	*scriptConn
	halfClosed bool
}

func (h *halfCloser) CloseWrite() error {
	h.halfClosed = true
	return nil
}

func TestPrefixConnReplaysBeforeTheConnection(t *testing.T) {
	prefix := []byte("already read")
	underlying := newScriptConn([]byte(" from the connection"))
	conn := NewPrefixConn(underlying, prefix)

	if conn.Buffered() != len(prefix) {
		t.Fatalf("Buffered() = %d, want %d", conn.Buffered(), len(prefix))
	}
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading replayed connection: %v", err)
	}
	if want := append(append([]byte{}, prefix...), " from the connection"...); !bytes.Equal(data, want) {
		t.Fatalf("read %q, want %q", data, want)
	}
	if conn.Buffered() != 0 {
		t.Fatalf("Buffered() = %d after the prefix was drained", conn.Buffered())
	}
}

// TestPrefixConnChunkedReads: the prefix is stream state, so it must be handed
// out in whatever sizes the layer above asks for, in order.
func TestPrefixConnChunkedReads(t *testing.T) {
	prefix := []byte("0123456789")
	conn := NewPrefixConn(newScriptConn([]byte("abc")), prefix)
	var got []byte
	for index := 0; ; index++ {
		size := index%3 + 1
		buffer := make([]byte, size)
		n, err := conn.Read(buffer)
		if n > 0 {
			got = append(got, buffer[:n]...)
		}
		if err != nil {
			if err != io.EOF {
				t.Fatalf("read %d returned %v", index, err)
			}
			break
		}
	}
	if want := []byte("0123456789abc"); !bytes.Equal(got, want) {
		t.Fatalf("read %q, want %q", got, want)
	}
}

// TestPrefixConnDoesNotTouchTheConnectionEarly: while prefix bytes remain, no
// read may reach the transport, or the replay order would invert.
func TestPrefixConnDoesNotTouchTheConnectionEarly(t *testing.T) {
	underlying := newScriptConn([]byte("later"))
	conn := NewPrefixConn(underlying, []byte("first"))
	buffer := make([]byte, 3)
	if _, err := conn.Read(buffer); err != nil {
		t.Fatalf("reading the prefix: %v", err)
	}
	if underlying.reads != 0 {
		t.Fatalf("the transport was read %d times while prefix bytes remained", underlying.reads)
	}
}

func TestPrefixConnWithNoPrefix(t *testing.T) {
	conn := NewPrefixConn(newScriptConn([]byte("stream")), nil)
	data, err := io.ReadAll(conn)
	if err != nil {
		t.Fatalf("reading: %v", err)
	}
	if string(data) != "stream" {
		t.Fatalf("read %q, want stream", data)
	}
}

func TestPrefixConnDelegatesWritesAndDeadlines(t *testing.T) {
	underlying := newScriptConn()
	conn := NewPrefixConn(underlying, []byte("prefix"))
	if _, err := conn.Write([]byte("request")); err != nil {
		t.Fatalf("write: %v", err)
	}
	if underlying.writes.String() != "request" {
		t.Fatalf("underlying connection received %q", underlying.writes.String())
	}
	deadline := time.Now().Add(time.Minute)
	if err := conn.SetDeadline(deadline); err != nil {
		t.Fatalf("SetDeadline: %v", err)
	}
	if err := conn.SetReadDeadline(deadline); err != nil {
		t.Fatalf("SetReadDeadline: %v", err)
	}
	if !underlying.readDeadline.Equal(deadline) {
		t.Fatalf("read deadline = %s, want %s", underlying.readDeadline, deadline)
	}
	if err := conn.SetWriteDeadline(deadline); err != nil {
		t.Fatalf("SetWriteDeadline: %v", err)
	}
	if conn.LocalAddr().String() != "local" || conn.RemoteAddr().String() != "remote" {
		t.Fatalf("addresses = %s/%s, want local/remote", conn.LocalAddr(), conn.RemoteAddr())
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	if !underlying.closed {
		t.Fatal("Close was not forwarded")
	}
}

// TestPrefixConnForwardsHalfClose: a wrapper that swallowed the transport's FIN
// would turn a clean upload-then-read exchange into a hung connection.
func TestPrefixConnForwardsHalfClose(t *testing.T) {
	underlying := &halfCloser{scriptConn: newScriptConn()}
	conn := NewPrefixConn(underlying, nil)
	if err := conn.CloseWrite(); err != nil {
		t.Fatalf("CloseWrite: %v", err)
	}
	if !underlying.halfClosed {
		t.Fatal("half-close was not forwarded")
	}

	plain := NewPrefixConn(newScriptConn(), nil)
	if err := plain.CloseWrite(); !errors.Is(err, ErrHalfCloseUnsupported) {
		t.Fatalf("CloseWrite on a transport without it = %v, want ErrHalfCloseUnsupported", err)
	}
}

func TestPrefixConnWithoutAConnection(t *testing.T) {
	conn := NewPrefixConn(nil, nil)
	if _, err := conn.Read(make([]byte, 1)); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Read = %v, want io.ErrClosedPipe", err)
	}
	if _, err := conn.Write([]byte("x")); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("Write = %v, want io.ErrClosedPipe", err)
	}
	if err := conn.SetDeadline(time.Now()); !errors.Is(err, io.ErrClosedPipe) {
		t.Fatalf("SetDeadline = %v, want io.ErrClosedPipe", err)
	}
	if err := conn.Close(); err != nil {
		t.Fatalf("Close = %v, want nil", err)
	}
}

// TestReplayedPrefixIsAcceptedByCryptoTLSServer proves the replay at the
// protocol level rather than byte by byte: the bytes a probe consumed are fed
// back into tls.Server through a PrefixConn and the server answers with a
// handshake record instead of an alert.
func TestReplayedPrefixIsAcceptedByCryptoTLSServer(t *testing.T) {
	hello := realClientHello(t, &tls.Config{
		ServerName: "example.test",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS12,
	})

	clientEnd, serverEnd := net.Pipe()
	replayed := NewPrefixConn(serverEnd, hello)
	server := tls.Server(replayed, &tls.Config{
		Certificates: []tls.Certificate{leafFor(t, x509.ECDSA, []string{"example.test"}, nil)},
		MinVersion:   tls.VersionTLS12,
	})
	handshakeDone := make(chan error, 1)
	go func() { handshakeDone <- server.Handshake() }()

	if err := clientEnd.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting read deadline: %v", err)
	}
	first := make([]byte, 1)
	if _, err := io.ReadFull(clientEnd, first); err != nil {
		t.Fatalf("reading the server's first byte: %v", err)
	}
	if first[0] != recordTypeHandshake {
		t.Fatalf("server answered with record type %#x, want a handshake record: the replayed hello was rejected", first[0])
	}
	// The captured hello is consumed once and released: nothing may keep a copy
	// of the client's hello for the life of the connection.
	if replayed.Buffered() != 0 {
		t.Fatalf("%d prefix bytes are still buffered after the handshake read them", replayed.Buffered())
	}

	clientEnd.Close()
	serverEnd.Close()
	<-handshakeDone
}

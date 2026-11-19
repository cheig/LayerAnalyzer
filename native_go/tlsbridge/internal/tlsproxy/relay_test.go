package tlsproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// The relay tests run on two kinds of real connection. The TLS cases go through
// the whole TLS-209 path — a real ClientHello probe, a real upstream handshake
// against a real listener, a real CA-signed leaf on the downstream leg — and
// then relay the two *tls.Conn the coordinator actually hands back, write
// boundary included. The plain cases relay loopback TCP, which is the same code
// path a bypassed connection takes (TLS-213). Nothing here mocks a transport
// except where the mock is the point: a wrapper that cannot half-close, and a
// transport that ignores Close.

// relayOrigin is the real server at the far end of a relayed connection. What
// it does after the handshake belongs to the test, so a case can be an echo, a
// server that answers only once the client has finished sending, a slow reader,
// or one that resets the connection.
type relayOrigin struct {
	address string
}

func newRelayOrigin(t *testing.T, serve func(*tls.Conn, net.Conn)) *relayOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening as the origin: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	// The certificate has to be for the identity the coordinator is given: the
	// upstream handshake verifies the name before any platform callback runs.
	certificate := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		server := tls.Server(conn, &tls.Config{
			Certificates: []tls.Certificate{certificate},
			MinVersion:   tls.VersionTLS12,
		})
		if err := server.Handshake(); err != nil {
			_ = conn.Close()
			return
		}
		serve(server, conn)
	}()
	return &relayOrigin{address: listener.Addr().String()}
}

// relayedTLS is one relayed connection after a real double handshake.
type relayedTLS struct {
	app     *appClient
	session Session
	results <-chan Result
}

// startRelayedTLS establishes both legs through the production coordinator and
// then relays them. The handshake budget is a parameter because one case pins
// that it does not survive into the data path.
func startRelayedTLS(t *testing.T, ctx context.Context, limits RelayLimits, handshakeBudget time.Duration, serve func(*tls.Conn, net.Conn)) *relayedTLS {
	t.Helper()
	ca, pool := testCA(t)
	origin := newRelayOrigin(t, serve)
	result, _ := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		originAddress: origin.address,
		trustCA:       true,
	}, &platformStub{verdict: engine.OK}, handshakeBudget)
	if !result.session.Intercepted() {
		t.Fatalf("the coordinator did not establish both legs: %s / %s", result.session.Code, result.session.Reason)
	}
	results := startRelayOver(t, ctx, limits, result.session.Downstream, result.session.Upstream)
	return &relayedTLS{app: result.app, session: result.session, results: results}
}

func (r *relayedTLS) wait(t *testing.T) Result {
	t.Helper()
	return awaitRelay(t, r.results)
}

// startRelayOver relays two already-built connections.
func startRelayOver(t *testing.T, ctx context.Context, limits RelayLimits, downstream, upstream net.Conn) <-chan Result {
	t.Helper()
	relay, code := NewRelay(limits)
	if code != engine.OK {
		t.Fatalf("NewRelay(%+v) = %v", limits, code)
	}
	results := make(chan Result, 1)
	go func() { results <- relay.Run(ctx, downstream, upstream) }()
	return results
}

func awaitRelay(t *testing.T, results <-chan Result) Result {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(20 * time.Second):
		t.Fatal("the relay never returned")
		return Result{}
	}
}

// requireClean asserts the relay ended because both peers were done, and not
// because anything broke.
func requireClean(t *testing.T, result Result) {
	t.Helper()
	if result.Code != engine.OK {
		t.Fatalf("relay ended as %s / %s in direction %q after %d/%d bytes",
			result.Code, result.Reason, result.Direction, result.BytesToUpstream, result.BytesToDownstream)
	}
}

// tcpPair returns the two ends of one loopback TCP connection: the dialed side
// first, the accepted side second.
func tcpPair(t *testing.T) (net.Conn, net.Conn) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for a loopback pair: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	accepted := make(chan net.Conn, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			accepted <- nil
			return
		}
		accepted <- conn
	}()
	dialed, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dialing the loopback pair: %v", err)
	}
	other := <-accepted
	if other == nil {
		t.Fatal("accepting the loopback pair")
	}
	t.Cleanup(func() {
		_ = dialed.Close()
		_ = other.Close()
	})
	return dialed, other
}

// halfClose ends the test's own sending side, which is what a request-response
// client does before it waits for the answer.
func halfClose(t *testing.T, conn net.Conn) {
	t.Helper()
	half, ok := conn.(interface{ CloseWrite() error })
	if !ok {
		t.Fatal("the test's own connection cannot half-close")
	}
	if err := half.CloseWrite(); err != nil {
		t.Fatalf("half-closing the test's connection: %v", err)
	}
}

// shrinkBuffers gives every socket in a relay path a small send and receive
// buffer, so a test about what the relay does with a large body is not also
// measuring this host's socket autotuning.
func shrinkBuffers(t *testing.T, conns ...net.Conn) {
	t.Helper()
	for _, conn := range conns {
		tcp, ok := conn.(*net.TCPConn)
		if !ok {
			t.Fatalf("the test's own connection is not a TCP connection")
		}
		if err := tcp.SetReadBuffer(4096); err != nil {
			t.Fatalf("shrinking a receive buffer: %v", err)
		}
		if err := tcp.SetWriteBuffer(4096); err != nil {
			t.Fatalf("shrinking a send buffer: %v", err)
		}
	}
}

// echoOrigin answers every byte it reads and closes when the client is done.
// It is the shape of the majority of real connections.
func echoOrigin(server *tls.Conn, _ net.Conn) {
	defer server.Close()
	buffer := make([]byte, 4096)
	for {
		n, err := server.Read(buffer)
		if n > 0 {
			if _, writeErr := server.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

// writeInChunks writes payload in small pieces, so a test that measures what the
// relay does with it is not measuring one large socket write.
func writeInChunks(conn net.Conn, payload []byte, chunk int) (int, error) {
	written := 0
	for written < len(payload) {
		end := written + chunk
		if end > len(payload) {
			end = len(payload)
		}
		n, err := conn.Write(payload[written:end])
		written += n
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// TestRelayCarriesApplicationDataBothDirections is the baseline: a relayed
// connection behaves like the connection the application asked for, in both
// directions, and ends cleanly when both peers are done.
func TestRelayCarriesApplicationDataBothDirections(t *testing.T) {
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, 0, echoOrigin)

	relayed.app.send(t, "ping")
	if echo := relayed.app.receive(t); echo != "ping" {
		t.Fatalf("the client received %q, want the bytes it sent", echo)
	}

	// The client finishes sending first, as a request-response client does. The
	// origin answers the end of the stream by closing, so the relay can finish
	// both directions.
	if err := relayed.app.conn.CloseWrite(); err != nil {
		t.Fatalf("half-closing the application's connection: %v", err)
	}
	rest, err := io.ReadAll(relayed.app.conn)
	if err != nil {
		t.Fatalf("reading after the half-close: %v", err)
	}
	if len(rest) != 0 {
		t.Fatalf("the client received %d unexpected bytes after the exchange", len(rest))
	}

	result := relayed.wait(t)
	requireClean(t, result)
	if result.BytesToUpstream != 4 || result.BytesToDownstream != 4 {
		t.Fatalf("relay copied %d up / %d down, want 4 / 4", result.BytesToUpstream, result.BytesToDownstream)
	}
	if !result.DownstreamHalfClosed || !result.UpstreamHalfClosed {
		t.Fatalf("a clean end of both streams was not recorded: %+v", result)
	}
	if result.HalfCloseUnsupported {
		t.Fatalf("a transport that does support half-close was reported without it: %+v", result)
	}
}

// TestUploadHalfCloseStillReceivesTheWholeAnswer is the case §6.5 exists for: a
// client that uploads, half-closes, and then waits for the answer must still get
// all of it. A relay that closed both sides when either one ended would truncate
// exactly here.
func TestUploadHalfCloseStillReceivesTheWholeAnswer(t *testing.T) {
	const bodyBytes = 512 << 10
	body := bytes.Repeat([]byte("response-body-"), bodyBytes/14+1)[:bodyBytes]
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, 0, func(server *tls.Conn, _ net.Conn) {
		defer server.Close()
		// The origin answers only once the client has finished sending, which
		// is where a half-close that was not forwarded becomes a hang.
		if _, err := io.Copy(io.Discard, server); err != nil {
			return
		}
		_, _ = server.Write(body)
	})

	if _, err := relayed.app.conn.Write([]byte("GET /")); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	if err := relayed.app.conn.CloseWrite(); err != nil {
		t.Fatalf("half-closing the application's connection: %v", err)
	}
	_ = relayed.app.conn.SetReadDeadline(time.Now().Add(15 * time.Second))
	answer, err := io.ReadAll(relayed.app.conn)
	if err != nil {
		t.Fatalf("reading the answer after the half-close: %v", err)
	}
	if !bytes.Equal(answer, body) {
		t.Fatalf("the client received %d of %d answer bytes", len(answer), len(body))
	}

	result := relayed.wait(t)
	requireClean(t, result)
	if result.BytesToDownstream != int64(bodyBytes) {
		t.Fatalf("the relay copied %d bytes down, want %d", result.BytesToDownstream, bodyBytes)
	}
	if !result.DownstreamHalfClosed || !result.UpstreamHalfClosed {
		t.Fatalf("the half-closed upload was not recorded: %+v", result)
	}
}

// TestAPlainRelayForwardsHalfCloseAndTheWholeAnswer is the same exchange on a
// bypassed connection: plain TCP, same code, FIN instead of close_notify.
func TestAPlainRelayForwardsHalfCloseAndTheWholeAnswer(t *testing.T) {
	client, relayDown := tcpPair(t)
	relayUp, origin := tcpPair(t)
	results := startRelayOver(t, context.Background(), RelayLimits{}, relayDown, relayUp)

	go func() {
		defer origin.Close()
		if _, err := io.Copy(io.Discard, origin); err != nil {
			return
		}
		_, _ = origin.Write([]byte("answer"))
	}()

	if _, err := client.Write([]byte("request")); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	halfClose(t, client)
	_ = client.SetReadDeadline(time.Now().Add(15 * time.Second))
	answer, err := io.ReadAll(client)
	if err != nil {
		t.Fatalf("reading the answer after the half-close: %v", err)
	}
	if string(answer) != "answer" {
		t.Fatalf("the client received %q, want %q", answer, "answer")
	}

	result := awaitRelay(t, results)
	requireClean(t, result)
	if result.BytesToUpstream != 7 || result.BytesToDownstream != 6 {
		t.Fatalf("relay copied %d up / %d down, want 7 / 6", result.BytesToUpstream, result.BytesToDownstream)
	}
	if !result.DownstreamHalfClosed || !result.UpstreamHalfClosed {
		t.Fatalf("a plain half-close was not recorded: %+v", result)
	}
}

// measuringConn records the largest buffer a Read was handed, which is how the
// fixed-memory requirement is checked without measuring allocations.
type measuringConn struct {
	net.Conn
	maxRead atomic.Int64
}

func (c *measuringConn) Read(p []byte) (int, error) {
	if int64(len(p)) > c.maxRead.Load() {
		c.maxRead.Store(int64(len(p)))
	}
	return c.Conn.Read(p)
}

// CloseWrite forwards the half-close. A wrapper that swallowed it would be a
// different test (see TestAHalfCloseThatCannotBeForwardedIsRecorded).
func (c *measuringConn) CloseWrite() error {
	if half, ok := c.Conn.(interface{ CloseWrite() error }); ok {
		return half.CloseWrite()
	}
	return ErrHalfCloseUnsupported
}

// TestABodyLargerThanTheBufferKeepsTheBufferFixed pins that a body far larger
// than the relay's budget crosses it in fixed memory: the relay never asks a
// transport for more than one buffer, so it cannot be holding the body.
func TestABodyLargerThanTheBufferKeepsTheBufferFixed(t *testing.T) {
	const bodyBytes = 4 << 20
	payload := bytes.Repeat([]byte("0123456789abcdef"), bodyBytes/16)

	client, relayDown := tcpPair(t)
	relayUp, originConn := tcpPair(t)
	down := &measuringConn{Conn: relayDown}
	up := &measuringConn{Conn: relayUp}
	results := startRelayOver(t, context.Background(), RelayLimits{}, down, up)

	received := make(chan []byte, 1)
	go func() {
		body, err := io.ReadAll(originConn)
		_ = originConn.Close()
		if err != nil {
			received <- nil
			return
		}
		received <- body
	}()

	wrote := make(chan int, 1)
	go func() {
		n, _ := writeInChunks(client, payload, 997)
		// The half-close is deliberately reported to the test rather than
		// asserted here: a failure must not call t.Fatal from another goroutine.
		if half, ok := client.(interface{ CloseWrite() error }); ok {
			_ = half.CloseWrite()
		}
		wrote <- n
	}()

	if n := <-wrote; n != bodyBytes {
		t.Fatalf("the client wrote %d of %d bytes", n, bodyBytes)
	}
	select {
	case body := <-received:
		if !bytes.Equal(body, payload) {
			t.Fatalf("the origin received %d of %d bytes, and they are not the ones that were sent", len(body), bodyBytes)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the origin never received the whole body")
	}

	result := awaitRelay(t, results)
	requireClean(t, result)
	if result.BytesToUpstream != int64(bodyBytes) {
		t.Fatalf("the relay copied %d bytes up, want %d", result.BytesToUpstream, bodyBytes)
	}
	if got := down.maxRead.Load(); got != DefaultRelayBufferBytes {
		t.Fatalf("the relay read into a %d-byte buffer, want %d", got, DefaultRelayBufferBytes)
	}
	if got := up.maxRead.Load(); got != DefaultRelayBufferBytes {
		t.Fatalf("the relay read into a %d-byte buffer, want %d", got, DefaultRelayBufferBytes)
	}
}

// TestASlowReaderBacksUpToTheSender pins where backpressure lives: with the
// origin not reading, the relay must not accumulate the body on its behalf —
// the sender stalls instead. §6.5 requires exactly that, and a relay that
// buffered would look identical from the outside until it ran out of memory.
func TestASlowReaderBacksUpToTheSender(t *testing.T) {
	const bodyBytes = 8 << 20
	payload := bytes.Repeat([]byte("slow-reader-body"), bodyBytes/16)

	client, relayDown := tcpPair(t)
	relayUp, originConn := tcpPair(t)
	// The sockets are given small buffers so the assertion below is about the
	// relay and not about how much this host's loopback happens to absorb: with
	// these in place the whole path can hold a few tens of kilobytes, whatever
	// the operating system would otherwise autotune to.
	shrinkBuffers(t, client, relayDown, relayUp, originConn)
	results := startRelayOver(t, context.Background(), RelayLimits{}, relayDown, relayUp)

	release := make(chan struct{})
	drained := make(chan int64, 1)
	go func() {
		<-release
		n, _ := io.Copy(io.Discard, originConn)
		_ = originConn.Close()
		drained <- n
	}()

	written := make(chan int, 1)
	go func() {
		n, _ := writeInChunks(client, payload, 32<<10)
		written <- n
	}()

	// The origin has read nothing, so the sender can only have filled the
	// socket buffers plus the relay's own two directions' worth of buffer.
	select {
	case n := <-written:
		t.Fatalf("the sender wrote %d of %d bytes with nothing reading at the far end", n, bodyBytes)
	case <-time.After(500 * time.Millisecond):
	}

	close(release)
	select {
	case n := <-written:
		if n != bodyBytes {
			t.Fatalf("the sender wrote %d of %d bytes once the reader started", n, bodyBytes)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the sender never finished once the origin started reading")
	}
	// The origin reads to the end of the stream, so the client's half-close is
	// what releases it.
	halfClose(t, client)
	select {
	case n := <-drained:
		if n != bodyBytes {
			t.Fatalf("the origin received %d of %d bytes", n, bodyBytes)
		}
	case <-time.After(30 * time.Second):
		t.Fatal("the origin never received the whole body")
	}

	result := awaitRelay(t, results)
	requireClean(t, result)
	if result.BytesToUpstream != int64(bodyBytes) {
		t.Fatalf("the relay copied %d bytes up, want %d", result.BytesToUpstream, bodyBytes)
	}
}

// TestAStreamedResponseArrivesIntact is the long-lived-stream shape: a server
// that keeps producing small pieces over time while the client consumes them.
// Nothing in the relay knows what the bytes mean, so what this pins is that a
// stream spread over hundreds of reads and pauses is carried in order, whole,
// and without the connection being ended for being slow.
func TestAStreamedResponseArrivesIntact(t *testing.T) {
	const chunks = 200
	const chunkBytes = 1 << 10
	chunk := bytes.Repeat([]byte("stream"), chunkBytes/6+1)[:chunkBytes]

	relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, 0, func(server *tls.Conn, _ net.Conn) {
		defer server.Close()
		request := make([]byte, 5)
		if _, err := io.ReadFull(server, request); err != nil {
			return
		}
		for index := 0; index < chunks; index++ {
			if _, err := server.Write(chunk); err != nil {
				return
			}
			time.Sleep(5 * time.Millisecond)
		}
	})

	if _, err := relayed.app.conn.Write([]byte("start")); err != nil {
		t.Fatalf("requesting the stream: %v", err)
	}
	_ = relayed.app.conn.SetReadDeadline(time.Now().Add(30 * time.Second))
	stream := make([]byte, chunks*chunkBytes)
	if _, err := io.ReadFull(relayed.app.conn, stream); err != nil {
		t.Fatalf("reading the stream: %v", err)
	}
	for index := 0; index < chunks; index++ {
		got := stream[index*chunkBytes : (index+1)*chunkBytes]
		if !bytes.Equal(got, chunk) {
			t.Fatalf("chunk %d of the stream is not the one that was sent", index)
		}
	}
	halfClose(t, relayed.app.conn)

	result := relayed.wait(t)
	requireClean(t, result)
	if result.BytesToDownstream != int64(chunks*chunkBytes) {
		t.Fatalf("the relay copied %d bytes down, want %d", result.BytesToDownstream, chunks*chunkBytes)
	}
}

// TestAResetFromTheOriginEndsTheRelayPromptly pins that a reset is a fault and
// not a wait: neither the application nor the relay may be left parked by a peer
// that vanished.
func TestAResetFromTheOriginEndsTheRelayPromptly(t *testing.T) {
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, 0, func(_ *tls.Conn, raw net.Conn) {
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = raw.Close()
	})

	start := time.Now()
	result := relayed.wait(t)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the relay took %v to notice a reset", elapsed)
	}
	if result.Code != engine.IOError || result.Reason != ReasonRelayReadFailed {
		t.Fatalf("a reset origin was reported as %s / %s", result.Code, result.Reason)
	}
	if result.Direction != UpstreamToDownstream {
		t.Fatalf("the reset was attributed to %q", result.Direction)
	}
	if result.JoinTimedOut {
		t.Fatalf("the relay waited out its join budget after a reset: %+v", result)
	}
	// The application is released rather than left hanging on a dead connection.
	_ = relayed.app.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := relayed.app.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the application's read returned data after the origin was reset")
	}
}

// TestBothDirectionsBreakingPublishesOneTerminalState is the counterweight to
// the first-fault rule: when both peers vanish at once, both copies fail, and
// the connection still gets exactly one published state — the relay returns one
// Result and never reports two outcomes.
func TestBothDirectionsBreakingPublishesOneTerminalState(t *testing.T) {
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, 0, func(_ *tls.Conn, raw net.Conn) {
		if tcp, ok := raw.(*net.TCPConn); ok {
			_ = tcp.SetLinger(0)
		}
		_ = raw.Close()
	})
	// Reset the application's own socket as well, so the second copy breaks
	// too rather than waiting for a peer that is already gone.
	if tcp, ok := relayed.app.conn.NetConn().(*net.TCPConn); ok {
		_ = tcp.SetLinger(0)
		_ = tcp.Close()
	}

	result := relayed.wait(t)
	if result.Code == engine.OK {
		t.Fatalf("a connection both peers reset was reported as clean: %+v", result)
	}
	if result.Reason == "" {
		t.Fatalf("a failed relay published no reason: %+v", result)
	}
	if result.JoinTimedOut {
		t.Fatalf("the relay waited out its join budget instead of ending: %+v", result)
	}
}

// TestAQuietConnectionIsNotEndedAndCarriesNoHandshakeDeadline is §6.5's other
// half: a WebSocket or gRPC stream that says nothing for a while must survive,
// and the handshake budget must not have survived into the data path. The
// coordinator is given a deliberately tiny handshake budget that is then far
// exceeded before any application byte moves.
func TestAQuietConnectionIsNotEndedAndCarriesNoHandshakeDeadline(t *testing.T) {
	const handshakeBudget = 250 * time.Millisecond
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, handshakeBudget, echoOrigin)

	time.Sleep(4 * handshakeBudget)

	relayed.app.send(t, "after-the-quiet")
	if echo := relayed.app.receive(t); echo != "after-the-quiet" {
		t.Fatalf("the client received %q after the quiet period", echo)
	}
	if err := relayed.app.conn.CloseWrite(); err != nil {
		t.Fatalf("half-closing the application's connection: %v", err)
	}
	if rest, err := io.ReadAll(relayed.app.conn); err != nil || len(rest) != 0 {
		t.Fatalf("reading after the half-close: %d bytes, %v", len(rest), err)
	}
	requireClean(t, relayed.wait(t))
}

// TestTheIdlePolicyEndsASilentConnection pins the separate idle policy: it is
// off by default (above) and ends a connection that really has moved nothing
// when it is configured.
func TestTheIdlePolicyEndsASilentConnection(t *testing.T) {
	const idle = 200 * time.Millisecond
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{IdleTimeout: idle}, 0, echoOrigin)

	start := time.Now()
	result := relayed.wait(t)
	elapsed := time.Since(start)
	if result.Code != engine.IOError || result.Reason != ReasonRelayIdleTimeout {
		t.Fatalf("a silent connection ended as %s / %s", result.Code, result.Reason)
	}
	if result.Direction != "" {
		t.Fatalf("a whole-connection idle policy was attributed to %q", result.Direction)
	}
	if elapsed > 5*time.Second {
		t.Fatalf("the idle policy fired after %v, want it bounded by its %v budget", elapsed, idle)
	}
	// The application is released: an idle policy ends a connection, it does not
	// leave it dangling.
	_ = relayed.app.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := relayed.app.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the application's read returned data after the idle policy fired")
	}
}

// TestTrafficKeepsAnIdlePolicyFromFiring pins that the idle budget is an idle
// budget and not a session length: bytes in either direction reset it, and it
// still fires once the traffic really stops.
func TestTrafficKeepsAnIdlePolicyFromFiring(t *testing.T) {
	const idle = 500 * time.Millisecond
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{IdleTimeout: idle}, 0, echoOrigin)

	for tick := 0; tick < 20; tick++ {
		relayed.app.send(t, "tick")
		if echo := relayed.app.receive(t); echo != "tick" {
			t.Fatalf("tick %d came back as %q", tick, echo)
		}
		time.Sleep(50 * time.Millisecond)
	}

	// Twenty exchanges over a second with a half-second budget: the policy not
	// having fired during them is the assertion. Now that they stopped, it must.
	result := relayed.wait(t)
	if result.Code != engine.IOError || result.Reason != ReasonRelayIdleTimeout {
		t.Fatalf("traffic did not end as an idle timeout: %s / %s", result.Code, result.Reason)
	}
}

// TestCancellationReleasesBothDirections pins the caller's abort: cancelling the
// context ends the connection, releases both peers, and is attributed to the
// caller rather than to either transport.
func TestCancellationReleasesBothDirections(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	relayed := startRelayedTLS(t, ctx, RelayLimits{}, 0, echoOrigin)

	start := time.Now()
	cancel()
	result := relayed.wait(t)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("cancellation took %v to end the relay", elapsed)
	}
	if result.Code != engine.Cancelled || result.Reason != ReasonRelayCancelled {
		t.Fatalf("a cancelled relay ended as %s / %s", result.Code, result.Reason)
	}
	if result.Direction != "" {
		t.Fatalf("a cancellation was attributed to %q", result.Direction)
	}
	_ = relayed.app.conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := relayed.app.conn.Read(make([]byte, 1)); err == nil {
		t.Fatal("the application was left connected after the relay was cancelled")
	}
}

// stubbornConn ignores Close and never ends its Read. It is how a join budget is
// reached without waiting for a real peer to misbehave.
type stubbornConn struct {
	release chan struct{}
}

func newStubbornConn() *stubbornConn { return &stubbornConn{release: make(chan struct{})} }

func (c *stubbornConn) Read([]byte) (int, error)         { <-c.release; return 0, io.EOF }
func (c *stubbornConn) Write(p []byte) (int, error)      { return len(p), nil }
func (c *stubbornConn) Close() error                     { return nil }
func (c *stubbornConn) LocalAddr() net.Addr              { return nil }
func (c *stubbornConn) RemoteAddr() net.Addr             { return nil }
func (c *stubbornConn) SetDeadline(time.Time) error      { return nil }
func (c *stubbornConn) SetReadDeadline(time.Time) error  { return nil }
func (c *stubbornConn) SetWriteDeadline(time.Time) error { return nil }

// TestAnUninterruptibleDirectionIsJoinedOnABoundedBudget pins that the join is
// bounded. Closing the transports releases a direction parked in a real read;
// this one is deliberately immune to that, so the relay has to give up waiting
// and say so rather than hold a shutdown open forever.
func TestAnUninterruptibleDirectionIsJoinedOnABoundedBudget(t *testing.T) {
	parked := newStubbornConn()
	t.Cleanup(func() { close(parked.release) })
	_, relayUp := tcpPair(t)

	ctx, cancel := context.WithCancel(context.Background())
	results := startRelayOver(t, ctx, RelayLimits{JoinTimeout: 50 * time.Millisecond}, parked, relayUp)

	start := time.Now()
	cancel()
	result := awaitRelay(t, results)
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the bounded join took %v", elapsed)
	}
	if result.Code != engine.Cancelled || result.Reason != ReasonRelayCancelled {
		t.Fatalf("the relay ended as %s / %s", result.Code, result.Reason)
	}
	if !result.JoinTimedOut {
		t.Fatalf("a copy that cannot be interrupted was not reported as a timed-out join: %+v", result)
	}
}

// wrappedConn hides CloseWrite, the way a wrapper that embeds net.Conn and
// forwards nothing does. It is not hypothetical: it is what an untyped wrapper
// looks like to the relay.
type wrappedConn struct{ net.Conn }

// TestAHalfCloseThatCannotBeForwardedIsRecorded covers both ways a transport can
// refuse a half-close: not having the method at all, and having it return
// ErrHalfCloseUnsupported (which is what PrefixConn does when the transport
// underneath it cannot half-close). Neither is a copy failure — the bytes moved
// — so both are recorded rather than turned into a fault.
func TestAHalfCloseThatCannotBeForwardedIsRecorded(t *testing.T) {
	cases := []struct {
		name string
		wrap func(net.Conn) net.Conn
	}{
		{"untyped wrapper", func(conn net.Conn) net.Conn { return &wrappedConn{Conn: conn} }},
		{"prefix replay over a transport without half-close", func(conn net.Conn) net.Conn {
			return NewPrefixConn(&wrappedConn{Conn: conn}, nil)
		}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			client, relayDown := tcpPair(t)
			relayUp, origin := tcpPair(t)
			results := startRelayOver(t, context.Background(), RelayLimits{}, test.wrap(relayDown), relayUp)

			go func() {
				_, _ = origin.Write([]byte("answer"))
				_ = origin.Close()
			}()

			answer := make([]byte, 6)
			_ = client.SetReadDeadline(time.Now().Add(10 * time.Second))
			if _, err := io.ReadFull(client, answer); err != nil {
				t.Fatalf("reading the answer: %v", err)
			}
			if string(answer) != "answer" {
				t.Fatalf("the client received %q, want %q", answer, "answer")
			}
			halfClose(t, client)

			result := awaitRelay(t, results)
			requireClean(t, result)
			if !result.HalfCloseUnsupported {
				t.Fatalf("a refused half-close was not recorded: %+v", result)
			}
			if result.BytesToDownstream != 6 {
				t.Fatalf("the relay copied %d bytes down, want 6", result.BytesToDownstream)
			}
			if !result.DownstreamHalfClosed || !result.UpstreamHalfClosed {
				t.Fatalf("the two ends of stream were not recorded: %+v", result)
			}
		})
	}
}

// TestRelayLimitsAndInputValidation pins the budget rules: a relay can be
// tightened but not raised, and a call that cannot be started takes nothing
// over.
func TestRelayLimitsAndInputValidation(t *testing.T) {
	t.Run("limits", func(t *testing.T) {
		cases := []struct {
			name   string
			limits RelayLimits
			want   engine.Code
		}{
			{"defaults", RelayLimits{}, engine.OK},
			{"at the ceilings", RelayLimits{BufferBytes: MaxRelayBufferBytes, JoinTimeout: MaxRelayJoinTimeout}, engine.OK},
			{"idle is a policy, not a budget", RelayLimits{IdleTimeout: time.Hour}, engine.OK},
			{"buffer above the ceiling", RelayLimits{BufferBytes: MaxRelayBufferBytes + 1}, engine.InvalidArgument},
			{"negative buffer", RelayLimits{BufferBytes: -1}, engine.InvalidArgument},
			{"negative idle", RelayLimits{IdleTimeout: -time.Millisecond}, engine.InvalidArgument},
			{"join above the ceiling", RelayLimits{JoinTimeout: MaxRelayJoinTimeout + time.Millisecond}, engine.InvalidArgument},
			{"negative join", RelayLimits{JoinTimeout: -time.Millisecond}, engine.InvalidArgument},
		}
		for _, test := range cases {
			if _, code := NewRelay(test.limits); code != test.want {
				t.Fatalf("%s: NewRelay(%+v) = %v, want %v", test.name, test.limits, code, test.want)
			}
		}
	})

	t.Run("input", func(t *testing.T) {
		var unassembled *Relay
		if result := unassembled.Run(context.Background(), nil, nil); result.Code != engine.NotReady || result.Reason != ReasonRelayNotReady {
			t.Fatalf("an unassembled relay answered %s / %s", result.Code, result.Reason)
		}

		relay, code := NewRelay(RelayLimits{})
		if code != engine.OK {
			t.Fatalf("NewRelay = %v", code)
		}
		client, accepted := tcpPair(t)
		if result := relay.Run(nil, client, accepted); result.Code != engine.InvalidArgument || result.Reason != ReasonRelayInvalidInput {
			t.Fatalf("a nil context answered %s / %s", result.Code, result.Reason)
		}
		if result := relay.Run(context.Background(), nil, accepted); result.Code != engine.InvalidArgument {
			t.Fatalf("a nil downstream transport answered %s", result.Code)
		}
		if result := relay.Run(context.Background(), client, nil); result.Code != engine.InvalidArgument {
			t.Fatalf("a nil upstream transport answered %s", result.Code)
		}

		// A rejected call takes nothing over, so the transport it was handed is
		// still open: a read on the peer times out rather than seeing a close.
		_ = accepted.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
		_, err := accepted.Read(make([]byte, 1))
		if err == nil || errors.Is(err, io.EOF) {
			t.Fatalf("a rejected relay call closed a transport: %v", err)
		}
	})
}

// TestOnlyTheFirstFaultIsPublished pins the one-terminal-state rule directly:
// both copies of a broken connection usually fail, and the first failure is the
// one that describes it.
func TestOnlyTheFirstFaultIsPublished(t *testing.T) {
	t.Run("sequential", func(t *testing.T) {
		outcome := &relayOutcome{}
		outcome.fault(engine.IOError, ReasonRelayReadFailed, UpstreamToDownstream)
		outcome.fault(engine.Cancelled, ReasonRelayCancelled, "")
		code, reason, direction, faulted := outcome.snapshot()
		if !faulted || code != engine.IOError || reason != ReasonRelayReadFailed || direction != UpstreamToDownstream {
			t.Fatalf("the second fault replaced the first: %s / %s / %q", code, reason, direction)
		}
	})

	t.Run("concurrent", func(t *testing.T) {
		outcome := &relayOutcome{}
		var group sync.WaitGroup
		for worker := 0; worker < 8; worker++ {
			group.Add(1)
			go func() {
				defer group.Done()
				for attempt := 0; attempt < 50; attempt++ {
					outcome.fault(engine.IOError, ReasonRelayWriteFailed, DownstreamToUpstream)
				}
			}()
		}
		group.Wait()
		code, reason, direction, faulted := outcome.snapshot()
		if !faulted || code != engine.IOError || reason != ReasonRelayWriteFailed || direction != DownstreamToUpstream {
			t.Fatalf("concurrent faults produced %s / %s / %q", code, reason, direction)
		}
	})
}

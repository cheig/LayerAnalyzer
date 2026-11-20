package gateway

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

func request(token []byte) map[string]any {
	return map[string]any{"version": 1, "captureId": "capture-202", "connectionId": "connection-1",
		"networkGeneration": int64(7), "destinationAddress": "192.0.2.1", "destinationPort": 443, "token": string(token)}
}
func frame(body []byte) []byte {
	prefix := make([]byte, 8, 8+len(body))
	copy(prefix, "LAT1")
	binary.BigEndian.PutUint32(prefix[4:], uint32(len(body)))
	return append(prefix, body...)
}
func requestFrame(t *testing.T, fields map[string]any) []byte {
	t.Helper()
	body, err := json.Marshal(fields)
	if err != nil {
		t.Fatal(err)
	}
	return frame(body)
}
func start(t *testing.T, dial DialFunc, handle FlowHandler, capacity int) *Server {
	t.Helper()
	s, code := Start(context.Background(), Options{CaptureID: "capture-202", NetworkGeneration: 7, Dial: dial, Handle: handle, Capacity: capacity})
	if code != engine.OK {
		t.Fatal(code)
	}
	t.Cleanup(s.Close)
	if addr := s.listener.Addr().(*net.TCPAddr); !addr.IP.Equal(net.IPv4(127, 0, 0, 1)) || addr.Port == 0 {
		t.Fatalf("listener must use random loopback port: %v", addr)
	}
	return s
}
func connect(t *testing.T, s *Server) net.Conn {
	t.Helper()
	c, err := net.DialTimeout("tcp4", net.JoinHostPort("127.0.0.1", strconv.Itoa(int(s.Port()))), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if err := c.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatal(err)
	}
	return c
}
func send(t *testing.T, c net.Conn, data []byte) {
	t.Helper()
	if _, err := io.Copy(c, bytes.NewReader(data)); err != nil {
		t.Fatal(err)
	}
}
func readReply(t *testing.T, c net.Conn, expected engine.Code) []byte {
	t.Helper()
	var prefix [8]byte
	if _, err := io.ReadFull(c, prefix[:]); err != nil {
		t.Fatal(err)
	}
	n := binary.BigEndian.Uint32(prefix[4:])
	if string(prefix[:4]) != "LAT1" || n == 0 || n > MaxReplyBytes {
		t.Fatal("invalid reply framing")
	}
	body := make([]byte, n)
	if _, err := io.ReadFull(c, body); err != nil {
		t.Fatal(err)
	}
	var reply struct {
		Version   int     `json:"version"`
		Success   bool    `json:"success"`
		ErrorCode *string `json:"errorCode"`
	}
	decoder := json.NewDecoder(bytes.NewReader(body))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&reply) != nil || reply.Version != 1 || reply.Success != (expected == engine.OK) {
		t.Fatal("incorrect reply")
	}
	if expected == engine.OK && reply.ErrorCode != nil || expected != engine.OK && (reply.ErrorCode == nil || *reply.ErrorCode != expected.String()) {
		t.Fatal("incorrect reply code")
	}
	return body
}
func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}
func idle(s *Server) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.connections) == 0 && len(s.slots) == 0
}
func neverHandle(context.Context, Metadata, net.Conn, net.Conn) { panic("unexpected flow handler") }

func TestFrameSplitsAndBufferedPayload(t *testing.T) {
	for _, mode := range []string{"bytewise", "header-and-clienthello", "two-frames", "wait-for-ready"} {
		t.Run(mode, func(t *testing.T) {
			// Synthetic opaque bytes only; this is not a TLS handshake fixture.
			payload := []byte{0x16, 0x03, 0x01, 0, 8, 1, 0, 0, 4, 0, 1, 2, 3}
			if mode == "two-frames" {
				payload = frame([]byte(`{"second":"opaque application payload"}`))
			}
			up, origin := net.Pipe() // Explicit connected-upstream test double.
			t.Cleanup(func() { origin.Close() })
			destination := make(chan Metadata, 1)
			s := start(t, func(ctx context.Context, metadata Metadata) (net.Conn, engine.Code) {
				deadline, ok := ctx.Deadline()
				if !ok || time.Until(deadline) > ConnectTimeout || time.Until(deadline) <= 0 {
					t.Error("missing bounded dial deadline")
				}
				destination <- metadata
				return up, engine.OK
			}, func(_ context.Context, _ Metadata, down, upstream net.Conn) {
				if _, err := io.CopyN(upstream, down, int64(len(payload))); err != nil {
					t.Error(err)
					return
				}
				if _, err := io.CopyN(down, upstream, 2); err != nil {
					t.Error(err)
				}
			}, 0)
			originResult := make(chan []byte, 1)
			go func() {
				defer origin.Close()
				got := make([]byte, len(payload))
				if _, err := io.ReadFull(origin, got); err != nil {
					originResult <- nil
					return
				}
				originResult <- got
				_, _ = origin.Write([]byte("OK"))
			}()
			c := connect(t, s)
			header := requestFrame(t, request(s.Token()))
			switch mode {
			case "bytewise":
				for _, b := range header {
					send(t, c, []byte{b})
				}
				send(t, c, payload)
			case "wait-for-ready":
				send(t, c, header)
			default:
				send(t, c, append(header, payload...))
			}
			readReply(t, c, engine.OK)
			if mode == "wait-for-ready" {
				send(t, c, payload)
			}
			var response [2]byte
			if _, err := io.ReadFull(c, response[:]); err != nil || string(response[:]) != "OK" {
				t.Fatal("application relay failed", err)
			}
			if got := <-originResult; !bytes.Equal(got, payload) {
				t.Fatal("metadata leaked or prefetched bytes lost")
			}
			if metadata := <-destination; metadata.Destination != netip.MustParseAddrPort("192.0.2.1:443") || metadata.NetworkGeneration != 7 {
				t.Fatal("destination changed")
			}
			waitFor(t, func() bool { return idle(s) })
		})
	}
}

func TestStrictMetadataAndAuthentication(t *testing.T) {
	var dials atomic.Int32
	s := start(t, func(context.Context, Metadata) (net.Conn, engine.Code) {
		dials.Add(1)
		return nil, engine.IOError
	}, neverHandle, 1)
	token := s.Token()
	tests := []struct {
		name   string
		change func(map[string]any)
		code   engine.Code
	}{
		{"wrong-token", func(m map[string]any) { m["token"] = base64.RawURLEncoding.EncodeToString(make([]byte, 32)) }, engine.InvalidArgument},
		{"missing-token", func(m map[string]any) { delete(m, "token") }, engine.InvalidArgument},
		{"padded-token", func(m map[string]any) { m["token"] = string(token) + "=" }, engine.InvalidArgument},
		{"noncanonical-token", func(m map[string]any) { m["token"] = strings.Repeat("_", 43) }, engine.InvalidArgument},
		{"version", func(m map[string]any) { m["version"] = 2 }, engine.InvalidArgument},
		{"null-version", func(m map[string]any) { m["version"] = nil }, engine.InvalidArgument},
		{"unknown-required", func(m map[string]any) { m["requiredFeature"] = true }, engine.InvalidArgument},
		{"field-case", func(m map[string]any) { m["Version"] = m["version"]; delete(m, "version") }, engine.InvalidArgument},
		{"zero-port", func(m map[string]any) { m["destinationPort"] = 0 }, engine.InvalidArgument},
		{"large-port", func(m map[string]any) { m["destinationPort"] = 65536 }, engine.InvalidArgument},
		{"negative-port", func(m map[string]any) { m["destinationPort"] = -1 }, engine.InvalidArgument},
		{"fraction-port", func(m map[string]any) { m["destinationPort"] = 443.5 }, engine.InvalidArgument},
		{"hostname", func(m map[string]any) { m["destinationAddress"] = "example.test" }, engine.InvalidArgument},
		{"ip-port", func(m map[string]any) { m["destinationAddress"] = "192.0.2.1:443" }, engine.InvalidArgument},
		{"ipv6-zone", func(m map[string]any) { m["destinationAddress"] = "fe80::1%eth0" }, engine.InvalidArgument},
		{"unspecified", func(m map[string]any) { m["destinationAddress"] = "0.0.0.0" }, engine.InvalidArgument},
		{"mapped-unspecified", func(m map[string]any) { m["destinationAddress"] = "::ffff:0.0.0.0" }, engine.InvalidArgument},
		{"multicast", func(m map[string]any) { m["destinationAddress"] = "ff02::1" }, engine.InvalidArgument},
		{"bad-id", func(m map[string]any) { m["connectionId"] = "../connection" }, engine.InvalidArgument},
		{"long-id", func(m map[string]any) { m["connectionId"] = strings.Repeat("a", 129) }, engine.InvalidArgument},
		{"capture-mismatch", func(m map[string]any) { m["captureId"] = "other-capture" }, engine.CaptureContextMissing},
		{"generation-mismatch", func(m map[string]any) { m["networkGeneration"] = 8 }, engine.StaleGeneration},
		{"negative-generation", func(m map[string]any) { m["networkGeneration"] = -1 }, engine.InvalidArgument},
		{"missing-generation", func(m map[string]any) { delete(m, "networkGeneration") }, engine.InvalidArgument},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			c := connect(t, s)
			fields := request(token)
			tt.change(fields)
			send(t, c, requestFrame(t, fields))
			body := readReply(t, c, tt.code)
			if bytes.Contains(body, token) || bytes.Contains(body, []byte("capture-202")) {
				t.Fatal("sensitive metadata in reply")
			}
			waitFor(t, func() bool { return idle(s) })
		})
	}
	if dials.Load() != 0 {
		t.Fatal("unauthenticated/invalid request dialed upstream")
	}
	// Both IP families remain exact; there is no DNS or fallback address.
	for _, address := range []string{"192.0.2.1", "2001:db8::1", "::ffff:192.0.2.1"} {
		fields := request(token)
		fields["destinationAddress"] = address
		metadata, _, code := readRequest(bytes.NewReader(requestFrame(t, fields)))
		if code != engine.OK || metadata.Destination.Addr().String() != address {
			t.Fatal("IP not preserved", address, code)
		}
	}
}

func TestMalformedFraming(t *testing.T) {
	s := start(t, func(context.Context, Metadata) (net.Conn, engine.Code) {
		t.Error("unexpected dial")
		return nil, engine.IOError
	}, neverHandle, 1)
	valid := requestFrame(t, request(s.Token()))
	long := []byte{'L', 'A', 'T', '1', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(long[4:], MaxHeaderBytes+1)
	max := append([]byte(nil), long...)
	binary.BigEndian.PutUint32(max[4:], ^uint32(0))
	duplicate := append([]byte(`{"version":1,`), valid[9:]...)
	cases := map[string][]byte{
		"over-limit": long, "uint32-max": max, "zero": []byte("LAT1\x00\x00\x00\x00"),
		"bad-magic": append([]byte("BAD1"), valid[4:]...), "duplicate": frame(duplicate),
		"invalid-utf8":    frame([]byte{'{', '"', 0xff, '"', ':', '1', '}'}),
		"trailing-object": frame(append(append([]byte(nil), valid[8:]...), []byte("{}")...)),
		"array":           frame([]byte("[]")), "bad-json": frame([]byte("{")),
		"truncated-prefix": []byte("LAT1"), "truncated-body": valid[:len(valid)-1],
	}
	for name, data := range cases {
		t.Run(name, func(t *testing.T) {
			c := connect(t, s)
			send(t, c, data)
			if err := c.(*net.TCPConn).CloseWrite(); err != nil {
				t.Fatal(err)
			}
			readReply(t, c, engine.InvalidArgument)
			waitFor(t, func() bool { return idle(s) })
		})
	}
	// 4096 is inclusive, and only exactly the declared bytes are consumed.
	body := append(append([]byte(nil), valid[8:]...), bytes.Repeat([]byte(" "), MaxHeaderBytes-len(valid[8:]))...)
	input := bufio.NewReader(bytes.NewReader(append(frame(body), []byte("tail")...)))
	if _, _, code := readRequest(input); code != engine.OK {
		t.Fatal(code)
	}
	if tail, _ := io.ReadAll(input); string(tail) != "tail" {
		t.Fatal("boundary swallowed following payload")
	}
}

func TestCapacityReservedBeforeDialAndReleased(t *testing.T) {
	var calls atomic.Int32
	dialEntered := make(chan struct{})
	unblock := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(unblock) }) })
	s := start(t, func(ctx context.Context, _ Metadata) (net.Conn, engine.Code) {
		if calls.Add(1) == 1 {
			close(dialEntered)
			select {
			case <-unblock:
			case <-ctx.Done():
			}
		}
		return nil, engine.ProtectFailed
	}, neverHandle, 1)
	first := connect(t, s)
	send(t, first, requestFrame(t, request(s.Token())))
	<-dialEntered
	second := connect(t, s)
	send(t, second, requestFrame(t, request(s.Token())))
	readReply(t, second, engine.CapacityExceeded)
	if calls.Load() != 1 {
		t.Fatal("capacity overflow dialed")
	}
	_ = first.SetReadDeadline(time.Now().Add(30 * time.Millisecond))
	if n, err := first.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("READY sent before dial completed")
	}
	_ = first.SetReadDeadline(time.Now().Add(5 * time.Second))
	once.Do(func() { close(unblock) })
	readReply(t, first, engine.ProtectFailed)
	waitFor(t, func() bool { return idle(s) })
	third := connect(t, s)
	send(t, third, requestFrame(t, request(s.Token())))
	readReply(t, third, engine.ProtectFailed)
	waitFor(t, func() bool { return idle(s) })
	if calls.Load() != 2 {
		t.Fatal("failed dial leaked reservation")
	}
}

func TestDialFailureClosesPartialSocket(t *testing.T) {
	up, peer := net.Pipe()
	t.Cleanup(func() { peer.Close() })
	s := start(t, func(context.Context, Metadata) (net.Conn, engine.Code) { return up, engine.IOError }, neverHandle, 1)
	c := connect(t, s)
	send(t, c, requestFrame(t, request(s.Token())))
	readReply(t, c, engine.IOError)
	waitFor(t, func() bool { return idle(s) })
	if _, err := peer.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("partial socket leaked", err)
	}
}

func TestAuthenticationTimeoutAndAdmissionBound(t *testing.T) {
	var dials atomic.Int32
	s := start(t, func(context.Context, Metadata) (net.Conn, engine.Code) { dials.Add(1); return nil, engine.IOError }, neverHandle, 0)
	clients := make([]net.Conn, DefaultAuthentication)
	for i := range clients {
		clients[i] = connect(t, s)
	}
	waitFor(t, func() bool { s.mu.Lock(); defer s.mu.Unlock(); return len(s.connections) == DefaultAuthentication })
	overflow := connect(t, s)
	if _, err := overflow.Read(make([]byte, 1)); err == nil {
		t.Fatal("admission overflow left open")
	}
	for _, c := range clients {
		readReply(t, c, engine.InvalidArgument)
	}
	waitFor(t, func() bool { return idle(s) })
	if dials.Load() != 0 {
		t.Fatal("unauthenticated timeout dialed")
	}
}

func TestStopCancelsDialAndJoinsFlows(t *testing.T) {
	for _, phase := range []string{"authentication", "dial", "flow-upstream-read"} {
		t.Run(phase, func(t *testing.T) {
			entered := make(chan struct{})
			up, peer := net.Pipe()
			t.Cleanup(func() { peer.Close(); up.Close() })
			s := start(t, func(ctx context.Context, _ Metadata) (net.Conn, engine.Code) {
				if phase == "dial" {
					close(entered)
					<-ctx.Done()
					return up, engine.Cancelled
				}
				return up, engine.OK
			}, func(_ context.Context, _ Metadata, _, upstream net.Conn) {
				close(entered)
				_, _ = upstream.Read(make([]byte, 1))
			}, 1)
			c := connect(t, s)
			if phase != "authentication" {
				send(t, c, requestFrame(t, request(s.Token())))
				if phase != "dial" {
					readReply(t, c, engine.OK)
				}
				<-entered
			}
			var wg sync.WaitGroup
			for range 8 {
				wg.Add(1)
				go func() { defer wg.Done(); s.Close() }()
			}
			done := make(chan struct{})
			go func() { wg.Wait(); close(done) }()
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("stop failed to join")
			}
			if !idle(s) || s.Token() != nil {
				t.Fatal("stop leaked slots/connections/token")
			}
			if _, err := c.Read(make([]byte, 1)); err == nil {
				t.Fatal("stopped downstream still open")
			}
		})
	}
}

func TestStartValidationAndFreshToken(t *testing.T) {
	dial := func(context.Context, Metadata) (net.Conn, engine.Code) { return nil, engine.IOError }
	valid := Options{CaptureID: "capture-202", NetworkGeneration: 7, Dial: dial, Handle: neverHandle}
	for _, mutate := range []func(*Options){
		func(o *Options) { o.Dial = nil }, func(o *Options) { o.Handle = nil },
		func(o *Options) { o.CaptureID = "" }, func(o *Options) { o.NetworkGeneration = -1 },
		func(o *Options) { o.Capacity = -1 }, func(o *Options) { o.Capacity = MaxConnections + 1 },
	} {
		o := valid
		mutate(&o)
		if s, code := Start(context.Background(), o); code != engine.InvalidArgument || s != nil {
			t.Fatal("invalid start accepted")
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if s, code := Start(ctx, valid); code != engine.Cancelled || s != nil {
		t.Fatal("cancelled start accepted")
	}
	s := start(t, dial, neverHandle, 0)
	token := s.Token()
	if decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(token)); err != nil || len(decoded) != 32 {
		t.Fatal("token format invalid")
	}
	copyToken := s.Token()
	copyToken[0] ^= 1
	if !bytes.Equal(token, s.Token()) {
		t.Fatal("token output aliases internal storage")
	}
	s.Close()
	next := start(t, dial, neverHandle, 0)
	if bytes.Equal(token, next.Token()) {
		t.Fatal("token reused after restart")
	}
	c := connect(t, next)
	send(t, c, requestFrame(t, request(token)))
	readReply(t, c, engine.InvalidArgument)
}

// A pipe blocks Flush until the peer reads the reply, making the READY/handler
// boundary deterministic. Deadline observations check that the application
// stream does not inherit the authentication/connect budgets.
type observedConn struct {
	net.Conn
	mu                          sync.Mutex
	readDeadline, writeDeadline time.Time
	closes                      atomic.Int32
}

func (c *observedConn) SetDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline, c.writeDeadline = deadline, deadline
	c.mu.Unlock()
	return c.Conn.SetDeadline(deadline)
}
func (c *observedConn) SetReadDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.readDeadline = deadline
	c.mu.Unlock()
	return c.Conn.SetReadDeadline(deadline)
}
func (c *observedConn) SetWriteDeadline(deadline time.Time) error {
	c.mu.Lock()
	c.writeDeadline = deadline
	c.mu.Unlock()
	return c.Conn.SetWriteDeadline(deadline)
}
func (c *observedConn) noDeadline() bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.readDeadline.IsZero() && c.writeDeadline.IsZero()
}
func (c *observedConn) Close() error {
	c.closes.Add(1)
	return c.Conn.Close()
}

func TestReadyFlushAndDeadlineOwnership(t *testing.T) {
	for _, failWrite := range []bool{false, true} {
		t.Run(strconv.FormatBool(failWrite), func(t *testing.T) {
			downPipe, client := net.Pipe()
			upPipe, origin := net.Pipe()
			down := &observedConn{Conn: downPipe}
			up := &observedConn{Conn: upPipe}
			t.Cleanup(func() { client.Close(); origin.Close() })
			_ = up.SetDeadline(time.Now().Add(ConnectTimeout))
			ctx, cancel := context.WithCancel(context.Background())
			t.Cleanup(cancel)
			dialed := make(chan struct{})
			var handled atomic.Int32
			s := &Server{ctx: ctx, slots: make(chan struct{}, 1)}
			s.options = Options{CaptureID: "capture-202", NetworkGeneration: 7, Dial: func(context.Context, Metadata) (net.Conn, engine.Code) {
				close(dialed)
				return up, engine.OK
			}, Handle: func(_ context.Context, _ Metadata, buffered, _ net.Conn) {
				handled.Add(1)
				if !down.noDeadline() || !up.noDeadline() {
					t.Error("application inherited a setup deadline")
				}
				var data [4]byte
				if _, err := io.ReadFull(buffered, data[:]); err != nil || string(data[:]) != "tail" {
					t.Error("prefix lost", err)
				}
			}, Capacity: 1}
			done := make(chan struct{})
			go func() { defer close(done); defer down.Close(); s.serve(down) }()
			header := requestFrame(t, request([]byte(base64.RawURLEncoding.EncodeToString(s.token[:]))))
			send(t, client, append(header, []byte("tail")...))
			<-dialed
			if handled.Load() != 0 {
				t.Fatal("handler ran before READY was flushed")
			}
			if failWrite {
				client.Close()
			} else {
				readReply(t, client, engine.OK)
			}
			select {
			case <-done:
			case <-time.After(2 * time.Second):
				t.Fatal("serve failed to finish")
			}
			want := int32(1)
			if failWrite {
				want = 0
			}
			if handled.Load() != want || len(s.slots) != 0 || up.closes.Load() != 1 {
				t.Fatal("READY failure/flow leaked resources")
			}
		})
	}
}

func TestNilDialResultRejected(t *testing.T) {
	s := start(t, func(context.Context, Metadata) (net.Conn, engine.Code) { return nil, engine.OK }, neverHandle, 1)
	c := connect(t, s)
	send(t, c, requestFrame(t, request(s.Token())))
	readReply(t, c, engine.IOError)
	waitFor(t, func() bool { return idle(s) })
}

func TestParentCancellationRejectsLateDialSuccess(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	up, origin := net.Pipe()
	t.Cleanup(func() { origin.Close() })
	dialed := make(chan struct{})
	s, code := Start(ctx, Options{CaptureID: "capture-202", NetworkGeneration: 7, Dial: func(ctx context.Context, _ Metadata) (net.Conn, engine.Code) {
		close(dialed)
		<-ctx.Done()
		return up, engine.OK // Deliberately broken adapter: cancellation still wins.
	}, Handle: neverHandle, Capacity: 1})
	if code != engine.OK {
		t.Fatal(code)
	}
	t.Cleanup(s.Close)
	c := connect(t, s)
	send(t, c, requestFrame(t, request(s.Token())))
	<-dialed
	cancel()
	select {
	case <-s.done:
	case <-time.After(2 * time.Second):
		t.Fatal("parent cancel did not stop gateway")
	}
	if !idle(s) {
		t.Fatal("late dial leaked reservation")
	}
	if n, err := c.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("READY emitted after cancellation")
	}
	if _, err := origin.Read(make([]byte, 1)); err != io.EOF {
		t.Fatal("late upstream leaked", err)
	}
}

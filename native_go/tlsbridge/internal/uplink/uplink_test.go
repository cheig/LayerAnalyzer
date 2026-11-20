package uplink

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/netip"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// Explicit platform doubles. They never open, protect or resolve a real
// socket; the connection side of every test is a real host loopback listener,
// so "the preparation was rejected" is proven by the listener seeing no
// connection rather than by a mocked dialer.
type platformStub struct {
	mu                 sync.Mutex
	prepareCalls       int
	resolveCalls       int
	fds                []uintptr
	prepareGenerations []int64
	resolveGenerations []int64
	names              []string
	prepare            func(call int, fd uintptr) engine.Code
	resolve            func(host string, generation int64) ([]byte, engine.Code)
}

func (s *platformStub) PrepareSocket(fd int, generation int64) engine.Code {
	s.mu.Lock()
	s.prepareCalls++
	s.fds = append(s.fds, uintptr(fd))
	s.prepareGenerations = append(s.prepareGenerations, generation)
	call := s.prepareCalls
	s.mu.Unlock()
	if s.prepare == nil {
		return engine.OK
	}
	return s.prepare(call, uintptr(fd))
}

func (s *platformStub) ResolveHost(host string, generation int64) ([]byte, engine.Code) {
	s.mu.Lock()
	s.resolveCalls++
	s.resolveGenerations = append(s.resolveGenerations, generation)
	s.names = append(s.names, host)
	s.mu.Unlock()
	if s.resolve == nil {
		return nil, engine.IOError
	}
	return s.resolve(host, generation)
}

func (s *platformStub) VerifyUpstream([][]byte, string, string, string) engine.Code {
	return engine.Unsupported
}
func (s *platformStub) OfferSecret(string, string, []byte) engine.Code {
	return engine.SecretsIncomplete
}

func (s *platformStub) prepares() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.prepareCalls
}

func (s *platformStub) preparesFor() []uintptr {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]uintptr(nil), s.fds...)
}

func (s *platformStub) generations() []int64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]int64(nil), s.prepareGenerations...)
}

func (s *platformStub) resolutions() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resolveCalls
}

func (s *platformStub) asked() []string {
	s.mu.Lock()
	defer s.mu.Unlock()
	return append([]string(nil), s.names...)
}

// gateStub mirrors the engine's admission gate: once shutdown has closed
// admission, Call returns CANCELLED without entering the platform.
type gateStub struct {
	platform engine.Platform
	closed   atomic.Bool
}

func (g *gateStub) Call(operation func(engine.Platform) engine.Code) engine.Code {
	if g.closed.Load() {
		return engine.Cancelled
	}
	return operation(g.platform)
}

type loopback struct {
	net.Listener
	accepted atomic.Int32
}

func listen(t *testing.T, network, address string) *loopback {
	t.Helper()
	raw, err := net.Listen(network, address)
	if err != nil {
		t.Fatalf("listen %s %s: %v", network, address, err)
	}
	server := &loopback{Listener: raw}
	go func() {
		for {
			connection, err := raw.Accept()
			if err != nil {
				return
			}
			server.accepted.Add(1)
			_ = connection.Close()
		}
	}()
	t.Cleanup(func() { _ = raw.Close() })
	return server
}

// expects waits for exactly want connections, then confirms no further one
// arrives. want=0 still waits, so a rejected preparation cannot pass before
// its connect would have been observable.
func (l *loopback) expects(t *testing.T, want int32) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for l.accepted.Load() < want && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if got := l.accepted.Load(); got != want {
		t.Fatalf("accepted %d connections, want %d", got, want)
	}
	time.Sleep(150 * time.Millisecond)
	if got := l.accepted.Load(); got != want {
		t.Fatalf("accepted %d connections after settling, want %d", got, want)
	}
}

func (l *loopback) port(t *testing.T) uint16 {
	t.Helper()
	address, ok := l.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("unexpected listener address %v", l.Addr())
	}
	return uint16(address.Port)
}

func dialer(t *testing.T, callbacks Callbacks, timeout time.Duration) *Dialer {
	t.Helper()
	value, code := New(callbacks, 7, timeout)
	if code != engine.OK {
		t.Fatalf("New: %v", code)
	}
	return value
}

func stubDialer(t *testing.T, platform *platformStub) (*Dialer, *gateStub) {
	t.Helper()
	gate := &gateStub{platform: platform}
	return dialer(t, gate, 0), gate
}

func envelope(addresses ...string) []byte {
	body, err := json.Marshal(map[string]any{
		"schemaVersion": 1, "success": true, "errorCode": nil, "error": nil, "addresses": addresses})
	if err != nil {
		panic(err)
	}
	return body
}

func TestNewValidatesBudgetAndGeneration(t *testing.T) {
	gate := &gateStub{platform: &platformStub{}}
	if _, code := New(nil, 0, 0); code != engine.InvalidArgument {
		t.Fatalf("nil callbacks accepted: %v", code)
	}
	if _, code := New(gate, -1, 0); code != engine.InvalidArgument {
		t.Fatalf("negative generation accepted: %v", code)
	}
	if _, code := New(gate, 0, -time.Second); code != engine.InvalidArgument {
		t.Fatalf("negative timeout accepted: %v", code)
	}
	if _, code := New(gate, 0, DefaultTimeout+time.Millisecond); code != engine.InvalidArgument {
		t.Fatalf("timeout above the C10 budget accepted: %v", code)
	}
	value, code := New(gate, 4, 0)
	if code != engine.OK || value.Generation() != 4 {
		t.Fatalf("zero timeout should select the default budget: %v %d", code, value.Generation())
	}
}

func TestDialCreatesProtectsAndBindsEverySocket(t *testing.T) {
	server := listen(t, "tcp4", "127.0.0.1:0")
	platform := &platformStub{}
	value, _ := stubDialer(t, platform)
	destination := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), server.port(t))

	connections := make([]net.Conn, 0, 3)
	for attempt := 0; attempt < 3; attempt++ {
		connection, code := value.Dial(context.Background(), destination)
		if code != engine.OK {
			t.Fatalf("dial %d: %v", attempt, code)
		}
		defer connection.Close()
		connections = append(connections, connection)
	}
	server.expects(t, 3)
	if platform.prepares() != 3 {
		t.Fatalf("prepared %d sockets for 3 dials", platform.prepares())
	}
	// Every attempt gets its own descriptor: protection is never reused from a
	// previous socket. Concurrent live connections keep the numbers distinct.
	seen := map[uintptr]bool{}
	for _, fd := range platform.preparesFor() {
		if seen[fd] {
			t.Fatalf("descriptor %d was protected for two sockets", fd)
		}
		seen[fd] = true
	}
	for _, generation := range platform.generations() {
		if generation != 7 {
			t.Fatalf("prepare saw generation %d, want the configured 7", generation)
		}
	}
	// The remote end really is the literal that was passed.
	remote := connections[0].RemoteAddr().(*net.TCPAddr)
	if !remote.IP.Equal(net.ParseIP("127.0.0.1")) || remote.Port != int(server.port(t)) {
		t.Fatalf("connection went to %v", remote)
	}
}

func TestRejectedPreparationNeverConnects(t *testing.T) {
	server := listen(t, "tcp4", "127.0.0.1:0")
	destination := netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), server.port(t))
	for _, rejected := range []engine.Code{
		engine.InvalidArgument, engine.ProtectFailed, engine.StaleGeneration, engine.NetworkChanged,
		engine.Cancelled, engine.CapacityExceeded, engine.IOError, engine.CaptureContextMissing,
	} {
		platform := &platformStub{prepare: func(int, uintptr) engine.Code { return rejected }}
		value, _ := stubDialer(t, platform)
		connection, code := value.Dial(context.Background(), destination)
		if connection != nil {
			connection.Close()
			t.Fatalf("%v returned a connection", rejected)
		}
		if code != rejected {
			t.Fatalf("preparation code %v became %v", rejected, code)
		}
		if platform.prepares() != 1 {
			t.Fatalf("%v prepared %d times for one dial", rejected, platform.prepares())
		}
	}
	server.expects(t, 0)
}

func TestClosedAdmissionCannotProtectOrConnect(t *testing.T) {
	server := listen(t, "tcp4", "127.0.0.1:0")
	platform := &platformStub{}
	value, gate := stubDialer(t, platform)
	gate.closed.Store(true)
	_, code := value.Dial(context.Background(),
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), server.port(t)))
	if code != engine.Cancelled {
		t.Fatalf("closed admission returned %v", code)
	}
	if platform.prepares() != 0 {
		t.Fatalf("closed admission entered the platform %d times", platform.prepares())
	}
	server.expects(t, 0)
}

func TestPanickingPreparationFailsClosed(t *testing.T) {
	server := listen(t, "tcp4", "127.0.0.1:0")
	platform := &platformStub{prepare: func(int, uintptr) engine.Code { panic("fixture-only") }}
	value, _ := stubDialer(t, platform)
	_, code := value.Dial(context.Background(),
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), server.port(t)))
	if code != engine.IOError {
		t.Fatalf("panicking preparation returned %v", code)
	}
	server.expects(t, 0)
}

func TestDialSupportsIpv6AndUnmapsV4MappedLiterals(t *testing.T) {
	six := listen(t, "tcp6", "[::1]:0")
	platform := &platformStub{}
	value, _ := stubDialer(t, platform)
	connection, code := value.Dial(context.Background(),
		netip.AddrPortFrom(netip.MustParseAddr("::1"), six.port(t)))
	if code != engine.OK {
		t.Fatalf("ipv6 dial: %v", code)
	}
	defer connection.Close()
	six.expects(t, 1)
	if remote := connection.RemoteAddr().(*net.TCPAddr); !remote.IP.Equal(net.ParseIP("::1")) {
		t.Fatalf("ipv6 connection went to %v", remote)
	}

	four := listen(t, "tcp4", "127.0.0.1:0")
	mapped := netip.AddrPortFrom(netip.MustParseAddr("::ffff:127.0.0.1"), four.port(t))
	connection, code = value.Dial(context.Background(), mapped)
	if code != engine.OK {
		t.Fatalf("v4-mapped dial: %v", code)
	}
	defer connection.Close()
	four.expects(t, 1)
	if remote := connection.RemoteAddr().(*net.TCPAddr); !remote.IP.Equal(net.ParseIP("127.0.0.1")) {
		t.Fatalf("v4-mapped connection went to %v", remote)
	}
	if platform.prepares() != 2 {
		t.Fatalf("both families should be protected, saw %d", platform.prepares())
	}
}

func TestDialRejectsNonUnicastAndInvalidDestinations(t *testing.T) {
	platform := &platformStub{}
	value, _ := stubDialer(t, platform)
	invalid := []netip.AddrPort{
		netip.AddrPortFrom(netip.MustParseAddr("127.0.0.1"), 0),
		netip.AddrPortFrom(netip.MustParseAddr("0.0.0.0"), 443),
		netip.AddrPortFrom(netip.MustParseAddr("::"), 443),
		netip.AddrPortFrom(netip.MustParseAddr("239.1.1.1"), 443),
		netip.AddrPortFrom(netip.MustParseAddr("ff02::1"), 443),
		netip.AddrPortFrom(netip.MustParseAddr("fe80::1%eth0"), 443),
	}
	for _, destination := range invalid {
		if connection, code := value.Dial(context.Background(), destination); code != engine.InvalidArgument || connection != nil {
			t.Fatalf("%v accepted: %v", destination, code)
		}
	}
	if platform.prepares() != 0 {
		t.Fatalf("invalid destinations reached the platform %d times", platform.prepares())
	}
}

func TestResolveReturnsLiteralsWithoutAnyLookup(t *testing.T) {
	platform := &platformStub{}
	value, _ := stubDialer(t, platform)
	for _, host := range []string{"203.0.113.7", "2001:db8::7", "203.0.113.7."} {
		addresses, code := value.Resolve(context.Background(), host)
		if code != engine.OK {
			t.Fatalf("%s: %v", host, code)
		}
		if len(addresses) != 1 || !addresses[0].IsValid() {
			t.Fatalf("%s resolved to %v", host, addresses)
		}
	}
	addresses, code := value.Resolve(context.Background(), "::ffff:203.0.113.7")
	if code != engine.OK || len(addresses) != 1 || addresses[0] != netip.MustParseAddr("203.0.113.7") {
		t.Fatalf("v4-mapped literal resolved to %v (%v)", addresses, code)
	}
	if platform.resolutions() != 0 {
		t.Fatalf("a numeric destination was resolved %d times", platform.resolutions())
	}
}

func TestResolveRejectsInvalidNamesBeforeTheCallback(t *testing.T) {
	platform := &platformStub{}
	value, _ := stubDialer(t, platform)
	invalid := []string{
		"", ".", "..", "-.example.test", "example-.test", "_dmarc.example.test",
		"example..test", "example.test:443",
		"exa mple.test", "exämple.test", "example.test/path", "example.test\x00",
		strings.Repeat("a", 254), strings.Repeat("a", 64) + ".test",
	}
	for _, host := range invalid {
		if addresses, code := value.Resolve(context.Background(), host); code != engine.InvalidArgument || addresses != nil {
			t.Fatalf("name %q accepted: %v %v", host, addresses, code)
		}
	}
	if platform.resolutions() != 0 {
		t.Fatalf("invalid names reached the platform %d times", platform.resolutions())
	}
}

func TestResolveUsesOnlyThePlatformCallback(t *testing.T) {
	platform := &platformStub{resolve: func(host string, generation int64) ([]byte, engine.Code) {
		if host != "Example.com" || generation != 7 {
			return nil, engine.InvalidArgument
		}
		// Public DNS would answer with real addresses; only this fixture value
		// may come back, which is what proves the OS resolver was not consulted.
		return envelope("192.0.2.9", "2001:db8::9", "192.0.2.9"), engine.OK
	}}
	value, _ := stubDialer(t, platform)
	addresses, code := value.Resolve(context.Background(), "Example.com.")
	if code != engine.OK {
		t.Fatalf("resolve: %v", code)
	}
	if len(addresses) != 2 || addresses[0] != netip.MustParseAddr("192.0.2.9") ||
		addresses[1] != netip.MustParseAddr("2001:db8::9") {
		t.Fatalf("addresses %v were not preserved and deduplicated", addresses)
	}
	if asked := platform.asked(); len(asked) != 1 || asked[0] != "Example.com" {
		t.Fatalf("platform was asked for %v", asked)
	}
}
func TestResolveNeverFallsBackOrAcceptsAMalformedAnswer(t *testing.T) {
	for _, failure := range []engine.Code{
		engine.InvalidArgument, engine.NotReady, engine.Unsupported, engine.StaleGeneration,
		engine.Cancelled, engine.IOError, engine.CapacityExceeded, engine.ProtectFailed,
		engine.NetworkChanged, engine.CaptureContextMissing,
	} {
		platform := &platformStub{resolve: func(string, int64) ([]byte, engine.Code) { return nil, failure }}
		value, _ := stubDialer(t, platform)
		if addresses, code := value.Resolve(context.Background(), "example.test"); code != failure || addresses != nil {
			t.Fatalf("platform %v became %v", failure, code)
		}
		if platform.resolutions() != 1 {
			t.Fatalf("platform %v was retried", failure)
		}
	}
	answers := map[string][]byte{
		"empty":           {},
		"not-json":        []byte("invalid json"),
		"empty-array":     envelope(),
		"scalar":          []byte(`"example.test"`),
		"wrong-schema":    []byte(`{"schemaVersion":2,"success":true,"errorCode":null,"error":null,"addresses":["192.0.2.1"]}`),
		"failed":          []byte(`{"schemaVersion":1,"success":false,"errorCode":"IO_ERROR","error":"x","addresses":["192.0.2.1"]}`),
		"extra-key":       []byte(`{"schemaVersion":1,"success":true,"errorCode":null,"error":null,"addresses":["192.0.2.1"],"token":"x"}`),
		"zoned":           envelope("fe80::1%eth0"),
		"unspecified":     envelope("0.0.0.0"),
		"multicast":       envelope("ff02::1"),
		"not-an-ip":       envelope("example.test"),
		"empty-string":    envelope(""),
		"trailing-object": []byte(`{"schemaVersion":1,"success":true,"errorCode":null,"error":null,"addresses":["192.0.2.1"]}{}`),
		"error-not-null":  []byte(`{"schemaVersion":1,"success":true,"errorCode":null,"error":"x","addresses":["192.0.2.1"]}`),
		"missing-success": []byte(`{"schemaVersion":1,"errorCode":null,"error":null,"addresses":["192.0.2.1"]}`),
		"oversized-answer": []byte(`{"schemaVersion":1,"success":true,"errorCode":null,"error":null,"addresses":["` +
			strings.Repeat("a", MaxResolveBytes) + `"]}`),
	}
	for name, answer := range answers {
		platform := &platformStub{resolve: func(string, int64) ([]byte, engine.Code) { return answer, engine.OK }}
		value, _ := stubDialer(t, platform)
		addresses, code := value.Resolve(context.Background(), "example.test")
		if code != engine.IOError || addresses != nil {
			t.Fatalf("%s answer accepted: %v %v", name, addresses, code)
		}
	}
}

func TestDialHostRetriesOnlyPlainIoFailures(t *testing.T) {
	server := listen(t, "tcp4", "127.0.0.1:0")
	platform := &platformStub{resolve: func(string, int64) ([]byte, engine.Code) {
		// The listener is tcp4 only, so ::1 on the same port is refused.
		return envelope("::1", "127.0.0.1"), engine.OK
	}}
	value, _ := stubDialer(t, platform)
	connection, code := value.DialHost(context.Background(), "example.test", server.port(t))
	if code != engine.OK {
		t.Fatalf("DialHost: %v", code)
	}
	defer connection.Close()
	server.expects(t, 1)
	if platform.prepares() != 2 {
		t.Fatalf("both candidate addresses should be protected, saw %d", platform.prepares())
	}

	// A stale generation is not worth another address: nothing else is
	// protected and the caller sees the real reason.
	platform = &platformStub{
		resolve: func(string, int64) ([]byte, engine.Code) { return envelope("127.0.0.1", "127.0.0.2"), engine.OK },
		prepare: func(int, uintptr) engine.Code { return engine.StaleGeneration },
	}
	value, _ = stubDialer(t, platform)
	if _, code = value.DialHost(context.Background(), "example.test", server.port(t)); code != engine.StaleGeneration {
		t.Fatalf("DialHost returned %v for a stale generation", code)
	}
	if platform.prepares() != 1 {
		t.Fatalf("a stale generation still protected %d sockets", platform.prepares())
	}
	server.expects(t, 1)

	// An invalid port is rejected before any resolution.
	platform = &platformStub{}
	value, _ = stubDialer(t, platform)
	if _, code = value.DialHost(context.Background(), "example.test", 0); code != engine.InvalidArgument {
		t.Fatalf("port 0 returned %v", code)
	}
	if platform.resolutions() != 0 {
		t.Fatalf("port 0 still resolved a name")
	}
}

func TestBudgetIsBoundedAndCancellationStopsImmediately(t *testing.T) {
	platform := &platformStub{}
	value, _ := stubDialer(t, platform)
	cancelled, cancel := context.WithCancel(context.Background())
	cancel()
	if _, code := value.Dial(cancelled,
		netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 80)); code != engine.Cancelled {
		t.Fatalf("cancelled context returned %v", code)
	}

	// TEST-NET-1 is not routed here: the attempt must fail on its own budget
	// rather than hang, and must not exceed it by more than a scheduling delay.
	bounded, code := New(&gateStub{platform: platform}, 7, 250*time.Millisecond)
	if code != engine.OK {
		t.Fatalf("New: %v", code)
	}
	started := time.Now()
	connection, code := bounded.Dial(context.Background(),
		netip.AddrPortFrom(netip.MustParseAddr("192.0.2.1"), 80))
	if connection != nil {
		connection.Close()
	}
	if code == engine.OK {
		t.Fatalf("an unroutable destination connected")
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("bounded dial took %v", elapsed)
	}
}

func TestFailureCarriesThePlatformCodeThroughTheStandardLibrary(t *testing.T) {
	// net returns Control errors inside *OpError, which unwraps back to the
	// platform code, so a rejected protect is never reported as a plain I/O
	// failure higher up.
	wrapped := &net.OpError{Op: "dial", Net: "tcp6", Err: failure{code: engine.ProtectFailed}}
	if code := classify(wrapped); code != engine.ProtectFailed {
		t.Fatalf("wrapped failure lost its code: %v", code)
	}
	if code := classify(errors.New("plain")); code != engine.IOError {
		t.Fatalf("plain error became %v", code)
	}
	if code := classify(context.Canceled); code != engine.Cancelled {
		t.Fatalf("cancellation became %v", code)
	}
	if code := classify(context.DeadlineExceeded); code != engine.IOError {
		t.Fatalf("deadline became %v", code)
	}
	if code := classify(failure{code: 99}); code != engine.IOError {
		t.Fatalf("out-of-range code became %v", code)
	}
}

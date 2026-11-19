package tlsproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/certstore"
	"com.layeranalyzer/tlsbridge/internal/engine"
)

// The handshake tests are end-to-end over loopback: the downstream side is a
// real crypto/tls client verifying a real CA-signed leaf against the capture
// CA, and the upstream side is a real TLS listener presenting a real
// certificate. What is replaced is only the platform half — the C05 trust
// callback — which TLS-204's own tests already cover, and which cannot run
// outside Android anyway. So "the handshake succeeded" and "the handshake
// failed" are decided by real handshakes here, not by doubles.

// testCA generates the capture CA once per test and returns the store that
// issues leaves plus the pool a client uses to trust it.
func testCA(t *testing.T) (*certstore.Store, *x509.CertPool) {
	t.Helper()
	store := certstore.NewStore(certstore.DefaultCapacity)
	root, code := store.NewRoot(time.Now())
	if code != engine.OK {
		t.Fatalf("generating the capture CA: %v", code)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.Certificate)
	return store, pool
}

// keyLogBuffer collects the downstream NSS keylog lines. Its contents are never
// printed: assertions report labels and counts only, because these lines are the
// connection's secrets (C03 6).
type keyLogBuffer struct {
	mu   sync.Mutex
	data bytes.Buffer
}

func (b *keyLogBuffer) Write(p []byte) (int, error) {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.data.Write(p)
}

func (b *keyLogBuffer) lines() []string {
	b.mu.Lock()
	defer b.mu.Unlock()
	text := strings.TrimSpace(b.data.String())
	if text == "" {
		return nil
	}
	return strings.Split(text, "\n")
}

// assertDownstreamSecretFor asserts that the recorded secrets belong to this
// connection: an NSS line whose label matches the negotiated version and whose
// client random is the one the probe read from this ClientHello. The failure
// message never contains a secret.
func assertDownstreamSecretFor(t *testing.T, keylog *keyLogBuffer, hello ClientHello, version uint16) {
	t.Helper()
	label := "CLIENT_RANDOM"
	if version == tls.VersionTLS13 {
		label = "CLIENT_HANDSHAKE_TRAFFIC_SECRET"
	}
	random := hex.EncodeToString(hello.ClientRandom[:])
	lines := keylog.lines()
	for _, line := range lines {
		fields := strings.Fields(line)
		if len(fields) == 3 && fields[0] == label && fields[1] == random {
			return
		}
	}
	t.Fatalf("no %s line for this connection's client random among %d keylog lines", label, len(lines))
}

// origin is a real TLS listener standing in for the server the application
// really wanted to reach.
type origin struct {
	listener  net.Listener
	echo      bool
	mu        sync.Mutex
	snis      []string
	protocols []string
	appBytes  int
	ended     chan struct{}
	once      sync.Once
}

func newOrigin(t *testing.T, certificate tls.Certificate, version uint16, nextProtos []string) *origin {
	t.Helper()
	o := &origin{echo: true, ended: make(chan struct{})}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   version,
		MaxVersion:   version,
		NextProtos:   nextProtos,
		GetConfigForClient: func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			o.mu.Lock()
			o.snis = append(o.snis, hello.ServerName)
			o.mu.Unlock()
			// nil means "use the configuration above", which is what this
			// listener records rather than replaces.
			return nil, nil
		},
	})
	if err != nil {
		t.Fatalf("listening as the origin: %v", err)
	}
	o.listener = listener
	t.Cleanup(func() { _ = listener.Close() })
	go o.accept()
	return o
}

func (o *origin) accept() {
	for {
		conn, err := o.listener.Accept()
		if err != nil {
			return
		}
		go o.serve(conn.(*tls.Conn))
	}
}

func (o *origin) serve(conn *tls.Conn) {
	defer conn.Close()
	defer o.once.Do(func() { close(o.ended) })
	if err := conn.Handshake(); err != nil {
		return
	}
	o.mu.Lock()
	o.protocols = append(o.protocols, conn.ConnectionState().NegotiatedProtocol)
	o.mu.Unlock()
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			o.mu.Lock()
			o.appBytes += n
			o.mu.Unlock()
			if o.echo {
				if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
					return
				}
			}
		}
		if err != nil {
			return
		}
	}
}

func (o *origin) address() string { return o.listener.Addr().String() }

func (o *origin) seenSNI() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.snis) == 0 {
		return ""
	}
	return o.snis[0]
}

func (o *origin) seenProtocol() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.protocols) == 0 {
		return ""
	}
	return o.protocols[0]
}

// received is how many application bytes the origin read after its handshake:
// the check behind "no application request is replayed".
func (o *origin) received() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.appBytes
}

// waitReleased asserts the coordinator closed the upstream socket rather than
// leaving the connection to the origin's own timeouts.
func (o *origin) waitReleased(t *testing.T) {
	t.Helper()
	select {
	case <-o.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the origin's connection was never released")
	}
}

// waitReceived waits until the origin has read at least want application bytes,
// which is how a test proves application data really left the proxy.
func (o *origin) waitReceived(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if o.received() >= want {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatalf("the origin read %d application bytes, want at least %d", o.received(), want)
}

// silentOrigin accepts a TCP connection and never speaks TLS: the origin that
// makes the upstream handshake run out of its budget.
type silentOrigin struct {
	listener net.Listener
	ended    chan struct{}
	once     sync.Once
}

func newSilentOrigin(t *testing.T) *silentOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening as a silent origin: %v", err)
	}
	o := &silentOrigin{listener: listener, ended: make(chan struct{})}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		defer o.once.Do(func() { close(o.ended) })
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		// Reading detects the peer's close; nothing is ever written back.
		buffer := make([]byte, 1)
		for {
			if _, err := conn.Read(buffer); err != nil {
				return
			}
		}
	}()
	return o
}

func (o *silentOrigin) address() string { return o.listener.Addr().String() }

func (o *silentOrigin) waitReleased(t *testing.T) {
	t.Helper()
	select {
	case <-o.ended:
	case <-time.After(3 * time.Second):
		t.Fatal("the silent origin's connection was never released")
	}
}

// appClient is the captured application's own TLS client. It drives the
// downstream handshake, so it runs concurrently with the coordinator.
type appClient struct {
	conn   *tls.Conn
	result chan error
}

func newAppClient(t *testing.T, address string, config *tls.Config) *appClient {
	t.Helper()
	raw, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dialing the downstream listener: %v", err)
	}
	client := &appClient{conn: tls.Client(raw, config), result: make(chan error, 1)}
	go func() { client.result <- client.conn.Handshake() }()
	return client
}

// wait returns the client's handshake result, failing the test if it never
// returns: a released peer must never leave this side waiting.
func (a *appClient) wait(t *testing.T) error {
	t.Helper()
	select {
	case err := <-a.result:
		return err
	case <-time.After(5 * time.Second):
		t.Fatal("the application's handshake never returned")
		return nil
	}
}

// send writes one request towards the proxy and returns; it does not wait for
// an answer.
func (a *appClient) send(t *testing.T, payload string) {
	t.Helper()
	if _, err := a.conn.Write([]byte(payload)); err != nil {
		t.Fatalf("writing application data: %v", err)
	}
}

// receive reads the answer the origin sent back.
func (a *appClient) receive(t *testing.T) string {
	t.Helper()
	if err := a.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting a read deadline: %v", err)
	}
	echo := make([]byte, 64)
	n, err := a.conn.Read(echo)
	if err != nil {
		t.Fatalf("reading the echoed application data: %v", err)
	}
	_ = a.conn.SetReadDeadline(time.Time{})
	return string(echo[:n])
}

// echoThroughProxy carries one request across both handed-back connections and
// back. The relay itself belongs to TLS-211; this stands in for it, because
// without an application-direction copy the two connections are not wired to
// each other at all, and the assertion here is that they can carry application
// data at all — no handshake budget left over, no half-closed side.
func echoThroughProxy(t *testing.T, session Session, app *appClient, payload string) string {
	t.Helper()
	app.send(t, payload)
	buffer := make([]byte, 64)
	if err := session.Downstream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting a downstream read deadline: %v", err)
	}
	n, err := session.Downstream.Read(buffer)
	if err != nil {
		t.Fatalf("reading from the downstream connection: %v", err)
	}
	if _, err := session.Upstream.Write(buffer[:n]); err != nil {
		t.Fatalf("writing to the upstream connection: %v", err)
	}
	if err := session.Upstream.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting an upstream read deadline: %v", err)
	}
	n, err = session.Upstream.Read(buffer)
	if err != nil {
		t.Fatalf("reading from the upstream connection: %v", err)
	}
	if _, err := session.Downstream.Write(buffer[:n]); err != nil {
		t.Fatalf("writing to the downstream connection: %v", err)
	}
	return app.receive(t)
}

// attempt is one attempt's frozen inputs.
type attempt struct {
	identity      string
	clientMin     uint16
	clientMax     uint16
	offered       []string
	originALPN    []string
	originVersion uint16
	originCert    tls.Certificate
	trustCA       bool
	// originAddress, when set, is dialed instead of a TLS listener this helper
	// starts, so a case can point the upstream leg at something that never
	// speaks.
	originAddress string
	// downstream, when set, replaces the recording keyLogBuffer as the writer
	// installed on the downstream configuration. It is how a case exercises a
	// real writer (TLS-210's production sink) instead of the buffer.
	downstream io.Writer
	// clientCurves, when set, is the application's key-exchange preference order.
	// A first entry the proxy does not enable (tls.MLKEM1024) forces a real
	// HelloRetryRequest on the downstream leg, because the client then sends a key
	// share for a group the proxy cannot use (TLS-217).
	clientCurves []tls.CurveID
	// clientCert, when set, is a client certificate the application is willing to
	// present. The proxy never asks for one, so it never leaves the client
	// (TLS-217's mTLS boundary).
	clientCert *tls.Certificate
	// clientSessionCache, when set, lets the application remember session tickets.
	// The proxy issues none, so a second connection still cannot resume (TLS-217).
	clientSessionCache tls.ClientSessionCache
}

// run performs one attempt against a real origin and a real client.
type runResult struct {
	session Session
	app     *appClient
	probe   Outcome
	keylog  *keyLogBuffer
}

func run(t *testing.T, ca *certstore.Store, pool *x509.CertPool, a attempt, platform *platformStub, timeout time.Duration) (*runResult, *origin) {
	t.Helper()
	return runContext(t, context.Background(), ca, pool, a, platform, timeout)
}

func runContext(t *testing.T, ctx context.Context, ca *certstore.Store, pool *x509.CertPool, a attempt, platform *platformStub, timeout time.Duration) (*runResult, *origin) {
	t.Helper()
	var origin *origin
	address := a.originAddress
	if address == "" {
		origin = newOrigin(t, a.originCert, a.originVersion, a.originALPN)
		address = origin.address()
	}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for the application: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })

	roots := pool
	if !a.trustCA {
		// An application that does not trust the capture CA: it still receives
		// the proxy's leaf, and refuses it.
		roots = x509.NewCertPool()
	}
	app := newAppClient(t, listener.Addr().String(), &tls.Config{
		RootCAs:            roots,
		ServerName:         a.identity,
		NextProtos:         a.offered,
		MinVersion:         a.clientMin,
		MaxVersion:         a.clientMax,
		CurvePreferences:   a.clientCurves,
		Certificates:       clientCertificates(a.clientCert),
		ClientSessionCache: a.clientSessionCache,
	})

	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accepting the application: %v", err)
	}
	probe := ProbeClientHello(accepted, Limits{})
	if probe.Verdict != VerdictClientHello {
		t.Fatalf("probe verdict = %s (%s), want a ClientHello", probe.Verdict, probe.Reason)
	}

	upstream, err := net.Dial("tcp", address)
	if err != nil {
		t.Fatalf("dialing the upstream: %v", err)
	}

	handshaker, code := NewHandshaker(ca, &gateStub{platform: platform}, timeout)
	if code != engine.OK {
		t.Fatalf("NewHandshaker = %v", code)
	}
	keylog := &keyLogBuffer{}
	sink := io.Writer(keylog)
	if a.downstream != nil {
		sink = a.downstream
	}
	session := handshaker.Handshake(ctx, Input{
		Probe:            probe,
		Upstream:         upstream,
		Identity:         a.identity,
		DownstreamKeyLog: sink,
	})
	return &runResult{session: session, app: app, probe: probe, keylog: keylog}, origin
}

// TestTheHandshakeBudgetDoesNotOutliveTheHandshake pins the "clear the deadline
// on success" requirement: a connection whose handshake budget has already
// passed must still carry application data, because a long-lived WebSocket or
// gRPC stream must not be killed by a handshake timeout (design §6.5). The
// assertion is a write, which cannot block on a healthy socket, so a deadline
// that is still installed fails it immediately instead of hanging the test.
func TestTheHandshakeBudgetDoesNotOutliveTheHandshake(t *testing.T) {
	ca, pool := testCA(t)
	budget := 300 * time.Millisecond
	result, origin := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS13,
		originCert:    leafFor(t, x509.ECDSA, []string{"example.test"}, nil),
		trustCA:       true,
	}, &platformStub{verdict: engine.OK}, budget)

	if !result.session.Intercepted() {
		t.Fatalf("attempt failed: %v (%s)", result.session.Code, result.session.Reason)
	}
	time.Sleep(2 * budget)
	if _, err := result.session.Upstream.Write([]byte("ping")); err != nil {
		t.Fatalf("writing to the upstream connection after the handshake budget expired: %v", err)
	}
	if _, err := result.session.Downstream.Write([]byte("ping")); err != nil {
		t.Fatalf("writing to the downstream connection after the handshake budget expired: %v", err)
	}
	// The write left the proxy rather than being accepted locally and dropped.
	origin.waitReceived(t, len("ping"))
}

// TestBothLegsCarryOneApplicationProtocol is the ALPN acceptance case: whatever
// the client offers and whatever the origin selects, the client, the proxy's
// downstream leg and the proxy's upstream leg all end on the same protocol — or
// on none, when the origin selected none. Each case runs over both TLS versions,
// because "one protocol" must not depend on the version.
func TestBothLegsCarryOneApplicationProtocol(t *testing.T) {
	cases := []struct {
		name       string
		offered    []string
		originALPN []string
		want       string
	}{
		{"h2_on_both_sides", []string{"h2"}, []string{"h2"}, "h2"},
		{"http11_on_both_sides", []string{"http/1.1"}, []string{"http/1.1"}, "http/1.1"},
		{"origin_selects_the_second_offer", []string{"h2", "http/1.1"}, []string{"http/1.1"}, "http/1.1"},
		{"origin_selects_the_first_offer", []string{"h2", "http/1.1"}, []string{"h2"}, "h2"},
		{"client_offers_no_alpn", nil, []string{"h2"}, ""},
		{"neither_side_declares_alpn", nil, nil, ""},
		{"origin_declares_no_alpn", []string{"h2", "http/1.1"}, nil, ""},
		// A server configured with only h2 that receives an http/1.1 client is
		// served by Go as if no ALPN had been used; the proxy must mirror that
		// rather than invent h2 downstream.
		{"h2_origin_accepts_an_http11_client", []string{"http/1.1"}, []string{"h2"}, ""},
	}
	versions := []struct {
		name    string
		version uint16
	}{{"tls12", tls.VersionTLS12}, {"tls13", tls.VersionTLS13}}

	// One CA for every case: the identity is the same in all of them, so the
	// leaf cache is shared as well.
	ca, pool := testCA(t)
	originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	platform := &platformStub{verdict: engine.OK}

	for _, test := range cases {
		for _, version := range versions {
			t.Run(test.name+"/"+version.name, func(t *testing.T) {
				result, origin := run(t, ca, pool, attempt{
					identity:      "example.test",
					clientMin:     version.version,
					clientMax:     version.version,
					offered:       test.offered,
					originALPN:    test.originALPN,
					originVersion: version.version,
					// The certificate the origin presents really proves the
					// identity: the upstream leg's own name verification runs
					// against it.
					originCert: originCert,
					trustCA:    true,
				}, platform, 0)

				session := result.session
				if !session.Intercepted() {
					t.Fatalf("attempt failed: %v (%s)", session.Code, session.Reason)
				}
				if session.ALPN != test.want {
					t.Fatalf("session ALPN = %q, want %q", session.ALPN, test.want)
				}
				if !session.SpokeToClient() {
					t.Fatal("a completed handshake reported that nothing was written to the client")
				}
				// The three ends of the two legs must agree, and the client's
				// own answer is the one that matters to the application.
				downstream := session.Downstream.ConnectionState()
				upstream := session.Upstream.ConnectionState()
				if downstream.NegotiatedProtocol != test.want || upstream.NegotiatedProtocol != test.want {
					t.Fatalf("proxy negotiated downstream %q / upstream %q, want both %q",
						downstream.NegotiatedProtocol, upstream.NegotiatedProtocol, test.want)
				}
				if got := origin.seenProtocol(); got != test.want {
					t.Fatalf("origin negotiated %q, want %q", got, test.want)
				}
				if downstream.Version != version.version || upstream.Version != version.version {
					t.Fatalf("versions = downstream %x / upstream %x, want both %x",
						downstream.Version, upstream.Version, version.version)
				}

				if err := result.app.wait(t); err != nil {
					t.Fatalf("the application's handshake failed: %v", err)
				}
				if got := result.app.conn.ConnectionState().NegotiatedProtocol; got != test.want {
					t.Fatalf("the application negotiated %q, want %q", got, test.want)
				}
				if echoed := echoThroughProxy(t, session, result.app, "ping"); echoed != "ping" {
					t.Fatalf("application round trip = %q, want the origin's echo", echoed)
				}
				if origin.received() == 0 {
					t.Fatal("the origin relayed no application data")
				}

				// The downstream keylog must describe this connection: same
				// client random, label matching the negotiated version.
				assertDownstreamSecretFor(t, result.keylog, result.probe.Hello, version.version)
			})
		}
	}
}

// TestTheTwoLegsMayUseDifferentVersions pins design §6.3: the TLS versions of
// the two legs are independent, while the application protocol is not. A client
// that offers both versions is served over TLS 1.3 downstream even though the
// origin only speaks TLS 1.2, and the floor derived from the client's offer
// (1.2) does not force the downstream leg down with it.
func TestTheTwoLegsMayUseDifferentVersions(t *testing.T) {
	ca, pool := testCA(t)
	result, origin := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS12,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS12,
		originCert:    leafFor(t, x509.ECDSA, []string{"example.test"}, nil),
		trustCA:       true,
	}, &platformStub{verdict: engine.OK}, 0)

	if !result.session.Intercepted() {
		t.Fatalf("attempt failed: %v (%s)", result.session.Code, result.session.Reason)
	}
	if got := result.session.Downstream.ConnectionState().Version; got != tls.VersionTLS13 {
		t.Fatalf("downstream version = %x, want TLS 1.3", got)
	}
	if got := result.session.Upstream.ConnectionState().Version; got != tls.VersionTLS12 {
		t.Fatalf("upstream version = %x, want TLS 1.2", got)
	}
	if result.session.ALPN != "h2" || origin.seenProtocol() != "h2" {
		t.Fatalf("ALPN = %q, origin saw %q, want h2 on both sides", result.session.ALPN, origin.seenProtocol())
	}
	if err := result.app.wait(t); err != nil {
		t.Fatalf("the application's handshake failed: %v", err)
	}
	if echoed := echoThroughProxy(t, result.session, result.app, "ping"); echoed != "ping" {
		t.Fatalf("application round trip = %q", echoed)
	}
	// The downstream secret must be the TLS 1.3 one: the two legs' versions
	// differ, so the labels do too.
	assertDownstreamSecretFor(t, result.keylog, result.probe.Hello, tls.VersionTLS13)
}

// TestNoSNIUsesTheDestinationAddress pins the IP-SAN case: a client that asserts
// no name is served a leaf for the address the socket was opened to, the
// upstream leg sends no SNI, and the origin's certificate proves the address.
func TestNoSNIUsesTheDestinationAddress(t *testing.T) {
	ca, pool := testCA(t)
	result, origin := run(t, ca, pool, attempt{
		identity:      "127.0.0.1",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS13,
		originCert:    leafFor(t, x509.ECDSA, nil, []net.IP{net.ParseIP("127.0.0.1")}),
		trustCA:       true,
	}, &platformStub{verdict: engine.OK}, 0)

	if !result.session.Intercepted() {
		t.Fatalf("attempt failed: %v (%s)", result.session.Code, result.session.Reason)
	}
	if result.probe.Hello.SNI != "" {
		t.Fatalf("the client asserted SNI %q, want none", result.probe.Hello.SNI)
	}
	if got := origin.seenSNI(); got != "" {
		t.Fatalf("the upstream handshake sent SNI %q, want none for an address", got)
	}
	if err := result.app.wait(t); err != nil {
		t.Fatalf("the application refused the address leaf: %v", err)
	}
	if echoed := echoThroughProxy(t, result.session, result.app, "ping"); echoed != "ping" {
		t.Fatalf("application round trip = %q", echoed)
	}
}

// TestNoCommonProtocolEndsTheAttempt is the other half of the ALPN case: when
// the origin refuses the protocols the client offered, the attempt ends with a
// definite code and reason, the client is never sent proxy TLS, and the origin
// is released.
func TestNoCommonProtocolEndsTheAttempt(t *testing.T) {
	ca, pool := testCA(t)
	platform := &platformStub{verdict: engine.OK}
	result, origin := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"http/1.1"},
		originVersion: tls.VersionTLS13,
		originCert:    leafFor(t, x509.ECDSA, []string{"example.test"}, nil),
		trustCA:       true,
	}, platform, 0)

	if result.session.Code != engine.Unsupported || result.session.Reason != ReasonUpstreamALPN {
		t.Fatalf("attempt = %v (%s), want UNSUPPORTED (alpn_not_agreed)", result.session.Code, result.session.Reason)
	}
	if result.session.Intercepted() {
		t.Fatal("a refused ALPN negotiation produced a session")
	}
	if result.session.SpokeToClient() || result.session.BytesToDownstream != 0 {
		t.Fatalf("the client was sent %d bytes of proxy TLS, want none", result.session.BytesToDownstream)
	}
	origin.waitReleased(t)
	if origin.received() != 0 {
		t.Fatal("application data reached an origin that refused the protocol")
	}
	// The client must be released rather than left waiting for a ServerHello
	// that will never come.
	if err := result.app.wait(t); err == nil {
		t.Fatal("the application's handshake succeeded against a connection that was never established")
	}
	// Nothing was ever verified, because nothing was ever negotiated.
	if calls, _, _, _, _ := platform.observed(); calls != 0 {
		t.Fatalf("the platform verifier was called %d times, want 0", calls)
	}
}

// TestUpstreamCertificateRejectionEndsBeforeTheClientIsSpokenTo covers the
// "wrong domain" case: the origin presents a certificate that does not prove the
// connection's identity, so the attempt ends with no byte written towards the
// client and no application request replayed.
func TestUpstreamCertificateRejectionEndsBeforeTheClientIsSpokenTo(t *testing.T) {
	ca, pool := testCA(t)
	platform := &platformStub{verdict: engine.OK}
	result, origin := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS13,
		// The origin proves a different name: Go's name verification must end
		// the handshake before the platform is asked anything.
		originCert: leafFor(t, x509.ECDSA, []string{"other.fixture.test"}, nil),
		trustCA:    true,
	}, platform, 0)

	if result.session.Code != engine.UpstreamCertInvalid || result.session.Reason != ReasonUpstreamVerification {
		t.Fatalf("attempt = %v (%s), want UPSTREAM_CERT_INVALID", result.session.Code, result.session.Reason)
	}
	if result.session.SpokeToClient() {
		t.Fatal("the client was sent proxy TLS before the upstream was verified")
	}
	if calls, _, _, _, _ := platform.observed(); calls != 0 {
		t.Fatalf("the platform verifier was called %d times, want 0", calls)
	}
	origin.waitReleased(t)
	if origin.received() != 0 {
		t.Fatal("application data reached an origin whose certificate was rejected")
	}
	if err := result.app.wait(t); err == nil {
		t.Fatal("the application's handshake succeeded after an upstream rejection")
	}
}

// TestPlatformVerdictEndsTheAttempt covers the second half of upstream
// verification: a chain the platform rejects ends the attempt even though Go's
// own name check passed, and a platform call the engine refused is reported as a
// cancellation rather than as a certificate verdict.
func TestPlatformVerdictEndsTheAttempt(t *testing.T) {
	for _, test := range []struct {
		name       string
		verdict    engine.Code
		wantCode   engine.Code
		wantReason Reason
	}{
		{"certificate_rejected_by_the_platform", engine.UpstreamCertInvalid, engine.UpstreamCertInvalid, ReasonUpstreamVerification},
		{"chain_unsupported_by_the_platform", engine.Unsupported, engine.Unsupported, ReasonUpstreamVerification},
		{"admission_closed", engine.Cancelled, engine.Cancelled, ReasonCancelled},
		{"generation_moved_on", engine.StaleGeneration, engine.StaleGeneration, ReasonCancelled},
	} {
		t.Run(test.name, func(t *testing.T) {
			ca, pool := testCA(t)
			platform := &platformStub{verdict: test.verdict}
			result, origin := run(t, ca, pool, attempt{
				identity:      "example.test",
				clientMin:     tls.VersionTLS13,
				clientMax:     tls.VersionTLS13,
				offered:       []string{"h2"},
				originALPN:    []string{"h2"},
				originVersion: tls.VersionTLS13,
				originCert:    leafFor(t, x509.ECDSA, []string{"example.test"}, nil),
				trustCA:       true,
			}, platform, 0)

			if result.session.Code != test.wantCode || result.session.Reason != test.wantReason {
				t.Fatalf("attempt = %v (%s), want %v (%s)",
					result.session.Code, result.session.Reason, test.wantCode, test.wantReason)
			}
			if result.session.SpokeToClient() {
				t.Fatal("the client was sent proxy TLS before the upstream was accepted")
			}
			if calls, identity, authType, version, leaf := platform.observed(); calls != 1 ||
				identity != "example.test" || authType != "ECDSA" || version != "TLSv1.3" || len(leaf) == 0 {
				t.Fatalf("platform saw %d calls, identity %q, authType %q, version %q, %d leaf bytes",
					calls, identity, authType, version, len(leaf))
			}
			origin.waitReleased(t)
			if err := result.app.wait(t); err == nil {
				t.Fatal("the application's handshake succeeded after a platform rejection")
			}
		})
	}
}

// TestClientRefusingTheCaptureCAIsRecordedAsADownstreamRejection covers the
// application that does not trust the capture CA: the proxy's certificate has
// already been presented, the upstream leg was established, no application
// request was relayed, and the recorded reason says the client refused rather
// than that it never answered.
func TestClientRefusingTheCaptureCAIsRecordedAsADownstreamRejection(t *testing.T) {
	ca, pool := testCA(t)
	platform := &platformStub{verdict: engine.OK}
	result, origin := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS13,
		originCert:    leafFor(t, x509.ECDSA, []string{"example.test"}, nil),
		trustCA:       false,
	}, platform, 0)

	if result.session.Code != engine.DownstreamTLSRejected || result.session.Reason != ReasonDownstreamAlert {
		t.Fatalf("attempt = %v (%s), want DOWNSTREAM_TLS_REJECTED", result.session.Code, result.session.Reason)
	}
	if !result.session.SpokeToClient() {
		t.Fatal("the certificate that was refused was never recorded as having been presented")
	}
	if result.session.Intercepted() {
		t.Fatal("a refused downstream handshake produced a session")
	}
	// The upstream leg had completed, which is why the failure is attributed to
	// the client and not to the origin.
	if calls, _, _, _, _ := platform.observed(); calls != 1 {
		t.Fatalf("the platform verifier was called %d times, want 1", calls)
	}
	origin.waitReleased(t)
	if origin.received() != 0 {
		t.Fatal("application data was relayed after the client refused the proxy's certificate")
	}
	if err := result.app.wait(t); err == nil {
		t.Fatal("the application accepted a certificate from an untrusted CA")
	}
}

// TestUpstreamThatNeverAnswersIsReleasedToTheClient uses an origin that accepts
// the TCP connection and then says nothing: the upstream handshake runs out of
// its own budget, and the client — which is waiting for a server it will never
// hear from — is released instead of waiting forever.
func TestUpstreamThatNeverAnswersIsReleasedToTheClient(t *testing.T) {
	ca, pool := testCA(t)
	silent := newSilentOrigin(t)
	result, _ := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		trustCA:       true,
		originAddress: silent.address(),
	}, &platformStub{verdict: engine.OK}, 250*time.Millisecond)

	if result.session.Code != engine.IOError || result.session.Reason != ReasonUpstreamTimeout {
		t.Fatalf("attempt = %v (%s), want IO_ERROR (upstream_handshake_timeout)",
			result.session.Code, result.session.Reason)
	}
	if result.session.SpokeToClient() {
		t.Fatal("the client was sent proxy TLS because the upstream stalled")
	}
	silent.waitReleased(t)
	if err := result.app.wait(t); err == nil {
		t.Fatal("the application's handshake succeeded against a stalled upstream")
	}
}

// TestADownstreamThatNeverAnswersIsNotCalledARejection stalls the other side:
// the origin answers normally, the client sends a real ClientHello and then
// stops, and the downstream budget expires. The reason must say that nothing was
// refused, and the origin must be released.
func TestADownstreamThatNeverAnswersIsNotCalledARejection(t *testing.T) {
	ca, _ := testCA(t)
	origin := newOrigin(t, leafFor(t, x509.ECDSA, []string{"example.test"}, nil), tls.VersionTLS13, []string{"h2"})

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for the stalled application: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	stalled, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dialing the downstream listener: %v", err)
	}
	t.Cleanup(func() { _ = stalled.Close() })
	// A real ClientHello, and then silence: the peer never reads the proxy's
	// answer and never sends its own.
	hello := realClientHello(t, &tls.Config{ServerName: "example.test", NextProtos: []string{"h2"}})
	if _, err := stalled.Write(hello); err != nil {
		t.Fatalf("writing the ClientHello: %v", err)
	}
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accepting the stalled application: %v", err)
	}
	probe := ProbeClientHello(accepted, Limits{})
	if probe.Verdict != VerdictClientHello {
		t.Fatalf("probe verdict = %s (%s)", probe.Verdict, probe.Reason)
	}
	upstream, err := net.Dial("tcp", origin.address())
	if err != nil {
		t.Fatalf("dialing the origin: %v", err)
	}

	handshaker, code := NewHandshaker(ca, &gateStub{platform: &platformStub{verdict: engine.OK}}, 250*time.Millisecond)
	if code != engine.OK {
		t.Fatalf("NewHandshaker = %v", code)
	}
	started := time.Now()
	session := handshaker.Handshake(context.Background(), Input{
		Probe:    probe,
		Upstream: upstream,
		Identity: "example.test",
	})

	if session.Code != engine.IOError || session.Reason != ReasonDownstreamTimeout {
		t.Fatalf("attempt = %v (%s), want IO_ERROR (downstream_handshake_timeout)",
			session.Code, session.Reason)
	}
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("the stalled handshake took %s to give up", elapsed)
	}
	if !session.SpokeToClient() {
		t.Fatal("the proxy had already written its handshake to the client, which the boundary must record")
	}
	origin.waitReleased(t)
	if origin.received() != 0 {
		t.Fatal("application data was relayed from a client that never answered")
	}
}

// TestCancellationReleasesBothSides cancels an attempt that is blocked on an
// upstream which never answers, and asserts that neither side is left waiting.
func TestCancellationReleasesBothSides(t *testing.T) {
	ca, pool := testCA(t)
	silent := newSilentOrigin(t)
	ctx, cancel := context.WithCancel(context.Background())
	// The cancellation has to land while the upstream handshake is blocked.
	go func() {
		time.Sleep(100 * time.Millisecond)
		cancel()
	}()
	defer cancel()

	result, _ := runContext(t, ctx, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		trustCA:       true,
		originAddress: silent.address(),
	}, &platformStub{verdict: engine.OK}, 0)

	if result.session.Code != engine.Cancelled || result.session.Reason != ReasonCancelled {
		t.Fatalf("attempt = %v (%s), want CANCELLED", result.session.Code, result.session.Reason)
	}
	if result.session.Intercepted() || result.session.SpokeToClient() {
		t.Fatal("a cancelled attempt produced a session or wrote to the client")
	}
	silent.waitReleased(t)
	if err := result.app.wait(t); err == nil {
		t.Fatal("the application's handshake succeeded after the attempt was cancelled")
	}
}

// TestHandshakeInputAndBudgetValidation covers the paths that must be refused
// before anything is handed to crypto/tls, and asserts the transports are still
// released.
func TestHandshakeInputAndBudgetValidation(t *testing.T) {
	ca, _ := testCA(t)
	gate := &gateStub{platform: &platformStub{verdict: engine.OK}}
	handshaker, code := NewHandshaker(ca, gate, 0)
	if code != engine.OK {
		t.Fatalf("NewHandshaker = %v", code)
	}
	hello := defaultHello().with(
		extension(extServerName, sniList(sniEntry(sniHostName, "example.test"))),
		extension(extALPN, alpnExtension("h2")),
		extension(extSupportedVersions, versionsExtension(tls.VersionTLS13)),
		extension(extSignatureAlgorithms, signatureAlgorithmsExtension(uint16(tls.ECDSAWithP256AndSHA256))),
	).wire()
	probe := func(t *testing.T) Outcome {
		t.Helper()
		outcome := probeWith(t, hello)
		if outcome.Verdict != VerdictClientHello {
			t.Fatalf("synthetic probe verdict = %s (%s)", outcome.Verdict, outcome.Reason)
		}
		return outcome
	}
	valid := func(t *testing.T) Input {
		t.Helper()
		return Input{Probe: probe(t), Upstream: newScriptConn(), Identity: "example.test"}
	}

	t.Run("nil_context", func(t *testing.T) {
		input := valid(t)
		session := handshaker.Handshake(nil, input)
		if session.Code != engine.InvalidArgument || session.Reason != ReasonInvalidInput {
			t.Fatalf("attempt = %v (%s), want INVALID_ARGUMENT", session.Code, session.Reason)
		}
		assertReleased(t, input)
	})
	t.Run("no_upstream_socket", func(t *testing.T) {
		input := valid(t)
		input.Upstream = nil
		session := handshaker.Handshake(context.Background(), input)
		if session.Code != engine.InvalidArgument || session.Reason != ReasonInvalidInput {
			t.Fatalf("attempt = %v (%s), want INVALID_ARGUMENT", session.Code, session.Reason)
		}
		if !input.Probe.Conn.conn.(*scriptConn).closed {
			t.Fatal("the downstream transport was not released")
		}
	})
	t.Run("no_probe_connection", func(t *testing.T) {
		input := valid(t)
		input.Probe.Conn = nil
		session := handshaker.Handshake(context.Background(), input)
		if session.Code != engine.InvalidArgument || session.Reason != ReasonInvalidInput {
			t.Fatalf("attempt = %v (%s), want INVALID_ARGUMENT", session.Code, session.Reason)
		}
	})
	t.Run("probe_is_not_a_client_hello", func(t *testing.T) {
		input := valid(t)
		input.Probe = probeWith(t, []byte("GET / HTTP/1.1\r\n\r\n"))
		if input.Probe.Verdict == VerdictClientHello {
			t.Fatal("the plain text stream was classified as a ClientHello")
		}
		session := handshaker.Handshake(context.Background(), input)
		if session.Code != engine.InvalidArgument || session.Reason != ReasonInvalidInput {
			t.Fatalf("attempt = %v (%s), want INVALID_ARGUMENT", session.Code, session.Reason)
		}
	})
	t.Run("identity_is_not_usable", func(t *testing.T) {
		input := valid(t)
		input.Identity = "exa mple.test"
		session := handshaker.Handshake(context.Background(), input)
		if session.Code != engine.InvalidArgument || session.Reason != ReasonInvalidInput {
			t.Fatalf("attempt = %v (%s), want INVALID_ARGUMENT", session.Code, session.Reason)
		}
	})
	t.Run("unassembled", func(t *testing.T) {
		input := valid(t)
		var missing *Handshaker
		session := missing.Handshake(context.Background(), input)
		if session.Code != engine.NotReady || session.Reason != ReasonNotReady {
			t.Fatalf("attempt = %v (%s), want NOT_READY", session.Code, session.Reason)
		}
		assertReleased(t, input)
	})
	t.Run("no_served_version", func(t *testing.T) {
		input := valid(t)
		// Built by hand: the probe already refuses a hello with no served
		// version, so this exercises the coordinator's own guard against a
		// caller that hands it an offer it cannot satisfy.
		input.Probe = Outcome{
			Verdict: VerdictClientHello,
			Conn:    NewPrefixConn(newScriptConn(), nil),
			Hello:   ClientHello{SupportedVersionsPresent: true, SupportedVersions: []uint16{tls.VersionTLS11}},
		}
		session := handshaker.Handshake(context.Background(), input)
		if session.Code != engine.Unsupported || session.Reason != ReasonNoVersion {
			t.Fatalf("attempt = %v (%s), want UNSUPPORTED (no_supported_version)", session.Code, session.Reason)
		}
	})
	t.Run("no_usable_signature_algorithm", func(t *testing.T) {
		input := valid(t)
		input.Probe = probeWith(t, defaultHello().with(
			extension(extServerName, sniList(sniEntry(sniHostName, "example.test"))),
			extension(extSupportedVersions, versionsExtension(tls.VersionTLS13)),
		).wire())
		session := handshaker.Handshake(context.Background(), input)
		if session.Code != engine.Unsupported || session.Reason != ReasonNoSignatures {
			t.Fatalf("attempt = %v (%s), want UNSUPPORTED (unsupported_signature_algorithms)", session.Code, session.Reason)
		}
	})
	t.Run("budgets", func(t *testing.T) {
		if _, code := NewHandshaker(nil, gate, 0); code != engine.NotReady {
			t.Fatalf("NewHandshaker without a CA = %v, want NOT_READY", code)
		}
		if _, code := NewHandshaker(ca, nil, 0); code != engine.NotReady {
			t.Fatalf("NewHandshaker without a platform gate = %v, want NOT_READY", code)
		}
		if _, code := NewHandshaker(ca, gate, -time.Second); code != engine.InvalidArgument {
			t.Fatalf("NewHandshaker with a negative budget = %v, want INVALID_ARGUMENT", code)
		}
		if _, code := NewHandshaker(ca, gate, MaxHandshakeTimeout+time.Second); code != engine.InvalidArgument {
			t.Fatalf("NewHandshaker above the ceiling = %v, want INVALID_ARGUMENT", code)
		}
		if _, code := NewHandshaker(ca, gate, MaxHandshakeTimeout); code != engine.OK {
			t.Fatalf("NewHandshaker at the ceiling = %v, want OK", code)
		}
	})
}

// assertReleased asserts both transports an input carried were closed.
func assertReleased(t *testing.T, input Input) {
	t.Helper()
	if !input.Probe.Conn.conn.(*scriptConn).closed {
		t.Fatal("the downstream transport was not released")
	}
	if !input.Upstream.(*scriptConn).closed {
		t.Fatal("the upstream transport was not released")
	}
}

// TestLeafThatCannotBeIssuedStopsTheAttempt covers the path where the CA cannot
// issue: the attempt stops before the client is spoken to, and the CA's own code
// is reported.
func TestLeafThatCannotBeIssuedStopsTheAttempt(t *testing.T) {
	gate := &gateStub{platform: &platformStub{verdict: engine.OK}}
	empty := certstore.NewStore(certstore.DefaultCapacity)
	handshaker, code := NewHandshaker(empty, gate, 0)
	if code != engine.OK {
		t.Fatalf("NewHandshaker = %v", code)
	}

	origin := newOrigin(t, leafFor(t, x509.ECDSA, []string{"example.test"}, nil), tls.VersionTLS13, []string{"h2"})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	app := newAppClient(t, listener.Addr().String(), &tls.Config{
		InsecureSkipVerify: true,
		ServerName:         "example.test",
		NextProtos:         []string{"h2"},
		MinVersion:         tls.VersionTLS13,
		MaxVersion:         tls.VersionTLS13,
	})
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accepting: %v", err)
	}
	probe := ProbeClientHello(accepted, Limits{})
	if probe.Verdict != VerdictClientHello {
		t.Fatalf("probe verdict = %s (%s)", probe.Verdict, probe.Reason)
	}
	upstream, err := net.Dial("tcp", origin.address())
	if err != nil {
		t.Fatalf("dialing the origin: %v", err)
	}

	session := handshaker.Handshake(context.Background(), Input{
		Probe:    probe,
		Upstream: upstream,
		Identity: "example.test",
	})
	if session.Code != engine.NotReady || session.Reason != ReasonLeafUnavailable {
		t.Fatalf("attempt = %v (%s), want NOT_READY (downstream_leaf_unavailable)", session.Code, session.Reason)
	}
	if session.SpokeToClient() {
		t.Fatal("the client was sent proxy TLS without a certificate")
	}
	origin.waitReleased(t)
	if err := app.wait(t); err == nil {
		t.Fatal("the application's handshake succeeded without a certificate")
	}
}

func TestMinServedVersionFollowsTheClientsOffer(t *testing.T) {
	for _, test := range []struct {
		name    string
		hello   ClientHello
		want    uint16
		wantErr engine.Code
	}{
		{"tls13_only", ClientHello{SupportedVersionsPresent: true, SupportedVersions: []uint16{tls.VersionTLS13}}, tls.VersionTLS13, engine.OK},
		{"tls12_only", ClientHello{SupportedVersionsPresent: true, SupportedVersions: []uint16{tls.VersionTLS12}}, tls.VersionTLS12, engine.OK},
		{"both_versions", ClientHello{SupportedVersionsPresent: true, SupportedVersions: []uint16{tls.VersionTLS13, tls.VersionTLS12}}, tls.VersionTLS12, engine.OK},
		{"legacy_field_is_authoritative_without_the_extension", ClientHello{LegacyVersion: tls.VersionTLS12}, tls.VersionTLS12, engine.OK},
		{"legacy_field_below_the_floor", ClientHello{LegacyVersion: tls.VersionTLS11}, 0, engine.Unsupported},
		{"extension_offers_nothing_served", ClientHello{SupportedVersionsPresent: true, SupportedVersions: []uint16{tls.VersionTLS10}}, 0, engine.Unsupported},
		{"extension_present_but_empty", ClientHello{SupportedVersionsPresent: true}, 0, engine.Unsupported},
		{"extension_wins_over_the_legacy_field", ClientHello{LegacyVersion: tls.VersionTLS10, SupportedVersionsPresent: true, SupportedVersions: []uint16{tls.VersionTLS13}}, tls.VersionTLS13, engine.OK},
	} {
		t.Run(test.name, func(t *testing.T) {
			version, code := minServedVersion(test.hello)
			if version != test.want || code != test.wantErr {
				t.Fatalf("minServedVersion = %x/%v, want %x/%v", version, code, test.want, test.wantErr)
			}
		})
	}
}

func TestOfferedALPNIsBoundedAndCopied(t *testing.T) {
	protocols := []string{"h2", "http/1.1"}
	offered, code := offeredALPN(protocols)
	if code != engine.OK || len(offered) != 2 || offered[0] != "h2" || offered[1] != "http/1.1" {
		t.Fatalf("offeredALPN = %v/%v", offered, code)
	}
	if none, code := offeredALPN(nil); code != engine.OK || none != nil {
		t.Fatalf("offeredALPN(nil) = %v/%v, want a nil list", none, code)
	}
	if _, code := offeredALPN([]string{""}); code != engine.InvalidArgument {
		t.Fatalf("an empty protocol name = %v, want INVALID_ARGUMENT", code)
	}
	if _, code := offeredALPN([]string{strings.Repeat("a", maxProtocolLength+1)}); code != engine.InvalidArgument {
		t.Fatalf("an over-long protocol name = %v, want INVALID_ARGUMENT", code)
	}
	if _, code := offeredALPN([]string{strings.Repeat("a", maxProtocolLength)}); code != engine.OK {
		t.Fatalf("a protocol name at the limit = %v, want OK", code)
	}
	tooMany := make([]string, maxOfferedProtocols+1)
	for index := range tooMany {
		tooMany[index] = "h2"
	}
	if _, code := offeredALPN(tooMany); code != engine.InvalidArgument {
		t.Fatalf("an over-long list = %v, want INVALID_ARGUMENT", code)
	}
	if _, code := offeredALPN(tooMany[:maxOfferedProtocols]); code != engine.OK {
		t.Fatalf("a list at the limit = %v, want OK", code)
	}
}

func TestDownstreamProtosDeclaresOnlyTheSelectedProtocol(t *testing.T) {
	if got := downstreamProtos(""); got != nil {
		t.Fatalf("downstreamProtos(\"\") = %v, want nothing declared", got)
	}
	got := downstreamProtos("http/1.1")
	if len(got) != 1 || got[0] != "http/1.1" {
		t.Fatalf("downstreamProtos = %v", got)
	}
}

// TestBothDownstreamConfigurationsCarryTheWriterAndTheSelectedProtocol is the
// checkable form of "the base configuration and the one GetConfigForClient
// returns both keep the downstream writer injection point": the writer TLS-210
// injects must be present on whichever configuration performs the handshake, and
// neither may declare a protocol other than the one the origin selected.
func TestBothDownstreamConfigurationsCarryTheWriterAndTheSelectedProtocol(t *testing.T) {
	writer := &keyLogBuffer{}
	sink := &keyLogSink{inner: writer}
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)

	config := newDownstreamConfig(leaf, "h2", tls.VersionTLS12, sink.writer())
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return newDownstreamConfig(leaf, "h2", tls.VersionTLS12, sink.writer()), nil
	}
	callback, err := config.GetConfigForClient(&tls.ClientHelloInfo{})
	if err != nil {
		t.Fatalf("GetConfigForClient: %v", err)
	}
	if callback.GetConfigForClient != nil {
		t.Fatal("the returned configuration still has the callback: it must be the terminal one")
	}
	for name, candidate := range map[string]*tls.Config{"base": config, "callback": callback} {
		if candidate.KeyLogWriter == nil {
			t.Fatalf("%s configuration has no keylog writer", name)
		}
		if len(candidate.NextProtos) != 1 || candidate.NextProtos[0] != "h2" {
			t.Fatalf("%s configuration declares %v, want only h2", name, candidate.NextProtos)
		}
		if candidate.MinVersion != tls.VersionTLS12 || candidate.MaxVersion != tls.VersionTLS13 {
			t.Fatalf("%s configuration versions = %x..%x", name, candidate.MinVersion, candidate.MaxVersion)
		}
		if !candidate.SessionTicketsDisabled {
			t.Fatalf("%s configuration allows session tickets", name)
		}
		if len(candidate.Certificates) != 1 {
			t.Fatalf("%s configuration has %d certificates", name, len(candidate.Certificates))
		}
	}
	if none := newDownstreamConfig(leaf, "", tls.VersionTLS12, nil); none.NextProtos != nil || none.KeyLogWriter != nil {
		t.Fatalf("a connection with no protocol and no writer got %v/%v", none.NextProtos, none.KeyLogWriter)
	}
}

// TestAKeyLogWriterThatFailsStopsTheConnectionItBelongsTo pins the behaviour
// crypto/tls gives a writer error: the handshake that could not record its
// secrets fails, and the failure is reported as a secret problem rather than as
// the client refusing the certificate.
func TestAKeyLogWriterThatFailsStopsTheConnectionItBelongsTo(t *testing.T) {
	ca, pool := testCA(t)
	origin := newOrigin(t, leafFor(t, x509.ECDSA, []string{"example.test"}, nil), tls.VersionTLS13, []string{"h2"})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	app := newAppClient(t, listener.Addr().String(), &tls.Config{
		RootCAs:    pool,
		ServerName: "example.test",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatalf("accepting: %v", err)
	}
	probe := ProbeClientHello(accepted, Limits{})
	if probe.Verdict != VerdictClientHello {
		t.Fatalf("probe verdict = %s (%s)", probe.Verdict, probe.Reason)
	}
	upstream, err := net.Dial("tcp", origin.address())
	if err != nil {
		t.Fatalf("dialing the origin: %v", err)
	}
	handshaker, code := NewHandshaker(ca, &gateStub{platform: &platformStub{verdict: engine.OK}}, 0)
	if code != engine.OK {
		t.Fatalf("NewHandshaker = %v", code)
	}

	session := handshaker.Handshake(context.Background(), Input{
		Probe:            probe,
		Upstream:         upstream,
		Identity:         "example.test",
		DownstreamKeyLog: failingWriter{},
	})
	if session.Code != engine.SecretsIncomplete || session.Reason != ReasonSecretsIncomplete {
		t.Fatalf("attempt = %v (%s), want SECRETS_INCOMPLETE (downstream_key_log_failed)",
			session.Code, session.Reason)
	}
	if session.Intercepted() {
		t.Fatal("a connection whose secrets were not recorded was handed back as established")
	}
	origin.waitReleased(t)
	if origin.received() != 0 {
		t.Fatal("application data was relayed for a connection whose secrets were not recorded")
	}
	if err := app.wait(t); err == nil {
		t.Fatal("the application's handshake succeeded although the proxy could not record its keys")
	}
}

// failingWriter is a keylog writer that refuses everything, standing in for a
// full queue or a failed secret store.
type failingWriter struct{}

func (failingWriter) Write([]byte) (int, error) {
	return 0, errors.New("key log rejected")
}

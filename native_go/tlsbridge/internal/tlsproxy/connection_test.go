package tlsproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io"
	"net"
	"net/netip"
	"strconv"
	"sync"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/certstore"
	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/secrets"
)

// The state machine is tested end to end over loopback: real sockets, a real
// ClientHello, a real origin, and — wherever a connection is intercepted — two
// real TLS handshakes. What is doubled is only what cannot run off Android: the
// C05 platform callbacks (the trust answer and the secret sink's consumer), the
// fallback dialer, and the decision maker, which lives in another package and
// cannot be imported from this one without a cycle. Every assertion about bytes
// here is made on bytes that really crossed a socket.

// routerStub is a fixed decision, recorded so a test can assert what the state
// machine asked and that it asked exactly once per connection.
type routerStub struct {
	route Route
	code  engine.Code

	mu          sync.Mutex
	routed      int
	destination netip.AddrPort
	application string
	sni         string
	verdict     Verdict
	reason      string
}

func (r *routerStub) Route(destination netip.AddrPort, application string, outcome Outcome) (Route, engine.Code) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.routed++
	r.destination, r.application = destination, application
	r.sni, r.verdict, r.reason = outcome.Hello.SNI, outcome.Verdict, outcome.Reason
	if r.code != engine.OK {
		return Route{}, r.code
	}
	return r.route, engine.OK
}

func (r *routerStub) attempts() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.routed
}

// observed returns what the state machine handed the decision maker.
func (r *routerStub) observed() (Verdict, string, string, netip.AddrPort, string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.verdict, r.reason, r.sni, r.destination, r.application
}

// keylogPlatform is the platform half: the trust answer the handshakes need and
// the secret consumer the sink delivers to. It counts records and never keeps
// one, so a failing assertion can never print a secret (C03 6).
type keylogPlatform struct {
	verdict engine.Code
	offer   engine.Code

	mu       sync.Mutex
	identity string
	offers   int
}

func (p *keylogPlatform) PrepareSocket(int, int64) engine.Code { return engine.OK }
func (p *keylogPlatform) ResolveHost(string, int64) ([]byte, engine.Code) {
	return nil, engine.NotReady
}

func (p *keylogPlatform) VerifyUpstream(_ [][]byte, identity, _, _ string) engine.Code {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.identity = identity
	return p.verdict
}

func (p *keylogPlatform) OfferSecret(_, _ string, _ []byte) engine.Code {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.offers++
	return p.offer
}

func (p *keylogPlatform) offered() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.offers
}

func (p *keylogPlatform) verifiedIdentity() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.identity
}

// dialerStub stands in for uplink.Dialer on the fallback path. It counts its
// calls, because "no second connection was opened" is an assertion about every
// path that must not fall back.
type dialerStub struct {
	address string
	code    engine.Code

	mu    sync.Mutex
	dials int
}

func (d *dialerStub) Dial(ctx context.Context, destination netip.AddrPort) (net.Conn, engine.Code) {
	d.mu.Lock()
	d.dials++
	code, address := d.code, d.address
	d.mu.Unlock()
	if code != engine.OK {
		return nil, code
	}
	if address == "" {
		// The real dialer connects to the destination it was given, and so does
		// this one: a fallback must land on the same origin on a fresh socket.
		address = destination.String()
	}
	conn, err := (&net.Dialer{}).DialContext(ctx, "tcp", address)
	if err != nil {
		return nil, engine.IOError
	}
	return conn, engine.OK
}

func (d *dialerStub) calls() int {
	d.mu.Lock()
	defer d.mu.Unlock()
	return d.dials
}

// captureOptions are the knobs a test turns before the pipeline is built.
type captureOptions struct {
	route            Route
	routeCode        engine.Code
	store            *certstore.Store
	pool             *x509.CertPool
	verdict          engine.Code
	offer            engine.Code
	queueBytes       int
	connectionLimit  int
	handshakeLimit   int
	handshakeTimeout time.Duration
	probe            Limits
	relay            RelayLimits
	dialerCode       engine.Code
}

// capture is one assembled pipeline plus everything a test observes about it.
type capture struct {
	pipeline *Pipeline
	router   *routerStub
	platform *keylogPlatform
	dialer   *dialerStub
	sink     *secrets.Sink
	budget   *engine.Budget
	events   *engine.Queue
	store    *certstore.Store
	pool     *x509.CertPool
	drained  []engine.Event
	opened   int
}

func newCapture(t *testing.T, tune ...func(*captureOptions)) *capture {
	t.Helper()
	store, pool := testCA(t)
	options := captureOptions{
		// The default decision is what an out-of-scope connection gets: it is
		// forwarded untouched. Tests that want interception say so.
		route:            Route{Reason: "no_include_match"},
		store:            store,
		pool:             pool,
		verdict:          engine.OK,
		handshakeTimeout: 2 * time.Second,
	}
	for _, apply := range tune {
		apply(&options)
	}
	router := &routerStub{route: options.route, code: options.routeCode}
	platform := &keylogPlatform{verdict: options.verdict, offer: options.offer}
	sink, code := secrets.NewSink("capture-one", &gateStub{platform: platform}, secrets.Limits{QueueBytes: options.queueBytes})
	if code != engine.OK {
		t.Fatalf("building the secret sink: %v", code)
	}
	t.Cleanup(func() { sink.Drain(context.Background()) })
	budget, code := engine.NewBudget(engine.Limits{Connections: options.connectionLimit, Handshakes: options.handshakeLimit})
	if code != engine.OK {
		t.Fatalf("building the connection budget: %v", code)
	}
	events, code := engine.NewQueue(0)
	if code != engine.OK {
		t.Fatalf("building the event queue: %v", code)
	}
	dialer := &dialerStub{code: options.dialerCode}
	pipeline, code := NewPipeline(Options{
		CaptureID:            "capture-one",
		Policy:               router,
		Leaves:               options.store,
		Gate:                 &gateStub{platform: platform},
		Dialer:               dialer,
		Secrets:              sink,
		Budget:               budget,
		Events:               events,
		ProbeLimits:          options.probe,
		HandshakeTimeout:     options.handshakeTimeout,
		RelayLimits:          options.relay,
		SecretsSettleTimeout: DefaultSecretsSettleTimeout,
	})
	if code != engine.OK {
		t.Fatalf("building the pipeline: %v", code)
	}
	return &capture{pipeline: pipeline, router: router, platform: platform, dialer: dialer,
		sink: sink, budget: budget, events: events, store: options.store, pool: options.pool}
}

// start opens one connection through the pipeline the way the gateway hop does:
// the client side is a real socket the test talks on, and the origin side is a
// real TCP connection to the destination, opened before the probe exactly as the
// gateway's dialer opens it.
func (c *capture) start(t *testing.T, destination netip.AddrPort) (net.Conn, <-chan ConnectionResult) {
	t.Helper()
	return c.startContext(t, context.Background(), destination)
}

func (c *capture) startContext(t *testing.T, ctx context.Context, destination netip.AddrPort) (net.Conn, <-chan ConnectionResult) {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening for the application: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	app, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("dialing the local hop: %v", err)
	}
	t.Cleanup(func() { _ = app.Close() })
	downstream, err := listener.Accept()
	if err != nil {
		t.Fatalf("accepting the application: %v", err)
	}
	upstream, err := net.Dial("tcp", destination.String())
	if err != nil {
		t.Fatalf("dialing the origin: %v", err)
	}
	results := make(chan ConnectionResult, 1)
	// One identifier per connection: a capture's events are keyed by it, so a
	// test that opens two connections must open two of them.
	c.opened++
	connectionID := "connection-" + strconv.Itoa(c.opened)
	go func() {
		results <- c.pipeline.Handle(ctx, Request{
			ConnectionID:      connectionID,
			Destination:       destination,
			NetworkGeneration: 7,
			Downstream:        downstream,
			Upstream:          upstream,
		})
	}()
	return app, results
}

// published returns every event the capture queued, in order. The queue is
// drained once and remembered, so a test can ask several questions about the
// same connection's events without removing them from the queue itself.
func (c *capture) published() []engine.Event {
	if c.drained == nil {
		c.drained = c.events.Poll(engine.MaxPollEvents)
	}
	return c.drained
}

func (c *capture) phases() []engine.Phase {
	events := c.published()
	out := make([]engine.Phase, 0, len(events))
	for _, event := range events {
		out = append(out, event.Phase)
	}
	return out
}

// reasonOf returns the decision reason an event of that phase carried, and
// reports whether such an event was published at all.
func (c *capture) reasonOf(phase engine.Phase) (string, bool) {
	for _, event := range c.published() {
		if event.Phase == phase {
			return event.DecisionReason, true
		}
	}
	return "", false
}

func await(t *testing.T, results <-chan ConnectionResult) ConnectionResult {
	t.Helper()
	select {
	case result := <-results:
		return result
	case <-time.After(10 * time.Second):
		t.Fatal("the connection never ended")
		return ConnectionResult{}
	}
}

func assertPhases(t *testing.T, got []engine.Phase, want ...engine.Phase) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("phases = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("phases = %v, want %v", got, want)
		}
	}
}

// rawOrigin is a plain TCP listener that records every byte it is sent and, when
// asked, echoes them back. It is the origin for the connections this engine must
// not touch: what it received is the evidence that the proxy forwarded the
// application's bytes unchanged.
type rawOrigin struct {
	listener net.Listener
	echo     bool

	mu          sync.Mutex
	received    bytes.Buffer
	connections int
}

func newRawOrigin(t *testing.T, echo bool) *rawOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening as the origin: %v", err)
	}
	o := &rawOrigin{listener: listener, echo: echo}
	t.Cleanup(func() { _ = listener.Close() })
	go o.accept()
	return o
}

func (o *rawOrigin) accept() {
	for {
		conn, err := o.listener.Accept()
		if err != nil {
			return
		}
		o.mu.Lock()
		o.connections++
		o.mu.Unlock()
		go o.serve(conn)
	}
}

func (o *rawOrigin) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	buffer := make([]byte, 4096)
	for {
		n, err := conn.Read(buffer)
		if n > 0 {
			o.mu.Lock()
			_, _ = o.received.Write(buffer[:n])
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

func (o *rawOrigin) destination() netip.AddrPort {
	return netip.MustParseAddrPort(o.listener.Addr().String())
}

func (o *rawOrigin) bytesReceived() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]byte(nil), o.received.Bytes()...)
}

func (o *rawOrigin) accepted() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.connections
}

// waitReceived waits until the origin has read at least want bytes, so a test
// asserts on bytes that arrived rather than on a sleep.
func (o *rawOrigin) waitReceived(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if len(o.bytesReceived()) >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the origin received %d bytes, want at least %d", len(o.bytesReceived()), want)
}

// destination and protocolCount are the two things the TLS origin does not
// already expose: where it is listening, and how many handshakes it completed.
func (o *origin) destination() netip.AddrPort {
	return netip.MustParseAddrPort(o.address())
}

func (o *origin) protocolCount() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return len(o.protocols)
}

// tlsOriginPool is the trust a test's application needs to reach the origin
// directly. It is how a pass-through case proves the stream was untouched: the
// application's own handshake completed against the origin's own certificate.
func tlsOriginPool(leaf tls.Certificate) *x509.CertPool {
	pool := x509.NewCertPool()
	pool.AddCert(leaf.Leaf)
	return pool
}

// closeTLS ends an application's TLS session the way a TLS client does: a
// close_notify, then the peer's own close_notify, then the socket. A client that
// slams the socket shut instead makes the proxy's reverse close_notify fail on a
// socket nobody is reading any more, which is a fact about that client rather
// than about the proxy, and would blur what these cases assert.
func closeTLS(t *testing.T, conn *tls.Conn) {
	t.Helper()
	_ = conn.CloseWrite()
	_ = conn.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, conn)
	_ = conn.Close()
}

// readExactly reads want bytes from the application's socket.
func readExactly(t *testing.T, conn net.Conn, want int) []byte {
	t.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("setting a read deadline: %v", err)
	}
	defer func() { _ = conn.SetReadDeadline(time.Time{}) }()
	payload := make([]byte, want)
	if _, err := io.ReadFull(conn, payload); err != nil {
		t.Fatalf("reading %d bytes from the application: %v", want, err)
	}
	return payload
}

// TestANonTLSConnectionIsForwardedByteForByte is the first half of the card's
// first acceptance case: a stream that is not TLS reaches the origin with
// exactly the bytes the application sent, including the ones the classifier read
// while it was deciding.
func TestANonTLSConnectionIsForwardedByteForByte(t *testing.T) {
	capture := newCapture(t)
	origin := newRawOrigin(t, true)
	payload := []byte("GET /plain HTTP/1.1\r\nHost: example.test\r\n\r\n")

	app, results := capture.start(t, origin.destination())
	if _, err := app.Write(payload); err != nil {
		t.Fatalf("writing the application's request: %v", err)
	}
	origin.waitReceived(t, len(payload))
	answer := readExactly(t, app, len(payload))
	if !bytes.Equal(answer, payload) {
		t.Fatalf("the application received %d bytes, want its own request echoed", len(answer))
	}
	if !bytes.Equal(origin.bytesReceived(), payload) {
		t.Fatalf("the origin received %q, want the application's own bytes", origin.bytesReceived())
	}
	if err := app.Close(); err != nil {
		t.Fatalf("closing the application: %v", err)
	}
	result := await(t, results)
	if result.Code != engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want a clean pass-through", result)
	}
	assertPhases(t, capture.phases(),
		engine.PhaseAccepted, engine.PhaseSniffing, engine.PhasePassthrough, engine.PhaseClosed)
	if usage := capture.budget.Usage(); usage.Connections != 0 || usage.Handshakes != 0 {
		t.Fatalf("budgets after the connection: %+v", usage)
	}
	if capture.router.attempts() != 1 {
		t.Fatalf("the decision maker was asked %d times", capture.router.attempts())
	}
	if verdict, _, _, destination, application := capture.router.observed(); verdict != VerdictNotTLS ||
		destination != origin.destination() || application != "" {
		t.Fatalf("the decision maker saw the verdict %v for %v", verdict, destination)
	}
}

// TestAProbeThatRunsOutOfBudgetForwardsEveryByte pins the other half: a prefix
// the classifier could not decide — here a record whose body never arrives — is
// still forwarded verbatim, from its first byte, once the probe gives up.
func TestAProbeThatRunsOutOfBudgetForwardsEveryByte(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		// A probe that gives up quickly, so the case is about the prefix rather
		// than about the three seconds the default budget spends.
		o.probe = Limits{Timeout: 150 * time.Millisecond}
	})
	origin := newRawOrigin(t, false)
	app, results := capture.start(t, origin.destination())
	head := []byte{0x16, 0x03, 0x01, 0x40, 0x00}
	if _, err := app.Write(head); err != nil {
		t.Fatalf("writing the truncated record: %v", err)
	}
	time.Sleep(300 * time.Millisecond)
	rest := []byte("the rest of the stream, never part of a handshake")
	if _, err := app.Write(rest); err != nil {
		t.Fatalf("writing the rest of the stream: %v", err)
	}
	want := append(append([]byte(nil), head...), rest...)
	origin.waitReceived(t, len(want))
	if !bytes.Equal(origin.bytesReceived(), want) {
		t.Fatalf("the origin received %d bytes, want the %d written", len(origin.bytesReceived()), len(want))
	}
	_ = app.Close()
	result := await(t, results)
	if result.Code != engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want a clean pass-through", result)
	}
	if verdict, _, _, _, _ := capture.router.observed(); verdict != VerdictIncomplete {
		t.Fatalf("verdict = %v, want an undecided prefix", verdict)
	}
	assertPhases(t, capture.phases(),
		engine.PhaseAccepted, engine.PhaseSniffing, engine.PhasePassthrough, engine.PhaseClosed)
}

// TestABypassForwardsTheApplicationsOwnHandshake is the card's "rule bypass"
// case, with the strongest evidence available: a bypassed connection carries a
// real TLS handshake from the application to the origin, so every byte the
// classifier read was reproduced exactly. Nothing was terminated, and the
// capture CA issued no leaf.
func TestABypassForwardsTheApplicationsOwnHandshake(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) { o.route = Route{Reason: "bypass_rule"} })
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOrigin(t, leaf, tls.VersionTLS13, []string{"h2"})
	app, results := capture.start(t, origin.destination())

	client := tls.Client(app, &tls.Config{
		RootCAs:    tlsOriginPool(leaf),
		ServerName: "example.test",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("the application's own handshake through the bypass: %v", err)
	}
	if got := client.ConnectionState().NegotiatedProtocol; got != "h2" {
		t.Fatalf("negotiated protocol = %q, want the origin's own answer", got)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("writing through the bypass: %v", err)
	}
	origin.waitReceived(t, 4)
	if got := string(readExactly(t, client, 4)); got != "ping" {
		t.Fatalf("the answer = %q, want the origin's echo", got)
	}
	closeTLS(t, client)
	result := await(t, results)
	if result.Code != engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want a clean pass-through", result)
	}
	if origin.seenSNI() != "example.test" || origin.seenProtocol() != "h2" {
		t.Fatalf("the origin saw SNI %q and protocol %q", origin.seenSNI(), origin.seenProtocol())
	}
	if issued := capture.store.Stats().Issued; issued != 0 {
		t.Fatalf("the capture CA issued %d leaves for a bypassed connection", issued)
	}
	if capture.router.attempts() != 1 {
		t.Fatalf("the decision maker was asked %d times", capture.router.attempts())
	}
	assertPhases(t, capture.phases(),
		engine.PhaseAccepted, engine.PhaseSniffing, engine.PhasePassthrough, engine.PhaseClosed)
	if reason, ok := capture.reasonOf(engine.PhasePassthrough); !ok || reason != "bypass_rule" {
		t.Fatalf("the pass-through event carried the reason %q (present: %v)", reason, ok)
	}
}

// TestAnInterceptedConnectionCarriesApplicationDataBothWays is the state
// machine's normal path: both TLS sides terminated, one application protocol,
// the application's request reaching the origin exactly once, and the capture's
// events and counters describing exactly that.
func TestAnInterceptedConnectionCarriesApplicationDataBothWays(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
	})
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOrigin(t, leaf, tls.VersionTLS13, []string{"h2"})
	app, results := capture.start(t, origin.destination())

	client := tls.Client(app, &tls.Config{
		RootCAs:    capture.pool,
		ServerName: "example.test",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("the application's handshake with the proxy: %v", err)
	}
	request := "POST /pay"
	if _, err := client.Write([]byte(request)); err != nil {
		t.Fatalf("writing the application's request: %v", err)
	}
	origin.waitReceived(t, len(request))
	if got := string(readExactly(t, client, len(request))); got != request {
		t.Fatalf("the answer = %q, want the origin's echo", got)
	}
	// Exactly one request reached the origin: a proxy that replayed the
	// application's data would show up here as more bytes than were written.
	if got := origin.received(); got != len(request) {
		t.Fatalf("the origin read %d application bytes, want exactly one request", got)
	}
	if origin.seenSNI() != "example.test" || origin.seenProtocol() != "h2" {
		t.Fatalf("the origin saw SNI %q and protocol %q", origin.seenSNI(), origin.seenProtocol())
	}
	if got := capture.platform.verifiedIdentity(); got != "example.test" {
		t.Fatalf("the upstream destination was verified as %q", got)
	}
	closeTLS(t, client)
	result := await(t, results)
	if result.Code != engine.OK || !result.Intercepted {
		t.Fatalf("result = %+v, want a clean intercepted connection", result)
	}
	if result.BytesToUpstream != int64(len(request)) {
		t.Fatalf("bytes to upstream = %d, want the application's request", result.BytesToUpstream)
	}
	assertPhases(t, capture.phases(),
		engine.PhaseAccepted, engine.PhaseSniffing, engine.PhaseUpstreamHandshake,
		engine.PhaseDownstreamHandshake, engine.PhaseRelaying, engine.PhaseClosed)

	terminals := capture.events.Terminals()
	if len(terminals) != 1 {
		t.Fatalf("terminal events = %d, want 1", len(terminals))
	}
	terminal := terminals[0]
	if terminal.Phase != engine.PhaseClosed || terminal.SNI != "example.test" || terminal.ALPN != "h2" {
		t.Fatalf("terminal event = %+v", terminal)
	}
	if terminal.DownstreamTLS != "TLS 1.3" || terminal.UpstreamTLS != "TLS 1.3" {
		t.Fatalf("terminal event versions = %q/%q", terminal.DownstreamTLS, terminal.UpstreamTLS)
	}
	if terminal.UpstreamCertificateSHA256 == "" || terminal.DownstreamClientRandom == "" {
		t.Fatal("the terminal event carries no certificate digest or client random")
	}
	if terminal.SecretRecordsAccepted == 0 || terminal.SecretRecordsPersisted != terminal.SecretRecordsAccepted ||
		!terminal.SecretsComplete {
		t.Fatalf("terminal event secrets = %d/%d complete=%v",
			terminal.SecretRecordsAccepted, terminal.SecretRecordsPersisted, terminal.SecretsComplete)
	}
	if offered := capture.platform.offered(); offered != int(terminal.SecretRecordsAccepted) {
		t.Fatalf("the platform accepted %d records, the event reports %d", offered, terminal.SecretRecordsAccepted)
	}
	stats := capture.events.Stats()
	if stats.ConnectionsProxied != 1 || stats.ConnectionsPassthrough != 0 || stats.HandshakesFailed != 0 {
		t.Fatalf("capture stats = %+v", stats)
	}
	if usage := capture.budget.Usage(); usage.Connections != 0 || usage.Handshakes != 0 {
		t.Fatalf("budgets after the connection: %+v", usage)
	}
	if calls := capture.dialer.calls(); calls != 0 {
		t.Fatalf("the fallback dialer was called %d times by a successful connection", calls)
	}
}

// TestACertificateRejectionEndsTheConnectionWithoutAFallback is the card's
// "certificate rejection" case. The origin's certificate is refused by the
// platform, so the connection ends: no second socket is opened, the proxy's TLS
// never reaches the client, and nothing is replayed to make the failure look
// like a success.
func TestACertificateRejectionEndsTheConnectionWithoutAFallback(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
		o.verdict = engine.UpstreamCertInvalid
	})
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOrigin(t, leaf, tls.VersionTLS13, nil)
	app, results := capture.start(t, origin.destination())

	client := tls.Client(app, &tls.Config{
		RootCAs:    capture.pool,
		ServerName: "example.test",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	// The application must be released rather than left waiting on a hop that
	// has nothing behind it. Its own handshake can only fail: the proxy never
	// speaks TLS to it.
	if err := client.Handshake(); err == nil {
		t.Fatal("the application completed a handshake with a rejected origin")
	}
	_ = client.Close()
	result := await(t, results)
	if result.Code != engine.UpstreamCertInvalid || result.Intercepted {
		t.Fatalf("result = %+v, want an upstream certificate failure", result)
	}
	if calls := capture.dialer.calls(); calls != 0 {
		t.Fatalf("the fallback dialer was called %d times for a rejected certificate", calls)
	}
	if got := origin.received(); got != 0 {
		t.Fatalf("the origin read %d application bytes from a failed attempt", got)
	}
	terminals := capture.events.Terminals()
	if len(terminals) != 1 || terminals[0].Phase != engine.PhaseFailed {
		t.Fatalf("terminal events = %+v, want one FAILED", terminals)
	}
	if terminals[0].ErrorCode != "UPSTREAM_CERT_INVALID" ||
		terminals[0].DecisionReason != string(ReasonUpstreamVerification) {
		t.Fatalf("terminal event = %+v", terminals[0])
	}
	for _, phase := range capture.phases() {
		if phase == engine.PhasePassthrough || phase == engine.PhaseRelaying {
			t.Fatalf("a rejected certificate published %s", phase)
		}
	}
	if failed := capture.events.Stats().HandshakesFailed; failed != 1 {
		t.Fatalf("handshake failures = %d, want 1", failed)
	}
}

// TestASecretFailureTurnsNewCandidatesIntoPassthrough is the card's "secret
// failure" case: once the capture cannot save records any more (§8.2), a new
// candidate is forwarded untouched and says why, while the connection whose
// records were lost reports itself as incomplete.
func TestASecretFailureTurnsNewCandidatesIntoPassthrough(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
		// One byte of secret queue: the first record a connection produces
		// cannot be queued, which is §8.2's "queue full" without a fake.
		o.queueBytes = 1
	})
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)

	// First connection: intercepted, and its records are lost.
	first := newOrigin(t, leaf, tls.VersionTLS13, nil)
	app, results := capture.start(t, first.destination())
	client := tls.Client(app, &tls.Config{
		RootCAs: capture.pool, ServerName: "example.test",
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("the first connection's handshake: %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("writing on the first connection: %v", err)
	}
	first.waitReceived(t, 4)
	closeTLS(t, client)
	firstResult := await(t, results)
	if !firstResult.Intercepted || firstResult.Code != engine.OK {
		t.Fatalf("first result = %+v, want an intercepted connection", firstResult)
	}
	terminals := capture.events.Terminals()
	if len(terminals) != 1 {
		t.Fatalf("terminal events = %+v, want one", terminals)
	}
	if terminals[0].SecretsComplete || terminals[0].SecretRecordsAccepted == 0 || terminals[0].SecretRecordsPersisted != 0 {
		t.Fatalf("terminal event secrets = %d/%d complete=%v, want a reported loss",
			terminals[0].SecretRecordsAccepted, terminals[0].SecretRecordsPersisted, terminals[0].SecretsComplete)
	}
	if capture.sink.AcceptingNewInterception() {
		t.Fatal("the capture still accepts new interception after losing a record")
	}

	// Second connection: the same decision, but the capture must not start
	// another interception it cannot decrypt. Its bytes still reach the origin
	// unchanged, which the application's own handshake proves.
	second := newOrigin(t, leaf, tls.VersionTLS13, []string{"http/1.1"})
	app2, results2 := capture.start(t, second.destination())
	client2 := tls.Client(app2, &tls.Config{
		RootCAs: tlsOriginPool(leaf), ServerName: "example.test",
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err := client2.Handshake(); err != nil {
		t.Fatalf("the second connection's own handshake: %v", err)
	}
	if _, err := client2.Write([]byte("ping")); err != nil {
		t.Fatalf("writing on the second connection: %v", err)
	}
	second.waitReceived(t, 4)
	closeTLS(t, client2)
	secondResult := await(t, results2)
	if secondResult.Intercepted || secondResult.Code != engine.OK {
		t.Fatalf("second result = %+v, want a pass-through", secondResult)
	}
	if got := second.seenSNI(); got != "example.test" {
		t.Fatalf("the second origin saw SNI %q", got)
	}
	stats := capture.events.Stats()
	if stats.ConnectionsProxied != 1 || stats.ConnectionsPassthrough != 1 || stats.SecretsIncomplete != 1 {
		t.Fatalf("capture stats = %+v", stats)
	}
	if reason, ok := capture.reasonOf(engine.PhasePassthrough); !ok || reason != "secrets_incomplete" {
		t.Fatalf("the pass-through event carried the reason %q (present: %v)", reason, ok)
	}
}

// TestALeafThatCannotBeIssuedFallsBackOnAFreshSocket is §6.1's fallback, and the
// only path that needs the redial: the upstream leg completed, so the origin
// socket has carried this proxy's ClientHello and can never carry the
// application's. The socket is replaced rather than reused, and the
// application's own handshake then completes against the origin — proof that its
// bytes were forwarded exactly, once.
func TestALeafThatCannotBeIssuedFallsBackOnAFreshSocket(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
		// A store with no CA: the upstream handshake succeeds and issuing the
		// downstream leaf is what fails, which is the one failure a connection
		// that has not been spoken to can still recover from.
		o.store = certstore.NewStore(certstore.DefaultCapacity)
	})
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOrigin(t, leaf, tls.VersionTLS13, []string{"http/1.1"})
	app, results := capture.start(t, origin.destination())

	client := tls.Client(app, &tls.Config{
		RootCAs:    tlsOriginPool(leaf),
		ServerName: "example.test",
		NextProtos: []string{"http/1.1"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("the application's handshake after the fallback: %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("writing after the fallback: %v", err)
	}
	origin.waitReceived(t, 4)
	if got := string(readExactly(t, client, 4)); got != "ping" {
		t.Fatalf("the answer = %q", got)
	}
	// The application's request reached the origin once: the redial replaced the
	// socket, it did not replay the application's data.
	if got := origin.received(); got != 4 {
		t.Fatalf("the origin read %d application bytes, want exactly one request", got)
	}
	// Two handshakes reached the origin: the proxy's (TLS B, which the fallback
	// abandoned) and the application's own. That is the redial, seen from the
	// only side that can see it.
	if completed := origin.protocolCount(); completed != 2 {
		t.Fatalf("the origin completed %d handshakes, want the proxy's then the application's", completed)
	}
	closeTLS(t, client)
	result := await(t, results)
	if result.Code != engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want a clean pass-through", result)
	}
	if calls := capture.dialer.calls(); calls != 1 {
		t.Fatalf("the fallback dialer was called %d times, want 1", calls)
	}
	assertPhases(t, capture.phases(),
		engine.PhaseAccepted, engine.PhaseSniffing, engine.PhaseUpstreamHandshake,
		engine.PhasePassthrough, engine.PhaseClosed)
	terminals := capture.events.Terminals()
	if len(terminals) != 1 || terminals[0].Phase != engine.PhaseClosed {
		t.Fatalf("terminal events = %+v, want one CLOSED", terminals)
	}
	if terminals[0].DecisionReason != "" {
		t.Fatalf("a clean terminal event carried the reason %q", terminals[0].DecisionReason)
	}
	if reason, ok := capture.reasonOf(engine.PhasePassthrough); !ok ||
		reason != "fallback_downstream_leaf_unavailable" {
		t.Fatalf("the pass-through event carried the reason %q (present: %v)", reason, ok)
	}
}

// TestAFallbackWhoseRedialFailsEndsTheConnection is the card's "upstream redial
// error" case: the replacement socket cannot be opened, so the connection ends
// with that code. The application is released, no pass-through is published, and
// the client's bytes went nowhere — a failed fallback is not a silent downgrade.
func TestAFallbackWhoseRedialFailsEndsTheConnection(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
		o.store = certstore.NewStore(certstore.DefaultCapacity)
		o.dialerCode = engine.ProtectFailed
	})
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOrigin(t, leaf, tls.VersionTLS13, nil)
	app, results := capture.start(t, origin.destination())

	client := tls.Client(app, &tls.Config{
		RootCAs: capture.pool, ServerName: "example.test",
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err := client.Handshake(); err == nil {
		t.Fatal("the application completed a handshake the engine could not complete")
	}
	_ = client.Close()
	result := await(t, results)
	if result.Code != engine.ProtectFailed || result.Intercepted {
		t.Fatalf("result = %+v, want the redial's failure", result)
	}
	if calls := capture.dialer.calls(); calls != 1 {
		t.Fatalf("the fallback dialer was called %d times, want 1", calls)
	}
	terminals := capture.events.Terminals()
	if len(terminals) != 1 {
		t.Fatalf("terminal events = %+v, want one", terminals)
	}
	if terminals[0].Phase != engine.PhaseFailed || terminals[0].ErrorCode != "PROTECT_FAILED" ||
		terminals[0].DecisionReason != "fallback_redial_failed" {
		t.Fatalf("terminal event = %+v", terminals[0])
	}
	for _, phase := range capture.phases() {
		if phase == engine.PhasePassthrough {
			t.Fatal("a failed fallback published PASSTHROUGH")
		}
	}
	if got := origin.received(); got != 0 {
		t.Fatalf("the origin read %d application bytes after a failed redial", got)
	}
}

// TestAHalfFinishedHandshakeEndsTheConnection is the card's "half handshake"
// case: an origin that accepts the socket and never answers. The upstream budget
// ends the attempt, both sides are released, and nothing is replayed.
func TestAHalfFinishedHandshakeEndsTheConnection(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
		o.handshakeTimeout = 250 * time.Millisecond
	})
	silent := newSilentOrigin(t)
	app, results := capture.start(t, netip.MustParseAddrPort(silent.address()))

	client := tls.Client(app, &tls.Config{
		RootCAs: capture.pool, ServerName: "example.test",
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err := client.Handshake(); err == nil {
		t.Fatal("the application completed a handshake with an origin that never answered")
	}
	_ = client.Close()
	result := await(t, results)
	if result.Code == engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want a failed attempt", result)
	}
	if calls := capture.dialer.calls(); calls != 0 {
		t.Fatalf("the fallback dialer was called %d times", calls)
	}
	silent.waitReleased(t)
	terminals := capture.events.Terminals()
	if len(terminals) != 1 || terminals[0].Phase != engine.PhaseFailed {
		t.Fatalf("terminal events = %+v", terminals)
	}
	if terminals[0].DecisionReason != string(ReasonUpstreamTimeout) {
		t.Fatalf("the terminal reason = %q, want the upstream budget", terminals[0].DecisionReason)
	}
	// The downstream phase must not appear: the upstream leg never finished, so
	// there was no second leg to start.
	for _, phase := range capture.phases() {
		if phase == engine.PhaseDownstreamHandshake || phase == engine.PhaseRelaying {
			t.Fatalf("a half-finished handshake published %s", phase)
		}
	}
}

// TestTheConnectionBudgetRefusalForwardsUntouched is the card's capacity case: a
// full connection budget forwards the connection as ordinary traffic and creates
// no proxy state, so the device stays online and the capture stays honest about
// what it did not decrypt.
func TestTheConnectionBudgetRefusalForwardsUntouched(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) { o.connectionLimit = 1 })
	held, code := capture.budget.Acquire(engine.ConnectionSlot)
	if code != engine.OK {
		t.Fatalf("holding the only connection slot: %v", code)
	}
	defer held.Release()
	origin := newRawOrigin(t, false)
	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	app, results := capture.start(t, origin.destination())
	if _, err := app.Write(payload); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	origin.waitReceived(t, len(payload))
	if !bytes.Equal(origin.bytesReceived(), payload) {
		t.Fatal("a refused connection did not reach the origin unchanged")
	}
	_ = app.Close()
	result := await(t, results)
	if result.Code != engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want the refusal to be a pass-through", result)
	}
	assertPhases(t, capture.phases(), engine.PhaseAccepted, engine.PhasePassthrough, engine.PhaseClosed)
	if capture.router.attempts() != 0 {
		t.Fatal("a refused connection was probed")
	}
	if reason, ok := capture.reasonOf(engine.PhasePassthrough); !ok || reason != "connection_capacity_exceeded" {
		t.Fatalf("the pass-through event carried the reason %q (present: %v)", reason, ok)
	}
	// The refusal is not a handshake failure and not a second attempt.
	if failed := capture.events.Stats().HandshakesFailed; failed != 0 || capture.dialer.calls() != 0 {
		t.Fatalf("handshake failures = %d, fallback dials = %d", failed, capture.dialer.calls())
	}
}

// TestTheHandshakeBudgetRefusalForwardsUntouched is the other capacity case: a
// candidate that cannot get a handshake slot is forwarded before any proxy TLS
// exists, and its own handshake still completes against the origin.
func TestTheHandshakeBudgetRefusalForwardsUntouched(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
		o.handshakeLimit = 1
	})
	held, code := capture.budget.Acquire(engine.HandshakeSlot)
	if code != engine.OK {
		t.Fatalf("holding the only handshake slot: %v", code)
	}
	defer held.Release()
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOrigin(t, leaf, tls.VersionTLS13, []string{"h2"})
	app, results := capture.start(t, origin.destination())
	client := tls.Client(app, &tls.Config{
		RootCAs: tlsOriginPool(leaf), ServerName: "example.test",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
	})
	if err := client.Handshake(); err != nil {
		t.Fatalf("the application's own handshake after the refusal: %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("writing after the refusal: %v", err)
	}
	origin.waitReceived(t, 4)
	closeTLS(t, client)
	result := await(t, results)
	if result.Code != engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want the refusal to be a pass-through", result)
	}
	assertPhases(t, capture.phases(),
		engine.PhaseAccepted, engine.PhaseSniffing, engine.PhasePassthrough, engine.PhaseClosed)
	if reason, ok := capture.reasonOf(engine.PhasePassthrough); !ok || reason != "handshake_capacity_exceeded" {
		t.Fatalf("the pass-through event carried the reason %q (present: %v)", reason, ok)
	}
	if issued := capture.store.Stats().Issued; issued != 0 || capture.dialer.calls() != 0 {
		t.Fatalf("a refused candidate issued %d leaves and dialed %d times", issued, capture.dialer.calls())
	}
	if refused := capture.budget.Usage().RefusedHandshakes; refused != 1 {
		t.Fatalf("refused handshakes = %d, want 1", refused)
	}
}

// TestADecisionThatContradictsItselfEndsTheConnection pins the one outcome that
// is a failure rather than a classification: a decision maker that rejects its
// own request. The connection is closed instead of guessed at.
func TestADecisionThatContradictsItselfEndsTheConnection(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) { o.routeCode = engine.InvalidArgument })
	origin := newRawOrigin(t, false)
	app, results := capture.start(t, origin.destination())
	if _, err := app.Write([]byte{0x16, 0x03, 0x01, 0x00, 0x05}); err != nil {
		t.Fatalf("writing the record: %v", err)
	}
	_ = app.Close()
	result := await(t, results)
	if result.Code != engine.InvalidArgument || result.Intercepted {
		t.Fatalf("result = %+v, want the rejected decision", result)
	}
	terminals := capture.events.Terminals()
	if len(terminals) != 1 || terminals[0].Phase != engine.PhaseFailed ||
		terminals[0].DecisionReason != "decision_rejected" ||
		terminals[0].ErrorCode != "INVALID_ARGUMENT" {
		t.Fatalf("terminal events = %+v", terminals)
	}
}

// TestAnUnusableRequestPublishesNothing pins the boundary this file refuses to
// guess about: a request whose destination or identifiers cannot be trusted is
// rejected without an event, because an event would have to name a connection
// this pipeline cannot describe.
func TestAnUnusableRequestPublishesNothing(t *testing.T) {
	capture := newCapture(t)
	left, right := net.Pipe()
	defer func() { _ = left.Close(); _ = right.Close() }()
	destination := netip.MustParseAddrPort("192.0.2.1:443")
	cases := map[string]Request{
		"missing identifiers": {Destination: destination, Downstream: left, Upstream: right},
		"unspecified address": {ConnectionID: "connection-one", Destination: netip.MustParseAddrPort("0.0.0.0:443"), Downstream: left, Upstream: right},
		"zero port":           {ConnectionID: "connection-one", Destination: netip.MustParseAddrPort("192.0.2.1:0"), Downstream: left, Upstream: right},
		"no transports":       {ConnectionID: "connection-one", Destination: destination},
		"negative generation": {ConnectionID: "connection-one", Destination: destination, NetworkGeneration: -1, Downstream: left, Upstream: right},
	}
	for name, request := range cases {
		if result := capture.pipeline.Handle(context.Background(), request); result.Code != engine.InvalidArgument {
			t.Fatalf("%s: result = %+v, want INVALID_ARGUMENT", name, result)
		}
	}
	if events := capture.published(); len(events) != 0 {
		t.Fatalf("an unusable request published %d events", len(events))
	}
}

// TestPipelineAssemblyIsValidated pins what NewPipeline refuses: a run that is
// missing one of its parts, an identifier the events cannot carry, and a budget
// above its ceiling. Nothing here opens a socket, so a refusal costs nothing.
func TestPipelineAssemblyIsValidated(t *testing.T) {
	capture := newCapture(t)
	base := Options{
		CaptureID: "capture-one",
		Policy:    capture.router,
		Leaves:    capture.store,
		Gate:      &gateStub{platform: capture.platform},
		Dialer:    capture.dialer,
		Secrets:   capture.sink,
		Budget:    capture.budget,
		Events:    capture.events,
	}
	if _, code := NewPipeline(base); code != engine.OK {
		t.Fatalf("a complete pipeline was rejected with %v", code)
	}
	notReady := map[string]func(*Options){
		"no policy":  func(o *Options) { o.Policy = nil },
		"no dialer":  func(o *Options) { o.Dialer = nil },
		"no secrets": func(o *Options) { o.Secrets = nil },
		"no budget":  func(o *Options) { o.Budget = nil },
		"no events":  func(o *Options) { o.Events = nil },
		"no CA":      func(o *Options) { o.Leaves = nil },
		"no gate":    func(o *Options) { o.Gate = nil },
	}
	for name, mutate := range notReady {
		options := base
		mutate(&options)
		if _, code := NewPipeline(options); code != engine.NotReady {
			t.Fatalf("%s: code = %v, want NOT_READY", name, code)
		}
	}
	invalid := map[string]func(*Options){
		"bad capture": func(o *Options) { o.CaptureID = "not a capture id" },
		"settle above the ceiling": func(o *Options) {
			o.SecretsSettleTimeout = MaxSecretsSettleTimeout + time.Second
		},
		"negative settle":                func(o *Options) { o.SecretsSettleTimeout = -time.Second },
		"relay buffer above the ceiling": func(o *Options) { o.RelayLimits = RelayLimits{BufferBytes: MaxRelayBufferBytes + 1} },
		"probe budget above the ceiling": func(o *Options) { o.HandshakeTimeout = MaxHandshakeTimeout + time.Second },
	}
	for name, mutate := range invalid {
		options := base
		mutate(&options)
		if _, code := NewPipeline(options); code != engine.InvalidArgument {
			t.Fatalf("%s: code = %v, want INVALID_ARGUMENT", name, code)
		}
	}
}

// TestTheStateMachineNeverInventsASecondTerminalState pins C04's "one terminal
// state per connection" at the producer: a connection that has ended stays
// ended, whatever a later phase would have said.
func TestTheStateMachineNeverInventsASecondTerminalState(t *testing.T) {
	capture := newCapture(t)
	state := &connState{pipeline: capture.pipeline, request: Request{
		ConnectionID:      "connection-one",
		Destination:       netip.MustParseAddrPort("192.0.2.1:443"),
		NetworkGeneration: 3,
	}}
	state.emit(engine.PhaseAccepted, "", engine.OK)
	state.emit(engine.PhaseSniffing, "", engine.OK)
	closed := state.finish(engine.OK, "")
	state.emit(engine.PhaseFailed, "too_late", engine.IOError)
	state.finish(engine.IOError, "too_late")

	if closed.Phase != engine.PhaseClosed || closed.Code != engine.OK || closed.Intercepted {
		t.Fatalf("result = %+v", closed)
	}
	events := capture.published()
	if len(events) != 3 {
		t.Fatalf("published %d events, want ACCEPTED, SNIFFING and one terminal", len(events))
	}
	if events[0].Phase != engine.PhaseAccepted || events[1].Phase != engine.PhaseSniffing ||
		events[2].Phase != engine.PhaseClosed {
		t.Fatalf("published %v", []engine.Phase{events[0].Phase, events[1].Phase, events[2].Phase})
	}
	if terminals := capture.events.Terminals(); len(terminals) != 1 || terminals[0].Phase != engine.PhaseClosed {
		t.Fatalf("terminal states = %+v, want exactly one CLOSED", terminals)
	}
	if suppressed := capture.events.Stats().TerminalsSuppressed; suppressed != 0 {
		t.Fatalf("the queue suppressed %d terminal states, want the producer to have refused them", suppressed)
	}
}

func TestBorrowedConnectionLeaseReusedAndForeignLeasesRejected(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) { o.connectionLimit = 1 })
	lease, _ := capture.budget.Acquire(engine.ConnectionSlot)
	defer lease.Release()
	down, app := net.Pipe()
	up, origin := net.Pipe()
	defer app.Close()
	defer origin.Close()
	request := Request{ConnectionID: "borrowed", Destination: netip.MustParseAddrPort("192.0.2.1:443"), NetworkGeneration: 7, Downstream: down, Upstream: up, ConnectionLease: lease}
	result := make(chan ConnectionResult, 1)
	go func() { result <- capture.pipeline.Handle(context.Background(), request) }()
	payload := []byte("GET / HTTP/1.1\r\n\r\n")
	go func() { _, _ = app.Write(payload) }()
	received := make([]byte, len(payload))
	if _, err := io.ReadFull(origin, received); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(received, payload) || capture.budget.Usage().RefusedConnections != 0 || capture.budget.Usage().Connections != 1 {
		t.Fatal(capture.budget.Usage())
	}
	app.Close()
	origin.Close()
	if got := await(t, result); got.Code != engine.OK {
		t.Fatal(got)
	}
	if !lease.Held() {
		t.Fatal("pipeline released gateway lease")
	}
	lease.Release()
	other, _ := engine.NewBudget(engine.Limits{})
	foreign, _ := other.Acquire(engine.ConnectionSlot)
	defer foreign.Release()
	handshake, _ := capture.budget.Acquire(engine.HandshakeSlot)
	defer handshake.Release()
	for _, invalid := range []*engine.Lease{foreign, handshake, lease} {
		down, app := net.Pipe()
		up, origin := net.Pipe()
		request.Downstream = down
		request.Upstream = up
		request.ConnectionLease = invalid
		if got := capture.pipeline.Handle(context.Background(), request); got.Code != engine.InvalidArgument {
			t.Fatal(got)
		}
		app.Close()
		origin.Close()
		down.Close()
		up.Close()
	}
}

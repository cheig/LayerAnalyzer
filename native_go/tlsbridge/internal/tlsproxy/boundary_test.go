package tlsproxy

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"net"
	"net/netip"
	"sync"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// This file is TLS-217's compatibility boundary: the handshake shapes that are
// not the ordinary "client offers, origin answers" exchange. Each case states
// which of the three outcomes the design allows the engine to have — the
// supported path carries the application's own bytes, an out-of-scope shape is
// bypassed untouched, or the handshake fails — and then makes the engine prove
// it. None of them is written to pass by pretending an unsupported outcome
// succeeded (C01, design §15.2).

// clientCertificates is the application's client-certificate offer, or nothing
// at all. An empty slice is the same as a nil field for crypto/tls, so an
// unconfigured client keeps its original single-certificate behaviour.
func clientCertificates(certificate *tls.Certificate) []tls.Certificate {
	if certificate == nil {
		return nil
	}
	return []tls.Certificate{*certificate}
}

// newOriginWithConfig starts a TLS origin the case configures itself, so it can
// require a client certificate, pin a key-exchange group, or speak only one
// version. It records the SNI it saw exactly like newOrigin does, so the two
// helpers stay interchangeable.
func newOriginWithConfig(t *testing.T, config *tls.Config) *origin {
	t.Helper()
	o := &origin{echo: true, ended: make(chan struct{})}
	if config.GetConfigForClient == nil {
		config.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
			o.mu.Lock()
			o.snis = append(o.snis, hello.ServerName)
			o.mu.Unlock()
			return nil, nil
		}
	}
	listener, err := tls.Listen("tcp", "127.0.0.1:0", config)
	if err != nil {
		t.Fatalf("listening as a configured origin: %v", err)
	}
	o.listener = listener
	t.Cleanup(func() { _ = listener.Close() })
	go o.accept()
	return o
}

// TestAHelloRetryRequestOnTheDownstreamLegStillRecordsTheConnectionsOwnSecrets
// is the boundary the design calls out by name (§6.3): a client that needs a
// HelloRetryRequest sends a second ClientHello on the same connection, and that
// second hello must not silently drop the per-connection keylog writer. The
// application's key preference starts with tls.MLKEM1024, which this engine does
// not enable, so the proxy answers the first hello with a HelloRetryRequest; the
// negotiated group can therefore only be the fallback the client was asked for.
// The connection must still carry the application's own bytes and still produce
// this connection's downstream secrets.
func TestAHelloRetryRequestOnTheDownstreamLegStillRecordsTheConnectionsOwnSecrets(t *testing.T) {
	ca, pool := testCA(t)
	originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	base := &platformStub{verdict: engine.OK}

	result, _ := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS13,
		originCert:    originCert,
		trustCA:       true,
		// MLKEM1024 first: the client sends a key share only for it, and the
		// proxy does not enable that group, so P256 is reachable only through a
		// HelloRetryRequest.
		clientCurves: []tls.CurveID{tls.MLKEM1024, tls.CurveP256},
	}, base, 0)

	session := result.session
	if err := result.app.wait(t); err != nil {
		t.Fatalf("the application's retried handshake: %v", err)
	}
	if !session.Intercepted() {
		t.Fatalf("the retried handshake was not intercepted: %s (%s)", session.Code, session.Reason)
	}
	if got := result.app.conn.ConnectionState().CurveID; got != tls.CurveP256 {
		t.Fatalf("the negotiated group is %v; a HelloRetryRequest was not exercised", got)
	}
	if echoed := echoThroughProxy(t, session, result.app, "ping"); echoed != "ping" {
		t.Fatalf("the retried connection did not carry application data: %q", echoed)
	}
	// The whole point of the boundary: the second hello must not lose the
	// connection's own downstream secrets.
	assertDownstreamSecretFor(t, result.keylog, result.probe.Hello, tls.VersionTLS13)
}

// TestAHelloRetryRequestOnTheUpstreamLegStillCarriesTheApplicationsOwnBytes
// exercises the same boundary on the other leg: the origin pins a group the
// proxy's own ClientHello did not send a key share for, so the origin issues a
// HelloRetryRequest. The proxy's upstream handshake must complete it and the two
// legs must still relay the application's bytes unchanged.
func TestAHelloRetryRequestOnTheUpstreamLegStillCarriesTheApplicationsOwnBytes(t *testing.T) {
	ca, pool := testCA(t)
	originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	// P-384 only: the proxy's default client sends X25519-family shares and so is
	// forced into a retry.
	origin := newOriginWithConfig(t, &tls.Config{
		Certificates:     []tls.Certificate{originCert},
		MinVersion:       tls.VersionTLS13,
		MaxVersion:       tls.VersionTLS13,
		NextProtos:       []string{"h2"},
		CurvePreferences: []tls.CurveID{tls.CurveP384},
	})
	base := &platformStub{verdict: engine.OK}

	result, _ := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originAddress: origin.address(),
		trustCA:       true,
	}, base, 0)

	session := result.session
	if !session.Intercepted() {
		t.Fatalf("the upstream retry ended the connection: %s (%s)", session.Code, session.Reason)
	}
	if got := session.Upstream.ConnectionState().CurveID; got != tls.CurveP384 {
		t.Fatalf("the upstream group is %v; the origin's HelloRetryRequest was not honoured", got)
	}
	if echoed := echoThroughProxy(t, session, result.app, "ping"); echoed != "ping" {
		t.Fatalf("the retried upstream did not carry application data: %q", echoed)
	}
}

// TestAClientWithASessionCacheCannotResumeBecauseTheProxyIssuesNoTicket covers
// §6.3's resumption rule as a behaviour rather than a config field: the engine
// issues no downstream ticket and keeps no upstream session cache, so a client
// that is willing to resume still performs a full handshake on every connection,
// and each connection keeps its own client random and its own secrets. The origin
// is a real listener across both attempts, so "no upstream resumption" is
// observed on the wire and not assumed.
func TestAClientWithASessionCacheCannotResumeBecauseTheProxyIssuesNoTicket(t *testing.T) {
	ca, pool := testCA(t)
	originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOrigin(t, originCert, tls.VersionTLS13, []string{"h2"})
	cache := tls.NewLRUClientSessionCache(8)
	base := &platformStub{verdict: engine.OK}

	randoms := make([]string, 0, 2)
	for attemptIndex := 0; attemptIndex < 2; attemptIndex++ {
		result, _ := run(t, ca, pool, attempt{
			identity:           "example.test",
			clientMin:          tls.VersionTLS13,
			clientMax:          tls.VersionTLS13,
			offered:            []string{"h2"},
			originAddress:      origin.address(),
			trustCA:            true,
			clientSessionCache: cache,
		}, base, 0)
		session := result.session
		if !session.Intercepted() {
			t.Fatalf("connection %d was not intercepted: %s (%s)", attemptIndex, session.Code, session.Reason)
		}
		if echoed := echoThroughProxy(t, session, result.app, "ping"); echoed != "ping" {
			t.Fatalf("connection %d did not carry application data: %q", attemptIndex, echoed)
		}
		if session.Downstream.ConnectionState().DidResume {
			t.Fatalf("connection %d resumed downstream; the proxy must issue no ticket", attemptIndex)
		}
		if session.Upstream.ConnectionState().DidResume {
			t.Fatalf("connection %d resumed upstream; the proxy keeps no session cache", attemptIndex)
		}
		if result.app.conn.ConnectionState().DidResume {
			t.Fatalf("connection %d resumed from the application's own cache", attemptIndex)
		}
		assertDownstreamSecretFor(t, result.keylog, result.probe.Hello, tls.VersionTLS13)
		random := string(result.probe.Hello.ClientRandom[:])
		randoms = append(randoms, random)
	}
	if len(randoms) == 2 && randoms[0] == randoms[1] {
		t.Fatal("two connections shared one client random; each capture connection must be keyed on its own")
	}
	if got := origin.protocolCount(); got != 2 {
		t.Fatalf("the origin completed %d handshakes, want two full ones", got)
	}
}

// TestAnOriginThatRequiresAClientCertificateFailsTheConnectionWithoutCarryingTheRequest
// is the upstream half of the mTLS boundary: this engine cannot carry the
// application's identity onto the upstream leg (§6.4), so an origin that demands
// a client certificate can never be satisfied. The card forbids turning that into
// an anonymous success, and the engine does not: the origin receives no
// application byte and the connection ends as a failure.
//
// The failure is observed during the relay rather than during the upstream
// handshake, and that is a fact about TLS 1.3 and not a proxy shortcut: the
// origin reads the client's Certificate and rejects it with certificate_required
// *after* the client's own Finished has been sent, so Go's client handshake
// returns before the alert arrives and the alert only surfaces on first use. The
// engine therefore presents its leaf and receives the request, then dies on the
// first upstream read. What matters for the boundary is that nothing reaches the
// origin and the connection is FAILED, not OK.
func TestAnOriginThatRequiresAClientCertificateFailsTheConnectionWithoutCarryingTheRequest(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
	})
	originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOriginWithConfig(t, &tls.Config{
		Certificates: []tls.Certificate{originCert},
		MinVersion:   tls.VersionTLS13,
		MaxVersion:   tls.VersionTLS13,
		// RequireAnyClientCert is enough: the proxy presents none.
		ClientAuth: tls.RequireAnyClientCert,
	})
	app, results := capture.start(t, origin.destination())

	client := tls.Client(app, &tls.Config{
		RootCAs:    capture.pool,
		ServerName: "example.test",
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	// Whatever the application's own handshake reports, the assertion that
	// matters is below: the certificate-required origin accepted no request.
	_ = client.Handshake()
	_, _ = client.Write([]byte("POST /charge HTTP/1.1\r\n\r\n"))
	_ = client.Close()
	result := await(t, results)

	if result.Code == engine.OK {
		t.Fatalf("an origin that requires a client certificate was satisfied: %+v", result)
	}
	if result.Phase != engine.PhaseFailed {
		t.Fatalf("terminal phase = %s, want FAILED", result.Phase)
	}
	if got := origin.received(); got != 0 {
		t.Fatalf("the mTLS-required origin received %d application bytes", got)
	}
	if origin.protocolCount() != 0 {
		t.Fatalf("the mTLS-required origin completed %d handshakes", origin.protocolCount())
	}
	for _, phase := range capture.phases() {
		if phase == engine.PhasePassthrough {
			t.Fatalf("an mTLS-required origin was bypassed instead of failed: %v", capture.phases())
		}
	}
	terminals := capture.events.Terminals()
	if len(terminals) != 1 || terminals[0].Phase != engine.PhaseFailed || terminals[0].ErrorCode == "" {
		t.Fatalf("terminal events = %+v, want one FAILED with an error code", terminals)
	}
	// The counters stay separate: this connection failed, and nothing about it is
	// recorded as a pass-through.
	if stats := capture.events.Stats(); stats.ConnectionsFailed != 1 || stats.ConnectionsPassthrough != 0 {
		t.Fatalf("capture stats = %+v", stats)
	}
}

// TestTheProxyNeverAsksTheApplicationForAClientCertificate is the downstream half
// of the mTLS boundary: even when the application offers a client certificate,
// the engine's downstream configuration never sends a CertificateRequest, so the
// certificate never leaves the client and is never forwarded (§6.4). The
// connection itself stays fully supported.
func TestTheProxyNeverAsksTheApplicationForAClientCertificate(t *testing.T) {
	ca, pool := testCA(t)
	originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	// A certificate the application is willing to present. The engine never
	// requests one, so it must stay on the client side.
	clientCert := leafFor(t, x509.ECDSA, []string{"client.example.test"}, nil)
	base := &platformStub{verdict: engine.OK}

	result, _ := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS13,
		originCert:    originCert,
		trustCA:       true,
		clientCert:    &clientCert,
	}, base, 0)

	session := result.session
	if !session.Intercepted() {
		t.Fatalf("offering a client certificate broke the connection: %s (%s)", session.Code, session.Reason)
	}
	if got := session.Downstream.ConnectionState().PeerCertificates; len(got) != 0 {
		t.Fatalf("the downstream handshake received %d client certificates; it must request none", len(got))
	}
	if echoed := echoThroughProxy(t, session, result.app, "ping"); echoed != "ping" {
		t.Fatalf("the connection did not carry application data: %q", echoed)
	}
}

// greetingOrigin is a server that speaks first — the SMTP, FTP and IMAP shape
// where the client waits for a banner before it says anything. It writes its
// greeting as soon as a connection is accepted and then relays whatever the
// client sends, so the test can see whether the engine kept the bytes intact.
type greetingOrigin struct {
	listener net.Listener
	greeting []byte

	mu       sync.Mutex
	received bytes.Buffer
}

func newGreetingOrigin(t *testing.T, greeting string) *greetingOrigin {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listening as a greeting origin: %v", err)
	}
	o := &greetingOrigin{listener: listener, greeting: []byte(greeting)}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		if _, err := conn.Write(o.greeting); err != nil {
			return
		}
		buffer := make([]byte, 4096)
		for {
			n, err := conn.Read(buffer)
			if n > 0 {
				o.mu.Lock()
				_, _ = o.received.Write(buffer[:n])
				o.mu.Unlock()
				if _, writeErr := conn.Write(buffer[:n]); writeErr != nil {
					return
				}
			}
			if err != nil {
				return
			}
		}
	}()
	return o
}

func (o *greetingOrigin) destination() netip.AddrPort {
	return netip.MustParseAddrPort(o.listener.Addr().String())
}

func (o *greetingOrigin) bytesReceived() []byte {
	o.mu.Lock()
	defer o.mu.Unlock()
	return append([]byte(nil), o.received.Bytes()...)
}

// TestAServerThatSpeaksFirstIsForwardedUntouched is the "server speaks first"
// boundary of §6.2: a client that stays quiet while the server sends a banner
// must not be left waiting for the probe's budget to expire on a connection the
// engine will not intercept anyway. The probe gives up inside its budget and the
// connection is forwarded, banner and all.
func TestAServerThatSpeaksFirstIsForwardedUntouched(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		// A short probe budget keeps the case quick; the boundary is the same at
		// the production three seconds.
		o.probe = Limits{Timeout: 150 * time.Millisecond}
	})
	origin := newGreetingOrigin(t, "220 mail.example.test ESMTP\r\n")
	app, results := capture.start(t, origin.destination())

	greeting := readExactly(t, app, len("220 mail.example.test ESMTP\r\n"))
	if string(greeting) != "220 mail.example.test ESMTP\r\n" {
		t.Fatalf("the banner = %q, want the origin's greeting", greeting)
	}
	_ = app.Close()
	result := await(t, results)
	if result.Code != engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want a clean pass-through", result)
	}
	assertPhases(t, capture.phases(),
		engine.PhaseAccepted, engine.PhaseSniffing, engine.PhasePassthrough, engine.PhaseClosed)
	// The event records the policy's reason; the probe's own verdict that the
	// banner was not a ClientHello is what routed it here, and no interception
	// phase followed.
	if reason, ok := capture.reasonOf(engine.PhasePassthrough); !ok || reason != "no_include_match" {
		t.Fatalf("the pass-through reason = %q (present %v)", reason, ok)
	}
}

// TestAStarttlsPreambleIsForwardedUntouched is §6.2's STARTTLS boundary: the
// client begins with a plaintext command, not TLS, so the probe classifies the
// stream as not a ClientHello and the connection is forwarded byte for byte. The
// engine must not invent an interception of a session whose TLS has not started.
func TestAStarttlsPreambleIsForwardedUntouched(t *testing.T) {
	capture := newCapture(t)
	origin := newRawOrigin(t, true)
	app, results := capture.start(t, origin.destination())

	preamble := "EHLO client.example.test\r\n"
	if _, err := app.Write([]byte(preamble)); err != nil {
		t.Fatalf("writing the STARTTLS preamble: %v", err)
	}
	if got := string(readExactly(t, app, len(preamble))); got != preamble {
		t.Fatalf("the echoed preamble = %q, want %q", got, preamble)
	}
	origin.waitReceived(t, len(preamble))
	if got := string(origin.bytesReceived()); got != preamble {
		t.Fatalf("the origin received %q, want the client's plaintext preamble", got)
	}
	_ = app.Close()
	result := await(t, results)
	if result.Code != engine.OK || result.Intercepted {
		t.Fatalf("result = %+v, want a clean pass-through", result)
	}
	assertPhases(t, capture.phases(),
		engine.PhaseAccepted, engine.PhaseSniffing, engine.PhasePassthrough, engine.PhaseClosed)
	reason, _ := capture.reasonOf(engine.PhasePassthrough)
	if reason != "no_include_match" {
		t.Fatalf("the pass-through reason = %q, want the policy's own reason", reason)
	}
	for _, phase := range capture.phases() {
		if phase == engine.PhaseUpstreamHandshake || phase == engine.PhaseRelaying {
			t.Fatalf("a STARTTLS preamble reached %s", phase)
		}
	}
}

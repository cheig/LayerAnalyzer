package tlsproxy

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"net"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// This file is TLS-217's failure-state half: the injections the card names —
// a filled writer, a platform verifier that raises, a slow client, a stop that
// lands at the same time as traffic, and a stream that ends inside a record —
// checked for the one property that matters at the boundary: the network state,
// the capture (secret) state and the decryption state stay separate. A lost
// secret must not be reported as a network failure, a network failure must not
// be reported as lost secrets, and neither may be reported as a decryption
// success. The cases that only need the relay's own behaviour (a slow reader
// backing up, a reset ending a copy) live in relay_test.go and are not repeated
// here; these go through the whole pipeline.

// TestAStreamThatEndsInsideARecordIsReportedAsTruncatedRatherThanComplete pins
// the difference between "the peer finished" and "the bytes ran out mid-record".
// The origin writes a whole record and then only the first bytes of the next one
// before the raw socket closes, so the proxy's upstream read ends with a torn
// record. That is a missing tail, not a clean end, and the connection event must
// say so rather than count the partial answer as complete.
func TestAStreamThatEndsInsideARecordIsReportedAsTruncatedRatherThanComplete(t *testing.T) {
	relayed := startRelayedTLS(t, context.Background(), RelayLimits{}, 0, func(server *tls.Conn, raw net.Conn) {
		if _, err := server.Write([]byte("part of an answer")); err != nil {
			return
		}
		// Three bytes of a record header, then nothing: the peer dies inside a
		// record, which crypto/tls reports as io.ErrUnexpectedEOF.
		if _, err := raw.Write([]byte{0x17, 0x03, 0x03}); err != nil {
			return
		}
		_ = raw.Close()
	})
	result := relayed.wait(t)
	if result.Code != engine.IOError || result.Reason != ReasonRelayStreamTruncated {
		t.Fatalf("relay result = %s / %s, want IO_ERROR / %s", result.Code, result.Reason, ReasonRelayStreamTruncated)
	}
	if result.BytesToDownstream == 0 {
		t.Fatal("the whole record before the tear was not delivered")
	}
}

// TestAPlatformVerificationThatPanicsEndsTheConnectionRatherThanFallingBack
// injects a raised exception in the platform half (§6.4: a verifier that is
// unavailable or faults must fail, never pass). The connection must end as a
// failed attempt, the client must not be handed proxy TLS, and the engine must
// not quietly open a second, unverified socket to make the failure look like a
// success.
func TestAPlatformVerificationThatPanicsEndsTheConnectionRatherThanFallingBack(t *testing.T) {
	ca, pool := testCA(t)
	originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	platform := &platformStub{verdict: engine.OK, panics: true}

	result, _ := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS13,
		originCert:    originCert,
		trustCA:       true,
	}, platform, 0)

	session := result.session
	if session.Intercepted() {
		t.Fatal("a panicking platform verifier was treated as a pass")
	}
	if session.Code != engine.IOError {
		t.Fatalf("failure code = %s, want IO_ERROR", session.Code)
	}
	if session.Reason != ReasonUpstreamVerification {
		t.Fatalf("failure reason = %s, want %s", session.Reason, ReasonUpstreamVerification)
	}
	if session.SpokeToClient() {
		t.Fatalf("the proxy wrote %d bytes towards the client of a failed attempt", session.BytesToDownstream)
	}
}

// TestASlowClientReceivesTheWholeAnswerThroughThePipeline is the slow-client
// injection at the pipeline level: the application reads its answer one small
// piece at a time, which backs the copy up into the relay's fixed buffer and
// then into the origin's send path. The whole body must still arrive, unchanged
// and once, which is what "the supported path returns the application's own
// bytes" means for a client that is simply slow.
func TestASlowClientReceivesTheWholeAnswerThroughThePipeline(t *testing.T) {
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
		t.Fatalf("the application's handshake: %v", err)
	}
	request := bytes.Repeat([]byte("0123456789abcdef"), 4096) // 64 KiB
	if _, err := client.Write(request); err != nil {
		t.Fatalf("writing the request: %v", err)
	}
	origin.waitReceived(t, len(request))

	answer := make([]byte, 0, len(request))
	buffer := make([]byte, 7)
	deadline := time.Now().Add(15 * time.Second)
	for len(answer) < len(request) && time.Now().Before(deadline) {
		if err := client.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
			t.Fatalf("setting a read deadline: %v", err)
		}
		n, err := client.Read(buffer)
		if n > 0 {
			answer = append(answer, buffer[:n]...)
		}
		if err != nil {
			t.Fatalf("the slow client's read failed after %d bytes: %v", len(answer), err)
		}
	}
	if !bytes.Equal(answer, request) {
		t.Fatalf("the slow client received %d bytes of %d, changed", len(answer), len(request))
	}
	closeTLS(t, client)
	result := await(t, results)
	if result.Code != engine.OK || !result.Intercepted {
		t.Fatalf("result = %+v, want a clean intercepted connection", result)
	}
	if result.BytesToUpstream != int64(len(request)) || result.BytesToDownstream != int64(len(request)) {
		t.Fatalf("relayed %d/%d bytes, want %d each way", result.BytesToUpstream, result.BytesToDownstream, len(request))
	}
}

// TestACancelledConnectionPublishesOneTerminalStateAndReleasesBothTransports is
// the "stop lands while traffic is flowing" injection. Cancellation must end the
// connection once — one terminal event, the caller's CANCELLED code — and both
// transports must be released, because a half-stopped connection that leaves a
// socket open is exactly the leak the stopping path exists to prevent.
func TestACancelledConnectionPublishesOneTerminalStateAndReleasesBothTransports(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
	})
	leaf := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)
	origin := newOrigin(t, leaf, tls.VersionTLS13, []string{"h2"})

	ctx, cancel := context.WithCancel(context.Background())
	app, results := capture.startContext(t, ctx, origin.destination())
	client := tls.Client(app, &tls.Config{
		RootCAs:    capture.pool,
		ServerName: "example.test",
		NextProtos: []string{"h2"},
		MinVersion: tls.VersionTLS13,
		MaxVersion: tls.VersionTLS13,
	})
	if err := client.Handshake(); err != nil {
		// The stop may land before the application's handshake finishes; either
		// way the connection must end, so this is not a failure.
		t.Logf("the application's handshake ended during the stop: %v", err)
	}
	cancel()
	result := await(t, results)
	if result.Code != engine.Cancelled {
		t.Fatalf("result code = %s, want CANCELLED", result.Code)
	}
	if result.Phase != engine.PhaseFailed {
		t.Fatalf("terminal phase = %s, want FAILED", result.Phase)
	}
	if terminals := capture.events.Terminals(); len(terminals) != 1 {
		t.Fatalf("terminal events = %d, want exactly one", len(terminals))
	}
	if usage := capture.budget.Usage(); usage.Connections != 0 || usage.Handshakes != 0 {
		t.Fatalf("budgets after a cancelled connection: %+v", usage)
	}
	_ = client.Close()
}

// TestARecordLossIsACaptureFailureAndNotANetworkFailureOrADecryptionClaim is the
// three-way separation the card asks for, on one connection. A capture whose
// secret queue is full loses a record, and the counters must show exactly that:
// the connection is counted as proxied (the network carried it), as
// secrets-incomplete (the capture lost a record) and *not* as failed (the
// network did not fail). Nothing here claims the connection was decrypted — the
// engine has no such counter, deliberately (§10.2, C03 7).
func TestARecordLossIsACaptureFailureAndNotANetworkFailureOrADecryptionClaim(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
		// One byte of secret queue: no record can be saved, so the first is lost.
		o.queueBytes = 1
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
	if err := client.Handshake(); err != nil {
		t.Fatalf("the application's handshake: %v", err)
	}
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("writing on the connection: %v", err)
	}
	origin.waitReceived(t, 4)
	closeTLS(t, client)
	result := await(t, results)
	// Network: the bytes were carried.
	if !result.Intercepted || result.Code != engine.OK || result.BytesToUpstream != 4 {
		t.Fatalf("result = %+v, want a carried connection", result)
	}
	terminals := capture.events.Terminals()
	if len(terminals) != 1 {
		t.Fatalf("terminal events = %d, want one", len(terminals))
	}
	terminal := terminals[0]
	// Capture: the record was lost and the connection says so.
	if terminal.SecretsComplete || terminal.SecretRecordsAccepted == 0 || terminal.SecretRecordsPersisted != 0 {
		t.Fatalf("terminal secrets = %d/%d complete=%v, want a reported loss",
			terminal.SecretRecordsAccepted, terminal.SecretRecordsPersisted, terminal.SecretsComplete)
	}
	// Separation: proxied (network) and secrets-incomplete (capture) are distinct
	// counters, and neither is a network failure.
	stats := capture.events.Stats()
	if stats.ConnectionsProxied != 1 || stats.SecretsIncomplete != 1 || stats.ConnectionsFailed != 0 {
		t.Fatalf("capture stats = %+v, want one proxied, one secrets-incomplete, no network failure", stats)
	}
}

package tlsproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"syscall"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

func TestDownstreamFailureClassifiesTransportWithoutInferringCertificateRejection(t *testing.T) {
	cases := []struct {
		name   string
		err    error
		code   engine.Code
		reason Reason
	}{
		{"eof", io.EOF, engine.IOError, ReasonDownstreamClosed},
		{"partial_record", io.ErrUnexpectedEOF, engine.IOError, ReasonDownstreamClosed},
		{"closed", net.ErrClosed, engine.IOError, ReasonDownstreamClosed},
		{"reset", &net.OpError{Op: "read", Net: "tcp", Err: syscall.ECONNRESET}, engine.IOError, ReasonDownstreamClosed},
		{"aborted", syscall.ECONNABORTED, engine.IOError, ReasonDownstreamClosed},
		{"broken_pipe", syscall.EPIPE, engine.IOError, ReasonDownstreamClosed},
		{"deadline", os.ErrDeadlineExceeded, engine.IOError, ReasonDownstreamTimeout},
		{"remote_alert", &net.OpError{Op: "remote error", Net: "tcp", Err: errors.New("tls: bad certificate")}, engine.DownstreamTLSRejected, ReasonDownstreamAlert},
		{"local_protocol_error", errors.New("tls: unexpected message"), engine.IOError, ReasonDownstreamHandshake},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			// Also exercise wrapping, as OS and TLS errors cross several layers.
			for _, err := range []error{test.err, fmt.Errorf("wrapped: %w", test.err)} {
				code, reason := classifyDownstreamFailure(context.Background(), err, &keyLogSink{})
				if code != test.code || reason != test.reason {
					t.Fatalf("classification = %s / %s, want %s / %s", code, reason, test.code, test.reason)
				}
			}
		})
	}
}

func TestDownstreamCancellationAndSecretFailureTakePrecedenceOverSocketClosure(t *testing.T) {
	sink := &keyLogSink{}
	sink.failed.Store(true)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if code, reason := classifyDownstreamFailure(ctx, io.EOF, sink); code != engine.Cancelled || reason != ReasonCancelled {
		t.Fatalf("cancelled classification = %s / %s", code, reason)
	}
	if code, reason := classifyDownstreamFailure(context.Background(), io.EOF, sink); code != engine.SecretsIncomplete || reason != ReasonSecretsIncomplete {
		t.Fatalf("secret failure classification = %s / %s", code, reason)
	}
}

// Exercise crypto/tls itself, not just synthetic errors: a browser can send a
// ClientHello and close before it ever receives a proxy certificate.
func TestClientClosingAfterClientHelloIsNotReportedAsCertificateRejection(t *testing.T) {
	ca, _ := testCA(t)
	origin := newOrigin(t, leafFor(t, x509.ECDSA, []string{"example.test"}, nil), tls.VersionTLS13, []string{"h2"})
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	client, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	accepted, err := listener.Accept()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = accepted.Close() })
	hello := realClientHello(t, &tls.Config{ServerName: "example.test", NextProtos: []string{"h2"}})
	if _, err := client.Write(hello); err != nil {
		t.Fatal(err)
	}
	probe := ProbeClientHello(accepted, Limits{})
	if probe.Verdict != VerdictClientHello {
		t.Fatalf("probe verdict = %s", probe.Verdict)
	}
	// FIN follows the complete ClientHello, before the proxy starts either TLS leg.
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	upstream, err := net.Dial("tcp", origin.address())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	handshaker, code := NewHandshaker(ca, &gateStub{platform: &platformStub{verdict: engine.OK}}, time.Second)
	if code != engine.OK {
		t.Fatalf("handshaker code = %s", code)
	}
	session := handshaker.Handshake(context.Background(), Input{Probe: probe, Upstream: upstream, Identity: "example.test"})
	if session.Code != engine.IOError || session.Reason != ReasonDownstreamClosed {
		t.Fatalf("closed client = %s / %s, want IO_ERROR / %s", session.Code, session.Reason, ReasonDownstreamClosed)
	}
	if session.Intercepted() {
		t.Fatal("an unfinished handshake was reported as intercepted")
	}
	origin.waitReleased(t)
	if origin.received() != 0 {
		t.Fatal("application bytes reached the origin before the handshake completed")
	}
}

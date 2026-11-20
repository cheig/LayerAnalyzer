package tlsproxy

import (
	"bytes"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"io"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

func TestFailureRecoveryStressLargeTLSStreamHasExactBytesAndReleasesSlots(t *testing.T) {
	capture := newCapture(t, func(o *captureOptions) {
		o.route = Route{Intercept: true, Identity: "example.test", Reason: "included_host"}
	})
	origin := newOrigin(t, leafFor(t, x509.ECDSA, []string{"example.test"}, nil), tls.VersionTLS13, nil)
	app, results := capture.start(t, origin.destination())
	client := tls.Client(app, &tls.Config{RootCAs: capture.pool, ServerName: "example.test", MinVersion: tls.VersionTLS13})
	defer client.Close()
	_ = client.SetDeadline(time.Now().Add(10 * time.Second))
	if err := client.Handshake(); err != nil {
		t.Fatal(err)
	}
	// Larger than every relay buffer, using actual TLS on both sides. This is
	// correctness stress, not a throughput or 30-minute stability measurement.
	body := bytes.Repeat([]byte("synthetic-tls403-"), 256*1024) // 4 MiB
	written := make(chan error, 1)
	go func() { _, err := io.Copy(client, bytes.NewReader(body)); written <- err }()
	answer := make([]byte, len(body))
	if _, err := io.ReadFull(client, answer); err != nil {
		t.Fatal(err)
	}
	if err := <-written; err != nil {
		t.Fatal(err)
	}
	if sha256.Sum256(body) != sha256.Sum256(answer) {
		t.Fatal("TLS stream body hash differs")
	}
	closeTLS(t, client)
	result := await(t, results)
	if result.Code != engine.OK || !result.Intercepted || result.BytesToUpstream != int64(len(body)) || result.BytesToDownstream != int64(len(body)) {
		t.Fatal("stream byte accounting failed")
	}
	if usage := capture.budget.Usage(); usage.Connections != 0 || usage.Handshakes != 0 {
		t.Fatalf("slots retained: %+v", usage)
	}
}

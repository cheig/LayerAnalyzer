package tlsproxy

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"strings"
	"sync"
	"testing"

	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/secrets"
)

// This file is TLS-210's integration point: it attaches the production secret
// sink (internal/secrets) to the coordinator's downstream writer and runs the
// two-sided handshake for real. It lives in package tlsproxy rather than in
// internal/secrets because the harness it needs — a real capture CA, a real
// origin, a real application client — is this package's, and duplicating it
// would only create a second handshake to keep in step.
//
// What it fixes is §8.1's requirement and C03 3: the writer must be present on
// the configuration that actually performs the handshake (including the one
// GetConfigForClient returns), it must carry the downstream leg's secrets for
// both TLS versions, and the upstream leg (TLS B) must contribute none.

const (
	integrationCapture    = "capture-tls-210"
	integrationConnection = "connection-tls-210"
)

type offeredSecret struct {
	capture    string
	connection string
	line       string
}

// secretPlatform is the C05 platform half for these cases. It answers the
// upstream verification the way a device that trusts the capture CA does, and
// records what the sink hands it. Its records are never printed: a failure
// reports labels, counts and the client random only.
type secretPlatform struct {
	*platformStub
	mu      sync.Mutex
	offered []offeredSecret
}

func (p *secretPlatform) OfferSecret(capture, connection string, line []byte) engine.Code {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.offered = append(p.offered, offeredSecret{capture: capture, connection: connection, line: string(line)})
	return engine.OK
}

func (p *secretPlatform) secrets() []offeredSecret {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]offeredSecret(nil), p.offered...)
}

// TestTheProductionSinkCarriesTheDownstreamSecretsOfBothVersions runs one real
// handshake per TLS version with the production sink installed as the
// downstream writer, and checks that the sink received exactly the downstream
// leg's secrets.
func TestTheProductionSinkCarriesTheDownstreamSecretsOfBothVersions(t *testing.T) {
	cases := []struct {
		name    string
		version uint16
		// label is the NSS label crypto/tls writes first for that version: a
		// TLS 1.2 server writes the master secret as CLIENT_RANDOM, a TLS 1.3
		// server writes the handshake traffic secret.
		label string
	}{
		{"tls12", tls.VersionTLS12, "CLIENT_RANDOM"},
		{"tls13", tls.VersionTLS13, "CLIENT_HANDSHAKE_TRAFFIC_SECRET"},
	}

	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			ca, pool := testCA(t)
			originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)

			base := &platformStub{verdict: engine.OK}
			platform := &secretPlatform{platformStub: base}
			sink, code := secrets.NewSink(integrationCapture, &gateStub{platform: platform}, secrets.Limits{})
			if code != engine.OK {
				t.Fatalf("NewSink = %v", code)
			}
			defer sink.Drain(context.Background())
			writer, code := sink.Writer(integrationConnection)
			if code != engine.OK {
				t.Fatalf("Writer = %v", code)
			}

			result, _ := run(t, ca, pool, attempt{
				identity:      "example.test",
				clientMin:     test.version,
				clientMax:     test.version,
				offered:       []string{"h2"},
				originALPN:    []string{"h2"},
				originVersion: test.version,
				originCert:    originCert,
				trustCA:       true,
				downstream:    writer,
			}, base, 0)

			session := result.session
			if !session.Intercepted() {
				t.Fatalf("attempt failed: %v (%s)", session.Code, session.Reason)
			}
			// The sink must not disturb the handshake it is recording from.
			if echoed := echoThroughProxy(t, session, result.app, "ping"); echoed != "ping" {
				t.Fatalf("the connection did not carry application data: %q", echoed)
			}
			writer.Close()
			stats := sink.Drain(context.Background())
			if stats.Incomplete || !sink.Complete() {
				t.Fatalf("stats = %+v, want every downstream record delivered", stats)
			}

			offered := platform.secrets()
			if len(offered) == 0 {
				t.Fatal("the production sink recorded no downstream secret")
			}
			random := hex.EncodeToString(result.probe.Hello.ClientRandom[:])
			labels := make(map[string]int)
			for _, secret := range offered {
				if secret.capture != integrationCapture || secret.connection != integrationConnection {
					t.Fatalf("secret carried capture %q connection %q", secret.capture, secret.connection)
				}
				fields := strings.Fields(secret.line)
				if len(fields) != 3 || fields[1] != random {
					// The label and the column count are safe to report; the
					// secret is not.
					t.Fatalf("a recorded secret does not belong to this downstream connection (%d columns)", len(fields))
				}
				labels[fields[0]]++
			}
			// The upstream leg has no writer at all, so a secret that belonged
			// to it could only appear here with a different client random —
			// which the loop above rejects. The version's own label is the
			// positive half of the same check.
			if labels[test.label] == 0 {
				t.Fatalf("no %s line among %d recorded secrets: %v", test.label, len(offered), labelNames(labels))
			}
			if got := uint64(len(offered)); got != stats.Accepted {
				t.Fatalf("platform saw %d secrets, sink accepted %d", got, stats.Accepted)
			}
		})
	}
}

// labelNames reduces recorded labels to a printable summary; it never returns a
// client random or a secret.
func labelNames(labels map[string]int) []string {
	names := make([]string, 0, len(labels))
	for name := range labels {
		names = append(names, name)
	}
	return names
}

// TestASinkThatCannotSaveStopsNewInterceptionWithoutBreakingTheConnection is the
// negative half of the same wiring: a capture-side secret failure must leave the
// connection working and close the door on the next candidate (§8.2).
func TestASinkThatCannotSaveStopsNewInterceptionWithoutBreakingTheConnection(t *testing.T) {
	ca, pool := testCA(t)
	originCert := leafFor(t, x509.ECDSA, []string{"example.test"}, nil)

	base := &platformStub{verdict: engine.OK}
	platform := &refusingPlatform{secretPlatform: &secretPlatform{platformStub: base}}
	// One line of budget is less than any record, so the very first secret is
	// refused at the door.
	sink, code := secrets.NewSink(integrationCapture, &gateStub{platform: platform}, secrets.Limits{QueueBytes: 1})
	if code != engine.OK {
		t.Fatalf("NewSink = %v", code)
	}
	defer sink.Drain(context.Background())
	writer, _ := sink.Writer(integrationConnection)

	result, _ := run(t, ca, pool, attempt{
		identity:      "example.test",
		clientMin:     tls.VersionTLS13,
		clientMax:     tls.VersionTLS13,
		offered:       []string{"h2"},
		originALPN:    []string{"h2"},
		originVersion: tls.VersionTLS13,
		originCert:    originCert,
		trustCA:       true,
		downstream:    writer,
	}, base, 0)

	session := result.session
	if !session.Intercepted() {
		t.Fatalf("a secret failure ended the handshake: %v (%s)", session.Code, session.Reason)
	}
	if echoed := echoThroughProxy(t, session, result.app, "ping"); echoed != "ping" {
		t.Fatalf("the connection did not survive the secret failure: %q", echoed)
	}
	writer.Close()
	stats := sink.Drain(context.Background())
	if !stats.Incomplete || stats.Dropped == 0 {
		t.Fatalf("stats = %+v, want the lost secret reported", stats)
	}
	if sink.AcceptingNewInterception() {
		t.Fatal("a lost secret must stop new interception candidates")
	}
	if platform.secrets() != nil {
		t.Fatal("the platform must not have accepted a record the sink dropped")
	}
}

// refusingPlatform answers the platform verification but reports the secret
// path as unavailable, the way a device whose secret consumer has failed would.
type refusingPlatform struct{ *secretPlatform }

func (p *refusingPlatform) OfferSecret(string, string, []byte) engine.Code {
	return engine.SecretsIncomplete
}

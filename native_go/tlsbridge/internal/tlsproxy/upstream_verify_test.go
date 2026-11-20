package tlsproxy

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// platformStub and gateStub are explicit doubles for the C05 platform half.
// They record the exact arguments Go passes and return a fixed verdict; no
// Android call happens. The connection side of the handshake tests is a real
// host TLS listener, so "the handshake succeeded" or "the handshake failed" is
// decided by a real handshake and not by a mocked dialer.
type platformStub struct {
	mu         sync.Mutex
	calls      int
	chains     [][][]byte
	identities []string
	authTypes  []string
	versions   []string
	verdict    engine.Code
	panics     bool
}

func (s *platformStub) PrepareSocket(int, int64) engine.Code            { return engine.NotReady }
func (s *platformStub) ResolveHost(string, int64) ([]byte, engine.Code) { return nil, engine.NotReady }
func (s *platformStub) OfferSecret(string, string, []byte) engine.Code  { return engine.NotReady }

func (s *platformStub) VerifyUpstream(chain [][]byte, identity, authType, version string) engine.Code {
	s.mu.Lock()
	s.calls++
	s.chains = append(s.chains, chain)
	s.identities = append(s.identities, identity)
	s.authTypes = append(s.authTypes, authType)
	s.versions = append(s.versions, version)
	verdict, panics := s.verdict, s.panics
	s.mu.Unlock()
	if panics {
		panic("platform verifier panic")
	}
	return verdict
}

func (s *platformStub) observed() (int, string, string, string, []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.calls == 0 {
		return 0, "", "", "", nil
	}
	var leaf []byte
	if len(s.chains[0]) > 0 {
		leaf = s.chains[0][0]
	}
	return s.calls, s.identities[0], s.authTypes[0], s.versions[0], leaf
}

// gateStub mirrors engine.Callbacks' admission gate without a running manager.
type gateStub struct {
	platform engine.Platform
	closed   bool
}

func (g *gateStub) Call(operation func(engine.Platform) engine.Code) engine.Code {
	if g.closed {
		return engine.Cancelled
	}
	return operation(g.platform)
}

// leafFor builds a self-signed leaf with the given SANs. The Go side never
// verifies signatures (that is the platform's job), so a self-signed leaf is
// the exact input the upstream handshake produces when a server sends no
// intermediate.
func leafFor(t *testing.T, algorithm x509.PublicKeyAlgorithm, dnsNames []string, ips []net.IP) tls.Certificate {
	t.Helper()
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "tlsproxy test leaf"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              dnsNames,
		IPAddresses:           ips,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	var public any
	switch algorithm {
	case x509.ECDSA:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			t.Fatalf("generate ecdsa key: %v", err)
		}
		public = &key.PublicKey
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
		if err != nil {
			t.Fatalf("create ecdsa certificate: %v", err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse ecdsa certificate: %v", err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
	case x509.RSA:
		key, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("generate rsa key: %v", err)
		}
		public = &key.PublicKey
		der, err := x509.CreateCertificate(rand.Reader, template, template, public, key)
		if err != nil {
			t.Fatalf("create rsa certificate: %v", err)
		}
		parsed, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatalf("parse rsa certificate: %v", err)
		}
		return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
	default:
		t.Fatalf("unsupported test key algorithm %v", algorithm)
		return tls.Certificate{}
	}
}

// startServer runs a real TLS listener that only offers the requested version.
func startServer(t *testing.T, certificate tls.Certificate, version uint16) string {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   version,
		MaxVersion:   version,
	})
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	t.Cleanup(func() { _ = listener.Close() })
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if handshake, ok := conn.(*tls.Conn); ok {
					_ = handshake.HandshakeContext(context.Background())
				}
			}()
		}
	}()
	return listener.Addr().String()
}

// handshake runs a real client handshake through the production constructor.
func handshake(t *testing.T, address string, spec UpstreamSpec, gate Gate) (*tls.Conn, error) {
	t.Helper()
	config, code := NewUpstreamTLSConfig(spec, gate)
	if code != engine.OK {
		t.Fatalf("NewUpstreamTLSConfig(%+v) = %v", spec, code)
	}
	// tls.Dial fills an empty ServerName from the address; for an IP identity
	// that is the IP, which Go never sends as SNI.
	config.ServerName = serverNameFor(spec.Identity)
	return tls.Dial("tcp", address, config)
}

func TestHandshakeVerifiesTLS12AndTLS13ThroughThePlatform(t *testing.T) {
	for _, test := range []struct {
		name        string
		version     uint16
		algorithm   x509.PublicKeyAlgorithm
		identity    string
		authType    string
		versionName string
	}{
		{"tls12-ecdsa-name", tls.VersionTLS12, x509.ECDSA, "upstream.fixture.test", "ECDSA", "TLSv1.2"},
		{"tls13-ecdsa-name", tls.VersionTLS13, x509.ECDSA, "upstream.fixture.test", "ECDSA", "TLSv1.3"},
		{"tls12-rsa-name", tls.VersionTLS12, x509.RSA, "upstream.fixture.test", "RSA", "TLSv1.2"},
		{"tls13-rsa-ip", tls.VersionTLS13, x509.RSA, "127.0.0.1", "RSA", "TLSv1.3"},
	} {
		t.Run(test.name, func(t *testing.T) {
			certificate := leafFor(t, test.algorithm, []string{"upstream.fixture.test"}, []net.IP{net.IPv4(127, 0, 0, 1)})
			address := startServer(t, certificate, test.version)
			platform := &platformStub{verdict: engine.OK}
			gate := &gateStub{platform: platform}
			conn, err := handshake(t, address, UpstreamSpec{Identity: test.identity, MinVersion: test.version}, gate)
			if err != nil {
				t.Fatalf("handshake rejected a verifiable upstream: %v", err)
			}
			defer conn.Close()
			if got := conn.ConnectionState().Version; got != test.version {
				t.Fatalf("negotiated version %x, want %x", got, test.version)
			}
			calls, identity, authType, version, leaf := platform.observed()
			if calls != 1 {
				t.Fatalf("platform verify calls = %d, want 1", calls)
			}
			if identity != test.identity {
				t.Fatalf("identity = %q, want %q", identity, test.identity)
			}
			if authType != test.authType {
				t.Fatalf("authType = %q, want %q", authType, test.authType)
			}
			if version != test.versionName {
				t.Fatalf("version = %q, want %q", version, test.versionName)
			}
			if string(leaf) != string(certificate.Certificate[0]) {
				t.Fatal("platform received a chain that is not the peer leaf")
			}
		})
	}
}

func TestReferenceIdentityMismatchNeverReachesThePlatform(t *testing.T) {
	certificate := leafFor(t, x509.ECDSA, []string{"upstream.fixture.test"}, []net.IP{net.IPv4(127, 0, 0, 1)})
	address := startServer(t, certificate, tls.VersionTLS13)
	for _, identity := range []string{"other.fixture.test", "127.0.0.2", "sub.upstream.fixture.test"} {
		platform := &platformStub{verdict: engine.OK}
		conn, err := handshake(t, address, UpstreamSpec{Identity: identity, MinVersion: tls.VersionTLS13}, &gateStub{platform: platform})
		if err == nil {
			conn.Close()
			t.Fatalf("identity %q was accepted by a certificate that does not prove it", identity)
		}
		if code := FailureCode(err); code != engine.UpstreamCertInvalid {
			t.Fatalf("identity %q failed with %v, want UPSTREAM_CERT_INVALID", identity, code)
		}
		var failure *Failure
		if !errors.As(err, &failure) || !strings.Contains(failure.Reason, "reference identity") {
			t.Fatalf("identity %q failed for an unexpected reason: %v", identity, err)
		}
		if calls, _, _, _, _ := platform.observed(); calls != 0 {
			t.Fatalf("identity %q asked the platform %d times before the name was proven", identity, calls)
		}
	}
}

func TestPlatformVerdictEndsTheHandshake(t *testing.T) {
	certificate := leafFor(t, x509.ECDSA, []string{"upstream.fixture.test"}, nil)
	address := startServer(t, certificate, tls.VersionTLS12)
	for _, code := range []engine.Code{
		engine.UpstreamCertInvalid, engine.Cancelled, engine.NotReady, engine.Unsupported,
		engine.StaleGeneration, engine.IOError, engine.CapacityExceeded, engine.CaptureContextMissing,
		engine.NetworkChanged, engine.ProtectFailed, engine.SecretsIncomplete, engine.InvalidArgument,
	} {
		platform := &platformStub{verdict: code}
		conn, err := handshake(t, address, UpstreamSpec{Identity: "upstream.fixture.test", MinVersion: tls.VersionTLS12}, &gateStub{platform: platform})
		if err == nil {
			conn.Close()
			t.Fatalf("platform verdict %v still produced a usable connection", code)
		}
		if got := FailureCode(err); got != code {
			t.Fatalf("platform verdict %v surfaced as %v", code, got)
		}
		if calls, _, _, _, _ := platform.observed(); calls != 1 {
			t.Fatalf("platform verdict %v consulted %d times, want 1", code, calls)
		}
	}
}

func TestClosedAdmissionFailsTheHandshake(t *testing.T) {
	certificate := leafFor(t, x509.ECDSA, []string{"upstream.fixture.test"}, nil)
	address := startServer(t, certificate, tls.VersionTLS13)
	platform := &platformStub{verdict: engine.OK}
	conn, err := handshake(t, address, UpstreamSpec{Identity: "upstream.fixture.test", MinVersion: tls.VersionTLS13}, &gateStub{platform: platform, closed: true})
	if err == nil {
		conn.Close()
		t.Fatal("a closed admission gate still produced a verified connection")
	}
	if code := FailureCode(err); code != engine.Cancelled {
		t.Fatalf("closed admission surfaced as %v, want CANCELLED", code)
	}
	if calls, _, _, _, _ := platform.observed(); calls != 0 {
		t.Fatalf("closed admission entered the platform %d times", calls)
	}
}

func TestPanickingPlatformFailsClosed(t *testing.T) {
	certificate := leafFor(t, x509.ECDSA, []string{"upstream.fixture.test"}, nil)
	address := startServer(t, certificate, tls.VersionTLS13)
	platform := &platformStub{verdict: engine.OK, panics: true}
	conn, err := handshake(t, address, UpstreamSpec{Identity: "upstream.fixture.test", MinVersion: tls.VersionTLS13}, &gateStub{platform: platform})
	if err == nil {
		conn.Close()
		t.Fatal("a panicking platform callback was treated as a successful verification")
	}
	if code := FailureCode(err); code != engine.IOError {
		t.Fatalf("panic surfaced as %v, want IO_ERROR", code)
	}
}

func TestNoVerifierCannotProduceAConfig(t *testing.T) {
	valid := UpstreamSpec{Identity: "upstream.fixture.test", MinVersion: tls.VersionTLS13}
	if config, code := NewUpstreamTLSConfig(valid, nil); code != engine.NotReady || config != nil {
		t.Fatalf("a missing platform gate produced config=%v code=%v, want NOT_READY and no config", config, code)
	}
}

func TestConfigRejectsInvalidIdentityAndVersion(t *testing.T) {
	gate := &gateStub{platform: &platformStub{}}
	for _, identity := range []string{
		"", ".", "..", "example.test:443", "upstream fixture.test", "[::1]", "*.fixture.test",
		"-leading.test", "trailing-.test", "empty..test",
		strings.Repeat("a", 254), strings.Repeat("a", 64) + ".test", "café.test", "a\x00.test", "a\x1f.test", "a\x7f.test",
	} {
		if config, code := NewUpstreamTLSConfig(UpstreamSpec{Identity: identity, MinVersion: tls.VersionTLS12}, gate); code != engine.InvalidArgument || config != nil {
			t.Fatalf("identity %q produced config=%v code=%v, want INVALID_ARGUMENT", identity, config, code)
		}
	}
	for _, identity := range []string{"upstream.fixture.test", "UPSTREAM.FIXTURE.TEST", "upstream.fixture.test.", "127.0.0.1", "2001:db8::1", "::ffff:127.0.0.1", "a-b.test", "a_b.test", "1.2.3.4"} {
		if _, code := NewUpstreamTLSConfig(UpstreamSpec{Identity: identity, MinVersion: tls.VersionTLS12}, gate); code != engine.OK {
			t.Fatalf("identity %q was rejected with %v", identity, code)
		}
	}
	for _, version := range []uint16{0, tls.VersionSSL30, tls.VersionTLS10, tls.VersionTLS11, 0x9000} {
		if _, code := NewUpstreamTLSConfig(UpstreamSpec{Identity: "upstream.fixture.test", MinVersion: version}, gate); code != engine.Unsupported {
			t.Fatalf("minimum version %x was accepted with %v", version, code)
		}
	}
}

func TestIdentityIsCanonicalisedWithoutOtherRewrites(t *testing.T) {
	for _, test := range []struct{ input, want string }{
		{"upstream.fixture.test", "upstream.fixture.test"},
		{"upstream.fixture.test.", "upstream.fixture.test"},
		{"UPSTREAM.Fixture.Test", "UPSTREAM.Fixture.Test"},
		{"2001:db8::1", "2001:db8::1"},
		{"127.0.0.1", "127.0.0.1"},
	} {
		got, code := CanonicalIdentity(test.input)
		if code != engine.OK || got != test.want {
			t.Fatalf("CanonicalIdentity(%q) = %q, %v; want %q", test.input, got, code, test.want)
		}
	}
}

func TestEveryUpstreamConfigEnforcesVerifyConnection(t *testing.T) {
	gate := &gateStub{platform: &platformStub{}}
	for _, spec := range []UpstreamSpec{
		{Identity: "upstream.fixture.test", MinVersion: tls.VersionTLS12},
		{Identity: "upstream.fixture.test", MinVersion: tls.VersionTLS13},
		{Identity: "127.0.0.1", MinVersion: tls.VersionTLS12},
	} {
		config, code := NewUpstreamTLSConfig(spec, gate)
		if code != engine.OK {
			t.Fatalf("NewUpstreamTLSConfig(%+v) = %v", spec, code)
		}
		if code := validateUpstreamConfig(config); code != engine.OK {
			t.Fatalf("config built from %+v fails its own invariant: %v", spec, code)
		}
		if config.VerifyConnection == nil {
			t.Fatalf("config built from %+v has no VerifyConnection", spec)
		}
	}
	// A hand-built config is what TLS-209 must never hand to tls.Client: with
	// InsecureSkipVerify and no callback it accepts any certificate at all.
	for name, config := range map[string]*tls.Config{
		"unset":                 {},
		"skip-without-callback": {InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
		"verify-without-skip":   {VerifyConnection: func(tls.ConnectionState) error { return nil }, MinVersion: tls.VersionTLS12},
		"resumable":             {InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, VerifyConnection: func(tls.ConnectionState) error { return nil }, ClientSessionCache: tls.NewLRUClientSessionCache(1)},
		"tickets":               {InsecureSkipVerify: true, MinVersion: tls.VersionTLS13, VerifyConnection: func(tls.ConnectionState) error { return nil }},
		"below-tls12":           {InsecureSkipVerify: true, MinVersion: tls.VersionTLS11, VerifyConnection: func(tls.ConnectionState) error { return nil }, SessionTicketsDisabled: true},
		"wildcard-servername":   {InsecureSkipVerify: true, MinVersion: tls.VersionTLS12, ServerName: "*.fixture.test", VerifyConnection: func(tls.ConnectionState) error { return nil }, SessionTicketsDisabled: true},
	} {
		if code := validateUpstreamConfig(config); code == engine.OK {
			t.Fatalf("config %q was accepted as a runnable upstream", name)
		}
	}
	if code := validateUpstreamConfig(nil); code != engine.NotReady {
		t.Fatalf("nil config returned %v, want NOT_READY", code)
	}
}

func TestUpstreamConfigPinsVersionsAndDisablesResumption(t *testing.T) {
	gate := &gateStub{platform: &platformStub{}}
	config, code := NewUpstreamTLSConfig(UpstreamSpec{Identity: "upstream.fixture.test", MinVersion: tls.VersionTLS12}, gate)
	if code != engine.OK {
		t.Fatalf("build config: %v", code)
	}
	if config.MinVersion != tls.VersionTLS12 || config.MaxVersion != tls.VersionTLS13 {
		t.Fatalf("version range = %x..%x, want TLS1.2..TLS1.3", config.MinVersion, config.MaxVersion)
	}
	if !config.InsecureSkipVerify {
		t.Fatal("the delegated config must not double-verify against a host root pool")
	}
	if config.ClientSessionCache != nil || !config.SessionTicketsDisabled {
		t.Fatal("the first version keeps no upstream cross-connection state")
	}
	if config.ServerName != "upstream.fixture.test" {
		t.Fatalf("ServerName = %q", config.ServerName)
	}
	if config.NextProtos != nil {
		t.Fatal("ALPN is chosen by the handshake coordinator, not by this constructor")
	}
	byIP, code := NewUpstreamTLSConfig(UpstreamSpec{Identity: "127.0.0.1", MinVersion: tls.VersionTLS13}, gate)
	if code != engine.OK {
		t.Fatalf("build ip config: %v", code)
	}
	if byIP.ServerName != "" {
		t.Fatalf("an IP reference identity must not produce SNI, got %q", byIP.ServerName)
	}
}

func TestVersionBelowTheMinimumIsNeverNegotiated(t *testing.T) {
	certificate := leafFor(t, x509.ECDSA, []string{"upstream.fixture.test"}, nil)
	address := startServer(t, certificate, tls.VersionTLS12)
	platform := &platformStub{verdict: engine.OK}
	conn, err := handshake(t, address, UpstreamSpec{Identity: "upstream.fixture.test", MinVersion: tls.VersionTLS13}, &gateStub{platform: platform})
	if err == nil {
		conn.Close()
		t.Fatal("a TLS1.3-only minimum negotiated a TLS1.2 upstream")
	}
	if calls, _, _, _, _ := platform.observed(); calls != 0 {
		t.Fatalf("a version below the minimum consulted the platform %d times", calls)
	}
}

func TestVerifyUpstreamRejectsInputsBeforeThePlatform(t *testing.T) {
	platform := &platformStub{verdict: engine.OK}
	gate := &gateStub{platform: platform}
	leaf := &x509.Certificate{DNSNames: []string{"upstream.fixture.test"}, Raw: []byte{0x30, 0x00}, PublicKeyAlgorithm: x509.ECDSA}

	tooMany := make([]*x509.Certificate, MaxPeerCertificates+1)
	for index := range tooMany {
		tooMany[index] = leaf
	}
	for name, state := range map[string]tls.ConnectionState{
		"empty-chain":    {Version: tls.VersionTLS13},
		"nil-leaf":       {Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{nil}},
		"too-many":       {Version: tls.VersionTLS13, PeerCertificates: tooMany},
		"oversized-cert": {Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{{DNSNames: []string{"upstream.fixture.test"}, Raw: make([]byte, MaxCertificateBytes+1), PublicKeyAlgorithm: x509.ECDSA}}},
		"tls11":          {Version: tls.VersionTLS11, PeerCertificates: []*x509.Certificate{leaf}},
		"unknown-algo":   {Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{unknownAlgorithmCert()}},
	} {
		err := verifyUpstream(state, "upstream.fixture.test", tls.VersionTLS12, gate)
		if err == nil {
			t.Fatalf("%s was accepted", name)
		}
		if calls, _, _, _, _ := platform.observed(); calls != 0 {
			t.Fatalf("%s reached the platform", name)
		}
	}
	if err := verifyUpstream(tls.ConnectionState{Version: tls.VersionTLS13, PeerCertificates: []*x509.Certificate{leaf}}, "upstream.fixture.test", tls.VersionTLS12, nil); err == nil {
		t.Fatal("a missing verifier accepted a chain")
	} else if code := FailureCode(err); code != engine.NotReady {
		t.Fatalf("missing verifier surfaced as %v, want NOT_READY", code)
	}
	if code := FailureCode(errors.New("unrelated")); code != engine.IOError {
		t.Fatalf("an unclassified error surfaced as %v, want IO_ERROR", code)
	}
}

func unknownAlgorithmCert() *x509.Certificate {
	return &x509.Certificate{DNSNames: []string{"upstream.fixture.test"}, Raw: []byte{0x30, 0x00}, PublicKeyAlgorithm: x509.UnknownPublicKeyAlgorithm}
}

func TestFailureTextCarriesNoIdentityOrCertificate(t *testing.T) {
	err := verifyUpstream(tls.ConnectionState{Version: tls.VersionTLS13}, "upstream.fixture.test", tls.VersionTLS12, &gateStub{platform: &platformStub{}})
	if err == nil {
		t.Fatal("an empty chain was accepted")
	}
	if strings.Contains(err.Error(), "fixture") {
		t.Fatalf("failure text leaks the identity: %q", err.Error())
	}
	var failure *Failure
	if !errors.As(err, &failure) || failure.Reason == "" {
		t.Fatalf("failure is not typed: %#v", err)
	}
}

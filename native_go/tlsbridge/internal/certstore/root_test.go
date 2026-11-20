package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"net"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// testNow is truncated so that NotBefore/NotAfter comparisons are exact rather
// than dependent on the sub-second part of the clock.
func testNow() time.Time { return time.Now().Truncate(time.Second) }

// testRoot generates one RSA 3072 root for the whole test binary: generating it
// costs a real key generation, and the cache, name and leaf rules below do not
// depend on which root they are exercised with.
var (
	sharedRootOnce sync.Once
	sharedRoot     *Root
	sharedRootCode engine.Code
)

func testRoot(t *testing.T) *Root {
	t.Helper()
	sharedRootOnce.Do(func() { sharedRoot, sharedRootCode = GenerateRoot(testNow()) })
	if sharedRootCode != engine.OK {
		t.Fatalf("GenerateRoot = %v", sharedRootCode)
	}
	return sharedRoot
}

// rootExpiringAt builds a real RSA root whose NotAfter is the given instant, so
// that the root-expiry clamp can be exercised without a hand-built certificate.
func rootExpiringAt(t *testing.T, until time.Time) *Root {
	t.Helper()
	root, code := GenerateRoot(until.Add(-RootValidity))
	if code != engine.OK {
		t.Fatalf("GenerateRoot = %v", code)
	}
	return root
}

func derOf(certificate tls.Certificate) []byte {
	if len(certificate.Certificate) == 0 {
		return nil
	}
	return certificate.Certificate[0]
}

func TestGeneratedRootHasTheDocumentedShape(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	certificate := root.Certificate

	key, ok := root.Signer.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("root signer is %T, want RSA", root.Signer)
	}
	if key.N.BitLen() != RootKeyBits {
		t.Fatalf("root key is %d bits, want %d", key.N.BitLen(), RootKeyBits)
	}
	if certificate.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("root signature algorithm is %v, want SHA256WithRSA", certificate.SignatureAlgorithm)
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid {
		t.Fatal("root is not a CA with basic constraints")
	}
	if certificate.KeyUsage != x509.KeyUsageCertSign {
		t.Fatalf("root key usage is %v, want keyCertSign only", certificate.KeyUsage)
	}
	if err := certificate.CheckSignatureFrom(certificate); err != nil {
		t.Fatalf("root is not self-signed: %v", err)
	}
	// The subject key id is what a leaf's authority key id points at, so a
	// client can build the leaf-to-root path.
	if len(certificate.SubjectKeyId) == 0 {
		t.Fatal("root has no subject key id")
	}
	if serial := certificate.SerialNumber; serial == nil || serial.Sign() <= 0 || len(serial.Bytes()) > 20 {
		t.Fatalf("root serial is %v, want a positive value of at most 20 octets", serial)
	}
	if !strings.HasPrefix(certificate.Subject.CommonName, rootCommonPrefix) {
		t.Fatalf("root CN is %q, want the %q prefix", certificate.Subject.CommonName, rootCommonPrefix)
	}
	if len(certificate.Subject.Organization) != 1 || certificate.Subject.Organization[0] != rootOrganization {
		t.Fatalf("root organization is %v", certificate.Subject.Organization)
	}
	if certificate.NotBefore.After(now) || !certificate.NotAfter.After(now) {
		t.Fatalf("root window is %v..%v with now %v", certificate.NotBefore, certificate.NotAfter, now)
	}
	if lifetime := certificate.NotAfter.Sub(certificate.NotBefore); lifetime != RootValidity+ClockSkew {
		t.Fatalf("root lifetime is %v, want %v", lifetime, RootValidity+ClockSkew)
	}
	// Two installs must not share a CA, and the serial must not be a clock
	// reading: this checks the generator, not a second key generation.
	other, code := randomSerial()
	if code != engine.OK {
		t.Fatalf("randomSerial = %v", code)
	}
	if other.Cmp(certificate.SerialNumber) == 0 {
		t.Fatal("two serials generated back to back are equal")
	}
}

func TestExportRoundTripsThroughTheStartValidation(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	certificateDER, privateKeyPKCS8, code := root.Export()
	if code != engine.OK {
		t.Fatalf("Export = %v", code)
	}
	if !bytes.Equal(certificateDER, root.CertificateDER()) {
		t.Fatal("exported certificate is not the CA certificate")
	}
	// This is the exact validation la_tls_start applies to a CA handed back in,
	// so a generated CA must pass it rather than fail at the next start.
	material, code := engine.ParseMaterial(certificateDER, privateKeyPKCS8, now)
	if code != engine.OK {
		t.Fatalf("engine.ParseMaterial rejected generated material: %v", code)
	}
	if !material.Certificate.Equal(root.Certificate) {
		t.Fatal("re-parsed certificate differs from the generated one")
	}
	var publicFromKey []byte
	exported, err := x509.ParsePKCS8PrivateKey(privateKeyPKCS8)
	if err != nil {
		t.Fatalf("exported key does not parse: %v", err)
	}
	signer, ok := exported.(crypto.Signer)
	if !ok {
		t.Fatalf("exported key is %T, not a signer", exported)
	}
	if publicFromKey, err = x509.MarshalPKIXPublicKey(signer.Public()); err != nil {
		t.Fatalf("exported key public part: %v", err)
	}
	if !bytes.Equal(publicFromKey, root.Certificate.RawSubjectPublicKeyInfo) {
		t.Fatal("exported key does not belong to the exported certificate")
	}
	// A corrupted key must not be accepted as the CA key.
	tampered := append([]byte(nil), privateKeyPKCS8...)
	tampered[len(tampered)-1] ^= 0xff
	if _, code := engine.ParseMaterial(certificateDER, tampered, now); code == engine.OK {
		t.Fatal("a tampered private key was accepted as CA material")
	}
}

func TestLeafForADNSNameHasTheDocumentedShape(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	leaf, code := root.Leaf("leaf.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	certificate := leaf.Leaf
	if certificate == nil {
		t.Fatal("leaf certificate is not parsed")
	}
	key, ok := leaf.PrivateKey.(*ecdsa.PrivateKey)
	if !ok {
		t.Fatalf("leaf key is %T, want ECDSA", leaf.PrivateKey)
	}
	if key.Curve != elliptic.P256() {
		t.Fatal("leaf key is not P-256")
	}
	if certificate.IsCA || !certificate.BasicConstraintsValid {
		t.Fatal("leaf must set basic constraints and not be a CA")
	}
	if certificate.KeyUsage != x509.KeyUsageDigitalSignature {
		t.Fatalf("leaf key usage is %v, want digitalSignature only", certificate.KeyUsage)
	}
	if len(certificate.ExtKeyUsage) != 1 || certificate.ExtKeyUsage[0] != x509.ExtKeyUsageServerAuth {
		t.Fatalf("leaf extended key usage is %v, want serverAuth only", certificate.ExtKeyUsage)
	}
	if len(certificate.DNSNames) != 1 || certificate.DNSNames[0] != "leaf.fixture.test" {
		t.Fatalf("leaf SAN is %v", certificate.DNSNames)
	}
	if len(certificate.IPAddresses) != 0 {
		t.Fatalf("a DNS leaf carries IP SANs: %v", certificate.IPAddresses)
	}
	if certificate.Subject.CommonName != "leaf.fixture.test" {
		t.Fatalf("leaf CN is %q", certificate.Subject.CommonName)
	}
	// The path the client builds is leaf -> root, named by the root's key id.
	if !bytes.Equal(certificate.AuthorityKeyId, root.Certificate.SubjectKeyId) {
		t.Fatal("leaf authority key id does not name the root")
	}
	if err := certificate.CheckSignatureFrom(root.Certificate); err != nil {
		t.Fatalf("leaf is not signed by the root: %v", err)
	}
	if err := certificate.VerifyHostname("leaf.fixture.test"); err != nil {
		t.Fatalf("leaf does not prove its own name: %v", err)
	}
	if err := certificate.VerifyHostname("other.fixture.test"); err == nil {
		t.Fatal("leaf proves a name it was not minted for")
	}
	if certificate.NotBefore.Before(root.Certificate.NotBefore) || certificate.NotBefore.After(now) {
		t.Fatalf("leaf NotBefore is %v", certificate.NotBefore)
	}
	if !certificate.NotAfter.After(now) || certificate.NotAfter.After(root.Certificate.NotAfter) {
		t.Fatalf("leaf NotAfter is %v", certificate.NotAfter)
	}
	if lifetime := certificate.NotAfter.Sub(certificate.NotBefore); lifetime > LeafValidity {
		t.Fatalf("leaf lifetime is %v, want at most %v", lifetime, LeafValidity)
	}
	if serial := certificate.SerialNumber; serial == nil || serial.Sign() <= 0 || len(serial.Bytes()) > 20 {
		t.Fatalf("leaf serial is %v", serial)
	}
}

func TestLeafForAnAddressUsesTheIPSAN(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	for _, address := range []string{"127.0.0.1", "2606:4700:4700::1111"} {
		leaf, code := root.Leaf(address, ECDSAP256, now)
		if code != engine.OK {
			t.Fatalf("Leaf(%q) = %v", address, code)
		}
		certificate := leaf.Leaf
		if len(certificate.IPAddresses) != 1 || !certificate.IPAddresses[0].Equal(net.ParseIP(address)) {
			t.Fatalf("Leaf(%q) SAN IPs are %v", address, certificate.IPAddresses)
		}
		if len(certificate.DNSNames) != 0 {
			t.Fatalf("Leaf(%q) also carries DNS SANs: %v", address, certificate.DNSNames)
		}
		if err := certificate.VerifyHostname(address); err != nil {
			t.Fatalf("Leaf(%q) does not prove its own address: %v", address, err)
		}
		if err := certificate.VerifyHostname("127.0.0.2"); err == nil {
			t.Fatalf("Leaf(%q) proves another address", address)
		}
	}
}

func TestLeafNameIsCanonicalInTheCertificate(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	// The certificate and the cache both use the canonical form, so the SAN is
	// never a name a client would have to compare case-insensitively.
	leaf, code := root.Leaf("UPPER.Fixture.Test.", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if got := leaf.Leaf.DNSNames; len(got) != 1 || got[0] != "upper.fixture.test" {
		t.Fatalf("SAN is %v, want the canonical name", got)
	}
	if err := leaf.Leaf.VerifyHostname("upper.fixture.test"); err != nil {
		t.Fatalf("canonical SAN does not verify: %v", err)
	}
}

func TestLeafLongNameKeepsTheSANAndOmitsTheCommonName(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	name := strings.Repeat("a", 60) + "." + strings.Repeat("b", 60) + ".example.test"
	if len(name) <= MaxCommonNameLength {
		t.Fatalf("test name %q is not longer than the CN limit", name)
	}
	leaf, code := root.Leaf(name, ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if got := leaf.Leaf.DNSNames; len(got) != 1 || got[0] != name {
		t.Fatalf("SAN is %v, want the full name", got)
	}
	if leaf.Leaf.Subject.CommonName != "" {
		t.Fatalf("an over-long CN was written as %q instead of omitted", leaf.Leaf.Subject.CommonName)
	}
	// An empty subject is legal and the SAN is what decides.
	if err := leaf.Leaf.VerifyHostname(name); err != nil {
		t.Fatalf("leaf does not prove its own name: %v", err)
	}
}

func TestLeafRSAUsesARSA2048Key(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	leaf, code := root.Leaf("rsa.fixture.test", RSA2048, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	key, ok := leaf.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("leaf key is %T, want RSA", leaf.PrivateKey)
	}
	if key.N.BitLen() != LeafRSAKeyBits {
		t.Fatalf("leaf key is %d bits, want %d", key.N.BitLen(), LeafRSAKeyBits)
	}
	want := x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if leaf.Leaf.KeyUsage != want {
		t.Fatalf("RSA leaf key usage is %v, want %v", leaf.Leaf.KeyUsage, want)
	}
	if leaf.Leaf.SignatureAlgorithm != x509.SHA256WithRSA {
		t.Fatalf("leaf signature algorithm is %v", leaf.Leaf.SignatureAlgorithm)
	}
	if err := leaf.Leaf.CheckSignatureFrom(root.Certificate); err != nil {
		t.Fatalf("RSA leaf is not signed by the root: %v", err)
	}
}

// TestLeafKeysAreIndependent pins that no private key is reused: not the CA's,
// not another leaf's.
func TestLeafKeysAreIndependent(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	first, code := root.Leaf("one.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	second, code := root.Leaf("two.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if first.PrivateKey == root.Signer {
		t.Fatal("a leaf reused the CA signer")
	}
	firstPublic, _ := x509.MarshalPKIXPublicKey(first.PrivateKey.(crypto.Signer).Public())
	rootPublic, _ := x509.MarshalPKIXPublicKey(root.Signer.Public())
	if bytes.Equal(firstPublic, rootPublic) {
		t.Fatal("a leaf reused the CA public key")
	}
	secondPublic, _ := x509.MarshalPKIXPublicKey(second.PrivateKey.(crypto.Signer).Public())
	if bytes.Equal(firstPublic, secondPublic) {
		t.Fatal("two leaves share a key")
	}
	if bytes.Equal(derOf(first), derOf(second)) {
		t.Fatal("two leaves for different names are the same certificate")
	}
	if first.Leaf.SerialNumber.Cmp(second.Leaf.SerialNumber) == 0 {
		t.Fatal("two leaves share a serial")
	}
}

func TestLeafRejectsAnUnusableNameOrAlgorithm(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	for _, test := range []struct {
		caseName  string
		name      string
		algorithm LeafAlgorithm
		code      engine.Code
	}{
		{"empty name", "", ECDSAP256, engine.InvalidArgument},
		{"dot only", ".", ECDSAP256, engine.InvalidArgument},
		{"wildcard", "*.fixture.test", ECDSAP256, engine.InvalidArgument},
		{"port", "fixture.test:443", ECDSAP256, engine.InvalidArgument},
		{"bracketed address", "[::1]", ECDSAP256, engine.InvalidArgument},
		{"non ascii", "café.test", ECDSAP256, engine.InvalidArgument},
		{"zero algorithm", "one.fixture.test", 0, engine.InvalidArgument},
		{"unknown algorithm", "one.fixture.test", LeafAlgorithm(99), engine.InvalidArgument},
	} {
		leaf, code := root.Leaf(test.name, test.algorithm, now)
		if code != test.code || derOf(leaf) != nil {
			t.Fatalf("%s: Leaf = %v, %v; want %v and no certificate", test.caseName, leaf, code, test.code)
		}
	}
	// A missing CA is never a signed certificate.
	var missing *Root
	if leaf, code := missing.Leaf("one.fixture.test", ECDSAP256, now); code != engine.NotReady || derOf(leaf) != nil {
		t.Fatalf("Leaf without a CA = %v, %v; want NOT_READY", leaf, code)
	}
}

func TestLeafOutsideTheRootWindowIsStale(t *testing.T) {
	root := testRoot(t)
	for _, test := range []struct {
		caseName string
		now      time.Time
	}{
		{"root not yet valid", root.Certificate.NotBefore.Add(-time.Second)},
		{"root already expired", root.Certificate.NotAfter},
		{"root expired long ago", root.Certificate.NotAfter.Add(48 * time.Hour)},
	} {
		if leaf, code := root.Leaf("window.fixture.test", ECDSAP256, test.now); code != engine.StaleGeneration || derOf(leaf) != nil {
			t.Fatalf("%s: Leaf = %v, %v; want STALE_GENERATION", test.caseName, leaf, code)
		}
	}
}

func TestLeafNeverOutlivesTheRoot(t *testing.T) {
	now := testNow()
	root := rootExpiringAt(t, now.Add(time.Hour))
	leaf, code := root.Leaf("soon.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if !leaf.Leaf.NotAfter.Equal(root.Certificate.NotAfter) {
		t.Fatalf("leaf NotAfter is %v, want the root's %v", leaf.Leaf.NotAfter, root.Certificate.NotAfter)
	}
	if leaf.Leaf.NotAfter.Sub(leaf.Leaf.NotBefore) > LeafValidity {
		t.Fatal("leaf lifetime exceeds the configured maximum")
	}
	if err := leaf.Leaf.CheckSignatureFrom(root.Certificate); err != nil {
		t.Fatalf("leaf is not signed by the root: %v", err)
	}
}

// TestLeafCompletesARealClientHandshake is the strongest available statement
// that the SAN, the signature, the key usage and the chain are correct: a real
// crypto/tls client that trusts only this root completes a handshake with the
// leaf, for both supported versions, for a DNS name and for an IP literal.
func TestLeafCompletesARealClientHandshake(t *testing.T) {
	now := testNow()
	root := testRoot(t)
	pool := x509.NewCertPool()
	pool.AddCert(root.Certificate)

	for _, test := range []struct {
		caseName string
		name     string
		version  uint16
	}{
		{"tls12 dns", "handshake.fixture.test", tls.VersionTLS12},
		{"tls13 dns", "handshake.fixture.test", tls.VersionTLS13},
		{"tls13 address", "127.0.0.1", tls.VersionTLS13},
	} {
		leaf, code := root.Leaf(test.name, ECDSAP256, now)
		if code != engine.OK {
			t.Fatalf("%s: Leaf = %v", test.caseName, code)
		}
		server := startProbeServer(t, leaf, test.version)
		state, err := dialProbe(t, server.address, test.name, pool, test.version)
		if err != nil {
			t.Fatalf("%s: a client trusting the root rejected the leaf: %v", test.caseName, err)
		}
		if len(state.PeerCertificates) == 0 || state.PeerCertificates[0].Subject.CommonName != test.name {
			t.Fatalf("%s: the client saw %v", test.caseName, state.PeerCertificates)
		}
		if state.Version != test.version {
			t.Fatalf("%s: negotiated %x, want %x", test.caseName, state.Version, test.version)
		}
		server.waitForHandshake(t)
	}

	// A client that does not trust this CA must fail: the leaf is not a
	// self-sufficient identity.
	leaf, code := root.Leaf("handshake.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	server := startProbeServer(t, leaf, tls.VersionTLS13)
	other, code := GenerateRoot(now)
	if code != engine.OK {
		t.Fatalf("GenerateRoot = %v", code)
	}
	otherPool := x509.NewCertPool()
	otherPool.AddCert(other.Certificate)
	if _, err := dialProbe(t, server.address, "handshake.fixture.test", otherPool, tls.VersionTLS13); err == nil {
		t.Fatal("a client trusting a different root accepted the leaf")
	}
}

// probeServer serves one leaf and counts completed handshakes. It never fails
// the test from its own goroutine.
type probeServer struct {
	address   string
	completed int32
}

func startProbeServer(t *testing.T, certificate tls.Certificate, version uint16) *probeServer {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	server := &probeServer{address: listener.Addr().String()}
	config := &tls.Config{Certificates: []tls.Certificate{certificate}, MinVersion: version, MaxVersion: version}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				if tls.Server(conn, config).Handshake() == nil {
					atomic.AddInt32(&server.completed, 1)
				}
			}()
		}
	}()
	t.Cleanup(func() { listener.Close() })
	return server
}

// waitForHandshake waits for the server half to finish, which may lag the
// client's return by one flight.
func (p *probeServer) waitForHandshake(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		if atomic.LoadInt32(&p.completed) > 0 {
			return
		}
		time.Sleep(5 * time.Millisecond)
	}
	t.Fatal("the server never completed a handshake")
}

func dialProbe(t *testing.T, address, name string, roots *x509.CertPool, version uint16) (tls.ConnectionState, error) {
	t.Helper()
	conn, err := tls.Dial("tcp", address, &tls.Config{
		RootCAs:    roots,
		ServerName: name,
		MinVersion: version,
		MaxVersion: version,
	})
	if err != nil {
		return tls.ConnectionState{}, err
	}
	defer conn.Close()
	return conn.ConnectionState(), nil
}

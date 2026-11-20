package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"math/big"
	"net"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// Root is one capture CA: the certificate the user installs as a trust anchor
// and the signer that mints its leaves.
//
// It is immutable once handed out by GenerateRoot or adopted by Store.SetRoot.
// Generation is assigned by the Store that owns it and changes on every CA
// replacement, which is what invalidates cached leaves.
type Root struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
	Generation  uint64
}

// GenerateRoot mints a fresh CA: RSA 3072, SHA-256, a random positive serial, a
// three-year validity, CA=true with keyCertSign, and a short random tag in the
// CN so a reset CA is distinguishable in the system trust list.
//
// The result satisfies the same invariants engine.ParseMaterial enforces when a
// CA is passed back in through la_tls_start, and that is checked here before the
// root is returned rather than discovered at the next start.
func GenerateRoot(now time.Time) (*Root, engine.Code) {
	key, err := rsa.GenerateKey(rand.Reader, RootKeyBits)
	if err != nil {
		return nil, engine.IOError
	}
	serial, code := randomSerial()
	if code != engine.OK {
		return nil, code
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   rootCommonPrefix + serialTag(serial),
			Organization: []string{rootOrganization},
		},
		NotBefore: now.Add(-ClockSkew),
		NotAfter:  now.Add(RootValidity),
		// CertSign is the whole authority of this key: it signs leaves and
		// nothing else. No CRL, no OCSP and no path length are claimed beyond
		// what design §7.1 lists.
		KeyUsage:              x509.KeyUsageCertSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, engine.IOError
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, engine.IOError
	}
	if code := validRoot(certificate, key); code != engine.OK {
		return nil, code
	}
	return &Root{Certificate: certificate, Signer: key}, engine.OK
}

// CertificateDER is the public CA certificate, which may be shown, exported and
// carried in the start call. It borrows the parsed certificate's bytes and must
// not be modified.
func (r *Root) CertificateDER() []byte {
	if r == nil || r.Certificate == nil {
		return nil
	}
	return r.Certificate.Raw
}

// Export returns the two independent buffers the C ABI hands to the caller: the
// CA certificate in DER and the CA private key in PKCS#8. It is the only way a
// CA key leaves this package, and it leaves as bytes — never as JSON, PEM or a
// Go pointer, and never together with a leaf key.
//
// The caller owns both buffers and must release them separately.
func (r *Root) Export() ([]byte, []byte, engine.Code) {
	if r == nil || r.Certificate == nil || r.Signer == nil {
		return nil, nil, engine.NotReady
	}
	privateKey, err := x509.MarshalPKCS8PrivateKey(r.Signer)
	if err != nil || len(privateKey) == 0 {
		return nil, nil, engine.IOError
	}
	return r.Certificate.Raw, privateKey, engine.OK
}

// Leaf mints one leaf for a name, without caching it; callers normally go
// through Store.Leaf, which adds the per-name cache and the CA generation.
func (r *Root) Leaf(name string, algorithm LeafAlgorithm, now time.Time) (tls.Certificate, engine.Code) {
	canonical, code := CanonicalName(name)
	if code != engine.OK {
		return tls.Certificate{}, code
	}
	return r.issue(canonical, algorithm, now)
}

// issue signs one leaf for an already canonical name. The returned certificate
// is the leaf alone: the client already holds the root as its trust anchor, and
// echoing a self-signed root back at it would only make the capture look more
// like a real server chain than it is.
func (r *Root) issue(canonical string, algorithm LeafAlgorithm, now time.Time) (tls.Certificate, engine.Code) {
	if r == nil || r.Certificate == nil || r.Signer == nil {
		return tls.Certificate{}, engine.NotReady
	}
	if now.Before(r.Certificate.NotBefore) || !now.Before(r.Certificate.NotAfter) {
		// The CA itself is outside its validity window, so every leaf minted
		// from it would be untrustworthy: report the stored material as stale
		// instead of signing something a client must reject.
		return tls.Certificate{}, engine.StaleGeneration
	}
	key, code := newLeafKey(algorithm)
	if code != engine.OK {
		return tls.Certificate{}, code
	}
	serial, code := randomSerial()
	if code != engine.OK {
		return tls.Certificate{}, code
	}
	notBefore := now.Add(-ClockSkew)
	if notBefore.Before(r.Certificate.NotBefore) {
		notBefore = r.Certificate.NotBefore
	}
	notAfter := notBefore.Add(LeafValidity)
	if notAfter.After(r.Certificate.NotAfter) {
		// Never later than the root, whatever the requested lifetime.
		notAfter = r.Certificate.NotAfter
	}
	if !notAfter.After(notBefore) {
		return tls.Certificate{}, engine.StaleGeneration
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		NotBefore:    notBefore,
		NotAfter:     notAfter,
		KeyUsage:     keyUsageFor(algorithm),
		// serverAuth only: this leaf is a TLS server identity and nothing else.
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
		SignatureAlgorithm:    x509.SHA256WithRSA,
	}
	if len(canonical) <= MaxCommonNameLength {
		template.Subject = pkix.Name{CommonName: canonical}
	}
	if address := addressOf(canonical); address != nil {
		template.IPAddresses = []net.IP{address}
	} else {
		template.DNSNames = []string{canonical}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, r.Certificate, key.Public(), r.Signer)
	if err != nil {
		return tls.Certificate{}, engine.IOError
	}
	leaf, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, engine.IOError
	}
	// A leaf is only useful if it proves the name it was minted for, so check
	// it with the same routine a client uses instead of trusting the template
	// just built. The CN is a display field: the SAN decides.
	if err := leaf.VerifyHostname(canonical); err != nil {
		return tls.Certificate{}, engine.IOError
	}
	return tls.Certificate{Certificate: [][]byte{leaf.Raw}, PrivateKey: key, Leaf: leaf}, engine.OK
}

// validRoot is the invariant a root must satisfy before leaves may be signed
// with it. It mirrors engine.ParseMaterial, minus the validity window: the
// window is the CA's own property and is checked per issuance, so a root that
// expires mid-capture stops minting instead of silently minting leaves nobody
// can trust.
func validRoot(certificate *x509.Certificate, signer crypto.Signer) engine.Code {
	if certificate == nil || signer == nil {
		return engine.InvalidArgument
	}
	if !certificate.IsCA || !certificate.BasicConstraintsValid ||
		certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
		return engine.InvalidArgument
	}
	if certificate.CheckSignatureFrom(certificate) != nil {
		return engine.InvalidArgument
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, certificate.RawSubjectPublicKeyInfo) {
		return engine.InvalidArgument
	}
	return engine.OK
}

// newLeafKey generates the leaf's own key pair. A leaf never reuses the CA key
// and never reuses another leaf's key.
func newLeafKey(algorithm LeafAlgorithm) (crypto.Signer, engine.Code) {
	switch algorithm {
	case ECDSAP256:
		key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
		if err != nil {
			return nil, engine.IOError
		}
		return key, engine.OK
	case RSA2048:
		key, err := rsa.GenerateKey(rand.Reader, LeafRSAKeyBits)
		if err != nil {
			return nil, engine.IOError
		}
		return key, engine.OK
	default:
		return nil, engine.InvalidArgument
	}
}

// keyUsageFor is the RFC 5280 key usage of the leaf: an ECDSA key signs, an RSA
// key signs and may also be used for key transport, which is what a TLS 1.2
// client offering an RSA key-exchange cipher suite requires.
func keyUsageFor(algorithm LeafAlgorithm) x509.KeyUsage {
	switch algorithm {
	case RSA2048:
		return x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	default:
		return x509.KeyUsageDigitalSignature
	}
}

// randomSerial returns a positive random serial. The top bit is cleared so the
// DER INTEGER is positive, and a zero value is redrawn rather than patched.
func randomSerial() (*big.Int, engine.Code) {
	buffer := make([]byte, serialBytes)
	for attempt := 0; attempt < 8; attempt++ {
		if _, err := rand.Read(buffer); err != nil {
			return nil, engine.IOError
		}
		buffer[0] &= 0x7f
		if serial := new(big.Int).SetBytes(buffer); serial.Sign() > 0 {
			return serial, engine.OK
		}
	}
	return nil, engine.IOError
}

// serialTag is the short CN suffix that distinguishes one installed CA from the
// next. It is derived from the serial, so it is as unpredictable as the CA.
func serialTag(serial *big.Int) string {
	bytes := serial.Bytes()
	if len(bytes) > 3 {
		bytes = bytes[len(bytes)-3:]
	}
	return hex.EncodeToString(bytes)
}

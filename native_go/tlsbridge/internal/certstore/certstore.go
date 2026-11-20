// Package certstore mints and caches the certificates the downstream TLS side
// presents to the captured application.
//
// It is pure Go cryptography over crypto/rand and crypto/x509: no network, no
// JNI, no platform callback, so it runs on the ABI thread that has no JNI
// environment and is testable on the host. The CA private key is never
// serialized into JSON and never crosses the ABI as text; the one binary export
// (Root.Export) exists for TLS-206 to encrypt at rest in the C06 container, and
// the two buffers it returns are owned and freed separately by the caller.
//
// Lifecycle (design §7.1):
//
//   - The CA is generated once per install (GenerateRoot) and persisted by the
//     Kotlin half; a Store adopts that same CA at engine start (SetRoot) so
//     every leaf of a capture chains to the root the user actually installed.
//     Generation is deliberately not shared between devices or stored in the
//     repository.
//   - Leaves are minted per name and cached on (canonical name, algorithm, CA
//     generation), bounded by MaxCapacity with LRU eviction. Replacing the CA
//     drops the whole leaf cache in the same step, so no leaf can outlive the
//     root it was signed by.
//   - A leaf private key is generated per leaf and never reuses the CA key.
//     Leaves stay in Go memory: nothing in this package hands a leaf key out.
//
// This package decides nothing about whether a connection may be intercepted
// (TLS-208) and performs no handshake (TLS-209); it only answers "which leaf
// proves this name under this CA".
package certstore

import (
	"crypto/tls"
	"net"
	"strings"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

const (
	// RootKeyBits is design §7.1's RSA 3072 root.
	RootKeyBits = 3072
	// RootValidity is design §7.1's three-year root lifetime.
	RootValidity = 3 * 365 * 24 * time.Hour
	// LeafValidity is design §7.1's 24-hour leaf lifetime. It is a ceiling: a
	// leaf never outlives the root either (issue clamps to the root's NotAfter).
	LeafValidity = 24 * time.Hour
	// LeafRSAKeyBits is design §7.1's RSA leaf size.
	LeafRSAKeyBits = 2048
	// ClockSkew backdates NotBefore so a client clock slightly behind the
	// generating device still accepts the certificate. Design §7.1 allows a
	// small skew; this is that allowance and nothing more.
	ClockSkew = 5 * time.Minute
	// DefaultCapacity and MaxCapacity are design §7.1's 256-entry leaf cache.
	// The ceiling is permanent: a capacity outside 1..MaxCapacity falls back to
	// DefaultCapacity rather than raising it.
	DefaultCapacity = 256
	MaxCapacity     = 256
	// MaxCommonNameLength is RFC 5280's upper bound for a CN. A longer name is
	// still usable, because the SAN is authoritative and is always set; the CN
	// is then simply omitted instead of being truncated into a wrong name.
	MaxCommonNameLength = 64
	// MaxSignatureSchemes bounds one ClientHello's signature_algorithms list. A
	// real client sends around ten; the ceiling exists so a malformed or hostile
	// list cannot turn leaf selection into unbounded work.
	MaxSignatureSchemes = 256
	// serialBytes is the random serial length. RFC 5280 caps a serial at 20
	// octets; 128 random bits keep collisions negligible without a counter,
	// which is the point: a timestamp or a counter is predictable.
	serialBytes = 16
	// rootOrganization and the CN tag identify the CA in the system trust list
	// so a user can tell a reset CA from a previous one (design §7.3).
	rootOrganization = "LayerAnalyzer"
	rootCommonPrefix = "LayerAnalyzer Capture CA "
)

// LeafAlgorithm is the leaf key family chosen from the client's advertised
// signature algorithms (TLS-207). The zero value is invalid on purpose: a leaf
// is only ever minted for an explicitly selected family, never by default.
type LeafAlgorithm uint8

const (
	// ECDSAP256 is an ECDSA P-256 leaf, the preferred family: it is accepted by
	// every client that advertises ecdsa_secp256r1_sha256, and signing with it
	// costs no RSA key generation on the device.
	ECDSAP256 LeafAlgorithm = iota + 1
	// RSA2048 is the fallback for clients that advertise only RSA schemes.
	RSA2048
)

func (a LeafAlgorithm) String() string {
	switch a {
	case ECDSAP256:
		return "ECDSA_P256"
	case RSA2048:
		return "RSA_2048"
	default:
		// Never report a family this package cannot actually mint.
		return "INVALID"
	}
}

// SelectAlgorithm picks the leaf key family for one connection from the
// signature algorithms the client offered. ECDSA P-256 wins when the client
// offers ecdsa_secp256r1_sha256, because the leaf then needs no RSA key
// generation; RSA 2048 is used only when the client offers no P-256 signature
// but does offer an RSA one.
//
// An empty list is not "no preference": TLS 1.2 without signature_algorithms
// means SHA-1 schemes (RFC 5246 §7.4.1.4.1), which this proxy does not sign
// with, and every other case with no usable scheme is a client this version
// cannot intercept. Both are UNSUPPORTED rather than a guess, so a connection
// is never handed a leaf whose key type its own hello excluded.
//
// This reads signature algorithms only. A client that offers an RSA-only cipher
// suite while advertising an ECDSA scheme would have to be given an RSA leaf,
// which needs its cipher suites; TLS-207 can extend the input when such a
// client is actually observed.
func SelectAlgorithm(schemes []tls.SignatureScheme) (LeafAlgorithm, engine.Code) {
	if len(schemes) == 0 {
		return 0, engine.Unsupported
	}
	if len(schemes) > MaxSignatureSchemes {
		return 0, engine.InvalidArgument
	}
	p256, rsa := false, false
	for _, scheme := range schemes {
		switch scheme {
		case tls.ECDSAWithP256AndSHA256:
			p256 = true
		case tls.PSSWithSHA256, tls.PSSWithSHA384, tls.PSSWithSHA512,
			tls.PKCS1WithSHA256, tls.PKCS1WithSHA384, tls.PKCS1WithSHA512:
			rsa = true
		}
	}
	switch {
	case p256:
		return ECDSAP256, engine.OK
	case rsa:
		return RSA2048, engine.OK
	default:
		// SHA-1 and EdDSA-only clients: recognised, deliberately not supported.
		return 0, engine.Unsupported
	}
}

// CanonicalName is the SAN and cache-key spelling of a leaf name: the shared
// engine.CanonicalName rule plus the lower-casing design C04 requires, so
// "EXAMPLE.test", "example.test" and "example.test." are one certificate
// instead of three. An IP literal is lower-cased too (its hexadecimal digits
// only), which keeps the comparison exact rather than case-insensitive.
//
// It rejects anything that cannot be a name or an IP literal — empty labels,
// ports, wildcards, brackets, non-ASCII, control characters and over-long
// names — so a certificate is never minted for input the upstream half would
// refuse to verify.
func CanonicalName(name string) (string, engine.Code) {
	canonical, code := engine.CanonicalName(name)
	if code != engine.OK {
		return "", code
	}
	return strings.ToLower(canonical), engine.OK
}

// addressOf reports the IP literal a canonical name denotes, or nil for a DNS
// name. A name shaped like an invalid address ("1.2.3.256") is a DNS name, which
// is what the upstream half does with it as well.
func addressOf(canonical string) net.IP {
	return net.ParseIP(canonical)
}

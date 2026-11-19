// Package tlsproxy owns the production single-connection TLS proxy: the
// ClientHello classifier, the interception decision, the two-sided handshake,
// the bounded relay and the per-connection state machine.
//
// TLS-204 adds the part that decides whether an intercepted connection may
// continue at all: upstream chain and name verification. The trust decision is
// delegated to the device's own trust store, which Go cannot read, so the only
// upstream TLS configuration this package can produce is the one
// NewUpstreamTLSConfig returns. InsecureSkipVerify is set in exactly that
// constructor and only there, and only to hand the decision to a
// VerifyConnection that runs on every handshake and always ends in an explicit
// platform answer: no exported switch, no "ignore certificate" path, and no
// config from here without the mandatory callback.
//
// TLS-207 adds the classifier that runs before any of that: it decides whether
// the stream opens with a ClientHello this engine can serve, and keeps every
// byte it read in a PrefixConn so the same bytes reach either crypto/tls or an
// unchanged passthrough. It holds no policy and closes nothing.
package tlsproxy

import (
	"crypto/tls"
	"crypto/x509"
	"errors"
	"net"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

const (
	// MaxPeerCertificates and MaxCertificateBytes mirror the C05 ABI limits:
	// exceeding either one would be rejected as INVALID_ARGUMENT inside the JNI
	// trampoline, so the same limits are enforced here first and reported as a
	// typed failure instead.
	MaxPeerCertificates = 16
	MaxCertificateBytes = 65536
	// MaxIdentityLength is the DNS name limit and the ABI's identity buffer. It
	// is engine.MaxNameLength: the identity, the policy target and the leaf SAN
	// are the same string, so they share one limit.
	MaxIdentityLength = engine.MaxNameLength
	// MaxLabelLength is the maximum DNS label length.
	MaxLabelLength = engine.MaxLabelLength
)

// Gate is the admission-gated platform entry point of C05. *engine.Callbacks
// implements it: once shutdown has closed admission a call returns CANCELLED
// without entering the platform, and shutdown waits for an in-flight call to
// return before the caller releases its JNI GlobalRef.
type Gate interface {
	Call(func(engine.Platform) engine.Code) engine.Code
}

var _ Gate = (*engine.Callbacks)(nil)

// Failure is a typed upstream verification failure carrying the fixed C05 code.
// Its text is a constant: it never contains the identity, a certificate, DER
// bytes or platform exception text.
type Failure struct {
	Code   engine.Code
	Reason string
}

func (f *Failure) Error() string { return f.Reason }

// FailureCode returns the C05 code of a verification failure. An error that did
// not come from this package maps to IO_ERROR, so a caller can never mistake an
// unclassified error for a certificate verdict.
func FailureCode(err error) engine.Code {
	var failure *Failure
	if errors.As(err, &failure) {
		return failure.Code
	}
	return engine.IOError
}

// UpstreamSpec is the frozen per-connection identity the upstream handshake
// must prove. It is built once from the ClientHello probe (TLS-209) and never
// re-derived from a later resolution result.
type UpstreamSpec struct {
	// Identity is the reference identity: the ClientHello SNI when the client
	// sent one, otherwise the original destination IP literal. One trailing dot
	// is removed; nothing else is rewritten.
	Identity string
	// MinVersion is the lowest acceptable negotiated version. tls.VersionTLS12
	// and tls.VersionTLS13 are the only supported values.
	MinVersion uint16
}

// NewUpstreamTLSConfig is the only constructor of an upstream TLS configuration
// in this package. It always installs VerifyConnection; there is no variant
// without it. The returned config is ready to hand to tls.Client once the
// upstream dial and the probe prefix are available (TLS-209).
func NewUpstreamTLSConfig(spec UpstreamSpec, gate Gate) (*tls.Config, engine.Code) {
	if gate == nil {
		return nil, engine.NotReady
	}
	if spec.MinVersion != tls.VersionTLS12 && spec.MinVersion != tls.VersionTLS13 {
		return nil, engine.Unsupported
	}
	identity, code := CanonicalIdentity(spec.Identity)
	if code != engine.OK {
		return nil, code
	}
	config := &tls.Config{
		MinVersion: spec.MinVersion,
		MaxVersion: tls.VersionTLS13,
		ServerName: serverNameFor(identity),
		// Go's own chain verification is switched off only because the device's
		// trust store is the authority and Go cannot read it: on Android a
		// default client would verify against the host root pool and reject
		// every real upstream. VerifyConnection below is unconditional and is
		// the only thing that can accept the connection.
		InsecureSkipVerify: true,
		// The first version keeps no upstream cross-connection state and
		// accepts no 0-RTT, so one captured connection maps to exactly one
		// handshake and one set of downstream secrets (design §6.3).
		ClientSessionCache:     nil,
		SessionTicketsDisabled: true,
		VerifyConnection: func(state tls.ConnectionState) error {
			return verifyUpstream(state, identity, spec.MinVersion, gate)
		},
	}
	if code := validateUpstreamConfig(config); code != engine.OK {
		return nil, code
	}
	return config, engine.OK
}

// validateUpstreamConfig is the invariant every upstream configuration must
// satisfy before tls.Client may use it, and the reason a hand-built config
// cannot run as an upstream: a configuration with InsecureSkipVerify and no
// VerifyConnection would accept any certificate. TLS-209 calls this before
// starting a handshake.
func validateUpstreamConfig(config *tls.Config) engine.Code {
	if config == nil {
		return engine.NotReady
	}
	if config.VerifyConnection == nil {
		return engine.NotReady
	}
	if config.MinVersion < tls.VersionTLS12 {
		return engine.Unsupported
	}
	if !config.InsecureSkipVerify {
		return engine.InvalidArgument
	}
	if config.ClientSessionCache != nil || !config.SessionTicketsDisabled {
		return engine.InvalidArgument
	}
	if config.ServerName != "" {
		if _, code := CanonicalIdentity(config.ServerName); code != engine.OK {
			return code
		}
	}
	return engine.OK
}

// verifyUpstream is the mandatory VerifyConnection body. Order is deliberate:
// an absent chain, an unsupported negotiated version and a reference identity
// that the leaf does not prove all end the handshake before the platform is
// asked anything, and the platform answer is then final.
func verifyUpstream(state tls.ConnectionState, identity string, minVersion uint16, gate Gate) error {
	if gate == nil {
		return &Failure{Code: engine.NotReady, Reason: "no upstream verifier configured"}
	}
	if len(state.PeerCertificates) == 0 {
		return &Failure{Code: engine.UpstreamCertInvalid, Reason: "upstream certificate chain is empty"}
	}
	switch state.Version {
	case tls.VersionTLS12, tls.VersionTLS13:
	default:
		return &Failure{Code: engine.Unsupported, Reason: "unsupported upstream TLS version"}
	}
	if state.Version < minVersion {
		return &Failure{Code: engine.Unsupported, Reason: "upstream TLS version below the configured minimum"}
	}
	leaf := state.PeerCertificates[0]
	if leaf == nil {
		return &Failure{Code: engine.UpstreamCertInvalid, Reason: "upstream certificate chain is empty"}
	}
	// Name verification happens here and again inside the platform trust
	// manager; neither side is allowed to be the only check.
	if err := leaf.VerifyHostname(identity); err != nil {
		return &Failure{Code: engine.UpstreamCertInvalid, Reason: "upstream reference identity is not proven by the certificate"}
	}
	authType, code := authTypeFor(leaf)
	if code != engine.OK {
		return &Failure{Code: code, Reason: "unsupported upstream certificate key algorithm"}
	}
	chain, code := peerChain(state.PeerCertificates)
	if code != engine.OK {
		return &Failure{Code: code, Reason: "upstream certificate chain exceeds the ABI limit"}
	}
	version := versionName(state.Version)
	if version == "" {
		return &Failure{Code: engine.Unsupported, Reason: "unsupported upstream TLS version"}
	}
	if code := callVerifier(gate, chain, identity, authType, version); code != engine.OK {
		return &Failure{Code: code, Reason: "upstream certificate rejected by the platform trust manager"}
	}
	return nil
}

// callVerifier enters the platform through the admission gate so a shutdown can
// never race a released JNI GlobalRef, and treats a panic in the platform half
// as a failed verification rather than as a pass or a process exit.
func callVerifier(gate Gate, chain [][]byte, identity, authType, version string) (code engine.Code) {
	defer func() {
		if recover() != nil {
			code = engine.IOError
		}
	}()
	return gate.Call(func(platform engine.Platform) engine.Code {
		return platform.VerifyUpstream(chain, identity, authType, version)
	})
}

// peerChain converts the peer certificates into the ABI's leaf-first array of
// DER blocks, after checking both ABI limits.
func peerChain(certificates []*x509.Certificate) ([][]byte, engine.Code) {
	if len(certificates) == 0 || len(certificates) > MaxPeerCertificates {
		return nil, engine.InvalidArgument
	}
	chain := make([][]byte, len(certificates))
	for index, certificate := range certificates {
		if certificate == nil || len(certificate.Raw) == 0 || len(certificate.Raw) > MaxCertificateBytes {
			return nil, engine.InvalidArgument
		}
		chain[index] = certificate.Raw
	}
	return chain, engine.OK
}

// authTypeFor is the key algorithm family reported to the platform, in the
// JSSE spelling the Android verifier cross-checks against the same leaf. Both
// sides derive it from the certificate itself, so a disagreement means the two
// halves see different chains and the connection must not continue.
func authTypeFor(leaf *x509.Certificate) (string, engine.Code) {
	switch leaf.PublicKeyAlgorithm {
	case x509.RSA:
		return "RSA", engine.OK
	case x509.ECDSA:
		return "ECDSA", engine.OK
	case x509.DSA:
		return "DSA", engine.OK
	case x509.Ed25519:
		return "EDDSA", engine.OK
	default:
		return "", engine.Unsupported
	}
}

func versionName(version uint16) string {
	switch version {
	case tls.VersionTLS12:
		return "TLSv1.2"
	case tls.VersionTLS13:
		return "TLSv1.3"
	default:
		return ""
	}
}

// serverNameFor is the SNI this handshake sends: the reference identity for a
// DNS name and nothing at all for an IP literal, which RFC 6066 forbids as an
// SNI value and Go already omits for a ServerName that parses as an address.
func serverNameFor(identity string) string {
	if net.ParseIP(identity) != nil {
		return ""
	}
	return identity
}

// CanonicalIdentity validates the reference identity and removes one trailing
// dot, matching the name the Android side resolves. The rule itself lives in
// engine.CanonicalName because the leaf SAN and the policy matcher must not
// implement a variant of it; this spelling is kept for the upstream half.
// Case, IDNA and wildcard policy stay with TLS-208; nothing else is
// reinterpreted here, so an exact name, a bare IP literal, a port, a wildcard
// or a bracketed literal is either taken as given or rejected.
func CanonicalIdentity(identity string) (string, engine.Code) {
	return engine.CanonicalName(identity)
}

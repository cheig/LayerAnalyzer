// Two-sided TLS handshake (TLS-209, design §6.3, §6.4).
//
// One intercepted connection is two independent TLS handshakes, and this file
// performs them in the only order that cannot downgrade the client: the
// upstream handshake (TLS B) completes first, so the real server decides the
// application protocol, and only then is the downstream handshake (TLS A)
// started with exactly the protocol that origin selected. The two legs may use
// different TLS versions and ciphers, but they always carry one application
// protocol: relaying h2 bytes inside an http/1.1 connection would need an HTTP
// gateway, which this engine does not have.
//
// Nothing is written towards the client before TLS A starts, which is what makes
// the recorded downstream boundary a fact rather than an estimate, and a failed
// attempt never hands a connection back: the coordinator owns both transports
// and closes them on every failure. That is deliberate. By the time this
// coordinator runs the interception decision is final (§6.1), so a bypass can
// only ever apply to a later connection, never to this one (C03 5), and no
// application request is ever replayed towards the origin.

package tlsproxy

import (
	"context"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"sync/atomic"
	"time"

	"com.layeranalyzer/tlsbridge/internal/certstore"
	"com.layeranalyzer/tlsbridge/internal/engine"
)

// Handshake budgets (design §6.5, C10). Each side of one connection gets its
// own budget: the upstream TCP dial is bounded separately by uplink, and a
// caller that needs a bound on the whole connection passes a context deadline.
const (
	// DefaultHandshakeTimeout is C10's per-side TLS handshake budget.
	DefaultHandshakeTimeout = 10 * time.Second
	// MaxHandshakeTimeout is the ceiling on that budget. A caller may lower it
	// (a stopping engine, a test), never raise it: it is a resource budget, not
	// a preference, and the ceiling itself is not removable.
	MaxHandshakeTimeout = DefaultHandshakeTimeout
	// maxOfferedProtocols bounds the ALPN set copied onto a TLS configuration.
	// It is the classifier's own structural cap, so a list that reached the
	// probe cannot be rejected here for a reason the probe did not report.
	maxOfferedProtocols = maxALPNProtocols
	// maxProtocolLength is RFC 7301's ProtocolName limit: an opaque vector with
	// a one-byte length prefix.
	maxProtocolLength = 255
	// noApplicationProtocolAlert is the name crypto/tls prints for RFC 8446 §6's
	// no_application_protocol (120) alert. It is a name rather than a code
	// because crypto/tls gives no exported way to read an alert off a received
	// one: tls.AlertError exists but is only ever produced for QUIC, and a
	// non-QUIC alert reaches the caller as a *net.OpError wrapping the
	// unexported alert type — whose text is exactly this standard name.
	noApplicationProtocolAlert = "tls: no application protocol"
)

// Reason is the fixed reason code a failed handshake attempt ends with. Like the
// probe's reasons it is a constant that carries no stream bytes, no identity and
// no platform text, so it can go straight into a connection event.
type Reason string

// Failure reasons. Each one names where the attempt stopped, so the code alone
// never has to carry that information.
const (
	// ReasonNotReady: the coordinator was not assembled (no CA, no platform
	// gate).
	ReasonNotReady Reason = "handshake_not_ready"
	// ReasonInvalidInput: the caller handed over something this coordinator
	// cannot start from — a nil transport, no probe result, a probe result that
	// is not a ClientHello, or an identity that is not a usable name or address.
	ReasonInvalidInput Reason = "invalid_handshake_input"
	// ReasonInvalidOffer: the ClientHello's ALPN list cannot be put on a TLS
	// configuration.
	ReasonInvalidOffer Reason = "invalid_alpn_offer"
	// ReasonNoVersion: the hello offers no version this engine serves.
	ReasonNoVersion Reason = "no_supported_version"
	// ReasonNoSignatures: the hello's signature algorithms permit no leaf this
	// engine can mint.
	ReasonNoSignatures Reason = "unsupported_signature_algorithms"
	// ReasonUpstreamConfig: the upstream TLS configuration was refused (a nil
	// gate, an unsupported minimum version, an unusable identity).
	ReasonUpstreamConfig Reason = "upstream_config_rejected"
	// ReasonUpstreamVerification: the mandatory upstream verification ended the
	// handshake. The code carries the verdict (UPSTREAM_CERT_INVALID,
	// UNSUPPORTED, CANCELLED); the reason only says which step spoke.
	ReasonUpstreamVerification Reason = "upstream_verification_failed"
	// ReasonUpstreamALPN: the origin refused the ALPN set the client offered, so
	// there is no single protocol both legs could carry.
	ReasonUpstreamALPN Reason = "alpn_not_agreed"
	// ReasonUpstreamTimeout: the origin did not finish the handshake inside the
	// upstream budget.
	ReasonUpstreamTimeout Reason = "upstream_handshake_timeout"
	// ReasonUpstreamHandshake: the upstream handshake failed for a transport
	// reason.
	ReasonUpstreamHandshake Reason = "upstream_handshake_failed"
	// ReasonLeafUnavailable: the CA could not issue the downstream certificate.
	ReasonLeafUnavailable Reason = "downstream_leaf_unavailable"
	// ReasonDownstreamRejected is the legacy ambiguous reason: older engines
	// also emitted it for EOF/reset. New failures use the specific reasons below;
	// readers must not infer a trust verdict from this historical value.
	ReasonDownstreamRejected Reason = "downstream_handshake_rejected"
	// A remote TLS alert is evidence of a TLS refusal, not proof of pinning.
	// Keep the older, ambiguous reason above readable by older captures.
	ReasonDownstreamAlert Reason = "downstream_tls_alert"
	// EOF/reset cannot tell us whether the client evaluated our certificate.
	ReasonDownstreamClosed    Reason = "downstream_connection_closed"
	ReasonDownstreamHandshake Reason = "downstream_handshake_failed"
	// ReasonDownstreamTimeout: the client never answered the downstream
	// handshake inside its budget, so nothing was refused — nothing was said.
	ReasonDownstreamTimeout Reason = "downstream_handshake_timeout"
	// ReasonDownstreamALPN: the two legs did not end up on one application
	// protocol, which is a state this engine must never relay.
	ReasonDownstreamALPN Reason = "downstream_alpn_mismatch"
	// ReasonSecretsIncomplete: the secret path failed the downstream handshake
	// itself, so the client is not the one who ended it.
	ReasonSecretsIncomplete Reason = "downstream_key_log_failed"
	// ReasonCancelled: the caller's context ended the attempt, or the platform
	// gate reported that admission had already closed.
	ReasonCancelled Reason = "handshake_cancelled"
)

// Input is one intercepted connection's frozen handshake facts. Everything here
// was decided before the first byte of proxy TLS: the identity by policy
// (TLS-208), the offer by the probe (TLS-207), the sockets by the gateway and
// the dialer. The coordinator resolves nothing and re-decides nothing.
type Input struct {
	// Probe is the ClientHello probe of the downstream connection. Its Conn
	// replays the archived ClientHello and becomes the transport the downstream
	// TLS handshake reads, and its Hello is the offer both legs have to satisfy.
	Probe Outcome
	// Upstream is the raw TCP connection to the real destination — already
	// protected, bound and connected on the captured network by uplink. It is
	// the destination the socket was opened to, never a re-resolved name.
	Upstream net.Conn
	// Identity is the canonical name or address the connection is being
	// intercepted for: the ClientHello SNI, or the original destination address
	// when the client asserted no usable name. It is the same string the
	// downstream leaf is issued for and the same reference identity the upstream
	// handshake must prove.
	Identity string
	// DownstreamKeyLog receives the downstream NSS keylog lines this connection
	// produces. It is where TLS-210 injects its per-connection writer, and it is
	// per connection because the secrets are: they are keyed by this client's
	// random. A nil writer records no secrets. The upstream leg never gets one.
	DownstreamKeyLog io.Writer
	// RetainDownstreamOnFailure asks the coordinator to leave the client
	// transport open when the attempt fails at a point where the connection can
	// still fall back to the client's own TLS (§6.1): nothing has been written
	// towards the client *and* the client's own bytes are all still unread in
	// the probe's replay buffer. That is the only state in which a caller can
	// forward the connection untouched, and in that state no read is in flight
	// on the client side either. The upstream socket is closed on every failure
	// path regardless, because the fallback must dial a fresh one: proxy TLS
	// bytes must never reach the origin's socket and then be replaced by the
	// client's own ClientHello on the same transport.
	//
	// The default (false) keeps the coordinator's original contract: a failed
	// attempt closes both transports and the caller never sees them again. With
	// the flag set the caller owns the client transport again and must close it,
	// on every path, including a fallback it then decides not to take.
	RetainDownstreamOnFailure bool
	// Progress reports that one side's handshake is about to begin, so a caller
	// can publish the connection's phase without this package knowing about
	// events. It is called on the goroutine running the handshake, at most once
	// per stage, and must not block or call back into this coordinator.
	Progress func(Stage)
}

// Stage names the point of one handshake attempt a caller is told about. The
// values are deliberately not a sequence number: a caller publishes the phase
// they name and nothing else.
type Stage uint8

const (
	// StageUpstream is the moment before the upstream (TLS B) handshake starts.
	StageUpstream Stage = iota + 1
	// StageDownstream is the moment before the downstream (TLS A) handshake
	// starts, which is after the origin selected the application protocol and
	// after the leaf was issued.
	StageDownstream
)

// Session is what one handshake attempt produced. It is returned for a failed
// attempt too, because the downstream boundary is a fact about the connection
// rather than about the attempt: an attempt that never spoke to the client and
// one that had already sent its certificate before failing are not the same
// event (C03 5, §6.1).
type Session struct {
	// Code is OK exactly when both handshakes completed.
	Code engine.Code
	// Reason is the fixed reason a failed attempt ended with, and is empty on
	// success.
	Reason Reason
	// Downstream and Upstream are the two handshaken connections, non-nil
	// exactly when the code is OK. A failed attempt hands back no connection:
	// its transports have been closed.
	Downstream *tls.Conn
	Upstream   *tls.Conn
	// ALPN is the application protocol the origin selected, which is also the
	// one the client negotiated, or "" when neither leg declared one.
	ALPN string
	// BytesToDownstream is how many TLS bytes the proxy wrote towards the client
	// during the attempt. See SpokeToClient.
	BytesToDownstream int64
}

// Intercepted reports whether both TLS sides are established.
func (s Session) Intercepted() bool {
	return s.Code == engine.OK && s.Downstream != nil && s.Upstream != nil
}

// SpokeToClient reports whether the proxy's own TLS had already written towards
// the client. While this is false the client still holds its original TLS
// session untouched; once it is true the client has been given proxy TLS on this
// connection, so only a later connection can be bypassed (C03 5). Every byte
// counts, including an alert: a connection this proxy has already alerted on is
// not one it can hand back.
func (s Session) SpokeToClient() bool { return s.BytesToDownstream > 0 }

// Handshaker coordinates the two handshakes of one connection. It holds no
// per-connection state, so it is safe for concurrent use; one Handshaker serves
// every connection of one engine run.
type Handshaker struct {
	leafs   *certstore.Store
	gate    Gate
	timeout time.Duration
}

// NewHandshaker validates the three things one handshake cannot be performed
// without: the CA that issues the downstream certificate, the admission-gated
// platform entry point the upstream verification runs on, and the per-side time
// budget. A zero timeout selects DefaultHandshakeTimeout; a larger one is
// rejected rather than clamped, so a budget can only ever be tightened.
func NewHandshaker(leafs *certstore.Store, gate Gate, timeout time.Duration) (*Handshaker, engine.Code) {
	if leafs == nil || gate == nil {
		return nil, engine.NotReady
	}
	if timeout < 0 || timeout > MaxHandshakeTimeout {
		return nil, engine.InvalidArgument
	}
	if timeout == 0 {
		timeout = DefaultHandshakeTimeout
	}
	return &Handshaker{leafs: leafs, gate: gate, timeout: timeout}, engine.OK
}

// Handshake performs one connection's two handshakes. It succeeds only when
// both completed with the same application protocol; on every other path both
// transports are closed and the returned Session says how far the attempt got.
// Ownership passes to this call: a caller that is handed back no connection must
// not use either transport again, and does not have to close one either.
//
// The context bounds the whole attempt: cancelling it (or letting its deadline
// pass) releases both sides, including a side that is blocked mid-handshake.
func (h *Handshaker) Handshake(ctx context.Context, input Input) Session {
	// Whatever this attempt was given is closed on the way out of a failed one,
	// including the upstream socket, so no failure path can leave a half-open
	// connection behind for the caller to clean up. The one exception is the
	// state Input.RetainDownstreamOnFailure describes: the client transport is
	// left open, and the caller takes it back, because the connection may still
	// be forwarded to the origin untouched.
	var downstream *writeBoundary
	fail := func(code engine.Code, reason Reason) Session {
		bytes := downstream.Bytes()
		retain := input.RetainDownstreamOnFailure && downstream != nil && bytes == 0 &&
			input.Probe.Conn != nil && input.Probe.Conn.Buffered() == input.Probe.Bytes
		switch {
		case retain:
		case downstream != nil:
			_ = downstream.Close()
		case input.Probe.Conn != nil:
			_ = input.Probe.Conn.Close()
		}
		if input.Upstream != nil {
			_ = input.Upstream.Close()
		}
		return Session{Code: code, Reason: reason, BytesToDownstream: bytes}
	}
	progress := func(stage Stage) {
		if input.Progress != nil {
			input.Progress(stage)
		}
	}

	if h == nil || h.leafs == nil || h.gate == nil {
		return fail(engine.NotReady, ReasonNotReady)
	}
	if ctx == nil || input.Upstream == nil || input.Probe.Conn == nil {
		return fail(engine.InvalidArgument, ReasonInvalidInput)
	}
	// The coordinator runs after an interception decision, so anything other
	// than a servable ClientHello is a caller contract violation and not an
	// outcome to interpret.
	if input.Probe.Verdict != VerdictClientHello {
		return fail(engine.InvalidArgument, ReasonInvalidInput)
	}
	identity, code := certstore.CanonicalName(input.Identity)
	if code != engine.OK {
		return fail(code, ReasonInvalidInput)
	}
	hello := input.Probe.Hello
	minVersion, code := minServedVersion(hello)
	if code != engine.OK {
		return fail(code, ReasonNoVersion)
	}
	offered, code := offeredALPN(hello.ALPN)
	if code != engine.OK {
		return fail(code, ReasonInvalidOffer)
	}
	algorithm, code := certstore.SelectAlgorithm(hello.SignatureAlgorithms)
	if code != engine.OK {
		return fail(code, ReasonNoSignatures)
	}

	// The downstream transport is wrapped before anything can write to it, so
	// the boundary the failure paths report counts every byte of proxy TLS from
	// the first one.
	downstream = &writeBoundary{Conn: input.Probe.Conn}

	// The proxy's upstream leg offers exactly the protocols the client offered,
	// in the client's order: that is what makes the origin's answer a decision
	// about the same offer the application made. The proxy has no protocol of its
	// own, so it adds none and removes none — an allowlist here would only break
	// the protocols it must forward intact (design §3.3). What it does enforce is
	// that both legs end on the same one.
	upstreamConfig, code := NewUpstreamTLSConfig(UpstreamSpec{Identity: identity, MinVersion: minVersion}, h.gate)
	if code != engine.OK {
		return fail(code, ReasonUpstreamConfig)
	}
	upstreamConfig.NextProtos = offered
	// The constructor returns a configuration that always verifies, but the ALPN
	// list is the one field added afterwards, so the invariant is checked once
	// more at exactly the point tls.Client is about to use it.
	if code := validateUpstreamConfig(upstreamConfig); code != engine.OK {
		return fail(code, ReasonUpstreamConfig)
	}

	// Upstream first (§6.3). If this leg fails, the client has not been sent a
	// single byte of proxy TLS, and it never will be for this connection.
	progress(StageUpstream)
	upstream := tls.Client(input.Upstream, upstreamConfig)
	upstream.SetDeadline(time.Now().Add(h.timeout))
	if err := upstream.HandshakeContext(ctx); err != nil {
		code, reason := classifyUpstreamFailure(ctx, err, offered)
		return fail(code, reason)
	}
	selected := upstream.ConnectionState().NegotiatedProtocol

	leaf, code := h.leafs.Leaf(identity, algorithm, time.Now())
	if code == engine.OK && !usableLeaf(leaf) {
		// A leaf the CA reported as issued but that cannot sign a handshake is
		// not a certificate this engine may present.
		code = engine.NotReady
	}
	if code != engine.OK {
		return fail(code, ReasonLeafUnavailable)
	}

	// Downstream: TLS A offers exactly the single protocol the origin selected,
	// or nothing at all when it selected none — never the client's whole list,
	// which would let the two legs land on different protocols.
	sink := &keyLogSink{inner: input.DownstreamKeyLog}
	config := newDownstreamConfig(leaf, selected, minVersion, sink.writer())
	config.GetConfigForClient = func(*tls.ClientHelloInfo) (*tls.Config, error) {
		return newDownstreamConfig(leaf, selected, minVersion, sink.writer()), nil
	}
	downstreamTLS := tls.Server(downstream, config)
	// The budget is per side (C10), so the downstream leg gets its own rather
	// than what is left of the upstream one.
	progress(StageDownstream)
	downstreamTLS.SetDeadline(time.Now().Add(h.timeout))
	if err := downstreamTLS.HandshakeContext(ctx); err != nil {
		code, reason := classifyDownstreamFailure(ctx, err, sink)
		return fail(code, reason)
	}

	bytes := downstream.Bytes()
	if got := downstreamTLS.ConnectionState().NegotiatedProtocol; got != selected {
		// Belt and braces: Go selects from the one protocol offered downstream,
		// so this can only happen if the client's second hello changed its mind.
		// Relaying it would be the h2-over-http/1.1 mixture that is forbidden.
		return fail(engine.Unsupported, ReasonDownstreamALPN)
	}

	// Both handshakes are done, so the deadlines installed above have served
	// their purpose. They are cleared rather than left to expire: a long-lived
	// WebSocket or gRPC stream must not be killed by a handshake budget
	// (design §6.5), and an idle policy is the relay's decision, not this one's.
	_ = downstream.SetDeadline(time.Time{})
	_ = input.Upstream.SetDeadline(time.Time{})

	return Session{
		Code:              engine.OK,
		Downstream:        downstreamTLS,
		Upstream:          upstream,
		ALPN:              selected,
		BytesToDownstream: bytes,
	}
}

// minServedVersion derives the handshake floor from what the client offered: the
// lowest version this engine serves that the hello also offered. Both legs use
// it, so neither can negotiate below what the client's own offer allowed the
// real connection to use, and a client that offers only TLS 1.3 is never served
// over TLS 1.2. The versions themselves may still differ between the legs
// (design §6.3); only the floor is shared.
func minServedVersion(hello ClientHello) (uint16, engine.Code) {
	versions := hello.SupportedVersions
	if !hello.SupportedVersionsPresent {
		// No supported_versions extension: the hello's own version field is the
		// whole offer and can only mean one version (RFC 8446 §4.2.1).
		versions = []uint16{hello.LegacyVersion}
	}
	floor := uint16(0)
	for _, version := range versions {
		if version != tls.VersionTLS12 && version != tls.VersionTLS13 {
			continue
		}
		if floor == 0 || version < floor {
			floor = version
		}
	}
	if floor == 0 {
		return 0, engine.Unsupported
	}
	return floor, engine.OK
}

// offeredALPN validates and copies the protocol list both legs are configured
// with. Order and case are the client's; the probe already removed GREASE.
func offeredALPN(protocols []string) ([]string, engine.Code) {
	if len(protocols) == 0 {
		return nil, engine.OK
	}
	if len(protocols) > maxOfferedProtocols {
		return nil, engine.InvalidArgument
	}
	offered := make([]string, 0, len(protocols))
	for _, protocol := range protocols {
		if len(protocol) == 0 || len(protocol) > maxProtocolLength {
			return nil, engine.InvalidArgument
		}
		offered = append(offered, protocol)
	}
	return offered, engine.OK
}

// downstreamProtos is the downstream offer: the one protocol the origin
// selected, or nothing at all. Declaring nothing when the origin selected
// nothing is what keeps the two legs honest — the client then decides for itself
// as it would have against the origin, and no protocol is invented downstream
// that the origin never agreed to.
func downstreamProtos(selected string) []string {
	if selected == "" {
		return nil
	}
	return []string{selected}
}

// newDownstreamConfig builds one downstream TLS configuration. It is called
// twice, for the base configuration and for the one GetConfigForClient returns,
// so the per-connection keylog writer TLS-210 injects is present on whichever
// configuration ends up performing the handshake. A client that sends a second
// ClientHello (HelloRetryRequest) must not silently lose its secrets, which is
// also why the callback builds a fresh configuration with this same constructor
// instead of mutating a shared one.
func newDownstreamConfig(leaf tls.Certificate, selected string, minVersion uint16, keyLog io.Writer) *tls.Config {
	return &tls.Config{
		Certificates: []tls.Certificate{leaf},
		NextProtos:   downstreamProtos(selected),
		MinVersion:   minVersion,
		MaxVersion:   tls.VersionTLS13,
		// One captured connection is one handshake. A resumed session would
		// produce application keys this engine cannot attribute to the
		// connection it is recording, so resumption is off (§6.3). Go
		// implements no 0-RTT on either side — the server advertises
		// max_early_data_size 0 and the client has no early-data path — so
		// refusing 0-RTT needs no switch of its own.
		SessionTicketsDisabled: true,
		KeyLogWriter:           keyLog,
	}
}

// usableLeaf reports whether a certificate returned by the CA can actually sign
// a handshake. Checking here keeps an unusable leaf from being reported as a
// client rejection later.
func usableLeaf(leaf tls.Certificate) bool {
	return len(leaf.Certificate) > 0 && leaf.PrivateKey != nil
}

// classifyUpstreamFailure maps one upstream handshake error onto the fixed code
// and reason a connection event carries. Nothing here is a guess about the
// origin's intent beyond the one alert the standard defines for it: alert 120
// means the origin refused the ALPN set the client offered, which is neither a
// certificate problem nor a transport one and must not be recorded as either.
func classifyUpstreamFailure(ctx context.Context, err error, offered []string) (engine.Code, Reason) {
	if ctx.Err() != nil {
		return engine.Cancelled, ReasonCancelled
	}
	var failure *Failure
	if errors.As(err, &failure) {
		if failure.Code == engine.Cancelled || failure.Code == engine.StaleGeneration {
			// The platform refused the call itself rather than judging the
			// certificate: the engine is going away or its state moved on.
			return failure.Code, ReasonCancelled
		}
		return failure.Code, ReasonUpstreamVerification
	}
	if len(offered) > 0 && refusedApplicationProtocol(err) {
		return engine.Unsupported, ReasonUpstreamALPN
	}
	if isTimeout(err) {
		return engine.IOError, ReasonUpstreamTimeout
	}
	return engine.IOError, ReasonUpstreamHandshake
}

// classifyDownstreamFailure distinguishes a remote TLS alert from a closed
// transport, a deadline, and a local/protocol error. A connection ending during
// the handshake is not evidence that the client evaluated the proxy certificate.
// Cancellation and keylog failures take precedence over secondary socket errors.
func classifyDownstreamFailure(ctx context.Context, err error, sink *keyLogSink) (engine.Code, Reason) {
	if ctx.Err() != nil {
		return engine.Cancelled, ReasonCancelled
	}
	if sink.failed.Load() {
		// crypto/tls fails a handshake whose keylog writer errors, so the client
		// is not the one who ended this handshake and must not be reported as if
		// it were.
		return engine.SecretsIncomplete, ReasonSecretsIncomplete
	}
	if isTimeout(err) {
		return engine.IOError, ReasonDownstreamTimeout
	}
	var remote *net.OpError
	if errors.As(err, &remote) && remote.Op == "remote error" {
		return engine.DownstreamTLSRejected, ReasonDownstreamAlert
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		errors.Is(err, net.ErrClosed) || isConnectionClosed(err) {
		return engine.IOError, ReasonDownstreamClosed
	}
	return engine.IOError, ReasonDownstreamHandshake
}

// refusedApplicationProtocol reports whether the origin answered the handshake
// by refusing the protocol set it was offered, which is the one handshake
// failure that is neither a certificate problem nor a transport one. The peer's
// alert is identified by its standard name for the reason given at
// noApplicationProtocolAlert; the structural check around it keeps an unrelated
// local error from being read that way.
func refusedApplicationProtocol(err error) bool {
	var remote *net.OpError
	if !errors.As(err, &remote) || remote.Op != "remote error" || remote.Err == nil {
		return false
	}
	return remote.Err.Error() == noApplicationProtocolAlert
}

// isTimeout reports whether err is a deadline this process installed, which is
// how a handshake that ran out of its budget is told apart from one the peer
// ended.
func isTimeout(err error) bool {
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// writeBoundary counts what the proxy's TLS wrote towards the client and nothing
// else — it is not a traffic counter. The count is the downstream output
// boundary of §6.1: while it is zero the client's own TLS session is still
// untouched, and once it is non-zero the client has been given proxy TLS on this
// connection.
type writeBoundary struct {
	net.Conn
	written atomic.Int64
}

func (w *writeBoundary) Write(p []byte) (int, error) {
	n, err := w.Conn.Write(p)
	w.written.Add(int64(n))
	return n, err
}

// Bytes is how many bytes have been written towards the peer so far. It is safe
// on a nil boundary, so a failure raised before the downstream transport was
// wrapped still reports "nothing was written towards the client".
func (w *writeBoundary) Bytes() int64 {
	if w == nil {
		return 0
	}
	return w.written.Load()
}

// keyLogSink is the writer crypto/tls is given for the downstream side. It
// records that the writer failed, because a writer error fails the handshake:
// without the flag that failure would be indistinguishable from the client
// refusing the proxy's certificate.
type keyLogSink struct {
	inner  io.Writer
	failed atomic.Bool
}

func (s *keyLogSink) Write(p []byte) (int, error) {
	n, err := s.inner.Write(p)
	if err != nil {
		s.failed.Store(true)
	}
	return n, err
}

// writer is the writer to install on a TLS configuration, or nil when no
// secrets are being recorded. It returns a plain nil interface so an absent
// writer is an absent writer and not a wrapper that pretends to accept bytes.
func (s *keyLogSink) writer() io.Writer {
	if s == nil || s.inner == nil {
		return nil
	}
	return s
}

// Single-connection state machine (TLS-213, design §6.1).
//
// One connection arrives from the local gateway hop as two transports: the
// client's side of the hop and a raw TCP socket already connected to the
// original destination. This file runs that connection to its end and publishes
// one connection event per phase (C04), in the only order the design allows:
//
//	ACCEPTED → SNIFFING → UPSTREAM_HANDSHAKE → DOWNSTREAM_HANDSHAKE → RELAYING
//	ACCEPTED → SNIFFING → PASSTHROUGH
//	ACCEPTED → PASSTHROUGH                      (capacity refused before probing)
//
// The classifier runs first, then the one decision maker (TLS-208), then either
// the two handshakes (TLS-209) with the bounded relay (TLS-211) or a plain
// relay of the very bytes that were read. Everything the pipeline publishes is
// counted by the capture's own queue and budget (TLS-212); nothing here keeps a
// second set of counters.
//
// The fallback boundary of §6.1 is the one subtle part. A connection can still
// be forwarded untouched while nothing has been written towards the client and
// while every byte read from it is still held by the probe's replay buffer. In
// that state an attempt that fails for a reason about *this engine* (not about
// the origin and not about the client's trust) falls back: the origin socket is
// closed and dialed again, because the proxy's own ClientHello has already been
// on it, and the client's original bytes are then forwarded on the fresh
// socket. After the proxy's TLS has written anything towards the client there is
// no fallback at all, and a user rule can only ever apply to a later connection
// (C03 5).
package tlsproxy

import (
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"net/netip"
	"time"

	"com.layeranalyzer/tlsbridge/internal/certstore"
	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/secrets"
)

// Fixed decision reasons this state machine adds to the ones the probe, the
// policy and the coordinator already own. Like those, they are constants that
// carry no stream bytes, no identity and no platform text, so they can go
// straight into a connection event.
const (
	// reasonConnectionCapacity: the shared connection budget was full, so this
	// connection is forwarded untouched and no proxy state is created (§15.3).
	reasonConnectionCapacity = "connection_capacity_exceeded"
	// reasonHandshakeCapacity: the simultaneous-handshake budget was full, so
	// this candidate is forwarded untouched rather than queued (§15.3).
	reasonHandshakeCapacity = "handshake_capacity_exceeded"
	// reasonSecretsIncomplete: the capture can no longer save records, so no
	// new interception is started (§8.2). Connections already established keep
	// forwarding.
	reasonSecretsIncomplete = "secrets_incomplete"
	// reasonFallbackLeaf: the engine could not issue the downstream leaf before
	// speaking to the client, so the connection continues as an ordinary one on
	// a fresh origin socket.
	reasonFallbackLeaf = "fallback_downstream_leaf_unavailable"
	// reasonFallbackDial: the fallback's own fresh socket to the original
	// destination could not be opened. The connection ends; the client's TLS
	// was never touched, and nothing is replayed towards the origin.
	reasonFallbackDial = "fallback_redial_failed"
	// reasonDecision: the decision maker refused the request as unusable
	// (a self-contradicting probe result, an unusable destination). The caller
	// closes the connection rather than guessing.
	reasonDecision = "decision_rejected"
	// reasonSecretPath: the capture could not create this connection's keylog
	// writer, so the interception cannot produce secrets.
	reasonSecretPath = "secret_path_unavailable"
	// reasonRefused: a failure with no reason of its own. Every failure path in
	// this file names one, so this only covers a fault raised by a part that
	// reported a code without a reason.
	reasonRefused = "connection_failed"
)

// Budgets this state machine adds on top of the ones its parts already own.
// Like every other budget in this package they can be tightened, never raised.
const (
	// DefaultSecretsSettleTimeout bounds the wait a connection's terminal report
	// does for the records it produced to reach the platform. The wait is for a
	// bounded platform call — the same kind of JNI copy C10 gives the gateway one
	// second for — and it is not a wait for the disk: persistence stays with the
	// platform consumer (C05).
	DefaultSecretsSettleTimeout = time.Second
	// MaxSecretsSettleTimeout is the ceiling on that wait.
	MaxSecretsSettleTimeout = DefaultSecretsSettleTimeout
)

// Router is the connection state machine's only decision input. policy.Policy
// implements it, so the single decision maker of TLS-208 stays the single
// decision maker: this file never derives a class, a priority or an identity of
// its own.
type Router interface {
	// Route returns the frozen decision for one connection, given what the
	// probe read. It returns engine.InvalidArgument only for a request that
	// contradicts itself, in which case the caller closes the connection.
	Route(destination netip.AddrPort, application string, outcome Outcome) (Route, engine.Code)
}

// Route is one connection's decision, reduced to the three things this state
// machine acts on. The class names and the reason taxonomy stay with the policy
// that produced them; Reason is copied verbatim into the connection event's
// decisionReason.
type Route struct {
	// Intercept is true when both TLS sides must be terminated.
	Intercept bool
	// Identity is the canonical name or address the downstream leaf is issued
	// for and the upstream handshake must prove. It is set exactly when
	// Intercept is true.
	Identity string
	// Reason is the policy's fixed reason string.
	Reason string
}

// Dialer opens the one raw TCP connection the fallback path needs. It is
// uplink.Dialer in production, so the replacement socket is protected, bound and
// connected on the captured network exactly like the first one, and the original
// destination IP is used unchanged (never a re-resolved name). It is called only
// when an origin socket has already carried proxy TLS.
type Dialer interface {
	Dial(ctx context.Context, destination netip.AddrPort) (net.Conn, engine.Code)
}

// Options assembles one connection pipeline. Everything here is run-scoped: one
// pipeline serves every connection of one engine run and holds no per-connection
// state, so it is safe for concurrent use.
type Options struct {
	// CaptureID is the capture every event belongs to.
	CaptureID string
	// Policy is the decision maker. Every candidate goes through it.
	Policy Router
	// Leaves issues the downstream certificates and Gate is the admission-gated
	// platform entry point the upstream verification runs on. Both are TLS-209's
	// dependencies, passed through unchanged.
	Leaves *certstore.Store
	Gate   Gate
	// Dialer is the fallback's only way to reach the original destination.
	Dialer Dialer
	// Secrets is the capture's downstream keylog path (TLS-210).
	Secrets *secrets.Sink
	// Budget and Events are the run's shared capacity accountant and bounded
	// event queue (TLS-212). They are required: a pipeline without them could
	// not honour either budget or publish a phase.
	Budget *engine.Budget
	Events *engine.Queue
	// ProbeLimits bounds the ClientHello probe. The zero value is the default
	// budget (64 KiB / 3 s, C10).
	ProbeLimits Limits
	// HandshakeTimeout is the per-side handshake budget (C10: 10 s).
	HandshakeTimeout time.Duration
	// RelayLimits bounds the two copies. The zero value takes every default,
	// including no idle policy.
	RelayLimits RelayLimits
	// SecretsSettleTimeout bounds the terminal wait for this connection's
	// records. Zero selects DefaultSecretsSettleTimeout.
	SecretsSettleTimeout time.Duration
	// Now is the wall clock, and Monotonic the monotonic one, both for the
	// connection events. They are separate because only the wall clock can be
	// corrected while a capture is running.
	Now       func() time.Time
	Monotonic func() int64
}

// Pipeline runs one connection of one engine run to its end, publishing the
// connection's phases as it goes.
type Pipeline struct {
	probes     probeMetrics
	captureID  string
	policy     Router
	handshaker *Handshaker
	relay      *Relay
	dialer     Dialer
	secrets    *secrets.Sink
	budget     *engine.Budget
	events     *engine.Queue
	probe      Limits
	settle     time.Duration
	now        func() time.Time
	monotonic  func() int64
}

// NewPipeline validates the run's parts and returns the state machine. It opens
// nothing, dials nothing and starts no worker: the first connection is what
// makes it do anything at all.
func NewPipeline(options Options) (*Pipeline, engine.Code) {
	if options.Policy == nil || options.Dialer == nil || options.Secrets == nil ||
		options.Budget == nil || options.Events == nil {
		return nil, engine.NotReady
	}
	if !engine.ValidID(options.CaptureID) {
		return nil, engine.InvalidArgument
	}
	settle := options.SecretsSettleTimeout
	if settle < 0 || settle > MaxSecretsSettleTimeout {
		return nil, engine.InvalidArgument
	}
	if settle == 0 {
		settle = DefaultSecretsSettleTimeout
	}
	handshaker, code := NewHandshaker(options.Leaves, options.Gate, options.HandshakeTimeout)
	if code != engine.OK {
		return nil, code
	}
	relay, code := NewRelay(options.RelayLimits)
	if code != engine.OK {
		return nil, code
	}
	now := options.Now
	if now == nil {
		now = time.Now
	}
	started := now()
	monotonic := options.Monotonic
	if monotonic == nil {
		monotonic = func() int64 { return time.Since(started).Nanoseconds() }
	}
	return &Pipeline{
		captureID:  options.CaptureID,
		policy:     options.Policy,
		handshaker: handshaker,
		relay:      relay,
		dialer:     options.Dialer,
		secrets:    options.Secrets,
		budget:     options.Budget,
		events:     options.Events,
		probe:      options.ProbeLimits,
		settle:     settle,
		now:        now,
		monotonic:  monotonic,
	}, engine.OK
}

// Request is one connection as the gateway hop hands it over.
type Request struct {
	// Optional borrowed gateway lease held before upstream dial. Gateway releases it.
	ConnectionLease *engine.Lease
	// ConnectionID is the capture's identifier for this connection. It is what
	// makes an event's ordering and terminal state belong to one connection.
	ConnectionID string
	// Destination is the original destination the socket was opened to. It is
	// never derived from the SNI and never replaced by one.
	Destination netip.AddrPort
	// Application is the VPN allowlist entry this connection belongs to, or ""
	// when the platform cannot attribute it (§8.4). SOCKS5 carries no
	// application identity, so this pipeline never guesses one from a source
	// address, and the application scope therefore selects nothing until an
	// attribution channel exists.
	Application string
	// NetworkGeneration is the captured physical network this connection was
	// opened on.
	NetworkGeneration int64
	// Downstream is the client's side of the local hop, with nothing read from
	// it yet.
	Downstream net.Conn
	// Upstream is the raw TCP connection to Destination: already protected,
	// bound and connected on the captured network, and unused so far.
	Upstream net.Conn
}

// ConnectionResult is what one connection ended with. It is a summary for the caller and
// for tests; the capture's counters are the ones the event queue keeps.
type ConnectionResult struct {
	// Code is OK when the connection was carried to its own end without a
	// fault, whatever it was classified as.
	Code engine.Code
	// Phase is the terminal phase this connection published.
	Phase engine.Phase
	// Reason is the fixed reason of the terminal event, empty on a clean end.
	Reason string
	// Intercepted reports that both TLS sides were terminated and the
	// connection reached relay.
	Intercepted bool
	// BytesToUpstream and BytesToDownstream are what the relay copied.
	BytesToUpstream   int64
	BytesToDownstream int64
}

// Handle runs one connection to its end and publishes its phases.
//
// Ownership passes to this call as soon as the request is accepted: both
// transports are closed on every path from there, including the paths that fall
// back and a failed attempt's sockets. A request this pipeline refuses outright
// is the one exception — nothing was taken, so the caller still owns what it
// passed.
func (p *Pipeline) Handle(ctx context.Context, request Request) ConnectionResult {
	if p == nil {
		return ConnectionResult{Code: engine.NotReady}
	}
	if ctx == nil || request.Downstream == nil || request.Upstream == nil ||
		!engine.ValidID(request.ConnectionID) || request.NetworkGeneration < 0 ||
		!usableDestination(request.Destination) {
		// Nothing usable was handed over, so no transport is taken and no event
		// is published: an event would have to name a destination this pipeline
		// cannot vouch for.
		return ConnectionResult{Code: engine.InvalidArgument}
	}
	if request.ConnectionLease != nil && !p.budget.Owns(request.ConnectionLease) {
		return ConnectionResult{Code: engine.InvalidArgument}
	}
	state := &connState{pipeline: p, request: request, ctx: ctx}
	defer state.closeTransports()

	if request.ConnectionLease == nil {
		if lease, code := p.budget.Acquire(engine.ConnectionSlot); code != engine.OK {
			state.emit(engine.PhaseAccepted, "", engine.OK)
			return state.passthrough(request.Downstream, request.Upstream, reasonConnectionCapacity)
		} else {
			defer lease.Release()
		}
	}

	state.emit(engine.PhaseAccepted, "", engine.OK)
	state.emit(engine.PhaseSniffing, "", engine.OK)
	reservation := p.probes.begin()
	outcome := probeClientHello(request.Downstream, p.probe, reservation.capacity)
	p.probes.finished(outcome)
	outcome.Conn.released = reservation.release
	defer func() {
		// Relay workers have joined before Handle returns. Drop an unread
		// replay prefix on every failure/stop path before returning its count.
		outcome.Conn.prefix = nil
		reservation.release()
	}()
	state.observed(outcome)

	route, code := p.policy.Route(request.Destination, request.Application, outcome)
	if code != engine.OK {
		return state.fail(code, reasonDecision)
	}
	if !route.Intercept {
		// Not TLS, unsupported, undecided, out of scope or explicitly bypassed:
		// all of them are the same thing here — the bytes the client sent go to
		// the origin unchanged, from the probe's replay buffer onwards.
		return state.passthrough(outcome.Conn, request.Upstream, route.Reason)
	}
	if !p.secrets.AcceptingNewInterception() {
		return state.passthrough(outcome.Conn, request.Upstream, reasonSecretsIncomplete)
	}

	// The handshake budget is the short-lived one and covers intercepted
	// connections only. It is released the moment the handshakes are over, so
	// a long relay does not hold a handshake slot (§15.3).
	handshake, code := p.budget.Acquire(engine.HandshakeSlot)
	if code != engine.OK {
		return state.passthrough(outcome.Conn, request.Upstream, reasonHandshakeCapacity)
	}
	writer, code := p.secrets.Writer(request.ConnectionID)
	if code != engine.OK {
		handshake.Release()
		return state.fail(code, reasonSecretPath)
	}
	state.keylog = writer

	session := p.handshaker.Handshake(ctx, Input{
		Probe:            outcome,
		Upstream:         request.Upstream,
		Identity:         route.Identity,
		DownstreamKeyLog: writer,
		// The client transport is kept open when the attempt fails before the
		// client was spoken to, which is what makes the fallback below possible
		// at all: the coordinator closes everything else, including the origin
		// socket that must be replaced rather than reused.
		RetainDownstreamOnFailure: true,
		Progress:                  state.progress,
	})
	handshake.Release()
	state.session = session

	if !session.Intercepted() {
		if state.fallBackAllowed(outcome, session) {
			return state.fallBack(outcome)
		}
		return state.fail(session.Code, string(session.Reason))
	}
	state.intercepted = true
	state.emit(engine.PhaseRelaying, "", engine.OK)
	result := p.relay.Run(ctx, session.Downstream, session.Upstream)
	return state.carried(result.Code, string(result.Reason), result.BytesToUpstream, result.BytesToDownstream)
}

// connState is one connection's mutable state. It is touched by one goroutine
// only: Handle runs the probe, the decision and the handshakes itself, and the
// relay's two copies touch nothing here.
type connState struct {
	pipeline    *Pipeline
	request     Request
	ctx         context.Context
	keylog      *secrets.Writer
	session     Session
	hello       ClientHello
	sniffed     bool
	intercepted bool
	terminal    bool
	phase       engine.Phase
	reason      string
	code        engine.Code
	bytesUp     int64
	bytesDown   int64
}

// observed records what the probe read, for the events that follow. A hello is
// remembered only when one was really parsed: a connection whose prefix is not
// TLS has no SNI and no client random to report, and inventing one would be a
// claim about a name the client never sent.
func (s *connState) observed(outcome Outcome) {
	if outcome.Hello.Records > 0 {
		s.hello = outcome.Hello
		s.sniffed = true
	}
}

// progress publishes the phase of the side that is about to start its
// handshake. It runs on the handshake's own goroutine, which is this
// connection's goroutine.
func (s *connState) progress(stage Stage) {
	switch stage {
	case StageUpstream:
		s.emit(engine.PhaseUpstreamHandshake, "", engine.OK)
	case StageDownstream:
		s.emit(engine.PhaseDownstreamHandshake, "", engine.OK)
	}
}

// passthrough forwards the connection untouched, from the bytes the given
// downstream still owes onwards, and publishes the phase that says so. The
// phase is published before the relay runs so that a forwarding failure is
// never counted as a handshake failure (TLS-212).
func (s *connState) passthrough(downstream, upstream net.Conn, reason string) ConnectionResult {
	s.emit(engine.PhasePassthrough, reason, engine.OK)
	result := s.pipeline.relay.Run(s.ctx, downstream, upstream)
	return s.carried(result.Code, string(result.Reason), result.BytesToUpstream, result.BytesToDownstream)
}

// fallBackAllowed is §6.1's boundary, checked as a fact rather than assumed: the
// proxy has written nothing towards the client, the client's own bytes are all
// still in the replay buffer, and the failure is about this engine's own
// material rather than about the origin or the client's trust.
//
// The last condition is deliberately a single reason. Every other failure of an
// attempt that got this far is a verdict — the origin's certificate, the
// origin's ALPN answer, the origin's transport, the client's own refusal — and
// none of them may be turned into a silent, unverified connection (C03 4).
func (s *connState) fallBackAllowed(outcome Outcome, session Session) bool {
	if session.SpokeToClient() {
		return false
	}
	if outcome.Conn == nil || outcome.Conn.Buffered() != outcome.Bytes {
		return false
	}
	return session.Reason == ReasonLeafUnavailable
}

// fallBack replaces the origin socket and forwards the client's own bytes on it.
// The socket the proxy's ClientHello went out on is closed and never reused
// (§6.1): proxy TLS must not be followed by the application's ClientHello on the
// same transport. A failure to open the replacement ends the connection — the
// client is not left waiting on a hop that has nothing behind it — and no byte
// of the application's stream is sent anywhere twice.
func (s *connState) fallBack(outcome Outcome) ConnectionResult {
	_ = s.request.Upstream.Close()
	fresh, code := s.pipeline.dialer.Dial(s.ctx, s.request.Destination)
	if code != engine.OK {
		return s.fail(code, reasonFallbackDial)
	}
	return s.passthrough(outcome.Conn, fresh, reasonFallbackLeaf)
}

// fail ends the connection with a failure.
func (s *connState) fail(code engine.Code, reason string) ConnectionResult {
	if code == engine.OK {
		code = engine.IOError
	}
	return s.finish(code, reason)
}

// carried records the relay's traffic once and ends the connection. The traffic
// counter is fed here and only here, so one connection's bytes are never counted
// twice (TLS-212), and the relay's own result is the only measurement used.
func (s *connState) carried(code engine.Code, reason string, toUpstream, toDownstream int64) ConnectionResult {
	_ = s.pipeline.events.RecordTraffic(toUpstream, toDownstream)
	s.bytesUp, s.bytesDown = toUpstream, toDownstream
	return s.finish(code, reason)
}

// finish closes this connection's keylog writer — before the terminal event, so
// a record that never arrived whole is already accounted for — and publishes the
// one terminal phase the connection gets.
func (s *connState) finish(code engine.Code, reason string) ConnectionResult {
	if s.keylog != nil {
		s.keylog.Close()
	}
	if code == engine.OK {
		s.emit(engine.PhaseClosed, "", engine.OK)
	} else {
		if reason == "" {
			reason = reasonRefused
		}
		s.emit(engine.PhaseFailed, reason, code)
	}
	return ConnectionResult{
		Code:              code,
		Phase:             s.phase,
		Reason:            s.reason,
		Intercepted:       s.intercepted,
		BytesToUpstream:   s.bytesUp,
		BytesToDownstream: s.bytesDown,
	}
}

// emit publishes one phase of this connection. A terminal phase is published
// once and nothing follows it, which is the connection half of C04's rule: the
// queue refuses a second terminal state, and this file does not produce one.
func (s *connState) emit(phase engine.Phase, reason string, code engine.Code) {
	if s.terminal {
		return
	}
	event := engine.Event{
		CaptureID:         s.pipeline.captureID,
		ConnectionID:      s.request.ConnectionID,
		MonotonicNanos:    s.pipeline.monotonic(),
		WallTimeMillis:    s.pipeline.now().UnixMilli(),
		DestinationIP:     s.request.Destination.Addr().Unmap().String(),
		DestinationPort:   s.request.Destination.Port(),
		NetworkGeneration: s.request.NetworkGeneration,
		Phase:             phase,
		DecisionReason:    reason,
	}
	if s.sniffed {
		event.SNI = s.hello.SNI
		event.DownstreamClientRandom = hex.EncodeToString(s.hello.ClientRandom[:])
	}
	if s.session.Downstream != nil {
		event.DownstreamTLS = tls.VersionName(s.session.Downstream.ConnectionState().Version)
	}
	if s.session.Upstream != nil {
		state := s.session.Upstream.ConnectionState()
		event.UpstreamTLS = tls.VersionName(state.Version)
		event.ALPN = s.session.ALPN
		if len(state.PeerCertificates) > 0 {
			digest := sha256.Sum256(state.PeerCertificates[0].Raw)
			event.UpstreamCertificateSHA256 = hex.EncodeToString(digest[:])
		}
	}
	if phase == engine.PhaseFailed {
		event.ErrorCode = code.String()
	}
	if phase.Terminal() {
		event.SecretRecordsAccepted, event.SecretRecordsPersisted, event.SecretsComplete = s.secretCounts()
		s.terminal = true
	}
	s.phase = phase
	s.reason = reason
	s.code = code
	_, _ = s.pipeline.events.Publish(event)
}

// secretCounts reports what this connection's records did. Accepted is what the
// connection produced; persisted is how many of them reached the platform,
// which is as far as this engine can see — whether they reached the disk is the
// platform consumer's answer (C05), and a capture that lost a record says so
// through SecretsComplete staying false.
func (s *connState) secretCounts() (accepted int64, persisted int64, complete bool) {
	if s.keylog == nil {
		return 0, 0, false
	}
	produced := s.keylog.Records()
	if produced == 0 {
		return 0, 0, false
	}
	if !s.pipeline.secrets.Settle(s.pipeline.settle) {
		return int64(produced), 0, false
	}
	return int64(produced), int64(produced), true
}

// closeTransports releases everything this connection owns. It is called on
// every path, after the relays have already closed the transports they were
// given, because a connection that is never carried anywhere must not be left
// open either.
func (s *connState) closeTransports() {
	if s.keylog != nil {
		s.keylog.Close()
	}
	if s.request.Downstream != nil {
		_ = s.request.Downstream.Close()
	}
	if s.request.Upstream != nil {
		_ = s.request.Upstream.Close()
	}
}

// usableDestination is the same screen the gateway and the policy apply: an
// address that is not unspecified, not multicast and carries no zone. The port
// is checked because an event names it and a zero port is not a destination.
func usableDestination(destination netip.AddrPort) bool {
	if !destination.IsValid() || destination.Port() == 0 || destination.Addr().Zone() != "" {
		return false
	}
	address := destination.Addr().Unmap()
	return !address.IsUnspecified() && !address.IsMulticast()
}

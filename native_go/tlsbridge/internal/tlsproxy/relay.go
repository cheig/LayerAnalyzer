// Bounded bidirectional relay and unified close (TLS-211, design §6.5).
//
// Once both handshakes are done (TLS-209) one intercepted connection is just an
// application byte stream running both ways, and this file moves it. It is
// deliberately the dumbest component in the engine: each direction reads into
// one fixed 32 KiB buffer and writes what it read to the other socket. Nothing
// here buffers a whole body, parses a byte of it, or retries anything. It is
// also transport-agnostic on purpose — two *tls.Conn from the coordinator, or
// the two plain sockets of a passthrough connection (TLS-213) — because a
// bypassed connection needs the same copy and the same close semantics, only
// without the TLS layer.
//
// Closing is where the care is (§6.5). A client that uploads and then
// half-closes must still receive the whole answer, so an end of stream in one
// direction is forwarded as a half-close — close_notify on a TLS connection,
// FIN on a plain one — and the reverse copy keeps running. Only a fault (a
// transport error, the idle budget, the caller's context) interrupts both
// directions, and it does so through one closer that runs once, so a broken
// connection is torn down exactly once and a healthy one is never cut short in
// the middle of a response.
//
// The relay never writes a byte of its own towards either peer and holds no
// hook into events, previews, statistics or the UI. That is structural rather
// than incidental: §6.5 requires backpressure to come from the business sockets
// and nothing else, and a copy loop with no other consumer cannot be stalled by
// one. One relay publishes exactly one terminal Result — the first fault that
// happened — because a connection that is already gone can only be described
// once.

package tlsproxy

import (
	"context"
	"errors"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// Fixed relay budgets (design §6.5, C10). As elsewhere in this package a budget
// can be tightened but not raised: the ceiling is part of the resource contract,
// so a larger value is rejected rather than quietly clamped.
const (
	// DefaultRelayBufferBytes is C10's per-direction copy buffer. It is the
	// whole memory cost of relaying a body of any size.
	DefaultRelayBufferBytes = 32 << 10
	// MaxRelayBufferBytes is the ceiling on that buffer, so one connection
	// holds at most two of them.
	MaxRelayBufferBytes = DefaultRelayBufferBytes
	// DefaultRelayJoinTimeout bounds how long a torn-down relay waits for its
	// two copy goroutines to notice. It is the five seconds C10 gives a
	// stop-path join, and it exists for the same reason: a relay that has
	// already closed its transports must not be able to hold a shutdown open,
	// and a peer that never returns must not be waited on forever.
	DefaultRelayJoinTimeout = 5 * time.Second
	// MaxRelayJoinTimeout is the ceiling on that wait.
	MaxRelayJoinTimeout = DefaultRelayJoinTimeout
	// relayIdlePollFloor is the shortest step of the idle watchdog. It bounds
	// how much later than the configured budget an idle connection is noticed,
	// so a short budget in a test still fires promptly.
	relayIdlePollFloor = 10 * time.Millisecond
)

// RelayReason is the fixed reason code a relay that did not end cleanly ends
// with. Like the probe's and the coordinator's reasons it is a constant that
// carries no stream bytes, no identity and no platform text, so it can go
// straight into a connection event.
type RelayReason string

// Failure reasons. Each names what ended the copy, so the code alone never has
// to carry that information. RelayNotReady and RelayInvalidInput are answered
// before any byte is moved; the rest are terminal states of a copy.
const (
	// ReasonRelayNotReady: the relay was asked to run without being assembled.
	ReasonRelayNotReady RelayReason = "relay_not_ready"
	// ReasonRelayInvalidInput: the caller handed over a nil context or a nil
	// transport. Nothing was closed, because nothing was taken over.
	ReasonRelayInvalidInput RelayReason = "invalid_relay_input"
	// ReasonRelayCancelled: the caller's context ended the copy. It is the
	// caller's decision, not a judgement about either peer.
	ReasonRelayCancelled RelayReason = "relay_cancelled"
	// ReasonRelayIdleTimeout: neither direction moved a byte for the configured
	// idle budget. Only reachable when an idle policy was configured.
	ReasonRelayIdleTimeout RelayReason = "relay_idle_timeout"
	// ReasonRelayReadFailed: a transport refused to deliver bytes — a reset, a
	// closed socket, a local I/O failure.
	ReasonRelayReadFailed RelayReason = "relay_read_failed"
	// ReasonRelayWriteFailed: a transport refused to carry bytes on. This is
	// also what a peer that stopped reading eventually looks like.
	ReasonRelayWriteFailed RelayReason = "relay_write_failed"
	// ReasonRelayStreamTruncated: a TLS peer ended its stream inside a record,
	// which is a torn stream and not the close_notify that means "finished".
	// A TLS peer that closes at a record boundary is reported as a clean end,
	// following crypto/tls itself (see conn.go's readFromUntil).
	ReasonRelayStreamTruncated RelayReason = "relay_stream_truncated"
	// ReasonRelayHalfCloseFailed: the end of one stream could not be handed to
	// the other peer, so that peer was never told there is nothing more coming.
	ReasonRelayHalfCloseFailed RelayReason = "relay_half_close_failed"
)

// RelayDirection names one of the two copies a relay runs. It is a string
// rather than an ordinal so it can be carried in an event without a lookup
// table and cannot silently change meaning when a case is added.
type RelayDirection string

const (
	// DownstreamToUpstream is the application's own direction: the bytes the
	// client sent, on their way to the origin.
	DownstreamToUpstream RelayDirection = "downstream_to_upstream"
	// UpstreamToDownstream is the answer: the bytes the origin sent, on their
	// way back to the client.
	UpstreamToDownstream RelayDirection = "upstream_to_downstream"
)

// RelayLimits bounds one relay. The zero value selects every default, which
// means no idle policy: a connection with no configured idle budget is never
// ended for being quiet, because a WebSocket or gRPC stream may legitimately
// say nothing for hours (§6.5).
type RelayLimits struct {
	// BufferBytes is one direction's copy buffer. Zero selects
	// DefaultRelayBufferBytes; negative, or above MaxRelayBufferBytes, is
	// rejected rather than clamped.
	BufferBytes int
	// IdleTimeout ends a connection that has moved no bytes in either
	// direction for this long. Zero (the default) disables it. It is a separate
	// policy from the handshake budget: the 10-second handshake deadline is
	// cleared on success and must never be reused here (§6.5).
	IdleTimeout time.Duration
	// JoinTimeout bounds the wait for the copy goroutines after a fault. Zero
	// selects DefaultRelayJoinTimeout; negative, or above MaxRelayJoinTimeout,
	// is rejected.
	JoinTimeout time.Duration
}

// Result is what one relay publishes: one terminal state, however many
// directions were involved in reaching it.
type Result struct {
	// Code is OK exactly when both directions ended at their own pace, with no
	// fault and no cancellation.
	Code engine.Code
	// Reason is the fixed reason a failed relay ended with, and is empty
	// exactly when Code is OK.
	Reason RelayReason
	// Direction is the copy the terminal fault came from, or "" when the fault
	// was not one direction's (cancellation, the idle policy, an unassembled
	// relay). It is set only together with a non-OK Code.
	Direction RelayDirection
	// BytesToUpstream is how many application bytes the relay handed to the
	// origin, and BytesToDownstream how many it handed to the client. They
	// count bytes actually copied, so a partial write before a failure is
	// included and nothing that was never written is.
	BytesToUpstream   int64
	BytesToDownstream int64
	// DownstreamHalfClosed reports that the client ended its stream, and
	// UpstreamHalfClosed the same for the origin. Either can be true while the
	// other direction kept running and even ended cleanly: that is what a
	// half-closed connection looks like from here. The end was handed to the
	// other peer as a half-close unless HalfCloseUnsupported is set.
	DownstreamHalfClosed bool
	UpstreamHalfClosed   bool
	// HalfCloseUnsupported reports that one direction reached the end of its
	// stream and could not tell the other peer, because that transport has no
	// half-close. The copy itself still succeeded; the peer simply was not told
	// (see ErrHalfCloseUnsupported).
	HalfCloseUnsupported bool
	// JoinTimedOut reports that a copy goroutine had still not returned when
	// the join budget expired. Both transports are closed at that point, so the
	// goroutine can only be waiting on something outside them.
	JoinTimedOut bool
}

// Relay moves application bytes between the two endpoints of one intercepted
// connection. It holds no per-connection state, so one Relay serves every
// connection of one engine run.
type Relay struct {
	bufferBytes int
	idle        time.Duration
	join        time.Duration
}

// NewRelay validates one relay's budgets. Out-of-range values are rejected
// rather than clamped, so a configuration can only ever tighten a budget.
func NewRelay(limits RelayLimits) (*Relay, engine.Code) {
	relay := &Relay{
		bufferBytes: limits.BufferBytes,
		idle:        limits.IdleTimeout,
		join:        limits.JoinTimeout,
	}
	if relay.bufferBytes < 0 || relay.bufferBytes > MaxRelayBufferBytes {
		return nil, engine.InvalidArgument
	}
	if relay.idle < 0 {
		return nil, engine.InvalidArgument
	}
	if relay.join < 0 || relay.join > MaxRelayJoinTimeout {
		return nil, engine.InvalidArgument
	}
	if relay.bufferBytes == 0 {
		relay.bufferBytes = DefaultRelayBufferBytes
	}
	if relay.join == 0 {
		relay.join = DefaultRelayJoinTimeout
	}
	return relay, engine.OK
}

// Run relays one connection to its end and returns the single terminal state of
// that connection.
//
// Ownership passes to this call: on return both transports have been closed,
// whatever happened, so a caller must not use or close either one again. The
// two connections are otherwise untouched — Run writes nothing of its own,
// rewrites no bytes, and performs no retry of anything a peer sent.
//
// The context is the caller's abort: cancelling it closes both transports and
// interrupts both copies. A cancellation that lands after both directions have
// already ended on their own is not a fault, because there was nothing left to
// interrupt.
func (r *Relay) Run(ctx context.Context, downstream, upstream net.Conn) Result {
	if r == nil || r.bufferBytes <= 0 || r.join <= 0 {
		return Result{Code: engine.NotReady, Reason: ReasonRelayNotReady}
	}
	if ctx == nil || downstream == nil || upstream == nil {
		return Result{Code: engine.InvalidArgument, Reason: ReasonRelayInvalidInput}
	}

	run := &relayRun{
		ctx:         ctx,
		relay:       r,
		outcome:     &relayOutcome{},
		activity:    &relayActivity{last: time.Now()},
		downstream:  downstream,
		upstream:    upstream,
		interrupted: make(chan struct{}),
		stopWatch:   make(chan struct{}),
	}

	run.both.Add(2)
	go run.copyDirection(downstream, upstream, DownstreamToUpstream)
	go run.copyDirection(upstream, downstream, UpstreamToDownstream)

	// The end of the two copies is what "the connection is over" means, so it
	// gets its own goroutine to turn a WaitGroup into something selectable.
	finished := make(chan struct{})
	go func() {
		run.both.Wait()
		close(finished)
	}()

	if r.idle > 0 {
		go run.watchIdle()
	}

	select {
	case <-finished:
		// Both directions ended on their own: whatever they recorded — a fault
		// or nothing at all — is the terminal state.
	case <-ctx.Done():
		// Only a cancellation that arrives before both directions have ended is
		// a fault of this relay. One that lands after is the caller's timing,
		// not a truncated copy.
		select {
		case <-finished:
		default:
			run.fail(engine.Cancelled, ReasonRelayCancelled, "")
			run.joinBounded(finished)
		}
	case <-run.interrupted:
		// A direction already failed and closed both transports; wait for the
		// other one to notice, but not forever.
		run.joinBounded(finished)
	}

	run.finished.Store(true)
	close(run.stopWatch)
	run.interrupt()
	return run.result()
}

// relayRun is one Run's per-connection state. It exists only for the duration
// of that call.
type relayRun struct {
	ctx      context.Context
	relay    *Relay
	outcome  *relayOutcome
	activity *relayActivity

	downstream net.Conn
	upstream   net.Conn

	both sync.WaitGroup

	// interrupted is closed by the first fault, so the main loop can stop
	// waiting for a clean finish, and the idle watchdog can stop watching.
	interrupted chan struct{}
	faultOnce   sync.Once
	// stopWatch ends the idle watchdog; closed once the copies are done.
	stopWatch chan struct{}
	// finished is set before the terminal state is read, so a watchdog tick
	// that fires at the same moment as a clean finish cannot turn it into an
	// idle fault.
	finished atomic.Bool

	// closeOnce is the unified closer: each of the two transports is closed
	// exactly once, and every failure path goes through it (C03, §6.5).
	closeOnce sync.Once

	toUpstream   atomic.Int64
	toDownstream atomic.Int64

	downstreamHalfClosed atomic.Bool
	upstreamHalfClosed   atomic.Bool
	halfCloseUnsupported atomic.Bool
	joinTimedOut         atomic.Bool
}

// copyDirection is one of the two copies. It runs until its source ends, its
// destination fails, or the relay is torn down.
func (run *relayRun) copyDirection(from, to net.Conn, direction RelayDirection) {
	defer run.both.Done()

	// One buffer for the whole direction, reused for every chunk: the memory
	// cost of relaying a ten-gigabyte body is this slice and nothing else.
	buffer := make([]byte, run.relay.bufferBytes)
	for {
		n, err := from.Read(buffer)
		if n > 0 {
			run.activity.mark()
			copied, writeErr := writeAll(to, buffer[:n])
			if copied > 0 {
				run.count(direction, int64(copied))
			}
			if writeErr != nil {
				// Bytes handed to the destination are what the peers saw;
				// a short write before a failure is part of the count.
				run.fail(engine.IOError, ReasonRelayWriteFailed, direction)
				return
			}
		}
		if err == nil {
			continue
		}
		if errors.Is(err, io.EOF) {
			// An end of stream, not a failure: hand it to the other peer as a
			// half-close and let the reverse copy finish its own work.
			run.forwardEnd(to, direction)
			return
		}
		if run.ctx.Err() != nil {
			run.fail(engine.Cancelled, ReasonRelayCancelled, "")
			return
		}
		code, reason := classifyRelayRead(err)
		run.fail(code, reason, direction)
		return
	}
}

// forwardEnd tells the peer at the far end of this direction that there is
// nothing more coming from this side. It is a half-close and not a close: the
// reverse copy still owns the connection and is usually carrying the answer.
func (run *relayRun) forwardEnd(to net.Conn, direction RelayDirection) {
	run.markEnded(direction)
	half, ok := to.(interface{ CloseWrite() error })
	if !ok {
		// The transport cannot express "I am done sending", so the peer will
		// not learn it from this. Recorded rather than forced: the copy itself
		// did its job, and the reverse direction is unaffected.
		run.halfCloseUnsupported.Store(true)
		return
	}
	if err := half.CloseWrite(); err != nil {
		if errors.Is(err, ErrHalfCloseUnsupported) {
			run.halfCloseUnsupported.Store(true)
			return
		}
		run.fail(engine.IOError, ReasonRelayHalfCloseFailed, direction)
	}
}

// count adds one direction's copied bytes to its own counter. The two counters
// are separate because they answer different questions and, in particular,
// because a proxy hop must never be counted as origin traffic (TLS-212).
func (run *relayRun) count(direction RelayDirection, n int64) {
	if direction == DownstreamToUpstream {
		run.toUpstream.Add(n)
		return
	}
	run.toDownstream.Add(n)
}

// markEnded records which of the two streams ended. Each name describes the
// peer whose stream ended, not the transport that was told about it.
func (run *relayRun) markEnded(direction RelayDirection) {
	if direction == DownstreamToUpstream {
		run.downstreamHalfClosed.Store(true)
		return
	}
	run.upstreamHalfClosed.Store(true)
}

// fail publishes one fault and interrupts both directions. Only the first fault
// survives: a connection has one terminal state, and the first thing that broke
// is the honest description of it.
func (run *relayRun) fail(code engine.Code, reason RelayReason, direction RelayDirection) {
	run.outcome.fault(code, reason, direction)
	run.interrupt()
	run.faultOnce.Do(func() { close(run.interrupted) })
}

// interrupt closes both transports exactly once. Closing is what unblocks a
// copy goroutine parked in a read or a write on the other side, so every
// failure path funnels through here.
func (run *relayRun) interrupt() {
	run.closeOnce.Do(func() {
		// A tls.Conn sends close_notify from Close, and that write is not
		// bounded by anything: a peer that stopped reading would otherwise keep
		// this close — and the join waiting for it — parked on a full socket
		// buffer. The transports are being abandoned, not finished, so an
		// immediate write deadline turns that send into an immediate failure.
		deadline := time.Now()
		_ = run.downstream.SetWriteDeadline(deadline)
		_ = run.upstream.SetWriteDeadline(deadline)
		_ = run.downstream.Close()
		_ = run.upstream.Close()
	})
}

// joinBounded waits for the copy goroutines after the relay has been torn down.
// It is only ever reached after a fault or a cancellation, so the budget bounds
// a shutdown and not a healthy connection: a quiet but working connection is
// never joined on a timer.
func (run *relayRun) joinBounded(finished <-chan struct{}) {
	timer := time.NewTimer(run.relay.join)
	defer timer.Stop()
	select {
	case <-finished:
	case <-timer.C:
		run.joinTimedOut.Store(true)
	}
}

// watchIdle ends a connection that has moved nothing for the idle budget. The
// watchdog is a separate policy from every deadline above it: §6.5 keeps the
// handshake budget out of the data path, and an idle budget is only ever
// configured deliberately.
func (run *relayRun) watchIdle() {
	step := run.relay.idle / 8
	if step < relayIdlePollFloor {
		step = relayIdlePollFloor
	}
	ticker := time.NewTicker(step)
	defer ticker.Stop()
	for {
		select {
		case <-run.stopWatch:
			return
		case <-run.interrupted:
			return
		case <-ticker.C:
			if run.finished.Load() {
				return
			}
			if run.activity.idleFor() >= run.relay.idle {
				// Not one direction's fault: the connection as a whole was
				// silent, so no Direction is reported.
				run.fail(engine.IOError, ReasonRelayIdleTimeout, "")
				return
			}
		}
	}
}

// result folds the run's recorded state into the one value the caller gets.
func (run *relayRun) result() Result {
	result := Result{
		Code:                 engine.OK,
		BytesToUpstream:      run.toUpstream.Load(),
		BytesToDownstream:    run.toDownstream.Load(),
		DownstreamHalfClosed: run.downstreamHalfClosed.Load(),
		UpstreamHalfClosed:   run.upstreamHalfClosed.Load(),
		HalfCloseUnsupported: run.halfCloseUnsupported.Load(),
		JoinTimedOut:         run.joinTimedOut.Load(),
	}
	if code, reason, direction, faulted := run.outcome.snapshot(); faulted {
		result.Code = code
		result.Reason = reason
		result.Direction = direction
	}
	return result
}

// relayOutcome holds the one terminal fault of a connection. Concurrent
// failures from both directions are expected — a reset is usually seen by both
// copies — and they must still produce one answer, so the first one is kept and
// every later one is dropped.
type relayOutcome struct {
	mu        sync.Mutex
	faulted   bool
	code      engine.Code
	reason    RelayReason
	direction RelayDirection
}

func (o *relayOutcome) fault(code engine.Code, reason RelayReason, direction RelayDirection) {
	o.mu.Lock()
	defer o.mu.Unlock()
	if o.faulted {
		return
	}
	o.faulted = true
	o.code = code
	o.reason = reason
	o.direction = direction
}

func (o *relayOutcome) snapshot() (engine.Code, RelayReason, RelayDirection, bool) {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.code, o.reason, o.direction, o.faulted
}

// relayActivity is when either direction last moved a byte. Writes count as
// activity as well as reads: a direction that keeps draining a slow peer is
// making progress, and a policy that ended it for being "idle" would be
// punishing exactly the connection that is working.
type relayActivity struct {
	mu   sync.Mutex
	last time.Time
}

func (a *relayActivity) mark() {
	a.mu.Lock()
	a.last = time.Now()
	a.mu.Unlock()
}

func (a *relayActivity) idleFor() time.Duration {
	a.mu.Lock()
	defer a.mu.Unlock()
	return time.Since(a.last)
}

// writeAll writes one chunk, reporting how many bytes the destination accepted.
// A partial write is not an error of its own — net.Conn is allowed to accept
// less than it was handed — so the remainder is written again; a destination
// that accepts nothing and reports no error would loop forever, so it is
// reported as a short write instead.
func writeAll(conn net.Conn, payload []byte) (int, error) {
	written := 0
	for len(payload) > 0 {
		n, err := conn.Write(payload)
		written += n
		payload = payload[n:]
		if err != nil {
			return written, err
		}
		if n == 0 {
			return written, io.ErrShortWrite
		}
	}
	return written, nil
}

// classifyRelayRead maps one failed read onto the fixed reason a connection
// event carries. A stream that ends inside a TLS record is separated from every
// other transport failure because it is the one that means "the rest of the
// answer is missing", and a proxy that reported it as a clean end would be
// claiming a truncated response was complete.
func classifyRelayRead(err error) (engine.Code, RelayReason) {
	if errors.Is(err, io.ErrUnexpectedEOF) {
		return engine.IOError, ReasonRelayStreamTruncated
	}
	return engine.IOError, ReasonRelayReadFailed
}

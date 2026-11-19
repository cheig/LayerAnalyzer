// Package secrets is the production downstream keylog path (TLS-210, design
// §8.1, §8.2).
//
// One capture's downstream secrets are the only secrets this engine produces:
// the downstream leg (TLS A) is the leg whose ClientHello is in the captured
// PCAP, and its client random is what a dissector matches on. The upstream leg
// (TLS B) gets no writer at all, so no upstream secret can be mixed into the
// capture's assets (C03 3, §8.1).
//
// The writer crypto/tls is given runs on the handshake path and the standard
// library serializes keylog writes, so it does exactly two things: split the
// bytes it is handed into complete NSS lines, and append them to one bounded
// in-memory queue shared by every connection of the capture. A single consumer
// goroutine hands the queued lines to the C05 offer_secret callback, which
// copies them into the platform's own bounded queue and returns. Encrypting and
// syncing them to disk is the platform consumer's work, never this package's,
// and never the handshake's (§8.2).
//
// A secret that cannot be queued or delivered is a lost secret, not a network
// failure. The sink records it, marks itself incomplete, stops accepting new
// interception candidates (AcceptingNewInterception), and lets the connection it
// belongs to keep running: §8.2's default policy is to degrade the capture's
// decryption completeness and keep forwarding traffic, never to turn a
// secret-copy failure into a broken connection. That is also why Write always
// reports the bytes it consumed: an error here would abort the client's
// handshake for a capture-side problem.
package secrets

import (
	"context"
	"sync"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

const (
	// DefaultQueueBytes is C10's secrets enqueue budget. It is one budget for
	// the whole capture, not one per connection: the ceiling is what bounds the
	// engine's memory when the platform consumer stalls.
	DefaultQueueBytes = 1 << 20
	// MaxQueueBytes is the ceiling on that budget. A caller may lower it, never
	// raise it: it is a resource budget, not a preference.
	MaxQueueBytes = DefaultQueueBytes
	// MaxLineBytes is one NSS line, the same 8 KiB limit C06 uses for a single
	// keylog line and the same limit the ABI's offer_secret accepts.
	MaxLineBytes = 8192
	// DefaultDrainTimeout is C10's stop-writer wait. Stopping waits for the
	// records already accepted, then reports what is left rather than waiting
	// without bound.
	DefaultDrainTimeout = 5 * time.Second
	// MaxDrainTimeout is the ceiling on that wait. A caller may shorten it.
	MaxDrainTimeout = DefaultDrainTimeout
)

// Callbacks is the admission-gated platform entry point. *engine.Callbacks
// implements it: once shutdown has closed admission a call returns CANCELLED
// without reaching the platform, and shutdown waits for an in-flight call to
// return before the caller releases its GlobalRef.
type Callbacks interface {
	Call(func(engine.Platform) engine.Code) engine.Code
}

var _ Callbacks = (*engine.Callbacks)(nil)

// Limits are the sink's two budgets. A zero field selects the default; a value
// above the ceiling is rejected rather than clamped.
type Limits struct {
	QueueBytes   int
	DrainTimeout time.Duration
}

func (l Limits) normalized() (Limits, engine.Code) {
	if l.QueueBytes < 0 || l.QueueBytes > MaxQueueBytes || l.DrainTimeout < 0 || l.DrainTimeout > MaxDrainTimeout {
		return Limits{}, engine.InvalidArgument
	}
	if l.QueueBytes == 0 {
		l.QueueBytes = DefaultQueueBytes
	}
	if l.DrainTimeout == 0 {
		l.DrainTimeout = DefaultDrainTimeout
	}
	return l, engine.OK
}

// Stats is the sink's observable state. It carries counts and fixed flags only:
// no label, client random, secret byte, connection identifier or platform text
// ever appears here, so a Stats value is safe to put in an event or a log.
type Stats struct {
	// PendingBytes excludes the record currently inside the platform callback.
	PendingBytes       int
	PendingRecords     int
	InFlightBytes      int
	PeakPendingBytes   int
	PeakPendingRecords int
	PeakRetainedBytes  int
	QueueLimitBytes    int
	SettleWaiters      int
	PeakSettleWaiters  int
	SettleTimeouts     uint64
	DrainTimeouts      uint64
	// Offered is how many NSS lines the downstream handshakes produced,
	// including the ones dropped before or instead of delivery.
	Offered uint64
	// Accepted is how many of them the platform reported as accepted. Accepted
	// means copied into the platform's bounded queue, not persisted (C05).
	Accepted uint64
	// Rejected is how many the platform refused (its queue was full, or it had
	// already failed). Each one is a secret this capture will not decrypt with.
	Rejected uint64
	// Dropped is how many never reached the platform because this sink's own
	// budget was exhausted, or because the line was not a usable NSS record.
	Dropped uint64
	// Incomplete is set by the first rejected or dropped record and never
	// cleared: a capture cannot become complete again by queueing more secrets.
	Incomplete bool
	// Draining reports that Drain has closed the sink to new records.
	Draining bool
}

// Sink owns one capture's bounded secret queue and its single consumer. It is
// safe for concurrent use and is shared by every connection of one engine run.
type Sink struct {
	capture   string
	callbacks Callbacks
	limits    Limits

	mu                 sync.Mutex
	cond               *sync.Cond
	pending            []record
	pendingBytes       int
	inFlightBytes      int
	peakPendingBytes   int
	peakPendingRecords int
	peakRetainedBytes  int
	settleWaiters      int
	peakSettleWaiters  int
	settleTimeouts     uint64
	drainTimeouts      uint64
	offered            uint64
	accepted           uint64
	rejected           uint64
	dropped            uint64
	incomplete         bool
	stopped            bool
	drained            chan struct{}
}

type record struct {
	connection string
	line       []byte
}

// NewSink validates the capture identifier, the platform gate and the budgets,
// then starts the one consumer goroutine. A caller that never drains the sink
// leaks that goroutine, so an engine must Drain on every shutdown path.
func NewSink(captureID string, callbacks Callbacks, limits Limits) (*Sink, engine.Code) {
	normalized, code := limits.normalized()
	if code != engine.OK || callbacks == nil || !engine.ValidID(captureID) {
		return nil, engine.InvalidArgument
	}
	sink := &Sink{capture: captureID, callbacks: callbacks, limits: normalized, drained: make(chan struct{})}
	sink.cond = sync.NewCond(&sink.mu)
	go sink.deliver()
	return sink, engine.OK
}

// Writer returns the per-connection writer to install as the downstream TLS
// configuration's KeyLogWriter. One writer belongs to one connection because
// the secrets do: they are keyed by that connection's client random.
func (s *Sink) Writer(connectionID string) (*Writer, engine.Code) {
	if s == nil || !engine.ValidID(connectionID) {
		return nil, engine.InvalidArgument
	}
	return &Writer{sink: s, connection: connectionID}, engine.OK
}

// Stats returns a consistent snapshot of the sink's counters.
func (s *Sink) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.statsLocked()
}

func (s *Sink) statsLocked() Stats {
	return Stats{
		PendingBytes:       s.pendingBytes,
		PendingRecords:     len(s.pending),
		InFlightBytes:      s.inFlightBytes,
		PeakPendingBytes:   s.peakPendingBytes,
		PeakPendingRecords: s.peakPendingRecords,
		PeakRetainedBytes:  s.peakRetainedBytes,
		QueueLimitBytes:    s.limits.QueueBytes,
		SettleWaiters:      s.settleWaiters,
		PeakSettleWaiters:  s.peakSettleWaiters,
		SettleTimeouts:     s.settleTimeouts,
		DrainTimeouts:      s.drainTimeouts,
		Offered:            s.offered,
		Accepted:           s.accepted,
		Rejected:           s.rejected,
		Dropped:            s.dropped,
		Incomplete:         s.incomplete,
		Draining:           s.stopped,
	}
}

// AcceptingNewInterception is the "no new MITM" gate of §8.2. While it is false
// the connection engine must pass new candidates through untouched instead of
// intercepting them, because their secrets could not be saved. Connections that
// are already established keep forwarding.
func (s *Sink) AcceptingNewInterception() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.incomplete && !s.stopped
}

// Complete reports whether every record this sink was given reached the
// platform. It is deliberately not a persistence claim: only the consumer that
// encrypts and syncs a record can advance the persisted watermark, so accepted
// is not persisted (C05).
func (s *Sink) Complete() bool {
	if s == nil {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.incomplete && s.offered == s.accepted && len(s.pending) == 0
}

// Drain closes the sink to new records and waits for the ones already accepted
// to reach the platform, bounded by the caller's context and by the sink's own
// drain budget whichever is sooner. Records still queued when the bound passes
// stay undelivered and are reported through Incomplete; the call never waits
// without bound (C10).
//
// Drain is idempotent. It does not stop the engine: it only ends this sink's
// admission, so a caller stops creating connections first and drains after.
func (s *Sink) Drain(ctx context.Context) Stats {
	if s == nil {
		return Stats{}
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if deadline, ok := ctx.Deadline(); !ok || time.Until(deadline) > s.limits.DrainTimeout {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, s.limits.DrainTimeout)
		defer cancel()
	}
	s.mu.Lock()
	s.stopped = true
	s.cond.Broadcast()
	s.mu.Unlock()
	select {
	case <-s.drained:
	case <-ctx.Done():
		// The consumer is still delivering. Records it has not reached are
		// undelivered, and the sink must not claim otherwise.
		s.mu.Lock()
		s.incomplete = true
		s.drainTimeouts++
		s.mu.Unlock()
	}
	return s.Stats()
}

// Settle waits, up to timeout, until every record the sink has been given has
// reached the platform, and reports whether that happened. It exists for a
// connection's last step: a terminal report that says "these records reached
// the platform" must be able to wait for the one delivery that is still in
// flight, and `offered == accepted` cannot be read without that wait because
// the delivery is asynchronous by construction (§8.2: the handshake never
// waits for the disk).
//
// It never waits without bound and it is not a drain: the sink keeps accepting
// records. A timeout of zero only inspects the current state. The answer is
// false as soon as anything was lost, because a loss cannot be undone, and it
// is capture-wide rather than per connection: the queue is shared, so a
// rejected record cannot be attributed to the connection that produced it.
func (s *Sink) Settle(timeout time.Duration) bool {
	if s == nil {
		return false
	}
	if timeout < 0 {
		timeout = 0
	}
	timeout = min(timeout, MaxDrainTimeout)
	deadline := time.Now().Add(timeout)
	// The consumer broadcasts after every delivery. A timer wakes this wait at
	// its own deadline even when nothing is delivered in between.
	timer := time.AfterFunc(timeout, func() {
		s.mu.Lock()
		defer s.mu.Unlock()
		s.cond.Broadcast()
	})
	defer timer.Stop()
	s.mu.Lock()
	defer s.mu.Unlock()
	s.settleWaiters++
	s.peakSettleWaiters = max(s.peakSettleWaiters, s.settleWaiters)
	defer func() { s.settleWaiters-- }()
	for (len(s.pending) > 0 || s.accepted+s.rejected < s.offered) &&
		!s.incomplete && !s.stopped && time.Now().Before(deadline) {
		s.cond.Wait()
	}
	complete := !s.incomplete && s.offered == s.accepted && len(s.pending) == 0
	if !complete && !s.incomplete && !s.stopped && timeout > 0 {
		s.settleTimeouts++
	}
	return complete
}

// deliver is the sink's single consumer. It hands one queued line at a time to
// the platform through the admission gate, so a shutdown that has closed
// admission ends the delivery path instead of leaving a call in flight.
func (s *Sink) deliver() {
	defer close(s.drained)
	for {
		s.mu.Lock()
		for len(s.pending) == 0 && !s.stopped {
			s.cond.Wait()
		}
		if len(s.pending) == 0 {
			s.mu.Unlock()
			return
		}
		next := s.pending[0]
		s.pending[0] = record{}
		s.pending = s.pending[1:]
		s.pendingBytes -= len(next.line)
		s.inFlightBytes = len(next.line)
		s.mu.Unlock()

		code := s.callbacks.Call(func(platform engine.Platform) engine.Code {
			return platform.OfferSecret(s.capture, next.connection, next.line)
		})
		// The platform copied what it needs; this copy is the only place the
		// secret bytes were held, so they are cleared rather than left for a
		// later allocation to reuse.
		clear(next.line)

		s.mu.Lock()
		s.inFlightBytes = 0
		if code == engine.OK {
			s.accepted++
		} else {
			s.rejected++
			s.incomplete = true
		}
		// A Settle that is waiting for exactly this delivery must be woken; the
		// counter it reads is not visible to it otherwise.
		s.cond.Broadcast()
		s.mu.Unlock()
	}
}

// enqueue takes ownership of line and appends it to the bounded queue. It never
// blocks: a full queue, a stopped sink or an already incomplete one drops the
// record and marks the loss.
func (s *Sink) enqueue(connection string, line []byte) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offered++
	if s.stopped || s.incomplete || s.pendingBytes+len(line) > s.limits.QueueBytes {
		s.dropped++
		s.incomplete = true
		clear(line)
		return
	}
	s.pending = append(s.pending, record{connection: connection, line: line})
	s.pendingBytes += len(line)
	s.peakPendingBytes = max(s.peakPendingBytes, s.pendingBytes)
	s.peakPendingRecords = max(s.peakPendingRecords, len(s.pending))
	s.peakRetainedBytes = max(s.peakRetainedBytes, s.pendingBytes+s.inFlightBytes)
	s.cond.Signal()
}

// drop records one line that was produced but cannot become a secret.
func (s *Sink) drop() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.offered++
	s.dropped++
	s.incomplete = true
}

// Records is how many complete NSS records this writer handed to the sink. It
// counts what the connection produced, not what reached the platform: whether
// those records survived is the sink's answer (Complete, and the per-record
// counters in Stats). A caller reads it after Close, so an unterminated
// fragment — which is a produced record that never arrived whole — is already
// accounted for on the sink side by then.
func (w *Writer) Records() uint64 {
	if w == nil {
		return 0
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.records
}

// Writer is the io.Writer one downstream TLS configuration receives. It is the
// only thing TLS-210 adds to the handshake path, and it is deliberately unable
// to fail or to block (see the package comment).
type Writer struct {
	sink       *Sink
	connection string

	mu       sync.Mutex
	partial  []byte
	overflow bool
	closed   bool
	records  uint64
}

// Write splits p into complete NSS lines and queues each one. A trailing
// fragment is kept until the rest of its line arrives; an unterminated line is
// reported by Close. Write always consumes all of p and never returns an error.
func (w *Writer) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return len(p), nil
	}
	for _, b := range p {
		if b == '\n' {
			w.flushLocked()
			continue
		}
		if len(w.partial) >= MaxLineBytes {
			// A line this long is not an NSS record, and buffering the rest of
			// it would only move the unbounded growth somewhere else.
			w.overflow = true
			continue
		}
		w.partial = append(w.partial, b)
	}
	return len(p), nil
}

// Close ends one connection's writer. crypto/tls terminates every keylog line,
// so a non-empty fragment here means a record was produced that never arrived
// whole; it is reported as a loss rather than kept.
func (w *Writer) Close() {
	if w == nil {
		return
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.closed {
		return
	}
	w.closed = true
	if w.overflow {
		w.overflow = false
		w.sink.drop()
	}
	if len(w.partial) > 0 {
		clear(w.partial)
		w.partial = nil
		w.sink.drop()
	}
}

// flushLocked hands one complete line to the sink. The buffer is passed on
// rather than reused, so the sink owns it and a caller reusing its own p after
// Write cannot reach a queued secret.
func (w *Writer) flushLocked() {
	line := w.partial
	w.partial = nil
	if w.overflow {
		w.overflow = false
		clear(line)
		w.sink.drop()
		return
	}
	if len(line) > 0 && line[len(line)-1] == '\r' {
		// A CRLF line ending is accepted and normalized away, matching the
		// import parser rather than inventing a second line-ending rule.
		line = line[:len(line)-1]
	}
	if len(line) == 0 {
		// An empty line is not a record: nothing was lost, so it is not counted
		// as one. crypto/tls never writes one.
		return
	}
	w.records++
	w.sink.enqueue(w.connection, line)
}

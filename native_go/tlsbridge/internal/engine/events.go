// Bounded connection events and the capture's real counters (TLS-212, design
// §8.2, §10.2, §15.3).
//
// §8.2 splits one capture into two channels and they must not be merged: the
// downstream key log goes through its own secrets path (TLS-210), and everything
// else — SNI, TLS versions, phases, errors, counts — goes through this one. No
// secret byte, key log line, CA private key or decrypted body can reach an Event:
// the struct has no field able to carry one, and every field it does have is
// bounded, so a flood of events costs a fixed amount of memory.
//
// The queue is bounded on purpose (§8.2: 元数据事件 1024 项). Two rules make it
// more than a ring buffer:
//
//   - A connection's terminal state is published once and cannot be displaced
//     by noise. When the queue is full, an ordinary event is dropped before a
//     terminal one. Recent terminal summaries are retained independently up to
//     their own bound; aggregate counters survive summary eviction.
//   - The counters are updated on every published event and are independent of
//     the queue, so they stay exact even while events are being dropped.
//
// A slow or absent UI consumer costs dropped events, never a producer waiting
// for queue space (§6.5). Publish uses a short bounded mutex section, with no
// reader wait, network I/O or disk I/O.
package engine

import (
	"encoding/json"
	"net"
	"sync"
)

const (
	// DefaultEventQueueSize is C10's ordinary-event budget. It bounds the memory
	// one capture's events can occupy when nobody polls.
	DefaultEventQueueSize = 1024
	// MaxEventQueueSize is the ceiling on that budget.
	MaxEventQueueSize = DefaultEventQueueSize
	// MaxPollEvents is C10's per-poll item ceiling.
	MaxPollEvents = 128
	// MaxPollBytes is C10's per-poll response ceiling. The item ceiling already
	// keeps a typical poll far below it; this is the hard bound.
	MaxPollBytes = 256 << 10
	// MaxEventFields bound one event's strings, so no single event can grow the
	// response without limit. They mirror the limits the gateway and the
	// verifier already apply to the same values.
	MaxEventSNI     = 253
	MaxEventTLS     = 16
	MaxEventALPN    = 64
	MaxEventReason  = 64
	MaxEventHashHex = 64
	MaxEventRandom  = 64
)

// Phase is a connection's lifecycle state (C04). The values are the fixed wire
// strings; a Kotlin reader maps them by name rather than by ordinal, so adding
// a phase cannot silently change what an older reader believes.
type Phase string

const (
	PhaseAccepted            Phase = "ACCEPTED"
	PhaseSniffing            Phase = "SNIFFING"
	PhaseUpstreamHandshake   Phase = "UPSTREAM_HANDSHAKE"
	PhaseDownstreamHandshake Phase = "DOWNSTREAM_HANDSHAKE"
	PhaseRelaying            Phase = "RELAYING"
	PhasePassthrough         Phase = "PASSTHROUGH"
	PhaseClosed              Phase = "CLOSED"
	PhaseFailed              Phase = "FAILED"
)

// Valid reports whether the phase is one of C04's states.
func (p Phase) Valid() bool {
	switch p {
	case PhaseAccepted, PhaseSniffing, PhaseUpstreamHandshake, PhaseDownstreamHandshake,
		PhaseRelaying, PhasePassthrough, PhaseClosed, PhaseFailed:
		return true
	default:
		return false
	}
}

// Terminal reports whether the phase ends a connection. Terminal states are
// published once and retained (C04).
func (p Phase) Terminal() bool { return p == PhaseClosed || p == PhaseFailed }

// Event is one connection event (C04). Optional fields are omitted when empty,
// which is what makes them optional on the Kotlin side too.
type Event struct {
	// CaptureID and ConnectionID identify the capture and the connection the
	// event belongs to. Both are validated ASCII identifiers.
	CaptureID    string `json:"captureId"`
	ConnectionID string `json:"connectionId"`
	// EventSequence is assigned by the queue and strictly increases across the
	// whole capture, so a consumer can drop anything it has already applied.
	EventSequence int64 `json:"eventSequence"`
	// MonotonicNanos is for measuring intervals inside the device, and
	// WallTimeMillis for showing a time. They are separate because only the
	// wall clock can be corrected while a capture is running.
	MonotonicNanos int64 `json:"monotonicNanos"`
	WallTimeMillis int64 `json:"wallTimeMillis"`
	// DestinationIP and DestinationPort are the original destination. The IP is
	// the one the connection was opened to, never a re-resolved address.
	DestinationIP     string `json:"destinationIp"`
	DestinationPort   uint16 `json:"destinationPort"`
	NetworkGeneration int64  `json:"networkGeneration"`
	// Optional: what the connection turned out to be.
	SNI                       string `json:"sni,omitempty"`
	DownstreamClientRandom    string `json:"downstreamClientRandom,omitempty"`
	DownstreamTLS             string `json:"downstreamTls,omitempty"`
	UpstreamTLS               string `json:"upstreamTls,omitempty"`
	ALPN                      string `json:"alpn,omitempty"`
	UpstreamCertificateSHA256 string `json:"upstreamCertificateSha256,omitempty"`
	// Phase is where the connection is now. DecisionReason and ErrorCode carry
	// the fixed strings a UI shows instead of prose invented at the call site.
	Phase          Phase  `json:"phase"`
	DecisionReason string `json:"decisionReason,omitempty"`
	ErrorCode      string `json:"errorCode,omitempty"`
	// SecretRecordsAccepted and SecretRecordsPersisted are the connection's
	// cumulative counts: accepted is what the platform queued, persisted is what
	// reached the disk. They are never equal claims (C05), and SecretsComplete
	// reports whether every record this connection produced was persisted.
	SecretRecordsAccepted  int64 `json:"secretRecordsAccepted"`
	SecretRecordsPersisted int64 `json:"secretRecordsPersisted"`
	SecretsComplete        bool  `json:"secretsComplete"`
}

// validate bounds every field and rejects an event the queue must not carry. It
// is what makes the memory bound on the queue a property of the event shape
// rather than a hope about its producers.
func (e Event) validate() Code {
	if !ValidID(e.CaptureID) || !ValidID(e.ConnectionID) {
		return InvalidArgument
	}
	if e.EventSequence != 0 {
		// The queue assigns the sequence; a producer that filled one in would be
		// asking to overwrite another connection's ordering.
		return InvalidArgument
	}
	if !e.Phase.Valid() || net.ParseIP(e.DestinationIP) == nil || e.DestinationPort == 0 {
		return InvalidArgument
	}
	if e.NetworkGeneration < 0 || e.MonotonicNanos < 0 || e.WallTimeMillis < 0 {
		return InvalidArgument
	}
	if e.SecretRecordsAccepted < 0 || e.SecretRecordsPersisted < 0 || e.SecretRecordsPersisted > e.SecretRecordsAccepted {
		return InvalidArgument
	}
	for _, field := range []struct {
		value string
		max   int
	}{
		{e.SNI, MaxEventSNI},
		{e.DownstreamClientRandom, MaxEventRandom},
		{e.DownstreamTLS, MaxEventTLS},
		{e.UpstreamTLS, MaxEventTLS},
		{e.ALPN, MaxEventALPN},
		{e.DecisionReason, MaxEventReason},
		{e.ErrorCode, MaxEventReason},
		{e.UpstreamCertificateSHA256, MaxEventHashHex},
	} {
		if len(field.value) > field.max {
			return InvalidArgument
		}
	}
	return OK
}

// Stats is one capture's real counters (TLS-212). Every field is a count or a
// fixed value: no destination, name, secret or platform text appears here, so a
// Stats value is safe in a stats response, a UI state or a log.
//
// The counters are deliberately separate, because §10.2 counts them separately:
// a connection whose two handshakes succeeded is proxied, a connection the rules
// bypassed is passthrough, and neither says anything about whether Wireshark
// will decrypt it. In particular DecryptedConnections does not exist here: only
// the analyser that actually recovered application data can make that claim
// (C03 7), and this engine is not it.
type Stats struct {
	// ConnectionsAccepted counts every connection this capture saw an event
	// for, whatever became of it.
	ConnectionsAccepted uint64 `json:"connectionsAccepted"`
	// ConnectionsProxied counts the connections whose two handshakes succeeded
	// and which entered relay. §10.2's "已代理" is this number.
	ConnectionsProxied uint64 `json:"connectionsProxied"`
	// ConnectionsPassthrough counts the connections that were forwarded
	// untouched — by a rule, by a capacity refusal, or because they were not
	// TLS.
	ConnectionsPassthrough uint64 `json:"connectionsPassthrough"`
	// ConnectionsClosed and ConnectionsFailed count terminal outcomes.
	ConnectionsClosed uint64 `json:"connectionsClosed"`
	ConnectionsFailed uint64 `json:"connectionsFailed"`
	// HandshakesFailed counts the failed connections that had not reached relay,
	// which is §10.2's "握手失败". A failure after the connection was already
	// proxied is a relay failure, not a handshake failure.
	HandshakesFailed uint64 `json:"handshakesFailed"`
	// SecretsIncomplete counts the proxied connections that ended without every
	// secret persisted. It is not a synonym for a failed connection, and it
	// never means "pinning": a downstream rejection is one possible cause among
	// several (§10.2).
	SecretsIncomplete uint64 `json:"secretsIncomplete"`
	// SecretRecordsAccepted and SecretRecordsPersisted are the capture totals
	// across connections, taken from the connections' own cumulative counts.
	SecretRecordsAccepted  uint64 `json:"secretRecordsAccepted"`
	SecretRecordsPersisted uint64 `json:"secretRecordsPersisted"`
	// BytesToUpstream and BytesToDownstream are the application bytes the relay
	// copied (TLS-211's Result). They are the engine's only byte counts: the
	// SOCKS hop sees the same connection from a different vantage, so its
	// counters must never be added to these (TLS-212's "不能重复计为上游流量").
	BytesToUpstream   int64 `json:"bytesToUpstream"`
	BytesToDownstream int64 `json:"bytesToDownstream"`
	// EventsPublished, EventsDropped and TerminalsSuppressed describe the event
	// path itself. A dropped event is a UI that did not keep up, not a lost
	// connection: the counters above are unaffected by it.
	EventsPublished     uint64 `json:"eventsPublished"`
	EventsDropped       uint64 `json:"eventsDropped"`
	TerminalsSuppressed uint64 `json:"terminalsSuppressed"`
	// EventsQueued and TerminalsRetained are the current sizes of the two
	// retained structures, so a reader can see the bounds working.
	EventsQueued                 int               `json:"eventsQueued"`
	TerminalsRetained            int               `json:"terminalsRetained"`
	ActiveRecords                int               `json:"activeRecords"`
	PeakActiveRecords            int               `json:"peakActiveRecords"`
	PeakEventsQueued             int               `json:"peakEventsQueued"`
	RecordLimit                  int               `json:"recordLimit"`
	TerminalLimit                int               `json:"terminalLimit"`
	RecordsRefused               uint64            `json:"recordsRefused"`
	TerminalsEvicted             uint64            `json:"terminalsEvicted"`
	HandshakeCapacityPassthrough uint64            `json:"handshakeCapacityPassthrough"`
	SecretsIncompletePassthrough uint64            `json:"secretsIncompletePassthrough"`
	PassthroughReasons           map[string]uint64 `json:"passthroughReasons"`
}

// connectionRecord is what the queue remembers about one connection. It exists
// so an event can be counted once per connection (a phase that is reported
// twice is one connection, not two) and so a terminal state can be retained
// after its event has been polled away.
type connectionRecord struct {
	seen            bool
	proxied         bool
	passthrough     bool
	intercepting    bool
	incomplete      bool
	secretAccepted  int64
	secretPersisted int64
	terminal        Event
	hasTerminal     bool
}

// Queue is one capture's bounded event queue and counters. One Queue belongs to
// one engine run; it is safe for concurrent use, and every Publish is a short,
// lock-bounded operation that never waits for a reader.
type Queue struct {
	size     int
	terminal int
	active   int

	mu       sync.Mutex
	pending  []Event
	records  map[string]*connectionRecord
	order    []string
	sequence int64
	stats    Stats
}

// NewQueue builds a queue. A size of zero selects C10's default and a size
// above the ceiling is rejected rather than clamped.
func NewQueue(size int) (*Queue, Code) {
	if size < 0 || size > MaxEventQueueSize {
		return nil, InvalidArgument
	}
	if size == 0 {
		size = DefaultEventQueueSize
	}
	return &Queue{
		size:     size,
		terminal: size,
		pending:  make([]Event, 0, size),
		records:  make(map[string]*connectionRecord),
	}, OK
}

// Publish adds one connection event and returns the sequence it was given.
//
// The queue assigns the sequence, so it is strictly increasing across the
// capture and a consumer can use it to reject a stale delivery (C04). An event
// for a connection that already published a terminal state is refused with
// StaleGeneration: a connection has one terminal state, and a second one is a
// producer bug rather than a second truth.
func (q *Queue) Publish(event Event) (int64, Code) {
	if q == nil {
		return 0, NotReady
	}
	if code := event.validate(); code != OK {
		return 0, code
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	record := q.records[event.ConnectionID]
	if record == nil {
		if !event.Phase.Terminal() && q.active >= MaxConnectionBudget {
			q.stats.RecordsRefused++
			return 0, CapacityExceeded
		}
		record = &connectionRecord{}
		q.records[event.ConnectionID] = record
		q.order = append(q.order, event.ConnectionID)
		if !event.Phase.Terminal() {
			q.active++
			q.stats.PeakActiveRecords = max(q.stats.PeakActiveRecords, q.active)
		}
	} else if !record.hasTerminal && event.Phase.Terminal() {
		q.active--
	}
	if record.hasTerminal {
		// Both a second terminal and anything after a terminal state are
		// refused. The connection is over; its counters were already settled.
		q.stats.TerminalsSuppressed++
		return 0, StaleGeneration
	}
	q.sequence++
	event.EventSequence = q.sequence
	q.accountLocked(record, event)
	q.enqueueLocked(event)
	if event.Phase.Terminal() {
		record.hasTerminal = true
		record.terminal = event
		q.trimTerminalsLocked()
	}
	q.stats.EventsPublished++
	return q.sequence, OK
}

// Poll removes and returns up to max events, oldest first. max is capped at
// MaxPollEvents and the returned slice at MaxPollBytes, so one poll can never
// be an unbounded response. It is the reader's call: a reader that never polls
// causes drops, never a blocked producer.
func (q *Queue) Poll(max int) []Event {
	if q == nil || max <= 0 {
		return nil
	}
	if max > MaxPollEvents {
		max = MaxPollEvents
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Event, 0, min(max, len(q.pending)))
	bytes := 0
	for len(q.pending) > 0 && len(out) < max {
		next := q.pending[0]
		size := eventBytes(next)
		if len(out) > 0 && bytes+size > MaxPollBytes {
			break
		}
		out = append(out, next)
		bytes += size
		// Shift the rest down rather than advancing the slice: a delivered
		// event must not be kept alive by the backing array.
		copy(q.pending, q.pending[1:])
		q.pending[len(q.pending)-1] = Event{}
		q.pending = q.pending[:len(q.pending)-1]
	}
	return out
}

// Terminals returns the retained terminal state of every connection the queue
// still remembers, in the order the connections were first seen. This is the
// summary a stop path reports: it is built from the connection records rather
// than from the event queue, so a flood of ordinary events cannot erase it.
func (q *Queue) Terminals() []Event {
	if q == nil {
		return nil
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	out := make([]Event, 0, len(q.records))
	for _, id := range q.order {
		if record, ok := q.records[id]; ok && record.hasTerminal {
			out = append(out, record.terminal)
		}
	}
	return out
}

// RecordTraffic adds the application bytes one finished relay copied (TLS-211's
// Result.BytesToUpstream/BytesToDownstream). It is the only traffic accounting
// the engine has, and it is fed at exactly one point per connection, so the
// same hop is never counted twice: the SOCKS side's own byte counters measure
// the same connection from the app's side of the proxy and are a different
// measurement, not an additional one.
func (q *Queue) RecordTraffic(toUpstream, toDownstream int64) Code {
	if q == nil {
		return NotReady
	}
	if toUpstream < 0 || toDownstream < 0 {
		return InvalidArgument
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	q.stats.BytesToUpstream += toUpstream
	q.stats.BytesToDownstream += toDownstream
	return OK
}

// Stats returns a consistent snapshot of the capture's counters.
func (q *Queue) Stats() Stats {
	if q == nil {
		return Stats{}
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	stats := q.stats
	stats.PassthroughReasons = make(map[string]uint64, len(q.stats.PassthroughReasons))
	for k, v := range q.stats.PassthroughReasons {
		stats.PassthroughReasons[k] = v
	}
	stats.EventsQueued = len(q.pending)
	stats.TerminalsRetained = q.terminalsLocked()
	stats.ActiveRecords = q.active
	stats.RecordLimit = MaxConnectionBudget + q.terminal
	stats.TerminalLimit = q.terminal
	return stats
}

// Len is the number of events waiting for a reader.
func (q *Queue) Len() int {
	if q == nil {
		return 0
	}
	q.mu.Lock()
	defer q.mu.Unlock()
	return len(q.pending)
}

// enqueueLocked appends one event, dropping an ordinary event if the queue is
// full. A terminal state is only displaced when every entry is a terminal
// state, so a flood of ordinary events can never hide one.
func (q *Queue) enqueueLocked(event Event) {
	if len(q.pending) >= q.size {
		drop := -1
		for index := range q.pending {
			if !q.pending[index].Phase.Terminal() {
				drop = index
				break
			}
		}
		if drop < 0 {
			if !event.Phase.Terminal() {
				q.stats.EventsDropped++
				return
			}
			drop = 0
		}
		copy(q.pending[drop:], q.pending[drop+1:])
		q.pending[len(q.pending)-1] = Event{}
		q.pending = q.pending[:len(q.pending)-1]
		q.stats.EventsDropped++
	}
	q.pending = append(q.pending, event)
	q.stats.PeakEventsQueued = max(q.stats.PeakEventsQueued, len(q.pending))
}

// accountLocked folds one event into the per-connection record and the capture
// counters. Counting through the record is what makes "one connection" mean one
// connection even when several of its events are delivered.
func (q *Queue) accountLocked(record *connectionRecord, event Event) {
	if !record.seen {
		record.seen = true
		q.stats.ConnectionsAccepted++
	}
	switch event.Phase {
	case PhaseSniffing, PhaseUpstreamHandshake, PhaseDownstreamHandshake:
		record.intercepting = true
	case PhaseRelaying:
		record.intercepting = true
		if !record.proxied {
			record.proxied = true
			q.stats.ConnectionsProxied++
		}
	case PhasePassthrough:
		// A bypassed connection is not being intercepted: a failure later on is
		// a forwarding failure, not a handshake failure.
		if !record.passthrough {
			record.passthrough = true
			q.stats.ConnectionsPassthrough++
			if q.stats.PassthroughReasons == nil {
				q.stats.PassthroughReasons = make(map[string]uint64)
			}
			q.stats.PassthroughReasons[boundedPassthroughReason(event.DecisionReason)]++
			switch event.DecisionReason {
			case "handshake_capacity_exceeded":
				q.stats.HandshakeCapacityPassthrough++
			case "secrets_incomplete":
				q.stats.SecretsIncompletePassthrough++
			}
		}
		record.intercepting = false
	case PhaseClosed:
		q.stats.ConnectionsClosed++
	case PhaseFailed:
		q.stats.ConnectionsFailed++
		if !record.proxied && !record.passthrough {
			q.stats.HandshakesFailed++
		}
	}
	if event.SecretRecordsAccepted > record.secretAccepted {
		q.stats.SecretRecordsAccepted += uint64(event.SecretRecordsAccepted - record.secretAccepted)
		record.secretAccepted = event.SecretRecordsAccepted
	}
	if event.SecretRecordsPersisted > record.secretPersisted {
		q.stats.SecretRecordsPersisted += uint64(event.SecretRecordsPersisted - record.secretPersisted)
		record.secretPersisted = event.SecretRecordsPersisted
	}
	// Only an intercepted connection can have incomplete secrets: a connection
	// that was never intercepted produced none, and counting it here would make
	// every bypassed connection look like a decryption loss.
	if event.Phase.Terminal() && record.proxied && !event.SecretsComplete && !record.incomplete {
		record.incomplete = true
		q.stats.SecretsIncomplete++
	}
}

// Count only fixed reasons. An arbitrary producer string cannot grow diagnostics
// or leak identifiers into an aggregate report.
func boundedPassthroughReason(reason string) string {
	switch reason {
	case "handshake_capacity_exceeded", "connection_capacity_exceeded", "secrets_incomplete",
		"fallback_downstream_leaf_unavailable", "disabled", "port_not_candidate", "application_not_selected",
		"bypass_rule", "no_include_match", "not_handshake_record", "bad_record_version", "bad_record_length",
		"malformed_client_hello", "unexpected_handshake_type", "client_hello_too_large", "no_supported_version",
		"prefix_budget_exceeded", "probe_timeout", "stream_ended", "read_error":
		return reason
	default:
		return "other"
	}
}

// Active records are never evicted. Completed records have an independent
// retention budget, trimmed on completion even when no new flow arrives.
// Aggregate counters survive eviction; duplicate suppression covers retained IDs.
func (q *Queue) trimTerminalsLocked() {
	for q.terminalsLocked() > q.terminal {
		for index, id := range q.order {
			stale, ok := q.records[id]
			if ok && stale.hasTerminal {
				copy(q.order[index:], q.order[index+1:])
				q.order[len(q.order)-1] = ""
				q.order = q.order[:len(q.order)-1]
				delete(q.records, id)
				q.stats.TerminalsEvicted++
				break
			}
		}
	}
}

func (q *Queue) terminalsLocked() int {
	count := 0
	for _, record := range q.records {
		if record.hasTerminal {
			count++
		}
	}
	return count
}

// eventBytes is how much one event costs in a poll response. It measures the
// same encoding the ABI marshals, so the byte ceiling is enforced against the
// bytes that will actually be sent.
func eventBytes(event Event) int {
	encoded, err := json.Marshal(event)
	if err != nil {
		// Unreachable: every field is a string, an integer or a bool. A
		// conservative estimate keeps the ceiling meaningful regardless.
		return MaxPollBytes
	}
	return len(encoded) + 1
}

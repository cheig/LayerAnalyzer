// Go counts the TLS candidate subset of Kotlin total TCP (direct + candidates).
// Gateway acquires before dial; pipeline reuses the lease. Counts must not be added.
package engine

import (
	"sync"
	"sync/atomic"
)

const (
	// DefaultConnectionBudget retains the original low migration default.
	DefaultConnectionBudget = 64
	// MaxConnectionBudget is the controlled NIO ceiling, not the production default.
	MaxConnectionBudget = 1024
	// DefaultHandshakeBudget is C10's limit on simultaneous TLS handshakes.
	DefaultHandshakeBudget = 8
	// MaxHandshakeBudget is the ceiling on that limit.
	MaxHandshakeBudget = DefaultHandshakeBudget
)

// Slot names one of the two budgets a connection can hold.
type Slot uint8

const (
	// ConnectionSlot is the long-lived slot: one per connection, for its whole
	// life, whether it ends up proxied, bypassed or refused.
	ConnectionSlot Slot = iota
	// HandshakeSlot is the short-lived slot: one per intercepted connection
	// while its two TLS handshakes run, released before relaying starts.
	HandshakeSlot
)

func (s Slot) String() string {
	switch s {
	case ConnectionSlot:
		return "connection"
	case HandshakeSlot:
		return "handshake"
	default:
		return "unknown"
	}
}

// Limits are the two shared ceilings. A zero field selects the C10 default; a
// value above its ceiling is rejected rather than clamped, because a clamped
// budget would silently admit more than the configuration asked for.
type Limits struct {
	Connections int
	Handshakes  int
}

// DefaultLimits is C10's initial budget, unmodified.
func DefaultLimits() Limits {
	return Limits{Connections: DefaultConnectionBudget, Handshakes: DefaultHandshakeBudget}
}

func (l Limits) normalized() (Limits, Code) {
	if l.Connections < 0 || l.Connections > MaxConnectionBudget ||
		l.Handshakes < 0 || l.Handshakes > MaxHandshakeBudget {
		return Limits{}, InvalidArgument
	}
	if l.Connections == 0 {
		l.Connections = DefaultConnectionBudget
	}
	if l.Handshakes == 0 {
		l.Handshakes = DefaultHandshakeBudget
	}
	return l, OK
}

// Usage is a consistent snapshot of one Budget. It carries counts only, so it
// is safe to put in a stats response or an event.
type Usage struct {
	// Connections and Handshakes are the slots held right now.
	Connections int `json:"connections"`
	Handshakes  int `json:"handshakes"`
	// ConnectionLimit and HandshakeLimit are the ceilings those counts were
	// taken against, so a reader never has to guess which defaults applied.
	ConnectionLimit int `json:"connectionLimit"`
	HandshakeLimit  int `json:"handshakeLimit"`
	// PeakConnections and PeakHandshakes are the high-water marks, which is what
	// answers "did this capture ever actually reach its budget".
	PeakConnections int `json:"peakConnections"`
	PeakHandshakes  int `json:"peakHandshakes"`
	// RefusedConnections and RefusedHandshakes count the acquisitions that were
	// turned down. A refused connection slot is a refused connection; a refused
	// handshake slot is a candidate that must be passed through instead
	// (§15.3).
	RefusedConnections uint64 `json:"refusedConnections"`
	RefusedHandshakes  uint64 `json:"refusedHandshakes"`
}

// Budget is the single accountant for both shared ceilings. One Budget belongs
// to one engine run and is handed to every half that admits work, so there is
// exactly one place where Go candidate connections are counted. It is safe for concurrent use, and its zero value is not usable:
// construct it with NewBudget.
type Budget struct {
	limits Limits

	mu                 sync.Mutex
	connections        int
	handshakes         int
	peakConnections    int
	peakHandshakes     int
	refusedConnections uint64
	refusedHandshakes  uint64
}

// NewBudget validates the two ceilings and returns the accountant. Zero fields
// take the C10 defaults; a value above a ceiling is rejected.
func NewBudget(limits Limits) (*Budget, Code) {
	normalized, code := limits.normalized()
	if code != OK {
		return nil, code
	}
	return &Budget{limits: normalized}, OK
}

// Limits returns the ceilings this budget was built with.
func (b *Budget) Limits() Limits {
	if b == nil {
		return Limits{}
	}
	return b.limits
}

// ConnectionCapacity is the gateway admission ceiling. Gateway and pipeline
// use the same candidate budget; pipeline never acquires the same flow twice.
func (b *Budget) ConnectionCapacity() int {
	if b == nil {
		return 0
	}
	return b.limits.Connections
}

// Acquire takes one slot. A full budget is answered with CapacityExceeded and
// the caller's own policy: a refused connection is a connection this capture
// will not handle, and a refused handshake means the candidate is forwarded
// untouched (§15.3).
//
// The returned Lease must be released on every exit path — a deferred
// lease.Release() at the top of the connection's function is the intended use.
// Acquire answers NotReady for a nil budget so an unassembled engine cannot
// silently admit unlimited work.
func (b *Budget) Acquire(slot Slot) (*Lease, Code) {
	if b == nil {
		return nil, NotReady
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	switch slot {
	case ConnectionSlot:
		if b.connections >= b.limits.Connections {
			b.refusedConnections++
			return nil, CapacityExceeded
		}
		b.connections++
		if b.connections > b.peakConnections {
			b.peakConnections = b.connections
		}
	case HandshakeSlot:
		if b.handshakes >= b.limits.Handshakes {
			b.refusedHandshakes++
			return nil, CapacityExceeded
		}
		b.handshakes++
		if b.handshakes > b.peakHandshakes {
			b.peakHandshakes = b.handshakes
		}
	default:
		return nil, InvalidArgument
	}
	lease := &Lease{budget: b, slot: slot}
	lease.held.Store(true)
	return lease, OK
}

// Usage returns a consistent snapshot of the budget.
func (b *Budget) Usage() Usage {
	if b == nil {
		return Usage{}
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return Usage{
		Connections:        b.connections,
		Handshakes:         b.handshakes,
		ConnectionLimit:    b.limits.Connections,
		HandshakeLimit:     b.limits.Handshakes,
		PeakConnections:    b.peakConnections,
		PeakHandshakes:     b.peakHandshakes,
		RefusedConnections: b.refusedConnections,
		RefusedHandshakes:  b.refusedHandshakes,
	}
}

// release returns one slot. A release that would take a count below zero is
// ignored rather than allowed to corrupt the budget: a double release is a bug
// in the caller, and it must not be able to hand the engine a connection budget
// larger than the one it was given.
func (b *Budget) release(slot Slot) {
	b.mu.Lock()
	defer b.mu.Unlock()
	switch slot {
	case ConnectionSlot:
		if b.connections > 0 {
			b.connections--
		}
	case HandshakeSlot:
		if b.handshakes > 0 {
			b.handshakes--
		}
	}
}

// Lease is one held slot. Release is idempotent and safe to call on a nil
// lease, so every exit path can defer it unconditionally. A released lease is
// inert: releasing it again neither changes the budget nor reports anything.
type Lease struct {
	budget *Budget
	slot   Slot
	once   sync.Once
	held   atomic.Bool
}

// Slot names the budget this lease was taken from.
func (l *Lease) Slot() Slot {
	if l == nil {
		return ConnectionSlot
	}
	return l.slot
}

// Held reports whether the slot is still held.
func (l *Lease) Held() bool {
	if l == nil {
		return false
	}
	return l.held.Load()
}

// Release returns the slot exactly once. The first call is the one that
// counts; every later call is a no-op, which is what makes "every exit branch
// releases its slot" cheap enough to state as a rule.
func (l *Lease) Release() {
	if l == nil {
		return
	}
	l.once.Do(func() {
		l.held.Store(false)
		l.budget.release(l.slot)
	})
}

// Owns validates a borrowed lease before the pipeline reuses it.
func (b *Budget) Owns(l *Lease) bool {
	return b != nil && l != nil && l.budget == b && l.slot == ConnectionSlot && l.Held()
}

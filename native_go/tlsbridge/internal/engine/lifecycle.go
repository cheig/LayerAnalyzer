// Package engine owns the production lifecycle. It never starts from init().
package engine

import (
	"context"
	"encoding/base64"
	"sync"
	"time"
)

type State string

const (
	New      State = "NEW"
	Starting State = "STARTING"
	Running  State = "RUNNING"
	Stopping State = "STOPPING"
	Stopped  State = "STOPPED"
)

// Platform calls must be entered through Call so shutdown can close admission
// and drain in-flight JNI calls before the caller releases its GlobalRef.
type Platform interface {
	PrepareSocket(int, int64) Code
	ResolveHost(string, int64) ([]byte, Code)
	VerifyUpstream([][]byte, string, string, string) Code
	OfferSecret(string, string, []byte) Code
}

// Session.Close cancels/joins every worker, including those awaiting platform
// callbacks. Factory must roll back partial resources before returning failure.
// Only a fully assembled gateway + connection pipeline may return a Session.
type Session struct {
	Port  uint16
	Token []byte // 43 base64url bytes; copied into ABI's dedicated output buffer
	Close func()
	// Read-only, bounded counters. Must remain safe while Close runs.
	Metrics func() RuntimeMetrics
	// Fixed numeric gateway admission counters only; never metadata or credentials.
	GatewayStats func() map[string]any
}

type RuntimeMetrics struct {
	CertificateCacheMisses           uint64 `json:"certificateCacheMisses"`
	CertificateCacheEvictions        uint64 `json:"certificateCacheEvictions"`
	CertificateCachePeakEntries      int    `json:"certificateCachePeakEntries"`
	CertificateIssuances             uint64 `json:"certificateIssuances"`
	CertificateIssueFailures         uint64 `json:"certificateIssueFailures"`
	CertificateIssuancesInFlight     int    `json:"certificateIssuancesInFlight"`
	CertificateIssuancesPeakInFlight int    `json:"certificateIssuancesPeakInFlight"`
	CertificateIssueWaiters          int    `json:"certificateIssueWaiters"`
	CertificateIssuePeakWaiters      int    `json:"certificateIssuePeakWaiters"`
	CertificateIssuesShared          uint64 `json:"certificateIssuesShared"`
	GoSecretsQueueRecords            int    `json:"goSecretsQueueRecords"`
	GoSecretsQueuePeakBytes          int    `json:"goSecretsQueuePeakBytes"`
	GoSecretsQueuePeakRecords        int    `json:"goSecretsQueuePeakRecords"`
	GoSecretsInFlightBytes           int    `json:"goSecretsInFlightBytes"`
	GoSecretsPeakRetainedBytes       int    `json:"goSecretsPeakRetainedBytes"`
	GoSecretsQueueLimitBytes         int    `json:"goSecretsQueueLimitBytes"`
	GoSecretsOffered                 uint64 `json:"goSecretsOffered"`
	GoSecretsAccepted                uint64 `json:"goSecretsAccepted"`
	GoSecretsRejected                uint64 `json:"goSecretsRejected"`
	GoSecretsDropped                 uint64 `json:"goSecretsDropped"`
	GoSecretsIncomplete              bool   `json:"goSecretsIncomplete"`
	GoSecretsSettleWaiters           int    `json:"goSecretsSettleWaiters"`
	GoSecretsPeakSettleWaiters       int    `json:"goSecretsPeakSettleWaiters"`
	GoSecretsSettleTimeouts          uint64 `json:"goSecretsSettleTimeouts"`
	GoSecretsDrainTimeouts           uint64 `json:"goSecretsDrainTimeouts"`
	ProbesActive                     int    `json:"probesActive"`
	ProbesPeakActive                 int    `json:"probesPeakActive"`
	ProbesStarted                    uint64 `json:"probesStarted"`
	ProbesFinished                   uint64 `json:"probesFinished"`
	ProbesIncomplete                 uint64 `json:"probesIncomplete"`
	ProbePrefixCapacityBytes         int    `json:"probePrefixCapacityBytes"`
	ProbePeakPrefixCapacityBytes     int    `json:"probePeakPrefixCapacityBytes"`
	ProbePrefixCapacityLimitBytes    int    `json:"probePrefixCapacityLimitBytes"`

	CertificateCacheEntries int    `json:"certificateCacheEntries"`
	CertificateCacheHits    uint64 `json:"certificateCacheHits"`
	GoSecretsQueueBytes     int    `json:"goSecretsQueueBytes"`
}

// Runtime is the per-run infrastructure the manager owns and the assembled
// pipeline shares: the two capacity budgets and the capture's bounded event
// queue (TLS-212). It is handed to the factory rather than created by it, so
// there is exactly one connection budget and one event queue per engine run and
// neither half can quietly keep a second one. Both are concurrency-safe and
// hold no key material, so the session may keep publishing into them until its
// Close returns.
type Runtime struct {
	Budget *Budget
	Events *Queue
}

type Factory func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code)

type Callbacks struct {
	mu       sync.Mutex
	closed   bool
	inFlight sync.WaitGroup
	platform Platform
}

func (c *Callbacks) Call(operation func(Platform) Code) Code {
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return Cancelled
	}
	c.inFlight.Add(1)
	c.mu.Unlock()
	defer c.inFlight.Done()
	return operation(c.platform)
}
func (c *Callbacks) closeAdmission() { c.mu.Lock(); c.closed = true; c.mu.Unlock() }

type instance struct {
	mu        sync.Mutex
	state     State
	handle    uint64
	cancel    context.CancelFunc
	callbacks *Callbacks
	session   *Session
	// runtime is created before the factory runs and never cleared: it carries
	// no key material, and a stop path still needs the counters it accumulated.
	runtime *Runtime
	done    chan struct{}
}

type Manager struct {
	mu          sync.Mutex
	issued      uint64
	active      *instance
	factory     Factory
	finalHandle uint64
	finalStats  map[string]any // one stopped run, counts only, cleared on next accepted start
	finalEvents *Queue         // bounded unread events; released after draining or the next accepted start
}

func NewManager(factory Factory) *Manager { return &Manager{factory: factory} }
func (m *Manager) Ready() bool            { return m.factory != nil }

func (m *Manager) Start(config Config, material Material, platform Platform) (uint64, uint16, []byte, Code) {
	if platform == nil || (config.SchemaVersion != 1 && config.SchemaVersion != 2) || !ValidID(config.CaptureID) || config.NetworkGeneration == nil || *config.NetworkGeneration < 0 || material.Certificate == nil || material.Signer == nil {
		return 0, 0, nil, InvalidArgument
	}
	// Validate the frozen start configuration before opening any run resources.
	frozen, code := config.RuntimeLimits()
	if code != OK {
		return 0, 0, nil, code
	}
	budget, code := NewBudget(Limits{Connections: frozen.TCP, Handshakes: frozen.TLSHandshakes})
	if code != OK {
		return 0, 0, nil, code
	}
	events, code := NewQueue(0)
	if code != OK {
		return 0, 0, nil, code
	}
	runtime := &Runtime{Budget: budget, Events: events}
	m.mu.Lock()
	if m.active != nil || m.factory == nil {
		m.mu.Unlock()
		return 0, 0, nil, NotReady
	}
	if m.issued == 1<<63-1 {
		m.mu.Unlock()
		return 0, 0, nil, CapacityExceeded
	}
	m.issued++
	m.finalHandle, m.finalStats, m.finalEvents = 0, nil, nil
	ctx, cancel := context.WithCancel(context.Background())
	e := &instance{state: New, handle: m.issued, cancel: cancel, callbacks: &Callbacks{platform: platform}, runtime: runtime, done: make(chan struct{})}
	e.state = Starting
	m.active = e
	m.mu.Unlock()
	session, code := m.factory(ctx, config, material, e.callbacks, runtime)
	if code == OK {
		if session == nil || session.Port == 0 || session.Close == nil || len(session.Token) != 43 {
			code = NotReady
		} else {
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(string(session.Token))
			if err != nil || len(decoded) != 32 {
				code = NotReady
			}
		}
	}
	e.mu.Lock()
	e.session = session
	if code == OK && e.state == Starting {
		e.state = Running
		token := append([]byte(nil), session.Token...)
		e.mu.Unlock()
		return e.handle, session.Port, token, OK
	}
	e.mu.Unlock()
	m.shutdown(e)
	<-e.done // Failure must release every callback before start returns.
	return 0, 0, nil, code
}

func (m *Manager) shutdown(e *instance) {
	e.mu.Lock()
	if e.state == Stopping || e.state == Stopped {
		e.mu.Unlock()
		return
	}
	e.state = Stopping
	e.callbacks.closeAdmission()
	e.cancel()
	session := e.session
	e.mu.Unlock()
	go func() {
		if session != nil && session.Close != nil {
			session.Close()
		}
		e.callbacks.inFlight.Wait()
		final := Envelope(OK)
		final["state"] = Stopped
		final["snapshotAtMillis"] = time.Now().UnixMilli()
		final["budget"] = e.runtime.Budget.Usage()
		final["events"] = e.runtime.Events.Stats()
		if session != nil && session.Metrics != nil {
			final["runtimeMetrics"] = session.Metrics()
		}
		if session != nil && session.GatewayStats != nil {
			final["gateway"] = session.GatewayStats()
		}
		e.mu.Lock()
		if session != nil {
			clear(session.Token)
		}
		e.session = nil
		e.callbacks.platform = nil
		e.state = Stopped
		e.mu.Unlock()
		m.mu.Lock()
		if m.active == e {
			m.active = nil
			m.finalHandle, m.finalStats, m.finalEvents = e.handle, final, e.runtime.Events
		}
		close(e.done)
		m.mu.Unlock()
	}()
}

func (m *Manager) Stop(handle uint64, timeout time.Duration) Code {
	if handle == 0 || timeout <= 0 || timeout > 5*time.Second {
		return InvalidArgument
	}
	m.mu.Lock()
	if handle > m.issued {
		m.mu.Unlock()
		return StaleGeneration
	}
	e := m.active
	if e == nil || e.handle != handle {
		m.mu.Unlock()
		return OK
	}
	m.mu.Unlock()
	// A handle is not public while STARTING. Reject guessed handles until the
	// factory finishes; this avoids closing callback ownership during startup.
	e.mu.Lock()
	state := e.state
	e.mu.Unlock()
	if state == Starting {
		return NotReady
	}
	m.shutdown(e)
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case <-e.done:
		return OK
	case <-timer.C:
		return NotReady
	}
}

// live resolves one handle to the instance it names. A handle the manager never
// issued, one from an earlier run, and one whose run has stopped all answer
// StaleGeneration; a run that is stopping still answers, so a stop path can
// drain what the pipeline already published.
func (m *Manager) live(handle uint64) (*instance, State, Code) {
	if handle == 0 {
		return nil, "", InvalidArgument
	}
	m.mu.Lock()
	e := m.active
	m.mu.Unlock()
	if e == nil || e.handle != handle {
		return nil, "", StaleGeneration
	}
	e.mu.Lock()
	defer e.mu.Unlock()
	if e.state == Stopped {
		return nil, "", StaleGeneration
	}
	return e, e.state, OK
}

func (m *Manager) Snapshot(handle uint64) (State, Code) {
	_, state, code := m.live(handle)
	return state, code
}

// Poll drains up to maxEvents connection events from the run's bounded queue.
//
// The ceiling is part of the contract, not a hint: maxEvents above MaxPollEvents
// is rejected rather than clamped, and the queue itself bounds both the number
// and the size of the events one poll can return, so no caller can turn a poll
// into an unbounded response (C10).
func (m *Manager) Poll(handle uint64, maxEvents uint32) (map[string]any, Code) {
	if maxEvents == 0 || maxEvents > MaxPollEvents {
		return Envelope(InvalidArgument), InvalidArgument
	}
	e, state, code := m.live(handle)
	var queue *Queue
	if code == OK {
		queue = e.runtime.Events
	} else {
		// Shutdown publishes terminal events while joining workers. Retain only
		// the bounded event queue, never the session/callbacks, so the owner can
		// drain those events after Stop succeeds. A subsequent Start expires it.
		m.mu.Lock()
		if handle != 0 && handle == m.finalHandle {
			queue = m.finalEvents
			state = Stopped
		}
		m.mu.Unlock()
		if queue == nil {
			return Envelope(code), code
		}
		if queue.Len() == 0 {
			m.mu.Lock()
			if m.finalEvents == queue {
				m.finalEvents = nil
			}
			m.mu.Unlock()
			return Envelope(StaleGeneration), StaleGeneration
		}
	}
	r := Envelope(OK)
	r["state"] = state
	events := queue.Poll(int(maxEvents))
	polled := make([]any, 0, len(events))
	for _, event := range events {
		polled = append(polled, event)
	}
	r["events"] = polled
	r["dropped"] = queue.Stats().EventsDropped
	if state == Stopped && queue.Len() == 0 {
		m.mu.Lock()
		if m.finalEvents == queue {
			m.finalEvents = nil
		}
		m.mu.Unlock()
	}
	return r, OK
}

// Stats returns the run's real counters: the two shared budgets, the capture's
// traffic, and the state of the event path itself (TLS-212). It carries no
// destination, name, secret or platform text, so it is safe for the UI, and it
// is computed from the connection records rather than the event queue, so a UI
// that has fallen behind still gets exact totals.
func (m *Manager) Stats(handle uint64) (map[string]any, Code) {
	e, state, code := m.live(handle)
	if code != OK {
		return Envelope(code), code
	}
	r := Envelope(OK)
	r["state"] = state
	r["budget"] = e.runtime.Budget.Usage()
	r["events"] = e.runtime.Events.Stats()
	e.mu.Lock()
	session := e.session
	e.mu.Unlock()
	if session != nil && session.Metrics != nil {
		r["runtimeMetrics"] = session.Metrics()
	}
	if session != nil && session.GatewayStats != nil {
		r["gateway"] = session.GatewayStats()
	}
	r["snapshotAtMillis"] = time.Now().UnixMilli()
	return r, OK
}

// FinalStats is used by the successful stop reply only. Stats keeps its stale-
// handle contract; Poll can drain the last stopped run's bounded event queue.
// No session, callback or token is retained.
func (m *Manager) FinalStats(handle uint64) map[string]any {
	m.mu.Lock()
	defer m.mu.Unlock()
	if handle == 0 || m.finalHandle != handle {
		return nil
	}
	r := make(map[string]any, len(m.finalStats))
	for k, v := range m.finalStats {
		if events, ok := v.(Stats); ok {
			copy := make(map[string]uint64, len(events.PassthroughReasons))
			for reason, count := range events.PassthroughReasons {
				copy[reason] = count
			}
			events.PassthroughReasons = copy
			r[k] = events
			continue
		}
		if nested, ok := v.(map[string]any); ok {
			copy := make(map[string]any, len(nested))
			for nk, nv := range nested {
				copy[nk] = nv
			}
			r[k] = copy
		} else {
			r[k] = v
		}
	}
	return r
}

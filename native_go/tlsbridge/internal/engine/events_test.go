package engine

import (
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// Synthetic events: real destinations, no traffic, no key material. The events
// this queue carries never hold a secret, and these fixtures do not pretend to
// be one.
func testEvent(connection string, phase Phase) Event {
	return Event{
		CaptureID:         "capture-1",
		ConnectionID:      connection,
		MonotonicNanos:    1_000,
		WallTimeMillis:    1_700_000_000_000,
		DestinationIP:     "203.0.113.7",
		DestinationPort:   443,
		NetworkGeneration: 3,
		Phase:             phase,
	}
}

func mustPublish(t *testing.T, queue *Queue, event Event) int64 {
	t.Helper()
	sequence, code := queue.Publish(event)
	if code != OK {
		t.Fatalf("publish %s/%s: %v", event.ConnectionID, event.Phase, code)
	}
	return sequence
}

func TestEventValidationRejectsMalformedEvents(t *testing.T) {
	valid := testEvent("connection-1", PhaseAccepted)
	if code := valid.validate(); code != OK {
		t.Fatal(code)
	}
	cases := map[string]func(*Event){
		"capture id":         func(e *Event) { e.CaptureID = "../capture" },
		"missing capture":    func(e *Event) { e.CaptureID = "" },
		"connection id":      func(e *Event) { e.ConnectionID = "" },
		"unknown phase":      func(e *Event) { e.Phase = "DECRYPTED" },
		"empty phase":        func(e *Event) { e.Phase = "" },
		"no destination":     func(e *Event) { e.DestinationIP = "" },
		"destination name":   func(e *Event) { e.DestinationIP = "example.test" },
		"zero port":          func(e *Event) { e.DestinationPort = 0 },
		"negative network":   func(e *Event) { e.NetworkGeneration = -1 },
		"negative monotonic": func(e *Event) { e.MonotonicNanos = -1 },
		"negative wall time": func(e *Event) { e.WallTimeMillis = -1 },
		"sequence set":       func(e *Event) { e.EventSequence = 9 },
		"negative accepted":  func(e *Event) { e.SecretRecordsAccepted = -1 },
		"persisted over accepted": func(e *Event) {
			e.SecretRecordsAccepted = 1
			e.SecretRecordsPersisted = 2
		},
		"long sni":             func(e *Event) { e.SNI = strings.Repeat("a", MaxEventSNI+1) },
		"long client random":   func(e *Event) { e.DownstreamClientRandom = strings.Repeat("a", MaxEventRandom+1) },
		"long downstream tls":  func(e *Event) { e.DownstreamTLS = strings.Repeat("a", MaxEventTLS+1) },
		"long upstream tls":    func(e *Event) { e.UpstreamTLS = strings.Repeat("a", MaxEventTLS+1) },
		"long alpn":            func(e *Event) { e.ALPN = strings.Repeat("a", MaxEventALPN+1) },
		"long decision reason": func(e *Event) { e.DecisionReason = strings.Repeat("a", MaxEventReason+1) },
		"long error code":      func(e *Event) { e.ErrorCode = strings.Repeat("a", MaxEventReason+1) },
		"long cert hash":       func(e *Event) { e.UpstreamCertificateSHA256 = strings.Repeat("a", MaxEventHashHex+1) },
	}
	queue, _ := NewQueue(0)
	for name, breakIt := range cases {
		broken := valid
		breakIt(&broken)
		if code := broken.validate(); code != InvalidArgument {
			t.Fatalf("%s accepted: %v", name, code)
		}
		if _, code := queue.Publish(broken); code != InvalidArgument {
			t.Fatalf("%s published: %v", name, code)
		}
	}
	// The boundaries themselves are accepted, so a maximum-length name is not a
	// rejected event.
	boundary := valid
	boundary.SNI = strings.Repeat("a", MaxEventSNI)
	boundary.ALPN = strings.Repeat("b", MaxEventALPN)
	boundary.UpstreamCertificateSHA256 = strings.Repeat("c", MaxEventHashHex)
	if code := boundary.validate(); code != OK {
		t.Fatalf("boundary event rejected: %v", code)
	}
	if queue.Len() != 0 {
		t.Fatal("a rejected event was queued")
	}
}

func TestPublishAssignsMonotonicSequences(t *testing.T) {
	queue, _ := NewQueue(0)
	for i := 0; i < 50; i++ {
		event := testEvent(fmt.Sprintf("connection-%d", i%5), PhaseSniffing)
		if got := mustPublish(t, queue, event); got != int64(i+1) {
			t.Fatalf("sequence %d at %d", got, i)
		}
	}
	if stats := queue.Stats(); stats.EventsPublished != 50 || stats.ConnectionsAccepted != 5 {
		t.Fatal(stats)
	}
}

func TestTerminalStateIsPublishedOnceAndRetained(t *testing.T) {
	queue, _ := NewQueue(0)
	mustPublish(t, queue, testEvent("connection-1", PhaseRelaying))
	terminal := testEvent("connection-1", PhaseFailed)
	terminal.ErrorCode = "UPSTREAM_CERT_INVALID"
	mustPublish(t, queue, terminal)

	for _, phase := range []Phase{PhaseFailed, PhaseClosed, PhaseSniffing} {
		event := testEvent("connection-1", phase)
		if _, code := queue.Publish(event); code != StaleGeneration {
			t.Fatalf("a second terminal or a later phase was accepted: %v", code)
		}
	}
	if stats := queue.Stats(); stats.TerminalsSuppressed != 3 {
		t.Fatal(stats.TerminalsSuppressed)
	}
	// A different connection is unaffected by the rule.
	mustPublish(t, queue, testEvent("connection-2", PhaseAccepted))

	terminals := queue.Terminals()
	if len(terminals) != 1 || terminals[0].ConnectionID != "connection-1" ||
		terminals[0].ErrorCode != "UPSTREAM_CERT_INVALID" || terminals[0].Phase != PhaseFailed {
		t.Fatalf("terminal summary: %+v", terminals)
	}
	// The summary outlives the event: polling everything away must not lose it.
	if got := len(queue.Poll(MaxPollEvents)); got != 3 {
		t.Fatalf("queued events: %d", got)
	}
	if len(queue.Poll(MaxPollEvents)) != 0 {
		t.Fatal("the queue was not drained")
	}
	if len(queue.Terminals()) != 1 {
		t.Fatal("the terminal summary was lost with the event")
	}
}

func TestTheQueueIsBoundedAndDropsOrdinaryEventsFirst(t *testing.T) {
	queue, _ := NewQueue(8)
	for i := 0; i < 7; i++ {
		mustPublish(t, queue, testEvent("connection-ordinary", PhaseSniffing))
	}
	mustPublish(t, queue, testEvent("connection-terminal", PhaseClosed))
	if queue.Len() != 8 {
		t.Fatal(queue.Len())
	}
	for i := 0; i < 200; i++ {
		mustPublish(t, queue, testEvent("connection-noise", PhaseUpstreamHandshake))
	}
	// Bounded: the queue never grows past its budget however hard it is pushed.
	if queue.Len() != 8 {
		t.Fatal(queue.Len())
	}
	delivered := queue.Poll(MaxPollEvents)
	if len(delivered) != 8 {
		t.Fatal(len(delivered))
	}
	found := false
	for _, event := range delivered {
		if event.ConnectionID == "connection-terminal" {
			found = true
		}
	}
	if !found {
		t.Fatal("a flood of ordinary events displaced a terminal state")
	}
	stats := queue.Stats()
	if stats.EventsDropped == 0 || stats.EventsPublished != 208 {
		t.Fatal(stats)
	}
	// The counters are independent of the queue, so dropping events to a slow
	// reader never changes what the capture reports.
	if stats.ConnectionsAccepted != 3 {
		t.Fatal(stats.ConnectionsAccepted)
	}
}

func TestPollHonoursTheItemAndByteCeilings(t *testing.T) {
	queue, _ := NewQueue(0)
	for i := 0; i < 600; i++ {
		event := testEvent(fmt.Sprintf("connection-%d", i), PhaseSniffing)
		event.SNI = strings.Repeat("s", MaxEventSNI)
		event.ALPN = strings.Repeat("a", MaxEventALPN)
		event.DownstreamClientRandom = strings.Repeat("d", MaxEventRandom)
		event.UpstreamCertificateSHA256 = strings.Repeat("e", MaxEventHashHex)
		event.DecisionReason = strings.Repeat("r", MaxEventReason)
		mustPublish(t, queue, event)
	}
	delivered := queue.Poll(1000)
	if len(delivered) != MaxPollEvents {
		t.Fatalf("item ceiling: %d", len(delivered))
	}
	encoded, err := json.Marshal(delivered)
	if err != nil {
		t.Fatal(err)
	}
	if len(encoded) > MaxPollBytes {
		t.Fatalf("byte ceiling: %d", len(encoded))
	}
	if len(queue.Poll(MaxPollEvents)) != MaxPollEvents {
		t.Fatal("the second poll was short")
	}
	for _, max := range []int{0, -1} {
		if queue.Poll(max) != nil {
			t.Fatal("a non-positive poll returned events")
		}
	}
	if queue.Len() != 600-2*MaxPollEvents {
		t.Fatal(queue.Len())
	}
}

func TestStatsSeparateProxiedPassthroughAndFailures(t *testing.T) {
	queue, _ := NewQueue(0)
	drive := func(connection string, phases ...Phase) {
		for _, phase := range phases {
			mustPublish(t, queue, testEvent(connection, phase))
		}
	}
	// Proxied and cleanly closed with all secrets persisted.
	for _, phase := range []Phase{PhaseAccepted, PhaseSniffing, PhaseUpstreamHandshake, PhaseDownstreamHandshake, PhaseRelaying} {
		mustPublish(t, queue, testEvent("intercepted-clean", phase))
	}
	clean := testEvent("intercepted-clean", PhaseClosed)
	clean.SecretRecordsAccepted, clean.SecretRecordsPersisted, clean.SecretsComplete = 3, 3, true
	mustPublish(t, queue, clean)
	// Bypassed by a rule, then closed.
	drive("bypassed", PhaseAccepted, PhasePassthrough, PhaseClosed)
	// Failed before relaying.
	failed := testEvent("handshake-failed", PhaseUpstreamHandshake)
	mustPublish(t, queue, failed)
	mustPublish(t, queue, testEvent("handshake-failed", PhaseFailed))
	// Proxied, then failed with secrets that never reached the disk.
	mustPublish(t, queue, testEvent("intercepted-lossy", PhaseRelaying))
	lossy := testEvent("intercepted-lossy", PhaseFailed)
	lossy.SecretRecordsAccepted, lossy.SecretRecordsPersisted, lossy.SecretsComplete = 2, 1, false
	mustPublish(t, queue, lossy)
	// Bypassed, then failed: a forwarding failure, not a handshake failure.
	drive("bypassed-failed", PhasePassthrough, PhaseFailed)

	stats := queue.Stats()
	if stats.ConnectionsAccepted != 5 || stats.ConnectionsProxied != 2 || stats.ConnectionsPassthrough != 2 {
		t.Fatal(stats)
	}
	if stats.ConnectionsClosed != 2 || stats.ConnectionsFailed != 3 || stats.HandshakesFailed != 1 {
		t.Fatal(stats)
	}
	if stats.SecretsIncomplete != 1 || stats.SecretRecordsAccepted != 5 || stats.SecretRecordsPersisted != 4 {
		t.Fatal(stats)
	}
	if stats.TerminalsRetained != 5 {
		t.Fatal(stats.TerminalsRetained)
	}
}

func TestSecretCountersAreCumulativeNotSummed(t *testing.T) {
	queue, _ := NewQueue(0)
	for _, counts := range [][3]int64{{1, 0, 0}, {3, 1, 0}, {4, 3, 0}} {
		event := testEvent("connection-1", PhaseRelaying)
		event.SecretRecordsAccepted, event.SecretRecordsPersisted = counts[0], counts[1]
		mustPublish(t, queue, event)
	}
	terminal := testEvent("connection-1", PhaseClosed)
	terminal.SecretRecordsAccepted, terminal.SecretRecordsPersisted, terminal.SecretsComplete = 4, 3, false
	mustPublish(t, queue, terminal)
	stats := queue.Stats()
	// The connection's own counts are cumulative, so the capture total is the
	// last value and not the sum of the three reports.
	if stats.SecretRecordsAccepted != 4 || stats.SecretRecordsPersisted != 3 {
		t.Fatal(stats)
	}
	if stats.SecretsIncomplete != 1 {
		t.Fatal(stats.SecretsIncomplete)
	}
}

func TestRecordTrafficCountsOneHop(t *testing.T) {
	queue, _ := NewQueue(0)
	if code := queue.RecordTraffic(1<<20, 4<<20); code != OK {
		t.Fatal(code)
	}
	if code := queue.RecordTraffic(0, 0); code != OK {
		t.Fatal(code)
	}
	if code := queue.RecordTraffic(-1, 0); code != InvalidArgument {
		t.Fatal(code)
	}
	stats := queue.Stats()
	if stats.BytesToUpstream != 1<<20 || stats.BytesToDownstream != 4<<20 {
		t.Fatal(stats)
	}
}

func TestTerminalSummariesAreBounded(t *testing.T) {
	queue, _ := NewQueue(4)
	for i := 0; i < 32; i++ {
		mustPublish(t, queue, testEvent(fmt.Sprintf("connection-%d", i), PhaseFailed))
	}
	if got := len(queue.Terminals()); got > 4 {
		t.Fatalf("terminal summary grew to %d", got)
	}
	// The aggregate counters are not bounded by the summary: every connection
	// was still counted while it was known.
	if stats := queue.Stats(); stats.ConnectionsAccepted != 32 || stats.ConnectionsFailed != 32 {
		t.Fatal(stats)
	}
}

func TestQueueDefaultsAndNilSafety(t *testing.T) {
	queue, code := NewQueue(0)
	if code != OK {
		t.Fatal(code)
	}
	if queue.size != DefaultEventQueueSize {
		t.Fatal(queue.size)
	}
	for _, size := range []int{-1, MaxEventQueueSize + 1} {
		if _, code := NewQueue(size); code != InvalidArgument {
			t.Fatalf("size %d accepted: %v", size, code)
		}
	}
	if _, code := (*Queue)(nil).Publish(testEvent("connection-1", PhaseAccepted)); code != NotReady {
		t.Fatal(code)
	}
	if (*Queue)(nil).Poll(8) != nil || (*Queue)(nil).Terminals() != nil || (*Queue)(nil).Len() != 0 {
		t.Fatal("nil queue answered a read")
	}
	if !reflect.DeepEqual((*Queue)(nil).Stats(), Stats{}) {
		t.Fatal("nil queue reported stats")
	}
}

func TestConcurrentPublishKeepsOneCountPerConnection(t *testing.T) {
	queue, _ := NewQueue(0)
	var wait sync.WaitGroup
	var sequences sync.Map
	var published atomic.Int64
	for worker := 0; worker < 16; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			connection := fmt.Sprintf("connection-%d", worker)
			for phase := 0; phase < 8; phase++ {
				event := testEvent(connection, PhaseSniffing)
				sequence, code := queue.Publish(event)
				if code != OK {
					t.Errorf("publish: %v", code)
					return
				}
				if _, duplicate := sequences.LoadOrStore(sequence, worker); duplicate {
					t.Errorf("sequence %d was assigned twice", sequence)
				}
				published.Add(1)
			}
			if _, code := queue.Publish(testEvent(connection, PhaseClosed)); code != OK {
				t.Errorf("terminal: %v", code)
			}
		}(worker)
	}
	wait.Wait()
	stats := queue.Stats()
	if stats.EventsPublished != 16*9 || published.Load() != 16*8 {
		t.Fatal(stats.EventsPublished, published.Load())
	}
	// One connection is one connection, however many of its events raced.
	if stats.ConnectionsAccepted != 16 || stats.ConnectionsProxied != 0 || stats.ConnectionsClosed != 16 {
		t.Fatal(stats)
	}
	if stats.TerminalsRetained != 16 || len(queue.Terminals()) != 16 {
		t.Fatal(stats.TerminalsRetained)
	}
	sequences.Range(func(key, value any) bool {
		if key.(int64) < 1 || uint64(key.(int64)) > stats.EventsPublished {
			t.Errorf("sequence %v out of range", key)
		}
		return true
	})
}

// The manager owns one budget and one queue per run and hands them to the
// assembled pipeline, so the ABI's poll and stats report the run's real
// counters rather than an empty list.
func TestManagerPollAndStatsReportTheRunCounters(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	var runtime *Runtime
	manager := NewManager(func(_ context.Context, _ Config, _ Material, _ *Callbacks, r *Runtime) (*Session, Code) {
		runtime = r
		return sessionStub(func() {}), OK
	})
	handle, _, _, code := manager.Start(cfg, mat, platformStub{})
	if code != OK {
		t.Fatal(code)
	}
	if runtime == nil || runtime.Budget == nil || runtime.Events == nil {
		t.Fatal("the factory did not receive the run's runtime")
	}
	lease, code := runtime.Budget.Acquire(HandshakeSlot)
	if code != OK {
		t.Fatal(code)
	}
	mustPublish(t, runtime.Events, testEvent("connection-1", PhaseRelaying))
	terminal := testEvent("connection-1", PhaseClosed)
	terminal.SecretRecordsAccepted, terminal.SecretRecordsPersisted, terminal.SecretsComplete = 2, 2, true
	mustPublish(t, runtime.Events, terminal)
	if code := runtime.Events.RecordTraffic(512, 1024); code != OK {
		t.Fatal(code)
	}

	r, code := manager.Poll(handle, MaxPollEvents)
	if code != OK {
		t.Fatal(code)
	}
	events, ok := r["events"].([]any)
	if !ok || len(events) != 2 {
		t.Fatalf("poll: %+v", r)
	}
	if state := r["state"]; state != Running {
		t.Fatal(state)
	}
	stats, code := manager.Stats(handle)
	if code != OK {
		t.Fatal(code)
	}
	budget, ok := stats["budget"].(Usage)
	if !ok || budget.Handshakes != 1 || budget.HandshakeLimit != DefaultHandshakeBudget {
		t.Fatalf("budget: %+v", stats["budget"])
	}
	queueStats, ok := stats["events"].(Stats)
	if !ok || queueStats.ConnectionsProxied != 1 || queueStats.BytesToUpstream != 512 || queueStats.BytesToDownstream != 1024 {
		t.Fatalf("stats: %+v", stats["events"])
	}
	// The budget survives the poll and the stats call, and a stop retires the
	// handle: after it there is nothing left to report against.
	if !lease.Held() {
		t.Fatal("the lease was released by a poll")
	}
	if code := manager.Stop(handle, time.Second); code != OK {
		t.Fatal(code)
	}
	if _, code := manager.Poll(handle, 1); code != StaleGeneration {
		t.Fatal(code)
	}
	if _, code := manager.Stats(handle); code != StaleGeneration {
		t.Fatal(code)
	}
	if _, code := manager.Stats(0); code != InvalidArgument {
		t.Fatal(code)
	}
	lease.Release()
}

package secrets

import (
	"context"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// Synthetic NSS lines. They are well-formed (so they exercise the real path)
// but correspond to no traffic, no fixture PCAP and no captured secret.
const (
	testCapture    = "capture-a"
	testConnection = "connection-1"
)

func line(label, randomByte, secretByte string, secretBytes int) string {
	return label + " " + strings.Repeat(randomByte, 32) + " " + strings.Repeat(secretByte, secretBytes)
}

func clientRandomLine() string    { return line("CLIENT_RANDOM", "ab", "cd", 48) }
func trafficSecretLine() string   { return line("CLIENT_TRAFFIC_SECRET_0", "ef", "12", 32) }
func handshakeSecretLine() string { return line("CLIENT_HANDSHAKE_TRAFFIC_SECRET", "34", "56", 32) }

type delivered struct {
	capture    string
	connection string
	line       string
}

// platformStub is the explicit C05 double. It records what crossed the
// boundary and can be made slow, blocking or rejecting on demand; it never
// writes a secret anywhere else.
type platformStub struct {
	mu      sync.Mutex
	calls   int
	records []delivered
	started chan struct{}
	release chan struct{}
	offer   func(call int, capture, connection string, text string) engine.Code
}

func newPlatform() *platformStub { return &platformStub{} }

func (p *platformStub) PrepareSocket(int, int64) engine.Code { return engine.NotReady }
func (p *platformStub) ResolveHost(string, int64) ([]byte, engine.Code) {
	return nil, engine.NotReady
}
func (p *platformStub) VerifyUpstream([][]byte, string, string, string) engine.Code {
	return engine.NotReady
}

func (p *platformStub) OfferSecret(capture, connection string, line []byte) engine.Code {
	p.mu.Lock()
	p.calls++
	call := p.calls
	p.records = append(p.records, delivered{capture: capture, connection: connection, line: string(line)})
	started, release, decide := p.started, p.release, p.offer
	p.mu.Unlock()
	if started != nil {
		select {
		case started <- struct{}{}:
		default:
		}
	}
	if release != nil {
		<-release
	}
	if decide != nil {
		return decide(call, capture, connection, string(line))
	}
	return engine.OK
}

func (p *platformStub) snapshot() []delivered {
	p.mu.Lock()
	defer p.mu.Unlock()
	return append([]delivered(nil), p.records...)
}

func (p *platformStub) callCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls
}

// gateStub is the admission gate. *engine.Callbacks is the production
// implementation (asserted at compile time); a stub is needed here only because
// the production type's admission switch is owned by engine.Manager, whose own
// tests cover it.
type gateStub struct {
	mu       sync.Mutex
	closed   bool
	platform engine.Platform
}

func (g *gateStub) Call(operation func(engine.Platform) engine.Code) engine.Code {
	g.mu.Lock()
	if g.closed {
		g.mu.Unlock()
		return engine.Cancelled
	}
	g.mu.Unlock()
	return operation(g.platform)
}

func (g *gateStub) closeAdmission() {
	g.mu.Lock()
	g.closed = true
	g.mu.Unlock()
}

func newSink(t *testing.T, limits Limits) (*Sink, *gateStub, *platformStub) {
	t.Helper()
	platform := newPlatform()
	gate := &gateStub{platform: platform}
	sink, code := NewSink(testCapture, gate, limits)
	if code != engine.OK {
		t.Fatalf("NewSink = %v", code)
	}
	return sink, gate, platform
}

func writer(t *testing.T, sink *Sink, connection string) *Writer {
	t.Helper()
	w, code := sink.Writer(connection)
	if code != engine.OK {
		t.Fatalf("Writer = %v", code)
	}
	return w
}

func write(t *testing.T, w *Writer, text string) {
	t.Helper()
	done := make(chan struct{})
	go func() {
		defer close(done)
		n, err := w.Write([]byte(text))
		if err != nil || n != len(text) {
			t.Errorf("Write = (%d, %v), want (%d, nil): a secret path must not fail the handshake", n, err, len(text))
		}
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("Write blocked: the keylog writer runs on the handshake path")
	}
}

// TestOneConnectionReachesThePlatform covers the ordinary path: a downstream
// configuration's writer hands each NSS line to the C05 callback under this
// capture's identifier and this connection's identifier.
func TestOneConnectionReachesThePlatform(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n"+trafficSecretLine()+"\n")
	w.Close()
	stats := sink.Drain(context.Background())

	if stats.Offered != 2 || stats.Accepted != 2 || stats.Rejected != 0 || stats.Dropped != 0 || stats.Incomplete {
		t.Fatalf("stats = %+v, want two accepted records and no loss", stats)
	}
	if !sink.Complete() {
		t.Fatal("a sink that delivered every record must report complete")
	}
	records := platform.snapshot()
	if len(records) != 2 {
		t.Fatalf("platform saw %d records, want 2", len(records))
	}
	for i, want := range []string{clientRandomLine(), trafficSecretLine()} {
		if records[i].capture != testCapture || records[i].connection != testConnection {
			t.Fatalf("record %d carried capture %q connection %q", i, records[i].capture, records[i].connection)
		}
		if records[i].line != want {
			t.Fatalf("record %d did not carry the line the writer was given", i)
		}
	}
}

// TestLineSplittingReassemblesPartialWrites pins the byte-level contract: the
// writer is handed an opaque stream, and only complete LF-terminated lines are
// records. A split at any position, a CRLF ending and a blank line all have to
// behave the same as one whole write.
func TestLineSplittingReassemblesPartialWrites(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	w := writer(t, sink, testConnection)
	text := clientRandomLine() + "\r\n" + "\n" + trafficSecretLine() + "\n"
	for i := 0; i < len(text); i++ {
		write(t, w, text[i:i+1])
	}
	w.Close()
	stats := sink.Drain(context.Background())

	if stats.Offered != 2 || stats.Accepted != 2 || stats.Incomplete {
		t.Fatalf("stats = %+v, want two records and no loss", stats)
	}
	records := platform.snapshot()
	if len(records) != 2 || records[0].line != clientRandomLine() || records[1].line != trafficSecretLine() {
		t.Fatalf("byte-at-a-time writes produced %d records, want the two complete lines", len(records))
	}
}

// TestTheWriterNeverFailsOrBlocksOnAFullQueue is §8.2's default policy: a
// secret that cannot be queued degrades the capture's completeness and
// suspends new interception, and the connection it belongs to is not broken.
func TestTheWriterNeverFailsOrBlocksOnAFullQueue(t *testing.T) {
	one := len(clientRandomLine()) + 1
	sink, _, platform := newSink(t, Limits{QueueBytes: 2 * one})
	platform.mu.Lock()
	platform.started = make(chan struct{}, 1)
	platform.release = make(chan struct{})
	platform.mu.Unlock()
	w := writer(t, sink, testConnection)

	write(t, w, clientRandomLine()+"\n")
	select {
	case <-platform.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the consumer never reached the platform")
	}
	// The consumer is now holding one record, so the queue holds exactly the
	// budget and the next line cannot fit.
	for i := 0; i < 3; i++ {
		write(t, w, clientRandomLine()+"\n")
	}
	stats := sink.Stats()
	// The consumer is still holding the first record, so the three that follow
	// are either queued or dropped here; none of them is delivered yet.
	if stats.InFlightBytes != len(clientRandomLine()) || stats.PendingRecords != 2 || stats.PeakRetainedBytes != 3*len(clientRandomLine()) || stats.PeakPendingBytes > stats.QueueLimitBytes {
		t.Fatal(stats)
	}
	if stats.PendingBytes != 2*len(clientRandomLine()) {
		t.Fatalf("queued bytes = %d, want %d excluding callback's record and line delimiters", stats.PendingBytes, 2*len(clientRandomLine()))
	}
	if stats.Offered != 4 || stats.Dropped == 0 || stats.Accepted+stats.Dropped+stats.Rejected > stats.Offered {
		t.Fatalf("stats = %+v, want the overflow counted against offered", stats)
	}
	if !stats.Incomplete {
		t.Fatal("a dropped secret must mark the capture incomplete")
	}
	if sink.AcceptingNewInterception() {
		t.Fatal("a dropped secret must stop new interception candidates")
	}
	if sink.Complete() {
		t.Fatal("a sink that dropped a record must not report complete")
	}
	// The connection itself keeps working: this is the whole point of dropping
	// instead of returning an error.
	write(t, w, clientRandomLine()+"\n")
	w.Close()
	close(platform.release)
	after := sink.Drain(context.Background())
	if after.PendingBytes != 0 {
		t.Fatalf("drain retained %d queue bytes", after.PendingBytes)
	}
	if after.Offered != 5 || after.Accepted+after.Dropped+after.Rejected != after.Offered {
		t.Fatalf("stats after the connection continued = %+v", after)
	}
}

// TestAnOverlongLineIsDroppedWithoutUnboundedGrowth checks the writer's own
// bound: a line that cannot be an NSS record is discarded as it arrives instead
// of being buffered until a newline that may never come.
func TestAnOverlongLineIsDroppedWithoutUnboundedGrowth(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	w := writer(t, sink, testConnection)
	huge := strings.Repeat("A", 4*MaxLineBytes)
	write(t, w, huge)
	write(t, w, "\n")
	w.Close()
	stats := sink.Drain(context.Background())

	if stats.Offered != 1 || stats.Dropped != 1 || stats.Accepted != 0 || !stats.Incomplete {
		t.Fatalf("stats = %+v, want the overlong line dropped once", stats)
	}
	if len(platform.snapshot()) != 0 {
		t.Fatal("an overlong line must never reach the platform")
	}
}

// TestAnUnfinishedLineIsReportedByClose: crypto/tls terminates every line, so a
// fragment left at Close is a record that never arrived whole and is reported
// rather than kept.
func TestAnUnfinishedLineIsReportedByClose(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine())
	w.Close()
	w.Close() // idempotent
	stats := sink.Drain(context.Background())

	if stats.Offered != 1 || stats.Dropped != 1 || !stats.Incomplete {
		t.Fatalf("stats = %+v, want the unterminated line reported once", stats)
	}
	if len(platform.snapshot()) != 0 {
		t.Fatal("an unterminated line must never reach the platform")
	}
}

// TestWriteAfterCloseIsIgnored: a connection that has ended must not be able to
// add secrets, and closing it twice must not double-count.
func TestWriteAfterCloseIsIgnored(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	w.Close()
	write(t, w, trafficSecretLine()+"\n")
	stats := sink.Drain(context.Background())

	if stats.Offered != 1 || stats.Accepted != 1 {
		t.Fatalf("stats = %+v, want only the record written before Close", stats)
	}
	if len(platform.snapshot()) != 1 {
		t.Fatal("a closed writer must not deliver anything")
	}
}

// TestTheSinkDoesNotRetainTheCallersBuffer: the bytes crypto/tls hands over are
// its own buffer, so the queued secret must not alias it.
func TestTheSinkDoesNotRetainTheCallersBuffer(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	w := writer(t, sink, testConnection)
	buffer := []byte(clientRandomLine() + "\n")
	if _, err := w.Write(buffer); err != nil {
		t.Fatalf("Write = %v", err)
	}
	clear(buffer)
	sink.Drain(context.Background())

	records := platform.snapshot()
	if len(records) != 1 || records[0].line != clientRandomLine() {
		t.Fatal("the delivered line was mutated after Write returned")
	}
}

// TestAPlatformRejectionMarksTheSinkIncomplete: the platform refusing a record
// is a lost secret, not a network failure. The connection is not broken and the
// sink stops offering new interception candidates.
func TestAPlatformRejectionMarksTheSinkIncomplete(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	platform.offer = func(int, string, string, string) engine.Code { return engine.SecretsIncomplete }
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	w.Close()
	stats := sink.Drain(context.Background())

	if stats.Accepted != 0 || stats.Rejected != 1 || !stats.Incomplete {
		t.Fatalf("stats = %+v, want one rejected record", stats)
	}
	if sink.AcceptingNewInterception() {
		t.Fatal("a rejected secret must stop new interception candidates")
	}
	if sink.Complete() {
		t.Fatal("a rejected secret must not be reported as complete")
	}
}

// TestAClosedAdmissionEndsDeliveryWithoutBlocking: once shutdown has closed
// admission, a queued record is not delivered and the sink reports it as
// rejected instead of leaving a call in flight against a released GlobalRef.
func TestAClosedAdmissionEndsDeliveryWithoutBlocking(t *testing.T) {
	sink, gate, platform := newSink(t, Limits{})
	w := writer(t, sink, testConnection)
	gate.closeAdmission()
	write(t, w, clientRandomLine()+"\n")
	done := make(chan Stats, 1)
	go func() { done <- sink.Drain(context.Background()) }()
	select {
	case stats := <-done:
		if stats.Rejected != 1 || stats.Accepted != 0 || !stats.Incomplete {
			t.Fatalf("stats = %+v, want one rejected record after admission closed", stats)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not return after admission closed")
	}
	if platform.callCount() != 0 {
		t.Fatal("a closed admission must not reach the platform")
	}
}

// TestDrainDeliversAcceptedRecordsAndRefusesLaterOnes: draining ends the sink's
// admission, delivers what was already accepted, and drops whatever arrives
// afterwards without waiting for it.
func TestDrainDeliversAcceptedRecordsAndRefusesLaterOnes(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	platform.mu.Lock()
	platform.started = make(chan struct{}, 1)
	platform.release = make(chan struct{})
	platform.mu.Unlock()
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	select {
	case <-platform.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the consumer never reached the platform")
	}
	write(t, w, trafficSecretLine()+"\n")

	drained := make(chan Stats, 1)
	go func() { drained <- sink.Drain(context.Background()) }()
	// The drain cannot finish while the platform is still holding the first
	// record, so the sink is observably draining before it is released.
	deadline := time.Now().Add(5 * time.Second)
	for !sink.Stats().Draining && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if !sink.Stats().Draining {
		t.Fatal("Drain did not close the sink to new records")
	}
	write(t, w, handshakeSecretLine()+"\n")
	close(platform.release)

	var stats Stats
	select {
	case stats = <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("Drain did not return")
	}
	if stats.Accepted != 2 || stats.Offered != 3 || stats.Dropped != 1 || !stats.Incomplete {
		t.Fatalf("stats = %+v, want the two queued records delivered and the later one dropped", stats)
	}
	if len(platform.snapshot()) != 2 {
		t.Fatalf("platform saw %d records, want the 2 accepted before the drain", len(platform.snapshot()))
	}
	if sink.AcceptingNewInterception() {
		t.Fatal("a drained sink must not accept new interception candidates")
	}
}

// TestDrainIsBoundedWhenThePlatformStalls: a stalled consumer must not make a
// stop wait without bound (C10). The records it has not reached stay
// undelivered and the sink says so.
func TestDrainIsBoundedWhenThePlatformStalls(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	platform.mu.Lock()
	platform.started = make(chan struct{}, 1)
	platform.release = make(chan struct{})
	platform.mu.Unlock()
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	select {
	case <-platform.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the consumer never reached the platform")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	stats := sink.Drain(ctx)
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Drain took %s with a 50 ms bound", elapsed)
	}
	if !stats.Incomplete || stats.Accepted != 0 || !stats.Draining {
		t.Fatalf("stats = %+v, want an incomplete, drained sink", stats)
	}
	close(platform.release) // let the consumer finish so no goroutine is left
}

// TestDrainUsesItsOwnBudgetWithoutACallerDeadline: C10's stop-writer wait is a
// budget the sink applies itself, so a caller that passes no deadline still
// cannot hang a stop.
func TestDrainUsesItsOwnBudgetWithoutACallerDeadline(t *testing.T) {
	sink, _, platform := newSink(t, Limits{DrainTimeout: 100 * time.Millisecond})
	platform.mu.Lock()
	platform.started = make(chan struct{}, 1)
	platform.release = make(chan struct{})
	platform.mu.Unlock()
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	select {
	case <-platform.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the consumer never reached the platform")
	}

	start := time.Now()
	stats := sink.Drain(context.Background())
	if elapsed := time.Since(start); elapsed > 3*time.Second {
		t.Fatalf("Drain took %s with a 100 ms budget", elapsed)
	}
	if !stats.Incomplete {
		t.Fatal("a drain that ran out of budget must report the capture incomplete")
	}
	close(platform.release)
}

// TestConcurrentConnectionsShareOneBudgetAndOneDeliveryPath: many connections
// enqueue at once, and every record is accounted for exactly once.
func TestConcurrentConnectionsShareOneBudgetAndOneDeliveryPath(t *testing.T) {
	const connections, perConnection = 16, 32
	sink, _, platform := newSink(t, Limits{QueueBytes: MaxQueueBytes})
	var group sync.WaitGroup
	for i := 0; i < connections; i++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			w, code := sink.Writer(fmt.Sprintf("connection-%d", index))
			if code != engine.OK {
				t.Errorf("Writer = %v", code)
				return
			}
			for j := 0; j < perConnection; j++ {
				if _, err := w.Write([]byte(clientRandomLine() + "\n")); err != nil {
					t.Errorf("Write = %v", err)
					return
				}
			}
			w.Close()
		}(i)
	}
	group.Wait()
	stats := sink.Drain(context.Background())

	if stats.Offered != connections*perConnection {
		t.Fatalf("offered = %d, want %d", stats.Offered, connections*perConnection)
	}
	if stats.Accepted+stats.Dropped+stats.Rejected != stats.Offered {
		t.Fatalf("stats = %+v, want every record accounted for once", stats)
	}
	if stats.Incomplete {
		t.Fatalf("a sink with the full C10 budget must not lose records: %+v", stats)
	}
	if got := len(platform.snapshot()); got != int(stats.Accepted) {
		t.Fatalf("platform saw %d records, want %d", got, stats.Accepted)
	}
}

// TestSinkAndWriterValidation: every entry point rejects what it cannot serve,
// and a nil sink answers instead of panicking.
func TestSinkAndWriterValidation(t *testing.T) {
	platform := newPlatform()
	gate := &gateStub{platform: platform}
	for name, test := range map[string]struct {
		capture   string
		callbacks Callbacks
		limits    Limits
	}{
		"empty capture":      {"", gate, Limits{}},
		"capture with slash": {"a/b", gate, Limits{}},
		"capture too long":   {strings.Repeat("a", 129), gate, Limits{}},
		"no callbacks":       {testCapture, nil, Limits{}},
		"queue over ceiling": {testCapture, gate, Limits{QueueBytes: MaxQueueBytes + 1}},
		"negative queue":     {testCapture, gate, Limits{QueueBytes: -1}},
		"drain over ceiling": {testCapture, gate, Limits{DrainTimeout: MaxDrainTimeout + time.Second}},
		"negative drain":     {testCapture, gate, Limits{DrainTimeout: -time.Second}},
	} {
		t.Run(name, func(t *testing.T) {
			if sink, code := NewSink(test.capture, test.callbacks, test.limits); sink != nil || code != engine.InvalidArgument {
				t.Fatalf("NewSink = (%v, %v), want (nil, INVALID_ARGUMENT)", sink, code)
			}
		})
	}
	sink, _, _ := newSink(t, Limits{})
	for _, id := range []string{"", "a/b", "a b", strings.Repeat("a", 129)} {
		if w, code := sink.Writer(id); w != nil || code != engine.InvalidArgument {
			t.Fatalf("Writer(%q) = (%v, %v), want (nil, INVALID_ARGUMENT)", id, w, code)
		}
	}
	var none *Sink
	if none.AcceptingNewInterception() || none.Complete() {
		t.Fatal("a nil sink must not claim to be usable")
	}
	if stats := none.Drain(context.Background()); stats != (Stats{}) {
		t.Fatalf("nil sink Drain = %+v", stats)
	}
}

// TestZeroLimitsSelectTheDocumentedDefaults: a caller that passes no budget gets
// C10's, not an unbounded queue and not an instant drain failure.
func TestZeroLimitsSelectTheDocumentedDefaults(t *testing.T) {
	sink, _, _ := newSink(t, Limits{})
	if sink.limits.QueueBytes != DefaultQueueBytes || sink.limits.DrainTimeout != DefaultDrainTimeout {
		t.Fatalf("limits = %+v, want the C10 defaults", sink.limits)
	}
	sink.Drain(context.Background())
	if stats := sink.Stats(); !stats.Draining || stats.Offered != 0 || stats.Incomplete {
		t.Fatalf("stats = %+v, want a clean, drained, empty sink", stats)
	}
}

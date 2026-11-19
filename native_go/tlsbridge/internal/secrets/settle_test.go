package secrets

import (
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// The settle wait and the per-connection record count are what a connection's
// last step needs (TLS-213): a terminal report that says "these records reached
// the platform" must be able to wait for the one delivery still in flight, and
// it must be able to stop waiting. These cases pin both, and the fact that the
// wait is bounded by its caller rather than by the sink.

func TestRecordsCountsWhatAConnectionProduced(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	defer sink.Drain(nil)
	w := writer(t, sink, testConnection)
	// Lines split across Write calls, which is what crypto/tls does.
	write(t, w, clientRandomLine()+"\n"+trafficSecretLine()[:20])
	write(t, w, trafficSecretLine()[20:]+"\n"+handshakeSecretLine()+"\n\n")
	if got := w.Records(); got != 3 {
		t.Fatalf("Records = %d, want the three complete lines", got)
	}
	// A record that never arrives whole. The writer counts only what it handed
	// on; Close is what reports the fragment as a loss.
	write(t, w, "CLIENT_TRAFFIC_SECRET_0 abcdef")
	if got := w.Records(); got != 3 {
		t.Fatalf("Records with a fragment pending = %d, want 3", got)
	}
	w.Close()
	if got := w.Records(); got != 3 {
		t.Fatalf("Records after Close = %d, want 3", got)
	}
	// The wait is what makes the records' fate knowable: the delivery is
	// asynchronous, so nothing else can report how many reached the platform.
	sink.Settle(5 * time.Second)
	if sink.Complete() {
		t.Fatal("a connection whose last line never arrived whole reported itself complete")
	}
	// A loss ends the wait by design (there is nothing left to wait for), so the
	// two records that were already queued are observed rather than waited on.
	waitForCalls(t, platform, 3)
}

// waitForCalls waits until the platform has been handed want records.
func waitForCalls(t *testing.T, platform *platformStub, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if platform.callCount() >= want {
			return
		}
		time.Sleep(time.Millisecond)
	}
	t.Fatalf("the platform was handed %d records, want %d", platform.callCount(), want)
}

func TestSettleWaitsForTheDeliveryInFlight(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	defer sink.Drain(nil)
	platform.started = make(chan struct{}, 4)
	platform.release = make(chan struct{})
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	w.Close()
	select {
	case <-platform.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the sink never started delivering")
	}
	if stats := sink.Stats(); stats.PendingBytes != 0 || stats.InFlightBytes == 0 || stats.PeakPendingBytes == 0 {
		t.Fatal(stats)
	}
	settled := make(chan bool, 1)
	go func() { settled <- sink.Settle(5 * time.Second) }()
	select {
	case result := <-settled:
		t.Fatalf("Settle returned %v while a record was still in flight", result)
	case <-time.After(100 * time.Millisecond):
	}
	close(platform.release)
	select {
	case result := <-settled:
		if !result {
			t.Fatal("Settle reported a loss after the delivery completed")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Settle never returned after the delivery completed")
	}
	if stats := sink.Stats(); stats.InFlightBytes != 0 || stats.SettleWaiters != 0 || stats.PeakSettleWaiters != 1 {
		t.Fatal(stats)
	}
	if !sink.Complete() {
		t.Fatal("the sink is not complete after every record was delivered")
	}
}

func TestSettleStopsAtItsOwnBudget(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	defer sink.Drain(nil)
	platform.started = make(chan struct{}, 4)
	platform.release = make(chan struct{})
	defer close(platform.release)
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	w.Close()
	select {
	case <-platform.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the sink never started delivering")
	}
	start := time.Now()
	if sink.Settle(50 * time.Millisecond) {
		t.Fatal("Settle reported success while a delivery was blocked")
	}
	if stats := sink.Stats(); stats.SettleTimeouts != 1 || stats.SettleWaiters != 0 {
		t.Fatal(stats)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("Settle waited %s, want no more than its budget", elapsed)
	}
}

func TestSettleReportsALossInsteadOfWaitingForIt(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	defer sink.Drain(nil)
	platform.offer = func(int, string, string, string) engine.Code { return engine.CapacityExceeded }
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	w.Close()
	// A loss cannot be undone, so the wait must not sit out its whole budget
	// waiting for something that will never happen.
	start := time.Now()
	if sink.Settle(5 * time.Second) {
		t.Fatal("Settle reported success after the platform refused a record")
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("Settle waited %s on a capture that had already lost a record", elapsed)
	}
	if got := platform.callCount(); got != 1 {
		t.Fatalf("the platform was handed %d records, want 1", got)
	}
}

func TestSettleOnlyInspectsWhenGivenNoBudget(t *testing.T) {
	sink, _, platform := newSink(t, Limits{})
	defer sink.Drain(nil)
	platform.started = make(chan struct{}, 4)
	platform.release = make(chan struct{})
	defer close(platform.release)
	w := writer(t, sink, testConnection)
	write(t, w, clientRandomLine()+"\n")
	w.Close()
	select {
	case <-platform.started:
	case <-time.After(5 * time.Second):
		t.Fatal("the sink never started delivering")
	}
	start := time.Now()
	if sink.Settle(0) {
		t.Fatal("Settle(0) reported success while a record was in flight")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Settle(0) waited %s, want an inspection and nothing more", elapsed)
	}
	if sink.Settle(-time.Second) {
		t.Fatal("Settle with a negative budget reported success")
	}
}

func TestSettleAndRecordsOnAnAbsentSinkOrWriter(t *testing.T) {
	var absent *Sink
	if absent.Settle(time.Second) {
		t.Fatal("a nil sink reported itself complete")
	}
	if absent.AcceptingNewInterception() {
		t.Fatal("a nil sink accepted a new interception")
	}
	var noWriter *Writer
	if noWriter.Records() != 0 {
		t.Fatal("a nil writer counted records")
	}
	noWriter.Close()
}

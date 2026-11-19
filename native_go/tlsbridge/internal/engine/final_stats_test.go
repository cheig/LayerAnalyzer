package engine

import (
	"context"
	"fmt"
	"testing"
	"time"
)

func TestFinalStatsAfterJoinAndNextStartClears(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	m := NewManager(func(_ context.Context, _ Config, _ Material, _ *Callbacks, runtime *Runtime) (*Session, Code) {
		lease, code := runtime.Budget.Acquire(ConnectionSlot)
		if code != OK {
			t.Fatal(code)
		}
		s := sessionStub(func() {
			lease.Release()
			runtime.Events.Publish(Event{CaptureID: "test-capture", ConnectionID: "last", DestinationIP: "127.0.0.1", DestinationPort: 443, Phase: PhaseClosed})
		})
		s.Metrics = func() RuntimeMetrics { return RuntimeMetrics{ProbesFinished: 7} }
		s.GatewayStats = func() map[string]any { return map[string]any{"ready": uint64(7)} }
		return s, OK
	})
	h, _, _, c := m.Start(cfg, mat, platformStub{})
	if c != OK {
		t.Fatal(c)
	}
	if m.FinalStats(h) != nil {
		t.Fatal("live run advertised final stats")
	}
	if c = m.Stop(h, time.Second); c != OK {
		t.Fatal(c)
	}
	s := m.FinalStats(h)
	if s == nil || s["state"] != Stopped || s["budget"].(Usage).Connections != 0 || s["events"].(Stats).ConnectionsClosed != 1 || s["events"].(Stats).EventsQueued != 1 || s["runtimeMetrics"].(RuntimeMetrics).ProbesFinished != 7 {
		t.Fatal(s)
	}
	s["gateway"].(map[string]any)["ready"] = uint64(99)
	if m.FinalStats(h)["gateway"].(map[string]any)["ready"] != uint64(7) {
		t.Fatal("mutable snapshot escaped")
	}
	if _, c = m.Stats(h); c != StaleGeneration {
		t.Fatal(c)
	}
	if c = m.Stop(h, time.Second); c != OK || m.FinalStats(h) == nil {
		t.Fatal(c)
	}
	h2, _, _, c := m.Start(cfg, mat, platformStub{})
	if c != OK || m.FinalStats(h) != nil {
		t.Fatal(c)
	}
	if c = m.Stop(h2, time.Second); c != OK {
		t.Fatal(c)
	}
}

func TestStopTimeoutHasNoFinalSnapshotUntilJoin(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	finish := make(chan struct{})
	m := NewManager(func(context.Context, Config, Material, *Callbacks, *Runtime) (*Session, Code) {
		return sessionStub(func() { <-finish }), OK
	})
	h, _, _, c := m.Start(cfg, mat, platformStub{})
	if c != OK {
		t.Fatal(c)
	}
	if c = m.Stop(h, time.Millisecond); c != NotReady || m.FinalStats(h) != nil {
		t.Fatal(c)
	}
	close(finish)
	if c = m.Stop(h, time.Second); c != OK || m.FinalStats(h) == nil {
		t.Fatal(c)
	}
}

func TestStopRetainsUnreadTerminalEventsUntilDrainedOrNextStart(t *testing.T) {
	cfg, mat, _, _ := fixture(t)
	m := NewManager(func(_ context.Context, _ Config, _ Material, _ *Callbacks, runtime *Runtime) (*Session, Code) {
		return sessionStub(func() {
			// These events do not exist until the engine is joined.
			for i := 0; i < MaxPollEvents+2; i++ {
				event := testEvent(fmt.Sprintf("closing-%d", i), PhaseClosed)
				if _, code := runtime.Events.Publish(event); code != OK {
					t.Error(code)
				}
			}
		}), OK
	})
	h, _, _, code := m.Start(cfg, mat, platformStub{})
	if code != OK {
		t.Fatal(code)
	}
	if code = m.Stop(h, time.Second); code != OK {
		t.Fatal(code)
	}
	first, code := m.Poll(h, MaxPollEvents)
	if code != OK || first["state"] != Stopped || len(first["events"].([]any)) != MaxPollEvents {
		t.Fatal(code, first)
	}
	second, code := m.Poll(h, MaxPollEvents)
	if code != OK || len(second["events"].([]any)) != 2 {
		t.Fatal(code, second)
	}
	previous := int64(0)
	for _, batch := range []map[string]any{first, second} {
		for _, raw := range batch["events"].([]any) {
			event := raw.(Event)
			if event.Phase != PhaseClosed || event.EventSequence <= previous {
				t.Fatal(event)
			}
			previous = event.EventSequence
		}
	}
	if m.finalEvents != nil {
		t.Fatal("drained connection metadata was retained")
	}
	if _, code = m.Poll(h, 1); code != StaleGeneration {
		t.Fatal(code)
	}
	if m.FinalStats(h) == nil {
		t.Fatal("draining events lost numeric final stats")
	}
	h2, _, _, code := m.Start(cfg, mat, platformStub{})
	if code != OK {
		t.Fatal(code)
	}
	if code = m.Stop(h2, time.Second); code != OK {
		t.Fatal(code)
	}
	h3, _, _, code := m.Start(cfg, mat, platformStub{})
	if code != OK {
		t.Fatal(code)
	}
	if _, code = m.Poll(h2, 1); code != StaleGeneration {
		t.Fatal(code)
	}
	if code = m.Stop(h3, time.Second); code != OK {
		t.Fatal(code)
	}
}

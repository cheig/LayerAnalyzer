package gateway

import (
	"com.layeranalyzer/tlsbridge/internal/engine"
	"context"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestSeparateAuthActiveSharedBudgetAndRecovery(t *testing.T) {
	budget, _ := engine.NewBudget(engine.Limits{Connections: 2})
	entered := make(chan struct{}, 4)
	release := make(chan struct{})
	var once sync.Once
	t.Cleanup(func() { once.Do(func() { close(release) }) })
	var dials atomic.Int32
	s, code := Start(context.Background(), Options{CaptureID: "capture-202", NetworkGeneration: 7, Capacity: 2, AuthenticationCapacity: 2, Budget: budget,
		Dial: func(ctx context.Context, m Metadata) (net.Conn, engine.Code) {
			if !budget.Owns(m.ConnectionLease) {
				t.Error("missing pre-dial lease")
			}
			dials.Add(1)
			select {
			case entered <- struct{}{}:
			case <-ctx.Done():
				return nil, engine.Cancelled
			}
			select {
			case <-release:
			case <-ctx.Done():
			}
			return nil, engine.ProtectFailed
		}, Handle: neverHandle})
	if code != engine.OK {
		t.Fatal(code)
	}
	t.Cleanup(s.Close)
	active := []net.Conn{connect(t, s), connect(t, s)}
	for _, c := range active {
		send(t, c, requestFrame(t, request(s.Token())))
		select {
		case <-entered:
		case <-time.After(3 * time.Second):
			t.Fatal("dial did not start")
		}
	}
	if got := budget.Usage(); got.Connections != 2 {
		t.Fatal(got)
	}
	silent := []net.Conn{connect(t, s), connect(t, s)}
	waitFor(t, func() bool { return s.Stats().Authentication == 2 })
	stats := s.Stats()
	if stats.Active != 2 || stats.AcceptedCurrent != 4 || stats.AcceptedLimit != 4 || stats.SocketLimit != 8 {
		t.Fatal(stats)
	}
	overflow := connect(t, s)
	_ = overflow.SetReadDeadline(time.Now().Add(time.Second))
	if n, err := overflow.Read(make([]byte, 1)); n != 0 || err == nil {
		t.Fatal("auth overflow open")
	}
	waitFor(t, func() bool { return s.Stats().RejectedBeforeAuthentication == 1 })
	// Auth->active refusal must retain/reap the original auth lease and never dial.
	send(t, silent[0], requestFrame(t, request(s.Token())))
	readReply(t, silent[0], engine.CapacityExceeded)
	waitFor(t, func() bool { return s.Stats().Authentication == 1 })
	if dials.Load() != 2 || s.Stats().RejectedActiveCapacity != 1 {
		t.Fatal(s.Stats())
	}
	// One connection returns capacity to both the map and the shared accountant.
	once.Do(func() { close(release) })
	for _, c := range active {
		readReply(t, c, engine.ProtectFailed)
	}
	silent[1].Close()
	waitFor(t, func() bool { return idle(s) })
	next := connect(t, s)
	send(t, next, requestFrame(t, request(s.Token())))
	readReply(t, next, engine.ProtectFailed)
	waitFor(t, func() bool { return idle(s) })
	stats = s.Stats()
	if stats.DialAttempts != 3 || stats.DialFailures != 3 || stats.PeakActive != 2 || stats.PeakAuthentication != 2 || budget.Usage().Connections != 0 {
		t.Fatal(stats, budget.Usage())
	}
	s.Close()
	if got := s.Stats(); got.Active != 0 || got.Authentication != 0 || got.AcceptedCurrent != 0 {
		t.Fatal(got)
	}
}
func TestSharedBudgetFullRefusesBeforeAnyDial(t *testing.T) {
	budget, _ := engine.NewBudget(engine.Limits{Connections: 1})
	held, _ := budget.Acquire(engine.ConnectionSlot)
	var dials atomic.Int32
	s, code := Start(context.Background(), Options{CaptureID: "capture-202", NetworkGeneration: 7, Capacity: 1, Budget: budget,
		Dial: func(context.Context, Metadata) (net.Conn, engine.Code) { dials.Add(1); return nil, engine.IOError }, Handle: neverHandle})
	if code != engine.OK {
		t.Fatal(code)
	}
	t.Cleanup(s.Close)
	t.Cleanup(held.Release)
	c := connect(t, s)
	send(t, c, requestFrame(t, request(s.Token())))
	readReply(t, c, engine.CapacityExceeded)
	waitFor(t, func() bool { return idle(s) })
	if dials.Load() != 0 || s.Stats().RejectedActiveCapacity != 1 || budget.Usage().RefusedConnections != 1 {
		t.Fatal(s.Stats(), budget.Usage())
	}
	held.Release()
	next := connect(t, s)
	send(t, next, requestFrame(t, request(s.Token())))
	readReply(t, next, engine.IOError)
	waitFor(t, func() bool { return idle(s) })
	if dials.Load() != 1 || budget.Usage().Connections != 0 {
		t.Fatal(s.Stats())
	}
}
func TestGatewayFiniteLimitsMatchBudget(t *testing.T) {
	for _, capacity := range []int{64, 128, 256, 512, 1024} {
		budget, _ := engine.NewBudget(engine.Limits{Connections: capacity})
		s, code := Start(context.Background(), Options{CaptureID: "capture-202", NetworkGeneration: 7, Capacity: capacity, AuthenticationCapacity: 128, Budget: budget,
			Dial: func(context.Context, Metadata) (net.Conn, engine.Code) { return nil, engine.IOError }, Handle: neverHandle})
		if code != engine.OK {
			t.Fatal(code)
		}
		stats := s.Stats()
		s.Close()
		if stats.ActiveLimit != capacity || stats.AuthenticationLimit != 128 || stats.AcceptedLimit != capacity+128 {
			t.Fatal(stats)
		}
	}
}

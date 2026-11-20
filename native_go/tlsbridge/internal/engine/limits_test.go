package engine

import (
	"sync"
	"sync/atomic"
	"testing"
)

func TestBudgetDefaultsCeilingsAndRejection(t *testing.T) {
	for _, limits := range []Limits{{}, {Connections: 4}, {Handshakes: 3}} {
		budget, code := NewBudget(limits)
		if code != OK {
			t.Fatalf("limits %+v: %v", limits, code)
		}
		usage := budget.Usage()
		wantConnections, wantHandshakes := limits.Connections, limits.Handshakes
		if wantConnections == 0 {
			wantConnections = DefaultConnectionBudget
		}
		if wantHandshakes == 0 {
			wantHandshakes = DefaultHandshakeBudget
		}
		if usage.ConnectionLimit != wantConnections || usage.HandshakeLimit != wantHandshakes {
			t.Fatal(usage)
		}
	}
	// Values above the finite ceiling are refused, never silently clamped.
	for _, limits := range []Limits{
		{Connections: -1}, {Connections: MaxConnectionBudget + 1}, {Handshakes: -1}, {Handshakes: MaxHandshakeBudget + 1},
	} {
		if _, code := NewBudget(limits); code != InvalidArgument {
			t.Fatalf("limits %+v accepted: %v", limits, code)
		}
	}
	if _, code := (*Budget)(nil).Acquire(ConnectionSlot); code != NotReady {
		t.Fatal(code)
	}
	if code := (*Queue)(nil).RecordTraffic(1, 1); code != NotReady {
		t.Fatal(code)
	}
	if (*Budget)(nil).Usage() != (Usage{}) {
		t.Fatal("nil budget reported usage")
	}
}

func TestConnectionBudgetRefusesInsteadOfExceeding(t *testing.T) {
	budget, _ := NewBudget(Limits{Connections: 2, Handshakes: 1})
	leases := make([]*Lease, 0, 2)
	for i := 0; i < 2; i++ {
		lease, code := budget.Acquire(ConnectionSlot)
		if code != OK {
			t.Fatal(i, code)
		}
		leases = append(leases, lease)
	}
	if lease, code := budget.Acquire(ConnectionSlot); code != CapacityExceeded || lease != nil {
		t.Fatalf("a full budget must refuse the connection: %v", code)
	}
	if usage := budget.Usage(); usage.RefusedConnections != 1 || usage.Connections != 2 || usage.PeakConnections != 2 {
		t.Fatal(usage)
	}
	// Releasing one slot makes exactly one more connection admissible.
	leases[0].Release()
	if leases[0].Held() {
		t.Fatal("released lease still reports held")
	}
	lease, code := budget.Acquire(ConnectionSlot)
	if code != OK {
		t.Fatal(code)
	}
	if usage := budget.Usage(); usage.Connections != 2 || usage.RefusedConnections != 1 {
		t.Fatal(usage)
	}
	lease.Release()
	leases[1].Release()
	if usage := budget.Usage(); usage.Connections != 0 || usage.PeakConnections != 2 {
		t.Fatal(usage)
	}
}

func TestHandshakeBudgetIsSeparateAndReleasedAtRelay(t *testing.T) {
	budget, _ := NewBudget(Limits{Connections: 4, Handshakes: 2})
	connections := make([]*Lease, 0, 4)
	for i := 0; i < 4; i++ {
		lease, code := budget.Acquire(ConnectionSlot)
		if code != OK {
			t.Fatal(i, code)
		}
		connections = append(connections, lease)
	}
	first, code := budget.Acquire(HandshakeSlot)
	if code != OK {
		t.Fatal(code)
	}
	second, code := budget.Acquire(HandshakeSlot)
	if code != OK {
		t.Fatal(code)
	}
	// The third simultaneous handshake is refused while the connections stay
	// admitted: the two budgets are counted apart (§15.3).
	if lease, code := budget.Acquire(HandshakeSlot); code != CapacityExceeded || lease != nil {
		t.Fatalf("a full handshake budget must refuse: %v", code)
	}
	if usage := budget.Usage(); usage.Connections != 4 || usage.Handshakes != 2 || usage.RefusedHandshakes != 1 {
		t.Fatal(usage)
	}
	// Entering relay gives the handshake slot back; the connection slot stays.
	first.Release()
	if usage := budget.Usage(); usage.Handshakes != 1 || usage.Connections != 4 {
		t.Fatal(usage)
	}
	third, code := budget.Acquire(HandshakeSlot)
	if code != OK {
		t.Fatal(code)
	}
	if usage := budget.Usage(); usage.PeakHandshakes != 2 || usage.Handshakes != 2 {
		t.Fatal(usage)
	}
	for _, lease := range connections {
		lease.Release()
	}
	second.Release()
	third.Release()
	if usage := budget.Usage(); usage.Connections != 0 || usage.Handshakes != 0 {
		t.Fatal(usage)
	}
}

func TestReleaseIsIdempotentAndCannotUnderflowTheBudget(t *testing.T) {
	budget, _ := NewBudget(Limits{Connections: 1, Handshakes: 1})
	lease, _ := budget.Acquire(ConnectionSlot)
	lease.Release()
	lease.Release()
	lease.Release()
	(*Lease)(nil).Release()
	if usage := budget.Usage(); usage.Connections != 0 {
		t.Fatal(usage)
	}
	// A double release must not be able to mint extra budget: the ceiling is
	// what a caller asked for, and a buggy caller cannot raise it.
	held, code := budget.Acquire(ConnectionSlot)
	if code != OK {
		t.Fatal(code)
	}
	for i := 0; i < 8; i++ {
		if next, code := budget.Acquire(ConnectionSlot); code != CapacityExceeded || next != nil {
			t.Fatalf("release granted extra budget: %v", code)
		}
	}
	if usage := budget.Usage(); usage.Connections != 1 || usage.PeakConnections != 1 || usage.RefusedConnections != 8 {
		t.Fatal(usage)
	}
	held.Release()
	if next, code := budget.Acquire(ConnectionSlot); code != OK {
		t.Fatalf("the single slot was not returned: %v", code)
	} else {
		next.Release()
	}
	if usage := budget.Usage(); usage.Connections != 0 {
		t.Fatal(usage)
	}
}

func TestInvalidSlotAndNilLeaseAccessors(t *testing.T) {
	budget, _ := NewBudget(Limits{})
	if lease, code := budget.Acquire(Slot(9)); code != InvalidArgument || lease != nil {
		t.Fatal(code)
	}
	if (*Lease)(nil).Held() {
		t.Fatal("nil lease reported held")
	}
	if (*Lease)(nil).Slot() != ConnectionSlot {
		t.Fatal("nil lease slot")
	}
	lease, _ := budget.Acquire(HandshakeSlot)
	if lease.Slot() != HandshakeSlot || !lease.Held() {
		t.Fatal(lease.Slot())
	}
	if ConnectionSlot.String() != "connection" || HandshakeSlot.String() != "handshake" || Slot(9).String() != "unknown" {
		t.Fatal("slot names")
	}
}

func TestConnectionCapacityIsTheSharedCeiling(t *testing.T) {
	// The gateway's own admission ceiling is taken from this number so the two
	// halves draw on one budget instead of two (§15.3).
	shared, _ := NewBudget(Limits{})
	if shared.ConnectionCapacity() != DefaultConnectionBudget {
		t.Fatal(shared.ConnectionCapacity())
	}
	lowered, _ := NewBudget(Limits{Connections: 12})
	if lowered.ConnectionCapacity() != 12 {
		t.Fatal(lowered.ConnectionCapacity())
	}
	if (*Budget)(nil).ConnectionCapacity() != 0 || (*Budget)(nil).Limits() != (Limits{}) {
		t.Fatal("nil budget accessors")
	}
}

func TestConcurrentAcquireReleaseBalances(t *testing.T) {
	budget, _ := NewBudget(Limits{Connections: 8, Handshakes: 4})
	var acquired, refused atomic.Uint64
	var wait sync.WaitGroup
	for worker := 0; worker < 32; worker++ {
		wait.Add(1)
		go func(worker int) {
			defer wait.Done()
			slot := ConnectionSlot
			if worker%3 == 0 {
				slot = HandshakeSlot
			}
			for i := 0; i < 200; i++ {
				lease, code := budget.Acquire(slot)
				switch code {
				case OK:
					acquired.Add(1)
					if !lease.Held() {
						t.Error("held lease reported released")
					}
					lease.Release()
					lease.Release() // a second release must be inert
				case CapacityExceeded:
					refused.Add(1)
				default:
					t.Errorf("code %v", code)
					return
				}
			}
		}(worker)
	}
	wait.Wait()
	usage := budget.Usage()
	if usage.Connections != 0 || usage.Handshakes != 0 {
		t.Fatalf("slots leaked: %+v", usage)
	}
	if usage.PeakConnections > 8 || usage.PeakHandshakes > 4 {
		t.Fatalf("budget exceeded: %+v", usage)
	}
	if got := usage.RefusedConnections + usage.RefusedHandshakes; got != refused.Load() {
		t.Fatalf("refusals %d vs %d", got, refused.Load())
	}
	if acquired.Load()+refused.Load() != 32*200 {
		t.Fatalf("attempts %d", acquired.Load()+refused.Load())
	}
}

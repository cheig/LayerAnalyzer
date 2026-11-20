package engine

import (
	"fmt"
	"testing"
)

func TestActiveRecordsSurviveTerminalChurnAndCompleteWithinIndependentBound(t *testing.T) {
	queue, _ := NewQueue(4)
	for i := 0; i < MaxConnectionBudget; i++ {
		mustPublish(t, queue, testEvent(fmt.Sprintf("live-%d", i), PhaseRelaying))
	}
	if _, code := queue.Publish(testEvent("overflow", PhaseAccepted)); code != CapacityExceeded {
		t.Fatal(code)
	}
	for i := 0; i < 30; i++ {
		mustPublish(t, queue, testEvent(fmt.Sprintf("churn-%d", i), PhaseClosed))
	}
	for i := 0; i < MaxConnectionBudget; i++ {
		event := testEvent(fmt.Sprintf("live-%d", i), PhaseClosed)
		event.SecretRecordsAccepted, event.SecretRecordsPersisted, event.SecretsComplete = 4, 4, true
		mustPublish(t, queue, event)
		if stats := queue.Stats(); stats.TerminalsRetained > 4 || stats.ActiveRecords > MaxConnectionBudget {
			t.Fatal(stats)
		}
	}
	stats := queue.Stats()
	if stats.ActiveRecords != 0 || stats.TerminalsRetained != 4 || stats.RecordsRefused != 1 ||
		stats.ConnectionsAccepted != MaxConnectionBudget+30 || stats.ConnectionsProxied != MaxConnectionBudget ||
		stats.SecretRecordsPersisted != MaxConnectionBudget*4 || stats.TerminalsEvicted != MaxConnectionBudget+26 {
		t.Fatal(stats)
	}
	mustPublish(t, queue, testEvent("recovered", PhaseAccepted))
}

func TestOrdinaryNoiseCannotDisplaceAnAllTerminalQueue(t *testing.T) {
	queue, _ := NewQueue(4)
	for i := 0; i < 4; i++ {
		mustPublish(t, queue, testEvent(fmt.Sprintf("terminal-%d", i), PhaseClosed))
	}
	for i := 0; i < 20; i++ {
		mustPublish(t, queue, testEvent("noise", PhaseSniffing))
	}
	for _, event := range queue.Poll(MaxPollEvents) {
		if !event.Phase.Terminal() {
			t.Fatal(event)
		}
	}
	if stats := queue.Stats(); stats.EventsDropped != 20 || stats.ConnectionsAccepted != 5 {
		t.Fatal(stats)
	}
}

func TestCapacityPassthroughReasonsAreCountedOnce(t *testing.T) {
	queue, _ := NewQueue(0)
	for _, reason := range []string{"handshake_capacity_exceeded", "secrets_incomplete"} {
		event := testEvent(reason, PhasePassthrough)
		event.DecisionReason = reason
		mustPublish(t, queue, event)
		mustPublish(t, queue, event)
	}
	if stats := queue.Stats(); stats.HandshakeCapacityPassthrough != 1 || stats.SecretsIncompletePassthrough != 1 {
		t.Fatal(stats)
	}
}

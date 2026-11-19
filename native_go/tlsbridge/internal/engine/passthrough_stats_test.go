package engine

import (
	"fmt"
	"testing"
)

func TestPassthroughReasonCountsSurvivePollingAndAreBounded(t *testing.T) {
	q, _ := NewQueue(1)
	for index, reason := range []string{"handshake_capacity_exceeded", "probe_timeout", "sensitive.example"} {
		e := Event{CaptureID: "test-capture", ConnectionID: fmt.Sprintf("flow-%d", index), DestinationIP: "127.0.0.1", DestinationPort: 443, Phase: PhasePassthrough, DecisionReason: reason}
		if _, code := q.Publish(e); code != OK {
			t.Fatal(code)
		}
		if _, code := q.Publish(e); code != OK {
			t.Fatal(code)
		}
	}
	q.Poll(1)
	s := q.Stats()
	if s.ConnectionsPassthrough != 3 || len(s.PassthroughReasons) != 3 || s.PassthroughReasons["handshake_capacity_exceeded"] != 1 || s.PassthroughReasons["probe_timeout"] != 1 || s.PassthroughReasons["other"] != 1 {
		t.Fatal(s)
	}
	s.PassthroughReasons["other"] = 99
	if q.Stats().PassthroughReasons["other"] != 1 {
		t.Fatal("mutable metrics escaped")
	}
}

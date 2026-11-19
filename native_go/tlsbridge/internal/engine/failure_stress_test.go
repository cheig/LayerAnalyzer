package engine

import (
	"fmt"
	"reflect"
	"sync"
	"testing"
)

func TestFailureRecoveryStressDefaultEventFlood(t *testing.T) {
	queue, code := NewQueue(0)
	if code != OK {
		t.Fatal(code)
	}
	// A stalled UI consumes nothing while 64 connections publish 64,000 events.
	var producers sync.WaitGroup
	for i := 0; i < DefaultConnectionBudget; i++ {
		producers.Add(1)
		go func(i int) {
			defer producers.Done()
			id := fmt.Sprintf("flood-%d", i)
			for j := 0; j < 1000; j++ {
				if _, code := queue.Publish(testEvent(id, PhaseRelaying)); code != OK {
					t.Errorf("publish: %v", code)
					return
				}
			}
			if _, code := queue.Publish(testEvent(id, PhaseClosed)); code != OK {
				t.Errorf("terminal: %v", code)
			}
		}(i)
	}
	producers.Wait()
	if queue.Len() > DefaultEventQueueSize || len(queue.Terminals()) != DefaultConnectionBudget {
		t.Fatal("unbounded queue or lost terminal summary")
	}
	stats := queue.Stats()
	if stats.EventsPublished != 64064 || stats.EventsDropped == 0 || stats.ConnectionsAccepted != 64 {
		t.Fatalf("stats: %+v", stats)
	}
	var sequence int64
	for queue.Len() > 0 {
		batch := queue.Poll(MaxPollEvents)
		if len(batch) == 0 || len(batch) > MaxPollEvents {
			t.Fatal("invalid bounded poll")
		}
		for _, event := range batch {
			if event.EventSequence <= sequence {
				t.Fatal("events reordered after flood")
			}
			sequence = event.EventSequence
		}
	}
	stats.EventsQueued = 0 // Poll drains queue depth, not connection counters.
	if !reflect.DeepEqual(queue.Stats(), stats) {
		t.Fatal("slow UI changed connection accounting")
	}
}

//go:build tlsprobe

package main

import (
	"sync"
	"testing"
)

func TestSmokeLifecycle(t *testing.T) {
	var s smokeRegistry
	if s.stop(0) != statusInvalidArgument || s.stop(1) != statusInvalidArgument {
		t.Fatal("invalid handles must fail")
	}
	var previous uint64
	for i := 0; i < 100; i++ {
		h, status := s.start()
		if status != statusOK || h <= previous || s.activeHandles() != 1 {
			t.Fatal("start did not issue a fresh active handle")
		}
		if second, status := s.start(); status != statusNotReady || second != 0 {
			t.Fatal("duplicate start must fail without issuing a handle")
		}
		if previous != 0 && (s.stop(previous) != statusOK || s.activeHandles() != 1) {
			t.Fatal("stale stop closed a newer handle")
		}
		if s.stop(h) != statusOK || s.stop(h) != statusOK || s.activeHandles() != 0 {
			t.Fatal("stop must be idempotent and release the active handle")
		}
		previous = h
	}
}

func TestConcurrentStartHasOneWinner(t *testing.T) {
	var s smokeRegistry
	var wg sync.WaitGroup
	handles := make(chan uint64, 32)
	for i := 0; i < cap(handles); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if h, status := s.start(); status == statusOK {
				handles <- h
			} else if status != statusNotReady {
				t.Errorf("unexpected start status %d", status)
			}
		}()
	}
	wg.Wait()
	close(handles)
	if len(handles) != 1 || s.activeHandles() != 1 {
		t.Fatal("concurrent starts must produce exactly one active engine")
	}
	for h := range handles {
		if s.stop(h) != statusOK {
			t.Fatal("winner did not stop")
		}
	}
}

func TestHandleExhaustion(t *testing.T) {
	s := smokeRegistry{issued: 1<<63 - 1}
	if h, status := s.start(); h != 0 || status != statusCapacityExceeded {
		t.Fatal("handle overflow must fail without wrapping")
	}
}

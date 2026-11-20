//go:build tlsprobe

package main

import "sync"

// These values match the deliberately small P0 C header, not the production ABI.
const (
	statusOK = iota
	statusInvalidArgument
	statusNotReady
	statusCapacityExceeded
)

type smokeRegistry struct {
	mu     sync.Mutex
	issued uint64
	active uint64
}

func (s *smokeRegistry) start() (uint64, int) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != 0 {
		return 0, statusNotReady
	}
	// Restrict handles to positive Java Long values for the JNI smoke adapter.
	if s.issued == 1<<63-1 {
		return 0, statusCapacityExceeded
	}
	s.issued++
	s.active = s.issued
	return s.active, statusOK
}

func (s *smokeRegistry) stop(handle uint64) int {
	s.mu.Lock()
	defer s.mu.Unlock()
	if handle == 0 || handle > s.issued {
		return statusInvalidArgument
	}
	if s.active == handle {
		s.active = 0
	}
	return statusOK
}

func (s *smokeRegistry) activeHandles() uint32 {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.active != 0 {
		return 1
	}
	return 0
}

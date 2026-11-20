package certstore

import (
	"container/list"
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// maxIssueAttempts bounds the retry after the CA is replaced while a leaf is
// being signed. A second replacement inside the same window is not a race worth
// serving: the caller is told the generation moved on and fails the connection.
const maxIssueAttempts = 3

// leafKey is the cache identity of one leaf: the canonical name, the key family
// and the CA generation. Including the algorithm keeps an RSA and a P-256 leaf
// for the same name apart, and including the generation makes every entry of a
// replaced CA unreachable rather than merely stale.
type leafKey struct {
	name       string
	algorithm  LeafAlgorithm
	generation uint64
}

type leafEntry struct {
	key         leafKey
	certificate tls.Certificate
}

// issuance is one in-flight signing operation. Callers that arrive for the same
// key wait on done instead of signing a second certificate (design §7.1: the
// concurrent issuance of one key is merged into one).
type issuance struct {
	done        chan struct{}
	certificate tls.Certificate
	code        engine.Code
}

// Stats is a snapshot of the cache. It is what a caller can observe about this
// package without reading its internals, and it is deliberately counters only:
// no key, no name and no certificate travels in it.
type Stats struct {
	// Generation is the CA generation currently installed; it starts at 0 for a
	// store that has never adopted a root.
	Generation uint64
	// Capacity is the enforced maximum number of cached leaves.
	Capacity int
	// Cached is the number of leaves currently held.
	Cached int
	// Issued counts successful signings, Hits and Misses the cache lookups, and
	// Evictions the entries dropped by the capacity bound. A leaf dropped by a
	// CA replacement is not an eviction: the generation moved instead.
	Issued       uint64
	Hits         uint64
	Misses       uint64
	Evictions    uint64
	InFlight     int
	PeakInFlight int
	Waiters      int
	PeakWaiters  int
	Shared       uint64
	Failed       uint64
	PeakCached   int
}

// Store owns one CA and its bounded leaf cache.
//
// It is safe for concurrent use. Every method that changes the CA is serialized
// against leaf lookups, so a leaf is never returned for a root that has already
// been replaced. A zero Store has no CA and answers Leaf with NOT_READY instead
// of panicking; Store values must otherwise come from NewStore.
type Store struct {
	mu       sync.Mutex
	root     *Root
	capacity int
	order    *list.List
	entries  map[leafKey]*list.Element
	inflight map[leafKey]*issuance
	stats    Stats
}

// NewStore returns an empty store with the given leaf-cache capacity. A capacity
// outside 1..MaxCapacity selects DefaultCapacity, so a bad number can never
// raise the ceiling; production uses DefaultCapacity.
func NewStore(capacity int) *Store {
	store := &Store{capacity: capacity}
	store.resetLocked()
	return store
}

// SetRoot adopts a CA — the one generated for this install, reloaded from the
// C06 container at start — and drops every cached leaf in the same step. It is
// also how a CA reset is applied: the generation advances, so leaves of the
// previous root are not merely evicted but unreachable.
//
// Re-adopting the same certificate advances the generation as well: the leaf
// cache belongs to one engine run, not to the CA, and a fresh run must not
// inherit leaves signed before it started.
//
// The certificate and signer are not copied and must not be mutated afterwards.
func (s *Store) SetRoot(certificate *x509.Certificate, signer crypto.Signer) engine.Code {
	if s == nil {
		return engine.NotReady
	}
	if code := validRoot(certificate, signer); code != engine.OK {
		return code
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.stats.Generation++
	s.root = &Root{Certificate: certificate, Signer: signer, Generation: s.stats.Generation}
	s.resetLocked()
	return engine.OK
}

// NewRoot generates a fresh CA, adopts it and drops every cached leaf.
func (s *Store) NewRoot(now time.Time) (*Root, engine.Code) {
	if s == nil {
		return nil, engine.NotReady
	}
	root, code := GenerateRoot(now)
	if code != engine.OK {
		return nil, code
	}
	if code := s.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		return nil, code
	}
	return s.Root(), engine.OK
}

// Root is the CA currently adopted, or nil. The returned value belongs to the
// store and must be treated as read-only; it is replaced, not modified, by a
// later SetRoot.
func (s *Store) Root() *Root {
	if s == nil {
		return nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.root
}

// Stats returns a snapshot of the cache counters.
func (s *Store) Stats() Stats {
	if s == nil {
		return Stats{}
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	stats := s.stats
	stats.Capacity = s.capacity
	stats.Cached = len(s.entries)
	stats.InFlight = len(s.inflight)
	return stats
}

// Leaf returns the leaf that proves name under the adopted CA, signing it if it
// is not cached. Concurrent requests for the same canonical name, algorithm and
// CA generation share one signing operation and one certificate.
//
// The returned certificate is shared with every other caller of the same key and
// must not be modified. Failures are typed and never partial: NOT_READY without
// a CA, INVALID_ARGUMENT for an unusable name or algorithm, STALE_GENERATION if
// the adopted CA is outside its validity window or was replaced while the leaf
// was being signed, and IO_ERROR if the random source or the signer failed.
func (s *Store) Leaf(name string, algorithm LeafAlgorithm, now time.Time) (tls.Certificate, engine.Code) {
	if s == nil {
		return tls.Certificate{}, engine.NotReady
	}
	canonical, code := CanonicalName(name)
	if code != engine.OK {
		return tls.Certificate{}, code
	}
	if algorithm != ECDSAP256 && algorithm != RSA2048 {
		return tls.Certificate{}, engine.InvalidArgument
	}
	for attempt := 0; attempt < maxIssueAttempts; attempt++ {
		s.mu.Lock()
		root := s.root
		if root == nil {
			s.mu.Unlock()
			return tls.Certificate{}, engine.NotReady
		}
		key := leafKey{name: canonical, algorithm: algorithm, generation: root.Generation}
		if element, ok := s.entries[key]; ok {
			certificate := element.Value.(*leafEntry).certificate
			s.order.MoveToFront(element)
			s.stats.Hits++
			s.mu.Unlock()
			return certificate, engine.OK
		}
		if pending, ok := s.inflight[key]; ok {
			// Someone is already signing this exact leaf: wait for their result
			// rather than generating a second key pair for one name.
			s.stats.Shared++
			s.stats.Waiters++
			s.stats.PeakWaiters = max(s.stats.PeakWaiters, s.stats.Waiters)
			s.mu.Unlock()
			<-pending.done
			s.mu.Lock()
			s.stats.Waiters--
			s.mu.Unlock()
			if pending.code == engine.StaleGeneration {
				// The CA changed while they were signing; retry against the new
				// one instead of failing a connection that is still handshaking.
				continue
			}
			return pending.certificate, pending.code
		}
		s.stats.Misses++
		pending := &issuance{done: make(chan struct{})}
		s.inflight[key] = pending
		s.stats.PeakInFlight = max(s.stats.PeakInFlight, len(s.inflight))
		s.mu.Unlock()

		certificate, code := root.issue(canonical, algorithm, now)

		s.mu.Lock()
		delete(s.inflight, key)
		if code == engine.OK && s.root != root {
			// The CA was replaced between the snapshot and the signature: this
			// leaf belongs to a root nobody will trust, so it is discarded and
			// never cached.
			code = engine.StaleGeneration
			certificate = tls.Certificate{}
		}
		if code == engine.OK {
			s.stats.Issued++
			s.insertLocked(key, certificate)
		}
		if code != engine.OK {
			s.stats.Failed++
		}
		pending.certificate, pending.code = certificate, code
		s.mu.Unlock()
		close(pending.done)

		if code == engine.StaleGeneration {
			continue
		}
		return certificate, code
	}
	return tls.Certificate{}, engine.StaleGeneration
}

// insertLocked adds one leaf and evicts least-recently-used entries until the
// capacity holds again. The cache never exceeds its bound, not even briefly.
func (s *Store) insertLocked(key leafKey, certificate tls.Certificate) {
	s.entries[key] = s.order.PushFront(&leafEntry{key: key, certificate: certificate})
	for s.order.Len() > s.capacity {
		oldest := s.order.Back()
		if oldest == nil {
			return
		}
		s.order.Remove(oldest)
		delete(s.entries, oldest.Value.(*leafEntry).key)
		s.stats.Evictions++
	}
	s.stats.PeakCached = max(s.stats.PeakCached, len(s.entries))
}

// resetLocked drops every cached leaf and makes the store usable, including a
// zero Store value that never went through NewStore: the capacity bound is
// re-applied and the maps are (re)created. It is called only while holding the
// lock and only from a CA change, so cached leaves can never outlive their root.
//
// In-flight issuances are deliberately left alone: their waiters are blocked on
// the issuance itself, and the signatures they produce are discarded by the
// generation check in Leaf rather than silently dropped from under them.
func (s *Store) resetLocked() {
	if s.capacity < 1 || s.capacity > MaxCapacity {
		s.capacity = DefaultCapacity
	}
	s.order = list.New()
	s.entries = make(map[leafKey]*list.Element)
	if s.inflight == nil {
		s.inflight = make(map[leafKey]*issuance)
	}
}

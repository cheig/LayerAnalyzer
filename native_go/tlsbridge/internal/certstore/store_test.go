package certstore

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/tls"
	"crypto/x509"
	"sync"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

func TestStoreWithoutARootIsNotReady(t *testing.T) {
	store := NewStore(4)
	if store.Root() != nil {
		t.Fatal("a fresh store already has a root")
	}
	if leaf, code := store.Leaf("notready.fixture.test", ECDSAP256, testNow()); code != engine.NotReady || derOf(leaf) != nil {
		t.Fatalf("Leaf without a root = %v, %v; want NOT_READY", leaf, code)
	}
	stats := store.Stats()
	if stats.Cached != 0 || stats.Issued != 0 || stats.Generation != 0 {
		t.Fatalf("a fresh store reports %+v", stats)
	}
	var absent *Store
	if leaf, code := absent.Leaf("notready.fixture.test", ECDSAP256, testNow()); code != engine.NotReady || derOf(leaf) != nil {
		t.Fatalf("Leaf on a nil store = %v, %v; want NOT_READY", leaf, code)
	}
	if absent.Root() != nil || absent.Stats() != (Stats{}) {
		t.Fatal("a nil store reports state")
	}
}

func TestStoreCachesOneLeafPerName(t *testing.T) {
	root := testRoot(t)
	store := NewStore(DefaultCapacity)
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatalf("SetRoot = %v", code)
	}
	now := testNow()
	first, code := store.Leaf("cached.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	second, code := store.Leaf("cached.fixture.test", ECDSAP256, now.Add(time.Minute))
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if !bytes.Equal(derOf(first), derOf(second)) {
		t.Fatal("a second request for the same name minted a new certificate")
	}
	stats := store.Stats()
	if stats.Issued != 1 || stats.Misses != 1 || stats.Hits != 1 || stats.Cached != 1 {
		t.Fatalf("cache stats are %+v, want one issuance, one miss and one hit", stats)
	}
	if stats.Generation != 1 || store.Root().Generation != 1 {
		t.Fatalf("generation is %d/%d after one adoption", stats.Generation, store.Root().Generation)
	}
}

func TestStoreKeepsAlgorithmsAndNamesApart(t *testing.T) {
	root := testRoot(t)
	store := NewStore(DefaultCapacity)
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatalf("SetRoot = %v", code)
	}
	now := testNow()
	ecdsaLeaf, code := store.Leaf("split.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	rsaLeaf, code := store.Leaf("split.fixture.test", RSA2048, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if bytes.Equal(derOf(ecdsaLeaf), derOf(rsaLeaf)) {
		t.Fatal("one name served the same certificate for two key families")
	}
	if _, ok := ecdsaLeaf.PrivateKey.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("P-256 entry holds %T", ecdsaLeaf.PrivateKey)
	}
	other, code := store.Leaf("other.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if bytes.Equal(derOf(ecdsaLeaf), derOf(other)) {
		t.Fatal("two names share one certificate")
	}
	// The canonical spelling is the key, so a differently written request for
	// an already cached name is a hit rather than a second certificate.
	aliased, code := store.Leaf("SPLIT.Fixture.Test.", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if !bytes.Equal(derOf(aliased), derOf(ecdsaLeaf)) {
		t.Fatal("a case or trailing-dot variant minted a second certificate")
	}
	if stats := store.Stats(); stats.Cached != 3 || stats.Issued != 3 {
		t.Fatalf("stats are %+v, want three entries", stats)
	}
}

// TestConcurrentRequestsForOneKeySignOnce is the singleflight requirement: the
// waiters may observe a hit or a wait, but only one certificate may be signed.
func TestConcurrentRequestsForOneKeySignOnce(t *testing.T) {
	root := testRoot(t)
	store := NewStore(DefaultCapacity)
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatalf("SetRoot = %v", code)
	}
	now := testNow()
	const callers = 32
	results := make([]tls.Certificate, callers)
	codes := make([]engine.Code, callers)
	var start sync.WaitGroup
	var done sync.WaitGroup
	start.Add(1)
	for index := 0; index < callers; index++ {
		done.Add(1)
		go func(index int) {
			defer done.Done()
			start.Wait()
			// RSA is used here because its key generation is slow enough for the
			// callers to actually overlap; the merging rule is the same for both
			// families.
			results[index], codes[index] = store.Leaf("merged.fixture.test", RSA2048, now)
		}(index)
	}
	start.Done()
	completed := make(chan struct{})
	go func() { done.Wait(); close(completed) }()
	select {
	case <-completed:
	case <-time.After(5 * time.Second):
		t.Fatal("issuance did not finish")
	}
	for index := 0; index < callers; index++ {
		if codes[index] != engine.OK {
			t.Fatalf("caller %d got %v", index, codes[index])
		}
		if !bytes.Equal(derOf(results[0]), derOf(results[index])) {
			t.Fatalf("caller %d received a different certificate", index)
		}
	}
	if stats := store.Stats(); stats.Issued != 1 || stats.Cached != 1 || stats.InFlight != 0 || stats.Waiters != 0 || stats.PeakInFlight != 1 || stats.PeakCached != 1 {
		t.Fatalf("stats are %+v, want exactly one issuance", stats)
	}
}

func TestStoreCapacityIsNeverExceeded(t *testing.T) {
	root := testRoot(t)
	const capacity = 4
	store := NewStore(capacity)
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatalf("SetRoot = %v", code)
	}
	now := testNow()
	for index := 0; index < 10; index++ {
		if _, code := store.Leaf(name(index), ECDSAP256, now); code != engine.OK {
			t.Fatalf("Leaf(%d) = %v", index, code)
		}
		if cached := store.Stats().Cached; cached > capacity {
			t.Fatalf("after %d names the cache holds %d entries, above the %d bound", index+1, cached, capacity)
		}
	}
	stats := store.Stats()
	if stats.Cached != capacity || stats.Evictions != 6 || stats.Issued != 10 {
		t.Fatalf("stats are %+v, want %d entries and 6 evictions", stats, capacity)
	}
	if stats.Capacity != capacity {
		t.Fatalf("capacity is %d, want %d", stats.Capacity, capacity)
	}
}

func TestLeastRecentlyUsedLeafIsEvictedFirst(t *testing.T) {
	root := testRoot(t)
	store := NewStore(2)
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatalf("SetRoot = %v", code)
	}
	now := testNow()
	first, code := store.Leaf("one.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	second, code := store.Leaf("two.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	// Touch the oldest entry so the other one becomes the least recently used.
	if _, code := store.Leaf("one.fixture.test", ECDSAP256, now); code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if _, code := store.Leaf("three.fixture.test", ECDSAP256, now); code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if stats := store.Stats(); stats.Evictions != 1 || stats.Cached != 2 {
		t.Fatalf("stats are %+v, want exactly one eviction", stats)
	}
	kept, code := store.Leaf("one.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if !bytes.Equal(derOf(first), derOf(kept)) {
		t.Fatal("the recently used entry was evicted instead of the oldest one")
	}
	// The evicted entry is gone, so re-requesting it mints a new certificate.
	evicted, code := store.Leaf("two.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if bytes.Equal(derOf(second), derOf(evicted)) {
		t.Fatal("an evicted leaf was still returned")
	}
	if err := evicted.Leaf.VerifyHostname("two.fixture.test"); err != nil {
		t.Fatalf("re-minted leaf does not prove its name: %v", err)
	}
	if stats := store.Stats(); stats.Evictions != 2 || stats.Cached != 2 {
		t.Fatalf("stats are %+v", stats)
	}
}

// TestReplacingTheRootDropsEveryCachedLeaf covers CA reset: the generation
// advances, no leaf of the previous root is reachable and every new leaf chains
// to the new root.
func TestReplacingTheRootDropsEveryCachedLeaf(t *testing.T) {
	root := testRoot(t)
	store := NewStore(DefaultCapacity)
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatalf("SetRoot = %v", code)
	}
	now := testNow()
	before, code := store.Leaf("reset.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	replacement, code := store.NewRoot(now)
	if code != engine.OK {
		t.Fatalf("NewRoot = %v", code)
	}
	if replacement == root || bytes.Equal(replacement.Certificate.Raw, root.Certificate.Raw) {
		t.Fatal("NewRoot returned the previous CA")
	}
	if stats := store.Stats(); stats.Generation != 2 || stats.Cached != 0 {
		t.Fatalf("after a reset stats are %+v, want generation 2 and an empty cache", stats)
	}
	after, code := store.Leaf("reset.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	if bytes.Equal(derOf(before), derOf(after)) {
		t.Fatal("a leaf of the replaced CA was reused")
	}
	if err := after.Leaf.CheckSignatureFrom(replacement.Certificate); err != nil {
		t.Fatalf("the new leaf is not signed by the new root: %v", err)
	}
	if err := after.Leaf.CheckSignatureFrom(root.Certificate); err == nil {
		t.Fatal("the new leaf is still signed by the replaced root")
	}
	if stats := store.Stats(); stats.Cached != 1 || stats.Generation != 2 {
		t.Fatalf("stats after re-minting are %+v", stats)
	}
}

func TestAdoptingARejectedRootChangesNothing(t *testing.T) {
	root := testRoot(t)
	store := NewStore(DefaultCapacity)
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatalf("SetRoot = %v", code)
	}
	now := testNow()
	leaf, code := store.Leaf("kept.fixture.test", ECDSAP256, now)
	if code != engine.OK {
		t.Fatalf("Leaf = %v", code)
	}
	before := store.Stats()

	// The adopted material must be a self-signed CA whose key matches. A leaf, a
	// CA signed by someone else, a mismatched signer and a missing certificate
	// are all refused, and a refused adoption must leave the usable CA and its
	// cache in place.
	notACA := *leaf.Leaf
	notACA.IsCA = true
	notACA.BasicConstraintsValid = true
	notACA.KeyUsage = x509.KeyUsageCertSign
	for _, test := range []struct {
		caseName    string
		certificate *x509.Certificate
		signer      crypto.Signer
	}{
		{"nil certificate", nil, root.Signer},
		{"nil signer", root.Certificate, nil},
		{"non-self-signed CA", &notACA, crypto.Signer(leaf.PrivateKey.(*ecdsa.PrivateKey))},
		{"leaf certificate", leaf.Leaf, crypto.Signer(leaf.PrivateKey.(*ecdsa.PrivateKey))},
		{"mismatched signer", root.Certificate, crypto.Signer(leaf.PrivateKey.(*ecdsa.PrivateKey))},
	} {
		if code := store.SetRoot(test.certificate, test.signer); code == engine.OK {
			t.Fatalf("%s was adopted as a root", test.caseName)
		}
		if store.Root() == nil || !bytes.Equal(store.Root().Certificate.Raw, root.Certificate.Raw) {
			t.Fatalf("%s replaced the usable root", test.caseName)
		}
		after := store.Stats()
		if after.Generation != before.Generation || after.Cached != before.Cached {
			t.Fatalf("%s changed the cache: %+v then %+v", test.caseName, before, after)
		}
	}
	// The cached leaf is still returned unchanged.
	again, code := store.Leaf("kept.fixture.test", ECDSAP256, now)
	if code != engine.OK || !bytes.Equal(derOf(leaf), derOf(again)) {
		t.Fatalf("cached leaf after rejected adoptions = %v, %v", again, code)
	}
}

func TestStoreCapacityOutsideTheRangeFallsBackToTheDefault(t *testing.T) {
	for _, capacity := range []int{-1, 0, MaxCapacity + 1, 1 << 20} {
		if got := NewStore(capacity).Stats().Capacity; got != DefaultCapacity {
			t.Fatalf("NewStore(%d) capacity is %d, want %d", capacity, got, DefaultCapacity)
		}
	}
	for _, capacity := range []int{1, DefaultCapacity, MaxCapacity} {
		if got := NewStore(capacity).Stats().Capacity; got != capacity {
			t.Fatalf("NewStore(%d) capacity is %d", capacity, got)
		}
	}
}

// TestZeroStoreValueIsUsable pins that a Store that never went through NewStore
// still adopts a CA and serves leaves against the default bound instead of
// panicking on a missing map.
func TestZeroStoreValueIsUsable(t *testing.T) {
	root := testRoot(t)
	var store Store
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatalf("SetRoot on a zero store = %v", code)
	}
	if got := store.Stats().Capacity; got != DefaultCapacity {
		t.Fatalf("zero store capacity is %d, want %d", got, DefaultCapacity)
	}
	leaf, code := store.Leaf("zero.fixture.test", ECDSAP256, testNow())
	if code != engine.OK {
		t.Fatalf("Leaf on a zero store = %v", code)
	}
	if err := leaf.Leaf.CheckSignatureFrom(root.Certificate); err != nil {
		t.Fatalf("zero-store leaf is not signed by the root: %v", err)
	}
	if stats := store.Stats(); stats.Cached != 1 || stats.Issued != 1 {
		t.Fatalf("zero-store stats are %+v", stats)
	}
}

// TestReplacementNeverLeaksALeafOfAnotherRoot runs issuance concurrently with CA
// replacement: every certificate a caller receives must belong to a root that
// was actually adopted, never to a CA that was replaced before the leaf was
// handed out.
func TestReplacementNeverLeaksALeafOfAnotherRoot(t *testing.T) {
	first := testRoot(t)
	second, code := GenerateRoot(testNow())
	if code != engine.OK {
		t.Fatalf("GenerateRoot = %v", code)
	}
	store := NewStore(DefaultCapacity)
	if code := store.SetRoot(first.Certificate, first.Signer); code != engine.OK {
		t.Fatalf("SetRoot = %v", code)
	}
	now := testNow()
	const issuers = 8
	var group sync.WaitGroup
	stop := make(chan struct{})
	group.Add(1)
	go func() {
		defer group.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			// Both roots are already generated, so replacement is cheap and the
			// two overlap tightly with issuance.
			if code := store.SetRoot(first.Certificate, first.Signer); code != engine.OK {
				t.Errorf("SetRoot = %v", code)
				return
			}
			if code := store.SetRoot(second.Certificate, second.Signer); code != engine.OK {
				t.Errorf("SetRoot = %v", code)
				return
			}
		}
	}()
	for index := 0; index < issuers; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			for round := 0; round < 32; round++ {
				leaf, code := store.Leaf(name(index), ECDSAP256, now)
				if code == engine.StaleGeneration {
					continue
				}
				if code != engine.OK {
					t.Errorf("Leaf = %v", code)
					return
				}
				if err := leaf.Leaf.CheckSignatureFrom(first.Certificate); err != nil {
					if err := leaf.Leaf.CheckSignatureFrom(second.Certificate); err != nil {
						t.Errorf("a leaf belongs to neither adopted root: %v", err)
						return
					}
				}
			}
		}(index)
	}
	time.Sleep(50 * time.Millisecond)
	close(stop)
	group.Wait()
	if stats := store.Stats(); stats.Cached > stats.Capacity {
		t.Fatalf("the cache grew past its bound: %+v", stats)
	}
}

func name(index int) string {
	return string(rune('a'+index%26)) + ".fixture.test"
}

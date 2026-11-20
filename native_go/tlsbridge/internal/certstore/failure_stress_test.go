package certstore

import (
	"bytes"
	"fmt"
	"testing"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

func TestFailureRecoveryStressDefaultCertificateCacheEvictsAndReissues(t *testing.T) {
	root := testRoot(t)
	store := NewStore(DefaultCapacity)
	if code := store.SetRoot(root.Certificate, root.Signer); code != engine.OK {
		t.Fatal(code)
	}
	first, code := store.Leaf("host-0.fixture.test", ECDSAP256, testNow())
	if code != engine.OK {
		t.Fatal(code)
	}
	for i := 1; i <= DefaultCapacity; i++ {
		leaf, code := store.Leaf(fmt.Sprintf("host-%d.fixture.test", i), ECDSAP256, testNow())
		if code != engine.OK {
			t.Fatal(code)
		}
		if err := leaf.Leaf.CheckSignatureFrom(root.Certificate); err != nil {
			t.Fatal(err)
		}
		if store.Stats().Cached > DefaultCapacity {
			t.Fatal("cache exceeded C10")
		}
	}
	stats := store.Stats()
	if stats.Cached != 256 || stats.Evictions != 1 {
		t.Fatalf("stats: %+v", stats)
	}
	again, code := store.Leaf("host-0.fixture.test", ECDSAP256, testNow())
	if code != engine.OK {
		t.Fatal(code)
	}
	if bytes.Equal(derOf(first), derOf(again)) {
		t.Fatal("evicted leaf was still cached")
	}
	if err := again.Leaf.CheckSignatureFrom(root.Certificate); err != nil {
		t.Fatal(err)
	}
	if stats := store.Stats(); stats.Cached != 256 || stats.Evictions != 2 {
		t.Fatalf("stats: %+v", stats)
	}
}

package tlsproxy

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func TestPrefixCapacityLivesThroughReplayAndReturnsOnCleanup(t *testing.T) {
	var metrics probeMetrics
	reservation := metrics.begin()
	// A malformed complete record consumes the whole 12 KiB budget. Capacity is capped
	// at a non-power-of-two limit, instead of relying on append's growth policy.
	input := make([]byte, 12<<10)
	copy(input, []byte{22, 3, 3, 0x40, 0, 1, 0, 0x2f, 0xf7})
	outcome := probeClientHello(newScriptConn(input), Limits{MaxPrefixBytes: len(input)}, reservation.capacity)
	metrics.finished(outcome)
	outcome.Conn.released = reservation.release
	if metrics.stats.Active != 0 || metrics.stats.PrefixCapacityBytes != len(input) {
		t.Fatal(metrics.stats)
	}
	got := make([]byte, len(input))
	if _, err := io.ReadFull(outcome.Conn, got); err != nil {
		t.Fatal(err)
	}
	if metrics.stats.PrefixCapacityBytes != 0 {
		t.Fatal(metrics.stats)
	}
	reservation.release()
	if metrics.stats.PrefixCapacityBytes != 0 {
		t.Fatal("double release")
	}
	retained := metrics.begin()
	retained.capacity(4096)
	metrics.finished(Outcome{})
	retained.release()
	if metrics.stats.PrefixCapacityBytes != 0 || metrics.stats.PeakPrefixCapacityBytes != len(input) {
		t.Fatal(metrics.stats)
	}
}

func TestConcurrentProbesReleasePrefixCapacityWhenStopped(t *testing.T) {
	capture := newCapture(t)
	const count = 16
	results := make(chan ConnectionResult, count)
	clients := make([]net.Conn, 0, count)
	t.Cleanup(func() {
		for _, client := range clients {
			client.Close()
		}
	})
	for i := 0; i < count; i++ {
		downstream, client := net.Pipe()
		clients = append(clients, client)
		request := Request{ConnectionID: fmt.Sprintf("probe-%d", i),
			Destination: netip.MustParseAddrPort("203.0.113.7:443"),
			Downstream:  downstream, Upstream: newScriptConn()}
		go func() { results <- capture.pipeline.Handle(context.Background(), request) }()
		client.SetWriteDeadline(time.Now().Add(3 * time.Second))
		if _, err := client.Write([]byte{22}); err != nil {
			t.Fatal(err)
		}
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		stats := capture.pipeline.ProbeStats()
		if stats.Active == count && stats.PrefixCapacityBytes == count*probeReadChunk {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal(stats)
		}
		time.Sleep(time.Millisecond)
	}
	for _, client := range clients {
		client.Close()
	}
	for i := 0; i < count; i++ {
		select {
		case <-results:
		case <-time.After(3 * time.Second):
			t.Fatal("stopped probe did not return")
		}
	}
	stats := capture.pipeline.ProbeStats()
	if stats.Active != 0 || stats.PrefixCapacityBytes != 0 || stats.Finished != count || stats.PeakActive != count {
		t.Fatal(stats)
	}
}

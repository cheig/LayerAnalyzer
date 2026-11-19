package assembly

import (
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// Real production assembly, TCP listener, authenticated gateway, upstream sockets
// and cancellation; platform protect/bind/trust remain host doubles. No VPN/TUN
// or device FD/thread claim is made by this test.
func TestFailureRecoveryStressSaturatedGatewayStopsAndRestarts(t *testing.T) {
	origin := newEchoOrigin(t, selfSigned(t, []string{"example.test"}))
	material, _ := captureMaterial(t)
	manager := engine.NewManager(Factory())
	for round := 0; round < 5; round++ {
		capture := fmt.Sprintf("stress-%d", round)
		config := startConfig(t, capture, frozenSettings(origin.port(), true, "example.test"))
		handle, port, token, code := manager.Start(config, material, &platformStub{})
		if code != engine.OK {
			t.Fatalf("round %d start: %v", round, code)
		}
		t.Cleanup(func() { manager.Stop(handle, 5*time.Second) })
		peers := make([]net.Conn, 0, engine.DefaultConnectionBudget)
		for i := 0; i < engine.DefaultConnectionBudget; i++ {
			// READY, then stall before ClientHello: all 64 gateway slots stay held.
			peer := gatewayHello(t, port, capture, fmt.Sprintf("flow-%d", i), string(token), origin.listener.Addr())
			_ = peer.SetDeadline(time.Now().Add(5 * time.Second))
			peers = append(peers, peer)
		}
		address := fmt.Sprintf("127.0.0.1:%d", port)
		// Active saturation still admits a bounded authentication population. A
		// silent client expires at the authentication deadline, rather than being
		// closed by the old mixed accepted-map ceiling.
		extra, err := net.DialTimeout("tcp", address, time.Second)
		if err != nil {
			t.Fatal(err)
		}
		_ = extra.SetReadDeadline(time.Now().Add(3 * time.Second))
		_, err = io.ReadAll(extra)
		_ = extra.Close()
		if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
			t.Fatal("authentication timeout left overflow open")
		}

		// Slow UI: never poll while the connections are live. Concurrent stop,
		// stats and poll must join actual workers and close all transports.
		var group sync.WaitGroup
		for i := 0; i < 8; i++ {
			group.Add(1)
			go func() {
				defer group.Done()
				manager.Poll(handle, 128)
				manager.Stats(handle)
				if code := manager.Stop(handle, 5*time.Second); code != engine.OK {
					t.Errorf("stop: %v", code)
				}
			}()
		}
		group.Wait()
		for _, peer := range peers {
			_, err := io.ReadAll(peer)
			_ = peer.Close()
			if timeout, ok := err.(net.Error); ok && timeout.Timeout() {
				t.Fatal("stop left a client transport open")
			}
		}
		if peer, err := net.DialTimeout("tcp", address, time.Second); err == nil {
			_ = peer.Close()
			t.Fatal("stopped listener still accepts")
		}
		if _, code := manager.Stats(handle); code != engine.StaleGeneration {
			t.Fatalf("old handle: %v", code)
		}
		clear(token)
	}
}

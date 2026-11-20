//go:build tlsprobe

package probe

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"sync/atomic"
	"testing"
	"time"
)

func socketFixture(t *testing.T, network, ip string) (int, *atomic.Uint32) {
	t.Helper()
	listener, err := net.Listen(network, net.JoinHostPort(ip, "0"))
	if err != nil {
		t.Fatal(err)
	}
	count := &atomic.Uint32{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			reply := []byte{'L', 'A', 'S', '1', 0, 0, 0, 0}
			binary.BigEndian.PutUint32(reply[4:], count.Add(1))
			conn.SetWriteDeadline(time.Now().Add(time.Second))
			conn.Write(reply)
			conn.Close()
		}
	}()
	t.Cleanup(func() { listener.Close(); <-done })
	return listener.Addr().(*net.TCPAddr).Port, count
}

func TestSocketIPv4AndIPv6(t *testing.T) {
	for _, ip := range []string{"127.0.0.1", "::1"} {
		t.Run(ip, func(t *testing.T) {
			network := "tcp4"
			if ip == "::1" {
				network = "tcp6"
			}
			port, count := socketFixture(t, network, ip)
			for i := uint32(1); i <= 20; i++ {
				returned := false
				r, status := DialSocket(context.Background(), ip, port, 7, time.Second, func(fd uintptr, generation int64) Status {
					if generation != 7 || count.Load() != i-1 {
						t.Error("callback must precede server accept")
					}
					returned = true
					return OK
				})
				if status != OK || !returned || !r.Connected || r.ControlCalls != 1 || r.ServerAcceptSequence != i {
					t.Fatalf("%+v status %d", r, status)
				}
			}
			if count.Load() != 20 {
				t.Fatal("unexpected extra connection")
			}
		})
	}
}

func TestRejectedPreparationNeverConnects(t *testing.T) {
	port, count := socketFixture(t, "tcp4", "127.0.0.1")
	for _, reason := range []Status{ProtectFailed, NetworkChanged, StaleGeneration, IOError, Cancelled} {
		r, status := DialSocket(context.Background(), "127.0.0.1", port, 7, time.Second, func(uintptr, int64) Status { return reason })
		if status != reason || r.Connected || r.ControlCalls != 1 {
			t.Fatalf("%+v status %d expected %d", r, status, reason)
		}
	}
	r, status := DialSocket(context.Background(), "127.0.0.1", port, 7, time.Second, func(uintptr, int64) Status { panic("fixture callback failure") })
	if status != IOError || r.Connected || r.ControlCalls != 1 {
		t.Fatal("callback panic must fail before connect")
	}
	time.Sleep(50 * time.Millisecond)
	if count.Load() != 0 {
		t.Fatal("rejected callback reached server")
	}
}

func TestFixtureTimeoutClosesSocket(t *testing.T) {
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer listener.Close()
	closed := make(chan error, 1)
	go func() {
		conn, err := listener.Accept()
		if err != nil {
			closed <- err
			return
		}
		defer conn.Close()
		conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		var data [1]byte
		_, err = conn.Read(data[:])
		closed <- err
	}()
	r, status := DialSocket(context.Background(), "127.0.0.1", listener.Addr().(*net.TCPAddr).Port, 0, 100*time.Millisecond, func(uintptr, int64) Status { return OK })
	if status != IOError || !r.Connected {
		t.Fatal("fixture timeout must report connection but no success")
	}
	if err := <-closed; err != io.EOF {
		t.Fatalf("timed out socket not closed: %v", err)
	}
}

func TestAlreadyCancelledDialDoesNotPrepare(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r, status := DialSocket(ctx, "127.0.0.1", 443, 0, time.Second, func(uintptr, int64) Status { t.Fatal("cancelled dial callback"); return OK })
	if status != Cancelled || r.Connected || r.ControlCalls != 0 {
		t.Fatal("cancelled dial accepted")
	}
}

func TestSocketRejectsDNSAndInvalidArguments(t *testing.T) {
	for _, ip := range []string{"example.test", "", "127.0.0.1:443", "fe80::1%3"} {
		r, status := DialSocket(context.Background(), ip, 443, 7, time.Second, func(uintptr, int64) Status { t.Fatal("unexpected callback"); return OK })
		if status != InvalidArgument || r.Connected || r.ControlCalls != 0 {
			t.Fatal("invalid IP accepted")
		}
	}
	for _, timeout := range []time.Duration{0, 11 * time.Second} {
		_, status := DialSocket(context.Background(), "127.0.0.1", 443, 0, timeout, func(uintptr, int64) Status { return OK })
		if status != InvalidArgument {
			t.Fatal("invalid timeout accepted")
		}
	}
}

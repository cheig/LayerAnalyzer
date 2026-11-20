//go:build tlsprobe

// Package probe contains isolated P0 experiments, never the production router.
package probe

import (
	"context"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"syscall"
	"time"
)

type Status int32

const (
	OK Status = iota
	InvalidArgument
	NotReady
	CapacityExceeded
	IOError
	ProtectFailed
	NetworkChanged
	StaleGeneration
	Cancelled
)

func (s Status) Error() string { return "socket probe failed" }

// Prepare runs synchronously inside RawConn.Control, before connect. It must
// never retain fd: Go owns it, including every failure/timeout close path.
type Prepare func(fd uintptr, generation int64) Status

type SocketResult struct {
	ControlCalls         uint32
	Connected            bool
	ServerAcceptSequence uint32
}

// DialSocket uses only an original literal IP. The fixture replies with LAS1
// and its big-endian accept sequence; no user bytes or TLS secrets are logged.
func DialSocket(ctx context.Context, ip string, port int, generation int64, timeout time.Duration, prepare Prepare) (r SocketResult, status Status) {
	address, err := netip.ParseAddr(ip)
	if err != nil || address.Zone() != "" || port < 1 || port > 65535 || generation < 0 || timeout <= 0 || timeout > 10*time.Second || prepare == nil {
		return r, InvalidArgument
	}
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	network := "tcp6"
	if address.Is4() {
		network = "tcp4"
	}
	dialer := net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		var prepared Status = IOError
		if err := raw.Control(func(fd uintptr) {
			r.ControlCalls++
			prepared = prepareSafely(prepare, fd, generation)
		}); err != nil {
			return IOError
		}
		if prepared != OK {
			return prepared
		}
		return nil
	}}
	conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(address.String(), strconv.Itoa(port)))
	if err != nil {
		var callbackStatus Status
		if errors.As(err, &callbackStatus) && callbackStatus >= InvalidArgument && callbackStatus <= Cancelled {
			return r, callbackStatus
		}
		if errors.Is(err, context.Canceled) {
			return r, Cancelled
		}
		return r, IOError
	}
	defer conn.Close()
	r.Connected = true
	deadline, _ := ctx.Deadline()
	if err := conn.SetDeadline(deadline); err != nil {
		return r, IOError
	}
	var reply [8]byte
	if _, err := io.ReadFull(conn, reply[:]); err != nil || string(reply[:4]) != "LAS1" {
		return r, IOError
	}
	r.ServerAcceptSequence = binary.BigEndian.Uint32(reply[4:])
	if r.ServerAcceptSequence == 0 {
		return r, IOError
	}
	return r, OK
}

func prepareSafely(prepare Prepare, fd uintptr, generation int64) (status Status) {
	status = IOError
	defer func() {
		if recover() != nil {
			status = IOError
		}
	}()
	return prepare(fd, generation)
}

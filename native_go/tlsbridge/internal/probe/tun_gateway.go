//go:build tlsprobe

package probe

import (
	"bytes"
	"context"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net"
	"time"
)

// Benchmark-only address intercepted by the test VPN. No packet for this target
// is forwarded to the public network; the origin is the ephemeral local fixture.
const TunFixtureIP = "198.18.0.8"
const TunFixturePort = 443

type tunHeader struct {
	Version      int    `json:"version"`
	CaptureID    string `json:"captureId"`
	ConnectionID string `json:"connectionId"`
	Generation   int64  `json:"networkGeneration"`
	Address      string `json:"destinationAddress"`
	Port         int    `json:"destinationPort"`
	Token        string `json:"token"`
}

// No buffered reader: bytes immediately after LAT1 remain available to TLS.
// One authenticated connection consumes the entire single-use lab capacity.
func acceptTunGateway(ctx context.Context, down net.Conn, token []byte, target string, prepare Prepare) (net.Conn, error) {
	_ = down.SetDeadline(time.Now().Add(time.Second))
	data, err := readTunFrame(down, 4096)
	defer clear(data)
	if err != nil {
		return nil, InvalidArgument
	}
	var header tunHeader
	if json.Unmarshal(data, &header) != nil {
		return nil, InvalidArgument
	}
	provided, err := base64.RawURLEncoding.DecodeString(header.Token)
	defer clear(provided)
	if err != nil || len(provided) != 32 || subtle.ConstantTimeCompare(token, provided) != 1 ||
		header.Version != 1 || header.CaptureID != "tls-008" || header.ConnectionID != "fixture" ||
		header.Generation != 0 || header.Address != TunFixtureIP || header.Port != TunFixturePort {
		_ = writeTunFrame(down, []byte(`{"version":1,"success":false,"errorCode":"INVALID_ARGUMENT"}`))
		return nil, InvalidArgument
	}
	deadline, _ := ctx.Deadline()
	_ = down.SetDeadline(deadline)
	up, err := dialFixture(ctx, target, prepare)
	if err != nil {
		_ = writeTunFrame(down, []byte(`{"version":1,"success":false,"errorCode":"IO_ERROR"}`))
		return nil, err
	}
	// READY precedes ClientHello, but requires authenticated metadata and a
	// protected, connected upstream TCP socket. TLS verification happens next.
	if err := writeTunFrame(down, []byte(`{"version":1,"success":true,"errorCode":null}`)); err != nil {
		_ = up.Close()
		return nil, IOError
	}
	return up, nil
}

func readTunFrame(r io.Reader, limit uint32) ([]byte, error) {
	var prefix [8]byte
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return nil, err
	}
	n := binary.BigEndian.Uint32(prefix[4:])
	if string(prefix[:4]) != "LAT1" || n == 0 || n > limit {
		return nil, InvalidArgument
	}
	body := make([]byte, n)
	_, err := io.ReadFull(r, body)
	return body, err
}

func writeTunFrame(w io.Writer, data []byte) error {
	header := []byte{'L', 'A', 'T', '1', 0, 0, 0, 0}
	binary.BigEndian.PutUint32(header[4:], uint32(len(data)))
	_, err := io.Copy(w, bytes.NewReader(append(header, data...)))
	return err
}

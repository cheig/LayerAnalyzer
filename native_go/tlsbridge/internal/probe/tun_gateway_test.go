//go:build tlsprobe

package probe

import (
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"net"
	"testing"
)

func TestTunGatewayPair(t *testing.T) {
	for _, tc := range []struct {
		name, alpn string
		version    uint16
	}{
		{"tls12-h1", "http/1.1", tls.VersionTLS12}, {"tls13-h1", "http/1.1", tls.VersionTLS13}, {"tls13-h2", "h2", tls.VersionTLS13},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var port int
			var token []byte
			calls := 0
			opts := PairOptions{Version: tc.version, ALPN: tc.alpn,
				TunReady: func(p int, secret []byte) error { port = p; token = append([]byte(nil), secret...); return nil }}
			opts.tunClientDial = func(ctx context.Context) (net.Conn, error) {
				conn, err := (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intString(port)))
				if err != nil {
					return nil, err
				}
				header, _ := json.Marshal(tunHeader{1, "tls-008", "fixture", 0, TunFixtureIP, TunFixturePort, base64.RawURLEncoding.EncodeToString(token)})
				if err := writeTunFrame(conn, header); err != nil {
					conn.Close()
					return nil, err
				}
				reply, err := readTunFrame(conn, 1024)
				var result struct{ Success bool }
				if err != nil || json.Unmarshal(reply, &result) != nil || !result.Success {
					conn.Close()
					return nil, IOError
				}
				return conn, nil
			}
			r, err := RunTLSPair(context.Background(), opts, func(uintptr, int64) Status { calls++; return OK }, nil)
			defer clear(token)
			defer clear(r.DownstreamKeys)
			defer clear(r.UpstreamKeys)
			if err != nil || calls != 1 || !r.GatewayReady || !r.UpstreamVerified || !r.ConfigReplaced || r.BodyBytes != len(FixtureBody) || r.DownstreamRandom == r.UpstreamRandom {
				t.Fatalf("gateway pair failed: error=%v calls=%d ready=%v bytes=%d", err, calls, r.GatewayReady, r.BodyBytes)
			}
		})
	}
}

func TestTunGatewayRejectsBeforeConnect(t *testing.T) {
	for _, mutation := range []string{"token", "target", "generation", "oversize", "magic", "version"} {
		t.Run(mutation, func(t *testing.T) {
			client, server := net.Pipe()
			defer client.Close()
			defer server.Close()
			calls := 0
			done := make(chan error, 1)
			token := make([]byte, 32)
			go func() {
				_, err := acceptTunGateway(context.Background(), server, token, "127.0.0.1:1", func(uintptr, int64) Status { calls++; return OK })
				server.Close()
				done <- err
			}()
			header := tunHeader{1, "tls-008", "fixture", 0, TunFixtureIP, TunFixturePort, base64.RawURLEncoding.EncodeToString(token)}
			switch mutation {
			case "token":
				header.Token = "wrong"
			case "target":
				header.Address = "127.0.0.1"
			case "generation":
				header.Generation = 1
			case "version":
				header.Version = 2
			}
			data, _ := json.Marshal(header)
			if mutation == "oversize" {
				_, _ = client.Write([]byte{'L', 'A', 'T', '1', 0, 0, 16, 1})
			} else if mutation == "magic" {
				_, _ = client.Write([]byte{'B', 'A', 'D', '1', 0, 0, 0, 1})
			} else {
				_ = writeTunFrame(client, data)
			}
			_, _ = readTunFrame(client, 1024)
			if err := <-done; err == nil || calls != 0 {
				t.Fatalf("accepted invalid gateway: %v calls=%d", err, calls)
			}
		})
	}
}

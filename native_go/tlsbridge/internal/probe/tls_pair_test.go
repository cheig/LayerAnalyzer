//go:build tlsprobe

package probe

import (
	"context"
	"crypto/tls"
	"errors"
	"strings"
	"testing"
)

func TestTLSPairProtocols(t *testing.T) {
	for _, opts := range []PairOptions{{Version: tls.VersionTLS12, ALPN: "http/1.1"},
		{Version: tls.VersionTLS13, ALPN: "http/1.1"}, {Version: tls.VersionTLS13, ALPN: "h2"}} {
		t.Run(opts.ALPN+intString(int(opts.Version)), func(t *testing.T) {
			calls := 0
			r, err := RunTLSPair(context.Background(), opts, func(uintptr, int64) Status { calls++; return OK }, nil)
			if err != nil {
				t.Fatal(err)
			}
			if calls != 1 || !r.UpstreamVerified || !r.ConfigReplaced || !r.DownstreamHandshake || r.ALPN != opts.ALPN || r.Version != opts.Version || r.BodyBytes != 29 {
				t.Fatalf("invalid diagnostics: %+v", publicPair(r))
			}
			if len(r.DownstreamRandom) != 64 || len(r.UpstreamRandom) != 64 || r.DownstreamRandom == r.UpstreamRandom {
				t.Fatal("key directions not distinct")
			}
			lines := 4
			if opts.Version == tls.VersionTLS12 {
				lines = 1
			}
			for _, keys := range [][]byte{r.DownstreamKeys, r.UpstreamKeys} {
				if len(strings.Split(strings.TrimSpace(string(keys)), "\n")) != lines {
					t.Fatal("missing TLS secrets after config replacement")
				}
			}
		})
	}
}

func publicPair(r PairResult) PairResult { r.DownstreamKeys = nil; r.UpstreamKeys = nil; return r }

func TestTLSPairRejectsBeforeDownstreamHandshake(t *testing.T) {
	for _, scenario := range []string{"root", "alpn", "protect"} {
		t.Run(scenario, func(t *testing.T) {
			opts := PairOptions{Version: tls.VersionTLS13, ALPN: "h2", RejectUpstreamRoot: scenario == "root", MismatchedUpstreamALPN: scenario == "alpn"}
			r, err := RunTLSPair(context.Background(), opts, func(uintptr, int64) Status {
				if scenario == "protect" {
					return ProtectFailed
				}
				return OK
			}, nil)
			if err == nil || r.UpstreamVerified || r.ConfigReplaced || r.DownstreamHandshake || len(r.DownstreamKeys) != 0 || r.BodyBytes != 0 {
				t.Fatal("failure incorrectly completed downstream TLS")
			}
			if scenario == "root" && err.Error() != "UPSTREAM_CERT_INVALID" {
				t.Fatal("certificate error was not classified")
			}
		})
	}
}

func TestTLSPairInputCancellationAndKeyLimit(t *testing.T) {
	prepare := func(uintptr, int64) Status { return OK }
	if _, err := RunTLSPair(context.Background(), PairOptions{}, prepare, nil); !errors.Is(err, InvalidArgument) {
		t.Fatal("invalid options accepted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := RunTLSPair(ctx, PairOptions{Version: tls.VersionTLS13, ALPN: "h2"}, prepare, nil); !errors.Is(err, Cancelled) {
		t.Fatal("cancelled probe accepted")
	}
	var keys keyBuffer
	if _, err := keys.Write(make([]byte, keylogLimit)); err != nil {
		t.Fatal(err)
	}
	if _, err := keys.Write([]byte{1}); err == nil {
		t.Fatal("unbounded keylog")
	}
}

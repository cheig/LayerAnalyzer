//go:build tlsprobe

// Host-only raw-capture harness. Never packaged as an Android executable.
package main

import (
	"bufio"
	"com.layeranalyzer/tlsbridge/internal/probe"
	"context"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

func main() {
	output := flag.String("output", "", "private synthetic artifact directory")
	protocol := flag.String("protocol", "", "tls12-h1, tls13-h1 or tls13-h2")
	flag.Parse()
	opts := probe.PairOptions{Version: tls.VersionTLS13, ALPN: "http/1.1"}
	switch *protocol {
	case "tls12-h1":
		opts.Version = tls.VersionTLS12
	case "tls13-h1":
	case "tls13-h2":
		opts.ALPN = "h2"
	default:
		os.Exit(2)
	}
	if *output == "" || os.MkdirAll(*output, 0700) != nil {
		os.Exit(2)
	}
	r, err := probe.RunTLSPair(context.Background(), opts, func(uintptr, int64) probe.Status { return probe.OK }, func(port int) error {
		_ = json.NewEncoder(os.Stdout).Encode(map[string]any{"ready": true, "downstreamPort": port})
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil || strings.TrimSpace(line) != "GO" {
			return fmt.Errorf("capture did not start")
		}
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "TLS pair probe failed")
		os.Exit(1)
	}
	for name, data := range map[string][]byte{"tls-a.keys": r.DownstreamKeys, "tls-b.keys": r.UpstreamKeys} {
		if os.WriteFile(filepath.Join(*output, name), data, 0600) != nil {
			os.Exit(1)
		}
		clear(data)
	}
	data, _ := json.MarshalIndent(r, "", "  ")
	if os.WriteFile(filepath.Join(*output, "result.json"), data, 0600) != nil {
		os.Exit(1)
	}
	fmt.Println("PASS")
}

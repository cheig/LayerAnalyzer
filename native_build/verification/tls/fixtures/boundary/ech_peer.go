// Copyright (c) 2026 cheig; GPL-3.0.
// Standalone, test-only ECH peers. No production build imports this file.
package main

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"encoding/json"
	"errors"
	"flag"
	"io"
	"net"
	"os"
	"time"
)

const innerName = "inner.boundary.test"
const outerName = "outer.boundary.test"

type peerResult struct {
	OK          bool   `json:"ok"`
	ECHAccepted bool   `json:"echAccepted"`
	ECHRejected bool   `json:"echRejected"`
	ServerName  string `json:"serverName"`
	Version     uint16 `json:"version"`
	Bytes       int    `json:"bytes"`
	Error       string `json:"error,omitempty"`
}

func length16(b []byte) []byte {
	return append(binary.BigEndian.AppendUint16(nil, uint16(len(b))), b...)
}

// RFC 9849 ECHConfig: X25519 / HKDF-SHA256 / AES-128-GCM. Keys are fresh for
// every process; only public configuration travels to the TLS client.
func echConfig(publicKey []byte) []byte {
	b := []byte{123, 0, 0x20}
	b = append(b, length16(publicKey)...)
	b = append(b, length16([]byte{0, 1, 0, 1})...)
	b = append(b, 64, byte(len(outerName)))
	b = append(b, outerName...)
	b = append(b, 0, 0)
	return append([]byte{0xfe, 0x0d}, length16(b)...)
}

func main() {
	bind := flag.String("bind", "127.0.0.1", "explicit controlled interface")
	certFile := flag.String("cert", "", "ephemeral server certificate PEM")
	keyFile := flag.String("key", "", "ephemeral server key PEM")
	rootsFile := flag.String("roots", "", "fixture and proxy public roots PEM")
	flag.Parse()
	certificate, err := tls.LoadX509KeyPair(*certFile, *keyFile)
	check(err)
	rootBytes, err := os.ReadFile(*rootsFile)
	check(err)
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(rootBytes) {
		panic("missing test roots")
	}
	key, err := ecdh.X25519().GenerateKey(rand.Reader)
	check(err)
	config := echConfig(key.PublicKey().Bytes())
	origin, err := net.Listen("tcp", net.JoinHostPort(*bind, "0"))
	check(err)
	defer origin.Close()
	client, err := net.Listen("tcp", net.JoinHostPort(*bind, "0"))
	check(err)
	defer client.Close()
	// A peer must never survive a missing Android bridge or a failed test.
	time.AfterFunc(45*time.Second, func() { os.Exit(2) })
	encoder := json.NewEncoder(os.Stdout)
	check(encoder.Encode(map[string]int{
		"originPort": origin.Addr().(*net.TCPAddr).Port,
		"clientPort": client.Addr().(*net.TCPAddr).Port,
	}))
	serverDone := make(chan peerResult, 1)
	go func() {
		raw, err := origin.Accept()
		if err != nil {
			serverDone <- peerResult{Error: "accept_failed"}
			return
		}
		defer raw.Close()
		_ = raw.SetDeadline(time.Now().Add(25 * time.Second))
		conn := tls.Server(raw, &tls.Config{
			Certificates: []tls.Certificate{certificate}, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
			EncryptedClientHelloKeys: []tls.EncryptedClientHelloKey{{Config: config, PrivateKey: key.Bytes(), SendAsRetry: true}},
		})
		result := peerResult{}
		if conn.Handshake() != nil {
			result.Error = "handshake_failed"
		} else {
			state := conn.ConnectionState()
			result.ECHAccepted, result.ServerName, result.Version = state.ECHAccepted, state.ServerName, state.Version
			want := payload()
			got := make([]byte, len(want))
			n, readErr := io.ReadFull(conn, got)
			result.Bytes = n
			if readErr == nil && bytes.Equal(got, want) {
				_, writeErr := conn.Write(got)
				result.OK = writeErr == nil
			} else if n != 0 {
				result.Error = "payload_mismatch"
			}
		}
		_ = conn.Close()
		serverDone <- result
	}()
	raw, err := client.Accept()
	check(err)
	_ = raw.SetDeadline(time.Now().Add(25 * time.Second))
	conn := tls.Client(raw, &tls.Config{
		RootCAs: roots, ServerName: innerName, MinVersion: tls.VersionTLS13, MaxVersion: tls.VersionTLS13,
		EncryptedClientHelloConfigList: length16(config),
	})
	result := peerResult{}
	err = conn.Handshake()
	if err != nil {
		var rejected *tls.ECHRejectionError
		result.ECHRejected = errors.As(err, &rejected)
		result.Error = "handshake_failed"
	} else {
		state := conn.ConnectionState()
		result.ECHAccepted, result.ServerName, result.Version = state.ECHAccepted, state.ServerName, state.Version
		want := payload()
		if _, err = conn.Write(want); err == nil {
			got := make([]byte, len(want))
			result.Bytes, err = io.ReadFull(conn, got)
			result.OK = err == nil && bytes.Equal(want, got)
		}
	}
	_ = conn.Close()
	check(encoder.Encode(map[string]peerResult{"client": result, "origin": <-serverDone}))
}

func payload() []byte { return bytes.Repeat([]byte("tls-217-real-ech\n"), 2048) }
func check(err error) {
	if err != nil {
		// Paths, certificates and runtime key material never enter diagnostics.
		panic("ECH fixture setup failed")
	}
}

// Copyright (c) 2026 cheig; GPL-3.0.
// Controlled LAN HTTP and untrusted-TLS origins for TlsVpnDecryptionTest.
// The positive TLS origin is independent (hostTlsHost), and must pass the
// production Android system trust policy. This self-signed origin is ONLY for
// the negative upstream-certificate test. Keys exist only in this process.
//
// go run native_build/verification/tls/vpn_decryption_fixture.go -bind <fixture-host>
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"flag"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"time"
)

func main() {
	bind := flag.String("bind", "", "explicit LAN IPv4/IPv6 address reachable by the device")
	httpPort := flag.Int("http-port", 18080, "plain HTTP regression port")
	badCertPort := flag.Int("bad-cert-port", 18444, "self-signed upstream negative-test port")
	matrixTLS12Origin := flag.String("matrix-tls12-origin", "", "optional system-trusted TLS 1.2 origin, host:port")
	matrixTLS13Origin := flag.String("matrix-tls13-origin", "", "optional system-trusted TLS 1.3 origin, host:port")
	matrixTLS12Port := flag.Int("matrix-tls12-port", 18442, "LAN TCP relay to the TLS 1.2 matrix origin")
	matrixTLS13Port := flag.Int("matrix-tls13-port", 18443, "LAN TCP relay to the TLS 1.3 matrix origin")
	flag.Parse()
	ip := net.ParseIP(*bind)
	if ip == nil || ip.IsUnspecified() {
		panic("-bind must be an explicit LAN IP address")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		panic(err)
	}
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: "TLS-218 untrusted fixture"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IPAddresses: []net.IP{ip}, KeyUsage: x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		panic(err)
	}
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		w.Header().Set("Connection", "close")
		fmt.Fprint(w, "tls-218-arm64-body\n")
	})
	plain, err := net.Listen("tcp", net.JoinHostPort(*bind, fmt.Sprint(*httpPort)))
	if err != nil {
		panic(err)
	}
	defer plain.Close()
	bad, err := tls.Listen("tcp", net.JoinHostPort(*bind, fmt.Sprint(*badCertPort)), &tls.Config{
		MinVersion:   tls.VersionTLS12,
		Certificates: []tls.Certificate{{Certificate: [][]byte{der}, PrivateKey: key}},
	})
	if err != nil {
		panic(err)
	}
	defer bad.Close()
	fmt.Printf("READY http=%s badCert=%s (untrusted; private key is memory-only)\n", plain.Addr(), bad.Addr())
	failures := make(chan error, 4)
	for _, origin := range []struct {
		address string
		port    int
		version uint16
	}{
		{*matrixTLS12Origin, *matrixTLS12Port, tls.VersionTLS12},
		{*matrixTLS13Origin, *matrixTLS13Port, tls.VersionTLS13},
	} {
		if origin.address == "" {
			continue
		}
		for _, alpn := range []string{"http/1.1", "h2"} {
			conn, err := tls.DialWithDialer(&net.Dialer{Timeout: 10 * time.Second}, "tcp", origin.address,
				&tls.Config{MinVersion: origin.version, MaxVersion: origin.version, NextProtos: []string{alpn}})
			if err != nil {
				panic(fmt.Errorf("matrix origin preflight: %w", err))
			}
			state := conn.ConnectionState()
			conn.Close()
			if state.Version != origin.version || state.NegotiatedProtocol != alpn {
				panic("matrix origin negotiated the wrong TLS version or ALPN")
			}
			fmt.Printf("PREFLIGHT origin=%s tls=%s alpn=%s systemTrusted=true\n",
				origin.address, tls.VersionName(state.Version), alpn)
		}
		listener, err := net.Listen("tcp", net.JoinHostPort(*bind, fmt.Sprint(origin.port)))
		if err != nil {
			panic(err)
		}
		defer listener.Close()
		fmt.Printf("MATRIX relay=%s origin=%s tlsTermination=false\n", listener.Addr(), origin.address)
		go func(listener net.Listener, address string) { failures <- serveMatrixRelay(listener, address) }(listener, origin.address)
	}
	go func() { failures <- (&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(plain) }()
	go func() { failures <- (&http.Server{Handler: handler, ReadHeaderTimeout: 5 * time.Second}).Serve(bad) }()
	panic(<-failures)
}

func serveMatrixRelay(listener net.Listener, address string) error {
	for {
		downstream, err := listener.Accept()
		if err != nil {
			return err
		}
		go func() {
			defer downstream.Close()
			upstream, err := net.DialTimeout("tcp", address, 10*time.Second)
			if err != nil {
				return
			}
			defer upstream.Close()
			deadline := time.Now().Add(45 * time.Second)
			downstream.SetDeadline(deadline)
			upstream.SetDeadline(deadline)
			finished := make(chan struct{})
			go func() {
				io.Copy(upstream, downstream)
				upstream.(*net.TCPConn).CloseWrite()
				close(finished)
			}()
			io.Copy(downstream, upstream)
			downstream.(*net.TCPConn).CloseWrite()
			<-finished
		}()
	}
}

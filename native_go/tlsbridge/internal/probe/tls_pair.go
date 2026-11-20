//go:build tlsprobe

package probe

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"errors"
	"io"
	"log"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"sync"
	"syscall"
	"time"
)

const FixtureName = "fixture.layeranalyzer.test"
const FixtureBody = "LayerAnalyzer TLS fixture v1\n"
const keylogLimit = 16 * 1024 // One synthetic connection, never a production queue.

// PairOptions cannot select an external destination, arbitrary identity or CA.
// All three endpoints are ephemeral loopback fixtures inside this process.
type PairOptions struct {
	Version                uint16
	ALPN                   string
	RejectUpstreamRoot     bool
	MismatchedUpstreamALPN bool
	// P0 only: installs the authenticated gateway in a test VPN before dialing
	// the synthetic routed address. Never supplied by the production engine.
	TunReady      func(port int, token []byte) error
	tunClientDial func(context.Context) (net.Conn, error) // host harness only
}

// Secret bytes deliberately never serialize into the ordinary JSON result.
type PairResult struct {
	DownstreamPort      int    `json:"downstreamPort"`
	DownstreamRandom    string `json:"downstreamClientRandom"`
	UpstreamRandom      string `json:"upstreamClientRandom"`
	Version             uint16 `json:"tlsVersion"`
	ALPN                string `json:"alpn"`
	UpstreamVerified    bool   `json:"upstreamVerified"`
	ConfigReplaced      bool   `json:"configReplaced"`
	DownstreamHandshake bool   `json:"downstreamHandshake"`
	BodySHA256          string `json:"bodySha256"`
	BodyBytes           int    `json:"bodyBytes"`
	GatewayReady        bool   `json:"gatewayReady"`
	DownstreamKeys      []byte `json:"-"`
	UpstreamKeys        []byte `json:"-"`
}

type keyBuffer struct{ bytes.Buffer }

func (w *keyBuffer) Write(p []byte) (int, error) {
	if w.Len()+len(p) > keylogLimit {
		return 0, errors.New("probe secret capacity")
	}
	return w.Buffer.Write(p)
}

func fixtureCertificate() (tls.Certificate, *x509.CertPool, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	now := time.Now()
	root := &x509.Certificate{SerialNumber: serial, Subject: pkix.Name{CommonName: "LayerAnalyzer ephemeral probe root"},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour), IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature}
	der, err := x509.CreateCertificate(rand.Reader, root, root, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	ca, err := x509.ParseCertificate(der)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	leaf := &x509.Certificate{SerialNumber: new(big.Int).Add(serial, big.NewInt(1)), DNSNames: []string{FixtureName},
		Subject: pkix.Name{CommonName: FixtureName}, NotBefore: root.NotBefore, NotAfter: root.NotAfter,
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	leafDER, err := x509.CreateCertificate(rand.Reader, leaf, ca, &leafKey.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, nil, err
	}
	pool := x509.NewCertPool()
	pool.AddCert(ca)
	return tls.Certificate{Certificate: [][]byte{leafDER, der}, PrivateKey: leafKey}, pool, nil
}

// RunTLSPair is a complete, single-use lab, not a production gateway or relay.
// ready allows an external raw packet capturer to start before the Go client.
// The only network target is the listener created here. prepare is synchronous
// before the upstream connect; Android physical-network binding remains TLS-005.
func RunTLSPair(ctx context.Context, opts PairOptions, prepare Prepare, ready func(int) error) (out PairResult, err error) {
	if (opts.Version != tls.VersionTLS12 && opts.Version != tls.VersionTLS13) ||
		(opts.ALPN != "http/1.1" && opts.ALPN != "h2") || prepare == nil {
		return out, InvalidArgument
	}
	originCert, originRoots, err := fixtureCertificate()
	if err != nil {
		return out, IOError
	}
	proxyCert, proxyRoots, err := fixtureCertificate()
	if err != nil {
		return out, IOError
	}
	origin, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return out, IOError
	}
	defer origin.Close()
	serverALPN := opts.ALPN
	if opts.MismatchedUpstreamALPN {
		serverALPN = "probe-invalid"
	}
	originServer := &http.Server{TLSConfig: &tls.Config{Certificates: []tls.Certificate{originCert},
		MinVersion: opts.Version, MaxVersion: opts.Version, NextProtos: []string{serverALPN},
		SessionTicketsDisabled: true}, ErrorLog: log.New(io.Discard, "", 0),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != "GET" || r.URL.Path != "/fixture" || r.Host != FixtureName {
				http.Error(w, "", 400)
				return
			}
			w.Header().Set("Content-Type", "text/plain")
			w.Header().Set("Content-Length", "29")
			_, _ = io.WriteString(w, FixtureBody)
		})}
	// Suppress automatic h2 ALPN insertion for the deliberate mismatch case.
	if opts.MismatchedUpstreamALPN {
		originServer.TLSNextProto = map[string]func(*http.Server, *tls.Conn, http.Handler){}
	}
	originDone := make(chan struct{})
	go func() { defer close(originDone); _ = originServer.ServeTLS(origin, "", "") }()
	defer func() { _ = originServer.Close(); <-originDone }()
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		return out, IOError
	}
	defer listener.Close()
	out.DownstreamPort = listener.Addr().(*net.TCPAddr).Port
	var token []byte
	if opts.TunReady != nil {
		token = make([]byte, 32)
		if _, err := rand.Read(token); err != nil {
			return out, IOError
		}
		defer clear(token)
		if err := opts.TunReady(out.DownstreamPort, token); err != nil {
			return out, Cancelled
		}
		out.DownstreamPort = TunFixturePort
	}
	if ready != nil {
		if err := ready(out.DownstreamPort); err != nil {
			return out, Cancelled
		}
	}
	if ctx.Err() != nil {
		return out, Cancelled
	}
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	// Both private keys stay in Go memory; each side trusts only its own test root.
	upstreamRoots := originRoots
	if opts.RejectUpstreamRoot {
		upstreamRoots = proxyRoots
	}
	proxyDone := make(chan error, 1)
	stopAccept := context.AfterFunc(ctx, func() { _ = listener.Close() })
	defer stopAccept()
	go func() {
		down, acceptErr := listener.Accept()
		_ = listener.Close() // Never accepts a second client or forwards arbitrary targets.
		if acceptErr != nil {
			proxyDone <- IOError
			return
		}
		var connected net.Conn
		if opts.TunReady != nil {
			connected, acceptErr = acceptTunGateway(ctx, down, token, origin.Addr().String(), prepare)
			if acceptErr != nil {
				_ = down.Close()
				proxyDone <- acceptErr
				return
			}
			defer connected.Close()
			out.GatewayReady = true
		}
		relayErr := relayFixturePair(ctx, down, origin.Addr().String(), opts, proxyCert, upstreamRoots, prepare, &out, connected)
		_ = down.Close()
		proxyDone <- relayErr
	}()
	transport := &http.Transport{ForceAttemptHTTP2: opts.ALPN == "h2", DisableKeepAlives: true,
		TLSClientConfig: &tls.Config{RootCAs: proxyRoots, ServerName: FixtureName,
			MinVersion: opts.Version, MaxVersion: opts.Version, NextProtos: []string{opts.ALPN}},
		DialContext: func(ctx context.Context, _, _ string) (net.Conn, error) {
			if opts.TunReady != nil {
				if opts.tunClientDial != nil {
					return opts.tunClientDial(ctx)
				}
				return (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort(TunFixtureIP, intString(TunFixturePort)))
			}
			return (&net.Dialer{}).DialContext(ctx, "tcp4", net.JoinHostPort("127.0.0.1", intString(out.DownstreamPort)))
		}}
	defer transport.CloseIdleConnections()
	request, _ := http.NewRequestWithContext(ctx, "GET", "https://"+FixtureName+"/fixture", nil)
	response, clientErr := transport.RoundTrip(request)
	var body []byte
	if clientErr == nil {
		body, clientErr = io.ReadAll(io.LimitReader(response.Body, 1025))
		_ = response.Body.Close()
		if response.StatusCode != 200 || response.TLS.NegotiatedProtocol != opts.ALPN || response.TLS.Version != opts.Version ||
			(opts.ALPN == "h2" && response.ProtoMajor != 2) || string(body) != FixtureBody {
			clientErr = IOError
		}
	}
	transport.CloseIdleConnections()
	proxyErr := <-proxyDone // Joins all relay work before keys/results are exposed.
	if proxyErr != nil {
		return out, proxyErr
	}
	if clientErr != nil {
		return out, IOError
	}
	out.BodyBytes = len(body)
	hash := sha256.Sum256(body)
	out.BodySHA256 = hex.EncodeToString(hash[:])
	return out, nil
}

func intString(n int) string { // net ports only; avoids accepting a host from callers.
	return strconv.Itoa(n)
}

func relayFixturePair(ctx context.Context, raw net.Conn, target string, opts PairOptions,
	cert tls.Certificate, roots *x509.CertPool, prepare Prepare, out *PairResult, connected net.Conn) error {
	deadline, _ := ctx.Deadline()
	_ = raw.SetDeadline(deadline)
	stop := context.AfterFunc(ctx, func() { _ = raw.Close() })
	defer stop()
	var a, b keyBuffer
	defer func() {
		out.DownstreamKeys = bytes.Clone(a.Bytes())
		out.UpstreamKeys = bytes.Clone(b.Bytes())
		out.DownstreamRandom = firstRandom(out.DownstreamKeys)
		out.UpstreamRandom = firstRandom(out.UpstreamKeys)
		clear(a.Bytes())
		clear(b.Bytes())
	}()
	var upstream *tls.Conn
	defer func() {
		if upstream != nil {
			_ = upstream.Close()
		}
	}()
	base := &tls.Config{MinVersion: opts.Version, MaxVersion: opts.Version, SessionTicketsDisabled: true,
		KeyLogWriter: &a} // Required even when GetConfigForClient returns a new config.
	base.GetConfigForClient = func(hello *tls.ClientHelloInfo) (*tls.Config, error) {
		if hello.ServerName != FixtureName || !contains(hello.SupportedProtos, opts.ALPN) {
			return nil, InvalidArgument
		}
		conn, err := connected, error(nil)
		if conn == nil {
			conn, err = dialFixture(ctx, target, prepare)
		}
		if err != nil {
			return nil, err
		}
		_ = conn.SetDeadline(deadline)
		upstream = tls.Client(conn, &tls.Config{RootCAs: roots, ServerName: FixtureName,
			MinVersion: opts.Version, MaxVersion: opts.Version, NextProtos: []string{opts.ALPN}, KeyLogWriter: &b})
		if err := upstream.HandshakeContext(ctx); err != nil {
			var certErr *tls.CertificateVerificationError
			if errors.As(err, &certErr) {
				return nil, errors.New("UPSTREAM_CERT_INVALID")
			}
			return nil, IOError
		}
		if upstream.ConnectionState().NegotiatedProtocol != opts.ALPN {
			return nil, errors.New("ALPN_MISMATCH")
		}
		out.UpstreamVerified = true
		out.ConfigReplaced = true
		return &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: opts.Version, MaxVersion: opts.Version,
			NextProtos: []string{opts.ALPN}, SessionTicketsDisabled: true, KeyLogWriter: &a}, nil
	}
	downstream := tls.Server(raw, base)
	if err := downstream.HandshakeContext(ctx); err != nil {
		return err
	}
	out.DownstreamHandshake = true
	out.Version = downstream.ConnectionState().Version
	out.ALPN = downstream.ConnectionState().NegotiatedProtocol
	if out.ALPN != upstream.ConnectionState().NegotiatedProtocol {
		return errors.New("ALPN_MISMATCH")
	}
	// Lab only: whole experiment shares a 10s budget. Production idle/half-close
	// policy belongs to TLS-211. 32 KiB per direction; no HTTP transformation.
	var wg sync.WaitGroup
	wg.Add(2)
	copyTo := func(dst, src *tls.Conn) {
		defer wg.Done()
		_, _ = io.CopyBuffer(dst, src, make([]byte, 32*1024))
		_ = dst.CloseWrite()
	}
	go copyTo(upstream, downstream)
	go copyTo(downstream, upstream)
	wg.Wait()
	return nil
}

func dialFixture(ctx context.Context, target string, prepare Prepare) (net.Conn, error) {
	return (&net.Dialer{Control: func(_, _ string, raw syscall.RawConn) error {
		status := IOError
		if err := raw.Control(func(fd uintptr) { status = prepareSafely(prepare, fd, 0) }); err != nil {
			return IOError
		}
		if status != OK {
			return status
		}
		return nil
	}}).DialContext(ctx, "tcp4", target)
}

func contains(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}
func firstRandom(keys []byte) string {
	fields := bytes.Fields(keys)
	if len(fields) < 3 {
		return ""
	}
	return string(fields[1])
}

package assembly

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math/big"
	"net"
	"strings"
	"sync"
	"testing"
	"time"

	"com.layeranalyzer/tlsbridge/internal/certstore"
	"com.layeranalyzer/tlsbridge/internal/engine"
)

// The assembler is tested through the production lifecycle, not around it:
// engine.NewManager(Factory()).Start(...) is exactly what la_tls_start does, so
// these cases cover the wiring, the gateway's authenticated frame, the decision
// maker, both handshakes, the relay and the capture's events in one run. The
// only double is the C05 platform, which cannot run off Android.

// platformStub is the platform half: it accepts every socket preparation, every
// resolution and every secret, and records what it was asked. It deliberately
// never keeps a secret's text.
type platformStub struct {
	mu       sync.Mutex
	verdict  engine.Code
	prepared int
	verified int
	offers   int
	identity string
}

func (p *platformStub) PrepareSocket(fd int, generation int64) engine.Code {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.prepared++
	return engine.OK
}

func (p *platformStub) ResolveHost(string, int64) ([]byte, engine.Code) { return nil, engine.NotReady }

func (p *platformStub) VerifyUpstream(_ [][]byte, identity, _, _ string) engine.Code {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.verified++
	p.identity = identity
	return p.verdict
}

func (p *platformStub) OfferSecret(_, _ string, _ []byte) engine.Code {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.offers++
	return engine.OK
}

func (p *platformStub) counts() (prepared, verified, offers int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.prepared, p.verified, p.offers
}

func (p *platformStub) verifiedIdentity() string {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.identity
}

// selfSigned builds the origin's server certificate. It is not a CA and not a
// fixture: it is the certificate the origin presents, which the platform's
// trust answer is the only thing deciding about.
func selfSigned(t *testing.T, names []string) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating the origin's key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "origin"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		DNSNames:              names,
		KeyUsage:              x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("creating the origin's certificate: %v", err)
	}
	parsed, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parsing the origin's certificate: %v", err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key, Leaf: parsed}
}

// echoOrigin is a real TLS server that echoes what it is sent and counts both
// its handshakes and the application bytes it read.
type echoOrigin struct {
	listener net.Listener
	mu       sync.Mutex
	attempts int
	appBytes int
	snis     []string
}

func newEchoOrigin(t *testing.T, certificate tls.Certificate) *echoOrigin {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates:       []tls.Certificate{certificate},
		MinVersion:         tls.VersionTLS12,
		GetConfigForClient: func(*tls.ClientHelloInfo) (*tls.Config, error) { return nil, nil },
	})
	if err != nil {
		t.Fatalf("listening as the origin: %v", err)
	}
	origin := &echoOrigin{listener: listener}
	t.Cleanup(func() { _ = listener.Close() })
	go origin.accept()
	return origin
}

func (o *echoOrigin) accept() {
	for {
		conn, err := o.listener.Accept()
		if err != nil {
			return
		}
		go o.serve(conn)
	}
}

func (o *echoOrigin) serve(conn net.Conn) {
	defer func() { _ = conn.Close() }()
	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}
	o.mu.Lock()
	o.attempts++
	o.mu.Unlock()
	if err := tlsConn.Handshake(); err != nil {
		return
	}
	o.mu.Lock()
	o.snis = append(o.snis, tlsConn.ConnectionState().ServerName)
	o.mu.Unlock()
	buffer := make([]byte, 4096)
	for {
		n, err := tlsConn.Read(buffer)
		if n > 0 {
			o.mu.Lock()
			o.appBytes += n
			o.mu.Unlock()
			if _, writeErr := tlsConn.Write(buffer[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			return
		}
	}
}

func (o *echoOrigin) port() uint16 { return uint16(o.listener.Addr().(*net.TCPAddr).Port) }

func (o *echoOrigin) received() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.appBytes
}

func (o *echoOrigin) seenSNI() string {
	o.mu.Lock()
	defer o.mu.Unlock()
	if len(o.snis) == 0 {
		return ""
	}
	return o.snis[0]
}

func (o *echoOrigin) waitReceived(t *testing.T, want int) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if o.received() >= want {
			return
		}
		time.Sleep(2 * time.Millisecond)
	}
	t.Fatalf("the origin read %d application bytes, want %d", o.received(), want)
}

// captureMaterial mints a capture CA and returns it in the two forms the callers
// need: the material the engine adopts, and the pool the application trusts.
func captureMaterial(t *testing.T) (engine.Material, *x509.CertPool) {
	t.Helper()
	root, code := certstore.GenerateRoot(time.Now())
	if code != engine.OK {
		t.Fatalf("generating the capture CA: %v", code)
	}
	certificateDER, keyPKCS8, code := root.Export()
	if code != engine.OK {
		t.Fatalf("exporting the capture CA: %v", code)
	}
	defer clear(keyPKCS8)
	material, code := engine.ParseMaterial(certificateDER, keyPKCS8, time.Now())
	if code != engine.OK {
		t.Fatalf("parsing the capture CA: %v", code)
	}
	pool := x509.NewCertPool()
	pool.AddCert(root.Certificate)
	return material, pool
}

// frozenSettings is the policy Kotlin freezes into the start config (C04).
func frozenSettings(port uint16, enabled bool, domains ...string) string {
	include := make([]map[string]string, 0, len(domains))
	for _, domain := range domains {
		include = append(include, map[string]string{"kind": "exactDomain", "value": domain})
	}
	settings := map[string]any{
		"schemaVersion":  1,
		"enabled":        enabled,
		"hostScope":      "ExplicitHosts",
		"candidatePorts": []int{int(port)},
		"include":        include,
		"bypass":         []any{},
		"applications":   []any{},
	}
	encoded, err := json.Marshal(settings)
	if err != nil {
		panic(err)
	}
	return string(encoded)
}

func startConfig(t *testing.T, captureID string, settings string) engine.Config {
	t.Helper()
	raw := map[string]any{
		"schemaVersion":     1,
		"captureId":         captureID,
		"networkGeneration": 11,
		"settings":          json.RawMessage(settings),
	}
	encoded, err := json.Marshal(raw)
	if err != nil {
		t.Fatalf("encoding the start config: %v", err)
	}
	// Parsed through the production parser, so a test config is exactly as valid
	// as the one the ABI hands over.
	config, code := engine.ParseConfig(encoded)
	if code != engine.OK {
		t.Fatalf("the test's start config was rejected with %v", code)
	}
	return config
}

// gatewayHello sends one C05 LAT1 frame and reads the gateway's reply.
func gatewayHello(t *testing.T, port uint16, captureID, connectionID, token string, destination net.Addr) net.Conn {
	t.Helper()
	conn, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		t.Fatalf("dialing the gateway: %v", err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	host, portText, err := net.SplitHostPort(destination.String())
	if err != nil {
		t.Fatalf("splitting the destination: %v", err)
	}
	metadata := map[string]any{
		"version":            1,
		"captureId":          captureID,
		"connectionId":       connectionID,
		"networkGeneration":  11,
		"destinationAddress": host,
		"destinationPort":    atoi(t, portText),
		"token":              token,
	}
	body, err := json.Marshal(metadata)
	if err != nil {
		t.Fatalf("encoding the gateway metadata: %v", err)
	}
	frame := make([]byte, 8, 8+len(body))
	copy(frame[:4], "LAT1")
	binary.BigEndian.PutUint32(frame[4:], uint32(len(body)))
	frame = append(frame, body...)
	if _, err := conn.Write(frame); err != nil {
		t.Fatalf("writing the gateway metadata: %v", err)
	}
	reply := make([]byte, 8)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("reading the gateway's reply: %v", err)
	}
	if string(reply[:4]) != "LAT1" {
		t.Fatalf("the gateway's reply is not a LAT1 frame: %q", reply[:4])
	}
	length := binary.BigEndian.Uint32(reply[4:])
	body = make([]byte, length)
	if _, err := io.ReadFull(conn, body); err != nil {
		t.Fatalf("reading the gateway's reply body: %v", err)
	}
	var decoded struct {
		Version   int     `json:"version"`
		Success   bool    `json:"success"`
		ErrorCode *string `json:"errorCode"`
	}
	if err := json.Unmarshal(body, &decoded); err != nil {
		t.Fatalf("parsing the gateway's reply: %v", err)
	}
	if !decoded.Success {
		failure := "unknown"
		if decoded.ErrorCode != nil {
			failure = *decoded.ErrorCode
		}
		t.Fatalf("the gateway refused the connection with %s; READY must come only after the upstream TCP is up", failure)
	}
	return conn
}

func atoi(t *testing.T, text string) int {
	t.Helper()
	var value int
	if _, err := fmt.Sscanf(text, "%d", &value); err != nil {
		t.Fatalf("%q is not a port: %v", text, err)
	}
	return value
}

// TestTheFactoryRefusesARunThatCannotIntercept pins the two configurations that
// must not open a port: one with no frozen policy at all, and one whose policy
// says interception is off. Both answer NOT_READY, because an engine that can
// only forward traffic is a useless listener announcing readiness (TLS-201).
func TestTheFactoryRefusesARunThatCannotIntercept(t *testing.T) {
	material, _ := captureMaterial(t)
	platform := &platformStub{}
	manager := engine.NewManager(Factory())

	noSettings, code := engine.ParseConfig([]byte(
		`{"schemaVersion":1,"captureId":"capture-one","networkGeneration":11}`))
	if code != engine.OK {
		t.Fatalf("parsing a config without settings: %v", code)
	}
	disabled := startConfig(t, "capture-one", frozenSettings(443, false, "example.test"))
	malformed := startConfig(t, "capture-one", `{"schemaVersion":1}`)
	for name, config := range map[string]engine.Config{
		"no settings": noSettings,
		"disabled":    disabled,
		"malformed":   malformed,
	} {
		handle, port, token, code := manager.Start(config, material, platform)
		if name == "malformed" {
			if code != engine.InvalidArgument {
				t.Fatalf("%s: code = %v, want INVALID_ARGUMENT", name, code)
			}
		} else if code != engine.NotReady {
			t.Fatalf("%s: code = %v, want NOT_READY", name, code)
		}
		if handle != 0 || port != 0 || token != nil {
			t.Fatalf("%s: a refused start returned handle %d, port %d, token %d bytes", name, handle, port, len(token))
		}
	}
	if prepared, verified, offers := platform.counts(); prepared != 0 || verified != 0 || offers != 0 {
		t.Fatalf("a refused start called the platform %d/%d/%d times", prepared, verified, offers)
	}
}

// TestAnAssembledRunCarriesOneRealConnection is the assembler's end-to-end case:
// the production factory starts a run, the gateway authenticates one frame, and
// the application's own TLS is terminated and carried to a real origin and back.
func TestAnAssembledRunCarriesOneRealConnection(t *testing.T) {
	testAssembledConnection(t, false)
}

func TestSelectedApplicationsRunCarriesTLSWithoutPerFlowAttribution(t *testing.T) {
	testAssembledConnection(t, true)
}

func testAssembledConnection(t *testing.T, selectedApplications bool) {
	t.Helper()
	origin := newEchoOrigin(t, selfSigned(t, []string{"example.test"}))
	material, pool := captureMaterial(t)
	platform := &platformStub{}
	manager := engine.NewManager(Factory())

	settings := frozenSettings(origin.port(), true, "example.test")
	if selectedApplications {
		settings = fmt.Sprintf(`{"schemaVersion":1,"enabled":true,"hostScope":"SelectedApplicationsCandidates",
			"candidatePorts":[%d],"include":[],"bypass":[],"applications":["com.example.first","com.example.second"]}`, origin.port())
	}
	config := startConfig(t, "capture-one", settings)
	handle, port, token, code := manager.Start(config, material, platform)
	if code != engine.OK {
		t.Fatalf("starting the assembled run: %v", code)
	}
	t.Cleanup(func() { manager.Stop(handle, 5*time.Second) })
	if port == 0 || len(token) == 0 {
		t.Fatalf("start returned port %d and a %d-byte token", port, len(token))
	}

	conn := gatewayHello(t, port, "capture-one", "connection-1", string(token), origin.listener.Addr())
	app := tls.Client(conn, &tls.Config{
		RootCAs:    pool,
		ServerName: "example.test",
		MinVersion: tls.VersionTLS12,
	})
	if err := app.Handshake(); err != nil {
		t.Fatalf("the application's handshake with the proxy: %v", err)
	}
	request := "POST /checkout"
	if _, err := app.Write([]byte(request)); err != nil {
		t.Fatalf("writing the application's request: %v", err)
	}
	origin.waitReceived(t, len(request))
	echo := make([]byte, len(request))
	if _, err := io.ReadFull(app, echo); err != nil {
		t.Fatalf("reading the origin's answer: %v", err)
	}
	if string(echo) != request {
		t.Fatalf("the answer = %q, want the origin's echo", echo)
	}
	if origin.received() != len(request) {
		t.Fatalf("the origin read %d application bytes, want exactly one request", origin.received())
	}
	if origin.seenSNI() != "example.test" {
		t.Fatalf("the origin saw SNI %q", origin.seenSNI())
	}
	if identity := platform.verifiedIdentity(); identity != "example.test" {
		t.Fatalf("the upstream destination was verified as %q", identity)
	}
	_ = app.CloseWrite()
	_ = app.SetReadDeadline(time.Now().Add(5 * time.Second))
	_, _ = io.Copy(io.Discard, app)
	_ = app.Close()

	// The events and the counters the UI reads come out of the same run. The
	// terminal phase is published when the connection ends, which is after the
	// last byte the application sees, so the reader waits for it the way the UI
	// does: poll, and check again.
	want := []string{"ACCEPTED", "SNIFFING", "UPSTREAM_HANDSHAKE", "DOWNSTREAM_HANDSHAKE", "RELAYING", "CLOSED"}
	phases := []string{}
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		events, code := manager.Poll(handle, 128)
		if code != engine.OK {
			t.Fatalf("polling the run's events: %v", code)
		}
		phases = append(phases, publishedPhases(t, events)...)
		if len(phases) > 0 && (phases[len(phases)-1] == "CLOSED" || phases[len(phases)-1] == "FAILED") {
			break
		}
		time.Sleep(5 * time.Millisecond)
	}
	if strings.Join(phases, ",") != strings.Join(want, ",") {
		t.Fatalf("phases = %v, want %v", phases, want)
	}
	stats, code := manager.Stats(handle)
	if code != engine.OK {
		t.Fatalf("reading the run's stats: %v", code)
	}
	metrics, ok := stats["runtimeMetrics"].(engine.RuntimeMetrics)
	if !ok || metrics.CertificateCacheEntries != 1 || metrics.GoSecretsQueueBytes != 0 ||
		metrics.CertificateCachePeakEntries != 1 || metrics.CertificateIssuances != 1 ||
		metrics.CertificateIssuancesInFlight != 0 || metrics.ProbesFinished == 0 ||
		metrics.ProbesActive != 0 || metrics.ProbePrefixCapacityBytes != 0 ||
		metrics.ProbePeakPrefixCapacityBytes == 0 || metrics.GoSecretsInFlightBytes != 0 ||
		metrics.GoSecretsOffered == 0 || metrics.GoSecretsQueuePeakBytes == 0 {
		t.Fatalf("real cache/queue counters missing: %+v", stats["runtimeMetrics"])
	}
	if value, ok := stats["events"].(engine.Stats); ok {
		if value.ConnectionsProxied != 1 || value.ConnectionsPassthrough != 0 {
			t.Fatalf("the capture counted %d proxied and %d pass-through connections",
				value.ConnectionsProxied, value.ConnectionsPassthrough)
		}
	} else {
		t.Fatalf("the stats response carries %T under \"events\"", stats["events"])
	}
	if _, _, offers := platform.counts(); offers == 0 {
		t.Fatal("the capture recorded no downstream secret for an intercepted connection")
	}

	// Stopping ends the run: the port stops accepting and the handle goes stale.
	if code := manager.Stop(handle, 5*time.Second); code != engine.OK {
		t.Fatalf("stopping the run: %v", code)
	}
	if _, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond); err == nil {
		t.Fatal("the gateway still accepts connections after a stop")
	}
	// Closing live connections may have emitted final events during Stop.
	// The last run remains drainable until its bounded queue is empty.
	for {
		batch, code := manager.Poll(handle, engine.MaxPollEvents)
		if code == engine.StaleGeneration {
			break
		}
		if code != engine.OK || batch["state"] != engine.Stopped {
			t.Fatal(code, batch)
		}
	}
}

// publishedPhases reads the phase of every event in a poll response.
func publishedPhases(t *testing.T, response map[string]any) []string {
	t.Helper()
	encoded, err := json.Marshal(response["events"])
	if err != nil {
		t.Fatalf("re-encoding the events: %v", err)
	}
	var events []struct {
		Phase string `json:"phase"`
	}
	if err := json.Unmarshal(encoded, &events); err != nil {
		t.Fatalf("parsing the events: %v", err)
	}
	phases := make([]string, 0, len(events))
	for _, event := range events {
		phases = append(phases, event.Phase)
	}
	return phases
}

// TestTheFactoryAssemblesAManagerThatIsReadyAndOpensNothing pins that
// assembling is not a side effect: the factory is a value, a manager built from
// it is ready, and a start that is refused because the policy is unusable calls
// no platform callback and leaves no run behind.
func TestTheFactoryAssemblesAManagerThatIsReadyAndOpensNothing(t *testing.T) {
	if Factory() == nil {
		t.Fatal("Factory returned nil")
	}
	manager := engine.NewManager(Factory())
	if !manager.Ready() {
		t.Fatal("a manager with the production factory reports itself unassembled")
	}
	material, _ := captureMaterial(t)
	platform := &platformStub{}
	handle, port, token, code := manager.Start(startConfig(t, "capture-one", `{"schemaVersion":1}`), material, platform)
	if code != engine.InvalidArgument || handle != 0 || port != 0 || token != nil {
		t.Fatalf("a malformed policy started a run: handle %d, port %d, %d-byte token, %v", handle, port, len(token), code)
	}
	if prepared, verified, offers := platform.counts(); prepared != 0 || verified != 0 || offers != 0 {
		t.Fatalf("a refused start called the platform %d/%d/%d times", prepared, verified, offers)
	}
	// The manager is still usable after the refusal: nothing was left half-built,
	// and there is no handle to stop because no run ever began.
	if !manager.Ready() {
		t.Fatal("the manager stopped being ready after a refused start")
	}
}

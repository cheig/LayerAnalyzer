package tlsproxy

import (
	"bytes"
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Fixing the constants here keeps the tests readable and makes an intentional
// budget change a one-line diff.
const (
	extPadding = 0x0015
	extUnknown = 0xfafa
	// grease* are RFC 8701 reserved values: both bytes equal a nibble marker.
	greaseExtension = 0x1a1a
	greaseVersion   = 0x0a0a
	greaseScheme    = 0x3a3a
)

// scriptConn is a transport double. Read hands out exactly the scripted chunks,
// so a test can place a TCP read boundary or a TLS record boundary at any byte
// offset deterministically. It is not a TLS peer: every classification under
// test is made by the real probe over these bytes.
//
// With block set, Read waits for the read deadline and then reports it, which
// is how a silent client (and a server that speaks first) is simulated without
// a real socket.
type scriptConn struct {
	chunks        [][]byte
	index         int
	offset        int
	reads         int
	writes        bytes.Buffer
	readDeadline  time.Time
	block         bool
	closed        bool
	readError     error
	deadlineError error
}

func newScriptConn(chunks ...[]byte) *scriptConn {
	kept := make([][]byte, 0, len(chunks))
	for _, chunk := range chunks {
		if len(chunk) > 0 {
			kept = append(kept, chunk)
		}
	}
	return &scriptConn{chunks: kept}
}

func (c *scriptConn) Read(p []byte) (int, error) {
	c.reads++
	if len(p) == 0 {
		return 0, nil
	}
	if c.readError != nil {
		return 0, c.readError
	}
	if c.index < len(c.chunks) {
		n := copy(p, c.chunks[c.index][c.offset:])
		c.offset += n
		if c.offset >= len(c.chunks[c.index]) {
			c.index++
			c.offset = 0
		}
		return n, nil
	}
	if !c.block {
		return 0, io.EOF
	}
	if !c.readDeadline.IsZero() {
		if wait := time.Until(c.readDeadline); wait > 0 {
			time.Sleep(wait)
		}
	}
	return 0, os.ErrDeadlineExceeded
}

func (c *scriptConn) Write(p []byte) (int, error)      { return c.writes.Write(p) }
func (c *scriptConn) Close() error                     { c.closed = true; return nil }
func (c *scriptConn) LocalAddr() net.Addr              { return scriptAddr("local") }
func (c *scriptConn) RemoteAddr() net.Addr             { return scriptAddr("remote") }
func (c *scriptConn) SetDeadline(time.Time) error      { return nil }
func (c *scriptConn) SetWriteDeadline(time.Time) error { return nil }

func (c *scriptConn) SetReadDeadline(deadline time.Time) error {
	if c.deadlineError != nil {
		return c.deadlineError
	}
	c.readDeadline = deadline
	return nil
}

type scriptAddr string

func (a scriptAddr) Network() string { return "script" }
func (a scriptAddr) String() string  { return string(a) }

// helloBuilder assembles a ClientHello so a crafted case — a split record, a
// contradictory length, a GREASE extension — is written out explicitly by the
// test that needs it.
type helloBuilder struct {
	legacyVersion  uint16
	random         [32]byte
	sessionID      []byte
	cipherSuites   []byte
	compression    []byte
	extensions     [][]byte
	omitExtensions bool
}

// defaultHello is a minimal TLS 1.3-capable ClientHello; each test adds only
// the extension it is about.
func defaultHello() helloBuilder {
	builder := helloBuilder{
		legacyVersion: tls.VersionTLS12,
		cipherSuites:  []byte{0x13, 0x01, 0x13, 0x02},
		compression:   []byte{0x00},
	}
	for index := range builder.random {
		builder.random[index] = byte(index)
	}
	return builder
}

func (b helloBuilder) with(extensions ...[]byte) helloBuilder {
	b.extensions = append(append([][]byte{}, b.extensions...), extensions...)
	return b
}

func (b helloBuilder) body() []byte {
	out := append16(nil, b.legacyVersion)
	out = append(out, b.random[:]...)
	out = append8Vector(out, b.sessionID)
	out = append16Vector(out, b.cipherSuites)
	out = append8Vector(out, b.compression)
	if b.omitExtensions {
		return out
	}
	var extensions []byte
	for _, extension := range b.extensions {
		extensions = append(extensions, extension...)
	}
	return append16Vector(out, extensions)
}

func (b helloBuilder) message() []byte { return handshakeMessage(b.body()) }

// wire frames the hello into TLS records of the given payload sizes; the last
// record takes the remainder, and no sizes at all makes it one record.
func (b helloBuilder) wire(sizes ...int) []byte { return tlsRecords(b.message(), sizes...) }

// handshakeMessage frames a body as a ClientHello handshake message.
func handshakeMessage(body []byte) []byte {
	out := []byte{handshakeTypeClientHello, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}
	return append(out, body...)
}

// helloBodyWith assembles a ClientHello body from parts a test has already
// encoded, so a deliberately contradictory body can be written out byte by
// byte. tail is appended verbatim after the compression list.
func helloBodyWith(prefix, sessionID, cipherSuites, compression, tail []byte) []byte {
	body := append([]byte{}, prefix...)
	body = append8Vector(body, sessionID)
	body = append16Vector(body, cipherSuites)
	body = append8Vector(body, compression)
	return append(body, tail...)
}

func extension(kind uint16, payload []byte) []byte {
	out := append16(nil, kind)
	out = append16Vector(out, payload)
	return out
}

// sniEntry encodes one server name with a chosen name type, so a
// non-host_name entry can be tested.
func sniEntry(nameType byte, name string) []byte {
	out := []byte{nameType}
	return append16Vector(out, []byte(name))
}

func sniList(entries ...[]byte) []byte {
	var list []byte
	for _, entry := range entries {
		list = append(list, entry...)
	}
	return append16Vector(nil, list)
}

func sniExtension(names ...string) []byte {
	entries := make([][]byte, 0, len(names))
	for _, name := range names {
		entries = append(entries, sniEntry(sniHostName, name))
	}
	return extension(extServerName, sniList(entries...))
}

func alpnExtension(names ...string) []byte {
	var list []byte
	for _, name := range names {
		list = append8Vector(list, []byte(name))
	}
	return extension(extALPN, append16Vector(nil, list))
}

func versionsExtension(versions ...uint16) []byte {
	var list []byte
	for _, version := range versions {
		list = append16(list, version)
	}
	return extension(extSupportedVersions, append8Vector(nil, list))
}

func signatureAlgorithmsExtension(schemes ...uint16) []byte {
	var list []byte
	for _, scheme := range schemes {
		list = append16(list, scheme)
	}
	return extension(extSignatureAlgorithms, append16Vector(nil, list))
}

func append16(dst []byte, value uint16) []byte {
	return append(dst, byte(value>>8), byte(value))
}

func append8Vector(dst, payload []byte) []byte {
	return append(append(dst, byte(len(payload))), payload...)
}

func append16Vector(dst, payload []byte) []byte {
	return append(append16(dst, uint16(len(payload))), payload...)
}

// tlsRecords frames a handshake byte stream into TLS handshake records.
func tlsRecords(message []byte, sizes ...int) []byte {
	var out []byte
	for len(message) > 0 {
		size := len(message)
		if len(sizes) > 0 {
			size = sizes[0]
			sizes = sizes[1:]
			if size <= 0 || size > len(message) {
				size = len(message)
			}
		}
		out = append(out, recordTypeHandshake, 0x03, 0x03, byte(size>>8), byte(size))
		out = append(out, message[:size]...)
		message = message[size:]
	}
	return out
}

func applicationRecord(payload []byte) []byte {
	out := []byte{0x17, 0x03, 0x03, byte(len(payload) >> 8), byte(len(payload))}
	return append(out, payload...)
}

// countRecords counts the records of a well-formed record stream.
func countRecords(stream []byte) int {
	count := 0
	for len(stream) >= recordHeaderLength {
		size := int(stream[3])<<8 | int(stream[4])
		if len(stream) < recordHeaderLength+size {
			break
		}
		count++
		stream = stream[recordHeaderLength+size:]
	}
	return count
}

func probeWithLimits(t *testing.T, limits Limits, chunks ...[]byte) Outcome {
	t.Helper()
	return ProbeClientHello(newScriptConn(chunks...), limits)
}

// probeWith runs one probe with the default budget. Every byte the probe leaves
// behind — its prefix plus whatever the transport still holds — is asserted to
// be the scripted stream exactly, because a classifier that drops a pre-read
// byte corrupts the connection it was asked to preserve.
func probeWith(t *testing.T, chunks ...[]byte) Outcome {
	t.Helper()
	conn := newScriptConn(chunks...)
	outcome := ProbeClientHello(conn, Limits{})
	if outcome.Conn == nil {
		t.Fatal("probe returned no replay connection")
	}
	expected := bytes.Join(chunks, nil)
	if replayed := replay(t, outcome); !bytes.Equal(replayed, expected) {
		t.Fatalf("prefix replay lost bytes: got %d bytes %x, want %d bytes %x",
			len(replayed), replayed, len(expected), expected)
	}
	if outcome.Bytes > MaxProbePrefix {
		t.Fatalf("probe consumed %d bytes, above the %d byte budget", outcome.Bytes, MaxProbePrefix)
	}
	if (outcome.Verdict == VerdictClientHello) != (outcome.Reason == "") {
		t.Fatalf("verdict %s carries reason %q", outcome.Verdict, outcome.Reason)
	}
	return outcome
}

// replay reads everything the probe did not consume out of the replay
// connection: the bytes it read, followed by the bytes still on the transport.
// It needs a transport with more to give, so tests that script a silent
// connection use prefixBytes instead.
func replay(t *testing.T, outcome Outcome) []byte {
	t.Helper()
	data, err := io.ReadAll(outcome.Conn)
	if err != nil {
		t.Fatalf("replaying probe prefix: %v", err)
	}
	return data
}

// prefixBytes reads back exactly the bytes the probe consumed, without waiting
// on a transport that has nothing more to give.
func prefixBytes(t *testing.T, outcome Outcome) []byte {
	t.Helper()
	data := make([]byte, outcome.Bytes)
	if _, err := io.ReadFull(outcome.Conn, data); err != nil {
		t.Fatalf("reading back %d prefix bytes: %v", outcome.Bytes, err)
	}
	return data
}

// realClientHello captures the ClientHello a real crypto/tls client sends, so
// the classifier is also exercised against bytes no test authored. The
// handshake itself never completes: nothing replies.
func realClientHello(t *testing.T, config *tls.Config) []byte {
	t.Helper()
	clientEnd, serverEnd := net.Pipe()
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = tls.Client(clientEnd, config).Handshake()
	}()
	t.Cleanup(func() {
		clientEnd.Close()
		serverEnd.Close()
		<-done
	})

	scanner := &scanner{}
	buffer := make([]byte, 1024)
	if err := serverEnd.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
		t.Fatalf("setting capture deadline: %v", err)
	}
	var hello []byte
	for {
		switch scanner.advance(hello) {
		case scanComplete:
			return hello
		case scanFailed:
			t.Fatalf("captured client hello failed to scan: %s", scanner.reason)
		}
		n, err := serverEnd.Read(buffer)
		if n > 0 {
			hello = append(hello, buffer[:n]...)
		}
		if err != nil {
			t.Fatalf("capturing client hello: %v", err)
		}
	}
}

func TestProbeRealClientHello(t *testing.T) {
	stream := realClientHello(t, &tls.Config{
		ServerName: "example.test",
		NextProtos: []string{"h2", "http/1.1"},
		MinVersion: tls.VersionTLS12,
	})

	outcome := probeWith(t, stream)
	if outcome.Verdict != VerdictClientHello {
		t.Fatalf("real client hello classified as %s (%s)", outcome.Verdict, outcome.Reason)
	}
	if outcome.Bytes != len(stream) {
		t.Fatalf("probe consumed %d of %d bytes", outcome.Bytes, len(stream))
	}
	hello := outcome.Hello
	if hello.SNI != "example.test" {
		t.Fatalf("SNI = %q, want example.test", hello.SNI)
	}
	if !reflect.DeepEqual(hello.ALPN, []string{"h2", "http/1.1"}) {
		t.Fatalf("ALPN = %v, want [h2 http/1.1]", hello.ALPN)
	}
	if !hello.SupportedVersionsPresent || !containsVersion(hello.SupportedVersions, tls.VersionTLS13) {
		t.Fatalf("supported versions = %v (present %v), want TLS 1.3 offered",
			hello.SupportedVersions, hello.SupportedVersionsPresent)
	}
	if !containsScheme(hello.SignatureAlgorithms, tls.ECDSAWithP256AndSHA256) {
		t.Fatalf("signature algorithms = %v, want ecdsa_secp256r1_sha256", hello.SignatureAlgorithms)
	}
	// The client random must be read from the hello's own offset: it is the key
	// every downstream keylog entry is written against.
	if firstRecord := int(stream[3])<<8 | int(stream[4]); firstRecord >= handshakeHeaderLength+2+32 {
		want := stream[recordHeaderLength+handshakeHeaderLength+2:][:32]
		if !bytes.Equal(hello.ClientRandom[:], want) {
			t.Fatalf("client random %x is not the hello's random %x", hello.ClientRandom, want)
		}
	} else if hello.ClientRandom == ([32]byte{}) {
		t.Fatal("client random is all zeroes")
	}
	if hello.ECHOffered {
		t.Fatal("a Go client hello does not offer ECH")
	}
	if hello.Records != countRecords(stream) {
		t.Fatalf("records = %d, want %d", hello.Records, countRecords(stream))
	}
}

func TestProbeTLS12ClientHelloWithoutSupportedVersions(t *testing.T) {
	stream := realClientHello(t, &tls.Config{
		ServerName: "example.test",
		MinVersion: tls.VersionTLS12,
		MaxVersion: tls.VersionTLS12,
	})
	outcome := probeWith(t, stream)
	if outcome.Verdict != VerdictClientHello {
		t.Fatalf("TLS 1.2 hello classified as %s (%s)", outcome.Verdict, outcome.Reason)
	}
	if outcome.Hello.LegacyVersion != tls.VersionTLS12 {
		t.Fatalf("legacy version = %#x, want TLS 1.2", outcome.Hello.LegacyVersion)
	}
}

// TestProbeEverySplitPosition replays the same hello with a read boundary at
// every byte offset, in one record and across several records: a ClientHello is
// recognised from any fragmentation of the stream, and every byte is preserved
// whatever the split.
func TestProbeEverySplitPosition(t *testing.T) {
	streams := map[string][]byte{
		"one record": defaultHello().with(
			sniExtension("example.test"),
			alpnExtension("h2", "http/1.1"),
			versionsExtension(greaseVersion, tls.VersionTLS13, tls.VersionTLS12),
			signatureAlgorithmsExtension(greaseScheme, uint16(tls.ECDSAWithP256AndSHA256)),
		).wire(),
		"records of 3, 2, 1 and the rest": defaultHello().with(
			sniExtension("example.test"),
		).wire(3, 2, 1),
	}
	for name, stream := range streams {
		t.Run(name, func(t *testing.T) {
			want := probeWith(t, stream)
			if want.Verdict != VerdictClientHello {
				t.Fatalf("unsplit hello classified as %s (%s)", want.Verdict, want.Reason)
			}
			for split := 1; split < len(stream); split++ {
				outcome := probeWith(t, stream[:split], stream[split:])
				if outcome.Verdict != want.Verdict || outcome.Reason != want.Reason {
					t.Fatalf("split at %d: verdict %s/%s, want %s/%s",
						split, outcome.Verdict, outcome.Reason, want.Verdict, want.Reason)
				}
				if !reflect.DeepEqual(outcome.Hello, want.Hello) {
					t.Fatalf("split at %d: hello %+v, want %+v", split, outcome.Hello, want.Hello)
				}
			}
		})
	}
}

// TestProbeReadsSeveralRecordsAtOnce is the other half of fragmentation: one
// Read may carry the whole record sequence, and each record must be stepped
// over by its own header rather than by how the transport happened to flush.
func TestProbeReadsSeveralRecordsAtOnce(t *testing.T) {
	stream := defaultHello().with(sniExtension("example.test")).wire(1, 1, 1, 1)
	wantRecords := countRecords(stream)
	if wantRecords < 5 {
		t.Fatalf("test needs a multi-record stream, got %d records", wantRecords)
	}
	conn := newScriptConn(stream)
	outcome := ProbeClientHello(conn, Limits{})
	if outcome.Verdict != VerdictClientHello {
		t.Fatalf("multi-record hello classified as %s (%s)", outcome.Verdict, outcome.Reason)
	}
	if outcome.Hello.SNI != "example.test" {
		t.Fatalf("SNI = %q, want example.test", outcome.Hello.SNI)
	}
	if outcome.Hello.Records != wantRecords {
		t.Fatalf("records = %d, want %d", outcome.Hello.Records, wantRecords)
	}
	if conn.reads != 1 {
		t.Fatalf("probe needed %d reads for a stream delivered in one", conn.reads)
	}
}

// TestProbeStopsAtTheClientHello: the client waits for the server before it
// sends a request, so the probe must return as soon as the hello is complete
// instead of waiting for bytes that are not coming.
func TestProbeStopsAtTheClientHello(t *testing.T) {
	hello := defaultHello().with(sniExtension("example.test")).message()
	request := []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n")
	stream := append(tlsRecords(hello), applicationRecord(request)...)

	conn := newScriptConn(stream)
	conn.block = true
	outcome := ProbeClientHello(conn, Limits{Timeout: 50 * time.Millisecond})
	if outcome.Verdict != VerdictClientHello {
		t.Fatalf("hello with a pipelined request classified as %s (%s)", outcome.Verdict, outcome.Reason)
	}
	if conn.reads != 1 {
		t.Fatalf("probe read %d times, want 1: it waited past the hello", conn.reads)
	}
	if outcome.Bytes != len(stream) {
		t.Fatalf("probe consumed %d bytes, want the whole %d", outcome.Bytes, len(stream))
	}
	if got := prefixBytes(t, outcome); !bytes.Equal(got, stream) {
		t.Fatalf("replay = %x, want %x: application bytes after the hello were lost", got, stream)
	}
}

func TestProbeHelloWithoutSNI(t *testing.T) {
	stream := defaultHello().with(alpnExtension("h2")).wire()
	outcome := probeWith(t, stream)
	// The verdict is about the offer, not about the policy: TLS-208 decides
	// that a connection with no name is not intercepted.
	if outcome.Verdict != VerdictClientHello {
		t.Fatalf("hello without SNI classified as %s (%s)", outcome.Verdict, outcome.Reason)
	}
	if outcome.Hello.SNI != "" {
		t.Fatalf("SNI = %q, want empty", outcome.Hello.SNI)
	}
}

func TestProbeSNIValues(t *testing.T) {
	cases := []struct {
		name string
		list []byte
		want string
	}{
		{"host name", sniList(sniEntry(sniHostName, "example.test")), "example.test"},
		{"case is preserved verbatim", sniList(sniEntry(sniHostName, "Example.Test")), "Example.Test"},
		{"the first host name wins", sniList(sniEntry(sniHostName, "first.test"), sniEntry(sniHostName, "second.test")), "first.test"},
		{"other name types are skipped", sniList(sniEntry(0x02, "ignored")), ""},
		{"a host name after another type", sniList(sniEntry(0x02, "ignored"), sniEntry(sniHostName, "chosen.test")), "chosen.test"},
		{"a name with a space is not usable", sniList(sniEntry(sniHostName, "bad name.test")), ""},
		{"an empty name is not usable", sniList(sniEntry(sniHostName, "")), ""},
		{"a name longer than a host name can be", sniList(sniEntry(sniHostName, strings.Repeat("a", 254))), ""},
		{"a bare label is usable", sniList(sniEntry(sniHostName, "localhost")), "localhost"},
		{"an IP literal is kept as sent", sniList(sniEntry(sniHostName, "192.0.2.10")), "192.0.2.10"},
		{"a malformed list drops the extension", []byte{0xff, 0x00, 0x00}, ""},
		{"an empty extension drops nothing", nil, ""},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outcome := probeWith(t, defaultHello().with(extension(extServerName, test.list)).wire())
			if outcome.Verdict != VerdictClientHello {
				t.Fatalf("classified as %s (%s)", outcome.Verdict, outcome.Reason)
			}
			if outcome.Hello.SNI != test.want {
				t.Fatalf("SNI = %q, want %q", outcome.Hello.SNI, test.want)
			}
		})
	}
}

func TestProbeALPNValues(t *testing.T) {
	cases := []struct {
		name string
		ext  []byte
		want []string
	}{
		{"protocols in offer order", alpnExtension("h2", "http/1.1"), []string{"h2", "http/1.1"}},
		{"GREASE protocol id is dropped", alpnExtension("\x0a\x0a", "h2"), []string{"h2"}},
		{"empty list", extension(extALPN, append16Vector(nil, nil)), nil},
		{"a malformed list drops the extension", extension(extALPN, []byte{0xff, 0x00}), nil},
		{"a zero-length protocol drops the extension", extension(extALPN, append16Vector(nil, []byte{0x00})), nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outcome := probeWith(t, defaultHello().with(test.ext).wire())
			if outcome.Verdict != VerdictClientHello {
				t.Fatalf("classified as %s (%s)", outcome.Verdict, outcome.Reason)
			}
			if !reflect.DeepEqual(outcome.Hello.ALPN, test.want) {
				t.Fatalf("ALPN = %v, want %v", outcome.Hello.ALPN, test.want)
			}
		})
	}
}

func TestProbeSupportedVersions(t *testing.T) {
	cases := []struct {
		name    string
		hello   helloBuilder
		verdict Verdict
		reason  string
		want    []uint16
		present bool
	}{
		{
			name:    "TLS 1.3 and 1.2 offered",
			hello:   defaultHello().with(versionsExtension(greaseVersion, tls.VersionTLS13, tls.VersionTLS12)),
			verdict: VerdictClientHello,
			want:    []uint16{tls.VersionTLS13, tls.VersionTLS12},
			present: true,
		},
		{
			name:    "only TLS 1.2 offered",
			hello:   defaultHello().with(versionsExtension(tls.VersionTLS12)),
			verdict: VerdictClientHello,
			want:    []uint16{tls.VersionTLS12},
			present: true,
		},
		{
			name:    "only TLS 1.0 offered",
			hello:   defaultHello().with(versionsExtension(tls.VersionTLS10)),
			verdict: VerdictUnsupported,
			reason:  reasonNoVersion,
			want:    []uint16{tls.VersionTLS10},
			present: true,
		},
		{
			name:    "only GREASE offered",
			hello:   defaultHello().with(versionsExtension(greaseVersion)),
			verdict: VerdictUnsupported,
			reason:  reasonNoVersion,
			present: true,
		},
		{
			name:    "TLS 1.0 client without the extension",
			hello:   helloBuilder{legacyVersion: tls.VersionTLS10, cipherSuites: []byte{0x00, 0x2f}, compression: []byte{0x00}, omitExtensions: true},
			verdict: VerdictUnsupported,
			reason:  reasonNoVersion,
		},
		{
			name:    "legacy version is the offer when the extension is absent",
			hello:   helloBuilder{legacyVersion: tls.VersionTLS12, cipherSuites: []byte{0x00, 0x2f}, compression: []byte{0x00}, omitExtensions: true},
			verdict: VerdictClientHello,
		},
		{
			name:    "a malformed extension leaves the legacy version in charge",
			hello:   defaultHello().with(extension(extSupportedVersions, []byte{0x03, 0x03, 0x03})),
			verdict: VerdictClientHello,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outcome := probeWith(t, test.hello.wire())
			if outcome.Verdict != test.verdict || outcome.Reason != test.reason {
				t.Fatalf("verdict %s/%s, want %s/%s", outcome.Verdict, outcome.Reason, test.verdict, test.reason)
			}
			if outcome.Hello.SupportedVersionsPresent != test.present {
				t.Fatalf("SupportedVersionsPresent = %v, want %v", outcome.Hello.SupportedVersionsPresent, test.present)
			}
			if !reflect.DeepEqual(outcome.Hello.SupportedVersions, test.want) {
				t.Fatalf("supported versions = %v, want %v", outcome.Hello.SupportedVersions, test.want)
			}
		})
	}
}

func TestProbeSignatureAlgorithms(t *testing.T) {
	stream := defaultHello().with(signatureAlgorithmsExtension(
		greaseScheme, uint16(tls.ECDSAWithP256AndSHA256), uint16(tls.PSSWithSHA256),
	)).wire()
	outcome := probeWith(t, stream)
	if outcome.Verdict != VerdictClientHello {
		t.Fatalf("classified as %s (%s)", outcome.Verdict, outcome.Reason)
	}
	want := []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256, tls.PSSWithSHA256}
	if !reflect.DeepEqual(outcome.Hello.SignatureAlgorithms, want) {
		t.Fatalf("signature algorithms = %v, want %v", outcome.Hello.SignatureAlgorithms, want)
	}
}

// TestProbeECHIsACandidateSignalOnly: the extension's presence is recorded, but
// it does not make the outer name the confirmed site. The inner name is not
// readable from a ClientHello, so nothing here may claim it.
func TestProbeECHIsACandidateSignalOnly(t *testing.T) {
	ech := extension(extEncryptedClientHello, []byte{0xfe, 0x0d, 0x00, 0x20, 0x01, 0x00, 0x01, 0x00})
	outcome := probeWith(t, defaultHello().with(ech, sniExtension("public.example")).wire())
	if outcome.Verdict != VerdictClientHello {
		t.Fatalf("classified as %s (%s)", outcome.Verdict, outcome.Reason)
	}
	if !outcome.Hello.ECHOffered {
		t.Fatal("ECHOffered = false for a hello carrying the ECH extension")
	}
	if outcome.Hello.SNI != "public.example" {
		t.Fatalf("SNI = %q, want the outer name as sent", outcome.Hello.SNI)
	}
}

// TestProbeSkipsUnknownExtensions covers the rule that TLS cannot be recognised
// from a leading 0x16: an otherwise valid hello carrying GREASE and unknown
// extensions is served, while a record whose handshake type is not ClientHello
// is reported as an unsupported TLS stream.
func TestProbeSkipsUnknownExtensions(t *testing.T) {
	outcome := probeWith(t, defaultHello().with(
		extension(greaseExtension, []byte{0x00}),
		extension(extUnknown, []byte{0x01, 0x02, 0x03}),
		extension(extPadding, nil),
		sniExtension("example.test"),
	).wire())
	if outcome.Verdict != VerdictClientHello {
		t.Fatalf("classified as %s (%s)", outcome.Verdict, outcome.Reason)
	}
	if outcome.Hello.SNI != "example.test" {
		t.Fatalf("SNI = %q, want example.test", outcome.Hello.SNI)
	}

	serverHello := tlsRecords([]byte{0x02, 0x00, 0x00, 0x02, 0x03, 0x03})
	outcome = probeWith(t, serverHello)
	if outcome.Verdict != VerdictUnsupported || outcome.Reason != reasonHandshakeType {
		t.Fatalf("verdict %s/%s, want unsupported/%s", outcome.Verdict, outcome.Reason, reasonHandshakeType)
	}
}

func TestProbeVerdictsForBrokenStreams(t *testing.T) {
	valid := defaultHello().with(sniExtension("example.test")).message()
	prefix := append(append16(nil, tls.VersionTLS12), bytes.Repeat([]byte{0xaa}, 32)...)
	suites := []byte{0x13, 0x01, 0x00, 0x2f}
	compression := []byte{0x00}

	cases := []struct {
		name    string
		stream  []byte
		verdict Verdict
		reason  string
	}{
		{
			name:    "HTTP request",
			stream:  []byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"),
			verdict: VerdictNotTLS,
			reason:  reasonNotHandshakeRecord,
		},
		{
			name:    "application data first",
			stream:  applicationRecord([]byte("early bytes")),
			verdict: VerdictNotTLS,
			reason:  reasonNotHandshakeRecord,
		},
		{
			name:    "change cipher spec first",
			stream:  []byte{0x14, 0x03, 0x03, 0x00, 0x01, 0x01},
			verdict: VerdictNotTLS,
			reason:  reasonNotHandshakeRecord,
		},
		{
			name:    "SSLv2 style record version",
			stream:  append([]byte{recordTypeHandshake, 0x02, 0x00}, valid...),
			verdict: VerdictNotTLS,
			reason:  reasonBadRecordVersion,
		},
		{
			name:    "record wider than the record layer allows",
			stream:  []byte{recordTypeHandshake, 0x03, 0x03, 0xff, 0xff, 0x00},
			verdict: VerdictNotTLS,
			reason:  reasonBadRecordLength,
		},
		{
			name:    "handshake body shorter than a hello",
			stream:  tlsRecords([]byte{handshakeTypeClientHello, 0x00, 0x00, 0x10, 0x03, 0x03}),
			verdict: VerdictNotTLS,
			reason:  reasonMalformedHello,
		},
		{
			name:    "handshake type is not ClientHello",
			stream:  tlsRecords([]byte{0x04, 0x00, 0x00, 0x02, 0x00, 0x00}),
			verdict: VerdictUnsupported,
			reason:  reasonHandshakeType,
		},
		{
			name:    "session id longer than the body",
			stream:  tlsRecords(handshakeMessage(append(append([]byte{}, prefix...), 0x40, 0x00, 0x00, 0x00, 0x00, 0x00))),
			verdict: VerdictNotTLS,
			reason:  reasonMalformedHello,
		},
		{
			name:    "cipher suite list with an odd length",
			stream:  tlsRecords(handshakeMessage(helloBodyWith(prefix, nil, []byte{0x13, 0x01, 0x00}, compression, nil))),
			verdict: VerdictNotTLS,
			reason:  reasonMalformedHello,
		},
		{
			name:    "no compression methods",
			stream:  tlsRecords(handshakeMessage(helloBodyWith(prefix, nil, suites, nil, nil))),
			verdict: VerdictNotTLS,
			reason:  reasonMalformedHello,
		},
		{
			name:    "extension block longer than the body",
			stream:  tlsRecords(handshakeMessage(helloBodyWith(prefix, nil, suites, compression, []byte{0x00, 0x40, 0x00, 0x00}))),
			verdict: VerdictNotTLS,
			reason:  reasonMalformedHello,
		},
		{
			name: "bytes after the extension block",
			stream: tlsRecords(handshakeMessage(helloBodyWith(prefix, nil, suites, compression,
				[]byte{0x00, 0x04, 0x00, 0x15, 0x00, 0x00, 0xde, 0xad}))),
			verdict: VerdictNotTLS,
			reason:  reasonMalformedHello,
		},
		{
			name:    "extension count above the structural cap",
			stream:  tlsRecords(handshakeMessage(bigExtensionHello(maxHelloExtensions + 1))),
			verdict: VerdictUnsupported,
			reason:  reasonTooManyEntries,
		},
		{
			name:    "ALPN list above the structural cap",
			stream:  tlsRecords(handshakeMessage(bigALPNHello(maxALPNProtocols + 1))),
			verdict: VerdictUnsupported,
			reason:  reasonTooManyEntries,
		},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outcome := probeWith(t, test.stream)
			if outcome.Verdict != test.verdict || outcome.Reason != test.reason {
				t.Fatalf("verdict %s/%s, want %s/%s", outcome.Verdict, outcome.Reason, test.verdict, test.reason)
			}
			if outcome.Bytes != len(test.stream) {
				t.Fatalf("probe consumed %d of %d bytes", outcome.Bytes, len(test.stream))
			}
		})
	}
}

// bigExtensionHello carries count padding extensions.
func bigExtensionHello(count int) []byte {
	builder := defaultHello()
	for index := 0; index < count; index++ {
		builder = builder.with(extension(extPadding, nil))
	}
	return builder.body()
}

// bigALPNHello offers count protocols, which no real client does.
func bigALPNHello(count int) []byte {
	names := make([]string, 0, count)
	for index := 0; index < count; index++ {
		names = append(names, "proto"+string(rune('a'+index%26)))
	}
	return defaultHello().with(alpnExtension(names...)).body()
}

// TestProbeAbandonsAnOversizedDeclaration: a hello that announces a 16 MiB body
// must be dropped on its declared length, before any of it is read or
// allocated.
func TestProbeAbandonsAnOversizedDeclaration(t *testing.T) {
	stream := tlsRecords([]byte{handshakeTypeClientHello, 0xff, 0xff, 0xff})
	conn := newScriptConn(stream)
	conn.block = true
	outcome := ProbeClientHello(conn, Limits{Timeout: 50 * time.Millisecond})
	if outcome.Verdict != VerdictIncomplete || outcome.Reason != reasonBudget {
		t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, reasonBudget)
	}
	if conn.reads != 1 {
		t.Fatalf("probe read %d times after an oversized declaration", conn.reads)
	}
	if outcome.Bytes != len(stream) {
		t.Fatalf("probe consumed %d bytes, want %d", outcome.Bytes, len(stream))
	}
	if got := prefixBytes(t, outcome); !bytes.Equal(got, stream) {
		t.Fatalf("replay = %x, want %x", got, stream)
	}
}

// TestProbeStopsAtThePrefixBudget covers the two ways a stream can outgrow the
// budget: a hello whose declared body exceeds it, and a stream of empty records
// that never declares anything at all. Neither may loop or allocate without
// bound.
func TestProbeStopsAtThePrefixBudget(t *testing.T) {
	t.Run("declared body exceeds the budget", func(t *testing.T) {
		padding := bytes.Repeat([]byte{0x00}, 40000)
		stream := defaultHello().with(extension(extPadding, padding), extension(extPadding, padding)).wire()
		if len(stream) <= MaxProbePrefix {
			t.Fatalf("test stream is %d bytes, not above the %d byte budget", len(stream), MaxProbePrefix)
		}
		outcome := probeWith(t, stream)
		if outcome.Verdict != VerdictIncomplete || outcome.Reason != reasonBudget {
			t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, reasonBudget)
		}
		if outcome.Bytes >= len(stream) {
			t.Fatalf("probe read the whole %d byte stream instead of stopping", len(stream))
		}
	})

	t.Run("endless empty records", func(t *testing.T) {
		empty := []byte{recordTypeHandshake, 0x03, 0x03, 0x00, 0x00}
		stream := bytes.Repeat(empty, MaxProbePrefix/len(empty)+64)
		conn := newScriptConn(stream)
		outcome := ProbeClientHello(conn, Limits{})
		if outcome.Verdict != VerdictIncomplete || outcome.Reason != reasonBudget {
			t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, reasonBudget)
		}
		if outcome.Bytes > MaxProbePrefix {
			t.Fatalf("probe consumed %d bytes, above the %d byte budget", outcome.Bytes, MaxProbePrefix)
		}
		// One read per chunk of the budget, so the scan stayed linear.
		if conn.reads > MaxProbePrefix/probeReadChunk+1 {
			t.Fatalf("probe needed %d reads for an empty-record stream", conn.reads)
		}
		if got := replay(t, outcome); !bytes.Equal(got, stream) {
			t.Fatalf("replay lost bytes over a %d byte stream", len(stream))
		}
	})
}

// TestProbeTimesOutOnASilentStream is the "the server speaks first" case: a
// protocol where the client waits for a banner looks exactly like this, and it
// must be handed back for passthrough after the probe deadline.
func TestProbeTimesOutOnASilentStream(t *testing.T) {
	t.Run("client says nothing", func(t *testing.T) {
		conn := newScriptConn()
		conn.block = true
		start := time.Now()
		outcome := ProbeClientHello(conn, Limits{Timeout: 40 * time.Millisecond})
		elapsed := time.Since(start)
		if outcome.Verdict != VerdictIncomplete || outcome.Reason != reasonTimeout {
			t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, reasonTimeout)
		}
		if outcome.Bytes != 0 {
			t.Fatalf("probe consumed %d bytes from a silent client", outcome.Bytes)
		}
		if elapsed > 2*time.Second {
			t.Fatalf("probe took %s to give up", elapsed)
		}
	})

	t.Run("client stops mid-hello", func(t *testing.T) {
		partial := tlsRecords(defaultHello().with(sniExtension("example.test")).message())[:12]
		conn := newScriptConn(partial)
		conn.block = true
		outcome := ProbeClientHello(conn, Limits{Timeout: 40 * time.Millisecond})
		if outcome.Verdict != VerdictIncomplete || outcome.Reason != reasonTimeout {
			t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, reasonTimeout)
		}
		if outcome.Bytes != len(partial) {
			t.Fatalf("probe consumed %d bytes, want %d", outcome.Bytes, len(partial))
		}
		if got := prefixBytes(t, outcome); !bytes.Equal(got, partial) {
			t.Fatalf("replay = %x, want %x", got, partial)
		}
	})
}

func TestProbeIncompleteStreams(t *testing.T) {
	hello := defaultHello().with(sniExtension("example.test")).message()
	partial := tlsRecords(hello)[:20]

	cases := []struct {
		name   string
		conn   *scriptConn
		reason string
		want   []byte
	}{
		{"stream ends mid-hello", newScriptConn(partial), reasonEndOfStream, partial},
		{"stream is empty", newScriptConn(), reasonEndOfStream, nil},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			outcome := ProbeClientHello(test.conn, Limits{Timeout: time.Second})
			if outcome.Verdict != VerdictIncomplete || outcome.Reason != test.reason {
				t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, test.reason)
			}
			if got := replay(t, outcome); !bytes.Equal(got, test.want) {
				t.Fatalf("replay = %x, want %x", got, test.want)
			}
		})
	}

	t.Run("transport read error", func(t *testing.T) {
		conn := newScriptConn(partial)
		conn.readError = errors.New("connection reset by peer")
		outcome := ProbeClientHello(conn, Limits{Timeout: time.Second})
		if outcome.Verdict != VerdictIncomplete || outcome.Reason != reasonReadError {
			t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, reasonReadError)
		}
	})

	// A transport that cannot hold a deadline cannot be probed in bounded time,
	// so it is handed back untouched rather than read from.
	t.Run("transport cannot hold a deadline", func(t *testing.T) {
		conn := newScriptConn(partial)
		conn.deadlineError = errors.New("deadlines unsupported")
		outcome := ProbeClientHello(conn, Limits{Timeout: time.Second})
		if outcome.Verdict != VerdictIncomplete || outcome.Reason != reasonReadError {
			t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, reasonReadError)
		}
		if conn.reads != 0 {
			t.Fatalf("probe read %d times without a deadline", conn.reads)
		}
		if got := replay(t, outcome); !bytes.Equal(got, partial) {
			t.Fatalf("replay = %x, want %x", got, partial)
		}
	})

	t.Run("no connection at all", func(t *testing.T) {
		outcome := ProbeClientHello(nil, Limits{})
		if outcome.Verdict != VerdictIncomplete || outcome.Reason != reasonReadError {
			t.Fatalf("verdict %s/%s, want incomplete/%s", outcome.Verdict, outcome.Reason, reasonReadError)
		}
		if _, err := outcome.Conn.Read(make([]byte, 8)); !errors.Is(err, io.ErrClosedPipe) {
			t.Fatalf("read from an unbacked replay connection: %v", err)
		}
	})
}

// TestProbeClearsItsDeadline: the probe's 3-second budget must not survive as
// the deadline of the handshake that follows it.
func TestProbeClearsItsDeadline(t *testing.T) {
	stream := defaultHello().with(sniExtension("example.test")).wire()
	conn := newScriptConn(stream)
	ProbeClientHello(conn, Limits{Timeout: 40 * time.Millisecond})
	if !conn.readDeadline.IsZero() {
		t.Fatalf("probe left read deadline %s on the connection", conn.readDeadline)
	}
}

func TestProbeLimitsNormalization(t *testing.T) {
	cases := []struct {
		name  string
		given Limits
		want  Limits
	}{
		{"zero value takes both defaults", Limits{}, Limits{DefaultProbePrefix, DefaultProbeTimeout}},
		{"negative values take both defaults", Limits{-1, -time.Second}, Limits{DefaultProbePrefix, DefaultProbeTimeout}},
		{"above the ceiling is not a way to raise the budget", Limits{MaxProbePrefix + 1, time.Minute},
			Limits{DefaultProbePrefix, time.Minute}},
		{"a smaller budget is honoured", Limits{1024, 250 * time.Millisecond}, Limits{1024, 250 * time.Millisecond}},
	}
	for _, test := range cases {
		t.Run(test.name, func(t *testing.T) {
			if got := test.given.normalize(); got != test.want {
				t.Fatalf("normalize(%+v) = %+v, want %+v", test.given, got, test.want)
			}
		})
	}
}

func TestVerdictString(t *testing.T) {
	cases := map[Verdict]string{
		VerdictClientHello: "client_hello",
		VerdictNotTLS:      "not_tls",
		VerdictUnsupported: "unsupported",
		VerdictIncomplete:  "incomplete",
		Verdict(99):        "invalid",
	}
	for verdict, want := range cases {
		if got := verdict.String(); got != want {
			t.Fatalf("Verdict(%d).String() = %q, want %q", int(verdict), got, want)
		}
	}
}

func containsVersion(versions []uint16, want uint16) bool {
	for _, version := range versions {
		if version == want {
			return true
		}
	}
	return false
}

func containsScheme(schemes []tls.SignatureScheme, want tls.SignatureScheme) bool {
	for _, scheme := range schemes {
		if scheme == want {
			return true
		}
	}
	return false
}

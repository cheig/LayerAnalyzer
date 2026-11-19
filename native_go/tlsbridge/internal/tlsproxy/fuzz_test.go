package tlsproxy

import (
	"bytes"
	"crypto/tls"
	"io"
	"testing"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// FuzzProbeClientHello checks the property the whole card rests on: whatever
// the bytes are and however the transport chunks them, the probe neither panics
// nor loses one. The seed corpus in testdata/fuzz holds record streams that are
// well formed, split across records, truncated and fabricated.
func FuzzProbeClientHello(f *testing.F) {
	seed := defaultHello().with(
		sniExtension("example.test"),
		alpnExtension("h2", "http/1.1"),
		versionsExtension(greaseVersion, tls.VersionTLS13, tls.VersionTLS12),
		signatureAlgorithmsExtension(greaseScheme, uint16(tls.ECDSAWithP256AndSHA256)),
	)
	f.Add(seed.wire(), byte(1))
	f.Add(seed.wire(1, 1, 1), byte(5))
	f.Add(seed.wire(), byte(0))
	f.Add(append(seed.wire(), applicationRecord([]byte("GET / HTTP/1.1\r\n\r\n"))...), byte(9))
	f.Add(tlsRecords([]byte{handshakeTypeClientHello, 0xff, 0xff, 0xff}), byte(0))
	f.Add(tlsRecords([]byte{handshakeTypeClientHello, 0x00, 0x00, 0x10, 0x03, 0x03}), byte(2))
	f.Add([]byte("GET / HTTP/1.1\r\nHost: example.test\r\n\r\n"), byte(3))
	f.Add(helloBodyWith(bytes.Repeat([]byte{0x03, 0x03}, 1), nil, nil, nil, nil), byte(0))

	f.Fuzz(func(t *testing.T, data []byte, split byte) {
		// Bound the input so a fuzz run stays a bounded test of the probe's own
		// limits rather than a test of io.ReadAll.
		if len(data) > 2*MaxProbePrefix {
			return
		}
		conn := newScriptConn(chunkBy(data, split)...)
		outcome := ProbeClientHello(conn, Limits{})
		if outcome.Conn == nil {
			t.Fatal("probe returned no replay connection")
		}
		if outcome.Bytes > MaxProbePrefix {
			t.Fatalf("probe consumed %d bytes, above the %d byte budget", outcome.Bytes, MaxProbePrefix)
		}
		if (outcome.Verdict == VerdictClientHello) != (outcome.Reason == "") {
			t.Fatalf("verdict %s carries reason %q", outcome.Verdict, outcome.Reason)
		}
		replayed, err := io.ReadAll(outcome.Conn)
		if err != nil {
			t.Fatalf("replaying the probe prefix: %v", err)
		}
		if !bytes.Equal(replayed, data) {
			t.Fatalf("replay of %d bytes differs from the %d byte input (%d bytes returned)",
				len(replayed), len(data), len(replayed))
		}
	})
}

// FuzzParseClientHello checks the body parser directly, where an arbitrary body
// reaches the length-driven readers inside the extensions.
func FuzzParseClientHello(f *testing.F) {
	f.Add(defaultHello().with(
		sniExtension("example.test"),
		alpnExtension("h2", "http/1.1"),
		versionsExtension(tls.VersionTLS13, tls.VersionTLS12),
		signatureAlgorithmsExtension(uint16(tls.ECDSAWithP256AndSHA256)),
		extension(extEncryptedClientHello, []byte{0xfe, 0x0d, 0x00, 0x04, 0x01, 0x00, 0x01, 0x00}),
	).body())
	f.Add([]byte{})
	f.Add([]byte{0x03, 0x03})
	f.Add(helloBodyWith(append(append16(nil, tls.VersionTLS12), bytes.Repeat([]byte{0xaa}, 32)...),
		nil, []byte{0x13, 0x01}, []byte{0x00}, []byte{0x00, 0x40, 0x00, 0x00}))

	f.Fuzz(func(t *testing.T, body []byte) {
		hello, reason := parseClientHello(body)
		if reason != "" && reason != reasonMalformedHello {
			t.Fatalf("parser returned reason %q", reason)
		}
		if reason != "" {
			return
		}
		if hello.SNI != "" {
			if _, code := engine.CanonicalName(hello.SNI); code != engine.OK {
				t.Fatalf("parser kept an unusable server name of %d bytes", len(hello.SNI))
			}
		}
		for _, protocol := range hello.ALPN {
			if len(protocol) == 0 || isGREASEProtocol([]byte(protocol)) {
				t.Fatalf("parser kept ALPN entry %q", protocol)
			}
		}
		if !hello.SupportedVersionsPresent && len(hello.SupportedVersions) != 0 {
			t.Fatalf("versions %v without the extension", hello.SupportedVersions)
		}
		for _, version := range hello.SupportedVersions {
			if isGREASE(version) {
				t.Fatalf("parser kept GREASE version %#x", version)
			}
		}
		for _, scheme := range hello.SignatureAlgorithms {
			if isGREASE(uint16(scheme)) {
				t.Fatalf("parser kept GREASE scheme %#x", uint16(scheme))
			}
		}
	})
}

// chunkBy splits data into the deterministic chunk sequence one fuzz input
// describes, so the same bytes reach the probe under many different
// fragmentation patterns.
func chunkBy(data []byte, split byte) [][]byte {
	size := 1 + int(split%16)
	var chunks [][]byte
	for len(data) > 0 {
		n := size
		if n > len(data) {
			n = len(data)
		}
		chunks = append(chunks, data[:n])
		data = data[n:]
	}
	return chunks
}

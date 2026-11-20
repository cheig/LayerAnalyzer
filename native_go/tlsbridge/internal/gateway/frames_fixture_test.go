package gateway

import (
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// The fixture is the TLS-215 cross-language contract for the LAT1 frame: Kotlin
// writes it, this reader consumes it. The Kotlin test drives its production
// channel against a recording gateway and asserts that what it sends is exactly
// these fields with this framing; the cases here feed the very same bytes to the
// real reader, so a frame Kotlin can produce is a frame the gateway accepts, and
// every refusal is the one the fixture recorded. A missing fixture is a failure,
// not a skip — without it nothing checks that the two halves still agree.
const framesFixtureRelative = "native_build/verification/tls/gateway-frame/frames.json"

type framesFixture struct {
	SchemaVersion int            `json:"schemaVersion"`
	FixtureID     string         `json:"fixtureId"`
	Frames        []fixtureFrame `json:"frames"`
}

type fixtureFrame struct {
	ID                 string `json:"id"`
	Accept             bool   `json:"accept"`
	Reason             string `json:"reason"`
	CaptureID          string `json:"captureId"`
	ConnectionID       string `json:"connectionId"`
	NetworkGeneration  int64  `json:"networkGeneration"`
	DestinationAddress string `json:"destinationAddress"`
	DestinationPort    int    `json:"destinationPort"`
	Token              string `json:"token"`
	Body               string `json:"body"`
	// Framing overrides, used only by the refused entries: a body that is not
	// UTF-8 cannot be spelled as JSON text, and a header length or a magic that
	// disagrees with the body is exactly what those entries are about.
	DeclaredLength *uint32 `json:"declaredLength"`
	Magic          *string `json:"magic"`
	BodyBytesB64   *string `json:"bodyBytesBase64"`
}

func readFramesFixture(t *testing.T) framesFixture {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory unavailable: %v", err)
	}
	for depth := 0; depth < 8; depth++ {
		candidate := filepath.Join(directory, filepath.FromSlash(framesFixtureRelative))
		if body, err := os.ReadFile(candidate); err == nil {
			var fixture framesFixture
			if err := json.Unmarshal(body, &fixture); err != nil {
				t.Fatalf("%s is not valid JSON: %v", candidate, err)
			}
			if fixture.SchemaVersion != 1 || fixture.FixtureID == "" || len(fixture.Frames) == 0 {
				t.Fatalf("%s is not a schemaVersion 1 fixture with frames", candidate)
			}
			return fixture
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	t.Fatalf("gateway frame fixture %s not found above the working directory; "+
		"it lives in the repository, so run this test from a checkout", framesFixtureRelative)
	return framesFixture{}
}

// framed rebuilds the exact bytes the SOCKS hop writes: four ASCII bytes, the
// big-endian body length, then the body. The Kotlin side asserts the same three
// parts, so what is parsed here is what is sent there.
func framed(t *testing.T, entry fixtureFrame) []byte {
	t.Helper()
	body := []byte(entry.Body)
	if entry.BodyBytesB64 != nil {
		decoded, err := base64.StdEncoding.DecodeString(*entry.BodyBytesB64)
		if err != nil {
			t.Fatalf("%s: bodyBytesBase64 is not base64: %v", entry.ID, err)
		}
		body = decoded
	}
	magic := "LAT1"
	if entry.Magic != nil {
		magic = *entry.Magic
	}
	length := uint32(len(body))
	if entry.DeclaredLength != nil {
		length = *entry.DeclaredLength
	}
	var prefix [8]byte
	copy(prefix[:4], magic)
	binary.BigEndian.PutUint32(prefix[4:], length)
	return append(prefix[:], body...)
}

// TestTheFrameKotlinWritesIsTheFrameTheGatewayAccepts is the Go half of TLS-215's
// byte-channel contract.
func TestTheFrameKotlinWritesIsTheFrameTheGatewayAccepts(t *testing.T) {
	fixture := readFramesFixture(t)
	accepted, refused := 0, 0
	for _, entry := range fixture.Frames {
		t.Run(entry.ID, func(t *testing.T) {
			if entry.Reason == "" {
				t.Fatal("every frame records why it is accepted or refused")
			}
			metadata, provided, code := readRequest(bytes.NewReader(framed(t, entry)))
			if !entry.Accept {
				refused++
				if code == engine.OK {
					t.Fatalf("refused frame was accepted as %+v", metadata)
				}
				if code != engine.InvalidArgument {
					t.Fatalf("refusal code = %s, want INVALID_ARGUMENT", code)
				}
				return
			}
			accepted++
			if code != engine.OK {
				t.Fatalf("accepted frame was refused with %s", code)
			}
			if metadata.CaptureID != entry.CaptureID || metadata.ConnectionID != entry.ConnectionID ||
				metadata.NetworkGeneration != entry.NetworkGeneration {
				t.Fatalf("metadata = %+v, want capture %q connection %q generation %d",
					metadata, entry.CaptureID, entry.ConnectionID, entry.NetworkGeneration)
			}
			// The destination is the literal the peer asked for: a name would
			// have to be resolved again, and the contract has no field for one.
			address, err := netip.ParseAddr(entry.DestinationAddress)
			if err != nil {
				t.Fatalf("fixture address %q is not a literal: %v", entry.DestinationAddress, err)
			}
			want := netip.AddrPortFrom(address, uint16(entry.DestinationPort))
			if metadata.Destination != want {
				t.Fatalf("destination = %s, want %s", metadata.Destination, want)
			}
			decoded, err := base64.RawURLEncoding.Strict().DecodeString(entry.Token)
			if err != nil || len(decoded) != len(provided) {
				t.Fatalf("fixture token is not %d base64url bytes: %v", len(provided), err)
			}
			if !bytes.Equal(decoded, provided[:]) {
				t.Fatal("the token the frame carried is not the one the fixture recorded")
			}
			if len(entry.Body) == 0 || len(entry.Body) > MaxHeaderBytes {
				t.Fatalf("accepted body is %d bytes, outside 1..%d", len(entry.Body), MaxHeaderBytes)
			}
		})
	}
	if accepted == 0 || refused == 0 {
		t.Fatalf("fixture exercised %d accepted and %d refused frames; both halves matter", accepted, refused)
	}
}

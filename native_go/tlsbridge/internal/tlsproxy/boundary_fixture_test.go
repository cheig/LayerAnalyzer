package tlsproxy

import (
	"crypto/sha256"
	"crypto/tls"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

const boundaryVectorsRelative = "native_build/verification/tls/fixtures/boundary/clienthello-vectors.json"

type clientHelloVectorFixture struct {
	SchemaVersion int                    `json:"schemaVersion"`
	FixtureID     string                 `json:"fixtureId"`
	Source        string                 `json:"source"`
	Vectors       []clientHelloVectorDef `json:"vectors"`
}

type clientHelloVectorDef struct {
	ID          string `json:"id"`
	Case        string `json:"case"`
	BytesBase64 string `json:"bytesBase64"`
	SHA256      string `json:"sha256"`
	Expect      struct {
		Verdict             string   `json:"verdict"`
		SNI                 string   `json:"sni"`
		ALPN                []string `json:"alpn"`
		SupportedVersions   []int    `json:"supportedVersions"`
		SignatureAlgorithms []int    `json:"signatureAlgorithms"`
		ECHOffered          bool     `json:"echOffered"`
	} `json:"expect"`
}

// readBoundaryFixture locates a repository fixture from the test's working
// directory upward, the same way the gateway frame fixture is found.
func readBoundaryFixture(t *testing.T, relative string, into any) {
	t.Helper()
	if err := json.Unmarshal(readRepositoryFile(t, relative), into); err != nil {
		t.Fatalf("%s is not valid JSON: %v", relative, err)
	}
}

func readRepositoryFile(t *testing.T, relative string) []byte {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory unavailable: %v", err)
	}
	for depth := 0; depth < 8; depth++ {
		candidate := filepath.Join(directory, filepath.FromSlash(relative))
		if body, err := os.ReadFile(candidate); err == nil {
			return body
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	t.Fatalf("boundary fixture %s not found above the working directory; run from a checkout", relative)
	return nil
}

// TestTheClientHelloVectorsAreClassifiedAsTheFixtureRecords feeds the fixture's
// exact bytes to the probe and asserts the parsed offer matches the recorded
// expectation. It is where "ECH presence is a candidate signal, never a
// negotiation" and "GREASE never reaches the parsed offer" are made concrete:
// the ECH vector must report the outer SNI with ECHOffered set, and the GREASE
// vector must contain no reserved value anywhere in the parsed lists.
func TestTheClientHelloVectorsAreClassifiedAsTheFixtureRecords(t *testing.T) {
	var fixture clientHelloVectorFixture
	readBoundaryFixture(t, boundaryVectorsRelative, &fixture)
	if fixture.SchemaVersion != 1 || len(fixture.Vectors) == 0 || fixture.Source == "" {
		t.Fatalf("the vector fixture is not a schemaVersion 1 fixture with a declared source: %+v", fixture)
	}
	for _, vector := range fixture.Vectors {
		t.Run(vector.ID, func(t *testing.T) {
			record, err := base64.StdEncoding.DecodeString(vector.BytesBase64)
			if err != nil {
				t.Fatalf("bytesBase64 is not base64: %v", err)
			}
			if got := hex.EncodeToString(sha256Bytes(record)); got != vector.SHA256 {
				t.Fatalf("the recorded bytes hash to %s, the fixture claims %s", got, vector.SHA256)
			}
			outcome := ProbeClientHello(newScriptConn(record), Limits{})
			if got := outcome.Verdict.String(); got != vector.Expect.Verdict {
				t.Fatalf("verdict = %s (%s), want %s", got, outcome.Reason, vector.Expect.Verdict)
			}
			hello := outcome.Hello
			if hello.SNI != vector.Expect.SNI {
				t.Fatalf("SNI = %q, want %q", hello.SNI, vector.Expect.SNI)
			}
			if !slices.Equal(hello.ALPN, vector.Expect.ALPN) {
				t.Fatalf("ALPN = %v, want %v", hello.ALPN, vector.Expect.ALPN)
			}
			if got := toInts(hello.SupportedVersions); !slices.Equal(got, vector.Expect.SupportedVersions) {
				t.Fatalf("supportedVersions = %v, want %v", got, vector.Expect.SupportedVersions)
			}
			if got := schemeInts(hello.SignatureAlgorithms); !slices.Equal(got, vector.Expect.SignatureAlgorithms) {
				t.Fatalf("signatureAlgorithms = %v, want %v", got, vector.Expect.SignatureAlgorithms)
			}
			if hello.ECHOffered != vector.Expect.ECHOffered {
				t.Fatalf("ECHOffered = %v, want %v", hello.ECHOffered, vector.Expect.ECHOffered)
			}
			// GREASE must be absent from every parsed list, no matter which vector
			// this is: a reserved value that survived would be advertised upstream.
			for _, version := range hello.SupportedVersions {
				if isGREASE(version) {
					t.Fatalf("a GREASE version %#x survived into the offer", version)
				}
			}
			for _, scheme := range hello.SignatureAlgorithms {
				if isGREASE(uint16(scheme)) {
					t.Fatalf("a GREASE signature scheme %#x survived into the offer", uint16(scheme))
				}
			}
			for _, protocol := range hello.ALPN {
				if isGREASEProtocol([]byte(protocol)) {
					t.Fatalf("a GREASE ALPN id %q survived into the offer", protocol)
				}
			}
		})
	}
}

func sha256Bytes(data []byte) []byte {
	digest := sha256.Sum256(data)
	return digest[:]
}

func toInts(values []uint16) []int {
	out := make([]int, len(values))
	for index, value := range values {
		out[index] = int(value)
	}
	return out
}

func schemeInts(values []tls.SignatureScheme) []int {
	out := make([]int, len(values))
	for index, value := range values {
		out[index] = int(value)
	}
	return out
}

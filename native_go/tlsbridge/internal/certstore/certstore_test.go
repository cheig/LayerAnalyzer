package certstore

import (
	"crypto/tls"
	"strings"
	"testing"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

func TestSelectAlgorithmPrefersP256AndFallsBackToRSA(t *testing.T) {
	for _, test := range []struct {
		caseName string
		schemes  []tls.SignatureScheme
		want     LeafAlgorithm
		code     engine.Code
	}{
		{"p256 only", []tls.SignatureScheme{tls.ECDSAWithP256AndSHA256}, ECDSAP256, engine.OK},
		{"rsa pss only", []tls.SignatureScheme{tls.PSSWithSHA256, tls.PSSWithSHA384}, RSA2048, engine.OK},
		{"rsa pkcs1 only", []tls.SignatureScheme{tls.PKCS1WithSHA256}, RSA2048, engine.OK},
		{"both prefers p256", []tls.SignatureScheme{tls.PSSWithSHA256, tls.ECDSAWithP256AndSHA256}, ECDSAP256, engine.OK},
		{"grease and unknown ignored", []tls.SignatureScheme{0x0a0a, tls.ECDSAWithP256AndSHA256}, ECDSAP256, engine.OK},
		{"p384 ecdsa is not a p256 leaf", []tls.SignatureScheme{tls.ECDSAWithP384AndSHA384}, 0, engine.Unsupported},
		{"sha1 only", []tls.SignatureScheme{tls.PKCS1WithSHA1, tls.ECDSAWithSHA1}, 0, engine.Unsupported},
		{"ed25519 only", []tls.SignatureScheme{tls.Ed25519}, 0, engine.Unsupported},
		{"empty is not a preference", nil, 0, engine.Unsupported},
		{"empty list", []tls.SignatureScheme{}, 0, engine.Unsupported},
	} {
		got, code := SelectAlgorithm(test.schemes)
		if code != test.code || got != test.want {
			t.Fatalf("%s: SelectAlgorithm = %v, %v; want %v, %v", test.caseName, got, code, test.want, test.code)
		}
	}
}

func TestSelectAlgorithmBoundsTheList(t *testing.T) {
	atCeiling := make([]tls.SignatureScheme, MaxSignatureSchemes)
	atCeiling[MaxSignatureSchemes-1] = tls.ECDSAWithP256AndSHA256
	if got, code := SelectAlgorithm(atCeiling); code != engine.OK || got != ECDSAP256 {
		t.Fatalf("a list of exactly %d schemes = %v, %v; want ECDSA_P256, OK", MaxSignatureSchemes, got, code)
	}
	oversized := make([]tls.SignatureScheme, MaxSignatureSchemes+1)
	oversized[0] = tls.ECDSAWithP256AndSHA256
	if got, code := SelectAlgorithm(oversized); code != engine.InvalidArgument || got != 0 {
		t.Fatalf("an oversized list = %v, %v; want INVALID_ARGUMENT and no family", got, code)
	}
}

func TestLeafAlgorithmNeverReportsAFamilyItCannotMint(t *testing.T) {
	for _, test := range []struct {
		algorithm LeafAlgorithm
		want      string
	}{
		{ECDSAP256, "ECDSA_P256"},
		{RSA2048, "RSA_2048"},
		{LeafAlgorithm(0), "INVALID"},
		{LeafAlgorithm(99), "INVALID"},
	} {
		if got := test.algorithm.String(); got != test.want {
			t.Fatalf("LeafAlgorithm(%d).String() = %q, want %q", test.algorithm, got, test.want)
		}
	}
}

func TestCanonicalNameLowerCasesAndStripsOneTrailingDot(t *testing.T) {
	for _, test := range []struct {
		input string
		want  string
		code  engine.Code
	}{
		{"example.test", "example.test", engine.OK},
		{"EXAMPLE.test.", "example.test", engine.OK},
		{"Upstream.Fixture.Test.", "upstream.fixture.test", engine.OK},
		{"a-b.example.test", "a-b.example.test", engine.OK},
		{"a_b.example.test", "a_b.example.test", engine.OK},
		{"127.0.0.1", "127.0.0.1", engine.OK},
		// An address shape the upstream half also treats as a DNS name: the two
		// halves must not disagree about the same client string.
		{"1.2.3.256", "1.2.3.256", engine.OK},
		{"2001:DB8::1", "2001:db8::1", engine.OK},
		{"::FFFF:127.0.0.1", "::ffff:127.0.0.1", engine.OK},

		{"", "", engine.InvalidArgument},
		{".", "", engine.InvalidArgument},
		{"..", "", engine.InvalidArgument},
		{"example.test:443", "", engine.InvalidArgument},
		{"[::1]", "", engine.InvalidArgument},
		{"*.example.test", "", engine.InvalidArgument},
		{"-leading.test", "", engine.InvalidArgument},
		{"trailing-.test", "", engine.InvalidArgument},
		{"empty..test", "", engine.InvalidArgument},
		{"has space.test", "", engine.InvalidArgument},
		{"café.test", "", engine.InvalidArgument},
		{"a\x00.test", "", engine.InvalidArgument},
		{"a\x1f.test", "", engine.InvalidArgument},
		{"a\x7f.test", "", engine.InvalidArgument},
		{strings.Repeat("a", engine.MaxNameLength+1), "", engine.InvalidArgument},
		{strings.Repeat("a", engine.MaxLabelLength+1) + ".test", "", engine.InvalidArgument},
		{strings.Repeat("a.", engine.MaxNameLength/2) + "test", "", engine.InvalidArgument},
	} {
		got, code := CanonicalName(test.input)
		if code != test.code || got != test.want {
			t.Fatalf("CanonicalName(%q) = %q, %v; want %q, %v", test.input, got, code, test.want, test.code)
		}
	}
}

// TestCanonicalNameAgreesWithTheUpstreamRule pins the one property the two
// halves must share: everything certstore accepts is accepted by the shared
// engine rule for the same input, and the returned form is the engine's form
// lower-cased.
func TestCanonicalNameAgreesWithTheUpstreamRule(t *testing.T) {
	for _, input := range []string{
		"example.test", "EXAMPLE.test.", "a-b.test", "127.0.0.1", "2001:DB8::1",
		"", ".", "a..b", "*.test", "a b.test", strings.Repeat("a", 254),
	} {
		shared, sharedCode := engine.CanonicalName(input)
		got, code := CanonicalName(input)
		if code != sharedCode {
			t.Fatalf("CanonicalName(%q) = %v; shared rule = %v", input, code, sharedCode)
		}
		if code == engine.OK && got != strings.ToLower(shared) {
			t.Fatalf("CanonicalName(%q) = %q; shared rule returned %q", input, got, shared)
		}
	}
}

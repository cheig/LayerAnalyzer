package policy

import (
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/tlsproxy"
)

// The fixture is the TLS-208 cross-language contract: the Kotlin test reads the
// same file and asserts that its normalizer and frozen encoding reproduce it.
// A missing fixture is a failure, not a skip — without it nothing in this file
// checks that the two languages still agree.
const fixtureRelative = "native_build/verification/tls/routing-policy/policy-cases.json"

type fixtureFile struct {
	SchemaVersion int             `json:"schemaVersion"`
	FixtureID     string          `json:"fixtureId"`
	Rules         []fixtureRule   `json:"rules"`
	Policies      []fixturePolicy `json:"policies"`
}

type fixtureRule struct {
	Input     string  `json:"input"`
	Kind      *string `json:"kind"`
	Value     *string `json:"value"`
	Canonical bool    `json:"canonical"`
}

type fixturePolicy struct {
	ID                  string             `json:"id"`
	AllowedApplications []string           `json:"allowedApplications"`
	Settings            json.RawMessage    `json:"settings"`
	Frozen              json.RawMessage    `json:"frozen"`
	Prefilter           []fixturePrefilter `json:"prefilter"`
	Connections         []fixtureConn      `json:"connections"`
}

type fixturePrefilter struct {
	Port        int     `json:"port"`
	Application *string `json:"application"`
	Expect      string  `json:"expect"`
}

type fixtureConn struct {
	ID          string `json:"id"`
	Destination string `json:"destination"`
	Port        int    `json:"port"`
	Application string `json:"application"`
	Verdict     string `json:"verdict"`
	ProbeReason string `json:"probeReason"`
	SNI         string `json:"sni"`
	Expect      struct {
		Class        string `json:"class"`
		Reason       string `json:"reason"`
		Identity     string `json:"identity"`
		IdentityKind string `json:"identityKind"`
		Code         string `json:"code"`
	} `json:"expect"`
}

func readFixture(t *testing.T) fixtureFile {
	t.Helper()
	directory, err := os.Getwd()
	if err != nil {
		t.Fatalf("working directory unavailable: %v", err)
	}
	for depth := 0; depth < 8; depth++ {
		candidate := filepath.Join(directory, filepath.FromSlash(fixtureRelative))
		if body, err := os.ReadFile(candidate); err == nil {
			var fixture fixtureFile
			if err := json.Unmarshal(body, &fixture); err != nil {
				t.Fatalf("%s is not valid JSON: %v", candidate, err)
			}
			if fixture.SchemaVersion != 1 || fixture.FixtureID == "" {
				t.Fatalf("%s is not a schemaVersion 1 fixture", candidate)
			}
			return fixture
		}
		parent := filepath.Dir(directory)
		if parent == directory {
			break
		}
		directory = parent
	}
	t.Fatalf("connection policy fixture %s not found above the working directory; "+
		"it lives in the repository, so run this test from a checkout", fixtureRelative)
	return fixtureFile{}
}

func fixtureVerdict(t *testing.T, name string) tlsproxy.Verdict {
	t.Helper()
	switch name {
	case "client_hello":
		return tlsproxy.VerdictClientHello
	case "not_tls":
		return tlsproxy.VerdictNotTLS
	case "unsupported":
		return tlsproxy.VerdictUnsupported
	case "incomplete":
		return tlsproxy.VerdictIncomplete
	default:
		t.Fatalf("fixture names an unknown verdict %q", name)
		return tlsproxy.VerdictClientHello
	}
}

// TestFixtureRuleNormalization is the Go half of "one normalization rule". The
// canonical text a fixture entry records must be accepted as-is; the input form
// it was derived from must not be, because accepting both would mean two
// spellings of one rule and two chances to disagree with Kotlin.
func TestFixtureRuleNormalization(t *testing.T) {
	fixture := readFixture(t)
	if len(fixture.Rules) == 0 {
		t.Fatal("fixture carries no rule cases")
	}
	for _, entry := range fixture.Rules {
		t.Run(entry.Input, func(t *testing.T) {
			kinds := []RuleKind{RuleExactDomain, RuleSubdomains, RuleExactIP}
			if entry.Kind == nil {
				if entry.Value != nil || entry.Canonical {
					t.Fatalf("an invalid entry must have a null kind and value")
				}
				for _, kind := range kinds {
					if _, code := ParseRule(kind, entry.Input); code == engine.OK {
						t.Fatalf("%q must not be accepted as %s", entry.Input, kind)
					}
				}
				return
			}
			kind, code := ParseRuleKind(*entry.Kind)
			if code != engine.OK {
				t.Fatalf("fixture names an unknown rule kind %q", *entry.Kind)
			}
			rule, code := ParseRule(kind, *entry.Value)
			if code != engine.OK {
				t.Fatalf("canonical value %q must be accepted as %s", *entry.Value, kind)
			}
			if rule.String() != *entry.Kind+":"+*entry.Value {
				t.Fatalf("parsed rule is %s, want %s:%s", rule, *entry.Kind, *entry.Value)
			}
			canonical := *entry.Value
			if kind == RuleSubdomains {
				// The frozen value is the bare domain; the text Kotlin's rule
				// normalizes to, and the text Go accepts, both keep the "*. "
				// prefix.
				canonical = "*." + *entry.Value
			}
			// Strip the wildcard prefix so the entry's own domain text is what
			// is offered as a value, exactly as Kotlin would hand it over.
			incoming, code := ParseRule(kind, strings.TrimPrefix(entry.Input, "*."))
			if entry.Canonical {
				if entry.Input != canonical {
					t.Fatalf("entry marked canonical must be the frozen text %q", canonical)
				}
				if code != engine.OK || incoming.String() != rule.String() {
					t.Fatalf("canonical input %q must parse to %s", entry.Input, rule)
				}
				return
			}
			if entry.Input == canonical {
				t.Fatalf("entry marked non-canonical is already the frozen text %q", canonical)
			}
			if code == engine.OK {
				t.Fatalf("non-canonical input %q must be rejected as %s, not read as %s", entry.Input, kind, incoming)
			}
		})
	}
}

func TestFixturePolicies(t *testing.T) {
	fixture := readFixture(t)
	if len(fixture.Policies) == 0 {
		t.Fatal("fixture carries no policies")
	}
	for _, entry := range fixture.Policies {
		t.Run(entry.ID, func(t *testing.T) {
			if len(entry.Settings) == 0 || len(entry.Frozen) == 0 {
				t.Fatalf("policy needs both a settings object and a frozen policy")
			}
			// The engine start config carries the frozen object; settings are
			// Kotlin's input and are not read here, because re-deriving the
			// frozen form would be the second normalizer this contract exists
			// to prevent.
			frozen, code := ParsePolicy(entry.Frozen)
			if code != engine.OK {
				t.Fatalf("frozen policy rejected: %s", code)
			}
			for _, screen := range entry.Prefilter {
				application := ""
				if screen.Application != nil {
					application = *screen.Application
				}
				got := frozen.Prefilter(uint16(screen.Port), application)
				if got.String() != screen.Expect {
					t.Fatalf("prefilter(%d, %q) = %s, want %s", screen.Port, application, got, screen.Expect)
				}
				candidate := screen.Expect == string(ReasonCandidate)
				if (got == PrefilterCandidate) != candidate {
					t.Fatalf("prefilter(%d, %q) agreed on the reason but not on candidacy", screen.Port, application)
				}
			}
			for _, connection := range entry.Connections {
				checkConnection(t, frozen, connection)
			}
		})
	}
}

func checkConnection(t *testing.T, frozen Policy, connection fixtureConn) {
	t.Helper()
	address, err := netip.ParseAddr(connection.Destination)
	if err != nil {
		t.Fatalf("fixture destination %q is not an address", connection.Destination)
	}
	destination := netip.AddrPortFrom(address, uint16(connection.Port))
	request := Request{
		Destination: destination,
		Application: connection.Application,
		Probe: Probe{
			Verdict: fixtureVerdict(t, connection.Verdict),
			Reason:  connection.ProbeReason,
			SNI:     connection.SNI,
		},
	}
	decision, code := frozen.Decide(request)
	if got := codeName(code); got != connection.Expect.Code {
		t.Fatalf("%s: code = %s, want %s", connection.ID, got, connection.Expect.Code)
	}
	if got := decision.Klass.String(); got != connection.Expect.Class {
		t.Fatalf("%s: class = %s, want %s", connection.ID, got, connection.Expect.Class)
	}
	if got := string(decision.Reason); got != connection.Expect.Reason {
		t.Fatalf("%s: reason = %q, want %q", connection.ID, got, connection.Expect.Reason)
	}
	if decision.Identity != connection.Expect.Identity {
		t.Fatalf("%s: identity = %q, want %q", connection.ID, decision.Identity, connection.Expect.Identity)
	}
	if got := decision.IdentityKind.String(); got != connection.Expect.IdentityKind {
		t.Fatalf("%s: identity kind = %q, want %q", connection.ID, got, connection.Expect.IdentityKind)
	}
	if !decision.Intercepts() && (decision.Identity != "" || decision.IdentityKind != IdentityNone) {
		t.Fatalf("%s: a non-intercepted decision must carry no identity", connection.ID)
	}
	// The destination used for dialing is the caller's and can never move to a
	// name the client asserted, or to whatever the SNI resolves to. The address
	// is required to be absent from the decision for the same reason.
	if request.Destination != destination {
		t.Fatalf("%s: the request destination was rewritten", connection.ID)
	}
	if decision.IdentityKind == IdentityIP && decision.Identity == connection.SNI && connection.SNI != "" {
		t.Fatalf("%s: the identity was taken from the asserted name", connection.ID)
	}
}

func codeName(code engine.Code) string {
	if code == engine.OK {
		return "OK"
	}
	return code.String()
}

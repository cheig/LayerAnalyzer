package policy

import (
	"net/netip"
	"strings"
	"testing"

	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/tlsproxy"
)

func mustParsePolicy(t *testing.T, settings string) Policy {
	t.Helper()
	policy, code := ParsePolicy([]byte(settings))
	if code != engine.OK {
		t.Fatalf("policy rejected: %s\n%s", code, settings)
	}
	return policy
}

// decide is the shape every case in this file needs: one connection to one
// address, with an explicit probe result.
func decide(t *testing.T, policy Policy, address string, port int, application string, probe Probe) (Decision, engine.Code) {
	t.Helper()
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		t.Fatalf("%q is not an address: %v", address, err)
	}
	return policy.Decide(Request{
		Destination: netip.AddrPortFrom(parsed, uint16(port)),
		Application: application,
		Probe:       probe,
	})
}

func clientHello(sni string) Probe {
	return Probe{Verdict: tlsproxy.VerdictClientHello, SNI: sni}
}

func TestZeroPolicyIsDisabledAndDecidesNothing(t *testing.T) {
	var disabled Policy
	if disabled.Enabled() {
		t.Fatal("a zero policy must be disabled")
	}
	if got := disabled.Prefilter(443, ""); got != PrefilterDisabled {
		t.Fatalf("prefilter = %s, want disabled", got)
	}
	decision, code := decide(t, disabled, "198.51.100.7", 443, "", clientHello("example.test"))
	if code != engine.OK || decision.Klass != KlassOutOfScope || decision.Reason != ReasonDisabled {
		t.Fatalf("zero policy decided %s/%s/%s, want out_of_scope/disabled/OK", decision.Klass, decision.Reason, code)
	}
	if decision.Intercepts() {
		t.Fatal("an unassembled policy must never intercept")
	}
}

func TestParsePolicyAcceptsTheFrozenForm(t *testing.T) {
	policy := mustParsePolicy(t, `{
		"schemaVersion": 1,
		"enabled": true,
		"hostScope": "SelectedApplicationsCandidates",
		"candidatePorts": [443, 8443],
		"include": [{"kind": "exactDomain", "value": "example.test"}],
		"bypass": [{"kind": "subdomains", "value": "blocked.test"}],
		"applications": ["com.example.fixture.app", "com.example.fixture.other"]
	}`)
	if !policy.Enabled() || policy.Scope() != ScopeSelectedApplicationsCandidates {
		t.Fatalf("enabled/scope = %v/%s", policy.Enabled(), policy.Scope())
	}
	if got := policy.CandidatePorts(); len(got) != 2 || got[0] != 443 || got[1] != 8443 {
		t.Fatalf("candidate ports = %v", got)
	}
	if got := policy.Include(); len(got) != 1 || got[0].String() != "exactDomain:example.test" {
		t.Fatalf("include = %v", got)
	}
	if got := policy.Bypass(); len(got) != 1 || got[0].String() != "subdomains:blocked.test" {
		t.Fatalf("bypass = %v", got)
	}
	if got := policy.Applications(); len(got) != 2 || got[0] != "com.example.fixture.app" {
		t.Fatalf("applications = %v", got)
	}
	// Accessors hand out copies: a frozen policy cannot be edited in place.
	ports := policy.CandidatePorts()
	ports[0] = 1
	if policy.CandidatePorts()[0] != 443 {
		t.Fatal("the frozen port set was mutated through an accessor")
	}
}

func TestParsePolicyRejectsAnythingButTheFrozenForm(t *testing.T) {
	shape := func(body string) string {
		return `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],` +
			`"include":[],"bypass":[],"applications":[]` + body + `}`
	}
	valid := shape("")
	if _, code := ParsePolicy([]byte(valid)); code != engine.OK {
		t.Fatalf("the reference policy must parse, got %s", code)
	}
	cases := map[string]string{
		"empty input":                    "",
		"not an object":                  `"policy"`,
		"unknown field":                  shape(`,"futureField":true`),
		"trailing content":               valid + `{}`,
		"schema version":                 `{"schemaVersion":2,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[],"applications":[]}`,
		"missing schema version":         `{"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[],"applications":[]}`,
		"missing enabled":                `{"schemaVersion":1,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[],"applications":[]}`,
		"missing ports":                  `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","include":[],"bypass":[],"applications":[]}`,
		"missing include":                `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"bypass":[],"applications":[]}`,
		"missing bypass":                 `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"applications":[]}`,
		"missing applications":           `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[]}`,
		"null enabled":                   `{"schemaVersion":1,"enabled":null,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[],"applications":[]}`,
		"unknown scope":                  `{"schemaVersion":1,"enabled":true,"hostScope":"EveryHost","candidatePorts":[443],"include":[],"bypass":[],"applications":[]}`,
		"scope is an ordinal":            `{"schemaVersion":1,"enabled":1,"hostScope":0,"candidatePorts":[443],"include":[],"bypass":[],"applications":[]}`,
		"port zero":                      `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[0],"include":[],"bypass":[],"applications":[]}`,
		"port too large":                 `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[65536],"include":[],"bypass":[],"applications":[]}`,
		"port duplicated":                `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443,443],"include":[],"bypass":[],"applications":[]}`,
		"ports unordered":                `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[8443,443],"include":[],"bypass":[],"applications":[]}`,
		"port is a string":               `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":["443"],"include":[],"bypass":[],"applications":[]}`,
		"unknown rule kind":              `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[{"kind":"regex","value":"example.test"}],"bypass":[],"applications":[]}`,
		"rule without a value":           `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[{"kind":"exactDomain"}],"bypass":[],"applications":[]}`,
		"non-canonical rule":             `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[{"kind":"exactDomain","value":"Example.TEST."}],"bypass":[],"applications":[]}`,
		"wildcard text as a rule value":  `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[{"kind":"exactDomain","value":"*.example.test"}],"bypass":[],"applications":[]}`,
		"duplicate rule in one list":     `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[{"kind":"exactDomain","value":"a.test"},{"kind":"exactDomain","value":"a.test"}],"bypass":[],"applications":[]}`,
		"duplicate bypass rule":          `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[{"kind":"exactIp","value":"192.0.2.1"},{"kind":"exactIp","value":"192.0.2.1"}],"applications":[]}`,
		"blank application":              `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[],"applications":[" "]}`,
		"duplicate application":          `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[],"applications":["a.b","a.b"]}`,
		"application scope without apps": `{"schemaVersion":1,"enabled":true,"hostScope":"SelectedApplicationsCandidates","candidatePorts":[443],"include":[],"bypass":[],"applications":[]}`,
		"oversized policy":               `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],"include":[],"bypass":[],"applications":[],"x":"` + strings.Repeat("a", MaxPolicyBytes) + `"}`,
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			if _, code := ParsePolicy([]byte(input)); code == engine.OK {
				t.Fatalf("%s must be rejected", name)
			}
		})
	}
	if _, code := ParsePolicy([]byte{0xff, 0xfe}); code == engine.OK {
		t.Fatal("invalid UTF-8 must be rejected")
	}
}

func TestParseRuleRejectsNonCanonicalText(t *testing.T) {
	valid := map[RuleKind][]string{
		RuleExactDomain: {"example.test", "a.test", "1.2.3.4a", "xn--bcher-kva.example"},
		RuleSubdomains:  {"example.test", "test"},
		RuleExactIP:     {"192.0.2.1", "2001:db8:0:0:0:0:0:1", "0:0:0:0:0:ffff:c000:201", "0:0:0:0:0:0:0:1"},
	}
	for kind, values := range valid {
		for _, value := range values {
			if _, code := ParseRule(kind, value); code != engine.OK {
				t.Fatalf("%s must accept %q", kind, value)
			}
		}
	}
	invalid := map[RuleKind][]string{
		RuleExactDomain: {"", "Example.test", "example.test.", ".example.test", "example..test", "example.test..", "_dmarc.example.test", "-a.test", "a-.test", "192.0.2.1", "1.2.3", "256.0.2.1", "192.00.2.1", "*.example.test", "example.*", "*", "exa mple.test", "例え.test", "example.test:443", "https://example.test", strings.Repeat("a", 64) + ".test"},
		RuleSubdomains:  {"", "192.0.2.1", "1.2.3", "*.example.test", "Example.test"},
		RuleExactIP:     {"", "::1", "2001:DB8::1", "2001:db8:0:0:0:0:0:1:2", "::ffff:192.0.2.1", "192.0.2.1.", "fe80::1%wlan0", "example.test", "0.0.0"},
	}
	for kind, values := range invalid {
		for _, value := range values {
			if rule, code := ParseRule(kind, value); code == engine.OK {
				t.Fatalf("%s must reject %q, read it as %s", kind, value, rule)
			}
		}
	}
	if _, code := ParseRule(RuleKind("regex"), "example.test"); code == engine.OK {
		t.Fatal("an unknown rule kind must be rejected")
	}
}

// The name and address limits are the platform verifier's, so a name accepted
// here is also expressible as a certificate SAN.
func TestCanonicalDomainLimits(t *testing.T) {
	label63 := strings.Repeat("a", 63)
	if _, code := ParseRule(RuleExactDomain, label63+".test"); code != engine.OK {
		t.Fatal("a 63-byte label must be accepted")
	}
	if _, code := ParseRule(RuleExactDomain, strings.Repeat("a", 64)+".test"); code == engine.OK {
		t.Fatal("a 64-byte label must be rejected")
	}
	longest := label63 + "." + strings.Repeat("b", 63) + "." + strings.Repeat("c", 63) + "." + strings.Repeat("d", 61)
	if len(longest) != engine.MaxNameLength {
		t.Fatalf("the reference name is %d bytes, want %d", len(longest), engine.MaxNameLength)
	}
	if _, code := ParseRule(RuleExactDomain, longest); code != engine.OK {
		t.Fatal("a 253-byte name must be accepted")
	}
	if _, code := ParseRule(RuleExactDomain, "e"+longest); code == engine.OK {
		t.Fatal("a 254-byte name must be rejected")
	}
}

const explicitPolicy = `{
	"schemaVersion": 1,
	"enabled": true,
	"hostScope": "ExplicitHosts",
	"candidatePorts": [443, 8443],
	"include": [
		{"kind": "exactDomain", "value": "checkout.example.test"},
		{"kind": "subdomains", "value": "example.test"},
		{"kind": "exactIp", "value": "192.0.2.1"}
	],
	"bypass": [{"kind": "exactDomain", "value": "api.example.test"}, {"kind": "subdomains", "value": "blocked.test"}],
	"applications": []
}`

func TestNameRulesMatchExactlyTheirOwnShape(t *testing.T) {
	policy := mustParsePolicy(t, explicitPolicy)
	cases := map[string]struct {
		sni     string
		address string
		class   Klass
		reason  Reason
	}{
		"exact name":                {"checkout.example.test", "198.51.100.7", KlassIntercepted, ReasonIncludedHost},
		"subdomain":                 {"www.example.test", "198.51.100.7", KlassIntercepted, ReasonIncludedHost},
		"multi-label subdomain":     {"a.b.example.test", "198.51.100.7", KlassIntercepted, ReasonIncludedHost},
		"root of a wildcard":        {"example.test", "198.51.100.7", KlassOutOfScope, ReasonNoIncludeMatch},
		"bad suffix":                {"badexample.test", "198.51.100.7", KlassOutOfScope, ReasonNoIncludeMatch},
		"longer name":               {"checkout.example.test.evil", "198.51.100.7", KlassOutOfScope, ReasonNoIncludeMatch},
		"name sent upper case":      {"CHECKOUT.Example.TEST.", "198.51.100.7", KlassIntercepted, ReasonIncludedHost},
		"root of a bypass wildcard": {"blocked.test", "198.51.100.7", KlassOutOfScope, ReasonNoIncludeMatch},
		"bypass wildcard":           {"x.blocked.test", "198.51.100.7", KlassBypassed, ReasonBypassRule},
		"explicit bypass wins":      {"api.example.test", "198.51.100.7", KlassBypassed, ReasonBypassRule},
	}
	for name, expected := range cases {
		t.Run(name, func(t *testing.T) {
			decision, code := decide(t, policy, expected.address, 443, "", clientHello(expected.sni))
			if code != engine.OK {
				t.Fatalf("code = %s", code)
			}
			if decision.Klass != expected.class || decision.Reason != expected.reason {
				t.Fatalf("decided %s/%s, want %s/%s", decision.Klass, decision.Reason, expected.class, expected.reason)
			}
			if decision.Identity != strings.ToLower(strings.TrimSuffix(expected.sni, ".")) && decision.Intercepts() {
				t.Fatalf("identity = %q, want the lower-cased name %q", decision.Identity, expected.sni)
			}
		})
	}
}

// Rule order is not part of the meaning of a rule set: the same rules in the
// other order must decide identically, so no capture depends on how a list was
// typed.
func TestRuleOrderDoesNotChangeADecision(t *testing.T) {
	forward := mustParsePolicy(t, `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts",
		"candidatePorts":[443],"include":[{"kind":"exactDomain","value":"a.test"},{"kind":"subdomains","value":"a.test"},{"kind":"exactIp","value":"192.0.2.1"}],
		"bypass":[{"kind":"exactDomain","value":"b.test"},{"kind":"subdomains","value":"c.test"}],"applications":[]}`)
	reverse := mustParsePolicy(t, `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts",
		"candidatePorts":[443],"include":[{"kind":"exactIp","value":"192.0.2.1"},{"kind":"subdomains","value":"a.test"},{"kind":"exactDomain","value":"a.test"}],
		"bypass":[{"kind":"subdomains","value":"c.test"},{"kind":"exactDomain","value":"b.test"}],"applications":[]}`)
	for _, sni := range []string{"a.test", "x.a.test", "b.test", "x.c.test", "other.test", ""} {
		first, firstCode := decide(t, forward, "192.0.2.1", 443, "", clientHello(sni))
		second, secondCode := decide(t, reverse, "192.0.2.1", 443, "", clientHello(sni))
		if firstCode != secondCode || first != second {
			t.Fatalf("sni %q decided %+v/%s and %+v/%s", sni, first, firstCode, second, secondCode)
		}
	}
}

func TestNamesAndAddressesNeverMatchEachOthersRules(t *testing.T) {
	policy := mustParsePolicy(t, explicitPolicy)
	// The address is rule-listed, but an asserted name is the identity, so the
	// address rule must not fire and the address must not become an identity.
	decision, code := decide(t, policy, "192.0.2.1", 443, "", clientHello("example.test"))
	if code != engine.OK || decision.Klass != KlassOutOfScope {
		t.Fatalf("decided %s/%s/%s, want out_of_scope", decision.Klass, decision.Reason, code)
	}
	// A name that is not listed, sent to a listed address, is still refused: the
	// address rule is not consulted while the identity is a name.
	decision, _ = decide(t, policy, "192.0.2.1", 443, "", clientHello("unlisted.test"))
	if decision.Klass != KlassOutOfScope {
		t.Fatalf("a name rule must not be satisfied by an address: %s", decision.Klass)
	}
	// And a bypass rule for an address does not apply to a named connection.
	bypassByAddress := mustParsePolicy(t, `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],
		"include":[],"bypass":[{"kind":"exactIp","value":"192.0.2.1"}],"applications":[]}`)
	decision, _ = decide(t, bypassByAddress, "192.0.2.1", 443, "", clientHello("example.test"))
	if decision.Klass != KlassOutOfScope {
		t.Fatalf("an address bypass must not apply to a named connection: %s", decision.Klass)
	}
}

func TestIdentityIsTheAssertedNameOrTheDestinationAddress(t *testing.T) {
	policy := mustParsePolicy(t, explicitPolicy)
	cases := []struct {
		name      string
		sni       string
		address   string
		kind      IdentityKind
		identity  string
		intercept bool
	}{
		{"usable name", "www.example.test", "198.51.100.7", IdentityDomain, "www.example.test", true},
		{"no name, listed address", "", "192.0.2.1", IdentityIP, "192.0.2.1", true},
		{"no name, unlisted address", "", "198.51.100.7", IdentityNone, "", false},
		{"address sent as a name", "1.2.3.4", "192.0.2.1", IdentityIP, "192.0.2.1", true},
		{"bracketed address as a name", "[::1]", "192.0.2.1", IdentityIP, "192.0.2.1", true},
		{"name with a space", "bad name.example", "192.0.2.1", IdentityIP, "192.0.2.1", true},
		{"non-ascii name", "例え.test", "192.0.2.1", IdentityIP, "192.0.2.1", true},
		{"name over the length limit", strings.Repeat("a", 254), "192.0.2.1", IdentityIP, "192.0.2.1", true},
		{"listed name with an unlisted address", "www.example.test", "192.0.2.1", IdentityDomain, "www.example.test", true},
	}
	for _, expected := range cases {
		t.Run(expected.name, func(t *testing.T) {
			decision, code := decide(t, policy, expected.address, 443, "", clientHello(expected.sni))
			if code != engine.OK {
				t.Fatalf("code = %s", code)
			}
			if decision.Intercepts() != expected.intercept {
				t.Fatalf("intercepts = %v, want %v (%s/%s)", decision.Intercepts(), expected.intercept, decision.Klass, decision.Reason)
			}
			if decision.Identity != expected.identity || decision.IdentityKind != expected.kind {
				t.Fatalf("identity = %q/%s, want %q/%s", decision.Identity, decision.IdentityKind, expected.identity, expected.kind)
			}
		})
	}
}

// IPv4-mapped destinations are reported in IPv4 form, so a rule names the
// address the capture actually shows.
func TestMappedDestinationIsReportedInIPv4Form(t *testing.T) {
	policy := mustParsePolicy(t, explicitPolicy)
	decision, code := decide(t, policy, "::ffff:198.51.100.7", 443, "", clientHello(""))
	if code != engine.OK {
		t.Fatalf("code = %s", code)
	}
	if decision.Klass == KlassInvalid {
		t.Fatal("a mapped destination is a normal address")
	}
	decision, _ = decide(t, policy, "::ffff:192.0.2.1", 443, "", clientHello(""))
	if !decision.Intercepts() || decision.Identity != "192.0.2.1" || decision.IdentityKind != IdentityIP {
		t.Fatalf("mapped destination decided %+v", decision)
	}
}

func TestIPv6RulesAndIdentitiesMatchByValue(t *testing.T) {
	// The frozen rule text is the fully expanded form; the identity is netip's
	// compressed rendering. They must still be the same address.
	policy := mustParsePolicy(t, `{"schemaVersion":1,"enabled":true,"hostScope":"ExplicitHosts","candidatePorts":[443],
		"include":[{"kind":"exactIp","value":"2001:db8:0:0:0:0:0:1"}],"bypass":[],"applications":[]}`)
	decision, code := decide(t, policy, "2001:db8::1", 443, "", clientHello(""))
	if code != engine.OK || !decision.Intercepts() || decision.Identity != "2001:db8::1" {
		t.Fatalf("decided %+v/%s", decision, code)
	}
	other, _ := decide(t, policy, "2001:db8::2", 443, "", clientHello(""))
	if other.Intercepts() {
		t.Fatal("a different address must not match")
	}
}

func TestPrefilterOnlyScreensPortAndApplication(t *testing.T) {
	explicit := mustParsePolicy(t, explicitPolicy)
	if got := explicit.Prefilter(443, ""); got != PrefilterCandidate {
		t.Fatalf("candidate port = %s", got)
	}
	if got := explicit.Prefilter(80, ""); got != PrefilterPortNotCandidate {
		t.Fatalf("non-candidate port = %s", got)
	}
	// The explicit scope has no application requirement, so an unattributed
	// connection is still probed: the name decides, not the application.
	if got := explicit.Prefilter(443, ""); got != PrefilterCandidate {
		t.Fatalf("explicit scope = %s", got)
	}

	scoped := mustParsePolicy(t, `{"schemaVersion":1,"enabled":true,"hostScope":"SelectedApplicationsCandidates","candidatePorts":[443],
		"include":[],"bypass":[],"applications":["com.example.fixture.app"]}`)
	for _, application := range []string{"com.example.fixture.other", "com.example.fixture.app.extra", "10142", "", " "} {
		if got := scoped.Prefilter(443, application); got != PrefilterApplicationNotSelected {
			t.Fatalf("application %q = %s", application, got)
		}
	}
	if got := scoped.Prefilter(443, "com.example.fixture.app"); got != PrefilterCandidate {
		t.Fatalf("selected application = %s", got)
	}
	if got := scoped.Prefilter(80, "com.example.fixture.app"); got != PrefilterPortNotCandidate {
		t.Fatalf("port is screened before the application: %s", got)
	}
}

// An include list set alongside the application scope narrows it; it can never
// widen it, and the reason says which of the two gates the connection passed.
func TestIncludeListNarrowsTheApplicationScope(t *testing.T) {
	policy := mustParsePolicy(t, `{"schemaVersion":1,"enabled":true,"hostScope":"SelectedApplicationsCandidates","candidatePorts":[443],
		"include":[{"kind":"exactDomain","value":"allowed.example.test"}],"bypass":[],"applications":["com.example.fixture.app"]}`)
	decision, code := decide(t, policy, "198.51.100.7", 443, "com.example.fixture.app", clientHello("allowed.example.test"))
	if code != engine.OK || !decision.Intercepts() || decision.Reason != ReasonIncludedHost {
		t.Fatalf("decided %+v/%s", decision, code)
	}
	decision, _ = decide(t, policy, "198.51.100.7", 443, "com.example.fixture.app", clientHello("other.example.test"))
	if decision.Klass != KlassOutOfScope || decision.Reason != ReasonNoIncludeMatch {
		t.Fatalf("an include list must still narrow the application scope: %+v", decision)
	}
	decision, _ = decide(t, policy, "198.51.100.7", 443, "com.example.fixture.other", clientHello("allowed.example.test"))
	if decision.Klass != KlassOutOfScope || decision.Reason != ReasonApplicationNotSelected {
		t.Fatalf("a name rule must not widen the application scope: %+v", decision)
	}

	withoutInclude := mustParsePolicy(t, `{"schemaVersion":1,"enabled":true,"hostScope":"SelectedApplicationsCandidates","candidatePorts":[443],
		"include":[],"bypass":[],"applications":["com.example.fixture.app"]}`)
	decision, _ = decide(t, withoutInclude, "198.51.100.7", 443, "com.example.fixture.app", clientHello("anything.example.test"))
	if !decision.Intercepts() || decision.Reason != ReasonSelectedApplication {
		t.Fatalf("decided %+v", decision)
	}
}

func TestDecideKeepsProtocolResultsApartFromTheUserRules(t *testing.T) {
	// A policy that would intercept the name: the probe result still decides,
	// because a stream that is not a servable ClientHello is never intercepted.
	policy := mustParsePolicy(t, explicitPolicy)
	cases := []struct {
		verdict tlsproxy.Verdict
		reason  string
		class   Klass
	}{
		{tlsproxy.VerdictNotTLS, "malformed_client_hello", KlassNotTLS},
		{tlsproxy.VerdictNotTLS, "not_handshake_record", KlassNotTLS},
		{tlsproxy.VerdictUnsupported, "no_supported_version", KlassUnsupported},
		{tlsproxy.VerdictUnsupported, "unexpected_handshake_type", KlassUnsupported},
		{tlsproxy.VerdictIncomplete, "probe_timeout", KlassUndecided},
		{tlsproxy.VerdictIncomplete, "prefix_budget_exceeded", KlassUndecided},
		{tlsproxy.VerdictIncomplete, "read_error", KlassUndecided},
	}
	for _, expected := range cases {
		t.Run(expected.reason, func(t *testing.T) {
			probe := Probe{Verdict: expected.verdict, Reason: expected.reason, SNI: "www.example.test"}
			decision, code := decide(t, policy, "198.51.100.7", 443, "", probe)
			if code != engine.OK || decision.Klass != expected.class || decision.Reason != Reason(expected.reason) {
				t.Fatalf("decided %s/%s/%s, want %s", decision.Klass, decision.Reason, code, expected.class)
			}
			if decision.Identity != "" || decision.IdentityKind != IdentityNone {
				t.Fatalf("a non-TLS result must carry no identity: %+v", decision)
			}
		})
	}
}

func TestDecideRefusesContradictoryOrUnknownProbeResults(t *testing.T) {
	policy := mustParsePolicy(t, explicitPolicy)
	contradictions := []Probe{
		{Verdict: tlsproxy.VerdictClientHello, Reason: "probe_timeout"},
		{Verdict: tlsproxy.VerdictNotTLS},
		{Verdict: tlsproxy.VerdictUnsupported},
		{Verdict: tlsproxy.VerdictIncomplete},
		{Verdict: tlsproxy.Verdict(99)},
		{Verdict: tlsproxy.Verdict(-1), Reason: "probe_timeout"},
	}
	for _, probe := range contradictions {
		decision, code := decide(t, policy, "198.51.100.7", 443, "", probe)
		if code != engine.InvalidArgument {
			t.Fatalf("%+v must be refused, got %s", probe, code)
		}
		if decision.Intercepts() {
			t.Fatalf("%+v must not intercept", probe)
		}
	}
}

func TestDecideRefusesAnUnusableDestination(t *testing.T) {
	policy := mustParsePolicy(t, explicitPolicy)
	unusable := []string{"0.0.0.0", "::", "224.0.0.1", "ff02::1"}
	for _, address := range unusable {
		decision, code := decide(t, policy, address, 443, "", clientHello("www.example.test"))
		if code != engine.InvalidArgument || decision.Intercepts() {
			t.Fatalf("%s must be refused, got %s/%+v", address, code, decision)
		}
	}
	var invalid netip.AddrPort
	if _, code := policy.Decide(Request{Destination: invalid, Probe: clientHello("www.example.test")}); code != engine.InvalidArgument {
		t.Fatalf("an unset destination must be refused, got %s", code)
	}
	zoned, err := netip.ParseAddr("fe80::1%wlan0")
	if err != nil {
		t.Fatalf("the fixture address is not parsable: %v", err)
	}
	if _, code := policy.Decide(Request{Destination: netip.AddrPortFrom(zoned, 443), Probe: clientHello("www.example.test")}); code != engine.InvalidArgument {
		t.Fatalf("a zoned destination must be refused, got %s", code)
	}
}

func TestPreFilterReasonStringsAreStable(t *testing.T) {
	// These strings are published in connection events, so their spelling is
	// part of the interface.
	expected := map[Prefilter]string{
		PrefilterCandidate:              "candidate",
		PrefilterDisabled:               "disabled",
		PrefilterPortNotCandidate:       "port_not_candidate",
		PrefilterApplicationNotSelected: "application_not_selected",
	}
	for screen, reason := range expected {
		if screen.String() != reason || string(screen.reason()) != reason {
			t.Fatalf("prefilter %d = %q/%q, want %q", screen, screen.String(), screen.reason(), reason)
		}
	}
	reasons := map[Reason]string{
		ReasonDisabled:               "disabled",
		ReasonBypassRule:             "bypass_rule",
		ReasonIncludedHost:           "included_host",
		ReasonSelectedApplication:    "selected_application",
		ReasonNoIncludeMatch:         "no_include_match",
		ReasonPortNotCandidate:       "port_not_candidate",
		ReasonApplicationNotSelected: "application_not_selected",
	}
	for reason, text := range reasons {
		if string(reason) != text {
			t.Fatalf("reason %q is published as %q", reason, text)
		}
	}
	classes := map[Klass]string{
		KlassIntercepted: "intercepted", KlassBypassed: "bypassed", KlassOutOfScope: "out_of_scope",
		KlassNotTLS: "not_tls", KlassUnsupported: "unsupported", KlassUndecided: "undecided", KlassInvalid: "invalid",
	}
	for class, text := range classes {
		if class.String() != text {
			t.Fatalf("class %d is published as %q", class, text)
		}
	}
	if IdentityDomain.String() != "domain" || IdentityIP.String() != "ip" || IdentityNone.String() != "" {
		t.Fatal("identity kinds changed spelling")
	}
}

func TestProbeFromOutcomeCarriesOnlyTheProbeVerdict(t *testing.T) {
	probe := ProbeFromOutcome(tlsproxy.Outcome{
		Verdict: tlsproxy.VerdictClientHello,
		Hello:   tlsproxy.ClientHello{SNI: "Example.TEST"},
	})
	if probe.Verdict != tlsproxy.VerdictClientHello || probe.Reason != "" || probe.SNI != "Example.TEST" {
		t.Fatalf("probe = %+v", probe)
	}
}

package policy

import (
	"fmt"
	"net/netip"
	"testing"

	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/tlsproxy"
)

// The adapter is the connection state machine's only way in, so these cases pin
// what it forwards: the same class, identity and reason Decide produced, and
// nothing re-derived. The state machine's own tests cannot cover this, because
// they may not import this package (TLS-213).

func route(t *testing.T, policy Policy, address string, port int, outcome tlsproxy.Outcome) (tlsproxy.Route, engine.Code) {
	t.Helper()
	parsed, err := netip.ParseAddr(address)
	if err != nil {
		t.Fatalf("%q is not an address: %v", address, err)
	}
	return policy.Route(netip.AddrPortFrom(parsed, uint16(port)), "", outcome)
}

func hello(sni string) tlsproxy.Outcome {
	return tlsproxy.Outcome{Verdict: tlsproxy.VerdictClientHello, Hello: tlsproxy.ClientHello{SNI: sni, Records: 1}}
}

func TestRouteInterceptsWhatDecideIntercepts(t *testing.T) {
	frozen := mustParsePolicy(t, `{
		"schemaVersion": 1, "enabled": true, "hostScope": "ExplicitHosts",
		"candidatePorts": [443],
		"include": [{"kind": "exactDomain", "value": "example.test"}],
		"bypass": [], "applications": []
	}`)
	got, code := route(t, frozen, "198.51.100.7", 443, hello("example.test"))
	if code != engine.OK || !got.Intercept {
		t.Fatalf("route = %+v (%s), want an interception", got, code)
	}
	// The identity is the one the leaf is issued for, and the reason is the
	// policy's own fixed string.
	decision, decisionCode := decide(t, frozen, "198.51.100.7", 443, "", clientHello("example.test"))
	if decisionCode != engine.OK {
		t.Fatalf("decide = %s", decisionCode)
	}
	if got.Identity != decision.Identity || got.Reason != string(decision.Reason) {
		t.Fatalf("route = %+v, decide = %+v: the adapter changed the answer", got, decision)
	}
	if got.Identity != "example.test" || got.Reason != string(ReasonIncludedHost) {
		t.Fatalf("route = %+v", got)
	}
}

func TestRouteLeavesEveryNonInterceptionAlone(t *testing.T) {
	frozen := mustParsePolicy(t, `{
		"schemaVersion": 1, "enabled": true, "hostScope": "ExplicitHosts",
		"candidatePorts": [443],
		"include": [{"kind": "exactDomain", "value": "example.test"}],
		"bypass": [{"kind": "exactDomain", "value": "api.example.test"}],
		"applications": []
	}`)
	cases := []struct {
		name    string
		address string
		port    int
		outcome tlsproxy.Outcome
		reason  Reason
	}{
		{"an explicit bypass wins", "198.51.100.7", 443, hello("api.example.test"), ReasonBypassRule},
		{"a port outside the frozen set", "198.51.100.7", 8443, hello("example.test"), ReasonPortNotCandidate},
		{"a name no rule lists", "198.51.100.7", 443, hello("other.test"), ReasonNoIncludeMatch},
		{"a stream that is not TLS", "198.51.100.7", 443,
			tlsproxy.Outcome{Verdict: tlsproxy.VerdictNotTLS, Reason: "not_handshake_record"}, Reason("not_handshake_record")},
		{"a hello this engine will not serve", "198.51.100.7", 443,
			tlsproxy.Outcome{Verdict: tlsproxy.VerdictUnsupported, Reason: "no_supported_version"}, Reason("no_supported_version")},
		{"an undecided prefix", "198.51.100.7", 443,
			tlsproxy.Outcome{Verdict: tlsproxy.VerdictIncomplete, Reason: "probe_timeout"}, Reason("probe_timeout")},
	}
	for _, testCase := range cases {
		got, code := route(t, frozen, testCase.address, testCase.port, testCase.outcome)
		if code != engine.OK || got.Intercept {
			t.Fatalf("%s: route = %+v (%s), want a pass-through", testCase.name, got, code)
		}
		if got.Identity != "" {
			t.Fatalf("%s: a pass-through carries the identity %q", testCase.name, got.Identity)
		}
		if got.Reason != string(testCase.reason) {
			t.Fatalf("%s: reason = %q, want %q", testCase.name, got.Reason, testCase.reason)
		}
	}
}

func TestRouteReportsAnUnusableRequestInsteadOfGuessing(t *testing.T) {
	frozen := mustParsePolicy(t, `{
		"schemaVersion": 1, "enabled": true, "hostScope": "ExplicitHosts",
		"candidatePorts": [443],
		"include": [{"kind": "exactDomain", "value": "example.test"}],
		"bypass": [], "applications": []
	}`)
	// A probe result that contradicts its own contract, and a destination the
	// policy cannot decide about: both are INVALID_ARGUMENT, so the state
	// machine closes the connection instead of classifying it.
	if _, code := route(t, frozen, "198.51.100.7", 443,
		tlsproxy.Outcome{Verdict: tlsproxy.VerdictClientHello, Reason: "not_handshake_record"}); code != engine.InvalidArgument {
		t.Fatalf("a hello with a reason = %s, want INVALID_ARGUMENT", code)
	}
	if _, code := route(t, frozen, "0.0.0.0", 443, hello("example.test")); code != engine.InvalidArgument {
		t.Fatalf("an unspecified destination = %s, want INVALID_ARGUMENT", code)
	}
}

func TestRouteNeverChangesTheDestination(t *testing.T) {
	frozen := mustParsePolicy(t, `{
		"schemaVersion": 1, "enabled": true, "hostScope": "ExplicitHosts",
		"candidatePorts": [443],
		"include": [{"kind": "exactDomain", "value": "example.test"}],
		"bypass": [], "applications": []
	}`)
	// The route carries no address at all, which is the structural reason the
	// SNI can never replace the destination: there is no field for it.
	for _, outcome := range []tlsproxy.Outcome{hello("example.test"), hello(""), {Verdict: tlsproxy.VerdictNotTLS, Reason: "bad_record_version"}} {
		got, _ := route(t, frozen, "198.51.100.7", 443, outcome)
		if got.Identity != "" && got.Identity != "example.test" {
			t.Fatalf("route = %+v, want the asserted name or nothing", got)
		}
	}
}

func TestVPNRouterUsesScopeMembershipAndPreservesRestrictions(t *testing.T) {
	cases := []struct {
		name, scope, include, bypass string
		enabled                      bool
		port                         uint16
		outcome                      tlsproxy.Outcome
		intercept                    bool
		reason                       string
	}{
		{"selected apps", "SelectedApplicationsCandidates", `[]`, `[]`, true, 443, hello("example.test"), true, "selected_application"},
		{"TLS off", "SelectedApplicationsCandidates", `[]`, `[]`, false, 443, hello("example.test"), false, "disabled"},
		{"other port", "SelectedApplicationsCandidates", `[]`, `[]`, true, 80, hello("example.test"), false, "port_not_candidate"},
		{"bypass", "SelectedApplicationsCandidates", `[]`, `[{"kind":"exactDomain","value":"example.test"}]`, true, 443, hello("example.test"), false, "bypass_rule"},
		{"include narrows", "SelectedApplicationsCandidates", `[{"kind":"exactDomain","value":"other.test"}]`, `[]`, true, 443, hello("example.test"), false, "no_include_match"},
		{"explicit empty", "ExplicitHosts", `[]`, `[]`, true, 443, hello("example.test"), false, "no_include_match"},
		{"not TLS", "SelectedApplicationsCandidates", `[]`, `[]`, true, 443, tlsproxy.Outcome{Verdict: tlsproxy.VerdictNotTLS, Reason: "not_handshake_record"}, false, "not_handshake_record"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			frozen := mustParsePolicy(t, fmt.Sprintf(`{"schemaVersion":1,"enabled":%t,"hostScope":%q,
				"candidatePorts":[443],"include":%s,"bypass":%s,"applications":["com.example.first","com.example.second"]}`,
				tc.enabled, tc.scope, tc.include, tc.bypass))
			destination := netip.AddrPortFrom(netip.MustParseAddr("198.51.100.7"), tc.port)
			got, code := frozen.VPNRouter().Route(destination, "", tc.outcome)
			if code != engine.OK || got.Intercept != tc.intercept || got.Reason != tc.reason {
				t.Fatalf("VPN route = %+v (%s), want intercept=%t reason=%s", got, code, tc.intercept, tc.reason)
			}
			if tc.intercept {
				ordinary, code := frozen.Route(destination, "", tc.outcome)
				if code != engine.OK || ordinary.Intercept || ordinary.Reason != "application_not_selected" {
					t.Fatalf("unattributed non-VPN route widened: %+v (%s)", ordinary, code)
				}
				outside, code := frozen.VPNRouter().Route(destination, "com.example.unselected", tc.outcome)
				if code != engine.OK || outside.Intercept || outside.Reason != "application_not_selected" {
					t.Fatalf("an explicitly unselected application was admitted: %+v (%s)", outside, code)
				}
			}
		})
	}
}

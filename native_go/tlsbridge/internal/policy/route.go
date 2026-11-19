// The connection state machine's decision hook (TLS-213).
//
// The state machine lives in tlsproxy and the decision lives here, and Go
// forbids the cycle that would let tlsproxy call this package directly. So the
// adapter is on this side, where the dependency already points: one method that
// reduces a Decision to the three facts the state machine acts on. It adds no
// rule of its own — the class, the identity and the reason are the ones Decide
// already produced, so there is still exactly one decision maker (TLS-208).
package policy

import (
	"net/netip"

	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/tlsproxy"
)

var _ tlsproxy.Router = Policy{}

// Route is the connection state machine's entry point into this package. It is
// Decide with the probe's outcome reduced to the facts Decide consumes, and it
// keeps Decide's answer intact: the reason a connection was bypassed, was not
// covered, or was not TLS at all is the string the connection event carries.
//
// The destination is passed through unchanged, as it is everywhere else in this
// package: this method never returns an address to dial, so no rule can move a
// connection to another server.
func (p Policy) Route(destination netip.AddrPort, application string, outcome tlsproxy.Outcome) (tlsproxy.Route, engine.Code) {
	return p.route(destination, application, outcome, false)
}

// VPNRouter is for the per-run authenticated TUN/SOCKS gateway only. Android's
// VpnService enforces the same frozen application allowlist before traffic
// reaches it. This proves scope membership without claiming per-flow attribution
// or adding an unverified application identity to the gateway metadata.
func (p Policy) VPNRouter() tlsproxy.Router { return vpnRouter{policy: p} }

type vpnRouter struct{ policy Policy }

func (r vpnRouter) Route(destination netip.AddrPort, application string, outcome tlsproxy.Outcome) (tlsproxy.Route, engine.Code) {
	return r.policy.route(destination, application, outcome, true)
}

func (p Policy) route(destination netip.AddrPort, application string, outcome tlsproxy.Outcome, vpnScopeEnforced bool) (tlsproxy.Route, engine.Code) {
	decision, code := p.decide(Request{
		Destination: destination,
		Application: application,
		Probe:       ProbeFromOutcome(outcome),
	}, vpnScopeEnforced)
	if code != engine.OK {
		return tlsproxy.Route{}, code
	}
	return tlsproxy.Route{
		Intercept: decision.Intercepts(),
		Identity:  decision.Identity,
		Reason:    string(decision.Reason),
	}, engine.OK
}

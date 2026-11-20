package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"net/netip"
	"slices"
	"strings"
	"unicode/utf8"

	"com.layeranalyzer/tlsbridge/internal/engine"
	"com.layeranalyzer/tlsbridge/internal/tlsproxy"
)

// MaxPolicyBytes bounds one frozen policy. It is the same bound
// engine.ParseConfig applies to the whole start config, so a policy that parses
// there parses here.
const MaxPolicyBytes = 65536

// Scope is the C04 host scope of a frozen policy.
type Scope string

const (
	// ScopeExplicitHosts decrypts only what the include rules name. An empty
	// include list therefore decrypts no domain at all.
	ScopeExplicitHosts Scope = "ExplicitHosts"
	// ScopeSelectedApplicationsCandidates decrypts the VPN allowlist's own
	// traffic, and only with a non-empty allowlist.
	ScopeSelectedApplicationsCandidates Scope = "SelectedApplicationsCandidates"
)

// Policy is one capture's frozen decision input. Every field is unexported and
// set only by ParsePolicy, so a capture cannot have its rules changed while it
// is running: a settings change produces a new policy for the next capture.
// The zero value is a disabled policy, which is also what an unassembled or
// failed configuration gets.
type Policy struct {
	enabled      bool
	scope        Scope
	ports        map[uint16]struct{}
	include      []Rule
	bypass       []Rule
	applications map[string]struct{}
}

// Enabled reports whether interception is switched on at all.
func (p Policy) Enabled() bool { return p.enabled }

// Scope reports the frozen host scope.
func (p Policy) Scope() Scope { return p.scope }

// CandidatePorts reports the frozen candidate ports in ascending order.
func (p Policy) CandidatePorts() []uint16 {
	ports := make([]uint16, 0, len(p.ports))
	for port := range p.ports {
		ports = append(ports, port)
	}
	slices.Sort(ports)
	return ports
}

// Include reports the frozen include rules, in the order the user's settings
// listed them. Rule order never changes a decision.
func (p Policy) Include() []Rule { return append([]Rule(nil), p.include...) }

// Bypass reports the frozen bypass rules.
func (p Policy) Bypass() []Rule { return append([]Rule(nil), p.bypass...) }

// Applications reports the frozen VPN allowlist the application scope matches
// against, in ascending order.
func (p Policy) Applications() []string {
	applications := make([]string, 0, len(p.applications))
	for application := range p.applications {
		applications = append(applications, application)
	}
	slices.Sort(applications)
	return applications
}

// policyJSON mirrors the frozen form Kotlin writes. Pointers distinguish a
// missing field from an empty one: a truncated or hand-edited config must fail
// rather than fall back to a default that intercepts something else.
type policyJSON struct {
	SchemaVersion  *int        `json:"schemaVersion"`
	Enabled        *bool       `json:"enabled"`
	HostScope      *string     `json:"hostScope"`
	CandidatePorts *[]int      `json:"candidatePorts"`
	Include        *[]ruleJSON `json:"include"`
	Bypass         *[]ruleJSON `json:"bypass"`
	Applications   *[]string   `json:"applications"`
}

type ruleJSON struct {
	Kind  string `json:"kind"`
	Value string `json:"value"`
}

// ParsePolicy reads the frozen policy from the engine start config's "settings"
// object. It is strict on purpose: unknown fields, a missing field, a
// non-canonical rule and an application scope without an allowlist are all
// rejected, because a policy is enforced against real traffic and a config this
// layer cannot interpret exactly is a configuration error, not a passthrough.
func ParsePolicy(settings []byte) (Policy, engine.Code) {
	if len(settings) == 0 || len(settings) > MaxPolicyBytes || !utf8.Valid(settings) {
		return Policy{}, engine.InvalidArgument
	}
	var raw policyJSON
	decoder := json.NewDecoder(bytes.NewReader(settings))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&raw) != nil {
		return Policy{}, engine.InvalidArgument
	}
	if decoder.Decode(new(any)) != io.EOF {
		return Policy{}, engine.InvalidArgument
	}
	if raw.SchemaVersion == nil || *raw.SchemaVersion != 1 || raw.Enabled == nil || raw.HostScope == nil ||
		raw.CandidatePorts == nil || raw.Include == nil || raw.Bypass == nil || raw.Applications == nil {
		return Policy{}, engine.InvalidArgument
	}
	scope := Scope(*raw.HostScope)
	if scope != ScopeExplicitHosts && scope != ScopeSelectedApplicationsCandidates {
		return Policy{}, engine.InvalidArgument
	}
	frozen := Policy{
		enabled: *raw.Enabled, scope: scope,
		ports:        make(map[uint16]struct{}, len(*raw.CandidatePorts)),
		applications: make(map[string]struct{}, len(*raw.Applications)),
	}
	if code := frozen.parsePorts(*raw.CandidatePorts); code != engine.OK {
		return Policy{}, code
	}
	if code := parseRules(&frozen.include, *raw.Include); code != engine.OK {
		return Policy{}, code
	}
	if code := parseRules(&frozen.bypass, *raw.Bypass); code != engine.OK {
		return Policy{}, code
	}
	if code := frozen.parseApplications(*raw.Applications); code != engine.OK {
		return Policy{}, code
	}
	return frozen, engine.OK
}

// parsePorts requires strictly ascending ports, which is the order Kotlin's
// normalizer emits; a duplicate or an unordered list means the config is not
// the frozen form this layer validated.
func (p *Policy) parsePorts(ports []int) engine.Code {
	previous := 0
	for _, port := range ports {
		if port < 1 || port > 65535 || port <= previous {
			return engine.InvalidArgument
		}
		previous = port
		p.ports[uint16(port)] = struct{}{}
	}
	return engine.OK
}

// parseRules requires each rule to be canonical and unique. One rule may appear
// in both lists: the bypass list wins, and that conflict is the user's explicit
// decision, not a configuration error.
func parseRules(destination *[]Rule, rules []ruleJSON) engine.Code {
	seen := make(map[string]struct{}, len(rules))
	for _, entry := range rules {
		kind, code := ParseRuleKind(entry.Kind)
		if code != engine.OK {
			return code
		}
		rule, code := ParseRule(kind, entry.Value)
		if code != engine.OK {
			return code
		}
		if _, duplicate := seen[rule.String()]; duplicate {
			return engine.InvalidArgument
		}
		seen[rule.String()] = struct{}{}
		*destination = append(*destination, rule)
	}
	return engine.OK
}

// parseApplications requires unique, non-blank package names and, for the
// application scope, at least one of them. Blank names are never kept: an
// unspecified application must not become a match for every application.
func (p *Policy) parseApplications(applications []string) engine.Code {
	for _, application := range applications {
		if strings.TrimSpace(application) == "" {
			return engine.InvalidArgument
		}
		if _, duplicate := p.applications[application]; duplicate {
			return engine.InvalidArgument
		}
		p.applications[application] = struct{}{}
	}
	if p.scope == ScopeSelectedApplicationsCandidates && len(p.applications) == 0 {
		return engine.InvalidArgument
	}
	return engine.OK
}

// Prefilter is the port and application screen the SOCKS hop applies before it
// reserves a slot or probes anything. It is a necessary condition only: passing
// it says nothing about the name, which is not known until the ClientHello.
type Prefilter int

const (
	// PrefilterCandidate means the connection is worth probing.
	PrefilterCandidate Prefilter = iota
	// PrefilterDisabled means interception is switched off.
	PrefilterDisabled
	// PrefilterPortNotCandidate means the destination port is not a candidate.
	PrefilterPortNotCandidate
	// PrefilterApplicationNotSelected means the application scope is in force
	// and this connection's application is not in the allowlist.
	PrefilterApplicationNotSelected
)

func (p Prefilter) String() string { return string(p.reason()) }

// reason is the fixed reason string the prefilter result publishes, so the
// SOCKS hop and the connection event use one spelling.
func (p Prefilter) reason() Reason {
	switch p {
	case PrefilterCandidate:
		return ReasonCandidate
	case PrefilterDisabled:
		return ReasonDisabled
	case PrefilterPortNotCandidate:
		return ReasonPortNotCandidate
	default:
		return ReasonApplicationNotSelected
	}
}

// Reason strings are fixed. They reach the connection event log and must never
// carry a stream byte, a name, a length or platform error text. The reasons
// this package forwards from the probe are fixed by tlsproxy in the same way.
type Reason string

const (
	ReasonCandidate              Reason = "candidate"
	ReasonDisabled               Reason = "disabled"
	ReasonPortNotCandidate       Reason = "port_not_candidate"
	ReasonApplicationNotSelected Reason = "application_not_selected"
	ReasonBypassRule             Reason = "bypass_rule"
	ReasonIncludedHost           Reason = "included_host"
	ReasonSelectedApplication    Reason = "selected_application"
	ReasonNoIncludeMatch         Reason = "no_include_match"
)

// Prefilter applies the port and application screen. The application is the
// VPN allowlist entry the connection belongs to; an unknown or missing value is
// never widened to "every application".
func (p Policy) Prefilter(port uint16, application string) Prefilter {
	return p.prefilter(port, application, false)
}

// vpnScopeEnforced is only set by the authenticated VPN gateway's router.
// Scope membership is distinct from attribution to an individual application.
func (p Policy) prefilter(port uint16, application string, vpnScopeEnforced bool) Prefilter {
	if !p.enabled {
		return PrefilterDisabled
	}
	if _, candidate := p.ports[port]; !candidate {
		return PrefilterPortNotCandidate
	}
	if p.scope == ScopeSelectedApplicationsCandidates {
		if _, selected := p.applications[application]; !selected && !(vpnScopeEnforced && application == "" && len(p.applications) > 0) {
			return PrefilterApplicationNotSelected
		}
	}
	return PrefilterCandidate
}

// Probe is what the ClientHello probe concluded, reduced to the three inputs
// this package needs. Verdict and Reason are tlsproxy's taxonomy: the probe is
// the only layer that reads bytes, and re-deriving its conclusion here would be
// a second classification.
type Probe struct {
	Verdict tlsproxy.Verdict
	// Reason is the probe's fixed reason code. It is empty exactly when the
	// verdict is tlsproxy.VerdictClientHello.
	Reason string
	// SNI is the server name exactly as the client sent it, or "" when the
	// client sent none. It is normalized here, not by the probe.
	SNI string
}

// ProbeFromOutcome reduces one probe result to a Probe.
func ProbeFromOutcome(outcome tlsproxy.Outcome) Probe {
	return Probe{Verdict: outcome.Verdict, Reason: outcome.Reason, SNI: outcome.Hello.SNI}
}

// Request is one connection's decision input. Destination is the original
// destination the socket was opened to; it is never derived from the SNI and is
// never replaced by one, so a policy can never move a connection to another
// server.
type Request struct {
	Destination netip.AddrPort
	// Application is the VPN allowlist entry this connection belongs to, or ""
	// when the platform cannot attribute it. SOCKS5 carries no application
	// identity, so this is never guessed from a source address or a UID.
	Application string
	Probe       Probe
}

// Klass is what the connection is, in the terms the connection event uses. The
// classes stay apart so a passthrough caused by the user's rule is never
// reported as a protocol the engine does not support, and neither is reported
// as a failure.
type Klass int

const (
	// KlassIntercepted means both TLS sides are terminated for this connection.
	KlassIntercepted Klass = iota
	// KlassBypassed means an explicit bypass rule matched.
	KlassBypassed
	// KlassOutOfScope means the user's policy does not cover this connection:
	// interception is off, the port is not a candidate, the application is not
	// selected, or no rule matched.
	KlassOutOfScope
	// KlassNotTLS means the probe read a prefix that cannot be client TLS.
	KlassNotTLS
	// KlassUnsupported means the stream is TLS but this engine does not serve it.
	KlassUnsupported
	// KlassUndecided means the probe ran out of budget, deadline or stream.
	KlassUndecided
	// KlassInvalid is never returned as a decision: it labels the error case, in
	// which the caller must close the connection rather than guess.
	KlassInvalid
)

func (k Klass) String() string {
	switch k {
	case KlassIntercepted:
		return "intercepted"
	case KlassBypassed:
		return "bypassed"
	case KlassOutOfScope:
		return "out_of_scope"
	case KlassNotTLS:
		return "not_tls"
	case KlassUnsupported:
		return "unsupported"
	case KlassUndecided:
		return "undecided"
	default:
		return "invalid"
	}
}

// IdentityKind tells the handshake layer how to name the connection when it
// issues the downstream certificate.
type IdentityKind int

const (
	IdentityNone IdentityKind = iota
	// IdentityDomain means the client asserted a usable name and the leaf needs
	// that DNS SAN.
	IdentityDomain
	// IdentityIP means no usable name was asserted and the leaf needs an IP SAN
	// for the destination the connection was actually opened to.
	IdentityIP
)

func (k IdentityKind) String() string {
	switch k {
	case IdentityDomain:
		return "domain"
	case IdentityIP:
		return "ip"
	default:
		return ""
	}
}

// Decision is the frozen answer for one connection. It carries no address: the
// destination used for dialing stays the caller's, unchanged.
type Decision struct {
	Klass  Klass
	Reason Reason
	// Identity is the canonical name or address the downstream leaf must be
	// issued for. It is set exactly when Klass is KlassIntercepted.
	Identity     string
	IdentityKind IdentityKind
}

// Intercepts reports whether both TLS sides must be terminated.
func (d Decision) Intercepts() bool { return d.Klass == KlassIntercepted }

// Decide is the only decision entry point. It returns a decision and, only for
// a request that contradicts the probe's own contract or an unusable
// destination, engine.InvalidArgument — in which case the decision is not to be
// used and the caller closes the connection.
//
// The order is fixed: the prefilter's conditions first, then what the probe
// read, then the user's rules. A connection whose port is not a candidate is
// reported as out of scope even if it carried a ClientHello, because the SOCKS
// hop should have kept it out of this path altogether.
func (p Policy) Decide(request Request) (Decision, engine.Code) {
	return p.decide(request, false)
}

func (p Policy) decide(request Request, vpnScopeEnforced bool) (Decision, engine.Code) {
	if !request.Destination.IsValid() || request.Destination.Addr().Zone() != "" {
		return Decision{Klass: KlassInvalid}, engine.InvalidArgument
	}
	address := request.Destination.Addr().Unmap()
	if address.IsUnspecified() || address.IsMulticast() {
		return Decision{Klass: KlassInvalid}, engine.InvalidArgument
	}
	if screen := p.prefilter(request.Destination.Port(), request.Application, vpnScopeEnforced); screen != PrefilterCandidate {
		return Decision{Klass: KlassOutOfScope, Reason: screen.reason()}, engine.OK
	}
	switch request.Probe.Verdict {
	case tlsproxy.VerdictClientHello:
		if request.Probe.Reason != "" {
			return Decision{Klass: KlassInvalid}, engine.InvalidArgument
		}
	case tlsproxy.VerdictNotTLS:
		if request.Probe.Reason == "" {
			return Decision{Klass: KlassInvalid}, engine.InvalidArgument
		}
		return Decision{Klass: KlassNotTLS, Reason: Reason(request.Probe.Reason)}, engine.OK
	case tlsproxy.VerdictUnsupported:
		if request.Probe.Reason == "" {
			return Decision{Klass: KlassInvalid}, engine.InvalidArgument
		}
		return Decision{Klass: KlassUnsupported, Reason: Reason(request.Probe.Reason)}, engine.OK
	case tlsproxy.VerdictIncomplete:
		if request.Probe.Reason == "" {
			return Decision{Klass: KlassInvalid}, engine.InvalidArgument
		}
		return Decision{Klass: KlassUndecided, Reason: Reason(request.Probe.Reason)}, engine.OK
	default:
		return Decision{Klass: KlassInvalid}, engine.InvalidArgument
	}

	identity := identityFor(request.Probe.SNI, address)
	// An explicit bypass is checked before anything can be intercepted, so a
	// name listed in both places bypasses.
	if matches(p.bypass, identity) {
		return Decision{Klass: KlassBypassed, Reason: ReasonBypassRule}, engine.OK
	}
	switch p.scope {
	case ScopeSelectedApplicationsCandidates:
		// The prefilter already required a selected application. An include
		// list, when the user set one, narrows this scope further rather than
		// replacing it: both the selected application and a listed name must
		// allow the connection, so no combination of settings intercepts more
		// than the user selected in either one.
		if len(p.include) == 0 {
			return intercept(identity, ReasonSelectedApplication), engine.OK
		}
		if !matches(p.include, identity) {
			return Decision{Klass: KlassOutOfScope, Reason: ReasonNoIncludeMatch}, engine.OK
		}
		return intercept(identity, ReasonIncludedHost), engine.OK
	default:
		if matches(p.include, identity) {
			return intercept(identity, ReasonIncludedHost), engine.OK
		}
		return Decision{Klass: KlassOutOfScope, Reason: ReasonNoIncludeMatch}, engine.OK
	}
}

// identity is the one thing a rule set is matched against. It is chosen once,
// before matching, so a single rule can only ever mean one thing.
type identity struct {
	kind IdentityKind
	name string
	addr netip.Addr
}

// identityFor picks the connection identity. A usable asserted name is the
// identity, because that is what the client will verify the proxy certificate
// against. When there is no usable name the destination address is the
// identity, which is the only case C04 allows an IP SAN for. The address is
// never taken from the SNI.
func identityFor(sni string, destination netip.Addr) identity {
	if name, ok := canonicalSNI(sni); ok {
		return identity{kind: IdentityDomain, name: name}
	}
	return identity{kind: IdentityIP, addr: destination}
}

// canonicalSNI applies the repository's single name rule and then the case
// folding C04 assigns to this layer. A name that is not usable, or that is an
// address literal where RFC 6066 requires a name, is reported as no name at
// all: it is never repaired into a name the client did not send.
func canonicalSNI(sni string) (string, bool) {
	if sni == "" {
		return "", false
	}
	name, code := engine.CanonicalName(sni)
	if code != engine.OK {
		return "", false
	}
	name = strings.ToLower(name)
	if _, err := netip.ParseAddr(name); err == nil {
		return "", false
	}
	return name, true
}

// matches reports whether any rule in the list applies to the identity. Domain
// rules never match an address identity and address rules never match a name
// identity, so a suffix rule cannot be pointed at an address and an address
// rule cannot be satisfied by a name the client chose.
func matches(rules []Rule, subject identity) bool {
	for _, rule := range rules {
		if subject.kind == IdentityDomain && rule.matchesName(subject.name) {
			return true
		}
		if subject.kind == IdentityIP && rule.matchesAddress(subject.addr) {
			return true
		}
	}
	return false
}

func intercept(subject identity, reason Reason) Decision {
	decision := Decision{Klass: KlassIntercepted, Reason: reason, IdentityKind: subject.kind}
	if subject.kind == IdentityDomain {
		decision.Identity = subject.name
	} else {
		decision.Identity = subject.addr.String()
	}
	return decision
}

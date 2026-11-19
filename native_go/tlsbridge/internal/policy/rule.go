// Package policy is the single connection interception decision maker. Kotlin
// normalizes the user's settings and freezes them (C04, §10.1); this package is
// the only place that turns a frozen policy plus one connection's facts into
// intercept, bypass or passthrough, so the SOCKS hop and the TLS hop can never
// apply two different rule orders.
package policy

import (
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// RuleKind is the closed set of rule shapes the first version supports. C04
// allows an exact name and an explicit subdomain wildcard; both are matched by
// structure, never by arbitrary suffix text, and no regular expression form
// exists that could match more than the user selected.
type RuleKind string

const (
	// RuleExactDomain matches one canonical name and nothing else. The name
	// "example.test" does not match "www.example.test".
	RuleExactDomain RuleKind = "exactDomain"
	// RuleSubdomains matches true subdomains of one canonical name: it matches
	// "www.example.test" and "a.b.example.test", but neither the root name
	// "example.test" nor the different name "badexample.test".
	RuleSubdomains RuleKind = "subdomains"
	// RuleExactIP matches one address by value, so a rule and an identity that
	// spell the same address differently still match.
	RuleExactIP RuleKind = "exactIp"
)

// Rule is one frozen include or bypass entry. Value is the canonical text
// Kotlin's normalizer produced; it is never rewritten here.
type Rule struct {
	Kind  RuleKind
	Value string

	// address backs RuleExactIP so matching compares parsed values. The frozen
	// text and the identity text do not have to agree byte for byte: the
	// normalizer emits eight lower-case hex groups without "::" compression
	// while an identity is rendered by netip, and both name the same address.
	address netip.Addr
}

func (r Rule) String() string { return string(r.Kind) + ":" + r.Value }

// ParseRule validates one frozen rule. It is a validator, not a second
// normalizer: IDNA mapping, case folding and one trailing dot are Kotlin's
// single rule (engine.CanonicalName's sibling), so anything that is not already
// in that canonical form is rejected rather than silently reinterpreted.
func ParseRule(kind RuleKind, value string) (Rule, engine.Code) {
	switch kind {
	case RuleExactDomain, RuleSubdomains:
		if !canonicalDomain(value) {
			return Rule{}, engine.InvalidArgument
		}
		return Rule{Kind: kind, Value: value}, engine.OK
	case RuleExactIP:
		address, ok := canonicalAddress(value)
		if !ok {
			return Rule{}, engine.InvalidArgument
		}
		return Rule{Kind: kind, Value: value, address: address}, engine.OK
	default:
		return Rule{}, engine.InvalidArgument
	}
}

// ParseRuleKind maps the wire name of a rule kind, so a frozen config and a
// test fixture are read the same way.
func ParseRuleKind(name string) (RuleKind, engine.Code) {
	switch RuleKind(name) {
	case RuleExactDomain, RuleSubdomains, RuleExactIP:
		return RuleKind(name), engine.OK
	default:
		return "", engine.InvalidArgument
	}
}

// matchesName reports whether a canonical domain identity satisfies the rule.
func (r Rule) matchesName(name string) bool {
	switch r.Kind {
	case RuleExactDomain:
		return r.Value == name
	case RuleSubdomains:
		// The separator is what keeps "*.example.test" away from both the root
		// name and "badexample.test".
		return strings.HasSuffix(name, "."+r.Value)
	default:
		return false
	}
}

// matchesAddress reports whether a destination satisfies the rule. It compares
// the parsed address, so the rule's frozen spelling and the identity's
// rendering are both accepted for the same address.
func (r Rule) matchesAddress(address netip.Addr) bool {
	return r.Kind == RuleExactIP && r.address == address
}

// canonicalDomain reports whether value is exactly the text IDN.toASCII with
// STD3 rules, lower-cased with one trailing dot removed, produces: lower-case
// LDH labels, 1..63 bytes each, 253 in total, no empty label and no leading or
// trailing hyphen. An all-digits-and-dots value is an address attempt and never
// a domain, which is what keeps a suffix rule from ever matching an address.
func canonicalDomain(value string) bool {
	if value == "" || len(value) > engine.MaxNameLength {
		return false
	}
	numeric := true
	for index := 0; index < len(value); index++ {
		if digitOrDot(value[index]) {
			continue
		}
		numeric = false
		break
	}
	if numeric {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > engine.MaxLabelLength {
			return false
		}
		if label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			if !lowercaseOrDigit(label[index]) && label[index] != '-' {
				return false
			}
		}
	}
	return true
}

// canonicalAddress validates one frozen address literal. IPv4 keeps its dotted
// form; IPv6 must be the fully expanded lower-case form the normalizer emits,
// so "::1" and "2001:DB8::1" are rejected as non-canonical rather than accepted
// as a second spelling of an address the policy already carries.
func canonicalAddress(value string) (netip.Addr, bool) {
	address, err := netip.ParseAddr(value)
	if err != nil || address.Zone() != "" {
		return netip.Addr{}, false
	}
	if address.Is4() {
		return address, address.String() == value
	}
	return address, expandedAddress(address) == value
}

// expandedAddress writes all eight groups in lower-case hex with no leading
// zeros, without the "::" compression RFC 5952 permits.
func expandedAddress(address netip.Addr) string {
	raw := address.As16()
	var text strings.Builder
	for group := 0; group < 8; group++ {
		if group > 0 {
			text.WriteByte(':')
		}
		fmt.Fprintf(&text, "%x", binary.BigEndian.Uint16(raw[group*2:group*2+2]))
	}
	return text.String()
}

func digitOrDot(c byte) bool {
	return c >= '0' && c <= '9' || c == '.'
}

func lowercaseOrDigit(c byte) bool {
	return c >= 'a' && c <= 'z' || c >= '0' && c <= '9'
}

package engine

import (
	"net"
	"strings"
)

// Name limits: one DNS name, and one label inside it. They are the same limits
// the platform verifier and a leaf SAN are checked against, so a name accepted
// as an upstream reference identity is also expressible as a downstream
// certificate SAN and vice versa.
const (
	MaxNameLength  = 253
	MaxLabelLength = 63
)

// CanonicalName validates a reference name or IP literal and removes one
// trailing dot.
//
// It is the repository's single normalization rule: upstream identity
// verification (TLS-204), the interception policy (TLS-208) and leaf SANs
// (TLS-205) all call this rather than each keeping a variant, which would let
// two halves of one connection disagree about the same name. It lives here,
// below both, so neither has to import the other.
//
// Only the trailing dot is rewritten. Case, IDNA and wildcard policy stay with
// TLS-208, so an exact name, a bare IP literal, a port, a wildcard or a
// bracketed literal is either taken as given or rejected, never reinterpreted.
func CanonicalName(name string) (string, Code) {
	if name == "" || len(name) > MaxNameLength {
		return "", InvalidArgument
	}
	for index := 0; index < len(name); index++ {
		if name[index] < 0x20 || name[index] > 0x7e {
			return "", InvalidArgument
		}
	}
	canonical := strings.TrimSuffix(name, ".")
	if canonical == "" || len(canonical) > MaxNameLength {
		return "", InvalidArgument
	}
	if net.ParseIP(canonical) != nil {
		return canonical, OK
	}
	for _, label := range strings.Split(canonical, ".") {
		if len(label) == 0 || len(label) > MaxLabelLength {
			return "", InvalidArgument
		}
		if !isAlphanumeric(label[0]) || !isAlphanumeric(label[len(label)-1]) {
			return "", InvalidArgument
		}
		for index := 1; index < len(label)-1; index++ {
			if !isAlphanumeric(label[index]) && label[index] != '-' && label[index] != '_' {
				return "", InvalidArgument
			}
		}
	}
	return canonical, OK
}

func isAlphanumeric(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9')
}

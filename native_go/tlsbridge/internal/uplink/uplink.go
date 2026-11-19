// Package uplink is the production upstream socket and name-resolution path.
//
// Every real outbound socket is protected and bound on the captured physical
// network from inside net.Dialer's synchronous Control callback, before
// connect(), through the same C05 platform callbacks the gateway uses. Names
// are resolved only by the selected Android network's callback; Go's default
// resolver is never consulted, and an already numeric destination is never
// re-resolved. This package opens no socket and starts no listener until
// Dial/DialHost is called, and it installs no production factory.
package uplink

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net"
	"net/netip"
	"strings"
	"syscall"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

const (
	// DefaultTimeout is C10's upstream TCP budget, used when the caller's
	// context carries no earlier deadline. It is a ceiling, never an extra
	// budget: an earlier context deadline always wins.
	DefaultTimeout = 10 * time.Second
	// MaxNameLength is the DNS name limit, and matches the ABI's host buffer.
	MaxNameLength = 253
	// MaxResolveBytes bounds one platform resolve response. The ABI reserves
	// 16 KiB for it, so nothing larger can arrive and nothing larger is parsed.
	MaxResolveBytes = 16384
	// MaxAttempts bounds the protected dial attempts of one connection. The
	// resolve response is already capped at 16 KiB, but a pathologically long
	// address list must not turn a single connection into unbounded
	// protect/bind/connect work; the ceiling matches the ABI's 16-certificate
	// array limit.
	MaxAttempts = 16
)

// Callbacks is the admission-gated platform entry point for prepare/bind and
// resolution. *engine.Callbacks implements it: once shutdown has closed
// admission a call returns CANCELLED and opens no socket, and shutdown waits
// for an in-flight call to return before the caller releases its GlobalRef.
type Callbacks interface {
	Call(func(engine.Platform) engine.Code) engine.Code
}

var _ Callbacks = (*engine.Callbacks)(nil)

// Dialer protects, binds and connects upstream sockets for one captured network
// generation. It holds no socket and no per-connection state, so it is safe for
// concurrent use; every call re-creates, re-protects and re-binds each socket.
type Dialer struct {
	callbacks  Callbacks
	generation int64
	timeout    time.Duration
}

// New validates the platform gate and the time budget. A zero timeout selects
// DefaultTimeout; a larger one is rejected rather than silently clamped.
func New(callbacks Callbacks, networkGeneration int64, timeout time.Duration) (*Dialer, engine.Code) {
	if callbacks == nil || networkGeneration < 0 || timeout < 0 || timeout > DefaultTimeout {
		return nil, engine.InvalidArgument
	}
	if timeout == 0 {
		timeout = DefaultTimeout
	}
	return &Dialer{callbacks: callbacks, generation: networkGeneration, timeout: timeout}, engine.OK
}

// Generation is the captured network generation passed to every callback; the
// platform side rejects a stale generation without protecting a socket.
func (d *Dialer) Generation() int64 { return d.generation }

// Resolve returns the validated addresses of a destination on the selected
// network. A numeric destination is returned as a single unmapped address and
// never reaches the resolver callback - an original destination IP is not
// re-resolved. Any other name goes only to the platform callback: there is no
// fallback to Go's resolver, so an empty or failed answer is an error, not a
// lookup somewhere else.
func (d *Dialer) Resolve(ctx context.Context, host string) ([]netip.Addr, engine.Code) {
	if ctx == nil {
		return nil, engine.InvalidArgument
	}
	if address, err := netip.ParseAddr(host); err == nil {
		return literal(address)
	}
	name, code := validName(host)
	if code != engine.OK {
		return nil, code
	}
	// Normalization can turn a trailing-dot literal back into a literal.
	if address, err := netip.ParseAddr(name); err == nil {
		return literal(address)
	}
	if ctx.Err() != nil {
		return nil, engine.Cancelled
	}
	var response []byte
	code = d.callbacks.Call(func(platform engine.Platform) engine.Code {
		data, status := platform.ResolveHost(name, d.generation)
		response = data
		return status
	})
	if code == engine.OK {
		return parseAddresses(response)
	}
	if !validCode(code) {
		return nil, engine.IOError
	}
	return nil, code
}

// Dial connects to an already resolved numeric destination. It resolves
// nothing, so the caller controls whether a name or a literal is used, and the
// literal that SOCKS actually received is preserved.
func (d *Dialer) Dial(ctx context.Context, destination netip.AddrPort) (net.Conn, engine.Code) {
	if ctx == nil {
		return nil, engine.InvalidArgument
	}
	target, code := numeric(destination)
	if code != engine.OK {
		return nil, code
	}
	bounded, cancel := d.bounded(ctx)
	defer cancel()
	return d.dial(bounded, target)
}

// DialHost is the path for a destination that really is a name, such as an
// explicit non-application-scoped rule. It resolves through the selected
// network and tries the validated addresses in order, each on its own
// protected socket, inside one shared time budget.
func (d *Dialer) DialHost(ctx context.Context, host string, port uint16) (net.Conn, engine.Code) {
	if ctx == nil || port == 0 {
		return nil, engine.InvalidArgument
	}
	addresses, code := d.Resolve(ctx, host)
	if code != engine.OK {
		return nil, code
	}
	bounded, cancel := d.bounded(ctx)
	defer cancel()
	last := engine.IOError
	for _, address := range addresses[:min(len(addresses), MaxAttempts)] {
		if bounded.Err() != nil {
			return nil, engine.Cancelled
		}
		connection, code := d.dial(bounded, netip.AddrPortFrom(address, port))
		if code == engine.OK {
			return connection, engine.OK
		}
		last = code
		// Only a plain I/O failure is worth another address. A rejected
		// protect/bind, a stale or changed network, or closed admission applies
		// to the whole connection: every remaining attempt is not started, so
		// nothing is left outstanding.
		if code != engine.IOError {
			return nil, code
		}
	}
	return nil, last
}

// bounded caps a call at the Dialer's budget without extending an earlier
// caller deadline, so one DialHost never spends more than one budget.
func (d *Dialer) bounded(ctx context.Context) (context.Context, context.CancelFunc) {
	if deadline, ok := ctx.Deadline(); ok && time.Until(deadline) <= d.timeout {
		return context.WithCancel(ctx)
	}
	return context.WithTimeout(ctx, d.timeout)
}

func (d *Dialer) dial(ctx context.Context, target netip.AddrPort) (net.Conn, engine.Code) {
	network := "tcp6"
	if target.Addr().Is4() {
		network = "tcp4"
	}
	// Control runs once per created socket, after the descriptor exists and
	// before connect(); a non-nil error there aborts the attempt and Go closes
	// the socket. Only validated numeric addresses reach this point, so the
	// standard library performs no resolution of its own.
	connector := &net.Dialer{Control: d.control}
	connection, err := connector.DialContext(ctx, network, target.String())
	if err != nil {
		return nil, classify(err)
	}
	if ctx.Err() != nil {
		// A socket that completes after the budget expired must not be used.
		_ = connection.Close()
		return nil, engine.Cancelled
	}
	return connection, engine.OK
}

func (d *Dialer) control(_, _ string, raw syscall.RawConn) error {
	if raw == nil {
		return failure{code: engine.IOError}
	}
	prepared := engine.IOError
	if err := raw.Control(func(fd uintptr) { prepared = d.prepare(fd) }); err != nil {
		return failure{code: engine.IOError}
	}
	if prepared != engine.OK {
		return failure{code: prepared}
	}
	return nil
}

// prepare must stay synchronous: the descriptor is only valid inside Control,
// and the platform callback copies it for binding before returning. A callback
// that did not return OK, or that shutdown refused, must never be followed by
// a connect. A panic in the callback is contained here, like TLS-005's probe:
// the attempt fails and Go closes the socket instead of unwinding the dial.
func (d *Dialer) prepare(fd uintptr) (code engine.Code) {
	defer func() {
		if recover() != nil {
			code = engine.IOError
		}
	}()
	if fd > math.MaxInt32 {
		// The C05 ABI carries the descriptor as int32_t; a value that does not
		// fit must fail rather than truncate into another descriptor.
		return engine.IOError
	}
	code = d.callbacks.Call(func(platform engine.Platform) engine.Code {
		return platform.PrepareSocket(int(fd), d.generation)
	})
	if !validCode(code) {
		return engine.IOError
	}
	return code
}

// failure carries a platform code unchanged out of net.Dialer.Control. The
// standard library wraps it in *OpError, which unwraps back to this value.
type failure struct{ code engine.Code }

func (failure) Error() string { return "upstream socket preparation rejected" }

func classify(err error) engine.Code {
	var rejected failure
	if errors.As(err, &rejected) && validCode(rejected.code) {
		return rejected.code
	}
	if errors.Is(err, context.Canceled) {
		return engine.Cancelled
	}
	// A connect deadline is an I/O failure, matching TLS-005's verified mapping.
	return engine.IOError
}

func validCode(code engine.Code) bool {
	return code >= engine.OK && code <= engine.CaptureContextMissing
}

// numeric accepts only an already resolved unicast address without a scope
// zone, and unmaps an IPv4-in-IPv6 form so the dial really uses tcp4.
func numeric(destination netip.AddrPort) (netip.AddrPort, engine.Code) {
	address := destination.Addr().Unmap()
	if !address.IsValid() || address.Zone() != "" || address.IsUnspecified() ||
		address.IsMulticast() || destination.Port() == 0 {
		return netip.AddrPort{}, engine.InvalidArgument
	}
	return netip.AddrPortFrom(address, destination.Port()), engine.OK
}

func literal(address netip.Addr) ([]netip.Addr, engine.Code) {
	// Port 1 is a placeholder: only the address is validated here.
	target, code := numeric(netip.AddrPortFrom(address, 1))
	if code != engine.OK {
		return nil, code
	}
	return []netip.Addr{target.Addr()}, engine.OK
}

// validName accepts only a plain ASCII name: one trailing dot is removed, and
// every remaining label must begin and end alphanumeric with at most 63 bytes
// and only letters, digits, '-' or '_' inside. Anything else - control
// characters, non-ASCII, port separators, paths, empty labels - is rejected
// before it reaches the platform resolver. Case is left to the caller's policy
// layer; the name is forwarded exactly as it was given.
func validName(host string) (string, engine.Code) {
	if host == "" || len(host) > MaxNameLength {
		return "", engine.InvalidArgument
	}
	name := strings.TrimSuffix(host, ".")
	if name == "" || len(name) > MaxNameLength {
		return "", engine.InvalidArgument
	}
	for _, label := range strings.Split(name, ".") {
		if label == "" || len(label) > 63 {
			return "", engine.InvalidArgument
		}
		for index := 0; index < len(label); index++ {
			character := label[index]
			alphanumeric := (character >= 'a' && character <= 'z') || (character >= 'A' && character <= 'Z') ||
				(character >= '0' && character <= '9')
			if alphanumeric || (index > 0 && index < len(label)-1 && (character == '-' || character == '_')) {
				continue
			}
			return "", engine.InvalidArgument
		}
	}
	return name, engine.OK
}

// resolveEnvelope is the schemaVersion=1 JSON the C05 resolve callback writes.
// Exact keys, one value per key, no trailing object: the same rejection of
// unknown fields the gateway applies to its own metadata.
type resolveEnvelope struct {
	SchemaVersion int      `json:"schemaVersion"`
	Success       bool     `json:"success"`
	ErrorCode     *string  `json:"errorCode"`
	Error         *string  `json:"error"`
	Addresses     []string `json:"addresses"`
}

func parseAddresses(response []byte) ([]netip.Addr, engine.Code) {
	if len(response) == 0 || len(response) > MaxResolveBytes {
		return nil, engine.IOError
	}
	decoder := json.NewDecoder(bytes.NewReader(response))
	decoder.DisallowUnknownFields()
	var envelope resolveEnvelope
	if decoder.Decode(&envelope) != nil || decoder.Decode(new(any)) != io.EOF {
		return nil, engine.IOError
	}
	if envelope.SchemaVersion != 1 || !envelope.Success || envelope.ErrorCode != nil || envelope.Error != nil {
		return nil, engine.IOError
	}
	if len(envelope.Addresses) == 0 {
		return nil, engine.IOError
	}
	seen := make(map[netip.Addr]struct{}, len(envelope.Addresses))
	addresses := make([]netip.Addr, 0, len(envelope.Addresses))
	for _, text := range envelope.Addresses {
		address, err := netip.ParseAddr(text)
		if err != nil || address.Zone() != "" {
			return nil, engine.IOError
		}
		target, code := numeric(netip.AddrPortFrom(address, 1))
		if code != engine.OK {
			return nil, engine.IOError
		}
		if _, duplicate := seen[target.Addr()]; duplicate {
			continue
		}
		seen[target.Addr()] = struct{}{}
		addresses = append(addresses, target.Addr())
	}
	if len(addresses) == 0 {
		return nil, engine.IOError
	}
	return addresses, engine.OK
}

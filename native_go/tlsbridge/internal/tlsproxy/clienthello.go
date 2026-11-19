// ClientHello probing: the lossless classifier that runs before any
// interception decision (TLS-207, design §6.2).
//
// The probe reads the first bytes of an application stream, decides whether the
// client started talking TLS immediately, and keeps every byte it read so they
// can be replayed into either crypto/tls or an unchanged passthrough copy. It
// answers exactly two questions — what did the client send, and is it something
// this engine serves — and deliberately answers neither "should this connection
// be intercepted" (TLS-208) nor "what happens next" (TLS-213).
//
// Nothing here decrypts a record, trusts a record length as a read size, or
// treats a single 0x16 byte as TLS. A verdict of VerdictClientHello is a
// statement about bytes the peer actually sent, not about a negotiated
// protocol: SNI, ALPN and versions are read back as offered values.

package tlsproxy

import (
	"crypto/tls"
	"errors"
	"io"
	"net"
	"os"
	"time"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

// Fixed probe budgets (design §6.2, C10). These are resource budgets, not
// protocol limits: exceeding one is a reason to hand the prefix back for
// passthrough with a recorded reason, never an assertion about what TLS allows.
const (
	// DefaultProbePrefix is how many application bytes the probe may read
	// before it gives up on finding a complete ClientHello.
	DefaultProbePrefix = 64 << 10
	// MaxProbePrefix is the hard ceiling on that budget. Limits may lower its
	// own budget but never raise it past this value, so a bad configuration can
	// only tighten the bound.
	MaxProbePrefix = 64 << 10
	// DefaultProbeTimeout bounds the whole probe, not one read: a client that
	// drips one byte at a time cannot extend it.
	DefaultProbeTimeout = 3 * time.Second
)

// Record and handshake framing limits (RFC 8446 §5.1, §5.2, §4.1.2).
const (
	// probeReadChunk is one Read's buffer. It is unrelated to TLS record
	// lengths: a record length is the peer's claim about its own framing and
	// must never be used to size a read or an allocation.
	probeReadChunk           = 4096
	recordHeaderLength       = 5
	handshakeHeaderLength    = 4
	tlsMajorVersion          = 0x03
	recordTypeHandshake      = 0x16
	handshakeTypeClientHello = 0x01
	// maxRecordPayload is the TLS plaintext record limit. A handshake record
	// larger than that is not a record this probe buffers.
	maxRecordPayload = 1 << 14
	// minClientHelloBody is the shortest possible ClientHello body: legacy
	// version, random and the three length-prefixed lists. Anything shorter is
	// truncated or fabricated, so the declared length is rejected before any
	// bytes are accumulated for it.
	minClientHelloBody = 38
	// maxSessionIDLength is the RFC 8446 §4.1.2 session id limit.
	maxSessionIDLength = 32
)

// Structural caps. A hello above one of them is well-formed TLS that this
// engine must not intercept, which is a different answer from "not TLS".
const (
	maxHelloExtensions = 64
	maxALPNProtocols   = 64
)

// Extension and handshake code points this classifier reads. Every other
// extension — including GREASE — is skipped by framing alone (RFC 8701).
const (
	extServerName           = 0x0000
	extSignatureAlgorithms  = 0x000d
	extALPN                 = 0x0010
	extSupportedVersions    = 0x002b
	extEncryptedClientHello = 0xfe0d
	sniHostName             = 0x00
)

// Verdict is what the probe concluded about the start of the stream. It is not
// the interception decision: TLS-208 turns a verdict (and the frozen policy)
// into intercept, bypass or unsupported.
type Verdict int

const (
	// VerdictClientHello means one complete ClientHello was parsed and its
	// offer includes a version this engine serves.
	VerdictClientHello Verdict = iota
	// VerdictNotTLS means the prefix cannot be the start of a client TLS
	// handshake: the record framing or the ClientHello structure is malformed.
	VerdictNotTLS
	// VerdictUnsupported means the framing is valid TLS but this engine must
	// not intercept it: an unexpected handshake type, no TLS 1.2/1.3 offer, or
	// a hello above a structural cap.
	VerdictUnsupported
	// VerdictIncomplete means the probe ran out of budget, deadline or stream
	// before it could decide.
	VerdictIncomplete
)

func (v Verdict) String() string {
	switch v {
	case VerdictClientHello:
		return "client_hello"
	case VerdictNotTLS:
		return "not_tls"
	case VerdictUnsupported:
		return "unsupported"
	case VerdictIncomplete:
		return "incomplete"
	default:
		return "invalid"
	}
}

// Reasons are fixed strings. They reach the connection event log and must never
// carry stream bytes, a server name, a peer length or platform error text.
const (
	// reasonNotHandshakeRecord: the first record is not a handshake record, so
	// the client did not open with a ClientHello.
	reasonNotHandshakeRecord = "not_handshake_record"
	// reasonBadRecordVersion: the record layer is not TLS's major version 3.
	reasonBadRecordVersion = "bad_record_version"
	// reasonBadRecordLength: a record declares a payload the record layer
	// cannot carry.
	reasonBadRecordLength = "bad_record_length"
	// reasonMalformedHello: a length inside the ClientHello contradicts the
	// bytes that follow it, so no ClientHello can be read from them.
	reasonMalformedHello = "malformed_client_hello"
	// reasonHandshakeType: the stream is TLS, but its first handshake message
	// is not a ClientHello.
	reasonHandshakeType = "unexpected_handshake_type"
	// reasonTooManyEntries: the hello exceeds a structural cap.
	reasonTooManyEntries = "client_hello_too_large"
	// reasonNoVersion: a complete ClientHello that offers no version this
	// engine implements.
	reasonNoVersion = "no_supported_version"
	// reasonBudget: the declared ClientHello needs more than the prefix budget.
	reasonBudget = "prefix_budget_exceeded"
	// reasonTimeout: the probe deadline passed first.
	reasonTimeout = "probe_timeout"
	// reasonEndOfStream: the peer closed before a ClientHello was complete.
	reasonEndOfStream = "stream_ended"
	// reasonReadError: the transport failed, or cannot carry a probe deadline.
	reasonReadError = "read_error"
)

// Limits bounds one probe. The zero value is the default budget.
type Limits struct {
	// MaxPrefixBytes is the largest prefix the probe may read. Zero, negative
	// or above MaxProbePrefix selects DefaultProbePrefix.
	MaxPrefixBytes int
	// Timeout bounds the whole probe. Zero or negative selects
	// DefaultProbeTimeout.
	Timeout time.Duration
}

func (l Limits) normalize() Limits {
	if l.MaxPrefixBytes <= 0 || l.MaxPrefixBytes > MaxProbePrefix {
		l.MaxPrefixBytes = DefaultProbePrefix
	}
	if l.Timeout <= 0 {
		l.Timeout = DefaultProbeTimeout
	}
	return l
}

// ClientHello is what one ClientHello offered. Every field is read back as
// sent: nothing here is normalized, repaired or resolved, because case, IDNA
// and trailing-dot handling are one rule owned by TLS-208 (engine.CanonicalName)
// and applying a second variant here would let two halves of one connection
// disagree about the same name.
type ClientHello struct {
	// LegacyVersion is the hello's own version field. It is only authoritative
	// when SupportedVersionsPresent is false (RFC 8446 §4.2.1).
	LegacyVersion uint16
	// ClientRandom is the 32-byte client random, the value a downstream
	// keylog entry is keyed by.
	ClientRandom [32]byte
	// SNI is the host_name the client sent, exactly as sent, or "" when it sent
	// none. An SNI that is not a usable name is reported as absent rather than
	// repaired, and it is not a confirmed site name: it is the name the client
	// offered, which is also what a client using ECH puts in the clear.
	SNI string
	// ALPN is the protocol list the client offered, with GREASE removed. An
	// empty list means the client offered none.
	ALPN []string
	// SupportedVersions is the §4.2.1 version list, with GREASE removed.
	SupportedVersions []uint16
	// SupportedVersionsPresent distinguishes "the client sent no
	// supported_versions extension" (TLS 1.2 style: LegacyVersion is
	// authoritative) from "the client sent one" (LegacyVersion is ignored).
	SupportedVersionsPresent bool
	// SignatureAlgorithms is the §4.2.3 scheme list, with GREASE removed.
	// Empty means the client sent no signature_algorithms; TLS 1.2 clients that
	// omit it are restricted to SHA-1, which this proxy does not sign.
	SignatureAlgorithms []tls.SignatureScheme
	// ECHOffered reports that the encrypted_client_hello extension was present.
	// It is a candidate signal only: the extension's presence does not mean ECH
	// was negotiated, and the inner name is not readable here, so SNI must not
	// be treated as the confirmed site when this is set.
	ECHOffered bool
	// Records is how many TLS records carried the ClientHello.
	Records int
}

// Outcome is one probe's result. Conn is always non-nil: on every verdict the
// caller receives a connection that replays the whole prefix ProbeClientHello
// consumed before continuing on the underlying connection.
type Outcome struct {
	Verdict Verdict
	// Reason is the fixed reason code, and is empty exactly when the verdict is
	// VerdictClientHello.
	Reason string
	// Hello carries the parsed ClientHello. It is filled whenever the body
	// parsed, which includes a well-formed hello this engine will not serve; it
	// is the zero value only when no ClientHello could be read at all.
	Hello ClientHello
	// Conn replays every byte the probe read. It is never nil.
	Conn *PrefixConn
	// Bytes is how many bytes the probe consumed, which is the size of the
	// prefix Conn still owes the caller.
	Bytes int
}

// ProbeClientHello reads the start of conn looking for one complete
// ClientHello. It always returns a Conn that replays what it read, so a caller
// can continue with tls.Client (TLS-209) or with a plain copy (TLS-213)
// without losing a single byte, in both directions.
//
// The probe stops as soon as the ClientHello is complete, so a client that
// waits for the server before sending a request is not mistaken for a stalled
// one. It clears the read deadline it installed before returning — a net.Conn
// has no deadline getter, so a caller must set its own per-phase deadline
// afterwards rather than rely on the probe's 3-second budget surviving.
// Cancellation is by closing conn, which unblocks the read.
func ProbeClientHello(conn net.Conn, limits Limits) Outcome {
	return probeClientHello(conn, limits, nil)
}

// onCapacity reports the capacity of the current prefix backing array only.
// Scanner/body copies, allocation overlap and runtime overhead are separate.
func probeClientHello(conn net.Conn, limits Limits, onCapacity func(int)) Outcome {
	limits = limits.normalize()

	var prefix []byte
	// Every exit reports the same two things: the reason, and a connection that
	// still owes the caller the whole prefix.
	fail := func(verdict Verdict, reason string) Outcome {
		return Outcome{
			Verdict: verdict,
			Reason:  reason,
			Conn:    NewPrefixConn(conn, prefix),
			Bytes:   len(prefix),
		}
	}

	scanner := &scanner{}

	// The budget is a wall-clock deadline for the whole probe, so a slow drip
	// cannot extend it, and it is installed before the first read. A transport
	// that cannot carry a deadline cannot be probed in bounded time: it is
	// handed straight back instead of being read from with nothing to stop it.
	if conn == nil || conn.SetReadDeadline(time.Now().Add(limits.Timeout)) != nil {
		return Outcome{
			Verdict: VerdictIncomplete,
			Reason:  reasonReadError,
			Conn:    NewPrefixConn(conn, nil),
		}
	}
	defer conn.SetReadDeadline(time.Time{})

	buffer := make([]byte, probeReadChunk)
	var readErr error

	for {
		switch scanner.advance(prefix) {
		case scanComplete:
			return finish(conn, prefix, scanner)
		case scanFailed:
			return fail(verdictForReason(scanner.reason), scanner.reason)
		}

		// A transport error never outranks a ClientHello the bytes already in
		// hand can still complete: the scan above runs first.
		if readErr != nil {
			verdict, reason := readFailure(readErr)
			return fail(verdict, reason)
		}

		// A hello that declares a body beyond the budget is abandoned before
		// any of that body is read or allocated.
		if scanner.declaredTotal() > limits.MaxPrefixBytes {
			return fail(VerdictIncomplete, reasonBudget)
		}
		room := limits.MaxPrefixBytes - len(prefix)
		if room <= 0 {
			return fail(VerdictIncomplete, reasonBudget)
		}
		want := buffer
		if len(want) > room {
			want = want[:room]
		}
		n, err := conn.Read(want)
		if n > 0 {
			if len(prefix)+n > cap(prefix) {
				capacity := min(limits.MaxPrefixBytes, max(len(prefix)+n, max(probeReadChunk, cap(prefix)*2)))
				grown := make([]byte, len(prefix), capacity)
				copy(grown, prefix)
				prefix = grown
				if onCapacity != nil {
					onCapacity(capacity)
				}
			}
			prefix = append(prefix, buffer[:n]...)
		}
		readErr = err
	}
}

// finish parses a complete ClientHello body and reports whether this engine can
// serve the offer. A well-formed hello this engine will not serve keeps its
// parsed fields: the offer is an observation the policy layer still has to make
// a decision about, and discarding it would hide, for instance, that the client
// sent a name and offered no version the proxy speaks.
func finish(conn net.Conn, prefix []byte, scanner *scanner) Outcome {
	hello, reason := parseClientHello(scanner.body)
	if reason != "" {
		return Outcome{
			Verdict: verdictForReason(reason),
			Reason:  reason,
			Conn:    NewPrefixConn(conn, prefix),
			Bytes:   len(prefix),
		}
	}
	hello.Records = scanner.records
	outcome := Outcome{
		Verdict: VerdictClientHello,
		Hello:   hello,
		Conn:    NewPrefixConn(conn, prefix),
		Bytes:   len(prefix),
	}
	if !offerSupported(hello) {
		outcome.Verdict = VerdictUnsupported
		outcome.Reason = reasonNoVersion
	}
	return outcome
}

// verdictForReason maps a failure onto the verdict taxonomy: malformed framing
// is not TLS, while well-formed framing this engine will not serve is
// unsupported.
func verdictForReason(reason string) Verdict {
	switch reason {
	case reasonHandshakeType, reasonTooManyEntries:
		return VerdictUnsupported
	default:
		return VerdictNotTLS
	}
}

// readFailure classifies a transport error. None of these verdicts is a claim
// about the protocol: the probe simply stopped before it could decide, which is
// what a caller needs in order to pass the prefix through unchanged.
func readFailure(err error) (Verdict, string) {
	switch {
	case errors.Is(err, os.ErrDeadlineExceeded):
		return VerdictIncomplete, reasonTimeout
	case errors.Is(err, io.EOF):
		return VerdictIncomplete, reasonEndOfStream
	default:
		return VerdictIncomplete, reasonReadError
	}
}

// offerSupported reports whether the client offered a version this engine
// implements. It is deliberately conservative: TLS 1.2 and 1.3 are the only
// versions the proxy speaks (design §6.3), so an offer that cannot be served is
// reported as unsupported rather than intercepted into a doomed handshake.
func offerSupported(hello ClientHello) bool {
	if hello.SupportedVersionsPresent {
		for _, version := range hello.SupportedVersions {
			if version == tls.VersionTLS12 || version == tls.VersionTLS13 {
				return true
			}
		}
		return false
	}
	return hello.LegacyVersion >= tls.VersionTLS12
}

// scanResult is one incremental step of the record scanner.
type scanResult int

const (
	scanNeedMore scanResult = iota
	scanComplete
	scanFailed
)

// scanner walks the record layer of a stream buffer and accumulates exactly the
// first handshake message. Its cursor only moves forward, so re-scanning a
// growing prefix stays linear in the bytes read.
//
// It never sizes anything from a declared length. The only buffer it grows is
// the ClientHello body it has actually received, so a peer that announces a
// 16 MiB body makes the probe stop on its budget rather than allocate one.
type scanner struct {
	stage           scanStage
	pos             int
	records         int
	recordRemaining int
	header          [handshakeHeaderLength]byte
	headerFilled    int
	bodyLength      int
	body            []byte
	reason          string
}

type scanStage int

const (
	stageRecordHeader scanStage = iota
	stageRecordPayload
	stageDone
	stageFailed
)

// advance consumes as much of data as it can, returning as soon as the
// ClientHello is complete, the stream is provably not a client ClientHello, or
// more bytes are needed.
func (s *scanner) advance(data []byte) scanResult {
	for {
		switch s.stage {
		case stageDone:
			return scanComplete
		case stageFailed:
			return scanFailed

		case stageRecordHeader:
			if len(data)-s.pos < recordHeaderLength {
				return scanNeedMore
			}
			contentType := data[s.pos]
			version := uint16(data[s.pos+1])<<8 | uint16(data[s.pos+2])
			length := int(data[s.pos+3])<<8 | int(data[s.pos+4])
			s.pos += recordHeaderLength
			switch {
			case contentType != recordTypeHandshake:
				return s.fail(reasonNotHandshakeRecord)
			// The first ClientHello record may legitimately carry a 0x0301
			// version field, so only the major version is checked: this rejects
			// random data without rejecting a compatibility record.
			case version>>8 != tlsMajorVersion:
				return s.fail(reasonBadRecordVersion)
			case length > maxRecordPayload:
				return s.fail(reasonBadRecordLength)
			}
			s.records++
			s.recordRemaining = length
			s.stage = stageRecordPayload

		case stageRecordPayload:
			if s.recordRemaining == 0 {
				s.stage = stageRecordHeader
				continue
			}
			available := len(data) - s.pos
			if available <= 0 {
				return scanNeedMore
			}
			if available > s.recordRemaining {
				available = s.recordRemaining
			}
			chunk := data[s.pos : s.pos+available]
			consumed, result := s.consumeHandshake(chunk)
			s.pos += consumed
			s.recordRemaining -= consumed
			if result != scanNeedMore {
				return result
			}
		}
	}
}

// consumeHandshake accumulates handshake bytes from one record's payload. It
// may stop early when the ClientHello completes inside chunk, and reports how
// many bytes of chunk it used so the record cursor stays exact.
func (s *scanner) consumeHandshake(chunk []byte) (int, scanResult) {
	consumed := 0
	if s.headerFilled < handshakeHeaderLength {
		n := copy(s.header[s.headerFilled:], chunk)
		s.headerFilled += n
		consumed += n
		if s.headerFilled < handshakeHeaderLength {
			return consumed, scanNeedMore
		}
		if s.header[0] != handshakeTypeClientHello {
			return consumed, s.fail(reasonHandshakeType)
		}
		s.bodyLength = int(s.header[1])<<16 | int(s.header[2])<<8 | int(s.header[3])
		if s.bodyLength < minClientHelloBody {
			return consumed, s.fail(reasonMalformedHello)
		}
	}
	if len(s.body) >= s.bodyLength {
		s.stage = stageDone
		return consumed, scanComplete
	}
	chunk = chunk[consumed:]
	if len(chunk) > 0 {
		need := s.bodyLength - len(s.body)
		if need > len(chunk) {
			need = len(chunk)
		}
		s.body = append(s.body, chunk[:need]...)
		consumed += need
		if len(s.body) >= s.bodyLength {
			s.stage = stageDone
			return consumed, scanComplete
		}
	}
	return consumed, scanNeedMore
}

func (s *scanner) fail(reason string) scanResult {
	s.reason = reason
	s.stage = stageFailed
	return scanFailed
}

// declaredTotal is a lower bound on the stream bytes the announced ClientHello
// still needs: bytes already consumed plus the body bytes still outstanding,
// ignoring the record headers those bytes will additionally cost. It is used to
// abandon an oversized announcement before reading any of it.
func (s *scanner) declaredTotal() int {
	if s.headerFilled < handshakeHeaderLength {
		return 0
	}
	return s.pos + (s.bodyLength - len(s.body))
}

// bodyCursor reads the ClientHello body. Every length in that body comes from
// the peer, so every read is bounds-checked and any inconsistency marks the
// cursor bad instead of panicking or reading past the buffer.
type bodyCursor struct {
	data []byte
	pos  int
	bad  bool
}

func (c *bodyCursor) remaining() int { return len(c.data) - c.pos }

func (c *bodyCursor) u8() byte {
	if c.bad || c.remaining() < 1 {
		c.bad = true
		return 0
	}
	value := c.data[c.pos]
	c.pos++
	return value
}

func (c *bodyCursor) u16() uint16 {
	if c.bad || c.remaining() < 2 {
		c.bad = true
		return 0
	}
	value := uint16(c.data[c.pos])<<8 | uint16(c.data[c.pos+1])
	c.pos += 2
	return value
}

func (c *bodyCursor) take(n int) []byte {
	if c.bad || n < 0 || n > c.remaining() {
		c.bad = true
		return nil
	}
	value := c.data[c.pos : c.pos+n]
	c.pos += n
	return value
}

func (c *bodyCursor) vector8() []byte  { return c.take(int(c.u8())) }
func (c *bodyCursor) vector16() []byte { return c.take(int(c.u16())) }

// parseClientHello reads one complete ClientHello body. It returns a fixed
// reason when the body is not a ClientHello. Individual extension contents are
// never allowed to fail the hello: an extension whose own lengths contradict
// itself is dropped, because a mangled extension says nothing about whether the
// client is speaking TLS, while a mangled body does.
func parseClientHello(body []byte) (ClientHello, string) {
	cursor := &bodyCursor{data: body}
	var hello ClientHello

	hello.LegacyVersion = cursor.u16()
	random := cursor.take(32)
	if cursor.bad {
		return ClientHello{}, reasonMalformedHello
	}
	copy(hello.ClientRandom[:], random)

	sessionID := cursor.vector8()
	if cursor.bad || len(sessionID) > maxSessionIDLength {
		return ClientHello{}, reasonMalformedHello
	}
	cipherSuites := cursor.vector16()
	if cursor.bad || len(cipherSuites) < 2 || len(cipherSuites)%2 != 0 {
		return ClientHello{}, reasonMalformedHello
	}
	compressionMethods := cursor.vector8()
	if cursor.bad || len(compressionMethods) == 0 {
		return ClientHello{}, reasonMalformedHello
	}
	if cursor.remaining() == 0 {
		// A TLS 1.0/1.1-shaped hello with no extension block at all.
		return hello, ""
	}
	extensions := cursor.vector16()
	if cursor.bad || cursor.remaining() != 0 {
		return ClientHello{}, reasonMalformedHello
	}
	return parseExtensions(extensions, hello)
}

// parseExtensions reads the extension block. Unknown and GREASE extensions are
// skipped by their own framing, which is the only thing needed to walk past
// them.
func parseExtensions(data []byte, hello ClientHello) (ClientHello, string) {
	cursor := &bodyCursor{data: data}
	count := 0
	for cursor.remaining() > 0 {
		count++
		if count > maxHelloExtensions {
			return hello, reasonTooManyEntries
		}
		kind := cursor.u16()
		payload := cursor.vector16()
		if cursor.bad {
			return hello, reasonMalformedHello
		}
		switch kind {
		case extServerName:
			parseServerName(payload, &hello)
		case extALPN:
			if !parseALPN(payload, &hello) {
				return hello, reasonTooManyEntries
			}
		case extSupportedVersions:
			parseSupportedVersions(payload, &hello)
		case extSignatureAlgorithms:
			parseSignatureAlgorithms(payload, &hello)
		case extEncryptedClientHello:
			hello.ECHOffered = true
		}
	}
	return hello, ""
}

// parseServerName reads the list of server names. Only the first host_name is
// meaningful (RFC 6066: at most one name per type), and a name that is not a
// usable identity is reported as no name at all rather than repaired.
func parseServerName(payload []byte, hello *ClientHello) {
	if len(payload) == 0 {
		return
	}
	list := &bodyCursor{data: payload}
	entries := list.vector16()
	if list.bad || list.remaining() != 0 {
		return
	}
	names := &bodyCursor{data: entries}
	found := false
	for names.remaining() > 0 {
		kind := names.u8()
		name := names.vector16()
		if names.bad {
			return
		}
		if found || kind != sniHostName {
			continue
		}
		found = true
		if _, code := engine.CanonicalName(string(name)); code != engine.OK {
			continue
		}
		hello.SNI = string(name)
	}
}

// parseALPN reads the offered protocol list, dropping GREASE (RFC 8701 says a
// recipient must ignore it) so a fabricated protocol is never advertised
// upstream as one the client proposed. It reports false when the list exceeds
// the structural cap, which is an unsupported hello rather than a malformed
// one.
func parseALPN(payload []byte, hello *ClientHello) bool {
	if len(payload) == 0 {
		return true
	}
	list := &bodyCursor{data: payload}
	protocols := list.vector16()
	if list.bad || list.remaining() != 0 {
		return true
	}
	entries := &bodyCursor{data: protocols}
	for entries.remaining() > 0 {
		name := entries.vector8()
		if entries.bad || len(name) == 0 {
			return true
		}
		if isGREASEProtocol(name) {
			continue
		}
		if len(hello.ALPN) >= maxALPNProtocols {
			return false
		}
		hello.ALPN = append(hello.ALPN, string(name))
	}
	return true
}

// parseSupportedVersions reads the §4.2.1 version list. An empty or malformed
// list leaves SupportedVersionsPresent false, so the hello falls back to its
// legacy version and the real negotiation still happens over the real bytes.
func parseSupportedVersions(payload []byte, hello *ClientHello) {
	if len(payload) == 0 {
		return
	}
	cursor := &bodyCursor{data: payload}
	list := cursor.vector8()
	if cursor.bad || cursor.remaining() != 0 || len(list) < 2 || len(list)%2 != 0 {
		return
	}
	hello.SupportedVersionsPresent = true
	for index := 0; index+1 < len(list); index += 2 {
		version := uint16(list[index])<<8 | uint16(list[index+1])
		if isGREASE(version) {
			continue
		}
		hello.SupportedVersions = append(hello.SupportedVersions, version)
	}
}

// parseSignatureAlgorithms reads the §4.2.3 scheme list. The list has the same
// two-byte encoding as tls.SignatureScheme, so the values are handed on
// unchanged for the leaf algorithm choice (TLS-205's SelectAlgorithm).
func parseSignatureAlgorithms(payload []byte, hello *ClientHello) {
	if len(payload) == 0 {
		return
	}
	cursor := &bodyCursor{data: payload}
	list := cursor.vector16()
	if cursor.bad || cursor.remaining() != 0 || len(list) < 2 || len(list)%2 != 0 {
		return
	}
	for index := 0; index+1 < len(list); index += 2 {
		scheme := uint16(list[index])<<8 | uint16(list[index+1])
		if isGREASE(scheme) {
			continue
		}
		hello.SignatureAlgorithms = append(hello.SignatureAlgorithms, tls.SignatureScheme(scheme))
	}
}

// isGREASE reports the RFC 8701 reserved values 0x?a?a: both bytes equal a
// nibble marker, chosen so they are never assigned a meaning. They must be
// skipped wherever they appear, or a fabricated value would be read as a real
// protocol offer.
func isGREASE(value uint16) bool { return value&0x0f0f == 0x0a0a }

// isGREASEProtocol reports a two-byte ALPN protocol id carrying a GREASE value.
func isGREASEProtocol(name []byte) bool {
	return len(name) == 2 && isGREASE(uint16(name[0])<<8|uint16(name[1]))
}

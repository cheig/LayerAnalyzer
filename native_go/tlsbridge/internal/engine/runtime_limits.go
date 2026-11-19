package engine

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

// The Go connection count is the TLS candidate subset of Kotlin's total TCP quota.
// It includes dial, READY, sniffing, handshake, fallback and relay; never add the two counts.
// Only capacities are executable configuration; the wire mode is a fixed NIO identity.
type SocksRuntimeLimits struct {
	TCP            int `json:"tcp"`
	UDP            int `json:"udp"`
	Authentication int `json:"authentication"`
	TLSHandshakes  int `json:"tlsHandshakes"`
}

func DefaultSocksRuntimeLimits() SocksRuntimeLimits {
	return SocksRuntimeLimits{TCP: 64, UDP: 64, Authentication: 64, TLSHandshakes: 8}
}
func (l SocksRuntimeLimits) Valid() bool {
	tcp := l.TCP == 64 || l.TCP == 128 || l.TCP == 256 || l.TCP == 512 || l.TCP == 1024
	udp := l.UDP == 64 || l.UDP == 128 || l.UDP == 256
	auth := l.Authentication == 64 || l.Authentication == 128
	return tcp && udp && auth && l.TLSHandshakes == 8
}

// Keep start-config v2 and diagnostic JSON compatible without storing a mode selector.
func (l SocksRuntimeLimits) MarshalJSON() ([]byte, error) {
	type capacity SocksRuntimeLimits
	return json.Marshal(struct {
		Mode string `json:"mode"`
		capacity
	}{"NIO", capacity(l)})
}

func (l *SocksRuntimeLimits) UnmarshalJSON(data []byte) error {
	fields, ok := strictObject(data, map[string]bool{"mode": true, "tcp": true, "udp": true, "authentication": true, "tlsHandshakes": true})
	if !ok || len(fields) != 5 {
		return io.ErrUnexpectedEOF
	}
	for _, value := range fields {
		if bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return io.ErrUnexpectedEOF
		}
	}
	var mode string
	if json.Unmarshal(fields["mode"], &mode) != nil || mode != "NIO" {
		return errors.New("unsupported SOCKS forwarding mode; only NIO is supported")
	}
	type capacity SocksRuntimeLimits
	var parsed capacity
	if err := json.Unmarshal(data, &parsed); err != nil {
		return err
	}
	if !SocksRuntimeLimits(parsed).Valid() {
		return io.ErrUnexpectedEOF
	}
	*l = SocksRuntimeLimits(parsed)
	return nil
}

// v1 has no new keys and selects the NIO 64/64/64/8 defaults. v2 requires the complete
// runtime object, preventing mixed-version binaries from silently dropping a requested ceiling.
func (c Config) RuntimeLimits() (SocksRuntimeLimits, Code) {
	if c.SchemaVersion == 1 && c.SocksRuntime == nil {
		return DefaultSocksRuntimeLimits(), OK
	}
	if c.SchemaVersion == 2 && c.SocksRuntime != nil && c.SocksRuntime.Valid() {
		return *c.SocksRuntime, OK
	}
	return SocksRuntimeLimits{}, InvalidArgument
}

// encoding/json alone accepts duplicate and case-insensitive names; reject both at the boundary.
func strictObject(data []byte, allowed map[string]bool) (map[string]json.RawMessage, bool) {
	d := json.NewDecoder(bytes.NewReader(data))
	if token, err := d.Token(); err != nil || token != json.Delim('{') {
		return nil, false
	}
	fields := make(map[string]json.RawMessage, len(allowed))
	for d.More() {
		token, err := d.Token()
		if err != nil {
			return nil, false
		}
		key, ok := token.(string)
		if !ok || !allowed[key] {
			return nil, false
		}
		if _, exists := fields[key]; exists {
			return nil, false
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, false
		}
		fields[key] = value
	}
	if token, err := d.Token(); err != nil || token != json.Delim('}') || d.Decode(new(any)) != io.EOF {
		return nil, false
	}
	return fields, true
}

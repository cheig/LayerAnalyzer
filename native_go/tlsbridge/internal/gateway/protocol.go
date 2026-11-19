// Package gateway implements the authenticated local TCP hop. It neither dials
// through the default resolver nor installs a production TLS flow handler.
package gateway

import (
	"bufio"
	"bytes"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"io"
	"net/netip"
	"unicode/utf8"

	"com.layeranalyzer/tlsbridge/internal/engine"
)

const (
	Version        = 1
	MaxHeaderBytes = 4096
	MaxReplyBytes  = 1024
)

// Metadata deliberately excludes the authentication token. The destination is
// an already resolved IP, never a host to be resolved again using SNI.
type Metadata struct {
	// Borrowed for Handle only; not part of LAT1 or serialized metadata.
	ConnectionLease   *engine.Lease
	CaptureID         string
	ConnectionID      string
	NetworkGeneration int64
	Destination       netip.AddrPort
}

func readRequest(r io.Reader) (Metadata, [32]byte, engine.Code) {
	var prefix [8]byte
	var secret [32]byte
	invalid := func() (Metadata, [32]byte, engine.Code) {
		return Metadata{}, [32]byte{}, engine.InvalidArgument
	}
	if _, err := io.ReadFull(r, prefix[:]); err != nil {
		return invalid()
	}
	n := binary.BigEndian.Uint32(prefix[4:])
	if string(prefix[:4]) != "LAT1" || n == 0 || n > MaxHeaderBytes {
		return invalid()
	}
	body := make([]byte, n)
	defer clear(body)
	if _, err := io.ReadFull(r, body); err != nil || !utf8.Valid(body) {
		return invalid()
	}
	// Exact keys, one value per key and no trailing object. encoding/json's
	// struct decoder alone accepts duplicate and case-insensitive field names.
	d := json.NewDecoder(bytes.NewReader(body))
	first, err := d.Token()
	if err != nil || first != json.Delim('{') {
		return invalid()
	}
	fields := make(map[string]json.RawMessage, 7)
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	for d.More() {
		key, err := d.Token()
		if err != nil {
			return invalid()
		}
		name, ok := key.(string)
		if !ok {
			return invalid()
		}
		switch name {
		case "version", "captureId", "connectionId", "networkGeneration", "destinationAddress", "destinationPort", "token":
		default:
			return invalid()
		}
		if _, exists := fields[name]; exists {
			return invalid()
		}
		var value json.RawMessage
		if d.Decode(&value) != nil || bytes.Equal(value, []byte("null")) {
			return invalid()
		}
		fields[name] = value
	}
	if last, err := d.Token(); err != nil || last != json.Delim('}') || len(fields) != 7 {
		return invalid()
	}
	if d.Decode(new(any)) != io.EOF {
		return invalid()
	}
	var version, port int
	var metadata Metadata
	var address, token string
	for key, dest := range map[string]any{
		"version": &version, "captureId": &metadata.CaptureID,
		"connectionId": &metadata.ConnectionID, "networkGeneration": &metadata.NetworkGeneration,
		"destinationAddress": &address, "destinationPort": &port, "token": &token,
	} {
		if json.Unmarshal(fields[key], dest) != nil {
			return invalid()
		}
	}
	if version != Version || !engine.ValidID(metadata.CaptureID) || !engine.ValidID(metadata.ConnectionID) ||
		metadata.NetworkGeneration < 0 || port < 1 || port > 65535 || len(token) != 43 {
		return invalid()
	}
	ip, err := netip.ParseAddr(address)
	if err != nil || ip.Zone() != "" || ip.Unmap().IsUnspecified() || ip.Unmap().IsMulticast() {
		return invalid()
	}
	decoded, err := base64.RawURLEncoding.Strict().DecodeString(token)
	defer clear(decoded)
	if err != nil || len(decoded) != len(secret) {
		return invalid()
	}
	copy(secret[:], decoded)
	metadata.Destination = netip.AddrPortFrom(ip, uint16(port))
	return metadata, secret, engine.OK
}

// This is the C05 binary-channel reply, not an ordinary ABI JSON envelope.
// Only fixed error codes are serialized; parser/dialer messages never escape.
func writeReply(w *bufio.Writer, code engine.Code) error {
	var errorCode *string
	if code != engine.OK {
		name := code.String()
		errorCode = &name
	}
	body, err := json.Marshal(struct {
		Version   int     `json:"version"`
		Success   bool    `json:"success"`
		ErrorCode *string `json:"errorCode"`
	}{Version, code == engine.OK, errorCode})
	if err != nil {
		return err
	}
	if len(body) > MaxReplyBytes {
		return io.ErrShortBuffer
	}
	prefix := [8]byte{'L', 'A', 'T', '1'}
	binary.BigEndian.PutUint32(prefix[4:], uint32(len(body)))
	if _, err := w.Write(prefix[:]); err != nil {
		return err
	}
	if _, err := w.Write(body); err != nil {
		return err
	}
	return w.Flush()
}

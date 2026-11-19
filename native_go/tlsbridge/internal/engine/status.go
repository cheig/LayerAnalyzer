package engine

type Code int32

const (
	OK Code = iota
	InvalidArgument
	NotReady
	Unsupported
	StaleGeneration
	Cancelled
	IOError
	CapacityExceeded
	ProtectFailed
	NetworkChanged
	UpstreamCertInvalid
	DownstreamTLSRejected
	SecretsIncomplete
	CaptureContextMissing
)

func (c Code) String() string {
	names := [...]string{"", "INVALID_ARGUMENT", "NOT_READY", "UNSUPPORTED", "STALE_GENERATION",
		"CANCELLED", "IO_ERROR", "CAPACITY_EXCEEDED", "PROTECT_FAILED", "NETWORK_CHANGED",
		"UPSTREAM_CERT_INVALID", "DOWNSTREAM_TLS_REJECTED", "SECRETS_INCOMPLETE", "CAPTURE_CONTEXT_MISSING"}
	if c < 0 || int(c) >= len(names) {
		return "IO_ERROR"
	}
	return names[c]
}

func Envelope(code Code) map[string]any {
	result := map[string]any{"schemaVersion": 1, "success": code == OK, "errorCode": nil, "error": nil}
	if code != OK {
		result["errorCode"] = code.String()
		// Never interpolate parser, platform or cryptographic error text.
		result["error"] = "TLS operation unavailable or rejected"
	}
	return result
}

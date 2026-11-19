package engine

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/json"
	"time"
	"unicode/utf8"
)

type Config struct {
	SchemaVersion     int                 `json:"schemaVersion"`
	CaptureID         string              `json:"captureId"`
	NetworkGeneration *int64              `json:"networkGeneration"`
	Settings          json.RawMessage     `json:"settings,omitempty"`
	SocksRuntime      *SocksRuntimeLimits `json:"socksRuntime,omitempty"`
}

type Material struct {
	Certificate *x509.Certificate
	Signer      crypto.Signer
}

func ParseConfig(data []byte) (Config, Code) {
	var c Config
	if len(data) == 0 || len(data) > 65536 || !utf8.Valid(data) {
		return c, InvalidArgument
	}
	fields, ok := strictObject(data, map[string]bool{"schemaVersion": true, "captureId": true, "networkGeneration": true, "settings": true, "socksRuntime": true})
	if !ok || json.Unmarshal(data, &c) != nil || c.NetworkGeneration == nil || *c.NetworkGeneration < 0 || !ValidID(c.CaptureID) {
		return Config{}, InvalidArgument
	}
	if _, present := fields["socksRuntime"]; present && c.SocksRuntime == nil {
		return Config{}, InvalidArgument
	}
	if _, code := c.RuntimeLimits(); code != OK {
		return Config{}, code
	}
	if len(c.Settings) != 0 && (len(bytes.TrimSpace(c.Settings)) == 0 || bytes.TrimSpace(c.Settings)[0] != '{') {
		return Config{}, InvalidArgument
	}
	return c, OK
}

func ValidID(s string) bool {
	if len(s) == 0 || len(s) > 128 {
		return false
	}
	for i, b := range []byte(s) {
		if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || (i > 0 && (b == '-' || b == '_')) {
			continue
		}
		return false
	}
	return true
}

func ParseMaterial(certDER, keyPKCS8 []byte, now time.Time) (Material, Code) {
	if len(certDER) == 0 || len(certDER) > 65536 || len(keyPKCS8) == 0 || len(keyPKCS8) > 16384 {
		return Material{}, InvalidArgument
	}
	cert, err := x509.ParseCertificate(certDER)
	if err != nil || !cert.IsCA || !cert.BasicConstraintsValid || cert.KeyUsage&x509.KeyUsageCertSign == 0 || now.Before(cert.NotBefore) || !now.Before(cert.NotAfter) || cert.CheckSignatureFrom(cert) != nil {
		return Material{}, InvalidArgument
	}
	key, err := x509.ParsePKCS8PrivateKey(keyPKCS8)
	if err != nil {
		return Material{}, InvalidArgument
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return Material{}, InvalidArgument
	}
	public, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil || !bytes.Equal(public, cert.RawSubjectPublicKeyInfo) {
		return Material{}, InvalidArgument
	}
	return Material{cert, signer}, OK
}

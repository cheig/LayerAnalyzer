#!/usr/bin/env python3
"""Generate the committed TLS-206 CA-material fixtures.

These are synthetic, local and test-only vectors for `TlsCertificateManager`:
one RSA 3072 self-signed CA and its matching PKCS#8 key, plus one unrelated
PKCS#8 key that exists only to prove a mismatched pair is rejected. Unlike the
TLS-204 upstream-trust fixtures, a *private key* is committed here, because the
whole point of the unit test is that the C06 container stores and unwraps one.

Nothing in this fixture is deployable: the CA is never installed on a device,
never shipped in an APK (it lands only in the unit-test resources source set,
which is not packaged), and it was never used to sign real traffic. Do not
reuse it anywhere outside `TlsCertificateStateTest`; the runtime CA is always
generated on the device by Go (`la_tls_generate_ca`).

Usage:
    python3 native_build/verification/tls/generate_certificate_manager_fixture.py
    python3 native_build/verification/tls/generate_certificate_manager_fixture.py --check
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[2]
TARGET = REPOSITORY / "app/src/test/resources/tls/certificate-manager"

COMMON_NAME = "LayerAnalyzer capture CA fixture"
ORGANIZATION = "LayerAnalyzer test fixture"
SERIAL = 0x4C41_0001
# Wide enough that the fixture is usable whenever the suite runs; the manager's
# expired/not-yet-valid states are exercised by injecting the clock, not by
# committing a second certificate.
VALID_FROM = datetime(2020, 1, 1, tzinfo=timezone.utc)
VALID_UNTIL = datetime(2045, 1, 1, tzinfo=timezone.utc)


def build() -> dict[str, bytes]:
    key = rsa.generate_private_key(public_exponent=65537, key_size=3072)
    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, COMMON_NAME),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, ORGANIZATION),
    ])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(SERIAL)
        .not_valid_before(VALID_FROM)
        .not_valid_after(VALID_UNTIL)
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=False, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    other = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    files = {
        "ca-certificate.der": certificate.public_bytes(serialization.Encoding.DER),
        "ca-private-key.pkcs8": key.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()),
        "other-private-key.pkcs8": other.private_bytes(
            serialization.Encoding.DER, serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption()),
    }
    manifest = {
        "schemaVersion": 1,
        "fixtureId": "certificate-manager",
        "purpose": "TLS-206 CA state, C06 sealing and reset",
        "source": "synthetic-local-test-only",
        "privateKeysCommitted": True,
        "warning": "Test vectors only: never installed, never shipped, never used for real traffic.",
        "subject": certificate.subject.rfc4514_string(),
        "notBefore": certificate.not_valid_before.isoformat(),
        "notAfter": certificate.not_valid_after.isoformat(),
        "keyAlgorithm": "RSA-3072",
        "files": [describe(name, payload) for name, payload in files.items()],
    }
    files["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    return files


def describe(name: str, payload: bytes) -> dict:
    role = {
        "ca-certificate.der": "fixture-ca-certificate",
        "ca-private-key.pkcs8": "fixture-ca-private-key-matching",
        "other-private-key.pkcs8": "fixture-unrelated-private-key",
    }[name]
    return {"file": name, "role": role, "bytes": len(payload), "sha256": hashlib.sha256(payload).hexdigest()}


def check() -> int:
    manifest_path = TARGET / "manifest.json"
    if not manifest_path.is_file():
        print(f"missing {manifest_path}")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    failures = 0
    for entry in manifest["files"]:
        path = TARGET / entry["file"]
        if not path.is_file():
            print(f"missing {path}")
            failures += 1
        elif hashlib.sha256(path.read_bytes()).hexdigest() != entry["sha256"]:
            print(f"changed {path}")
            failures += 1
    print("certificate manager fixtures match their manifest" if failures == 0 else f"{failures} fixture problems")
    return 1 if failures else 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify committed fixtures without regenerating")
    arguments = parser.parse_args()
    if arguments.check:
        return check()
    TARGET.mkdir(parents=True, exist_ok=True)
    for name, payload in build().items():
        (TARGET / name).write_bytes(payload)
        print(f"wrote {name} ({len(payload)} bytes)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

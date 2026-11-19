#!/usr/bin/env python3
"""Generate the committed TLS-204 upstream trust fixtures.

The fixtures are synthetic, local and test-only: one trust root, one decoy root
and a handful of leaves that differ only in the property under test (a valid
name, a wrong name, an expired window, a different issuer). Only public
certificates are written - no private key is committed, and nothing here is ever
packaged in the application APK: the files land in the unit-test resources and
the instrumentation-test assets, both of which are test-only source sets.

Usage:
    python3 native_build/verification/tls/generate_upstream_trust_fixture.py
    python3 native_build/verification/tls/generate_upstream_trust_fixture.py --check

`--check` re-reads the committed files and verifies them against the committed
manifest without regenerating anything.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import ipaddress
import json
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[2]
TARGETS = (
    REPOSITORY / "app/src/test/resources/tls/upstream-trust",
    REPOSITORY / "app/src/androidTest/assets/tls/upstream-trust",
)

IDENTITY = "upstream.fixture.test"
WRONG_IDENTITY = "other.fixture.test"
IP_IDENTITY = "127.0.0.1"
VALID_FROM = datetime(2020, 1, 1, tzinfo=timezone.utc)
VALID_UNTIL = datetime(2045, 1, 1, tzinfo=timezone.utc)
EXPIRED_FROM = datetime(1999, 1, 1, tzinfo=timezone.utc)
EXPIRED_UNTIL = datetime(2000, 1, 1, tzinfo=timezone.utc)


def root_certificate(name: str) -> tuple[x509.Certificate, x509.Certificate]:
    key = ec.generate_private_key(ec.SECP256R1())
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])
    certificate = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(1)
        .not_valid_before(VALID_FROM)
        .not_valid_after(VALID_UNTIL)
        .add_extension(x509.BasicConstraints(ca=True, path_length=1), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=False,
                data_encipherment=False, key_agreement=False, key_cert_sign=True,
                crl_sign=True, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return certificate, key


def leaf_certificate(
    issuer: x509.Certificate,
    issuer_key,
    common_name: str,
    dns_names: list[str],
    ip_addresses: list[str],
    not_before: datetime,
    not_after: datetime,
    algorithm: str,
    serial: int,
) -> x509.Certificate:
    key = ec.generate_private_key(ec.SECP256R1()) if algorithm == "ec" else rsa.generate_private_key(65537, 2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    alternatives: list[x509.GeneralName] = [x509.DNSName(name) for name in dns_names]
    alternatives += [x509.IPAddress(ipaddress.ip_address(value)) for value in ip_addresses]
    return (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer.subject)
        .public_key(key.public_key())
        .serial_number(serial)
        .not_valid_before(not_before)
        .not_valid_after(not_after)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, content_commitment=False, key_encipherment=algorithm == "rsa",
                data_encipherment=False, key_agreement=False, key_cert_sign=False,
                crl_sign=False, encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        .add_extension(x509.SubjectAlternativeName(alternatives), critical=False)
        .sign(issuer_key, hashes.SHA256())
    )


def describe(name: str, role: str, certificate: x509.Certificate, payload: bytes) -> dict:
    return {
        "file": name,
        "role": role,
        "sha256": hashlib.sha256(payload).hexdigest(),
        "subject": certificate.subject.rfc4514_string(),
        "issuer": certificate.issuer.rfc4514_string(),
        "notBefore": certificate.not_valid_before.isoformat(),
        "notAfter": certificate.not_valid_after.isoformat(),
        "ca": certificate.extensions.get_extension_for_class(x509.BasicConstraints).value.ca,
    }


def build() -> tuple[dict[str, bytes], dict]:
    trust_root, trust_key = root_certificate("LayerAnalyzer upstream trust fixture root")
    decoy_root, decoy_key = root_certificate("LayerAnalyzer upstream trust fixture decoy root")

    certificates: dict[str, x509.Certificate] = {
        "root.der": trust_root,
        "other-root.der": decoy_root,
        "leaf-valid-ec.der": leaf_certificate(trust_root, trust_key, IDENTITY, [IDENTITY], [IP_IDENTITY], VALID_FROM, VALID_UNTIL, "ec", 10),
        "leaf-valid-rsa.der": leaf_certificate(trust_root, trust_key, IDENTITY, [IDENTITY], [IP_IDENTITY], VALID_FROM, VALID_UNTIL, "rsa", 11),
        "leaf-wrong-name.der": leaf_certificate(trust_root, trust_key, WRONG_IDENTITY, [WRONG_IDENTITY], [], VALID_FROM, VALID_UNTIL, "ec", 12),
        "leaf-expired.der": leaf_certificate(trust_root, trust_key, IDENTITY, [IDENTITY], [IP_IDENTITY], EXPIRED_FROM, EXPIRED_UNTIL, "ec", 13),
        "leaf-unknown-ca.der": leaf_certificate(decoy_root, decoy_key, IDENTITY, [IDENTITY], [IP_IDENTITY], VALID_FROM, VALID_UNTIL, "ec", 14),
    }
    roles = {
        "root.der": "fixture-trust-root",
        "other-root.der": "fixture-decoy-root",
        "leaf-valid-ec.der": "leaf-ec-valid",
        "leaf-valid-rsa.der": "leaf-rsa-valid",
        "leaf-wrong-name.der": "leaf-wrong-name",
        "leaf-expired.der": "leaf-expired",
        "leaf-unknown-ca.der": "leaf-unknown-ca",
    }
    files = {name: certificate.public_bytes(serialization.Encoding.DER) for name, certificate in certificates.items()}
    manifest = {
        "schemaVersion": 1,
        "fixtureId": "upstream-trust",
        "purpose": "TLS-204 upstream chain and name verification",
        "source": "synthetic-local-test-only",
        "privateKeysCommitted": False,
        "identity": IDENTITY,
        "ipIdentity": IP_IDENTITY,
        "certificates": [describe(name, roles[name], certificates[name], files[name]) for name in certificates],
        "cases": [
            {"leaf": "leaf-valid-ec.der", "trust": ["root.der"], "identity": IDENTITY, "expected": "verified"},
            {"leaf": "leaf-valid-ec.der", "trust": ["root.der"], "identity": IP_IDENTITY, "expected": "verified"},
            {"leaf": "leaf-valid-rsa.der", "trust": ["root.der"], "identity": IDENTITY, "expected": "verified"},
            {"leaf": "leaf-wrong-name.der", "trust": ["root.der"], "identity": IDENTITY, "expected": "name-mismatch"},
            {"leaf": "leaf-wrong-name.der", "trust": ["root.der"], "identity": IP_IDENTITY, "expected": "name-mismatch"},
            {"leaf": "leaf-expired.der", "trust": ["root.der"], "identity": IDENTITY, "expected": "expired"},
            {"leaf": "leaf-unknown-ca.der", "trust": ["root.der"], "identity": IDENTITY, "expected": "unknown-ca"},
            {"leaf": "leaf-valid-ec.der", "trust": ["other-root.der"], "identity": IDENTITY, "expected": "unknown-ca"},
        ],
    }
    return files, manifest


def sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def check() -> int:
    failures = 0
    for target in TARGETS:
        manifest_path = target / "manifest.json"
        if not manifest_path.is_file():
            print(f"missing {manifest_path}")
            failures += 1
            continue
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        for entry in manifest["certificates"]:
            path = target / entry["file"]
            if not path.is_file():
                print(f"missing {path}")
                failures += 1
            elif sha256(path) != entry["sha256"]:
                print(f"changed {path}")
                failures += 1
    print("upstream trust fixtures match their manifest" if failures == 0 else f"{failures} fixture problems")
    return 1 if failures else 0


def generate() -> int:
    files, manifest = build()
    payloads = dict(files)
    payloads["manifest.json"] = (json.dumps(manifest, indent=2) + "\n").encode()
    for target in TARGETS:
        target.mkdir(parents=True, exist_ok=True)
        for name, payload in payloads.items():
            (target / name).write_bytes(payload)
        print(f"wrote {len(payloads)} files to {target.relative_to(REPOSITORY)}")
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="Verify committed fixtures without regenerating")
    arguments = parser.parse_args()
    return check() if arguments.check else generate()


if __name__ == "__main__":
    raise SystemExit(main())

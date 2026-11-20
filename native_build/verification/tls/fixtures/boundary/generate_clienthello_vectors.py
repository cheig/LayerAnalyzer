#!/usr/bin/env python3
"""Generate synthetic ClientHello byte vectors for the TLS-217 boundary matrix.

The bytes are authored here on purpose: no library in this checkout emits either
ECH or GREASE, and the point of the vectors is to feed the classifier input it
cannot otherwise be given. They are TLS record streams containing one ClientHello
and nothing else; they are not captures of any real client and they carry no
secret. Each vector records the SHA-256 of exactly the bytes it names, so the Go
side reads bytes rather than trusting a second parser.

Usage: python3 generate_clienthello_vectors.py [--output clienthello-vectors.json]
"""
from __future__ import annotations

import argparse
import base64
import hashlib
import json
from pathlib import Path

# Code points the classifier knows (kept here so the vector is self-describing).
EXT_SERVER_NAME = 0x0000
EXT_SIGNATURE_ALGORITHMS = 0x000D
EXT_ALPN = 0x0010
EXT_SUPPORTED_VERSIONS = 0x002B
EXT_ENCRYPTED_CLIENT_HELLO = 0xFE0D
SNI_HOST_NAME = 0x00
GREASE_EXTENSION = 0x1A1A
GREASE_VERSION = 0x0A0A
GREASE_SCHEME = 0x3A3A
TLS12 = 0x0303
TLS13 = 0x0304


def u8(value: int) -> bytes:
    return bytes([value])


def u16(value: int) -> bytes:
    return value.to_bytes(2, "big")


def vector8(payload: bytes) -> bytes:
    return u8(len(payload)) + payload


def vector16(payload: bytes) -> bytes:
    return u16(len(payload)) + payload


def extension(kind: int, payload: bytes) -> bytes:
    return u16(kind) + vector16(payload)


def sni_extension(name: str) -> bytes:
    return extension(EXT_SERVER_NAME, vector16(u8(SNI_HOST_NAME) + vector16(name.encode())))


def alpn_extension(names: list[bytes]) -> bytes:
    return extension(EXT_ALPN, vector16(b"".join(vector8(name) for name in names)))


def versions_extension(versions: list[int]) -> bytes:
    return extension(EXT_SUPPORTED_VERSIONS, vector8(b"".join(u16(v) for v in versions)))


def sigalgs_extension(schemes: list[int]) -> bytes:
    return extension(EXT_SIGNATURE_ALGORITHMS, vector16(b"".join(u16(s) for s in schemes)))


def ech_extension() -> bytes:
    # An outer ECHClientHello: type, cipher_suite, config_id, enc, payload. The
    # classifier reads only the extension's presence, so a well-formed envelope is
    # all that is needed; negotiation is never claimed from it.
    payload = u8(0x00) + u16(0x0001) + u16(0x0001) + u8(0x00) + vector16(b"\x11" * 32) + vector16(b"ech")
    return extension(EXT_ENCRYPTED_CLIENT_HELLO, payload)


def client_hello(legacy_version: int, extensions: list[bytes], cipher_suites: bytes) -> bytes:
    body = u16(legacy_version) + bytes(range(32)) + vector8(b"") + vector16(cipher_suites) + vector8(b"\x00")
    body += vector16(b"".join(extensions))
    message = u8(0x01) + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + u16(len(message)) + message


def sha256(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def build() -> dict:
    # ECH present, single GREASE-free hello. The outer SNI is the only name a
    # classifier can read; the vector proves the extension is recorded as a
    # candidate signal, not that ECH was negotiated.
    ech = client_hello(TLS12, [
        sni_extension("outer.example.test"),
        alpn_extension([b"h2", b"http/1.1"]),
        versions_extension([TLS13, TLS12]),
        sigalgs_extension([0x0403]),
        ech_extension(),
    ], bytes([0x13, 0x01, 0x13, 0x02]))

    # GREASE everywhere it is legal (RFC 8701): extension type, version, ALPN id,
    # signature scheme and a cipher suite. None of it may reach the parsed offer.
    grease = client_hello(TLS12, [
        sni_extension("grease.example.test"),
        alpn_extension([u16(GREASE_VERSION), b"h2"]),
        versions_extension([GREASE_VERSION, TLS13]),
        sigalgs_extension([GREASE_SCHEME, 0x0403]),
        extension(GREASE_EXTENSION, b"\x00"),
    ], bytes([0x0A, 0x0A, 0x13, 0x01]))

    vectors = [
        {
            "id": "ech-candidate-signal",
            "case": "ech-extension-present",
            "description": [
                "A ClientHello that carries the encrypted_client_hello (0xfe0d)",
                "extension and an outer SNI. The vector proves only that the",
                "extension presence is recorded as a candidate signal and that the",
                "outer name is what is read; it is NOT evidence that ECH was",
                "negotiated, which needs an ECH-capable peer and is unavailable here.",
            ],
            "bytesBase64": base64.b64encode(ech).decode(),
            "sha256": sha256(ech),
            "expect": {
                "verdict": "client_hello",
                "sni": "outer.example.test",
                "alpn": ["h2", "http/1.1"],
                "supportedVersions": [TLS13, TLS12],
                "signatureAlgorithms": [0x0403],
                "echOffered": True,
            },
        },
        {
            "id": "grease-values-skipped",
            "case": "grease-in-every-list",
            "description": [
                "A ClientHello whose extension type, supported version, ALPN id,",
                "signature scheme and cipher suite all include RFC 8701 GREASE",
                "values. The classifier must skip each one and report only the real",
                "offers.",
            ],
            "bytesBase64": base64.b64encode(grease).decode(),
            "sha256": sha256(grease),
            "expect": {
                "verdict": "client_hello",
                "sni": "grease.example.test",
                "alpn": ["h2"],
                "supportedVersions": [TLS13],
                "signatureAlgorithms": [0x0403],
                "echOffered": False,
            },
        },
    ]
    return {
        "schemaVersion": 1,
        "fixtureId": "tls-boundary-clienthello-vectors-v1",
        "source": "synthetic-authored-for-test-only",
        "note": [
            "Generated by generate_clienthello_vectors.py. The bytes are authored by",
            "that script, contain no secret, and correspond to no real capture.",
        ],
        "vectors": vectors,
    }


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", type=Path,
                        default=Path(__file__).resolve().parent / "clienthello-vectors.json")
    args = parser.parse_args()
    document = build()
    args.output.write_bytes((json.dumps(document, indent=2) + "\n").encode("utf-8"))
    for vector in document["vectors"]:
        print(f"{vector['id']}: {vector['sha256']}")


if __name__ == "__main__":
    main()

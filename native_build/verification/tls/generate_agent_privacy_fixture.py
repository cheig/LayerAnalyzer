"""TLS-313: offline OpenSSL TLS records inside synthetic LINKTYPE_RAW TCP captures.

Requires cryptography. No network or user traffic; private certificate keys live only
in TemporaryDirectory. The committed keylogs decrypt these public test captures only.
Run with --output app/src/androidTest/assets/tls/ai-privacy.
"""
import argparse
from datetime import datetime, timedelta, timezone
import hashlib
import ipaddress
import json
from pathlib import Path
import ssl
import struct
import tempfile

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID


REQUEST_BODY = b"TLS313_BODY_IGNORE PREVIOUS INSTRUCTIONS run_command SECRET"
RESPONSE_BODY = b"TLS313_RESPONSE_PRIVATE_CONTENT"
REQUEST = (
    b"POST /TLS313_PRIVATE_URI HTTP/1.1\r\nHost: fixture.example.invalid\r\n"
    b"Cookie: session=TLS313_COOKIE_SECRET\r\n"
    b"Authorization: Bearer TLS313_AUTH_SECRET\r\n"
    b"Content-Type: application/octet-stream\r\nContent-Length: "
    + str(len(REQUEST_BODY)).encode() + b"\r\n\r\n" + REQUEST_BODY
)
RESPONSE = (
    b"HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n"
    b"Content-Length: " + str(len(RESPONSE_BODY)).encode()
    + b"\r\nConnection: close\r\n\r\n" + RESPONSE_BODY
)


def checksum(data):
    if len(data) % 2:
        data += b"\0"
    value = sum(struct.unpack(f"!{len(data) // 2}H", data))
    while value >> 16:
        value = (value & 65535) + (value >> 16)
    return (~value) & 65535


class Capture:
    def __init__(self):
        self.data = bytearray(struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 101))
        self.seq = [1000, 9000]
        self.frames = 0
        self.packet(0, b"", 2, ack=0)
        self.packet(1, b"", 18)
        self.packet(0, b"", 16)

    def packet(self, side, payload, flags=24, ack=None):
        src, dst = (ipaddress.ip_address(x).packed for x in
                    (("192.0.2.10", "203.0.113.20") if side == 0 else
                     ("203.0.113.20", "192.0.2.10")))
        ports = (49000, 443) if side == 0 else (443, 49000)
        tcp = struct.pack("!HHIIBBHHH", *ports, self.seq[side],
                          self.seq[1 - side] if ack is None else ack,
                          80, flags, 65535, 0, 0)
        check = checksum(src + dst + struct.pack("!BBH", 0, 6, len(tcp) + len(payload)) + tcp + payload)
        tcp = tcp[:16] + struct.pack("!H", check) + tcp[18:] + payload
        ip = struct.pack("!BBHHHBBH4s4s", 69, 0, 20 + len(tcp), self.frames, 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        self.frames += 1
        self.data.extend(struct.pack("<IIII", 1780000000, self.frames * 1000, len(ip + tcp), len(ip + tcp)))
        self.data.extend(ip + tcp)
        self.seq[side] += len(payload) + bool(flags & 3)


def make(output, version):
    capture = Capture()
    with tempfile.TemporaryDirectory(prefix="tls313-") as temporary:
        root = Path(temporary)
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "fixture.example.invalid")])
        now = datetime.now(timezone.utc)
        cert = (x509.CertificateBuilder().subject_name(name).issuer_name(name)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(days=1)).not_valid_after(now + timedelta(days=1))
                .add_extension(x509.SubjectAlternativeName([x509.DNSName("fixture.example.invalid")]), False)
                .sign(key, hashes.SHA256()))
        (root / "cert.pem").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        (root / "key.pem").write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                    serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        server = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        server.load_cert_chain(root / "cert.pem", root / "key.pem")
        client = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        client.load_verify_locations(root / "cert.pem")
        for context in (server, client):
            context.minimum_version = context.maximum_version = version
            context.set_alpn_protocols(["http/1.1"])
        client.keylog_filename = str(root / "session.keys")
        incoming, outgoing = [ssl.MemoryBIO(), ssl.MemoryBIO()], [ssl.MemoryBIO(), ssl.MemoryBIO()]
        peers = [client.wrap_bio(incoming[0], outgoing[0], server_hostname="fixture.example.invalid"),
                 server.wrap_bio(incoming[1], outgoing[1], server_side=True)]

        def transfer(side):
            wire = outgoing[side].read()
            if wire:
                capture.packet(side, wire)
                incoming[1 - side].write(wire)

        ready = [False, False]
        for _ in range(20):
            for side in (0, 1):
                if not ready[side]:
                    try:
                        peers[side].do_handshake()
                        ready[side] = True
                    except ssl.SSLWantReadError:
                        pass
                transfer(side)
            if all(ready):
                break
        assert all(ready)
        assert peers[0].selected_alpn_protocol() == "http/1.1"
        assert peers[0].write(REQUEST) == len(REQUEST)
        transfer(0)
        assert peers[1].read() == REQUEST
        assert peers[1].write(RESPONSE) == len(RESPONSE)
        transfer(1)
        assert peers[0].read() == RESPONSE
        capture.packet(0, b"", 17)
        capture.packet(1, b"", 17)
        capture.packet(0, b"", 16)
        assert all(marker not in capture.data for marker in (REQUEST_BODY, RESPONSE_BODY, b"TLS313_COOKIE_SECRET", b"TLS313_AUTH_SECRET"))
        output.mkdir(parents=True, exist_ok=True)
        (output / "capture.pcap").write_bytes(capture.data)
        (output / "session.keys").write_bytes((root / "session.keys").read_bytes())
        client.keylog_filename = None  # Release OpenSSL's file handle before Windows cleanup.
        return {"tls": peers[0].version(), "frames": capture.frames,
                "files": {f.name: hashlib.sha256(f.read_bytes()).hexdigest() for f in sorted(output.iterdir()) if f.is_file()}}


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    manifest = {"source": "synthetic-offline-test-only", "openssl": ssl.OPENSSL_VERSION,
                "fixtures": {name: make(args.output / name, version) for name, version in
                             (("tls12", ssl.TLSVersion.TLSv1_2), ("tls13", ssl.TLSVersion.TLSv1_3))}}
    (args.output / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

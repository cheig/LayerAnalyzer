#!/usr/bin/env python3
"""Create public TLS-401 exchanges using OpenSSL memory BIOs, never live traffic.

TCP/IP is serialized around real TLS records (not an Android TUN capture).
Keys are temporary; the checked-in keylogs are intentionally public test secrets.
Generation always targets a NEW directory, never the published golden.
"""
from __future__ import annotations

import argparse
import base64
import ctypes as C
import ctypes.util
from datetime import datetime, timezone
import json
import importlib.metadata
from pathlib import Path
import platform
import shutil
import struct
import sys
import tempfile

from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived

from generate_fixture import BODY, SERVER_NAME, certificates, write_json
from check_fixture import ROOT, incomplete_capture, inspect_capture, keylog_random, require, sha256

SPECS = {
    "tls12-h2": (0x303, "h2", "ECDHE-RSA-AES128-GCM-SHA256", []),
    "tls13-chacha-h1": (0x304, "http/1.1", "TLS_CHACHA20_POLY1305_SHA256", []),
    "tls13-chacha-h2": (0x304, "h2", "TLS_CHACHA20_POLY1305_SHA256", []),
    "tls13-hrr-h1": (0x304, "http/1.1", "TLS_AES_128_GCM_SHA256", ["hrr"]),
    "tls13-keyupdate-h1": (0x304, "http/1.1", "TLS_AES_128_GCM_SHA256", ["key-update"]),
}


class OpenSSL:
    def __init__(self, library: str):
        self.lib = C.CDLL(library)
        self.crypto = C.CDLL(str(Path(library).with_name("libcrypto-3.dll"))) if sys.platform == "win32" else C.CDLL(ctypes.util.find_library("crypto"))
        p, i, s = C.c_void_p, C.c_int, C.c_char_p
        signatures = {
            "TLS_method": (p, []), "SSL_CTX_new": (p, [p]),
            "SSL_CTX_free": (None, [p]), "SSL_CTX_ctrl": (C.c_long, [p, i, C.c_long, p]),
            "SSL_CTX_use_certificate_chain_file": (i, [p, s]),
            "SSL_CTX_use_PrivateKey_file": (i, [p, s, i]),
            "SSL_CTX_load_verify_locations": (i, [p, s, s]),
            "SSL_CTX_set_verify": (None, [p, i, p]),
            "SSL_CTX_set_cipher_list": (i, [p, s]), "SSL_CTX_set_ciphersuites": (i, [p, s]),
            "SSL_CTX_set_alpn_protos": (i, [p, s, C.c_uint]),
            "SSL_CTX_set_alpn_select_cb": (None, [p, p, p]),
            "SSL_CTX_set_keylog_callback": (None, [p, p]),
            "SSL_new": (p, [p]), "SSL_free": (None, [p]),
            "SSL_set_bio": (None, [p, p, p]), "SSL_set_connect_state": (None, [p]),
            "SSL_set_accept_state": (None, [p]), "SSL_set1_host": (i, [p, s]),
            "SSL_ctrl": (C.c_long, [p, i, C.c_long, p]),
            "SSL_do_handshake": (i, [p]), "SSL_is_init_finished": (i, [p]),
            "SSL_get_error": (i, [p, i]), "SSL_get_verify_result": (C.c_long, [p]),
            "SSL_write": (i, [p, p, i]), "SSL_read": (i, [p, p, i]),
            "SSL_key_update": (i, [p, i]),
            "OpenSSL_version": (s, [i]),
            "BIO_s_mem": (p, []), "BIO_new": (p, [p]),
            "BIO_read": (i, [p, p, i]), "BIO_write": (i, [p, p, i]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.crypto if name.startswith(("BIO_", "OpenSSL_")) else self.lib, name)
            function.restype, function.argtypes = result, args
            setattr(self, name, function)


class Pair:
    def __init__(self, api, directory, version, alpn, cipher, features, identity=SERVER_NAME, trust=True):
        self.api, self.contexts, self.sockets, self.bios = api, [], [], []
        self.wire, self.keys, self.callbacks = [], [], []
        ca, cert, key = certificates(directory)
        self.ca = ca.read_bytes()
        protocol = alpn.encode()
        self.alpn_buffer = C.create_string_buffer(protocol)
        key_cb = C.CFUNCTYPE(None, C.c_void_p, C.c_char_p)(
            lambda _, line: self.keys.append(line.decode("ascii")))
        select_type = C.CFUNCTYPE(C.c_int, C.c_void_p, C.POINTER(C.c_void_p),
                                 C.POINTER(C.c_ubyte), C.c_void_p, C.c_uint, C.c_void_p)

        def select(_, output, size, offered, length, arg):
            if C.string_at(offered, length) != bytes([len(protocol)]) + protocol:
                return 2
            output[0], size[0] = C.addressof(self.alpn_buffer), len(protocol)
            return 0

        alpn_cb = select_type(select)
        self.callbacks += [key_cb, alpn_cb]
        for server in (False, True):
            ctx = api.SSL_CTX_new(api.TLS_method())
            require(bool(ctx), "SSL_CTX_new failed")
            self.contexts.append(ctx)
            for command in (123, 124):  # SSL_CTRL_SET_MIN/MAX_PROTO_VERSION
                require(api.SSL_CTX_ctrl(ctx, command, version, None) == 1, "TLS version rejected")
            setter = api.SSL_CTX_set_cipher_list if version == 0x303 else api.SSL_CTX_set_ciphersuites
            require(setter(ctx, cipher.encode()) == 1, "Cipher rejected")
            groups = b"P-256" if server and "hrr" in features else b"X25519:P-256"
            require(api.SSL_CTX_ctrl(ctx, 92, 0, C.cast(C.c_char_p(groups), C.c_void_p)) == 1,
                    "Groups rejected")
            if server:
                require(api.SSL_CTX_use_certificate_chain_file(ctx, str(cert).encode()) == 1, "Cert rejected")
                require(api.SSL_CTX_use_PrivateKey_file(ctx, str(key).encode(), 1) == 1, "Key rejected")
                api.SSL_CTX_set_alpn_select_cb(ctx, alpn_cb, None)
            else:
                api.SSL_CTX_set_verify(ctx, 1, None)  # SSL_VERIFY_PEER, always enabled
                if trust:
                    require(api.SSL_CTX_load_verify_locations(ctx, str(ca).encode(), None) == 1,
                            "Test trust root rejected")
                require(api.SSL_CTX_set_alpn_protos(ctx, bytes([len(protocol)]) + protocol,
                                                  len(protocol) + 1) == 0, "ALPN rejected")
                api.SSL_CTX_set_keylog_callback(ctx, key_cb)
            sock = api.SSL_new(ctx)
            require(bool(sock), "SSL_new failed")
            self.sockets.append(sock)
            incoming, outgoing = api.BIO_new(api.BIO_s_mem()), api.BIO_new(api.BIO_s_mem())
            self.bios.append((incoming, outgoing))
            api.SSL_set_bio(sock, incoming, outgoing)  # SSL owns both BIOs
            (api.SSL_set_accept_state if server else api.SSL_set_connect_state)(sock)
            if not server:
                require(api.SSL_set1_host(sock, identity.encode()) == 1, "Hostname verification setup failed")
                require(api.SSL_ctrl(sock, 55, 0, C.cast(C.c_char_p(identity.encode()), C.c_void_p)) == 1,
                        "SNI rejected")

    def pump(self):
        for side in (0, 1):
            buffer = C.create_string_buffer(65536)
            while (size := self.api.BIO_read(self.bios[side][1], buffer, len(buffer))) > 0:
                wire = buffer.raw[:size]
                self.wire.append((side, wire))
                require(self.api.BIO_write(self.bios[1-side][0], wire, size) == size, "BIO transfer failed")

    def handshake(self):
        for _ in range(100):
            for sock in self.sockets:
                result = self.api.SSL_do_handshake(sock)
                if result != 1 and self.api.SSL_get_error(sock, result) not in (2, 3):
                    self.pump()
                    return False
            self.pump()
            if all(self.api.SSL_is_init_finished(sock) for sock in self.sockets):
                require(self.api.SSL_get_verify_result(self.sockets[0]) == 0, "Verification was bypassed")
                return True
        raise ValueError("TLS handshake exceeded bounded iterations")

    def send(self, side, data):
        require(self.api.SSL_write(self.sockets[side], data, len(data)) == len(data), "TLS write failed")
        self.pump()
        result = bytearray()
        for _ in range(100):
            buffer = C.create_string_buffer(65536)
            size = self.api.SSL_read(self.sockets[1-side], buffer, len(buffer))
            self.pump()
            if size > 0:
                result.extend(buffer.raw[:size])
                if len(result) == len(data):
                    return bytes(result)
            else:
                require(self.api.SSL_get_error(self.sockets[1-side], size) in (2, 3), "TLS read failed")
        raise ValueError("TLS read exceeded bounded iterations")

    def update(self):
        for sock in self.sockets:
            require(self.api.SSL_key_update(sock, 0) == 1, "KeyUpdate scheduling failed")
            require(self.api.SSL_do_handshake(sock) == 1, "KeyUpdate failed")
        self.pump()

    def close(self):
        for sock in self.sockets:
            self.api.SSL_free(sock)
        for ctx in self.contexts:
            self.api.SSL_CTX_free(ctx)


def pcap(wire, port):
    """DLT_RAW IPv4/TCP, full handshake, deterministic segmentation and checksums."""
    packets, sequence = [], [1000, 9000]

    def checksum(data):
        if len(data) % 2: data += b"\0"
        total = sum(struct.unpack(f"!{len(data)//2}H", data))
        while total >> 16: total = (total & 65535) + (total >> 16)
        return ~total & 65535

    def packet(side, payload=b"", flags=0x18):
        addresses = [bytes([198, 18, 0, 1]), bytes([198, 18, 0, 2])]
        src, dst = addresses[side], addresses[1-side]
        ports = [49152, port]
        tcp = struct.pack("!HHIIBBHHH", ports[side], ports[1-side], sequence[side],
                          sequence[1-side] if flags != 2 else 0, 0x50, flags, 65535, 0, 0)
        check = checksum(src + dst + struct.pack("!BBH", 0, 6, len(tcp)+len(payload)) + tcp + payload)
        tcp = tcp[:16] + struct.pack("!H", check) + tcp[18:]
        ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 40+len(payload), len(packets), 0, 64, 6, 0, src, dst)
        ip = ip[:10] + struct.pack("!H", checksum(ip)) + ip[12:]
        packets.append(ip + tcp + payload)
        sequence[side] += len(payload) + bool(flags & 3)

    packet(0, flags=2); packet(1, flags=0x12); packet(0, flags=0x10)
    for side, data in wire:
        for start in range(0, len(data), 1000):
            packet(side, data[start:start+1000])
            packet(1-side, flags=0x10)
    packet(0, flags=0x11); packet(1, flags=0x11); packet(0, flags=0x10)
    result = struct.pack("<IHHIIII", 0xa1b2c3d4, 2, 4, 0, 0, 65535, 101)
    for index, data in enumerate(packets):
        result += struct.pack("<IIII", 1700000000, index * 1000, len(data), len(data)) + data
    return result


def exchange(a, b, alpn, port, update):
    if alpn == "h2":
        client = H2Connection(config=H2Configuration(client_side=True))
        server = H2Connection(config=H2Configuration(client_side=False))
        client.initiate_connection(); server.initiate_connection()
        client.send_headers(1, [(":method", "GET"), (":scheme", "https"),
                               (":authority", SERVER_NAME), (":path", "/fixture")], end_stream=True)
        request = client.data_to_send()
    else:
        request = (f"GET /fixture HTTP/1.1\r\nHost: {SERVER_NAME}:{port}\r\n"
                   "Accept-Encoding: identity\r\nConnection: close\r\n\r\n").encode()
    received = b.send(0, a.send(0, request))
    require(received == request, "Proxy upstream request mismatch")
    if alpn == "h2":
        server.receive_data(received)
        server.send_headers(1, [(":status", "200"), ("content-length", str(len(BODY)))])
        server.send_data(1, BODY, end_stream=True)
        response = server.data_to_send()
    else:
        response = f"HTTP/1.1 200 OK\r\nContent-Length: {len(BODY)}\r\nConnection: close\r\n\r\n".encode() + BODY
    if update:
        a.update(); b.update()
    received = a.send(1, b.send(1, response))
    require(received == response, "Proxy downstream response mismatch")
    body = (b"".join(event.data for event in client.receive_data(received) if isinstance(event, DataReceived))
            if alpn == "h2" else received.split(b"\r\n\r\n", 1)[1])
    require(body == BODY, "Independent client body differs from fixed contract")


def generate(output, library, tshark):
    require(not output.exists(), "Choose a new output directory; published goldens cannot be overwritten")
    output.mkdir(parents=True)
    # Preserve P0 bytes and provenance, then add release exchanges.
    original = json.loads((ROOT / "fixtures/manifest.json").read_text())
    original["fixtures"] = [f for f in original["fixtures"] if f["fixtureId"] in ("tls12-h1", "tls13-h1", "tls13-h2")]
    for fixture in original["fixtures"]:
        fixture["files"] = [entry for entry in fixture["files"] if entry["role"] not in
                            {"corrupt-keylog", "missing-handshake", "missing-segment"}]
        shutil.copytree(ROOT / "fixtures" / fixture["fixtureId"], output / fixture["fixtureId"])
        fixture["cipherSuite"] = json.loads((output / fixture["fixtureId"] / "client-result.json").read_text())["trusted"]["cipher"]
    api = OpenSSL(library)
    failures = []
    for id, (version, alpn, cipher, features) in SPECS.items():
        directory = output / id
        directory.mkdir()
        port = 18443
        with tempfile.TemporaryDirectory(prefix="la-release-cert-") as temporary:
            temp = Path(temporary)
            pairs = []
            try:
                for name in ("a", "b", "untrusted", "wrong-name"):
                    cert_dir = temp / name; cert_dir.mkdir()
                    pair = Pair(api, cert_dir, version, alpn, cipher, features,
                                identity="wrong.layeranalyzer.test" if name == "wrong-name" else SERVER_NAME,
                                trust=name != "untrusted")
                    pairs.append(pair)
                a, b, untrusted, wrong_name = pairs
                require(a.handshake() and b.handshake(), "Trusted TLS handshake failed")
                for name, pair in (("untrusted", untrusted), ("wrong-name", wrong_name)):
                    require(not pair.handshake(), "Invalid certificate was accepted")
                    (directory / f"{name}.pcap").write_bytes(pcap(pair.wire, port))
                    failures.append({"fixtureId": id, "case": name, "verified": False,
                                     "verifyResult": api.SSL_get_verify_result(pair.sockets[0])})
                exchange(a, b, alpn, port, "key-update" in features)
                (directory / "capture.pcap").write_bytes(pcap(a.wire, port))
                (directory / "upstream.pcap").write_bytes(pcap(b.wire, port))
                # Wireshark derives updated keys from *_0 and the real KeyUpdate.
                # OpenSSL's nonstandard *_N callback labels are deliberately excluded.
                for name, pair in (("session.keys", a), ("wrong.keys", b)):
                    lines = [line for line in dict.fromkeys(pair.keys) if not line.split()[0].endswith("_N")]
                    (directory / name).write_text("\n".join(lines) + "\n", encoding="ascii")
                (directory / "ca.pem").write_bytes(a.ca)
                (directory / "golden-body.bin").write_bytes(BODY)  # fixed input, never dissection output
                random, upstream_random = keylog_random(directory / "session.keys"), keylog_random(directory / "wrong.keys")
                trusted = {"success": True, "certificateVerified": True,
                           "tlsVersion": "TLS1.2" if version == 0x303 else "TLS1.3", "alpn": alpn,
                           "cipher": cipher, "destinationPort": port, "status": 200,
                           "bodyBase64": base64.b64encode(BODY).decode(), "bodySha256": sha256(BODY),
                           "connectionId": f"client-random:{random}"}
                write_json(directory / "client-result.json", {"schemaVersion": 1, "trusted": trusted,
                    "wrongConnection": dict(trusted, connectionId=f"client-random:{upstream_random}"),
                    "untrusted": {"success": False, "errorCode": "CERTIFICATE_VERIFY_FAILED"}})
            finally:
                for pair in pairs: pair.close()
        files = []
        for role, name in (("pcap", "capture.pcap"), ("keylog", "session.keys"),
                           ("wrong-keylog", "wrong.keys"), ("upstream-pcap", "upstream.pcap"),
                           ("untrusted-pcap", "untrusted.pcap"), ("wrong-name-pcap", "wrong-name.pcap"),
                           ("ca-certificate", "ca.pem"), ("golden-body", "golden-body.bin"),
                           ("client-result", "client-result.json")):
            entry = {"role": role, "path": f"{id}/{name}", "sha256": sha256((directory / name).read_bytes())}
            if role in ("pcap", "keylog", "wrong-keylog", "upstream-pcap"):
                entry["connectionId"] = f"client-random:{upstream_random if role in ('wrong-keylog', 'upstream-pcap') else random}"
            if role in ("keylog", "wrong-keylog"):
                entry["keyDirection"] = "downstream-tls-a" if role == "keylog" else "upstream-tls-b"
            files.append(entry)
        original["fixtures"].append({"fixtureId": id, "tlsVersion": trusted["tlsVersion"], "alpn": alpn,
            "cipherSuite": cipher, "features": features, "source": "synthetic-local-test-only",
            "expectedBody": {"encoding": "utf-8", "text": BODY.decode(), "sha256": sha256(BODY)}, "files": files,
            "generation": {"generatedAtUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                "command": ["python", "native_build/verification/tls/generate_release_fixture.py", "--output",
                            output.relative_to(ROOT.parents[2]).as_posix(), "--libssl", "${LIBSSL}", "--tshark", "${TSHARK}"],
                "workingDirectory": "repository-root", "captureMethod": "synthetic-tcp-serialization",
                "toolVersions": {"python": platform.python_version(), "openssl": api.OpenSSL_version(0).decode(),
                                 "h2": importlib.metadata.version("h2"), "cryptography": importlib.metadata.version("cryptography")}}})
    original["suiteVersion"] = "tls-golden-v1"
    original["referenceVersions"] = {"embedded": "4.0.10", "desktop": "3.6.0"}
    original["certificateChecks"] = failures
    for fixture in original["fixtures"]:
        id = fixture["fixtureId"]
        directory = output / id
        client = json.loads((directory / "client-result.json").read_text())["trusted"]
        actual = inspect_capture(tshark, directory / "capture.pcap", directory / "session.keys",
                                 client["destinationPort"], fixture["alpn"])
        require(actual["body"] == BODY, "Reference body differs from immutable input")
        lines = []
        for line in (directory / "session.keys").read_text().splitlines():
            if not line or line.startswith("#"): continue
            label, random, secret = line.split()
            lines.append(f"{label} {random} {'0' * len(secret)}")
        (directory / "corrupt.keys").write_text("\n".join(lines) + "\n", encoding="ascii")
        for name, handshake in (("missing-handshake", True), ("missing-segment", False)):
            (directory / f"{name}.pcap").write_bytes(incomplete_capture(
                (directory / "capture.pcap").read_bytes(), client["destinationPort"], handshake, actual["bodyFrames"]))
        for role, name in (("corrupt-keylog", "corrupt.keys"), ("missing-handshake", "missing-handshake.pcap"),
                           ("missing-segment", "missing-segment.pcap")):
            fixture["files"].append({"role": role, "path": f"{id}/{name}",
                                     "sha256": sha256((directory / name).read_bytes())})
    (output / "manifest.json").write_text(json.dumps(original, indent=2) + "\n", encoding="utf-8", newline="\n")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--libssl", default=ctypes.util.find_library("ssl"))
    parser.add_argument("--tshark", default="tshark")
    args = parser.parse_args()
    generate(args.output.resolve(), args.libssl, args.tshark)

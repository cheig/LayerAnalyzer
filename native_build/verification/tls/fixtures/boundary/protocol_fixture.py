#!/usr/bin/env python3
"""TLS-217 controlled peers: real OpenSSL KeyUpdate and Go ECH.

Only public certificates and result counters cross the HTTP control channel.
The Android test bridges a host TLS client to the device's production gateway;
both TLS endpoints remain on this controlled host. No public Internet is used.
"""
import argparse
import base64
import ctypes as C
import ctypes.util
import datetime as dt
import http.server
import json
import os
from pathlib import Path
import socket
import subprocess
import sys
import tempfile
import threading
import uuid

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

NAMES = ["inner.boundary.test", "outer.boundary.test"]
PAYLOADS = [bytes((i + offset) % 251 for i in range(32768)) for offset in (0, 19)]


class OpenSSL:
    """Public libssl API, independent of CPython's private SSL object layout."""
    MSG = C.CFUNCTYPE(None, C.c_int, C.c_int, C.c_int, C.c_void_p, C.c_size_t, C.c_void_p, C.c_void_p)

    def __init__(self):
        if os.name == "nt":
            lib = Path(sys.base_prefix) / "DLLs" / "libssl-3.dll"
        else:
            lib = ctypes.util.find_library("ssl")
        self.lib = C.CDLL(str(lib))
        p, i, l = C.c_void_p, C.c_int, C.c_long
        signatures = {
            "TLS_method": (p, []), "SSL_CTX_new": (p, [p]), "SSL_CTX_free": (None, [p]),
            "SSL_CTX_ctrl": (l, [p, i, l, p]), "SSL_CTX_set_verify": (None, [p, i, p]),
            "SSL_CTX_load_verify_locations": (i, [p, C.c_char_p, C.c_char_p]),
            "SSL_CTX_use_certificate_chain_file": (i, [p, C.c_char_p]),
            "SSL_CTX_use_PrivateKey_file": (i, [p, C.c_char_p, i]),
            "SSL_new": (p, [p]), "SSL_free": (None, [p]), "SSL_set_fd": (i, [p, i]),
            "SSL_ctrl": (l, [p, i, l, p]), "SSL_set1_host": (i, [p, C.c_char_p]),
            "SSL_connect": (i, [p]), "SSL_accept": (i, [p]),
            "SSL_get_verify_result": (l, [p]), "SSL_version": (i, [p]),
            "SSL_write": (i, [p, p, i]), "SSL_read": (i, [p, p, i]),
            "SSL_key_update": (i, [p, i]), "SSL_do_handshake": (i, [p]),
            "SSL_shutdown": (i, [p]), "SSL_set_msg_callback": (None, [p, self.MSG]),
        }
        for name, (result, args) in signatures.items():
            function = getattr(self.lib, name)
            function.restype, function.argtypes = result, args
            setattr(self, name, function)

    @staticmethod
    def require(value):
        if value != 1:
            raise RuntimeError("openssl_operation_failed")

    def peer(self, raw, directory, server):
        ctx, ssl = None, None
        result = {"ok": False, "version": 0, "bytes": 0, "updatesSent": [], "updatesReceived": []}

        @self.MSG
        def observe(write, version, kind, data, size, connection, arg):
            # OpenSSL calls this with decrypted handshake messages. Count actual
            # KeyUpdate messages, including request_update; do not log key material.
            if kind == 22 and size == 5:
                message = C.string_at(data, size)
                if message[:4] == b"\x18\x00\x00\x01":
                    result["updatesSent" if write else "updatesReceived"].append(message[4])

        try:
            raw.setblocking(True)
            ctx = self.SSL_CTX_new(self.TLS_method())
            if not ctx:
                raise RuntimeError("openssl_context_failed")
            self.require(self.SSL_CTX_ctrl(ctx, 123, 0x0304, None))  # minimum TLS 1.3
            self.require(self.SSL_CTX_ctrl(ctx, 124, 0x0304, None))  # maximum TLS 1.3
            if server:
                self.require(self.SSL_CTX_use_certificate_chain_file(ctx, os.fsencode(directory / "leaf.pem")))
                self.require(self.SSL_CTX_use_PrivateKey_file(ctx, os.fsencode(directory / "leaf.key"), 1))
            else:
                self.SSL_CTX_set_verify(ctx, 1, None)
                self.require(self.SSL_CTX_load_verify_locations(ctx, os.fsencode(directory / "roots.pem"), None))
            ssl = self.SSL_new(ctx)
            if not ssl:
                raise RuntimeError("openssl_connection_failed")
            self.SSL_set_msg_callback(ssl, observe)
            self.require(self.SSL_set_fd(ssl, raw.fileno()))
            if not server:
                name = C.create_string_buffer(NAMES[0].encode())
                self.require(self.SSL_ctrl(ssl, 55, 0, C.cast(name, C.c_void_p)))  # SNI
                self.require(self.SSL_set1_host(ssl, NAMES[0].encode()))
            self.require((self.SSL_accept if server else self.SSL_connect)(ssl))
            result["version"] = self.SSL_version(ssl)
            if not server and self.SSL_get_verify_result(ssl) != 0:
                raise RuntimeError("untrusted_peer")

            def write(data):
                offset = 0
                while offset < len(data):
                    buf = C.create_string_buffer(data[offset:])
                    count = self.SSL_write(ssl, buf, len(data) - offset)
                    if count <= 0:
                        raise RuntimeError("tls_write_failed")
                    offset += count

            def read(size):
                data = bytearray()
                while len(data) < size:
                    buf = C.create_string_buffer(size - len(data))
                    count = self.SSL_read(ssl, buf, len(buf))
                    if count <= 0:
                        raise RuntimeError("tls_read_failed")
                    data.extend(buf.raw[:count])
                return bytes(data)

            for index, payload in enumerate(PAYLOADS):
                if index == 1:
                    # Both endpoints request an update. On an intercepted
                    # connection each talks to a different Go tls.Conn.
                    self.require(self.SSL_key_update(ssl, 1))
                    self.require(self.SSL_do_handshake(ssl))
                if not server:
                    write(payload)
                if read(len(payload)) != payload:
                    raise RuntimeError("payload_mismatch")
                result["bytes"] += len(payload)
                if server:
                    write(payload)
            if 1 not in result["updatesSent"] or not result["updatesReceived"]:
                raise RuntimeError("key_update_not_observed")
            # Receive the peer's close_notify as well. Closing a socket while a
            # KeyUpdate acknowledgement is still unread can generate TCP RST.
            # The session watchdog bounds this blocking public OpenSSL call.
            shutdown = self.SSL_shutdown(ssl)
            if shutdown == 0:
                shutdown = self.SSL_shutdown(ssl)
            self.require(shutdown)
            result["ok"] = True
        except Exception as error:
            result["error"] = str(error) if isinstance(error, RuntimeError) else type(error).__name__
        finally:
            if ssl:
                self.SSL_free(ssl)
            if ctx:
                self.SSL_CTX_free(ctx)
            raw.close()
        return result


def certificates(directory, proxy_der):
    now = dt.datetime.now(dt.timezone.utc)
    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TLS-217 ephemeral fixture")])
    root = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(days=1))
            .not_valid_after(now + dt.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=0), True)
            .add_extension(x509.KeyUsage(False, False, False, False, False, True, True, False, False), True)
            .sign(key, hashes.SHA256()))
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = (x509.CertificateBuilder().subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, NAMES[0])]))
            .issuer_name(root.subject).public_key(leaf_key.public_key()).serial_number(x509.random_serial_number())
            .not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=1))
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(n) for n in NAMES]), False)
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), True).sign(key, hashes.SHA256()))
    pem = serialization.Encoding.PEM
    (directory / "leaf.pem").write_bytes(leaf.public_bytes(pem) + root.public_bytes(pem))
    (directory / "leaf.key").write_bytes(leaf_key.private_bytes(pem, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
    roots = root.public_bytes(pem)
    if proxy_der:
        roots += x509.load_der_x509_certificate(proxy_der).public_bytes(pem)
    (directory / "roots.pem").write_bytes(roots)
    return base64.b64encode(root.public_bytes(serialization.Encoding.DER)).decode()


class Session:
    def __init__(self, service, kind, proxy_der):
        if kind not in ("keyupdate", "ech"):
            raise ValueError("unknown_kind")
        self.id = uuid.uuid4().hex
        self.temp = tempfile.TemporaryDirectory(prefix="tls217-", dir=service.work)
        self.directory = Path(self.temp.name)
        self.root = certificates(self.directory, proxy_der)
        self.done = threading.Event()
        self.result = {}
        self.sockets = []
        self.process = None
        self.threads = []
        self.closed = False
        if kind == "ech":
            self.process = subprocess.Popen([service.ech, "-bind", service.bind,
                "-cert", str(self.directory / "leaf.pem"), "-key", str(self.directory / "leaf.key"),
                "-roots", str(self.directory / "roots.pem")], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                text=True, creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0)
            self.ports = json.loads(self.process.stdout.readline())
            def collect():
                try:
                    self.result = json.loads(self.process.stdout.readline())
                except Exception:
                    self.result = {"error": "ech_peer_failed"}
                finally:
                    self.done.set()
            self.start_thread(collect)
        else:
            self.ports = {}
            for role in ("origin", "client"):
                listener = socket.socket()
                listener.bind((service.bind, 0))
                listener.listen(1)
                listener.settimeout(30)
                self.sockets.append(listener)
                self.ports[role + "Port"] = listener.getsockname()[1]
                def peer(listener=listener, role=role):
                    try:
                        raw, _ = listener.accept()
                        self.sockets.append(raw)
                        self.result[role] = service.openssl.peer(raw, self.directory, role == "origin")
                    except Exception:
                        self.result[role] = {"ok": False, "error": "accept_failed"}
                    finally:
                        listener.close()
                        if "origin" in self.result and "client" in self.result:
                            self.done.set()
                self.start_thread(peer)
        self.timer = threading.Timer(40, self.close)
        self.timer.daemon = True
        self.timer.start()

    def start_thread(self, target):
        thread = threading.Thread(target=target, daemon=True)
        self.threads.append(thread)
        thread.start()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if hasattr(self, "timer"):
            self.timer.cancel()
        for raw in self.sockets:
            try:
                raw.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            raw.close()
        if self.process:
            if self.process.poll() is None:
                self.process.terminate()
            self.process.wait(timeout=5)
            self.process.stdout.close()
        for thread in self.threads:
            if thread is not threading.current_thread():
                thread.join(timeout=5)
        self.temp.cleanup()


class Service:
    def __init__(self, bind, work, ech):
        self.bind, self.work, self.ech = bind, work, ech
        self.openssl = OpenSSL()
        self.sessions = {}


def handler(service):
    class Handler(http.server.BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def send(self, status, value):
            data = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(data)))
            self.end_headers()
            self.wfile.write(data)

        def do_POST(self):
            try:
                size = int(self.headers.get("Content-Length", "0"))
                if self.path != "/session" or not 0 < size <= 16384 or len(service.sessions) >= 8:
                    raise ValueError("invalid_request")
                request = json.loads(self.rfile.read(size))
                session = Session(service, request["kind"], base64.b64decode(request.get("proxyCaDer", ""), validate=True))
                service.sessions[session.id] = session
                self.send(200, {"id": session.id, "caDer": session.root, **session.ports})
            except Exception:
                self.send(400, {"error": "fixture_setup_failed"})

        def do_GET(self):
            session = service.sessions.get(self.path.removeprefix("/result/"))
            if session is None:
                self.send(404, {"error": "unknown_session"})
            elif not session.done.wait(30):
                self.send(504, {"error": "peer_timeout"})
            else:
                self.send(200, session.result)

        def do_DELETE(self):
            session = service.sessions.pop(self.path.removeprefix("/session/"), None)
            if session:
                session.close()
            self.send(200, {"closed": True})
    return Handler


def bridge(host, ports):
    """Host positive control; the Android test replaces this with its gateway."""
    with socket.create_connection((host, ports["originPort"])) as origin, \
            socket.create_connection((host, ports["clientPort"])) as client:
        origin.settimeout(30)
        client.settimeout(30)
        def copy(source, target):
            try:
                while data := source.recv(32768):
                    target.sendall(data)
                target.shutdown(socket.SHUT_WR)
            except OSError:
                pass
        thread = threading.Thread(target=copy, args=(origin, client))
        thread.start()
        copy(client, origin)
        thread.join(30)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--bind", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=18087)
    parser.add_argument("--ech-peer", required=True)
    parser.add_argument("--work", default="build/tls-217/protocol-fixture")
    parser.add_argument("--self-test", action="store_true")
    args = parser.parse_args()
    work = Path(args.work).resolve()
    work.mkdir(parents=True, exist_ok=True)
    service = Service(args.bind, work, str(Path(args.ech_peer).resolve()))
    if args.self_test:
        for kind in ("keyupdate", "ech"):
            session = Session(service, kind, b"")
            try:
                bridge(args.bind, session.ports)
                assert session.done.wait(30), "peer_timeout"
                print(json.dumps({"kind": kind, **session.result}), flush=True)
                for role in ("client", "origin"):
                    assert session.result[role]["ok"]
                    assert session.result[role]["version"] == 0x0304
                    if kind == "ech":
                        assert session.result[role]["echAccepted"]
                        assert session.result[role]["serverName"] == NAMES[0]
            finally:
                session.close()
        return
    server = http.server.ThreadingHTTPServer((args.bind, args.port), handler(service))
    print(json.dumps({"ready": True, "bind": args.bind, "port": args.port}), flush=True)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        for session in list(service.sessions.values()):
            session.close()


if __name__ == "__main__":
    main()

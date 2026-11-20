#!/usr/bin/env python3
"""Run controlled TLS endpoints and capture public, synthetic loopback fixtures.

Subcommands: generate, serve, client. Certificate keys exist only in a temporary
directory during execution. Only the explicit test root is trusted by clients.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timedelta, timezone
import http.client
import http.server
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import DataReceived, RequestReceived, ResponseReceived, StreamEnded, StreamReset

from check_fixture import check_manifest, inspect_capture, keylog_random, require, sha256, tool_version

ROOT = Path(__file__).resolve().parent
REPOSITORY = ROOT.parents[2]
BODY = b"LayerAnalyzer TLS fixture v1\n"
SERVER_NAME = "fixture.layeranalyzer.test"
PROTOCOLS = {"tls12-h1": (ssl.TLSVersion.TLSv1_2, "TLS1.2", "http/1.1"),
             "tls13-h1": (ssl.TLSVersion.TLSv1_3, "TLS1.3", "http/1.1"),
             "tls13-h2": (ssl.TLSVersion.TLSv1_3, "TLS1.3", "h2")}


def write_json(path: Path, data: dict) -> None:
    path.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")


def configure_tls(context: ssl.SSLContext, protocol: str) -> None:
    version, _, alpn = PROTOCOLS[protocol]
    context.minimum_version = context.maximum_version = version
    context.set_alpn_protocols([alpn])
    if version == ssl.TLSVersion.TLSv1_2:
        context.set_ciphers("ECDHE-RSA-AES128-GCM-SHA256")


def certificates(directory: Path) -> tuple[Path, Path, Path]:
    now = datetime.now(timezone.utc)
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    leaf_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "LayerAnalyzer synthetic test root")])
    ca = (x509.CertificateBuilder().subject_name(ca_name).issuer_name(ca_name)
          .public_key(ca_key.public_key()).serial_number(x509.random_serial_number())
          .not_valid_before(now - timedelta(minutes=5)).not_valid_after(now + timedelta(days=2))
          .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
          .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=None, decipher_only=None), critical=True)
          .sign(ca_key, hashes.SHA256()))
    leaf = (x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, SERVER_NAME)]))
            .issuer_name(ca_name).public_key(leaf_key.public_key())
            .serial_number(x509.random_serial_number()).not_valid_before(now - timedelta(minutes=5))
            .not_valid_after(now + timedelta(days=1))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.SubjectAlternativeName([x509.DNSName(SERVER_NAME)]), critical=False)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .sign(ca_key, hashes.SHA256()))
    ca_path, leaf_path, key_path = (directory / name for name in ("ca.pem", "server.pem", "server.key"))
    ca_path.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    leaf_path.write_bytes(leaf.public_bytes(serialization.Encoding.PEM)
                          + ca.public_bytes(serialization.Encoding.PEM))
    key_path.write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
                                              serialization.PrivateFormat.PKCS8,
                                              serialization.NoEncryption()))
    if os.name != "nt":
        key_path.chmod(0o600)
    return ca_path, leaf_path, key_path


class FixtureHttpHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        if self.path != "/fixture":
            self.send_error(404)
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/octet-stream")
        self.send_header("Content-Length", str(len(BODY)))
        self.send_header("Connection", "close")
        self.end_headers()
        self.wfile.write(BODY)
        self.wfile.flush()

    def log_message(self, format: str, *args) -> None:
        pass


def serve_h2(connection: ssl.SSLSocket) -> None:
    h2 = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
    h2.initiate_connection()
    connection.sendall(h2.data_to_send())
    while True:
        data = connection.recv(65536)
        require(bool(data), "HTTP2 client closed before completing request")
        finished = False
        for event in h2.receive_data(data):
            if isinstance(event, RequestReceived):
                headers = dict(event.headers)
                require(headers.get(":method") == "GET" and headers.get(":path") == "/fixture",
                        "Unexpected HTTP2 request")
            if isinstance(event, DataReceived):
                h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            if isinstance(event, StreamEnded):
                h2.send_headers(event.stream_id, [(":status", "200"),
                                                 ("content-type", "application/octet-stream"),
                                                 ("content-length", str(len(BODY)))])
                h2.send_data(event.stream_id, BODY, end_stream=True)
                finished = True
        pending = h2.data_to_send()
        if pending:
            connection.sendall(pending)
        if finished:
            # Drain the client's SETTINGS ACK until it closes after reading END_STREAM.
            # Closing with unread TCP bytes can send RST and discard the response on Windows.
            while True:
                try:
                    pending_client = connection.recv(65536)
                except (ConnectionResetError, ssl.SSLEOFError):
                    break
                if not pending_client:
                    break
                h2.receive_data(pending_client)
            return


class FixtureServer:
    def __init__(self, protocol: str, bind: str, port: int, certificate: Path, key: Path):
        self.protocol = protocol
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        configure_tls(self.context, protocol)
        self.context.load_cert_chain(certificate, key)
        self.listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.listener.bind((bind, port))
        self.listener.listen(4)
        self.listener.settimeout(0.2)
        self.port = self.listener.getsockname()[1]
        self.stop_event = threading.Event()
        self.errors: list[str] = []
        self.rejected_handshakes = 0
        self.thread = threading.Thread(target=self.run, name="tls-fixture-server", daemon=True)

    def run(self) -> None:
        while not self.stop_event.is_set():
            try:
                raw, address = self.listener.accept()
            except socket.timeout:
                continue
            except OSError:
                break
            established = False
            try:
                raw.settimeout(5)
                with raw, self.context.wrap_socket(raw, server_side=True) as connection:
                    established = True
                    require(connection.selected_alpn_protocol() == PROTOCOLS[self.protocol][2],
                            "Client did not negotiate required ALPN")
                    if self.protocol.endswith("h2"):
                        serve_h2(connection)
                    else:
                        FixtureHttpHandler(connection, address, self)
            except (ssl.SSLError, ConnectionResetError) as error:
                # OpenSSL may send an alert or reset on a rejected certificate. The client
                # independently proves CERTIFICATE_VERIFY_FAILED; established I/O errors fail.
                if not established:
                    self.rejected_handshakes += 1
                else:
                    self.errors.append(type(error).__name__)
            except Exception as error:
                self.errors.append(type(error).__name__)
            finally:
                raw.close()

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, *args):
        self.stop_event.set()
        self.listener.close()
        self.thread.join(timeout=6)
        require(not self.thread.is_alive(), "Fixture server did not stop")
        require(not self.errors, f"Fixture server failed: {self.errors}")


def client_h2(connection: ssl.SSLSocket, server_name: str) -> tuple[int, bytes]:
    h2 = H2Connection(config=H2Configuration(client_side=True, header_encoding="utf-8"))
    h2.initiate_connection()
    h2.send_headers(1, [(":method", "GET"), (":scheme", "https"),
                        (":authority", server_name), (":path", "/fixture")], end_stream=True)
    connection.sendall(h2.data_to_send())
    body, status, finished = bytearray(), None, False
    while not finished:
        data = connection.recv(65536)
        require(bool(data), "HTTP2 response ended before END_STREAM")
        for event in h2.receive_data(data):
            if isinstance(event, ResponseReceived):
                require(event.stream_id == 1, "Unexpected HTTP2 stream")
                status = int(dict(event.headers)[":status"])
            if isinstance(event, DataReceived):
                require(event.stream_id == 1, "Unexpected HTTP2 DATA stream")
                body.extend(event.data)
                h2.acknowledge_received_data(event.flow_controlled_length, event.stream_id)
            if isinstance(event, StreamReset):
                raise ValueError("HTTP2 stream reset")
            if isinstance(event, StreamEnded):
                require(event.stream_id == 1, "Unexpected HTTP2 end stream")
                finished = True
        # Do not write SETTINGS acknowledgements after the server has completed and closed.
        if not finished and (pending := h2.data_to_send()):
            connection.sendall(pending)
        require(len(body) <= 1024 * 1024, "Fixture response exceeds limit")
    require(status is not None, "Missing HTTP2 response status")
    return status, bytes(body)


def run_client(protocol: str, host: str, port: int, server_name: str,
               ca: Path | None, keylog: Path | None = None) -> dict:
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    configure_tls(context, protocol)
    # With ca=None the store remains empty: certificate verification is still REQUIRED.
    if ca:
        context.load_verify_locations(cafile=str(ca))
    if keylog:
        require(not keylog.exists(), "Refusing to append to an existing keylog")
        context.keylog_filename = str(keylog)
    try:
        with socket.create_connection((host, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname=server_name) as connection:
                actual_version = connection.version().replace("v", "")
                actual_alpn = connection.selected_alpn_protocol()
                require((actual_version, actual_alpn) == PROTOCOLS[protocol][1:], "TLS/ALPN mismatch")
                cipher = connection.cipher()[0]
                if actual_alpn == "h2":
                    status, body = client_h2(connection, server_name)
                else:
                    request = http.client.HTTPConnection(server_name, port, timeout=5)
                    request.sock = connection
                    request.request("GET", "/fixture", headers={"Connection": "close"})
                    response = request.getresponse()
                    status, body = response.status, response.read(1024 * 1024 + 1)
                    request.close()
                require(status == 200 and body == BODY, "Independent client response mismatch")
        result = {"success": True, "certificateVerified": True, "tlsVersion": actual_version,
                  "alpn": actual_alpn, "cipher": cipher, "destinationPort": port,
                  "serverName": server_name, "status": status,
                  "bodyBase64": base64.b64encode(body).decode("ascii"), "bodySha256": sha256(body)}
        if keylog:
            result["connectionId"] = "client-random:" + keylog_random(keylog)
        return result
    except ssl.SSLCertVerificationError:
        return {"success": False, "errorCode": "CERTIFICATE_VERIFY_FAILED"}


def capture_client(dumpcap: str, interface: str, output: Path,
                   protocol: str, port: int, ca: Path, keylog: Path) -> dict:
    command = [dumpcap, "-i", interface, "-p", "-f", f"host 127.0.0.1 and tcp port {port}",
               "-P", "-w", str(output), "-a", "duration:5", "-q"]
    with subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE) as process:
        try:
            deadline = time.monotonic() + 4
            while not output.exists() or output.stat().st_size < 24:
                require(process.poll() is None, "dumpcap failed before capture became ready")
                require(time.monotonic() < deadline, "dumpcap readiness timed out")
                time.sleep(0.05)
            # The file header is created by dumpcap after the interface is activated.
            result = run_client(protocol, "127.0.0.1", port, SERVER_NAME, ca, keylog)
            process.communicate(timeout=10)
            require(process.returncode == 0, "dumpcap failed")
            require(result["success"], "Trusted client failed")
            return result
        finally:
            if process.poll() is None:
                process.kill()
                process.communicate(timeout=5)


def generate(args) -> None:
    output = args.output.resolve()
    output.mkdir(parents=True, exist_ok=True)
    # Explicit, new output only: failed generations cannot overwrite a published manifest.
    require(not (output / "manifest.json").exists(), "Output already contains manifest.json; use a new directory")
    require(not any((output / protocol).exists() for protocol in PROTOCOLS),
            "Output contains fixture directories; use a new directory")
    tshark = shutil.which(args.tshark)
    require(tshark is not None, "tshark executable not found")
    dumpcap = args.dumpcap or str(Path(tshark).with_name("dumpcap.exe" if os.name == "nt" else "dumpcap"))
    versions = {"python": platform.python_version(), "openssl": ssl.OPENSSL_VERSION,
                "h2": importlib.metadata.version("h2"),
                "cryptography": importlib.metadata.version("cryptography"),
                "jsonschema": importlib.metadata.version("jsonschema"),
                "tshark": tool_version(tshark), "dumpcap": tool_version(dumpcap)}
    interface = args.interface or (r"\Device\NPF_Loopback" if os.name == "nt" else "lo")
    require(interface in (r"\Device\NPF_Loopback", "lo", "lo0"), "Only loopback capture is allowed")
    relative_output = os.path.relpath(output, REPOSITORY).replace("\\", "/")
    require(not relative_output.startswith(".."), "Generate under the repository to preserve portable provenance")
    command = ["python", "native_build/verification/tls/generate_fixture.py", "generate",
               "--output", relative_output, "--tshark", "${TSHARK}",
               "--dumpcap", "${DUMPCAP}", "--interface", interface]
    manifest = {"schemaVersion": 1, "fixtures": []}
    for protocol, (_, tls_version, alpn) in PROTOCOLS.items():
        directory = output / protocol
        directory.mkdir()
        with tempfile.TemporaryDirectory(prefix="la-fixture-cert-") as temporary:
            ca, certificate, key = certificates(Path(temporary))
            shutil.copyfile(ca, directory / "ca.pem")
            with FixtureServer(protocol, "127.0.0.1", 0, certificate, key) as server:
                trusted = capture_client(dumpcap, interface, directory / "capture.pcap", protocol,
                                         server.port, ca, directory / "session.keys")
                # Capture has stopped; this is a new SSLContext and a new TCP/TLS connection.
                wrong = run_client(protocol, "127.0.0.1", server.port, SERVER_NAME,
                                   ca, directory / "wrong.keys")
                untrusted = run_client(protocol, "127.0.0.1", server.port, SERVER_NAME, None)
                require(wrong["success"] and not untrusted["success"], "Trust test did not behave as expected")
                clients = {"schemaVersion": 1, "trusted": trusted, "wrongConnection": wrong,
                           "untrusted": untrusted}
                write_json(directory / "client-result.json", clients)
            actual = inspect_capture(tshark, directory / "capture.pcap", directory / "session.keys",
                                     trusted["destinationPort"], alpn)
            require(actual["body"] == BODY, f"{protocol}: reference dissection body mismatch")
            (directory / "golden-body.bin").write_bytes(actual["body"])

        entries = []
        for role, filename in (("pcap", "capture.pcap"), ("keylog", "session.keys"),
                               ("wrong-keylog", "wrong.keys"), ("ca-certificate", "ca.pem"),
                               ("client-result", "client-result.json"), ("golden-body", "golden-body.bin")):
            entry = {"role": role, "path": f"{protocol}/{filename}",
                     "sha256": sha256((directory / filename).read_bytes())}
            if role in ("pcap", "keylog", "wrong-keylog"):
                entry["connectionId"] = (wrong if role == "wrong-keylog" else trusted)["connectionId"]
            if role in ("keylog", "wrong-keylog"):
                entry["keyDirection"] = "direct-test-connection"
            entries.append(entry)
        manifest["fixtures"].append({"fixtureId": protocol, "tlsVersion": tls_version, "alpn": alpn,
                                     "source": "synthetic-local-test-only",
                                     "expectedBody": {"encoding": "utf-8", "text": BODY.decode("utf-8"),
                                                      "sha256": sha256(BODY)}, "files": entries,
                                     "generation": {"generatedAtUtc": datetime.now(timezone.utc).isoformat().replace("+00:00", "Z"),
                                                    "command": command, "workingDirectory": "repository-root",
                                                    "toolVersions": versions, "captureMethod": "host-loopback"}})
        print(f"Captured {protocol}: trusted response verified; unknown root rejected", flush=True)
    pending_manifest = output / "manifest.pending.json"
    write_json(pending_manifest, manifest)
    check_manifest(pending_manifest, tshark)
    pending_manifest.replace(output / "manifest.json")
    print("Validated all three protocols with correct, wrong and empty keylogs", flush=True)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    generator = commands.add_parser("generate", help="Capture only synthetic IPv4 loopback traffic")
    generator.add_argument("--output", type=Path, default=ROOT / "fixtures")
    generator.add_argument("--tshark", default="tshark")
    generator.add_argument("--dumpcap")
    generator.add_argument("--interface")
    server = commands.add_parser("serve", help="Serve a fixture on an explicitly chosen controlled address")
    server.add_argument("--protocol", required=True, choices=PROTOCOLS)
    server.add_argument("--bind", required=True)
    server.add_argument("--port", type=int, required=True)
    server.add_argument("--ca-output", type=Path, required=True, help="Public certificate only")
    client = commands.add_parser("client", help="Fetch and verify the known fixture response")
    client.add_argument("--protocol", required=True, choices=PROTOCOLS)
    client.add_argument("--host", required=True, help="10.0.2.2 on emulator, controlled LAN IP on device")
    client.add_argument("--port", type=int, required=True)
    client.add_argument("--server-name", default=SERVER_NAME)
    trust = client.add_mutually_exclusive_group(required=True)
    trust.add_argument("--trust-ca", type=Path)
    trust.add_argument("--reject-ca", action="store_true")
    client.add_argument("--result", type=Path, required=True)
    args = parser.parse_args()
    try:
        if args.command == "generate":
            generate(args)
        elif args.command == "serve":
            require(not args.ca_output.exists(), "Public CA output already exists; choose a new path")
            with tempfile.TemporaryDirectory(prefix="la-fixture-cert-") as directory:
                ca, certificate, key = certificates(Path(directory))
                args.ca_output.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(ca, args.ca_output)
                with FixtureServer(args.protocol, args.bind, args.port, certificate, key) as endpoint:
                    print(json.dumps({"ready": True, "port": endpoint.port, "serverName": SERVER_NAME,
                                      "protocol": args.protocol}), flush=True)
                    try:
                        while True:
                            time.sleep(0.5)
                    except KeyboardInterrupt:
                        pass
        else:
            result = run_client(args.protocol, args.host, args.port, args.server_name, args.trust_ca)
            args.result.parent.mkdir(parents=True, exist_ok=True)
            write_json(args.result, result)
            expected_success = not args.reject_ca
            require(result["success"] == expected_success, "Client trust outcome mismatch")
            print("Client response verified" if result["success"] else "Unknown test root rejected as expected")
        return 0
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Fixture generation failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Controlled TLS-402 LAN origins. No Internet, persistent keys or trust-all.

Run with the fixture requirements installed. Public certificates, counters and
client public keys cross the control channel; all private keys stay local.
"""
import argparse
import base64
import datetime as dt
import hashlib
import http.server
import ipaddress
import json
from pathlib import Path
import socket
import ssl
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from h2.config import H2Configuration
from h2.connection import H2Connection
from h2.events import ConnectionTerminated, RequestReceived, StreamEnded

BODY = b"LayerAnalyzer TLS-402 controlled body\n"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--ipv4", required=True)
    parser.add_argument("--ipv6", required=True)
    parser.add_argument("--control-port", type=int, default=18088)
    parser.add_argument("--tls-port", type=int, default=18448)
    parser.add_argument("--mtls-port", type=int, default=18449)
    args = parser.parse_args()
    addresses = [str(ipaddress.ip_address(args.ipv4)), str(ipaddress.ip_address(args.ipv6))]
    now = dt.datetime.now(dt.timezone.utc)
    root_key = ec.generate_private_key(ec.SECP256R1())
    root_name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "TLS-402 ephemeral origin root")])

    def certificate(public_key, name, *, ca=False, client=False):
        builder = (x509.CertificateBuilder().subject_name(name).issuer_name(root_name)
                   .public_key(public_key).serial_number(x509.random_serial_number())
                   .not_valid_before(now - dt.timedelta(minutes=5))
                   .not_valid_after(now + dt.timedelta(days=1))
                   .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
        if not ca:
            builder = builder.add_extension(x509.ExtendedKeyUsage([
                ExtendedKeyUsageOID.CLIENT_AUTH if client else ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
        if not ca and not client:
            builder = builder.add_extension(x509.SubjectAlternativeName([
                x509.DNSName("localhost"), *[x509.IPAddress(ipaddress.ip_address(a)) for a in addresses]]), critical=False)
        return builder.sign(root_key, hashes.SHA256())

    root = certificate(root_key.public_key(), root_name, ca=True)
    leaf_key = ec.generate_private_key(ec.SECP256R1())
    leaf = certificate(leaf_key.public_key(), x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
    der = lambda cert: base64.b64encode(cert.public_bytes(serialization.Encoding.DER)).decode("ascii")
    counters, lock = {}, threading.Lock()
    listeners = []

    with tempfile.TemporaryDirectory(prefix="tls402-origin-") as directory:
        directory = Path(directory)
        (directory / "root.pem").write_bytes(root.public_bytes(serialization.Encoding.PEM))
        (directory / "leaf.pem").write_bytes(leaf.public_bytes(serialization.Encoding.PEM) + root.public_bytes(serialization.Encoding.PEM))
        (directory / "leaf.key").write_bytes(leaf_key.private_bytes(serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))

        def serve_peer(raw, context, label):
            with lock:
                counters[label]["accepted"] += 1
            try:
                raw.settimeout(15)
                with context.wrap_socket(raw, server_side=True) as peer:
                    def record_request():
                        with lock:
                            counters[label]["requests"] += 1
                            counters[label]["tls"] = peer.version()
                            counters[label]["alpn"] = peer.selected_alpn_protocol()
                            counters[label]["clientIdentity"] = bool(peer.getpeercert(binary_form=True))

                    if peer.selected_alpn_protocol() == "h2":
                        connection = H2Connection(config=H2Configuration(client_side=False, header_encoding="utf-8"))
                        connection.initiate_connection()
                        peer.sendall(connection.data_to_send())
                        received = 0
                        request = False
                        while True:
                            data = peer.recv(4096)
                            if not data:
                                return
                            received += len(data)
                            if received > 65536:
                                raise ValueError("h2 request budget")
                            for event in connection.receive_data(data):
                                if isinstance(event, ConnectionTerminated):
                                    return
                                if isinstance(event, RequestReceived):
                                    headers = dict(event.headers)
                                    if request or event.stream_id != 1 or headers.get(":method") != "GET" or headers.get(":path") != "/":
                                        raise ValueError("one controlled h2 GET required")
                                    request = True
                                if isinstance(event, StreamEnded):
                                    if not request or event.stream_id != 1:
                                        raise ValueError("missing h2 request")
                                    record_request()
                                    connection.send_headers(1, [(":status", "200"), ("content-length", str(len(BODY)))])
                                    connection.send_data(1, BODY, end_stream=True)
                            peer.sendall(connection.data_to_send())
                    data = bytearray()
                    while b"\r\n\r\n" not in data and len(data) <= 4096:
                        part = peer.recv(1024)
                        if not part:
                            break
                        data.extend(part)
                    if not data:
                        return
                    if not data.startswith(b"GET / HTTP/1.") or b"\r\n\r\n" not in data:
                        raise ValueError("invalid controlled request")
                    record_request()
                    peer.sendall(b"HTTP/1.0 200 OK\r\nContent-Length: " + str(len(BODY)).encode() +
                                 b"\r\nConnection: close\r\n\r\n" + BODY)
            except (OSError, ssl.SSLError, ValueError):
                with lock:
                    counters[label]["rejected"] += 1
            finally:
                raw.close()

        def accept(listener, context, label):
            while True:
                try:
                    raw, _ = listener.accept()
                except OSError:
                    return
                threading.Thread(target=serve_peer, args=(raw, context, label), daemon=True).start()

        for address in addresses:
            for mtls in (False, True):
                label = ("ipv6" if ":" in address else "ipv4") + ("-mtls" if mtls else "-tls")
                counters[label] = {"accepted": 0, "requests": 0, "rejected": 0}
                context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
                context.minimum_version = ssl.TLSVersion.TLSv1_2
                context.load_cert_chain(directory / "leaf.pem", directory / "leaf.key")
                context.set_alpn_protocols(["h2", "http/1.1"])
                if mtls:
                    context.verify_mode = ssl.CERT_REQUIRED
                    context.load_verify_locations(directory / "root.pem")
                listener = socket.socket(socket.AF_INET6 if ":" in address else socket.AF_INET, socket.SOCK_STREAM)
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                if ":" in address:
                    listener.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
                listener.bind((address, args.mtls_port if mtls else args.tls_port))
                listener.listen(8)
                listeners.append(listener)
                threading.Thread(target=accept, args=(listener, context, label), daemon=True).start()

        # SSLContext has copied the leaf key. Remove its temporary copy now so
        # terminating the host process cannot leave a private-key file behind.
        (directory / "leaf.key").unlink()

        class Control(http.server.BaseHTTPRequestHandler):
            def log_message(self, *unused):
                pass

            def reply(self, value):
                data = json.dumps(value).encode()
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(data)))
                self.end_headers()
                self.wfile.write(data)

            def do_GET(self):
                if self.path != "/":
                    self.send_error(404)
                    return
                with lock:
                    self.reply({"rootDer": der(root), "leafDer": der(leaf), "ipv4": addresses[0],
                        "ipv6": addresses[1], "tlsPort": args.tls_port, "mtlsPort": args.mtls_port,
                        "bodySha256": hashlib.sha256(BODY).hexdigest(), "counters": counters})

            def do_POST(self):
                length = int(self.headers.get("Content-Length", "0"))
                if self.path != "/client-certificate" or not 0 < length <= 4096:
                    self.send_error(400)
                    return
                try:
                    key = serialization.load_der_public_key(base64.b64decode(self.rfile.read(length), validate=True))
                    if not isinstance(key, ec.EllipticCurvePublicKey):
                        raise ValueError("EC client public key required")
                    client = certificate(key, x509.Name([x509.NameAttribute(NameOID.COMMON_NAME,
                        "TLS-402 ephemeral client")]), client=True)
                    self.reply({"certificateDer": der(client)})
                except ValueError:
                    self.send_error(400)

            def do_DELETE(self):
                if self.path != "/":
                    self.send_error(404)
                    return
                self.reply({"stopped": True})
                threading.Thread(target=self.server.shutdown, daemon=True).start()

        try:
            server = http.server.ThreadingHTTPServer((addresses[0], args.control_port), Control)
            print("READY TLS-402 controlled IPv4/IPv6 TLS and mTLS origins; memory/temporary keys only", flush=True)
            server.serve_forever()
        finally:
            for listener in listeners:
                listener.close()
            if "server" in locals():
                server.server_close()


if __name__ == "__main__":
    main()

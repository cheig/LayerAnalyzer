"""Exercise the controlled source with real TLS and certificate validation."""
import base64
import json
from pathlib import Path
import socket
import ssl
import subprocess
import sys
import tempfile
import unittest
import urllib.request

from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from h2.connection import H2Connection
from h2.events import DataReceived, StreamEnded

from platform_fixture import BODY


class PlatformFixtureTest(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        def port():
            with socket.socket() as peer:
                peer.bind(("127.0.0.1", 0))
                return peer.getsockname()[1]
        cls.control, cls.tls, cls.mtls = port(), port(), port()
        cls.process = subprocess.Popen([sys.executable, str(Path(__file__).with_name("platform_fixture.py")),
            "--ipv4", "127.0.0.1", "--ipv6", "::1", "--control-port", str(cls.control),
            "--tls-port", str(cls.tls), "--mtls-port", str(cls.mtls)], stdout=subprocess.PIPE,
            stderr=subprocess.PIPE, text=True)
        if not cls.process.stdout.readline().startswith("READY TLS-402"):
            raise AssertionError("controlled source did not start")
        cls.base = f"http://127.0.0.1:{cls.control}/"
        # Explicitly avoid any host HTTP proxy configuration for loopback control.
        cls.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
        with cls.opener.open(cls.base, timeout=5) as response:
            cls.fixture = json.load(response)
        root = x509.load_der_x509_certificate(base64.b64decode(cls.fixture["rootDer"]))
        cls.root_pem = root.public_bytes(serialization.Encoding.PEM).decode()

    @classmethod
    def tearDownClass(cls):
        try:
            with cls.opener.open(urllib.request.Request(cls.base, method="DELETE"), timeout=5):
                pass
            cls.process.communicate(timeout=10)
        finally:
            if cls.process.poll() is None:
                cls.process.kill()
                cls.process.communicate(timeout=5)

    def request(self, address, port, context):
        with socket.create_connection((address, port), timeout=5) as raw:
            with context.wrap_socket(raw, server_hostname="localhost") as peer:
                version = peer.version()
                peer.sendall(b"GET / HTTP/1.0\r\nHost: localhost\r\n\r\n")
                data = bytearray()
                while chunk := peer.recv(1024):
                    data.extend(chunk)
                if not data:
                    # TLS1.3/OpenSSL may surface the server's missing-client-cert
                    # alert as a clean EOF instead of raising SSLError on recv.
                    raise EOFError("Controlled TLS source returned no application bytes")
                self.assertIn(b"\r\n\r\n", data, "source must return an actual HTTP response")
                self.assertEqual(BODY, data.split(b"\r\n\r\n", 1)[1])
                return version

    def context(self):
        return ssl.create_default_context(cadata=self.root_pem)

    def test_both_ip_families_and_tls_versions_return_the_locked_body(self):
        for address in ("127.0.0.1", "::1"):
            for version, expected in ((ssl.TLSVersion.TLSv1_2, "TLSv1.2"), (ssl.TLSVersion.TLSv1_3, "TLSv1.3")):
                with self.subTest(address=address, version=expected):
                    context = self.context()
                    context.minimum_version = context.maximum_version = version
                    self.assertEqual(expected, self.request(address, self.tls, context))

    def test_system_trust_rejects_the_ephemeral_origin(self):
        with self.assertRaises(ssl.SSLCertVerificationError):
            self.request("127.0.0.1", self.tls, ssl.create_default_context())

    def test_http2_negotiates_and_returns_the_locked_body_on_both_tls_versions(self):
        for version in (ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_3):
            with self.subTest(version=version):
                context = self.context()
                context.minimum_version = context.maximum_version = version
                context.set_alpn_protocols(["h2"])
                with socket.create_connection(("127.0.0.1", self.tls), timeout=5) as raw:
                    with context.wrap_socket(raw, server_hostname="localhost") as peer:
                        self.assertEqual("h2", peer.selected_alpn_protocol())
                        connection = H2Connection()
                        connection.initiate_connection()
                        connection.send_headers(1, [(":method", "GET"), (":scheme", "https"),
                            (":authority", "localhost"), (":path", "/")], end_stream=True)
                        peer.sendall(connection.data_to_send())
                        body = bytearray()
                        done = False
                        while not done:
                            data = peer.recv(4096)
                            self.assertTrue(data, "h2 must end its stream")
                            for event in connection.receive_data(data):
                                if isinstance(event, DataReceived):
                                    body.extend(event.data)
                                if isinstance(event, StreamEnded):
                                    done = True
                        self.assertEqual(BODY, body)
                        connection.close_connection()
                        peer.sendall(connection.data_to_send())

    def test_mtls_rejects_an_anonymous_client(self):
        with self.assertRaises((ssl.SSLError, EOFError)):
            self.request("127.0.0.1", self.mtls, self.context())
        # A dead fixture is not evidence of client-certificate rejection.
        self.assertIsNone(self.process.poll(), "controlled mTLS source must stay alive")
        with self.opener.open(self.base, timeout=5) as response:
            self.assertEqual(200, response.status)

    def test_mtls_accepts_only_the_identity_signed_for_the_client_public_key(self):
        key = ec.generate_private_key(ec.SECP256R1())
        public = base64.b64encode(key.public_key().public_bytes(serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo))
        with self.opener.open(urllib.request.Request(self.base + "client-certificate", data=public), timeout=5) as response:
            certificate = x509.load_der_x509_certificate(base64.b64decode(json.load(response)["certificateDer"]))
        self.assertEqual(key.public_key().public_numbers(), certificate.public_key().public_numbers())
        with tempfile.TemporaryDirectory(prefix="tls402-host-client-") as directory:
            directory = Path(directory)
            (directory / "client.pem").write_bytes(certificate.public_bytes(serialization.Encoding.PEM))
            path = directory / "client.key"
            path.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
            context = self.context()
            context.load_cert_chain(directory / "client.pem", path)
            path.unlink()
            self.assertEqual("TLSv1.3", self.request("::1", self.mtls, context))


if __name__ == "__main__":
    unittest.main()

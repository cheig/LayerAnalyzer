"""Host regressions for evidence tampering and real HTTP2 shutdown behavior."""
import base64
import json
import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from check_fixture import check_manifest, sha256
from generate_fixture import BODY, FixtureServer, PROTOCOLS, ROOT, SERVER_NAME, certificates, run_client
from jsonschema.exceptions import ValidationError


class FixtureEvidenceTest(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory(prefix="la-fixture-test-")
        self.addCleanup(self.temporary.cleanup)
        self.directory = Path(self.temporary.name)
        source = ROOT / "fixtures"
        self.data = json.loads((source / "manifest.json").read_text(encoding="utf-8"))
        for protocol in (fixture["fixtureId"] for fixture in self.data["fixtures"]):
            shutil.copytree(source / protocol, self.directory / protocol)
        self.manifest = self.directory / "manifest.json"
        self.tshark = os.environ.get("TSHARK", "tshark")

    def save(self):
        self.manifest.write_text(json.dumps(self.data), encoding="utf-8")

    def change_file(self, role, content):
        entry = next(item for item in self.data["fixtures"][0]["files"] if item["role"] == role)
        (self.directory / entry["path"]).write_bytes(content)
        entry["sha256"] = sha256(content)

    def assert_rejected(self, message):
        self.save()
        with self.assertRaisesRegex(ValueError, message):
            check_manifest(self.manifest, self.tshark)

    def test_changed_capture_hash(self):
        (self.directory / "tls12-h1/capture.pcap").write_bytes(b"tampered")
        self.assert_rejected("File hash mismatch")

    def test_unknown_schema_version_cli_returns_nonzero(self):
        self.data["schemaVersion"] = 2
        self.save()
        process = subprocess.run([sys.executable, str(ROOT / "check_fixture.py"),
                                  "--manifest", str(self.manifest), "--tshark", self.tshark],
                                 capture_output=True, timeout=20)
        self.assertEqual(1, process.returncode)
        self.assertIn(b"schema validation failed", process.stderr)

    def test_path_traversal(self):
        self.data["fixtures"][0]["files"][0]["path"] = "../capture.pcap"
        self.save()
        with self.assertRaises((ValueError, ValidationError)):
            check_manifest(self.manifest, self.tshark)

    def test_missing_protocol_combination(self):
        self.data["fixtures"] = [fixture for fixture in self.data["fixtures"] if fixture["alpn"] != "h2"]
        self.assert_rejected("Missing required TLS/ALPN")

    def test_wrong_keylog_cannot_be_correct_keylog(self):
        self.change_file("wrong-keylog", (self.directory / "tls12-h1/session.keys").read_bytes())
        self.assert_rejected("Wrong keylog belongs")

    def test_client_claim_is_checked(self):
        client = json.loads((self.directory / "tls12-h1/client-result.json").read_text())
        client["trusted"]["certificateVerified"] = False
        self.change_file("client-result", json.dumps(client).encode())
        self.assert_rejected("Trusted client did not verify")

    def test_forged_golden_and_client_cannot_replace_dissection(self):
        forged = b"This text never crossed the TLS connection\n"
        expected = self.data["fixtures"][0]["expectedBody"]
        expected.update(text=forged.decode(), sha256=sha256(forged))
        client = json.loads((self.directory / "tls12-h1/client-result.json").read_text())
        for name in ("trusted", "wrongConnection"):
            client[name].update(bodyBase64=base64.b64encode(forged).decode(), bodySha256=sha256(forged))
        self.change_file("client-result", json.dumps(client).encode())
        self.change_file("golden-body", forged)
        self.assert_rejected("Dissected golden response mismatch")

    def test_standalone_clients_and_http2_ack_shutdown(self):
        ca, cert, key = certificates(self.directory)
        for protocol in PROTOCOLS:
            with FixtureServer(protocol, "127.0.0.1", 0, cert, key) as server:
                for option in (["--trust-ca", str(ca)], ["--reject-ca"]):
                    process = subprocess.run([sys.executable, str(ROOT / "generate_fixture.py"), "client",
                                              "--protocol", protocol, "--host", "127.0.0.1",
                                              "--port", str(server.port), "--result", str(self.directory / "client.json"),
                                              *option], capture_output=True, timeout=15)
                    self.assertEqual(0, process.returncode, process.stderr.decode(errors="replace"))
                if protocol == "tls13-h2":
                    for _ in range(20):
                        result = run_client(protocol, "127.0.0.1", server.port, SERVER_NAME, ca)
                        self.assertEqual(sha256(BODY), result["bodySha256"])


if __name__ == "__main__":
    unittest.main()

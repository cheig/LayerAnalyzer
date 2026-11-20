"""Fail closed when dependency provenance or actual build metadata drifts."""
import sys
import tempfile
from pathlib import Path
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_tls_dependencies as tls


INFO = """liblayanalyzer_tls.so: go1.27.2
    path com.layeranalyzer/tlsbridge/cmd/androidbridge
    mod com.layeranalyzer/tlsbridge (devel)
    build -buildmode=c-shared
    build CGO_ENABLED=1
    build GOOS=android
"""


class TlsDependencyTest(unittest.TestCase):
    def test_reviewed_source_materials(self):
        self.assertEqual([], tls.check_materials())

    def test_json_stream_handles_multiple_packages(self):
        self.assertEqual([{"a": 1}, {"b": 2}], tls.json_stream(' \n{"a":1}\n {"b":2}\n'))

    def test_go_json_uses_utf8_instead_of_windows_locale(self):
        with patch.object(tls.subprocess, "check_output", return_value='{"Doc":"TLS → TCP"}') as command:
            self.assertEqual([{"Doc": "TLS → TCP"}], tls.json_stream(tls.go_output("go", ["list"], {})))
            self.assertEqual("utf-8", command.call_args.kwargs["encoding"])

    def test_external_module_and_replacement_rejected(self):
        main = {"Main": True, "Path": "com.layeranalyzer/tlsbridge"}
        tls.validate_modules([main], main["Path"])
        for modules in ([], [main, {"Path": "example.org/dep"}],
                        [{**main, "Replace": {"Path": "../outside"}}],
                        [{**main, "Main": False}], [{**main, "Path": "wrong"}]):
            with self.subTest(modules=modules), self.assertRaises(ValueError):
                tls.validate_modules(modules, main["Path"])

    def test_actual_production_build_info_accepted(self):
        tls.check_build_info(INFO)

    def test_wrong_or_missing_build_info_rejected(self):
        cases = ["", INFO.replace("go1.27.2", "go1.26.0"),
                 INFO.replace("GOOS=android", "GOOS=linux"),
                 INFO.replace("CGO_ENABLED=1", "CGO_ENABLED=0"),
                 INFO.replace("-buildmode=c-shared", "-buildmode=exe"),
                 INFO.replace("/cmd/androidbridge", "/cmd/other"),
                 INFO.replace("(devel)", "v1.0.0"),
                 INFO + "    dep example.org/library v1.0.0 h1:abc\n",
                 INFO + "    => ../replacement\n", INFO + "    build -tags=tlsprobe\n"]
        for info in cases:
            with self.subTest(info=info), self.assertRaises(ValueError):
                tls.check_build_info(info)

    def test_new_go_requirement_rejected_without_running_go(self):
        original = Path.read_text

        def changed(path, *args, **kwargs):
            value = original(path, *args, **kwargs)
            return value + "require example.org/lib v1.0.0\n" if path.name == "go.mod" else value

        with patch.object(Path, "read_text", changed):
            self.assertTrue(any("go.mod" in error for error in tls.check_materials()))

    def test_go_license_digest_drift_rejected(self):
        original = tls.digest
        with patch.object(tls, "digest", side_effect=lambda path: "bad" if Path(path).name == "Go.txt" else original(path)):
            self.assertTrue(any("Go.txt" in error for error in tls.check_materials()))

    def test_archive_hash_and_size_are_both_required(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "go.test.zip"
            path.write_bytes(b"archive")
            entry = {"url": "https://example.test/go.test.zip", "bytes": 7, "sha256": tls.digest(path)}
            with patch.object(tls, "read_json", return_value={"archives": [entry]}):
                self.assertEqual("PASS", tls.verify_archive(path)["status"])
                path.write_bytes(b"changed")
                with self.assertRaises(ValueError):
                    tls.verify_archive(path)
                path.write_bytes(b"too short")
                with self.assertRaises(ValueError):
                    tls.verify_archive(path)

    def test_installed_go_vendor_notice_drift_rejected(self):
        inventory = tls.read_json(tls.MODULE / "dependencies.json")
        distribution = inventory["goDistribution"]
        with patch.object(tls, "go_output", side_effect=["go version go1.27.2 windows/amd64", "/unused"]), \
             patch.object(tls, "digest", side_effect=[distribution["licenseSha256"], "changed"]):
            with self.assertRaisesRegex(ValueError, "PATENTS"):
                tls.check_toolchain("go", tls.offline_env())


if __name__ == "__main__":
    unittest.main()

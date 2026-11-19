"""Public CI toolchain checks."""
import hashlib
import io
from pathlib import Path
import os
import sys
import tarfile
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import tls_ci_toolchain as clean


class ToolchainTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_native_hash_works_without_python311_file_digest(self):
        import fetch_native_deps
        data = b"x" * (2 * 1024 * 1024 + 7)
        path = self.root / "bundle"
        path.write_bytes(data)
        with patch.object(hashlib, "file_digest", create=True, side_effect=AssertionError("Python 3.11 only")):
            self.assertEqual(hashlib.sha256(data).hexdigest(), fetch_native_deps.sha256(path))

    def test_safe_paths(self):
        for name in ("../x", "/x", "C:/x", "a\\x", "a/../x", "a//x", "./a", "", "."):
            with self.subTest(name=name), self.assertRaises(ValueError):
                clean.safe_name(name)

    def test_go_tar_symlink_and_traversal_rejected(self):
        for name, kind in (("go/bin/go", tarfile.SYMTYPE), ("go/../../x", tarfile.REGTYPE),
                           ("other/x", tarfile.REGTYPE)):
            archive = self.root / "go.tar.gz"
            with tarfile.open(archive, "w:gz") as bundle:
                member = tarfile.TarInfo(name)
                member.type = kind
                member.linkname = "../../x" if kind == tarfile.SYMTYPE else ""
                bundle.addfile(member, io.BytesIO(b""))
            with self.subTest(name=name), self.assertRaises(ValueError):
                clean.extract_go(archive, self.root / "toolchain")

    def test_go_tar_preserves_executable(self):
        archive = self.root / "go.tar.gz"
        with tarfile.open(archive, "w:gz") as bundle:
            member = tarfile.TarInfo("go/bin/go")
            member.mode, member.size = 0o755, 3
            bundle.addfile(member, io.BytesIO(b"exe"))
        clean.extract_go(archive, self.root / "toolchain")
        self.assertEqual(b"exe", (self.root / "toolchain/go/bin/go").read_bytes())

    def test_exact_cmake_with_reviewed_android_sdk_suffix(self):
        clean.check_cmake_version("cmake version 3.22.1\n")
        clean.check_cmake_version("cmake version 3.22.1-g37088a8\n")
        for version in ("3.22.10", "3.22.2", "4.2.1", "3.22.1-unknown", "3.22.1-g37088a8-dirty"):
            with self.subTest(version=version), self.assertRaises(ValueError):
                clean.check_cmake_version("cmake version " + version + "\n")

    def test_exact_package_revision(self):
        properties = self.root / "source.properties"
        properties.write_text("Pkg.Revision = 27.0.12077973\n")
        self.assertEqual(clean.digest(properties), clean.revision(properties, "27.0.12077973"))
        with self.assertRaises(ValueError):
            clean.revision(properties, "27.1.0")

    def test_failed_command_preserves_exit_and_log(self):
        report = {"steps": []}
        with self.assertRaisesRegex(ValueError, "failed"):
            clean.run_step(report, self.root, "negative", [sys.executable, "-c", "print('failure');exit(3)"],
                           self.root, os.environ.copy())
        self.assertEqual(3, report["steps"][0]["exitCode"])
        self.assertIn("failure", (self.root / "negative.log").read_text())

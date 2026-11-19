"""R05: exact ON/OFF inventories, attachment staging and fail-closed CI gates."""
import copy
import hashlib
import json
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch
import zipfile

import yaml

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import check_release_inventory as inventory_check
import check_tls_dependencies as tls
import prepare_tls_ci as ci
import run_required_tests as required
import stage_release as release

ROOT = release.ROOT


def bridge_provenance():
    files = tls.source_inputs()
    tree = hashlib.sha256("".join(f"{name}\0{sha}\n" for name, sha in sorted(files.items())).encode()).hexdigest()
    return {"kind": "production-go", "abi": "arm64-v8a", "goVersion": "go1.27.2",
            "sourceFiles": files, "sourceTreeSha256": tree,
            "manifestSha256": "a" * 64, "librarySha256": "b" * 64,
            "packagedSha256": hashlib.sha256(b"fixture library").hexdigest()}


class TlsStagingTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.apk = self.directory / "app.apk"
        outputs = patch.object(inventory_check, 'checked_bridge_outputs')
        outputs.start()
        self.addCleanup(outputs.stop)
        self.inventory = copy.deepcopy(release.read_json(ROOT / "docs/dependency-licenses.json"))
        self.inventory["build"] = {"versionName": "1.0.0", "versionCode": 4, "applicationId": "com.layeranalyzer.android",
                                  "ndkVersion": "27.0.12077973", "abis": ["arm64-v8a"],
                                  "g729": True, "ilbc": False, "tlsEnabled": False, "tlsProbe": False, "tlsBridge": None}
        deps = release.read_json(ROOT / "native_build/native-deps.json")
        self.names = {n for n in deps["files"] if n.startswith("arm64-v8a/") and n.endswith(".so")}
        self.names |= {"arm64-v8a/" + n for n in ("liblayanalyzer.so", "liblayanalyzer_tunnel.so", "libc++_shared.so", "libandroidx.graphics.path.so")}

    def binary(self, enabled=False, extra=None, omit=None):
        self.inventory["build"].update(tlsEnabled=enabled, tlsBridge=bridge_provenance() if enabled else None)
        names = set(self.names)
        if enabled:
            names.add("arm64-v8a/liblayanalyzer_tls.so")
        if extra:
            names.add("arm64-v8a/" + extra)
        if omit:
            names.remove("arm64-v8a/" + omit)
        with zipfile.ZipFile(self.apk, "w") as archive:
            for name in sorted(names):
                archive.writestr("lib/" + name, b"fixture library")
        self.inventory["build"]["apkSha256"] = release.digest(self.apk)

    def stage(self):
        path = self.directory / "inventory.json"
        release.write_json(path, self.inventory)
        # Fixture libraries are not actual APK license assets; the real license checker
        # is covered separately and remains enabled in CI and production staging.
        with patch.object(release.subprocess, "check_output", return_value=b""), patch.object(release, "check_licenses", return_value=[]):
            return release.create_apk(self.directory / "staging", path, self.apk)

    def test_off_staging_success(self):
        self.binary()
        self.assertEqual(1, self.stage())
        self.assertEqual({"LayerAnalyzer-arm64-v8a-1.0.0.apk", "SHA256SUMS"}, {p.name for p in (self.directory / "staging").iterdir()})

    def test_on_staging_success(self):
        self.binary(True)
        self.assertEqual(1, self.stage())
        release.verify_apk(self.directory / "staging", "v1.0.0")

    def test_read_only_inputs_check_does_not_stage_or_require_clean_checkout(self):
        self.binary(True)
        path = self.directory / "inventory.json"
        release.write_json(path, self.inventory)
        with patch.object(release, "check_licenses", return_value=[]), \
                patch.object(release.subprocess, "check_output", side_effect=AssertionError("must not invoke git or stage")):
            build, libraries = release.checked_apk_inputs(path, self.apk)
        self.assertTrue(build["tlsEnabled"])
        self.assertIn("liblayanalyzer_tls.so", libraries)
        self.assertFalse((self.directory / "staging").exists())

    def test_read_only_check_cannot_bypass_dirty_staging_guard(self):
        self.binary(True)
        path = self.directory / "inventory.json"
        release.write_json(path, self.inventory)
        with patch.object(release.subprocess, "check_output", return_value=b" M reviewed-file"):
            with self.assertRaisesRegex(ValueError, "checkout must be clean"):
                release.create_apk(self.directory / "staging", path, self.apk)
        self.assertFalse((self.directory / "staging").exists())

    def test_on_missing_bridge(self):
        self.binary(True, omit="liblayanalyzer_tls.so")
        with self.assertRaisesRegex(ValueError, "Packaged TLS bridge"):
            self.stage()

    def test_off_with_bridge(self):
        self.binary(False, extra="liblayanalyzer_tls.so")
        with self.assertRaisesRegex(ValueError, "Packaged TLS bridge"):
            self.stage()

    def test_unknown_libraries_rejected_in_both_modes(self):
        for enabled in (False, True):
            with self.subTest(enabled=enabled):
                self.binary(enabled, extra="libunknown.so")
                with self.assertRaisesRegex(ValueError, "Packaged native library set"):
                    self.stage()

    def test_missing_reviewed_runtime_native_library_rejected(self):
        self.binary(True, omit='libandroidx.graphics.path.so')
        with self.assertRaisesRegex(ValueError, 'Packaged native library set'):
            self.stage()

    def test_changed_runtime_native_aar_cannot_extend_allowlist(self):
        self.binary()
        component = next(c for c in self.inventory['components'] if c['coordinate'] == 'androidx.graphics:graphics-path:1.0.1')
        component['artifacts'][0]['sha256'] = '0' * 64
        with self.assertRaisesRegex(ValueError, 'Unreviewed graphics-path'):
            release.runtime_native_libraries(self.inventory)

    def test_missing_non_tls_library_rejected(self):
        self.binary(True, omit="libwireshark.so")
        with self.assertRaisesRegex(ValueError, "Packaged native library set"):
            self.stage()

    def test_off_claim_for_on_bytes_rejected(self):
        self.binary(True)
        self.inventory["build"].update(tlsEnabled=False, tlsBridge=None)
        with self.assertRaises(ValueError):
            self.stage()

    def test_stale_inventory_cannot_stage_new_apk(self):
        self.binary(True)
        with zipfile.ZipFile(self.apk, "a") as archive:
            archive.writestr("changed.txt", b"new APK")
        with self.assertRaisesRegex(ValueError, "APK bytes differ"):
            self.stage()

    def test_on_sbom_records_bridge_and_go_ownership(self):
        self.binary(True)
        self.apk.rename(self.directory / "fixture.apk")
        (self.directory / "source.zip").write_bytes(b"fixture source")
        deps = release.read_json(ROOT / "native_build/native-deps.json")
        sources = release.read_json(ROOT / "native_build/native-sources.json")
        provenance = release.read_json(ROOT / sources["verificationRecord"])
        sbom = release.make_sbom(self.inventory, "a" * 40, "source.zip", self.directory, deps, sources, provenance)
        self.assertIn("SPDXRef-TLS-Go", {p["SPDXID"] for p in sbom["packages"]})
        bridge = next(f for f in sbom["files"] if f["fileName"].endswith("/liblayanalyzer_tls.so"))
        self.assertIn({"spdxElementId": "SPDXRef-TLS-Bridge", "relationshipType": "CONTAINS", "relatedSpdxElement": bridge["SPDXID"]}, sbom["relationships"])

    def test_invalid_tls_flags_fail_closed(self):
        self.binary()
        for key, value in (("tlsEnabled", None), ("tlsEnabled", "false"), ("tlsEnabled", 1), ("tlsProbe", None), ("tlsProbe", True)):
            with self.subTest(key=key, value=value):
                bad = copy.deepcopy(self.inventory)
                bad["build"][key] = value
                with self.assertRaises(ValueError):
                    inventory_check.checked_build(bad)

    def test_off_bridge_provenance_rejected(self):
        self.binary()
        self.inventory["build"]["tlsBridge"] = bridge_provenance()
        with self.assertRaisesRegex(ValueError, "OFF inventory"):
            self.stage()

    def test_wrong_bridge_source_toolchain_or_hash_rejected(self):
        self.binary(True)
        for key, value in (("goVersion", "go1.26.0"), ("abi", "x86_64"), ("kind", "probe"),
                           ("sourceFiles", {}), ("sourceTreeSha256", "0" * 64), ("packagedSha256", "0" * 64),
                           ("manifestSha256", "invalid"), ("librarySha256", None)):
            with self.subTest(key=key):
                bad = copy.deepcopy(self.inventory)
                bad["build"]["tlsBridge"][key] = value
                with self.assertRaises(ValueError):
                    inventory_check.checked_apk(bad, self.apk)

    def test_wrong_license_review_fails(self):
        self.binary(True)
        with patch.object(inventory_check, "check_materials", return_value=["Changed Go LICENSE"]):
            with self.assertRaisesRegex(ValueError, "Go LICENSE"):
                self.stage()


class BridgeOutputsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.directory = self.root / 'build/tls-production/release'
        self.directory.mkdir(parents=True)
        (self.directory / inventory_check.BRIDGE).write_bytes(b'fixture library')
        self.bridge = bridge_provenance()
        self.bridge['librarySha256'] = inventory_check.digest(self.directory / inventory_check.BRIDGE)
        self.manifest = {'schemaVersion': 1, 'elfAudit': 'PASS', 'abi': 'arm64-v8a', 'goVersion': 'go1.27.2',
                         'sha256': self.bridge['librarySha256'], 'inputs': {
                             'sourceFiles': self.bridge['sourceFiles'], 'sourceTreeSha256': self.bridge['sourceTreeSha256'],
                             'environment': {'GOTOOLCHAIN': 'local', 'GOOS': 'android'}, 'command': ['go', 'build']}}
        self.write()

    def write(self):
        release.write_json(self.directory / 'build-manifest.json', self.manifest)
        self.bridge['manifestSha256'] = inventory_check.digest(self.directory / 'build-manifest.json')

    def test_real_output_binding_passes(self):
        inventory_check.checked_bridge_outputs(self.bridge, self.root)

    def test_manifest_bytes_or_library_bytes_changed_rejected(self):
        for path in ('build-manifest.json', inventory_check.BRIDGE):
            with self.subTest(path=path):
                file = self.directory / path
                original = file.read_bytes()
                file.write_bytes(original + b'changed')
                with self.assertRaises(ValueError):
                    inventory_check.checked_bridge_outputs(self.bridge, self.root)
                file.write_bytes(original)

    def test_self_consistent_hash_cannot_hide_wrong_source_or_probe(self):
        for key, value in (('sourceFiles', {}), ('command', ['go', 'build', '-tags=tlsprobe'])):
            with self.subTest(key=key):
                old = self.manifest['inputs'][key]
                self.manifest['inputs'][key] = value
                self.write()
                with self.assertRaises(ValueError):
                    inventory_check.checked_bridge_outputs(self.bridge, self.root)
                self.manifest['inputs'][key] = old


class RequiredResultsTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)

    def test_junit_pass(self):
        (self.directory / "TEST-pass.xml").write_text('<testsuite tests="2" failures="0" errors="0" skipped="0"><testcase name="one"/><testcase name="two"/></testsuite>' )
        self.assertEqual(2, required.junit(self.directory))

    def test_junit_empty_failed_errored_skipped_rejected(self):
        for attrs in ('tests="0"', 'tests="1" failures="1"', 'tests="1" errors="1"', 'tests="1" skipped="1"', 'tests="1" disabled="1"'):
            (self.directory / "TEST-result.xml").write_text(f'<testsuite {attrs}/>')
            with self.subTest(attrs=attrs), self.assertRaises(ValueError):
                required.junit(self.directory)

    def test_junit_declared_pass_without_testcases_rejected(self):
        (self.directory / 'TEST-empty.xml').write_text('<testsuite tests="1"/>')
        with self.assertRaisesRegex(ValueError, 'testcase count'):
            required.junit(self.directory)

    def test_missing_junit_rejected(self):
        with self.assertRaises(ValueError):
            required.junit(self.directory)

    def test_go_pass_and_failure_skip_incomplete_rejected(self):
        events = [{"Action": "start", "Package": "p"}, {"Action": "pass", "Package": "p", "Test": "TestOne"}, {"Action": "pass", "Package": "p"}]
        path = self.directory / "go.json"
        path.write_text("\n".join(json.dumps(e) for e in events))
        self.assertEqual(1, required.go_report(path))
        for bad in ([], events[:-1], events + [{"Action": "skip", "Test": "TestRequired"}], events + [{"Action": "fail"}]):
            path.write_text("\n".join(json.dumps(e) for e in bad))
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                required.go_report(path)

    def test_go_no_test_abi_entry_is_not_a_skipped_test(self):
        package = 'com.layeranalyzer/tlsbridge/cmd/androidbridge'
        events = [{'Action': 'start', 'Package': package}, {'Action': 'output', 'Package': package, 'Output': '[no test files]'},
                  {'Action': 'skip', 'Package': package}, {'Action': 'start', 'Package': 'tests'},
                  {'Action': 'pass', 'Package': 'tests', 'Test': 'TestOne'}, {'Action': 'pass', 'Package': 'tests'}]
        path = self.directory / 'go.json'
        path.write_text('\n'.join(json.dumps(e) for e in events))
        self.assertEqual(1, required.go_report(path))
        # A Test skip, an unknown empty package, or an empty package without its
        # compiler no-test-files output is never exempted.
        for bad in ([e for e in events if e['Action'] != 'output'],
                    events + [{'Action': 'skip', 'Package': package, 'Test': 'TestRequired'}],
                    events + [{'Action': 'skip', 'Package': 'unknown'}]):
            path.write_text('\n'.join(json.dumps(e) for e in bad))
            with self.assertRaises(ValueError):
                required.go_report(path)

    def test_python_required_skip_rejected(self):
        fake = unittest.TestResult()
        fake.testsRun = 1
        fake.skipped = [(None, "missing platform")]
        with patch.object(required.unittest.defaultTestLoader, "discover", return_value=unittest.TestSuite()), patch.object(required.unittest.TextTestRunner, "run", return_value=fake):
            with self.assertRaises(ValueError):
                required.required_unittest(self.directory)


class PublicCiPolicyTest(unittest.TestCase):
    def setUp(self):
        self.workflow = yaml.load((ROOT / ".github/workflows/android.yml").read_text(), Loader=yaml.BaseLoader)
        self.setup = yaml.load((ROOT / ".github/actions/tls-ci-setup/action.yml").read_text(), Loader=yaml.BaseLoader)

    def test_ci_builds_arm64_with_production_tls_only(self):
        for job in ("unit-tests", "build"):
            steps = self.workflow["jobs"][job]["steps"]
            gradle = [s["run"] for s in steps if "./gradlew " in s.get("run", "")]
            self.assertTrue(gradle, job)
            for command in gradle:
                self.assertIn("-PlayanalyzerEnableTls=true", command)
                self.assertIn("-PlayanalyzerTlsProbe=false", command)
        workflow = (ROOT / ".github/workflows/android.yml").read_text()
        self.assertNotIn("matrix.tls", workflow)
        self.assertNotIn("assembleEmulator", workflow)

    def test_pr_cannot_read_signing_secrets_or_publish(self):
        self.assertEqual({"contents": "read"}, self.workflow["permissions"])
        jobs = self.workflow["jobs"]
        for name, job in jobs.items():
            if name != "package":
                self.assertNotIn("secrets.", json.dumps(job))
            if name != "release-draft":
                self.assertNotEqual("write", job.get("permissions", {}).get("contents"))
        for name in ("package", "release-draft"):
            self.assertIn("github.event_name == 'push'", jobs[name]["if"])
            self.assertIn("refs/tags/v", jobs[name]["if"])
            self.assertIn("ENABLE_APK_PACKAGING", jobs[name]["if"])
        self.assertIn("tls-tests", jobs["package"]["needs"])
        self.assertNotIn("pull_request_target", self.workflow["on"])
        self.assertNotIn("--publish", json.dumps(jobs))

    def test_signed_release_has_explicit_tls_on_and_probe_off(self):
        package = self.workflow["jobs"]["package"]
        command = next(s["run"] for s in package["steps"] if s.get("name") == "Check, build APK and export resolved runtime inputs")
        for value in ("-PlayanalyzerEnableTls=true", "-PlayanalyzerTlsProbe=false", "assembleRelease", "testReleaseUnitTest", "exportRuntimeLicenseInventory", "--no-build-cache", "--rerun-tasks"):
            self.assertIn(value, command)
        self.assertTrue(any("check_release_apk.py" in s.get("run", "") for s in package["steps"]))

    def test_setup_versions_match_lock(self):
        lock = release.read_json(ROOT / "native_build/tls-ci-toolchain.json")
        steps = self.setup["runs"]["steps"]
        java = next(s for s in steps if s.get("uses", "").startswith("actions/setup-java"))["with"]
        python = next(s for s in steps if s.get("uses", "").startswith("actions/setup-python"))["with"]
        self.assertEqual(lock["javaVersion"], java["java-version"])
        self.assertEqual(lock["javaDistribution"], java["distribution"])
        self.assertEqual(lock["pythonVersion"], python["python-version"])
        self.assertIn("fixture", json.dumps(steps))

    def test_public_native_manifests_match_without_local_rebuild(self):
        deps = release.read_json(ROOT / "native_build/native-deps.json")
        sources = release.read_json(ROOT / "native_build/native-sources.json")
        provenance = release.read_json(ROOT / sources["verificationRecord"])
        ci.check_public_native(deps, sources, provenance)
        for key in ("requiredLocalRebuild", "localRebuild"):
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "localRebuild"):
                ci.check_public_native(dict(deps, **{key: {"required": True}}), sources, provenance)

    def test_native_candidate_linkage(self):
        deps = {"sha256": "a" * 64}
        sources = {"binaryArchiveSha256": "a" * 64, "sha256": "b" * 64}
        provenance = {"pinnedBinaryArchiveSha256": "a" * 64, "sourceArchiveSha256": "b" * 64}
        ci.check_public_native(deps, sources, provenance)
        for data in (dict(deps, sha256="0" * 64),):
            with self.assertRaises(ValueError):
                ci.check_public_native(data, sources, provenance)

    def test_wrong_installed_go_version_rejected_before_use(self):
        with patch.object(tls, 'go_output', return_value='go version go1.20.7 linux/amd64'):
            with self.assertRaisesRegex(ValueError, 'exact reviewed Go'):
                tls.check_toolchain('go', {})

    def test_secret_archive_urls_rejected(self):
        with patch.object(ci, "urlopen") as network:
            for url in ("http://example.org/a.zip", "https://u:p@example.org/a.zip", "https://example.org/a.zip?token=x"):
                with self.subTest(url=url), self.assertRaises(ValueError):
                    ci.download({"url": url}, ROOT)
            network.assert_not_called()


if __name__ == "__main__":
    unittest.main()

"""Required skip/failure, stale evidence and independent golden comparison gates."""
import argparse
import copy
import json
from pathlib import Path
import shutil
import tempfile
import unittest
from unittest.mock import patch
import subprocess

from check_fixture import ROOT, RELEASE_IDS, sha256
from suite_runner import BASE_CASES, EXTENDED_CASES, OLD_IDS, CLASS, compare_device, execute, validate_xml


class SuiteGateTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.manifest_bytes = (ROOT / "fixtures/manifest.json").read_bytes()
        self.manifest = json.loads(self.manifest_bytes)
        self.manifest_hash = sha256(self.manifest_bytes)
        self.desktop = {"fixtures": [{"fixtureId": f["fixtureId"], "bodySha256": f["expectedBody"]["sha256"]}
                                     for f in self.manifest["fixtures"]]}
        self.device = {f["fixtureId"]: {
            "schemaVersion": 1, "suiteVersion": "tls-golden-v1", "runId": "fresh",
            "fixtureId": f["fixtureId"], "manifestSha256": self.manifest_hash,
            "passed": True, "abi": "arm64-v8a", "api": 36, "buildType": "debug", "embeddedVersion": "4.0.10",
            "tlsEnabled": True, "probeEnabled": False,
            "bodySha256": f["expectedBody"]["sha256"],
            "cases": dict.fromkeys(BASE_CASES | (EXTENDED_CASES if f["fixtureId"] not in OLD_IDS else set()), True)
        } for f in self.manifest["fixtures"]}

    def compare(self):
        return compare_device(self.manifest, self.manifest_hash, self.desktop, self.device, "fresh")

    def xml(self, ids=None, child="", suite_attributes=""):
        text = f'<testsuite {suite_attributes}>' + "".join(
            f'<testcase classname="{CLASS}" name="goldenNegativesAndClearReload[{id}]">{child}</testcase>'
            for id in (sorted(RELEASE_IDS) if ids is None else ids)) + '</testsuite>'
        path = self.directory / "results.xml"
        path.write_text(text)
        return [path]

    def test_complete_xml(self):
        self.assertEqual(RELEASE_IDS, set(validate_xml(self.xml())))

    def test_missing_xml_case_rejected(self):
        with self.assertRaisesRegex(ValueError, "Missing required"):
            validate_xml(self.xml(sorted(RELEASE_IDS)[1:]))

    def test_duplicate_case_rejected(self):
        with self.assertRaisesRegex(ValueError, "Duplicate"):
            validate_xml(self.xml(list(RELEASE_IDS) + [next(iter(RELEASE_IDS))]))

    def test_skipped_failed_and_error_cases_rejected_even_when_suite_counts_are_zero(self):
        for tag in ("skipped", "failure", "error"):
            with self.subTest(tag=tag), self.assertRaisesRegex(ValueError, "failed or was skipped"):
                validate_xml(self.xml(child=f'<{tag}/>'))

    def test_suite_level_skipped_rejected(self):
        with self.assertRaisesRegex(ValueError, "skipped required"):
            validate_xml(self.xml(suite_attributes='skipped="1"'))

    def test_complete_comparison(self):
        self.assertTrue(all(item["equal"] for item in self.compare()))

    def test_bad_golden_comparison_is_recorded_without_updating_expectation(self):
        self.device["tls13-h1"]["bodySha256"] = "0" * 64
        result = self.compare()
        self.assertFalse(next(item for item in result if item["fixtureId"] == "tls13-h1")["equal"])
        self.assertEqual(self.manifest_bytes, (ROOT / "fixtures/manifest.json").read_bytes())

    def test_missing_device_fixture_rejected(self):
        del self.device["tls13-h1"]
        with self.assertRaisesRegex(ValueError, "Missing/extra"):
            self.compare()

    def test_stale_run_and_manifest_rejected(self):
        original = copy.deepcopy(self.device)
        for key, value in (("runId", "old"), ("manifestSha256", "0" * 64)):
            self.device = copy.deepcopy(original)
            self.device["tls13-h1"][key] = value
            with self.subTest(key=key), self.assertRaisesRegex(ValueError, "Stale/invalid"):
                self.compare()

    def test_wrong_abi_version_build_type_and_old_api_rejected(self):
        original = copy.deepcopy(self.device)
        for key, value in (("abi", "x86_64"), ("api", 25), ("buildType", "emulator"),
                           ("tlsEnabled", False), ("probeEnabled", True), ("tlsEnabled", None),
                           ("embeddedVersion", "14.0.100")):
            self.device = copy.deepcopy(original)
            self.device["tls13-h1"][key] = value
            with self.subTest(key=key), self.assertRaises(ValueError): self.compare()

    def test_skipped_or_missing_scenario_rejected(self):
        self.device["tls13-h1"]["cases"].pop("reload")
        with self.assertRaisesRegex(ValueError, "required device scenario"): self.compare()
        self.device["tls13-h1"]["cases"]["reload"] = False
        with self.assertRaisesRegex(ValueError, "required device scenario"): self.compare()

    def test_required_device_skip_returns_nonzero_and_records_counts(self):
        args = argparse.Namespace(results_root=self.directory / "run", skip_device=True,
                                  tshark="mock-tool", adb="unused", arm64_serial="", offline=True)
        def checker(command, **kwargs):
            Path(command[-1]).write_text(json.dumps(self.desktop))
            return subprocess.CompletedProcess(command, 0)
        with patch("suite_runner.platform.platform", return_value="test-os"), \
                patch("suite_runner.platform.machine", return_value="test-abi"), \
                patch("suite_runner.subprocess.run", side_effect=checker):
            report, code = execute(args)
        self.assertEqual(2, code)
        self.assertFalse(report["gatePassed"])
        self.assertEqual(8, report["summary"]["skipped"])
        self.assertEqual(8, report["summary"]["passed"])

    def test_checker_failure_returns_nonzero_and_never_runs_device(self):
        args = argparse.Namespace(results_root=self.directory / "failed", skip_device=False,
                                  tshark="mock-tool", adb="unused", arm64_serial="", offline=True)
        with patch("suite_runner.platform.platform", return_value="test-os"), \
                patch("suite_runner.platform.machine", return_value="test-abi"), \
                patch("suite_runner.subprocess.run", return_value=subprocess.CompletedProcess([], 1)) as run:
            report, code = execute(args)
        self.assertEqual(1, code)
        self.assertEqual(1, run.call_count)
        self.assertEqual(8, report["summary"]["failed"])

    def test_device_reports_collected_without_run_as_and_invalid_output_rejected(self):
        for invalid_output, incremental in ((False, False), (True, False), (False, True), ("hash", True)):
            with self.subTest(invalid_output=invalid_output, incremental=incremental):
                args = argparse.Namespace(results_root=self.directory / f"{invalid_output}-{incremental}", skip_device=False,
                                          tshark="mock-tool", adb="adb", arm64_serial="test-device", offline=True,
                                          incremental=incremental)
                run_id = ""
                pulled = []

                def run(command, **kwargs):
                    nonlocal run_id
                    if "--report" in command:
                        Path(command[-1]).write_text(json.dumps(self.desktop))
                        return subprocess.CompletedProcess(command, 0)
                    if ":app:connectedDebugAndroidTest" in command:
                        self.assertIn("-PlayanalyzerEnableTls=true", command)
                        self.assertIn("-PlayanalyzerTlsProbe=false", command)
                        self.assertEqual(not incremental, "--rerun-tasks" in command)
                        run_id = next(arg.split("=", 1)[1] for arg in command if arg.startswith(
                            "-Pandroid.testInstrumentationRunnerArguments.tlsSuiteRunId="))
                        junit = self.directory / "app/build/outputs/androidTest-results/connected/debug"
                        junit.mkdir(parents=True, exist_ok=True)
                        shutil.copyfile(self.xml()[0], junit / "TEST-suite.xml")
                        for relative in ("app/build/outputs/apk/debug/app-debug.apk",
                                         "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"):
                            artifact = self.directory / relative
                            artifact.parent.mkdir(parents=True, exist_ok=True)
                            artifact.write_bytes(b"mock-apk")
                        return subprocess.CompletedProcess(command, 0)
                    if command[-1] == "devices":
                        output = "List of devices attached\ntest-device\tdevice\n"
                    elif command[-1] == "ro.product.cpu.abi": output = "arm64-v8a"
                    elif command[-1] == "ro.build.version.sdk": output = "30"
                    elif command[3:6] == ["shell", "pm", "path"]: output = "package:/base.apk"
                    elif command[3:5] == ["shell", "sha256sum"]:
                        output = ("0" * 64 if invalid_output == "hash" else sha256(b"mock-apk")) + " /base.apk"
                    else:
                        self.assertEqual(["exec-out", "cat"], command[3:5])
                        path = command[-1]
                        self.assertTrue(path.startswith("/sdcard/Android/data/com.layeranalyzer.android.debug/files/"
                                                        f"tls-suite-v1/{run_id}/"))
                        fixture = Path(path).stem
                        pulled.append(fixture)
                        output = "run-as: permission denied" if invalid_output else json.dumps(
                            dict(self.device[fixture], runId=run_id))
                    return subprocess.CompletedProcess(command, 0, stdout=output)

                with patch("suite_runner.REPO", self.directory), \
                        patch("suite_runner.platform.platform", return_value="test-os"), \
                        patch("suite_runner.platform.machine", return_value="test-abi"), \
                        patch("suite_runner.subprocess.run", side_effect=run):
                    report, code = execute(args)
                self.assertEqual(1 if invalid_output else 0, code)
                self.assertEqual(not invalid_output, report["gatePassed"])
                if not invalid_output:
                    self.assertEqual(RELEASE_IDS, set(pulled))
                    self.assertEqual(16, report["summary"]["passed"])


if __name__ == "__main__":
    unittest.main()

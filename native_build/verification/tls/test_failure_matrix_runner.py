"""Regression checks for the TLS-403 evidence gate; no Android/Go required."""
import json
from pathlib import Path
import tempfile
import unittest

import failure_matrix_runner as runner


class FailureMatrixRunnerTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def xml(self, text):
        path = self.root / "results.xml"
        path.write_text(text, encoding="utf-8")
        return runner.read_junit([path])

    def test_only_exactly_one_successful_required_test_passes(self):
        parsed = self.xml('<testsuite><testcase classname="X" name="required"/></testsuite>')
        result = runner.attach_tests({"status": "PASS"}, parsed)
        self.assertEqual("PASS", runner.result_for(result, "X", "required"))
        self.assertEqual("FAIL", runner.result_for(result, "X", "renamed"))
        result["cases"][("X", "required")].append("PASS")
        self.assertEqual("FAIL", runner.result_for(result, "X", "required"))

    def test_skipped_failure_and_error_children_fail_even_with_zero_counters(self):
        for tag in ("skipped", "error", "failure"):
            with self.subTest(tag=tag):
                parsed = self.xml(f'<testsuite failures="0" errors="0" skipped="0"><testcase classname="X" name="required"><{tag}/></testcase></testsuite>')
                result = runner.attach_tests({"status": "PASS"}, parsed)
                self.assertEqual("FAIL", runner.result_for(result, "X", "required"))

    def test_suite_counter_failures_cannot_be_hidden_by_passing_children(self):
        for field in ("failures", "errors", "skipped"):
            parsed = self.xml(f'<testsuite {field}="1"><testcase classname="X" name="required"/></testsuite>')
            self.assertEqual("FAIL", runner.attach_tests({"status": "PASS"}, parsed)["status"])

    def test_empty_junit_and_failed_process_do_not_pass(self):
        self.assertEqual("FAIL", runner.attach_tests({"status": "PASS"}, self.xml("<testsuite/>"))["status"])
        parsed = self.xml('<testsuite><testcase classname="X" name="required"/></testsuite>')
        self.assertEqual("FAIL", runner.attach_tests({"status": "FAIL"}, parsed)["status"])

    def go(self, events):
        path = self.root / "go.jsonl"
        path.write_text("\n".join(json.dumps(e) for e in events), encoding="utf-8")
        return runner.read_go(path)

    def test_go_package_build_failure_is_a_failure_without_testcases(self):
        parsed = self.go([{"Action": "fail", "Package": "com.layeranalyzer/tlsbridge/internal/engine"}])
        self.assertEqual(1, parsed["counts"]["errors"])
        self.assertEqual("FAIL", runner.attach_tests({"status": "PASS"}, parsed)["status"])

    def test_go_nested_skip_blocks_gate(self):
        parsed = self.go([
            {"Action": "skip", "Package": "com.layeranalyzer/tlsbridge/internal/engine", "Test": "TestRequired/child"},
            {"Action": "pass", "Package": "com.layeranalyzer/tlsbridge/internal/engine", "Test": "TestRequired"},
        ])
        self.assertEqual(1, parsed["counts"]["tests"])
        self.assertEqual(1, parsed["counts"]["skipped"])
        self.assertEqual("FAIL", runner.attach_tests({"status": "PASS"}, parsed)["status"])

    def test_go_duplicate_and_missing_names_fail(self):
        event = {"Action": "pass", "Package": "com.layeranalyzer/tlsbridge/internal/engine", "Test": "TestRequired"}
        parsed = self.go([event, event])
        result = runner.attach_tests({"status": "PASS"}, parsed)
        self.assertEqual("FAIL", runner.result_for(result, "internal/engine", "TestRequired"))
        self.assertEqual("FAIL", runner.result_for(result, "internal/engine", "TestMissing"))

    def test_blocked_device_or_manual_experiment_never_counts_as_success(self):
        for status in ("BLOCKED", "NOT_RUN", "SKIPPED"):
            self.assertEqual(2, runner.exit_code([{"status": "PASS"}, {"status": status}]))
        self.assertEqual(1, runner.exit_code([{"status": "FAIL"}, {"status": "NOT_RUN"}]))
        self.assertEqual(0, runner.exit_code([{"status": "PASS"}]))

    def test_subprocess_failure_and_missing_executable_are_reported(self):
        import sys
        failed = runner.execute([sys.executable, "-c", "raise SystemExit(7)"], self.root, self.root / "fail", 5)
        self.assertEqual(7, failed["exitCode"])
        self.assertEqual("FAIL", failed["status"])
        missing = runner.execute([str(self.root / "missing")], self.root, self.root / "missing-run", 5)
        self.assertEqual("FAIL", missing["status"])

    def test_go_json_missing_compiler_is_blocked_but_test_failure_is_not(self):
        events = [
            {"Action": "build-output", "ImportPath": "runtime/cgo", "Output": 'cgo: C compiler "gcc" not found'},
            {"Action": "build-fail", "ImportPath": "runtime/cgo"},
        ]
        text = "\n".join(json.dumps(e) for e in events)
        self.assertTrue(runner.compiler_missing(text, ""))
        self.assertFalse(runner.compiler_missing(text + '\n{"Action":"fail","Test":"TestRace"}', ""))
        self.assertFalse(runner.compiler_missing('{"Action":"output","Output":"C compiler not found"}', ""))

    def test_timeout_stops_process_and_is_a_failure(self):
        import sys
        result = runner.execute([sys.executable, "-c", "import time; time.sleep(30)"],
                                self.root, self.root / "timeout", 1)
        self.assertEqual("FAIL", result["status"])
        self.assertEqual("TIMEOUT", result["reason"])

    def test_timeout_cleanup_only_targets_the_built_debug_package(self):
        path = self.root / "metadata.json"
        path.write_text(json.dumps({"variantName": "debug", "applicationId": "com.layeranalyzer.android.debug"}))
        self.assertEqual("com.layeranalyzer.android.debug", runner.debug_application_id(path))
        for variant, package in (("release", "com.layeranalyzer.android"),
                                 ("debug", "com.layeranalyzer.android"),
                                 ("emulator", "com.layeranalyzer.android.emulator")):
            path.write_text(json.dumps({"variantName": variant, "applicationId": package}))
            with self.assertRaises(ValueError):
                runner.debug_application_id(path)


if __name__ == "__main__":
    unittest.main()

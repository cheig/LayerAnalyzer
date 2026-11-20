"""TLS-403 bounded fault/race verification. Only fresh, non-skipped tests pass.

Host doubles and Android JNI evidence are reported separately from destructive
device experiments, which require an isolated test device and a reviewed record.
"""
from __future__ import annotations

import argparse
import collections
import datetime
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import time
import uuid
import xml.etree.ElementTree as ET

ROOT = Path(__file__).resolve().parents[3]
PACKAGE = "com.example.layanalyzer."
JVM_CLASSES = [
    "capture.tls.TlsCaptureLifecycleTest", "capture.tls.TlsSecretQueueTest",
    "capture.tls.TlsEncryptedAssetTest", "data.TlsCapturePurgeTest",
    "data.TlsAnalysisTransactionTest",
]
DEVICE_CLASSES = ["TlsFailureRecoveryStressTest", "TlsCaptureRecoveryTest"]
# Each scenario requires actual named test results, not just a successful process.
# The full selected classes/module are also checked for failures and skips.
SCENARIOS = {
    "tls-start-boundaries": ("jvm", "capture.tls.TlsCaptureLifecycleTest", "exceptionsAtEachTlsStartBoundaryReleaseOwnershipAndAllowAnotherCapture"),
    "start-stop-race": ("jvm", "capture.tls.TlsCaptureLifecycleTest", "concurrentStopDuringStartupRejectsLateSecretsAndCanRestart"),
    "writer-full": ("jvm", "capture.tls.TlsSecretQueueTest", "aFullQueueRefusesRecordsWithoutBlockingAndSuspendsNewInterception"),
    "writer-drain-timeout": ("jvm", "capture.tls.TlsSecretQueueTest", "aConsumerThatNeverReturnsIsBoundedAndPublishesNothing"),
    "writer-budget-exhausted": ("jvm", "capture.tls.TlsSecretQueueTest", "aFailedPersistLeavesAcceptedAbovePersistedAndKeepsTheSinkUsable"),
    "tag-corruption": ("jvm", "capture.tls.TlsEncryptedAssetTest", "completeTagFailureNeverTruncates"),
    "startup-secret-cleanup": ("jvm", "data.TlsCapturePurgeTest", "startupSweepsOnlyOrphanPlaintextAndWorkspaces"),
    "interrupted-record-recovery": ("jvm", "data.TlsCapturePurgeTest", "recoveryTrimsOnlyPartialPacketAndAuthenticatedSecretTail"),
    "gateway-capacity-repeated-stop-restart": ("go", "internal/engine/assembly", "TestFailureRecoveryStressSaturatedGatewayStopsAndRestarts"),
    "callback-exception": ("go", "internal/tlsproxy", "TestAPlatformVerificationThatPanicsEndsTheConnectionRatherThanFallingBack"),
    "cancel-real-transports": ("go", "internal/tlsproxy", "TestACancelledConnectionPublishesOneTerminalStateAndReleasesBothTransports"),
    "slow-reader": ("go", "internal/tlsproxy", "TestASlowClientReceivesTheWholeAnswerThroughThePipeline"),
    "large-real-tls-stream": ("go", "internal/tlsproxy", "TestFailureRecoveryStressLargeTLSStreamHasExactBytesAndReleasesSlots"),
    "default-event-budget-flood": ("go", "internal/engine", "TestFailureRecoveryStressDefaultEventFlood"),
    "event-flood-slow-ui": ("go", "internal/engine", "TestTheQueueIsBoundedAndDropsOrdinaryEventsFirst"),
    "event-summary-bound": ("go", "internal/engine", "TestTerminalSummariesAreBounded"),
    "certificate-cache-eviction": ("go", "internal/certstore", "TestLeastRecentlyUsedLeafIsEvictedFirst"),
    "default-certificate-budget-eviction": ("go", "internal/certstore", "TestFailureRecoveryStressDefaultCertificateCacheEvictsAndReissues"),
    "native-race-tls12": ("android", "TlsFailureRecoveryStressTest", "tls12DetailsFilterFollowKeysCancelCloseAndReopen"),
    "native-race-tls13-h2": ("android", "TlsFailureRecoveryStressTest", "tls13H2DetailsFilterFollowKeysCancelCloseAndReopen"),
    "jni-callback-exception-recovery": ("android", "TlsFailureRecoveryStressTest", "jniCallbackExceptionStopsCleanlyAndNextEngineForwards"),
    "android-keystore-recovery": ("android", "TlsCaptureRecoveryTest", "recoveredAuthenticatedTailStillDecryptsAndRemainsInterrupted"),
    "android-tag-corruption": ("android", "TlsCaptureRecoveryTest", "authenticatedRecordCorruptionIsReportedWithoutTrimmingIt"),
}
DEVICE_EXPERIMENTS = [
    "all-service-start-stages", "disk-enospc", "vpn-revocation", "physical-network-loss",
    "app-process-kill-restart", "long-tls-stream-cancel", "device-fd-thread-lease-baseline",
]


def debug_application_id(metadata: Path) -> str:
    """Never force-stop the user's separately installed release application."""
    value = json.loads(metadata.read_text(encoding="utf-8"))
    if value.get("variantName") != "debug" or value.get("applicationId") != "com.layeranalyzer.android.debug":
        raise ValueError("Unexpected debug APK identity; refusing timeout cleanup")
    return value["applicationId"]


def read_junit(paths: list[Path]) -> dict:
    cases: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    counts = dict(tests=0, failures=0, errors=0, skipped=0)
    for path in paths:
        root = ET.parse(path).getroot()
        suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
        for suite in suites:
            # Suite-level failures/errors/skips must not disappear when a runner
            # writes inconsistent counters or omits the corresponding testcase.
            for field in ("failures", "errors", "skipped"):
                counts[field] += int(suite.get(field, "0"))
            for case in suite.findall("testcase"):
                state = "PASS"
                for tag, field in (("skipped", "skipped"), ("error", "errors"), ("failure", "failures")):
                    if case.find(tag) is not None:
                        state = "SKIPPED" if tag == "skipped" else "FAIL"
                        # Avoid trusting the suite's zero counters.
                        if not int(suite.get(field, "0")):
                            counts[field] += 1
                key = (case.get("classname", suite.get("name", "")), case.get("name", ""))
                cases[key].append(state)
                counts["tests"] += 1
    return {"cases": cases, "counts": counts}


def read_go(path: Path) -> dict:
    cases: dict[tuple[str, str], list[str]] = collections.defaultdict(list)
    counts = dict(tests=0, failures=0, errors=0, skipped=0)
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        event = json.loads(line)
        action = event.get("Action")
        name = event.get("Test")
        if action not in ("pass", "fail", "skip"):
            continue
        if name:
            key = (event["Package"].removeprefix("com.layeranalyzer/tlsbridge/"), name)
            cases[key].append({"pass": "PASS", "fail": "FAIL", "skip": "SKIPPED"}[action])
            if "/" not in name:  # top-level tests; subtests remain available for selectors
                counts["tests"] += 1
                counts["failures"] += action == "fail"
            counts["skipped"] += action == "skip"
        elif action == "fail":
            counts["errors"] += 1
    return {"cases": cases, "counts": counts}


def result_for(result: dict, package: str, name: str) -> str:
    if result["status"] != "PASS":
        return result["status"]
    # Exactly one matching testcase: empty, duplicate or renamed suites fail.
    return "PASS" if result["cases"].get((package, name)) == ["PASS"] else "FAIL"


def exit_code(rows: list[dict]) -> int:
    if any(row["status"] == "FAIL" for row in rows):
        return 1
    return 0 if all(row["status"] == "PASS" for row in rows) else 2


def compiler_missing(stdout: str, stderr: str) -> bool:
    """Go 1.27 -json emits cgo build diagnostics as JSON on stdout."""
    events = []
    for line in stdout.splitlines():
        try:
            events.append(json.loads(line))
        except ValueError:
            return False
    if any(e.get("Action") == "fail" and e.get("Test") for e in events):
        return False
    build = "".join(e.get("Output", "") for e in events
                    if e.get("ImportPath") == "runtime/cgo" and e.get("Action") == "build-output")
    failed = any(e.get("Action") == "build-fail" and e.get("ImportPath") == "runtime/cgo" for e in events)
    return ((failed and 'cgo: C compiler "' in build and "not found" in build) or
            ('cgo: C compiler "' in stderr and "not found" in stderr))


def execute(command: list[str], cwd: Path, out: Path, timeout: int, env=None) -> dict:
    """Bounded process tree, shell-free arguments, private ignored logs."""
    stdout, stderr = out.with_suffix(".stdout.log"), out.with_suffix(".stderr.log")
    try:
        with stdout.open("w", encoding="utf-8") as output, stderr.open("w", encoding="utf-8") as errors:
            kwargs = {"start_new_session": True} if os.name != "nt" else {"creationflags": subprocess.CREATE_NEW_PROCESS_GROUP}
            proc = subprocess.Popen(command, cwd=cwd, stdout=output, stderr=errors, env=env, **kwargs)
            try:
                code = proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                if os.name == "nt":
                    subprocess.run(["taskkill", "/PID", str(proc.pid), "/T", "/F"], capture_output=True, timeout=15)
                else:
                    import signal
                    os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=15)
                return {"status": "FAIL", "reason": "TIMEOUT", "exitCode": None, "stdout": str(stdout), "stderr": str(stderr)}
        return {"status": "PASS" if code == 0 else "FAIL", "exitCode": code,
                "stdout": str(stdout), "stderr": str(stderr)}
    except OSError as error:
        return {"status": "FAIL", "reason": type(error).__name__, "exitCode": None}


def attach_tests(result: dict, parsed: dict) -> dict:
    result.update(parsed)
    if not parsed["counts"]["tests"] or any(parsed["counts"][key] for key in ("failures", "errors", "skipped")):
        result["status"] = "FAIL"
    return result


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", default="go")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--arm64-serial")
    parser.add_argument("--skip-device", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--results-root", type=Path, default=ROOT / "build/tls-403")
    args = parser.parse_args()
    run_id = uuid.uuid4().hex
    output = args.results_root.resolve() / run_id
    output.mkdir(parents=True, exist_ok=False)
    report = {"schemaVersion": 1, "suite": "tls-failure-matrix-v1", "runId": run_id,
              "environment": {"host": platform.platform(), "python": platform.python_version(),
                              "utc": datetime.datetime.now(datetime.timezone.utc).isoformat()},
              "backends": {}, "scenarios": []}
    backends = report["backends"]
    go = str(Path(args.go).resolve()) if Path(args.go).is_file() else args.go
    report["environment"]["fixtureManifestSha256"] = hashlib.sha256(
        (ROOT / "native_build/verification/tls/fixtures/manifest.json").read_bytes()).hexdigest()
    for field, command in (("goVersion", [go, "version"]), ("gitHead", ["git", "rev-parse", "HEAD"])):
        try:
            report["environment"][field] = subprocess.check_output(command, cwd=ROOT, text=True, timeout=10).strip()
        except (OSError, subprocess.SubprocessError):
            report["environment"][field] = None
    gradle = [str(ROOT / "gradlew.bat")] if os.name == "nt" else [str(ROOT / "gradlew")]
    common = ["--no-daemon", "-PlayanalyzerTlsProbe=false"]
    if args.offline:
        common.append("--offline")
    # --rerun applies to the test task; dependencies may remain up-to-date.
    started = time.time()
    jvm = execute(gradle + [":app:testDebugUnitTest", "--rerun"] + common +
                  [arg for cls in JVM_CLASSES for arg in ("--tests", PACKAGE + cls)], ROOT, output / "jvm", 600)
    xml = [ROOT / f"app/build/test-results/testDebugUnitTest/TEST-{PACKAGE}{cls}.xml" for cls in JVM_CLASSES]
    try:
        # mtime also rejects stale files if Gradle failed before executing tests.
        fresh = [path for path in xml if path.is_file() and path.stat().st_mtime >= started]
        if len(fresh) != len(xml):
            raise ValueError("Missing fresh JVM XML")
        backends["jvm"] = attach_tests(jvm, read_junit(fresh))
        archive = output / "jvm-xml"
        archive.mkdir()
        for path in fresh:
            shutil.copyfile(path, archive / path.name)
    except (ValueError, ET.ParseError) as error:
        backends["jvm"] = dict(jvm, status="FAIL", reason=type(error).__name__, cases={})

    go_result = execute([go, "test", "-json", "-count=1", "-timeout=90s", "./..."], ROOT / "native_go/tlsbridge", output / "go", 240,
                        dict(os.environ, CGO_ENABLED="0"))
    try:
        backends["go"] = attach_tests(go_result, read_go(output / "go.stdout.log"))
    except (ValueError, OSError):
        backends["go"] = dict(go_result, status="FAIL", cases={}, reason="INVALID_GO_RESULTS")
    race = execute([go, "test", "-race", "-json", "-count=1", "-timeout=90s", "./..."], ROOT / "native_go/tlsbridge", output / "race", 300,
                   dict(os.environ, CGO_ENABLED="1"))
    # Only the explicit missing-compiler diagnostic is an environment blocker.
    # Compilation failures, races and test failures remain failures.
    race_errors = (output / "race.stderr.log").read_text(encoding="utf-8", errors="replace")
    race_output = (output / "race.stdout.log").read_text(encoding="utf-8", errors="replace")
    if race["exitCode"] == 1 and compiler_missing(race_output, race_errors):
        race.update(status="BLOCKED", reason="HOST_C_COMPILER_MISSING", cases={})
    else:
        try:
            attach_tests(race, read_go(output / "race.stdout.log"))
        except (ValueError, OSError):
            race.update(status="FAIL", cases={}, reason="INVALID_RACE_RESULTS")
    backends["race"] = race

    device = {"status": "NOT_RUN", "reason": "ARM64_DEVICE_NOT_SELECTED", "cases": {}}
    if args.arm64_serial and not args.skip_device:
        # Never choose an arbitrary connected device or change its network.
        info = {}
        try:
            for prop in ("ro.product.cpu.abi", "ro.build.version.sdk"):
                info[prop] = subprocess.check_output([args.adb, "-s", args.arm64_serial, "shell", "getprop", prop], text=True, timeout=10).strip()
            if info["ro.product.cpu.abi"] != "arm64-v8a":
                raise ValueError("Required device must be ARM64")
            started = time.time()
            device = execute(gradle + [":app:connectedDebugAndroidTest", "--rerun"] + common + [
                "-PlayanalyzerEnableTls=true", f"-PlayanalyzerTlsGo={go}",
                "-Pandroid.testInstrumentationRunnerArguments.class=" + ",".join(PACKAGE + cls for cls in DEVICE_CLASSES)
            ], ROOT, output / "android", 900, dict(os.environ, ANDROID_SERIAL=args.arm64_serial))
            if device.get("reason") == "TIMEOUT":
                # JNI cannot be interrupted by Future.cancel. End only the
                # selected test app if its instrumentation is stuck in native.
                application_id = debug_application_id(ROOT / "app/build/outputs/apk/debug/output-metadata.json")
                device["timeoutCleanup"] = execute(
                    [args.adb, "-s", args.arm64_serial, "shell", "am", "force-stop", application_id],
                    ROOT, output / "android-timeout-cleanup", 15)
            paths = list((ROOT / "app/build/outputs/androidTest-results/connected/debug").rglob("TEST-*.xml"))
            paths = [p for p in paths if p.stat().st_mtime >= started]
            attach_tests(device, read_junit(paths))
            archive = output / "android-xml"
            archive.mkdir()
            for index, path in enumerate(paths):
                shutil.copyfile(path, archive / f"{index}-{path.name}")
        except (ValueError, OSError, subprocess.SubprocessError, ET.ParseError):
            device.update(status="FAIL", reason="DEVICE_EXECUTION_OR_EVIDENCE_INVALID", cases={})
        device["environment"] = dict(info, serial=args.arm64_serial, buildType="debug", tlsProbe=False, tlsEnabled=True)
    backends["android"] = device

    rows = report["scenarios"]
    for scenario, (backend, cls, method) in SCENARIOS.items():
        package = cls if backend == "go" else PACKAGE + cls
        rows.append({"id": scenario, "backend": backend, "test": cls + "." + method,
                     "status": result_for(backends[backend], package, method)})
    rows.append({"id": "go-race", "backend": "race", "status": race["status"]})
    for experiment in DEVICE_EXPERIMENTS:
        rows.append({"id": experiment, "backend": "isolated-device-experiment", "status": "NOT_RUN",
                     "reason": "Requires a separate run on an isolated Android device"})
    # A backend failure not named by a scenario still fails the overall gate.
    for name, backend in backends.items():
        rows.append({"id": name + "-suite", "backend": name, "status": backend["status"]})
        backend.pop("cases", None)  # tuple keys are internal, reports contain no payloads
    code = exit_code(rows)
    report["gatePassed"] = code == 0
    report["exitCode"] = code
    report["summary"] = dict(collections.Counter(row["status"] for row in rows))
    destination = output / "matrix.json"
    destination.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(destination), "gatePassed": report["gatePassed"], "summary": report["summary"]}))
    return code


if __name__ == "__main__":
    raise SystemExit(main())

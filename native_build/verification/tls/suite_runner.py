#!/usr/bin/env python3
"""TLS-401 host + ARM64 production JNI gate. Required skips return exit code 2.

Only fresh results from this invocation are accepted. No golden update mode.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
import uuid
import xml.etree.ElementTree as ET

from check_fixture import ROOT, RELEASE_IDS, require, sha256

REPO = ROOT.parents[2]
CLASS = "com.example.layanalyzer.TlsGoldenSuiteTest"
BASE_CASES = {"golden", "no-key", "wrong-key", "corrupt-secret", "missing-handshake", "missing-segment", "clear", "reload"}
EXTENDED_CASES = {"upstream-own-key", "untrusted-pcap", "wrong-name-pcap"}
OLD_IDS = {"tls12-h1", "tls13-h1", "tls13-h2"}


def validate_xml(paths: list[Path]) -> dict:
    cases = {}
    for path in paths:
        for suite in ET.parse(path).iter("testsuite"):
            require(all(int(suite.get(key, "0")) == 0 for key in ("failures", "errors", "skipped")),
                    "JUnit reports failed/errored/skipped required cases")
            for case in suite.findall("testcase"):
                require(case.get("classname") == CLASS, "Unexpected test class in suite results")
                name = case.get("name", "")
                match = re.fullmatch(r"goldenNegativesAndClearReload\[([^]]+)\]", name)
                require(match is not None and match[1] not in cases, "Duplicate/unknown required JUnit case")
                require(not any(case.find(tag) is not None for tag in ("failure", "error", "skipped")),
                        "Required case failed or was skipped")
                cases[match[1]] = "PASS"
    require(set(cases) == RELEASE_IDS, "Missing required JUnit cases")
    return cases


def compare_device(manifest: dict, manifest_hash: str, desktop: dict, device: dict, run_id: str) -> list[dict]:
    require(set(device) == RELEASE_IDS, "Missing/extra device fixture reports")
    require({item["fixtureId"] for item in desktop["fixtures"]} == RELEASE_IDS, "Missing desktop fixture reports")
    reference = {item["fixtureId"]: item for item in desktop["fixtures"]}
    comparisons = []
    for fixture in manifest["fixtures"]:
        id = fixture["fixtureId"]
        report = device[id]
        require(report["schemaVersion"] == 1 and report["suiteVersion"] == "tls-golden-v1"
                and report["runId"] == run_id and report["manifestSha256"] == manifest_hash
                and report["fixtureId"] == id and report["passed"] is True, "Stale/invalid device fixture report")
        require(report["abi"] == "arm64-v8a" and report["api"] >= 26 and report["buildType"] == "debug",
                "Required device must be ARM64 debug API26+")
        require(report.get("tlsEnabled") is True and report.get("probeEnabled") is False,
                "Required device must use TLS ON / production JNI / probe OFF")
        require(re.search(r"(?<![\d.])4\.0\.10(?![\d.])", report["embeddedVersion"]) is not None,
                "Embedded Wireshark version mismatch")
        expected_cases = BASE_CASES | (EXTENDED_CASES if id not in OLD_IDS else set())
        require(set(report["cases"]) == expected_cases and all(value is True for value in report["cases"].values()),
                "Missing/failed required device scenario")
        expected = fixture["expectedBody"]["sha256"]
        same = report["bodySha256"] == reference[id]["bodySha256"] == expected
        comparisons.append({"fixtureId": id, "expectedBodySha256": expected,
                            "desktopBodySha256": reference[id]["bodySha256"],
                            "embeddedBodySha256": report["bodySha256"], "equal": same,
                            "device": {key: report[key] for key in ("api", "abi", "buildType", "embeddedVersion")}})
    return comparisons


def execute(args) -> tuple[dict, int]:
    run_id = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ_") + uuid.uuid4().hex[:12]
    output = (args.results_root or REPO / "build/tls-401" / run_id).resolve()
    require(not output.exists(), "Results directory already exists; choose a fresh directory")
    output.mkdir(parents=True)
    manifest_path = ROOT / "fixtures/manifest.json"
    manifest_bytes = manifest_path.read_bytes()
    manifest = json.loads(manifest_bytes)
    require(manifest.get("suiteVersion") == "tls-golden-v1" and
            {item["fixtureId"] for item in manifest["fixtures"]} == RELEASE_IDS,
            "Runner requires the locked TLS-401 release manifest")
    report = {"schemaVersion": 1, "suiteVersion": "tls-golden-v1", "runId": run_id,
              "manifestSha256": sha256(manifest_bytes), "gatePassed": False,
              "environment": {"os": platform.platform(), "python": platform.python_version(), "hostAbi": platform.machine()},
              "desktop": {"status": "FAILED"}, "android": {"status": "NOT_RUN", "requiredAbi": "arm64-v8a"},
              "comparison": {"desktopPinned": "3.6.0", "embeddedPinned": "4.0.10", "status": "NOT_RUN",
                             "fixtures": []}}
    desktop_path = output / "desktop.json"
    with (output / "desktop.log").open("w", encoding="utf-8") as log:
        process = subprocess.run([sys.executable, str(ROOT / "check_fixture.py"), "--tshark", args.tshark,
                                  "--report", str(desktop_path)], cwd=REPO, stdout=log, stderr=log, timeout=300)
    desktop_ok = process.returncode == 0
    if desktop_ok:
        desktop = json.loads(desktop_path.read_text())
        report["desktop"] = dict(desktop, status="PASS")
        report["comparison"]["fixtures"] = [{"fixtureId": item["fixtureId"],
            "desktopBodySha256": item["bodySha256"], "embeddedBodySha256": None,
            "status": "NOT_RUN"} for item in desktop["fixtures"]]
    else:
        report["desktop"]["reason"] = "Fixture checker failed; see desktop.log"
    device_ok = False
    device_failed = False
    if args.skip_device:
        report["android"]["reason"] = "Explicitly not run: required ARM64 device validation pending"
    elif not desktop_ok:
        report["android"]["reason"] = "Desktop golden validation failed"
    else:
        def adb(*command):
            prefix = [args.adb] + (["-s", args.arm64_serial] if args.arm64_serial else [])
            return subprocess.run(prefix + list(command), capture_output=True, check=True, timeout=30,
                                  encoding="utf-8", errors="strict").stdout.strip()
        try:
            devices = [line.split()[0] for line in adb("devices").splitlines()[1:]
                       if len(line.split()) >= 2 and line.split()[1] == "device"]
            if args.arm64_serial:
                require(args.arm64_serial in devices, "Selected ARM64 device is unavailable")
            elif len(devices) == 1:
                args.arm64_serial = devices[0]
            else:
                require(not devices, "Select --arm64-serial when multiple devices are connected")
            if not devices:
                report["android"]["reason"] = "No connected device; required ARM64 validation pending"
            else:
                device_failed = True
                require(adb("shell", "getprop", "ro.product.cpu.abi") == "arm64-v8a", "Selected device is not ARM64")
                report["android"]["api"] = int(adb("shell", "getprop", "ro.build.version.sdk"))
                started = time.time()
                incremental = getattr(args, "incremental", False)
                command = [str(REPO / ("gradlew.bat" if os.name == "nt" else "gradlew")),
                           ":app:connectedDebugAndroidTest", "--no-build-cache",
                           "--no-daemon", "--max-workers=1", "--console=plain",
                           "-PlayanalyzerEnableTls=true",
                           "-PlayanalyzerTlsProbe=false", "-PlayanalyzerTestBuildType=debug",
                           f"-Pandroid.testInstrumentationRunnerArguments.class={CLASS}",
                           f"-Pandroid.testInstrumentationRunnerArguments.tlsSuiteRunId={run_id}",
                           "-Pandroid.injected.androidTest.leaveApksInstalledAfterRun=true"]
                if incremental:
                    init = output / "fresh-device-tests.init.gradle"
                    init.write_text('allprojects { tasks.configureEach { if (name == "connectedDebugAndroidTest") { '
                                    'outputs.upToDateWhen { false } } } }\n', encoding="utf-8")
                    command.extend(["-I", str(init)])
                else:
                    command.append("--rerun-tasks")
                report["android"]["incrementalBuild"] = incremental
                if getattr(args, "go", None):
                    command.append("-PlayanalyzerTlsGo=" + str(Path(args.go).resolve()))
                command.append("-PlayanalyzerTlsPython=" + sys.executable)
                if args.offline: command.append("--offline")
                environment = dict(os.environ, ANDROID_SERIAL=args.arm64_serial)
                for key in list(environment):
                    if key.startswith("LAYANALYZER_SIGNING_"):
                        environment.pop(key)
                report["android"]["command"] = command
                with (output / "android.log").open("w", encoding="utf-8") as log:
                    result = subprocess.run(command, cwd=REPO, env=environment, stdout=log, stderr=log, timeout=1800)
                report["android"]["exitCode"] = result.returncode
                report["android"]["artifacts"] = {}
                for relative in ("app/build/outputs/apk/debug/app-debug.apk",
                                 "app/build/outputs/apk/androidTest/debug/app-debug-androidTest.apk"):
                    artifact = REPO / relative
                    require(artifact.is_file() and (incremental or artifact.stat().st_mtime >= started - 2),
                            "Missing/stale APK from this Golden build")
                    shutil.copyfile(artifact, output / artifact.name)
                    report["android"]["artifacts"][artifact.name] = {
                        "sha256": sha256(artifact.read_bytes()), "size": artifact.stat().st_size}
                require(result.returncode == 0, "Android suite failed; see android.log")
                if incremental:
                    for package, name in (("com.layeranalyzer.android.debug", "app-debug.apk"),
                                          ("com.layeranalyzer.android.debug.test", "app-debug-androidTest.apk")):
                        installed = adb("shell", "pm", "path", package)
                        require(installed.startswith("package:") and "\n" not in installed, "Expected one base APK")
                        actual = adb("shell", "sha256sum", installed.removeprefix("package:")).split()[0]
                        require(actual == report["android"]["artifacts"][name]["sha256"], "Installed APK hash mismatch")
                # AGP writes into this directory via the project build configuration.
                junit = REPO / "app/build/outputs/androidTest-results/connected/debug"
                paths = list(junit.rglob("TEST-*.xml"))
                require(paths and all(path.stat().st_mtime >= started - 2 for path in paths),
                        "Missing/stale JUnit results")
                report["android"]["junit"] = validate_xml(paths)
                shutil.copytree(junit, output / "junit")
                device = {}
                for id in sorted(RELEASE_IDS):
                    # Test-only public hashes/status: run-as is disabled on some OEM devices.
                    raw = adb("exec-out", "cat", "/sdcard/Android/data/com.layeranalyzer.android.debug/files/"
                              f"tls-suite-v1/{run_id}/{id}.json")
                    device[id] = json.loads(raw)
                    (output / f"{id}.json").write_text(raw + "\n", encoding="utf-8")
                comparisons = compare_device(manifest, sha256(manifest_bytes), desktop, device, run_id)
                report["comparison"].update(status="PASS" if all(item["equal"] for item in comparisons) else "FAILED", fixtures=comparisons)
                require(all(item["equal"] for item in comparisons), "Desktop/embedded golden body difference")
                report["android"].update(status="PASS", serial=args.arm64_serial)
                device_ok, device_failed = True, False
        except (ValueError, KeyError, OSError, subprocess.SubprocessError, ET.ParseError) as error:
            report["android"].update(status="FAILED", reason=f"{type(error).__name__}: {error}")
            device_failed = True
    report["gatePassed"] = desktop_ok and device_ok
    report["summary"] = {"total": 2 * len(RELEASE_IDS),
                         "passed": len(RELEASE_IDS) * (int(desktop_ok) + int(device_ok)),
                         "failed": len(RELEASE_IDS) * (int(not desktop_ok) + int(device_failed)),
                         "skipped": len(RELEASE_IDS) if not device_ok and not device_failed else 0}
    report["summary"]["countUnit"] = "fixture/backend verification (not individual assertions)"
    (output / "suite.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"report": str(output / "suite.json"), "gatePassed": report["gatePassed"],
                      "summary": report["summary"]}, indent=2))
    return report, 0 if report["gatePassed"] else (1 if not desktop_ok or device_failed else 2)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--tshark", default="tshark")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--arm64-serial", default="")
    parser.add_argument("--go", type=Path, help="Pinned Go executable for the TLS ON device build")
    parser.add_argument("--results-root", type=Path)
    parser.add_argument("--skip-device", action="store_true")
    parser.add_argument("--offline", action="store_true")
    parser.add_argument("--incremental", action="store_true", help="Reuse up-to-date compile outputs; rerun device cases and verify installed APK hashes")
    try:
        return execute(parser.parse_args())[1]
    except (ValueError, OSError, subprocess.SubprocessError) as error:
        print(f"Suite failed: {type(error).__name__}: {error}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

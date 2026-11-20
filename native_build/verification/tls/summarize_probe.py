#!/usr/bin/env python3
"""TLS-008 required device matrix. Missing/failed/skipped evidence fails closed."""
from __future__ import annotations
import argparse
import base64
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import xml.etree.ElementTree as ET

ABIS = {"arm64-v8a": "debug", "x86_64": "emulator"}
FIXTURES = ("tls12-h1", "tls13-h1", "tls13-h2")
REQUIRED = {"TlsTunEndToEndProbeTest": 4, "TlsBridgeProbeTest": 7,
            "TlsSocketProbeTest": 3, "TlsKeyLogProbeTest": 5,
            "TlsDissectionProbeTest": 5, "LiveCaptureForwardingTest": 1}
BODY_SHA = "9b1ce3253f3312a2d0f896f307a944a2effe972d55ba1a33cc939feb6e6fd7c4"
BODY = b"LayerAnalyzer TLS fixture v1\n"


def check_raw_tun(pcap: bytes, data: dict) -> None:
    assert len(pcap) == data["tunPcapBytes"] and len(pcap) > 24
    assert pcap[:4] == bytes.fromhex("d4c3b2a1") and int.from_bytes(pcap[20:24], "little") == 101
    assert BODY not in pcap
    offset, packets, outbound, inbound = 24, 0, 0, 0
    fixture = bytes((198, 18, 0, 8))
    while offset < len(pcap):
        assert offset + 16 <= len(pcap)
        size = int.from_bytes(pcap[offset + 8:offset + 12], "little")
        assert size > 0 and offset + 16 + size <= len(pcap)
        packet = pcap[offset + 16:offset + 16 + size]
        if size >= 20 and packet[0] >> 4 == 4:
            outbound += packet[16:20] == fixture
            inbound += packet[12:16] == fixture
        packets += 1
        offset += 16 + size
    assert 6 <= packets <= 4096 and packets == data["packetCount"]
    assert outbound > 0 and inbound > 0


def summarize(root: Path) -> dict:
    if not __debug__:
        raise ValueError("Evidence verification requires Python assertions; do not use -O")
    report = {"schemaVersion": 1, "gatePassed": False, "tunMatrixPassed": False, "abis": {}}
    for abi in ABIS:
        errors = []
        cases: dict[str, dict[str, str]] = {name: {} for name in REQUIRED}
        for file in (root / abi).rglob("*.xml"):
            try:
                tree = ET.parse(file)
                for case in tree.iter("testcase"):
                    cls = case.get("classname", "").removeprefix("com.example.layanalyzer.")
                    if cls not in cases:
                        continue
                    name = case.get("name", "")
                    status = "PASS"
                    if case.find("skipped") is not None: status = "SKIPPED"
                    if case.find("failure") is not None or case.find("error") is not None: status = "FAILED"
                    if not name or name in cases[cls]:
                        errors.append(f"duplicate/unnamed required test: {cls}.{name}")
                    cases[cls][name] = status
                for suite in tree.iter("testsuite"):
                    # Some runners report a suite failure without a testcase.
                    if any(int(suite.get(k, "0")) > 0 for k in ("failures", "errors", "skipped")):
                        errors.append("XML reports failed/errored/skipped tests")
            except (ET.ParseError, ValueError, OSError):
                errors.append("invalid test XML")
        classes = {cls: {"expected": expected, "executed": len(cases[cls]),
                         "passed": sum(v == "PASS" for v in cases[cls].values()),
                         "skipped": sum(v == "SKIPPED" for v in cases[cls].values()),
                         "failed": sum(v == "FAILED" for v in cases[cls].values())}
                   for cls, expected in REQUIRED.items()}
        complete = {}
        for fixture in FIXTURES:
            directory = root / abi / "evidence" / fixture
            try:
                data = json.loads((directory / "report.json").read_text(encoding="utf-8"))
                assert data["schemaVersion"] == 1 and data["fixtureId"] == fixture
                assert data["complete"] is True and data["abi"] == abi and data["api"] >= 26
                assert "4.0.10" in data["embeddedVersion"]
                assert data["captureMethod"] == "Android VpnService TUN / original packet relay"
                assert data["fdRecovered"] is True and data["fdFinal"] <= data["fdBaseline"]
                assert data["routeReleaseMillis"] <= 2000 and data["stopMillis"] <= 5000
                assert data["prepareCalls"] == 1 and data["client"]["gatewayReady"] is True
                assert data["droppedPacketCount"] == 0
                assert data["client"]["success"] is True and data["client"]["bodySha256"] == BODY_SHA
                assert data["client"]["upstreamVerified"] is True and data["client"]["configReplaced"] is True
                assert data["client"]["downstreamHandshake"] is True
                assert data["client"]["tlsVersion"] == (771 if fixture == "tls12-h1" else 772)
                assert data["client"]["alpn"] == ("h2" if fixture == "tls13-h2" else "http/1.1")
                assert data["client"]["downstreamClientRandom"] != data["client"]["upstreamClientRandom"]
                for filename, field in (("capture.pcap", "tunPcapSha256"), ("tls-a.keys", "tlsAKeylogSha256"), ("tls-b.keys", "tlsBKeylogSha256")):
                    raw = (directory / filename).read_bytes()
                    assert len(raw) > 0 and hashlib.sha256(raw).hexdigest() == data[field]
                pcap = (directory / "capture.pcap").read_bytes()
                check_raw_tun(pcap, data)
                for phase in ("empty", "tlsB", "tlsA", "clear", "reload"):
                    result = data[phase]
                    assert result["schemaVersion"] == 1 and result["success"] is True
                    assert result["errorCode"] is None and result["error"] is None
                    assert result["preferenceCleared"] is True and result["epanRebuilt"] is True
                    scan = result["scan"]
                    assert scan["frames"] == data["packetCount"] and scan["tcpStreams"] == 1
                    assert scan["tapName"] == "tls" and scan["withTaps"] is True
                    sources = scan["sources"]
                    decrypted_sources = [s for s in sources if s["name"].startswith("Decrypted TLS")]
                    if phase in ("tlsA", "reload"):
                        assert scan["bodySha256"] == BODY_SHA and scan["bodyBytes"] == len(BODY)
                        assert decrypted_sources and scan["records"] and scan["bodyFields"] and scan["directionKnown"] is True
                        for field in scan["bodyFields"]:
                            assert field["field"] == ("http2.data.data" if fixture == "tls13-h2" else "http.file_data")
                            assert field["offsetValid"] is True and field["dataSourceId"] != "raw"
                            matches = [s for s in sources if s["frameNumber"] == field["frameNumber"] and s["id"] == field["dataSourceId"]]
                            assert len(matches) == 1 and 0 <= field["start"]
                            assert 0 < field["length"] <= matches[0]["byteLength"] - field["start"]
                        server_bytes = bytearray()
                        for record in scan["records"]:
                            payload = base64.b64decode(record["bytesBase64"], validate=True)
                            assert len(payload) == record["byteLength"] and 1 <= record["frameNumber"] <= scan["frames"]
                            assert isinstance(record["fromServer"], bool)
                            if record["fromServer"]: server_bytes.extend(payload)
                        assert BODY in server_bytes
                    else:
                        assert scan["bodyBytes"] == 0 and not scan["records"] and not scan["bodyFields"] and not decrypted_sources
                complete[fixture] = True
            except (OSError, ValueError, KeyError, AssertionError, TypeError):
                complete[fixture] = False
        tun = classes["TlsTunEndToEndProbeTest"]
        tun_names = {"tls12H1Tun", "tls13H1Tun", "tls13H2Tun", "socksConnectPreservesReadAhead"}
        tun_ok = (set(cases["TlsTunEndToEndProbeTest"]) == tun_names and
                  tun["executed"] == tun["passed"] == tun["expected"] and all(complete.values()) and not errors)
        all_ok = all(c["executed"] == c["passed"] == c["expected"] for c in classes.values())
        report["abis"][abi] = {"tests": classes, "fixtures": complete, "errors": sorted(set(errors)),
                               "tunPassed": tun_ok, "allRequiredDeviceTestsPassed": all_ok and tun_ok}
    report["tunMatrixPassed"] = all(r["tunPassed"] for r in report["abis"].values())
    report["gatePassed"] = all(r["allRequiredDeviceTestsPassed"] for r in report["abis"].values())
    report["status"] = "PASS" if report["gatePassed"] else "PARTIAL"
    report["scope"] = "Device evidence gate; retain separate ON/OFF/16KiB build audits and Linux race prerequisite"
    return report


def run_tun(args) -> None:
    # A fresh output root prevents old XML or successful captures from masking a
    # failed current run. Never recursively delete caller directories.
    if args.results_root.exists():
        raise ValueError("--run requires a new results root")
    if not args.arm64_serial or not args.x86_serial:
        raise ValueError("--run requires explicit serials for both ABIs")
    for abi, serial in zip(ABIS, (args.arm64_serial, args.x86_serial)):
        actual = subprocess.check_output([args.adb, "-s", serial, "shell", "getprop", "ro.product.cpu.abi"], text=True).strip()
        if actual != abi: raise ValueError("device ABI mismatch")
    args.results_root.mkdir(parents=True)
    for abi, serial in zip(ABIS, (args.arm64_serial, args.x86_serial)):
        variant = ABIS[abi]
        out = args.results_root / abi
        out.mkdir()
        command = [str(Path("gradlew.bat").resolve()), f":app:connected{variant.title()}AndroidTest",
                   "-PlayanalyzerTlsProbe=true", f"-PlayanalyzerTlsProbeLibDir={args.probe_lib_dir}",
                   f"-PlayanalyzerTestBuildType={variant}",
                   "-Pandroid.testInstrumentationRunnerArguments.class=com.example.layanalyzer.TlsTunEndToEndProbeTest", "--console=plain"]
        with (out / "gradle.log").open("wb") as log:
            result = subprocess.run(command, env={**os.environ, "ANDROID_SERIAL": serial}, stdout=log, stderr=subprocess.STDOUT)
        if result.returncode: continue  # Never consume stale Gradle XML after failure.
        source = Path("app/build/outputs/androidTest-results/connected") / variant
        for index, xml in enumerate(source.rglob("*.xml")):
            shutil.copyfile(xml, out / f"test-{index}.xml")
        for fixture in FIXTURES:
            directory = out / "evidence" / fixture
            directory.mkdir(parents=True)
            for filename in ("report.json", "capture.pcap", "tls-a.keys", "tls-b.keys"):
                command = [args.adb, "-s", serial, "exec-out", "run-as", "com.layeranalyzer.android", "cat", f"no_backup/tls-008/{fixture}/{filename}"]
                with (directory / filename).open("wb") as output:
                    subprocess.run(command, stdout=output, stderr=subprocess.DEVNULL, check=False)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--results-root", type=Path, required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--probe-lib-dir", default="build/tls-008")
    parser.add_argument("--adb", default="adb")
    parser.add_argument("--arm64-serial", default="")
    parser.add_argument("--x86-serial", default="")
    parser.add_argument("--run", action="store_true")
    args = parser.parse_args()
    if args.run: run_tun(args)
    report = summarize(args.results_root)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    raise SystemExit(0 if report["gatePassed"] else 2)


if __name__ == "__main__": main()

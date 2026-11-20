#!/usr/bin/env python3
"""TLS-006: capture real Go client-side packets; verify A/B/empty key direction.

Host loopback evidence only. This is not Android TUN or embedded Wireshark proof.
Requires the tlsprobe-tagged cmd/tlspairprobe executable and TLS-002 dependencies.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import subprocess
import time

from check_fixture import inspect_capture, keylog_random, require, sha256, tool_version

BODY = b"LayerAnalyzer TLS fixture v1\n"
PROTOCOLS = {"tls12-h1": (771, "http/1.1"), "tls13-h1": (772, "http/1.1"), "tls13-h2": (772, "h2")}


def check(directory: Path, protocol: str, tshark: str) -> dict:
    version, alpn = PROTOCOLS[protocol]
    result = json.loads((directory / "result.json").read_text(encoding="utf-8"))
    port = result["downstreamPort"]
    a, b = directory / "tls-a.keys", directory / "tls-b.keys"
    require(keylog_random(a) == result["downstreamClientRandom"], "A random mismatch")
    require(keylog_random(b) == result["upstreamClientRandom"], "B random mismatch")
    require(keylog_random(a) != keylog_random(b), "A/B secrets were mixed")
    require(result["upstreamVerified"] and result["configReplaced"] and result["downstreamHandshake"], "Handshake ordering/config replacement failed")
    require(result["tlsVersion"] == version and result["alpn"] == alpn, "Client TLS/ALPN mismatch")
    require(result["bodyBytes"] == len(BODY) and result["bodySha256"] == sha256(BODY), "Independent client body mismatch")
    pcap = directory / "client.pcap"
    correct = inspect_capture(tshark, pcap, a, port, alpn)
    wrong = inspect_capture(tshark, pcap, b, port, alpn)
    empty = inspect_capture(tshark, pcap, None, port, alpn)
    require(correct["streams"] == {"0"} and correct["randoms"] == {keylog_random(a)}, "PCAP must contain exactly TLS A")
    require(correct["versions"] == {f"0x{version:04x}"} and correct["alpn"] == {alpn}, "Captured TLS/ALPN mismatch")
    require(correct["requestSeen"] and correct["statuses"] == ["200"] and correct["body"] == BODY, "TLS A did not decrypt the real HTTP body")
    require(not wrong["body"] and not empty["body"] and not wrong["requestSeen"] and not empty["requestSeen"], "Negative secrets decrypted TLS A")
    return {"protocol": protocol, "passed": True, "captureSource": "host-raw-loopback",
            "packets": correct["packets"], "bodySha256": sha256(correct["body"]),
            "tlsBPlaintextBytes": len(wrong["body"]), "emptyPlaintextBytes": len(empty["body"]),
            "downstreamClientRandom": keylog_random(a), "upstreamClientRandom": keylog_random(b),
            "files": {name: sha256((directory / name).read_bytes()) for name in
                      ("client.pcap", "tls-a.keys", "tls-b.keys", "result.json")}}


def capture(executable: Path, directory: Path, protocol: str, dumpcap: str, interface: str) -> None:
    directory.mkdir(parents=True, exist_ok=False)
    process = subprocess.Popen([str(executable.resolve()), "-protocol", protocol, "-output", str(directory.resolve())],
                               stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    capturer = None
    try:
        # The executable emits ready before making the actual TLS client socket.
        ready = json.loads(process.stdout.readline())
        require(ready["ready"] is True, "Probe not ready")
        with (directory / "dumpcap.log").open("w") as log:
            capturer = subprocess.Popen([dumpcap, "-i", interface, "-p", "-f",
                f"host 127.0.0.1 and tcp port {ready['downstreamPort']}", "-P", "-w",
                str(directory / "client.pcap"), "-a", "duration:4", "-q"], stdout=log, stderr=log)
            time.sleep(0.8)
            require(capturer.poll() is None, "dumpcap exited before capture")
            stdout, _ = process.communicate("GO\n", timeout=15)
            require(process.returncode == 0 and stdout.strip() == "PASS", "Go pair failed")
            require(capturer.wait(timeout=10) == 0, "dumpcap capture failed")
    finally:
        for child in (process, capturer):
            if child is not None and child.poll() is None:
                child.kill()
                child.wait(timeout=5)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--executable", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--tshark", required=True)
    parser.add_argument("--dumpcap")
    parser.add_argument("--interface", required=True)
    parser.add_argument("--check-only", action="store_true")
    args = parser.parse_args()
    dumpcap = args.dumpcap or str(Path(args.tshark).with_name("dumpcap.exe" if Path(args.tshark).suffix == ".exe" else "dumpcap"))
    report = {"schemaVersion": 1, "tshark": tool_version(args.tshark), "androidDeviceTestsExecuted": 0, "fixtures": []}
    for protocol in PROTOCOLS:
        directory = args.output / protocol
        if not args.check_only:
            capture(args.executable, directory, protocol, dumpcap, args.interface)
        report["fixtures"].append(check(directory, protocol, args.tshark))
    (args.output / "report.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print("PASS: 3 protocols; TLS A decrypts; TLS B/empty do not; Android tests executed: 0")


if __name__ == "__main__":
    main()

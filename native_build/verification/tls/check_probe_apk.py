#!/usr/bin/env python3
"""Audit TLS-004 ON/OFF packaging without claiming Android runtime validation."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

from audit_bridge import inspect_elf

PROBE_SYMBOLS = {
    "Java_com_example_layanalyzer_NativeEngine_" + name
    for name in ("getTlsBridgeProbeState", "loadTlsBridgeProbe", "startTlsBridgeProbe", "stopTlsBridgeProbe", "runTlsSocketProbe", "runTlsKeyLogProbe", "runTlsDissectionProbe", "runTlsTunProbe")
}


def audit(apk: Path, abi: str, enabled: bool, readelf: Path, require_socket_probe: bool = False, require_pair_probe: bool = False, require_tun_probe: bool = False) -> dict:
    if (require_socket_probe or require_pair_probe or require_tun_probe) and not enabled:
        raise ValueError("probe extensions require an ON build")
    report = {"schemaVersion": 1, "apk": apk.name, "abi": abi, "probeEnabled": enabled,
              "deviceTestsExecuted": 0, "libraries": {}}
    with zipfile.ZipFile(apk) as archive, tempfile.TemporaryDirectory(prefix="tls004-") as directory:
        service_name = "com.example.layanalyzer.capture.tls.TlsTunProbeVpnService"
        manifest = archive.read("AndroidManifest.xml")
        if any(service_name.encode(encoding) in manifest for encoding in ("utf-16le", "utf-8")) != enabled:
            raise ValueError("TUN probe service manifest does not match ON/OFF")
        dex_marker = b"Lcom/example/layanalyzer/capture/tls/TlsTunProbeVpnService;"
        has_service = any(dex_marker in archive.read(name) for name in archive.namelist() if re.fullmatch(r"classes\d*\.dex", name))
        if has_service != enabled:
            raise ValueError("TUN probe implementation does not match ON/OFF")
        if any(name.startswith("assets/tls/fixtures/") for name in archive.namelist()):
            raise ValueError("Synthetic TLS fixtures must stay in the test APK")
        entries = [entry for entry in archive.namelist() if entry.startswith("lib/") and entry.endswith(".so")]
        if {entry.split("/")[1] for entry in entries} != {abi}:
            raise ValueError("APK ABI set differs from the requested single ABI")
        go_entry = f"lib/{abi}/liblayanalyzer_tls_probe.so"
        if (go_entry in entries) != enabled:
            raise ValueError("Go probe packaging does not match ON/OFF")
        libraries = [f"lib/{abi}/liblayanalyzer.so"] + ([go_entry] if enabled else [])
        for entry in libraries:
            data = archive.read(entry)
            loads = inspect_elf(data, abi)
            local = Path(directory) / Path(entry).name
            local.write_bytes(data)
            def elf(*args: str) -> str:
                return subprocess.run([str(readelf), *args, str(local)], check=True,
                                      capture_output=True, text=True).stdout
            symbols = elf("--dyn-syms", "--wide")
            exports = [parts[7] for line in symbols.splitlines()
                       if len(parts := line.split()) >= 8 and
                       parts[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and parts[6] != "UND"]
            needed = re.findall(r"\(NEEDED\).*?\[(.*?)\]", elf("--dynamic", "--wide"))
            if entry.endswith("/liblayanalyzer.so"):
                if exports.count("JNI_OnLoad") != 1:
                    raise ValueError("Main library must export exactly one JNI_OnLoad")
                if (set(exports) & PROBE_SYMBOLS) != (PROBE_SYMBOLS if enabled else set()):
                    raise ValueError("JNI probe exports do not match ON/OFF")
                if any("tls_probe" in name for name in needed):
                    raise ValueError("Main library eagerly links the Go probe")
            if entry == go_entry and require_socket_probe:
                required = {"la_tls_probe_socket_abi_version", "la_tls_probe_socket_dial"}
                if not required <= set(exports):
                    raise ValueError("Go library lacks the TLS-005 socket extension; rebuild it")
            if entry == go_entry and require_pair_probe:
                required = {"la_tls_probe_pair_abi_version", "la_tls_probe_pair_run", "la_tls_probe_pair_free"}
                if not required <= set(exports):
                    raise ValueError("Go library lacks the TLS-006 pair extension; rebuild it")
            if entry == go_entry and require_tun_probe:
                if not {"la_tls_probe_tun_abi_version", "la_tls_probe_tun_run"} <= set(exports):
                    raise ValueError("Go library lacks the TLS-008 TUN extension; rebuild it")
            info = archive.getinfo(entry)
            # Record ZIP page alignment separately from ELF LOAD alignment. Older
            # AGP packaging may need a later fix; do not mistake either for runtime proof.
            with apk.open("rb") as source:
                source.seek(info.header_offset + 26)
                name_size, extra_size = struct.unpack("<HH", source.read(4))
            data_offset = info.header_offset + 30 + name_size + extra_size
            report["libraries"][Path(entry).name] = {
                "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data),
                "needed": needed, "loadAlignment": [load["alignment"] for load in loads],
                "probeJniExports": sorted(set(exports) & PROBE_SYMBOLS),
                "jniOnLoadCount": exports.count("JNI_OnLoad"),
                "zipStored": info.compress_type == zipfile.ZIP_STORED,
                "zip16KiBAligned": info.compress_type == zipfile.ZIP_STORED and data_offset % 16384 == 0,
            }
    return report


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--apk", required=True, type=Path)
    parser.add_argument("--abi", required=True, choices=["arm64-v8a", "x86_64"])
    parser.add_argument("--probe", required=True, choices=["on", "off"])
    parser.add_argument("--readelf", required=True, type=Path)
    parser.add_argument("--report", required=True, type=Path)
    parser.add_argument("--require-socket-probe", action="store_true")
    parser.add_argument("--require-pair-probe", action="store_true")
    parser.add_argument("--require-tun-probe", action="store_true")
    args = parser.parse_args()
    report = audit(args.apk, args.abi, args.probe == "on", args.readelf, args.require_socket_probe, args.require_pair_probe, args.require_tun_probe)
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()

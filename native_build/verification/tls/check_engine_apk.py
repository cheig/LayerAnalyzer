#!/usr/bin/env python3
"""Audit production TLS packaging and lazy linkage; does not run Android code."""
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
from check_probe_apk import audit as audit_probe


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apk", required=True, type=Path)
    p.add_argument("--abi", required=True, choices=("arm64-v8a", "x86_64"))
    p.add_argument("--tls", required=True, choices=("on", "off"))
    p.add_argument("--readelf", required=True, type=Path)
    p.add_argument("--report", required=True, type=Path)
    a = p.parse_args()
    report = audit_probe(a.apk, a.abi, False, a.readelf)
    report["tlsEnabled"] = a.tls == "on"
    # The production surface grows only with the task that adds it: TLS-206 added
    # generateTlsCaMaterial and TLS-215 added getTlsProxyToken, and each must
    # exist exactly once in ON and OFF alike.
    required = {"Java_com_example_layanalyzer_NativeEngine_" + name for name in (
        "getTlsProxyCapabilities", "startTlsProxy", "stopTlsProxy", "pollTlsProxyEvents",
        "getTlsProxyStats", "generateTlsCaMaterial", "getTlsProxyToken")}
    with zipfile.ZipFile(a.apk) as archive, tempfile.TemporaryDirectory(prefix="tls201-") as directory:
        go_entry = f"lib/{a.abi}/liblayanalyzer_tls.so"
        if (go_entry in archive.namelist()) != report["tlsEnabled"]:
            raise ValueError("TLS Go packaging does not match ON/OFF")
        for name in (["liblayanalyzer.so", "liblayanalyzer_tls.so"] if report["tlsEnabled"] else ["liblayanalyzer.so"]):
            entry = f"lib/{a.abi}/{name}"
            data = archive.read(entry)
            loads = inspect_elf(data, a.abi)
            local = Path(directory) / name
            local.write_bytes(data)
            symbols = subprocess.check_output([a.readelf, "--dyn-syms", "--wide", local], text=True)
            dynamic = subprocess.check_output([a.readelf, "--dynamic", "--wide", local], text=True)
            exports = [v[7] for line in symbols.splitlines() if len(v := line.split()) >= 8 and v[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and v[6] != "UND"]
            if name == "liblayanalyzer.so":
                if any(exports.count(s) != 1 for s in required):
                    raise ValueError("production JNI must exist exactly once in ON and OFF")
                if any("layanalyzer_tls" in value for value in re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic)):
                    raise ValueError("main library must not eagerly link Go")
            elif any(s.startswith("la_tls_probe_") for s in exports):
                raise ValueError("production library includes probe exports")
            info = archive.getinfo(entry)
            with a.apk.open("rb") as stream:
                stream.seek(info.header_offset + 26)
                n, e = struct.unpack("<HH", stream.read(4))
            aligned = info.compress_type == zipfile.ZIP_STORED and (info.header_offset + 30 + n + e) % 16384 == 0
            if not aligned:
                raise ValueError("library ZIP entry is not 16 KiB aligned")
            report["libraries"].setdefault(name, {}).update(sha256=hashlib.sha256(data).hexdigest(), bytes=len(data),
                loadAlignment=[v["alignment"] for v in loads], zip16KiBAligned=aligned)
    report["productionJni"] = sorted(required)
    a.report.parent.mkdir(parents=True, exist_ok=True)
    a.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"PASS {a.abi} TLS {a.tls}: packaging, unique JNI, lazy linkage, ELF/ZIP alignment")


if __name__ == "__main__":
    main()

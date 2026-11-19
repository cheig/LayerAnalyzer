#!/usr/bin/env python3
"""Fail closed on Android smoke-library ABI, dependency and 16 KiB violations."""
from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import sys

EXPECTED_SYMBOLS = {
    "la_tls_probe_abi_version", "la_tls_probe_start", "la_tls_probe_stop",
    "la_tls_probe_active_handles",
}
# Only Android public NDK libraries needed by Go's runtime are permitted.
PUBLIC_DEPENDENCIES = {"libc.so", "libm.so", "libdl.so", "liblog.so"}


def run(*args: str) -> str:
    return subprocess.run(args, check=True, capture_output=True, text=True).stdout


def inspect_elf(data: bytes, abi: str) -> list[dict]:
    if data[:7] != b"\x7fELF\x02\x01\x01":
        raise ValueError("expected a little-endian ELF64 library")
    elf_type, machine = struct.unpack_from("<HH", data, 16)
    if elf_type != 3 or machine != {"arm64-v8a": 183, "x86_64": 62}[abi]:
        raise ValueError("ELF type or machine does not match requested ABI")
    phoff = struct.unpack_from("<Q", data, 32)[0]
    phsize, phnum = struct.unpack_from("<HH", data, 54)
    if phsize != 56 or phoff + phsize * phnum > len(data):
        raise ValueError("invalid ELF program header bounds")
    loads = []
    for index in range(phnum):
        kind, flags, offset, vaddr, _, filesz, memsz, align = struct.unpack_from(
            "<IIQQQQQQ", data, phoff + index * phsize)
        if kind != 1:
            continue
        if align < 16384 or align & (align - 1) or offset % 16384 != vaddr % 16384:
            raise ValueError(f"LOAD {index} is not compatible with 16 KiB pages")
        if filesz > memsz or offset + filesz > len(data):
            raise ValueError(f"LOAD {index} exceeds file bounds")
        loads.append({"offset": offset, "virtualAddress": vaddr, "fileSize": filesz,
                      "memorySize": memsz, "flags": flags, "alignment": align})
    if not loads:
        raise ValueError("ELF has no LOAD segments")
    return loads


def audit(args: argparse.Namespace) -> dict:
    path = args.library
    data = path.read_bytes()
    loads = inspect_elf(data, args.abi)
    dynamic = run(args.readelf, "--dynamic", "--wide", str(path))
    symbols = run(args.readelf, "--dyn-syms", "--wide", str(path))
    headers = run(args.readelf, "--file-header", "--program-headers", "--wide", str(path))
    needed = sorted(re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic))
    sonames = re.findall(r"\(SONAME\).*?\[(.*?)\]", dynamic)
    if sonames != ["liblayanalyzer_tls_probe.so"]:
        raise ValueError("missing or unexpected SONAME")
    if not needed or set(needed) - PUBLIC_DEPENDENCIES:
        raise ValueError(f"unexpected dynamic dependencies: {needed}")
    exported = set()
    for line in symbols.splitlines():
        fields = line.split()
        if len(fields) >= 8 and fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and fields[6] != "UND":
            exported.add(fields[7])
    if not EXPECTED_SYMBOLS <= exported:
        raise ValueError(f"missing exports: {sorted(EXPECTED_SYMBOLS - exported)}")
    build_info = run(args.go, "version", "-m", str(path))
    for setting in ("go1.27.2", "-buildmode=c-shared", "-tags=tlsprobe", "CGO_ENABLED=1", "GOOS=android",
                    "GOARCH=" + {"arm64-v8a": "arm64", "x86_64": "amd64"}[args.abi]):
        if setting not in build_info:
            raise ValueError(f"missing Go build setting: {setting}")
    # Reports contain relative artifact names only; compiler installation paths
    # are deliberately not embedded in the committed manifest.
    for name, content in (("readelf-headers.txt", headers), ("readelf-dynamic.txt", dynamic),
                          ("readelf-symbols.txt", symbols)):
        (args.manifest.parent / name).write_text(content, encoding="utf-8")
    return {
        "schemaVersion": 1, "purpose": "TLS-003 P0 smoke only", "abi": args.abi,
        "androidApi": 26, "goVersion": "go1.27.2", "ndkVersion": "27.0.12077973",
        "host": args.host, "soname": sonames[0], "needed": needed,
        "smokeExports": sorted(EXPECTED_SYMBOLS), "loadSegments": loads,
        "compiler": "clang --target=" + {"arm64-v8a": "aarch64", "x86_64": "x86_64"}[args.abi] + "-linux-android26",
        "cFlags": ["-O2", "-g", "-fPIC"],
        "goBuildFlags": ["-trimpath", "-buildvcs=false", "-tags=tlsprobe", "-buildmode=c-shared"],
        "linkFlags": ["-linkmode=external", "-Wl,-z,max-page-size=16384,-z,common-page-size=16384,-soname,liblayanalyzer_tls_probe.so"],
        "files": [{"path": name, "sha256": hashlib.sha256((path.parent / name).read_bytes()).hexdigest(),
                   "bytes": (path.parent / name).stat().st_size}
                  for name in (path.name, "liblayanalyzer_tls_probe.h", "tls_probe.h")],
        "elfAudit": "PASS", "androidRuntimeTest": "NOT_RUN",
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--library", required=True, type=Path)
    parser.add_argument("--abi", required=True, choices=("arm64-v8a", "x86_64"))
    parser.add_argument("--readelf", required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--host", required=True, choices=("linux-x86_64", "windows-x86_64"))
    parser.add_argument("--manifest", required=True, type=Path)
    args = parser.parse_args()
    try:
        report = audit(args)
        args.manifest.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"PASS {args.abi}: {len(report['loadSegments'])} LOAD segments, 16 KiB, "
              f"public dependencies {','.join(report['needed'])}")
    except (OSError, ValueError, struct.error, subprocess.CalledProcessError) as exc:
        print(f"TLS bridge audit failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

#!/usr/bin/env python3
"""Build and audit the production (no tlsprobe tag) Android C ABI library."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import sys

REPO = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(REPO / "native_build/verification/tls"))
from audit_bridge import inspect_elf, PUBLIC_DEPENDENCIES
sys.path.insert(0, str(REPO / "tools"))
from check_tls_dependencies import build_provenance, check_build_info, offline_env, digest


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--ndk", required=True, type=Path)
    p.add_argument("--abi", required=True, choices=("arm64-v8a", "x86_64"))
    p.add_argument("--go", default="go")
    p.add_argument("--output", required=True, type=Path)
    a = p.parse_args()
    out = a.output.resolve()
    if out == REPO or out in REPO.parents or any(out == REPO / s or REPO / s in out.parents for s in ("app/src", "native_go", "native_build", "docs")):
        raise ValueError("output must be a separate build directory")
    ndk = a.ndk.resolve()
    if not re.search(r"Pkg.Revision\s*=\s*27\.0\.12077973\s*$", (ndk / "source.properties").read_text(), re.M):
        raise ValueError("NDK 27.0.12077973 required")
    go = shutil.which(a.go)
    if not go:
        raise ValueError("Go 1.27.2 not found; set -PlayanalyzerTlsGo to its executable")
    env = offline_env()
    version = subprocess.check_output([go, "version"], env=env, text=True)
    if not version.startswith("go version go1.27.2 "):
        raise ValueError("Go 1.27.2 required; automatic download disabled")
    host = "windows-x86_64" if os.name == "nt" else "linux-x86_64"
    exe = ".exe" if os.name == "nt" else ""
    bin_dir = ndk / "toolchains/llvm/prebuilt" / host / "bin"
    clang = bin_dir / ("clang" + exe)
    readelf = bin_dir / ("llvm-readelf" + exe)
    arch, target = {"arm64-v8a": ("arm64", "aarch64-linux-android26"), "x86_64": ("amd64", "x86_64-linux-android26")}[a.abi]
    env.update(CGO_ENABLED="1", GOOS="android", GOARCH=arch,
               CC=f'"{clang.as_posix()}" --target={target}', CGO_CFLAGS="-O2 -g -fPIC",
               CGO_CPPFLAGS="", CGO_CXXFLAGS="", CGO_LDFLAGS="")
    out.mkdir(parents=True, exist_ok=True)
    env.update(GOCACHE=str(out / "go-cache"), GOMODCACHE=str(out / "go-mod-cache"))
    provenance = build_provenance(go, env)
    provenance["tools"] = {"clangSha256": digest(clang), "readelfSha256": digest(readelf),
                           "ndkSourcePropertiesSha256": digest(ndk / "source.properties"),
                           "pythonVersion": sys.version.split()[0]}
    library = out / "liblayanalyzer_tls.so"
    flags = "-linkmode=external -extldflags=-Wl,-z,max-page-size=16384,-z,common-page-size=16384,-soname,liblayanalyzer_tls.so"
    build_args = ["build", "-mod=readonly", "-trimpath", "-buildvcs=false", "-buildmode=c-shared", "-ldflags=" + flags]
    subprocess.run([go, *build_args, "-o", str(library), "./cmd/androidbridge"],
                   cwd=REPO / "native_go/tlsbridge", env=env, check=True)
    provenance["command"] = ["go", *build_args, "-o", "<output>/liblayanalyzer_tls.so", "./cmd/androidbridge"]
    provenance["environment"] = {k: env[k] for k in ("GOTOOLCHAIN", "GOENV", "GOFLAGS", "GOWORK", "GOEXPERIMENT",
        "GOPROXY", "GOSUMDB", "CGO_ENABLED", "GOOS", "GOARCH", "CGO_CFLAGS", "CGO_CPPFLAGS", "CGO_CXXFLAGS", "CGO_LDFLAGS")}
    provenance["compilerTarget"] = target
    data = library.read_bytes()
    loads = inspect_elf(data, a.abi)
    dynamic = subprocess.check_output([readelf, "--dynamic", "--wide", library], text=True)
    symbols = subprocess.check_output([readelf, "--dyn-syms", "--wide", library], text=True)
    expected = {"la_tls_abi_version", "la_tls_capabilities", "la_tls_start", "la_tls_stop", "la_tls_poll", "la_tls_stats", "la_tls_generate_ca", "la_tls_free_buffer"}
    exports = {fields[7] for line in symbols.splitlines() if len(fields := line.split()) >= 8 and fields[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and fields[6] != "UND"}
    if not expected <= exports or any(s.startswith("la_tls_probe_") for s in exports):
        raise ValueError("production ABI exports mismatch")
    needed = sorted(re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic))
    if not needed or set(needed) - PUBLIC_DEPENDENCIES or re.findall(r"\(SONAME\).*?\[(.*?)\]", dynamic) != [library.name]:
        raise ValueError("unexpected dependencies/SONAME")
    info = subprocess.check_output([go, "version", "-m", library], env=env, encoding="utf-8")
    check_build_info(info)
    if "tlsprobe" in info or not all(s in info for s in ("go1.27.2", "-buildmode=c-shared", "CGO_ENABLED=1", "GOOS=android", "GOARCH=" + arch)):
        raise ValueError("Go production build metadata mismatch")
    shutil.copyfile(REPO / "native_go/tlsbridge/include/la_tls_bridge.h", out / "la_tls_bridge.h")
    report = {"schemaVersion": 1, "abi": a.abi, "host": host, "goVersion": "go1.27.2", "ndkVersion": "27.0.12077973",
              "androidApi": 26, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data), "exports": sorted(expected),
              "needed": needed, "loadSegments": loads, "elfAudit": "PASS", "androidRuntimeTest": "NOT_RUN",
              "inputs": provenance}
    (out / "build-manifest.json").write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"PASS production TLS {a.abi}: ABI v1, {len(loads)} aligned LOAD segments", flush=True)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""TLS-405: audit the final APK, including R8 output; never sign or install it."""
import argparse
import base64
import hashlib
import json
from pathlib import Path
import re
import struct
import subprocess
import tempfile
import zipfile

from audit_bridge import inspect_elf, PUBLIC_DEPENDENCIES
from dex_contract import read_dex, has_parent, resolve_method

ROOT = Path(__file__).resolve().parents[3]
NATIVE = "Lcom/example/layanalyzer/NativeEngine;"
CALLBACK = "Lcom/example/layanalyzer/capture/tls/TlsPlatformCallbacks;"
EXCEPTION = "Lcom/example/layanalyzer/capture/tls/TlsCertificateException;"
CALLBACK_METHODS = {
    ("prepareSocket", "(IJ)Ljava/lang/String;"),
    ("resolveHost", "(Ljava/lang/String;J)Ljava/lang/String;"),
    ("verifyUpstream", "([[BLjava/lang/String;Ljava/lang/String;Ljava/lang/String;)Ljava/lang/String;"),
    ("offerSecret", "(Ljava/lang/String;Ljava/lang/String;[B)Z"),
}
TLS_METHODS = {
    "getTlsProxyCapabilities", "startTlsProxy", "stopTlsProxy", "pollTlsProxyEvents",
    "getTlsProxyStats", "getTlsProxyToken", "generateTlsCaMaterial", "configureTlsSecrets",
    "projectTlsClientHellos", "getPacketDataSources", "readPacketDataSource",
    "followTlsStream", "exportTlsFollowStream",
}
PROGRESS_CALLBACK_METHODS = {
    "Lcom/example/layanalyzer/NativeEngine$IndexProgressCallback;": ("onProgress", "(IJJ)Z"),
    "Lcom/example/layanalyzer/NativeEngine$RtpProgressCallback;": ("onProgress", "(II)Z"),
}
GO_EXPORTS = {"la_tls_" + v for v in ("abi_version", "capabilities", "start", "stop", "poll", "stats", "generate_ca", "free_buffer")}
SYSTEM_LIBS = PUBLIC_DEPENDENCIES | {"libandroid.so", "libz.so"}
PROBE_MARKERS = (b"la_tls_probe_", b"tlsprobe", b"tlsbridge/internal/probe", b"TlsTunProbeVpnService",
                 b"LayerAnalyzer ephemeral probe root")


def sha(data):
    return hashlib.sha256(data).hexdigest()


def run(*args):
    return subprocess.check_output([str(a) for a in args], text=True, encoding="utf-8", errors="replace")


def jni_name(owner, name):
    def escape(value):
        return value.replace("_", "_1").replace("/", "_").replace("$", "_00024")
    return "Java_" + escape(owner[1:-1]) + "_" + escape(name)


def check_dex(classes, exports, release):
    if NATIVE not in classes:
        raise ValueError("NativeEngine was removed or renamed")
    methods = classes[NATIVE]["methods"]
    if not TLS_METHODS <= {name for name, _ in methods}:
        raise ValueError("production TLS JNI declarations missing in DEX")
    checked = []
    for owner, cls in classes.items():
        if release and owner.startswith("Lcom/example/layanalyzer/") and ("Tls" in owner and "Probe" in owner):
            raise ValueError("P0 probe class retained in release DEX: " + owner)
        if owner not in (NATIVE, "Lcom/example/layanalyzer/capture/Tun2SocksBridge;"):
            continue
        for (name, descriptor), method in cls["methods"].items():
            if release and ("Probe" in name or name == "exportPerfResults"):
                raise ValueError("debug/probe method retained in release DEX: " + name)
            if method["access"] & 0x100 and (release or "Probe" not in name):
                symbol = jni_name(owner, name)
                if exports.count(symbol) != 1:
                    raise ValueError("native DEX method lacks unique final ELF export: " + symbol)
                checked.append(name + descriptor)
    if CALLBACK not in classes:
        raise ValueError("TLS callback interface removed or renamed")
    implementations = []
    for name, cls in classes.items():
        if cls["access"] & 0x600 or not has_parent(classes, name, CALLBACK):
            continue
        for method in CALLBACK_METHODS:
            resolved = resolve_method(classes, name, method)
            if not resolved or not resolved["access"] & 1 or resolved["access"] & 0x408 or not resolved["code"]:
                raise ValueError("JNI callback missing public concrete instance method: " + name + "." + method[0])
        implementations.append(name)
    if not implementations:
        raise ValueError("no concrete production TLS callbacks in DEX")
    progress_implementations = {}
    for interface, method in PROGRESS_CALLBACK_METHODS.items():
        declaration = resolve_method(classes, interface, method)
        if not declaration or not declaration["access"] & 1 or declaration["access"] & 8:
            raise ValueError("JNI progress callback interface method missing: " + interface)
        concrete = []
        for name, cls in classes.items():
            if cls["access"] & 0x600 or not has_parent(classes, name, interface):
                continue
            resolved = resolve_method(classes, name, method)
            if not resolved or not resolved["access"] & 1 or resolved["access"] & 0x408 or not resolved["code"]:
                raise ValueError("JNI progress callback missing public concrete instance method: " + name)
            concrete.append(name)
        if not concrete:
            raise ValueError("no concrete JNI progress callbacks in DEX: " + interface)
        progress_implementations[interface] = sorted(concrete)
    constructor = resolve_method(classes, EXCEPTION, ("<init>", "(Ljava/lang/String;)V"))
    if EXCEPTION not in classes or not constructor or not constructor["access"] & 1 or not constructor["code"]:
        raise ValueError("JNI ThrowNew exception class/String constructor not preserved")
    return {"nativeMethods": sorted(checked), "callbackImplementations": sorted(implementations),
            "callbackDescriptors": sorted(name + desc for name, desc in CALLBACK_METHODS),
            "progressCallbackImplementations": progress_implementations, "exceptionStringConstructor": "PASS"}


def dependency_closure(libraries):
    for name, lib in libraries.items():
        missing = set(lib["needed"]) - libraries.keys() - SYSTEM_LIBS
        if missing:
            raise ValueError(f"unresolved/private ELF dependency in {name}: {sorted(missing)}")
        if lib["soname"] != name:
            raise ValueError("ELF SONAME differs from packaged name: " + name)
        if name != "liblayanalyzer_tls.so" and "liblayanalyzer_tls.so" in lib["needed"]:
            raise ValueError("Go must be lazy-loaded, not DT_NEEDED")


def fixture_markers():
    # Check exact public test CA bytes, both DER and PEM payload. Never include
    # certificate/key contents in the report. This is not a general secret detector.
    markers = set()
    for folder in (ROOT / "native_build/verification/tls/fixtures", ROOT / "app/src/androidTest/assets/tls"):
        for pem in folder.rglob("*.pem"):
            for body in re.findall(rb"-----BEGIN CERTIFICATE-----\s*(.*?)\s*-----END CERTIFICATE-----", pem.read_bytes(), re.S):
                compact = re.sub(rb"\s", b"", body)
                markers.add(base64.b64decode(compact, validate=True))
                markers.add(compact)
                markers.add(body)
        for der in folder.rglob("*.der"):
            markers.add(der.read_bytes())
    if not markers:
        raise ValueError("public TLS fixture certificate corpus is missing")
    return markers


def scan_entry(name, data, certificates, release):
    if name.startswith(("assets/tls/", "assets/agent_golden/")) or name.endswith((".keys", ".keylog", ".jks", ".keystore", ".p12", ".pfx")):
        raise ValueError("test/secret asset in application APK: " + name)
    if any(marker in data for marker in PROBE_MARKERS):
        raise ValueError("P0 implementation marker in APK: " + name)
    if any(marker in data for marker in certificates):
        raise ValueError("known test root certificate in APK: " + name)
    if name.startswith(("assets/", "res/raw/")):
        if re.search(rb"-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----", data) or re.search(
                rb"(?m)^(?:CLIENT_RANDOM|CLIENT_TRAFFIC_SECRET_0|SERVER_TRAFFIC_SECRET_0) [0-9a-fA-F]{64} [0-9a-fA-F]+\r?$", data):
            raise ValueError("private key/keylog asset in APK: " + name)
    if release and re.fullmatch(r"classes\d*\.dex", name) and any(marker in data for marker in (
            b"Landroidx/test/", b"TlsPerformanceBenchmarkTest", b"[PERF-export]", b"perf_export")):
        raise ValueError("test/debug entry in release DEX: " + name)


def audit(args):
    release = args.variant == "release"
    enabled = args.tls == "on"
    libraries, classes, exports = {}, {}, []
    certificates = fixture_markers()
    dex_hashes = {}
    with zipfile.ZipFile(args.apk) as archive, args.apk.open("rb") as raw, tempfile.TemporaryDirectory(prefix="tls405-") as tmp:
        if len(set(archive.namelist())) != len(archive.namelist()):
            raise ValueError("duplicate ZIP entries")
        abis = {p.split("/")[1] for p in archive.namelist() if p.startswith("lib/") and p.endswith(".so")}
        if abis != {args.abi}:
            raise ValueError("APK ABI set differs from variant")
        for entry in archive.infolist():
            data = archive.read(entry)
            scan_entry(entry.filename, data, certificates, release)
            if re.fullmatch(r"classes\d*\.dex", entry.filename):
                parsed = read_dex(data)
                if classes.keys() & parsed.keys():
                    raise ValueError("duplicate DEX classes")
                classes.update(parsed)
                dex_hashes[entry.filename] = sha(data)
            if not entry.filename.startswith("lib/") or not entry.filename.endswith(".so"):
                continue
            name = Path(entry.filename).name
            loads = inspect_elf(data, args.abi)
            raw.seek(entry.header_offset + 26)
            n, e = struct.unpack("<HH", raw.read(4))
            offset = entry.header_offset + 30 + n + e
            if entry.compress_type != zipfile.ZIP_STORED or offset % 16384:
                raise ValueError("native ZIP entry is not stored/16KiB aligned: " + name)
            local = Path(tmp) / name
            local.write_bytes(data)
            dynamic = run(args.readelf, "--dynamic", "--wide", local)
            symbols = run(args.readelf, "--dyn-syms", "--wide", local)
            sections = run(args.readelf, "--sections", "--wide", local)
            defined = [p[7] for line in symbols.splitlines() if len(p := line.split()) >= 8 and p[3:6] == ["FUNC", "GLOBAL", "DEFAULT"] and p[6] != "UND"]
            exports.extend(defined)
            sonames = re.findall(r"\(SONAME\).*?\[(.*?)\]", dynamic)
            if len(sonames) != 1:
                raise ValueError("missing/duplicate ELF SONAME: " + name)
            stripped = not re.search(r"\.(?:debug_info|symtab)\s", sections)
            if release and not stripped:
                raise ValueError("release library was not stripped: " + name)
            libraries[name] = {"sha256": sha(data), "bytes": len(data), "needed": re.findall(r"\(NEEDED\).*?\[(.*?)\]", dynamic),
                               "soname": sonames[0], "loadAlignment": [s["alignment"] for s in loads],
                               "zip16KiBAligned": True, "stripped": stripped}
            if name == "libwireshark.so":
                if "layanalyzer_addr_resolv_scope_fix_v1" not in defined:
                    raise ValueError("Wireshark address-resolution lifetime fix missing from final APK")
                libraries[name]["addressResolutionLifetimeFix"] = True
            if name == "liblayanalyzer_tls.so":
                if {s for s in defined if s.startswith("la_tls_")} != GO_EXPORTS:
                    raise ValueError("final Go C ABI export set mismatch")
                if set(libraries[name]["needed"]) - PUBLIC_DEPENDENCIES:
                    raise ValueError("Go depends on a non-public runtime library")
                info = run(args.go, "version", "-m", local)
                arch = "arm64" if args.abi == "arm64-v8a" else "amd64"
                if "tlsprobe" in info or not all(v in info for v in ("go1.27.2", "-buildmode=c-shared", "GOOS=android", "CGO_ENABLED=1", "GOARCH=" + arch)):
                    raise ValueError("final Go production build metadata mismatch")
                libraries[name]["goVersion"] = "go1.27.2"
                libraries[name]["exports"] = sorted(GO_EXPORTS)
        if ("liblayanalyzer_tls.so" in libraries) != enabled:
            raise ValueError("Go packaging does not match ON/OFF")
    dependency_closure(libraries)
    if exports.count("JNI_OnLoad") != 1:
        raise ValueError("expected exactly one JNI_OnLoad")
    dex = check_dex(classes, exports, release)
    badging = run(args.aapt, "dump", "badging", args.apk)
    expected_id = "com.layeranalyzer.android" + {"release": "", "debug": ".debug", "emulator": ".emulator"}[args.variant]
    if f"package: name='{expected_id}'" not in badging or ("application-debuggable" in badging) == release:
        raise ValueError("manifest application id/debuggable mismatch")
    manifest = run(args.aapt, "dump", "xmltree", args.apk, "AndroidManifest.xml")
    if release and ("android:testOnly" in manifest or "android:networkSecurityConfig" in manifest or "TlsTunProbe" in manifest):
        raise ValueError("unexpected release test component/trust override")
    run(args.zipalign, "-c", "-P", "16", "4", args.apk)
    with args.apk.open("rb") as stream:
        apk_hash = hashlib.file_digest(stream, "sha256").hexdigest()
    with zipfile.ZipFile(args.apk) as archive:
        payload_bytes = sum(entry.compress_size for entry in archive.infolist())
    return {"schemaVersion": "tls-release-apk-v1", "status": "PASS", "apk": args.apk.name,
            "apkSha256": apk_hash, "apkBytes": args.apk.stat().st_size,
            "zipPayloadBytes": payload_bytes, "zipOverheadBytes": args.apk.stat().st_size - payload_bytes,
            "variant": args.variant, "abi": args.abi, "tlsEnabled": enabled, "libraries": libraries,
            "dependencyClosure": "PASS", "zipalign16KiB": "PASS", "dexSha256": dex_hashes, "dexContract": dex,
            "knownTestCertificateMarkers": len(certificates), "probeAndTestAssetScan": "PASS",
            "manifestApplicationId": expected_id, "runtimeSmoke": "NOT_RUN", "deviceTestsExecuted": 0}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("apk", "readelf", "aapt", "zipalign", "report"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--go", required=True)
    parser.add_argument("--abi", choices=("arm64-v8a", "x86_64"), required=True)
    parser.add_argument("--variant", choices=("debug", "emulator", "release"), required=True)
    parser.add_argument("--tls", choices=("on", "off"), required=True)
    args = parser.parse_args()
    try:
        report = audit(args)
    except (ValueError, OSError, subprocess.CalledProcessError) as error:
        report = {"schemaVersion": "tls-release-apk-v1", "status": "FAIL", "error": str(error), "deviceTestsExecuted": 0}
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f"{report['status']} {args.variant} TLS {args.tls}: {report.get('error', 'final APK audit; runtime NOT_RUN')}")
    return 0 if report["status"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())

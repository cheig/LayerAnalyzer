#!/usr/bin/env python3
"""Bind a Release runtime inventory to its TLS mode, source and actual APK bytes."""
import hashlib
from pathlib import Path
import re
import zipfile

from check_tls_dependencies import check_materials, read_json, source_inputs

ROOT = Path(__file__).resolve().parents[1]
BRIDGE = "liblayanalyzer_tls.so"


def digest(path):
    checksum = hashlib.sha256()
    with Path(path).open('rb') as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b''):
            checksum.update(chunk)
    return checksum.hexdigest()


def checked_bridge_outputs(bridge, root):
    directory = Path(root) / 'build/tls-production/release'
    manifest_path = directory / 'build-manifest.json'
    library = directory / BRIDGE
    if digest(manifest_path) != bridge['manifestSha256'] or digest(library) != bridge['librarySha256']:
        raise ValueError('TLS bridge output/manifest hashes differ from inventory')
    manifest = read_json(manifest_path)
    inputs = manifest['inputs']
    if (manifest.get('schemaVersion') != 1 or manifest.get('elfAudit') != 'PASS' or
            manifest.get('abi') != bridge['abi'] or manifest.get('goVersion') != bridge['goVersion'] or
            manifest.get('sha256') != bridge['librarySha256'] or
            inputs.get('sourceFiles') != bridge['sourceFiles'] or
            inputs.get('sourceTreeSha256') != bridge['sourceTreeSha256'] or
            inputs.get('environment', {}).get('GOTOOLCHAIN') != 'local' or
            inputs.get('environment', {}).get('GOOS') != 'android' or
            any('tlsprobe' in str(arg) for arg in inputs.get('command', []))):
        raise ValueError('TLS bridge manifest source/build mode differs from inventory')


def checked_build(inventory, root=ROOT):
    root = Path(root)
    build = inventory["build"]
    if inventory["configuration"] != "releaseRuntimeClasspath":
        raise ValueError("TLS inventory must describe releaseRuntimeClasspath")
    for flag in ("tlsEnabled", "tlsProbe"):
        if type(build.get(flag)) is not bool:
            raise ValueError("Missing/non-boolean inventory TLS flag: " + flag)
    if build["tlsProbe"]:
        raise ValueError("Release inventory must not enable the TLS probe")
    if (not build.get("abis") or len(set(build["abis"])) != len(build["abis"]) or
            set(build["abis"]) - {"arm64-v8a", "x86_64"}):
        raise ValueError("Invalid inventory ABI set")
    if "tlsBridge" not in build:
        raise ValueError("Missing inventory production bridge provenance")
    bridge = build["tlsBridge"]
    if not build["tlsEnabled"]:
        if bridge is not None:
            raise ValueError("TLS OFF inventory contains bridge provenance")
        return build
    if not isinstance(bridge, dict) or bridge.get("kind") != "production-go":
        raise ValueError("TLS ON inventory requires production bridge provenance")
    lock = read_json(root / "native_go/tlsbridge/toolchain-lock.json")
    if (bridge.get("goVersion") != lock["goVersion"] or
            build.get("ndkVersion") != lock["androidNdkVersion"] or
            bridge.get("abi") not in build["abis"] or len(build["abis"]) != 1):
        raise ValueError("TLS bridge toolchain/ABI differs from inventory or lock")
    failures = check_materials(root)
    if failures:
        raise ValueError("\n".join(failures))
    inputs = source_inputs(root)
    tree = hashlib.sha256("".join(f"{name}\0{sha}\n" for name, sha in sorted(inputs.items())).encode()).hexdigest()
    if bridge.get("sourceFiles") != inputs or bridge.get("sourceTreeSha256") != tree:
        raise ValueError("TLS bridge source provenance differs from checkout")
    for name in ("manifestSha256", "librarySha256", "packagedSha256"):
        if not re.fullmatch(r"[0-9a-f]{64}", str(bridge.get(name, ""))):
            raise ValueError("Missing/invalid TLS bridge hash: " + name)
    checked_bridge_outputs(bridge, root)
    return build


def checked_apk(inventory, apk, root=ROOT):
    build = checked_build(inventory, root)
    if build.get("apkSha256") != digest(apk):
        raise ValueError("APK bytes differ from runtime inventory (stale/wrong build)")
    with zipfile.ZipFile(apk) as archive:
        members = [n for n in archive.namelist() if n.startswith("lib/") and Path(n).name == BRIDGE]
        expected = ["lib/" + abi + "/" + BRIDGE for abi in build["abis"]] if build["tlsEnabled"] else []
        if sorted(members) != sorted(expected):
            raise ValueError("Packaged TLS bridge differs from ON/OFF inventory")
        if members and hashlib.sha256(archive.read(members[0])).hexdigest() != build["tlsBridge"]["packagedSha256"]:
            raise ValueError("Packaged TLS bridge hash differs from provenance")
    return build


def main():
    # Shared production checks, but no staging, signing or clean-checkout waiver.
    import argparse
    import json
    from stage_release import checked_apk_inputs
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--inventory', type=Path, required=True)
    parser.add_argument('--apk', type=Path, required=True)
    parser.add_argument('--report', type=Path, required=True)
    args = parser.parse_args()
    try:
        build, libraries = checked_apk_inputs(args.inventory, args.apk)
        result = dict(schemaVersion=1, status='PASS', tlsEnabled=build['tlsEnabled'],
                      tlsProbe=build['tlsProbe'], abis=build['abis'],
                      apkSha256=digest(args.apk), inventorySha256=digest(args.inventory),
                      nativeLibraries=sorted(libraries), staging='NOT_RUN')
    except (ValueError, KeyError, OSError, zipfile.BadZipFile) as error:
        result = dict(schemaVersion=1, status='FAIL', error=str(error), staging='NOT_RUN')
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(result, indent=2) + '\n', encoding='utf-8')
    print(json.dumps(result, indent=2))
    return 0 if result['status'] == 'PASS' else 1


if __name__ == '__main__':
    raise SystemExit(main())

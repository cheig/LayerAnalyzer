#!/usr/bin/env python3
"""Verify the optional TLS engine's source, Go distribution and APK notices."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "native_go/tlsbridge"
ASSETS = ROOT / "app/src/main/assets/licenses"


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def read_json(path):
    return json.loads(Path(path).read_text(encoding="utf-8"))


def json_stream(text):
    decoder = json.JSONDecoder()
    values = []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        values.append(value)
        text = text.lstrip()[end:]
    return values


def offline_env():
    env = os.environ.copy()
    env.update(GOTOOLCHAIN="local", GOENV="off", GOFLAGS="", GOWORK="off",
               GOEXPERIMENT="", GOPROXY="off", GOSUMDB="off")
    return env


def check_materials(root=ROOT):
    root = Path(root)
    inventory = read_json(root / "native_go/tlsbridge/dependencies.json")
    distribution = inventory["goDistribution"]
    failures = []
    if inventory["externalModules"]:
        failures.append("External TLS modules need a new review/checker policy")
    # This small module intentionally has no require/replace/exclude/tool/vendor
    # inputs. Resolve it with Go as well when --go or a production build is used.
    expected = f'module {inventory["module"]}\n\ngo {distribution["version"][2:]}\n'
    module = root / "native_go/tlsbridge"
    if (module / "go.mod").read_text(encoding="utf-8") != expected:
        failures.append("TLS go.mod differs from the reviewed no-external-module graph")
    if (module / "go.sum").exists() or (module / "vendor").exists():
        failures.append("Unreviewed TLS go.sum/vendor input")
    lock = read_json(root / inventory["toolchainLock"])
    if lock["goVersion"] != distribution["version"]:
        failures.append("TLS Go version differs between dependency and toolchain locks")
    review = read_json(root / "docs/dependency-licenses.json")["licenseFiles"]
    for asset, sha in ((distribution["licenseAsset"], distribution["licenseSha256"]),
                       (distribution["patentsAsset"], distribution["patentsSha256"])):
        path = root / "app/src/main/assets/licenses" / asset
        if not path.is_file() or digest(path) != sha or review.get(asset) != sha:
            failures.append("Missing/changed TLS license review: " + asset)
    return failures


def validate_modules(modules, expected):
    if (len(modules) != 1 or modules[0].get("Path") != expected or
            modules[0].get("Main") is not True or modules[0].get("Replace")):
        raise ValueError("TLS module graph contains an unreviewed dependency/replacement")


def go_output(go, args, env):
    # Go emits UTF-8 JSON, including source comments. Windows' locale may be GBK.
    return subprocess.check_output([str(go), *args], cwd=MODULE, env=env, encoding="utf-8")


def check_toolchain(go, env):
    inventory = read_json(MODULE / "dependencies.json")
    distribution = inventory["goDistribution"]
    version = go_output(go, ["version"], env).strip()
    if not version.startswith("go version " + distribution["version"] + " "):
        raise ValueError("TLS requires the exact reviewed Go version")
    goroot = Path(go_output(go, ["env", "GOROOT"], env).strip())
    for relative, sha in (("LICENSE", distribution["licenseSha256"]),
                          ("PATENTS", distribution["patentsSha256"]),
                          ("src/vendor/modules.txt", distribution["vendorModulesSha256"])):
        if digest(goroot / relative) != sha:
            raise ValueError("Unreviewed Go distribution file: " + relative)
    vendors = distribution["vendoredModules"]
    actual = re.findall(r"^# (\S+) (\S+)$", (goroot / "src/vendor/modules.txt").read_text(), re.M)
    if actual != [(v["module"], v["version"]) for v in vendors]:
        raise ValueError("Go vendored module versions differ from review")
    for vendor in vendors:
        for name, sha in (("LICENSE", distribution["licenseSha256"]),
                          ("PATENTS", distribution["patentsSha256"])):
            if digest(goroot / "src/vendor" / vendor["module"] / name) != sha:
                raise ValueError("Changed Go vendored notice: " + vendor["module"] + "/" + name)
    modules = json_stream(go_output(go, ["list", "-mod=readonly", "-m", "-json", "all"], env))
    validate_modules(modules, inventory["module"])
    return {"version": version, "goExecutableSha256": digest(go),
            "licenseSha256": distribution["licenseSha256"],
            "patentsSha256": distribution["patentsSha256"],
            "vendorModulesSha256": distribution["vendorModulesSha256"],
            "externalModules": []}


def source_inputs(root=ROOT):
    """Exact path/hash set shared by build provenance and release inventory validation."""
    root = Path(root)
    inputs = {p.relative_to(root).as_posix(): digest(p) for p in sorted((root / "native_go/tlsbridge").rglob("*"))
              if p.is_file() and (p.suffix in (".go", ".h", ".c", ".s") or
                                 p.name in ("go.mod", "dependencies.json", "toolchain-lock.json"))}
    for relative in ("native_build/scripts/build_tls_engine.py", "tools/check_tls_dependencies.py",
                     "native_build/verification/tls/audit_bridge.py"):
        inputs[relative] = digest(root / relative)
    return inputs


def build_provenance(go, env):
    failures = check_materials()
    if failures:
        raise ValueError("\n".join(failures))
    toolchain = check_toolchain(go, env)
    packages = json_stream(go_output(go, ["list", "-mod=readonly", "-deps", "-json", "./cmd/androidbridge"], env))
    local = read_json(MODULE / "dependencies.json")["module"]
    for package in packages:
        if not package.get("Standard") and package.get("Module", {}).get("Path") != local:
            raise ValueError("Unreviewed Go package: " + package["ImportPath"])
    inputs = source_inputs()
    # Hash path + file digest, independent of source/output absolute directories.
    tree = "".join(f"{name}\0{sha}\n" for name, sha in sorted(inputs.items())).encode()
    selected_vendors = sorted(p["ImportPath"] for p in packages if p["ImportPath"].startswith("vendor/"))
    return {"schema": "tls-build-inputs-v1", "toolchain": toolchain,
            "sourceTreeSha256": hashlib.sha256(tree).hexdigest(), "sourceFiles": inputs,
            "selectedGoVendorPackages": selected_vendors,
            "localPackages": sorted(p["ImportPath"] for p in packages if not p.get("Standard"))}


def check_build_info(info):
    if not info.strip():
        raise ValueError("TLS build metadata is empty")
    if not re.search(r": go1\.27\.2\s*$", info.splitlines()[0]):
        raise ValueError("Packaged TLS engine has an unreviewed Go version")
    if re.search(r"^\s*(dep|=>)\s", info, re.M):
        raise ValueError("Packaged TLS engine contains unreviewed external modules")
    if not re.search(r"^\s*path\s+com\.layeranalyzer/tlsbridge/cmd/androidbridge\s*$", info, re.M):
        raise ValueError("Packaged TLS entry point differs from review")
    if not re.search(r"^\s*mod\s+com\.layeranalyzer/tlsbridge\s+\(devel\)\s*$", info, re.M):
        raise ValueError("Packaged TLS module differs from review")
    for value in ("-buildmode=c-shared", "CGO_ENABLED=1", "GOOS=android"):
        if value not in info:
            raise ValueError("TLS build metadata missing: " + value)
    if "tlsprobe" in info:
        raise ValueError("Production TLS engine contains probe build tag")


def verify_archive(path):
    lock = read_json(MODULE / "toolchain-lock.json")
    entry = next((a for a in lock["archives"] if a["url"].rsplit("/", 1)[-1] == path.name), None)
    if entry is None or path.stat().st_size != entry["bytes"] or digest(path) != entry["sha256"]:
        raise ValueError("Go archive does not match the exact toolchain lock: " + path.name)
    return {"file": path.name, "sha256": entry["sha256"], "bytes": entry["bytes"], "status": "PASS"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--go", help="Exact Go executable; also validates installed Go notices/graph")
    parser.add_argument("--apk", type=Path, action="append", default=[])
    parser.add_argument("--expect-tls", choices=("on", "off"))
    parser.add_argument("--archive", type=Path, action="append", default=[])
    parser.add_argument("--report", type=Path, help="Write a path-free validation summary")
    args = parser.parse_args()
    failures = check_materials()
    if failures:
        raise SystemExit("\n".join(failures))
    report = {"schema": "tls-dependency-check-v1", "status": "PASS", "archives": [], "apks": []}
    env = offline_env()
    go = shutil.which(args.go or "go")
    if args.go or args.apk:
        if not go:
            raise ValueError("--go is required to validate the actual TLS build information")
        report["toolchain"] = check_toolchain(go, env)
    report["archives"] = [verify_archive(p) for p in args.archive]
    from check_runtime_licenses import check
    for apk in args.apk:
        failures = check(apk=apk)
        if failures:
            raise ValueError("\n".join(failures))
        engines = []
        with zipfile.ZipFile(apk) as archive:
            names = [n for n in archive.namelist() if n.startswith("lib/") and n.endswith(".so")]
            if any("tls_probe" in n for n in names):
                raise ValueError("Production license audit received a probe APK")
            for name in names:
                if Path(name).name != "liblayanalyzer_tls.so":
                    continue
                with tempfile.TemporaryDirectory(prefix="tls-license-") as temporary:
                    library = Path(temporary) / "liblayanalyzer_tls.so"
                    data = archive.read(name)
                    library.write_bytes(data)
                    check_build_info(go_output(go, ["version", "-m", str(library)], env))
                    engines.append({"entry": name, "sha256": hashlib.sha256(data).hexdigest(), "bytes": len(data)})
        if args.expect_tls and bool(engines) != (args.expect_tls == "on"):
            raise ValueError("APK TLS engine presence differs from --expect-tls")
        report["apks"].append({"file": apk.name, "sha256": digest(apk), "engines": engines,
                               "licenseAssets": "PASS", "status": "PASS"})
    if args.report:
        args.report.parent.mkdir(parents=True, exist_ok=True)
        args.report.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(f'PASS TLS dependencies: {len(report["archives"])} archives, {len(report["apks"])} APKs; no external Go modules')


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Install hash-locked Linux Go and verify public source/native/toolchain inputs for CI.

No candidate overlays, local fixed libraries or secret download URLs are accepted.
Failure logs/downloads remain in the new output directory; never reuse it.
"""
import argparse
import json
import os
from pathlib import Path
import platform
import re
import shutil
import sys
from urllib.parse import urlparse
from urllib.request import urlopen

from check_tls_dependencies import check_toolchain, offline_env, verify_archive
from tls_ci_toolchain import check_tools, extract_go, run_step, write_json
from check_native_source_archive import check as check_native_source
from fetch_native_deps import fetch

ROOT = Path(__file__).resolve().parents[1]


def download(entry, directory):
    url = urlparse(entry["url"])
    if url.scheme != "https" or url.username or url.password or url.query or url.fragment:
        raise ValueError("CI requires an anonymous immutable HTTPS archive URL")
    name = Path(url.path).name
    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", name):
        raise ValueError("Nonportable archive name")
    target = directory / name
    with urlopen(entry["url"], timeout=120) as response, target.open("xb") as output:
        shutil.copyfileobj(response, output)
    return target


def check_public_native(deps, sources, provenance):
    if deps.get("requiredLocalRebuild") or deps.get("localRebuild"):
        raise ValueError("R03 public repaired native pin is required; legacy bundle plus localRebuild is not a clean CI input")
    if (deps["sha256"] != sources["binaryArchiveSha256"] or
            deps["sha256"] != provenance["pinnedBinaryArchiveSha256"] or
            sources["sha256"] != provenance["sourceArchiveSha256"]):
        raise ValueError("Public native source/binary/provenance linkage differs")


def prepare(output, sdk, java_home):
    if platform.system() != "Linux" or platform.machine() != "x86_64":
        raise ValueError("TLS CI setup requires a Linux x86_64 host")
    output.mkdir(parents=True, exist_ok=False)
    report = {"schemaVersion": 1, "status": "FAIL", "steps": [],
              "commit": os.environ.get("GITHUB_SHA"), "runId": os.environ.get("GITHUB_RUN_ID")}
    try:
        lock = json.loads((ROOT / "native_build/tls-ci-toolchain.json").read_text())
        if platform.python_version() != lock["pythonVersion"]:
            raise ValueError("CI Python differs from exact reviewed version")
        env = offline_env()
        env.pop("GOROOT", None)
        check_tools(report, output, ROOT, sdk, java_home, env)
        java = (output / "java-version.log").read_text(encoding="utf-8")
        if lock["javaVersion"] not in java or "Temurin" not in java:
            raise ValueError("CI Java differs from exact reviewed Temurin build")
        go_lock = json.loads((ROOT / lock["goLock"]).read_text())
        entries = [next(a for a in go_lock["archives"] if a["url"].endswith(suffix))
                   for suffix in (".linux-amd64.tar.gz", ".src.tar.gz")]
        archives = [download(entry, output) for entry in entries]
        report["goArchives"] = [verify_archive(path) for path in archives]
        extract_go(archives[0], output)
        go = output / "go/bin/go"
        env.update(GOCACHE=str(output / "go-check-cache"), GOMODCACHE=str(output / "go-check-mod-cache"))
        report["goToolchain"] = check_toolchain(go, env)
        for name, script in (("source-check", "tools/check_source_checkout.py"),
                             ("license-check", "tools/check_runtime_licenses.py")):
            run_step(report, output, name, [sys.executable, script], ROOT, env)
        deps = json.loads((ROOT / "native_build/native-deps.json").read_text())
        sources = json.loads((ROOT / "native_build/native-sources.json").read_text())
        provenance = json.loads((ROOT / sources["verificationRecord"]).read_text())
        check_public_native(deps, sources, provenance)
        native_source = download(sources, output)
        check_native_source(native_source, sources)
        native_binary = download(deps, output)
        destination = ROOT / "app/src/main/cpp/libs"
        if destination.exists() and any(destination.rglob("*.so")):
            raise ValueError("CI checkout must not contain preinstalled application native libraries")
        fetch(deps, destination, native_binary, False)
        fetch(deps, destination, None, True)
        report["nativeInputs"] = {"binarySha256": deps["sha256"], "sourceSha256": sources["sha256"]}
        report["status"] = "PASS"
        github_env = os.environ.get("GITHUB_ENV")
        github_path = os.environ.get("GITHUB_PATH")
        if github_env and github_path:
            with open(github_env, "a", encoding="utf-8") as stream:
                for name, value in {"LAYANALYZER_CI_GO": str(go), "GOROOT": str(output / "go"),
                                    "GOTOOLCHAIN": "local", "GOENV": "off", "GOWORK": "off",
                                    "GOFLAGS": "", "GOEXPERIMENT": "", "GOPROXY": "off", "GOSUMDB": "off",
                                    "GOCACHE": str(output / "go-tests-cache"),
                                    "GOMODCACHE": str(output / "go-tests-mod-cache")}.items():
                    stream.write(f"{name}={value}\n")
            with open(github_path, "a", encoding="utf-8") as stream:
                stream.write(str(go.parent) + "\n")
        return report
    except Exception as error:
        report["error"] = str(error)
        raise
    finally:
        write_json(output / "setup-report.json", report)


def main():
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--output", required=True, type=Path)
    p.add_argument("--sdk", type=Path, default=os.environ.get("ANDROID_HOME"))
    p.add_argument("--java-home", type=Path, default=os.environ.get("JAVA_HOME"))
    args = p.parse_args()
    if not args.sdk or not args.java_home:
        p.error("ANDROID_HOME and JAVA_HOME (or explicit arguments) are required")
    prepare(args.output.resolve(), args.sdk.resolve(), args.java_home.resolve())


if __name__ == "__main__":
    main()

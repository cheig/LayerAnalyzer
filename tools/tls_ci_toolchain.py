"""Verify the Linux toolchain used by public Android CI."""
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import subprocess
import tarfile


def digest(path):
    h = hashlib.sha256()
    with Path(path).open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            h.update(block)
    return h.hexdigest()


def write_json(path, value):
    Path(path).write_text(json.dumps(value, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")


def safe_name(name):
    path = PurePosixPath(name)
    if (not name or not path.parts or "\\" in name or ":" in name or path.is_absolute() or
            ".." in path.parts or path.as_posix() != name.rstrip("/")):
        raise ValueError("Unsafe/noncanonical archive path: " + name)
    return path


def extract_go(archive, destination):
    names = set()
    with tarfile.open(archive, "r:gz") as bundle:
        for member in bundle:
            path = safe_name(member.name)
            if path.parts[0] != "go" or path.as_posix() in names or not (member.isdir() or member.isfile()):
                raise ValueError("Unsafe/nonregular Go distribution member: " + member.name)
            names.add(path.as_posix())
            target = destination / path
            if member.isdir():
                target.mkdir(parents=True, exist_ok=True)
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                with bundle.extractfile(member) as stream, target.open("wb") as output:
                    shutil.copyfileobj(stream, output)
                target.chmod(0o755 if member.mode & 0o111 else 0o644)


def run_step(report, output, name, command, cwd, env):
    log = output / (name + ".log")
    with log.open("wb") as stream:
        result = subprocess.run([str(item) for item in command], cwd=cwd, env=env,
                                stdout=stream, stderr=subprocess.STDOUT, check=False)
    report["steps"].append({"id": name, "exitCode": result.returncode,
                            "status": "PASS" if result.returncode == 0 else "FAIL",
                            "log": log.name, "command": [str(item) for item in command]})
    if result.returncode:
        raise ValueError(f"{name} failed ({result.returncode}); retained {log.name}")
    return log.read_text(encoding="utf-8")


def revision(path, expected):
    text = path.read_text(encoding="utf-8")
    if not re.search(r"^Pkg.Revision\s*=\s*" + re.escape(expected) + r"\s*$", text, re.M):
        raise ValueError("Wrong locked Android package: " + str(path))
    return digest(path)


def check_cmake_version(text):
    # Android SDK's locked cmake;3.22.1 binary includes this upstream git suffix.
    # Do not accept arbitrary suffixes or a newer patch/minor version.
    if not text.splitlines() or text.splitlines()[0] not in ("cmake version 3.22.1", "cmake version 3.22.1-g37088a8"):
        raise ValueError("Locked CMake3.22.1 (Android SDK g37088a8) required")


def check_tools(report, output, source, sdk, java_home, env):
    ndk = sdk / "ndk/27.0.12077973"
    records = {}
    for name, version in (("ndk", "27.0.12077973"), ("cmake", "3.22.1"),
                          ("build-tools", "34.0.0"), ("build-tools", "35.0.0")):
        relative = f"{name}/{version}/source.properties"
        records[relative] = revision(sdk / relative, version)
    records["platforms/android-34/source.properties"] = digest(sdk / "platforms/android-34/source.properties")
    if not re.search(r"^AndroidVersion.ApiLevel\s*=\s*34\s*$",
                     (sdk / "platforms/android-34/source.properties").read_text(), re.M):
        raise ValueError("SDK34 platform required")
    tools = {"java": java_home / "bin/java", "javac": java_home / "bin/javac",
             "cmake": sdk / "cmake/3.22.1/bin/cmake",
             "clang": ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/clang",
             "readelf": ndk / "toolchains/llvm/prebuilt/linux-x86_64/bin/llvm-readelf"}
    for version in ("34.0.0", "35.0.0"):
        for name in ("zipalign", "apksigner"):
            tools[f"{name}-{version}"] = sdk / f"build-tools/{version}/{name}"
    for name, tool in tools.items():
        if not tool.is_file() or not os.access(tool, os.X_OK):
            raise ValueError("Missing Linux host tool: " + name)
        if name not in ("java", "javac", "apksigner-34.0.0", "apksigner-35.0.0") and tool.read_bytes()[:4] != b"\x7fELF":
            raise ValueError("Non-Linux executable: " + name)
    java = run_step(report, output, "java-version", [tools["java"], "-version"], source, env)
    javac = run_step(report, output, "javac-version", [tools["javac"], "-version"], source, env)
    if not re.search(r'version "17(?:\.|\")', java) or not javac.startswith("javac 17"):
        raise ValueError("JDK17 required; tool upgrades need separate review")
    cmake = run_step(report, output, "cmake-version", [tools["cmake"], "--version"], source, env)
    clang = run_step(report, output, "clang-version", [tools["clang"], "--version"], source, env)
    check_cmake_version(cmake)
    if "clang version 18.0.1" not in clang:
        raise ValueError("Locked Clang18.0.1 required")
    report["androidTools"] = {"packageProperties": records,
                               "executables": {name: digest(tool) for name, tool in tools.items()}}
    return ndk

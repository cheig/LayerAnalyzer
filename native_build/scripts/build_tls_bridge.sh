#!/usr/bin/env bash
# P0 only: builds a tlsprobe-tagged Go c-shared library into an explicit directory.
set -euo pipefail

usage() {
    echo "Usage: $0 --ndk DIR --abi arm64-v8a|x86_64 --output DIR [--go EXECUTABLE] [--python EXECUTABLE]"
    echo "Requires Go 1.27.2, NDK 27.0.12077973; Android API is fixed at 26."
}
fail() { echo "TLS bridge build: $*" >&2; exit 2; }
ndk= abi= output= go_bin=go python_bin=python3
while (($#)); do
    case "$1" in
        --ndk|--abi|--output|--go|--python)
            (($# >= 2)) && [[ -n "$2" && "$2" != --* ]] || fail "missing value for $1"
            case "$1" in
                --ndk) ndk=$2 ;; --abi) abi=$2 ;; --output) output=$2 ;;
                --go) go_bin=$2 ;; --python) python_bin=$2 ;;
            esac
            shift 2 ;;
        --help|-h) usage; exit 0 ;;
        *) fail "unknown option: $1" ;;
    esac
done
[[ -n "$ndk" && -n "$abi" && -n "$output" ]] || { usage >&2; exit 2; }
case "$abi" in
    arm64-v8a) go_arch=arm64; target=aarch64-linux-android26 ;;
    x86_64) go_arch=amd64; target=x86_64-linux-android26 ;;
    *) fail "unsupported ABI: $abi" ;;
esac
[[ -d "$ndk" && -f "$ndk/source.properties" ]] || fail "NDK directory is missing or invalid"
ndk=$(cd "$ndk" && pwd -P)
ndk_version=$(sed -n 's/^Pkg.Revision[[:space:]]*=[[:space:]]*//p' "$ndk/source.properties" | tr -d '\r')
[[ "$ndk_version" == 27.0.12077973 ]] || fail "expected NDK 27.0.12077973, got $ndk_version"
case "$(uname -s)" in
    Linux) host=linux-x86_64; exe= ;;
    MINGW*|MSYS*) host=windows-x86_64; exe=.exe ;;
    *) fail "supported hosts: Linux/WSL or Git Bash on Windows" ;;
esac
compiler="$ndk/toolchains/llvm/prebuilt/$host/bin/clang$exe"
readelf="$ndk/toolchains/llvm/prebuilt/$host/bin/llvm-readelf$exe"
[[ -x "$compiler" && -x "$readelf" ]] || fail "NDK host compiler/readelf not found for $host"
export GOTOOLCHAIN=local
[[ "$("$go_bin" version)" == "go version go1.27.2 "* ]] || fail "Go 1.27.2 is required; automatic toolchain downloads are disabled"
repo=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd -P)
command -v "$python_bin" >/dev/null || fail "Python 3 is required for ELF auditing"
# Resolve symlinks and reject app/ or source directories before creating output.
"$python_bin" - "$repo" "$output" <<'PY'
from pathlib import Path
import sys
repo, out = (Path(p).resolve() for p in sys.argv[1:])
if out == repo or repo.is_relative_to(out) or any(
    out == repo / part or (repo / part) in out.parents
    for part in ('app', 'native_go', 'docs', 'native_build/scripts', 'native_build/verification')
):
    raise SystemExit('output must be a separate build directory, outside application/source trees')
out.mkdir(parents=True, exist_ok=True)
PY
output=$(cd "$output" && pwd -P)
# Windows Go/Python are native executables; normalize command argument paths.
if [[ "$host" == windows-x86_64 ]]; then
    compiler=$(cygpath -m "$compiler")
    readelf=$(cygpath -m "$readelf")
    output=$(cygpath -m "$output")
fi
export CGO_ENABLED=1 GOOS=android GOARCH="$go_arch"
export GOENV=off GOFLAGS= GOWORK=off GOEXPERIMENT=
export CC="\"$compiler\" --target=$target"
export CGO_CFLAGS="-O2 -g -fPIC" CGO_CPPFLAGS= CGO_CXXFLAGS= CGO_LDFLAGS=
export GOCACHE="$output/go-cache"
library="$output/liblayanalyzer_tls_probe.so"
link_flags='-linkmode=external -extldflags=-Wl,-z,max-page-size=16384,-z,common-page-size=16384,-soname,liblayanalyzer_tls_probe.so'
cd "$repo/native_go/tlsbridge"
echo "Building TLS P0 probe: go1.27.2, $abi, Android API26, NDK $ndk_version ($host)"
"$go_bin" build -trimpath -buildvcs=false -tags=tlsprobe -buildmode=c-shared \
    -ldflags="$link_flags" -o "$library" ./cmd/androidbridge
cp cmd/androidbridge/tls_probe.h "$output/tls_probe.h"
"$python_bin" "$repo/native_build/verification/tls/audit_bridge.py" \
    --library "$library" --abi "$abi" --readelf "$readelf" \
    --go "$go_bin" --host "$host" --manifest "$output/build-manifest.json"

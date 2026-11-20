# TLS engine source and rebuild material

The runtime is original LayerAnalyzer code under the repository's GPL-3.0
license, plus the unmodified Go **1.27.2** runtime/standard library under
BSD-3-Clause. [dependencies.json](dependencies.json) is the reviewed inventory.
go-mitmproxy/mitmproxy are design references with fixed research commits, not
copied implementations or runtime dependencies. No MIT proxy fork/patch set
exists. HEV and its nested dependencies retain their existing exact revisions
and original MIT/BSD texts in [THIRD_PARTY_NOTICES.md](../../THIRD_PARTY_NOTICES.md).
TLS work did not modify their vendored sources. Go TLS/X.509 supplies the
cryptography; no new OpenSSL, BoringSSL or Conscrypt binary is bundled.

Go's own `src/vendor` packages do not appear in the application's module graph
or require a `go.sum`. Their exact versions are in the inventory, pinned by
the complete Go archive checksum and `src/vendor/modules.txt` hash. Each has
the same unmodified LICENSE/PATENTS bytes as Go. Both texts are distributed
in `assets/licenses/` and readable in the existing offline notices dialog.
Compiler-only `src/cmd/vendor` dependencies are not APK runtime modules. New
modules, copied code, toolchain updates and license edits require a new review;
the checker fails rather than automatically changing the inventory.

## Obtain the exact inputs

Use the source checkout/archive from the **same application commit** as the
binary. Include `native_go/tlsbridge/`, build/audit scripts, `tools/`, the
reviewed licenses and manifests. The new Go library is not part of the nine
projects in `native_build/native-sources.json` or the pinned Wireshark binary
bundle. Those archives and their existing provenance remain separate.

| Input | Exact selection / source |
|---|---|
| Go host toolchain | Go 1.27.2 Windows amd64 or Linux amd64 archive in [toolchain-lock.json](toolchain-lock.json), with mandatory SHA-256 and byte count |
| Go source | `https://go.dev/dl/go1.27.2.src.tar.gz`, SHA-256 `03495da2ba64894d40f5c4992e49454fa78b50690604ff92b6afff5081b76e62`, 35,134,614 bytes; tag `go1.27.2`, no local patches |
| Android NDK | r27 `27.0.12077973`, SDK Manager package `ndk;27.0.12077973`; clang 18.0.1, Windows/Linux x86_64 host binaries |
| Python | Python 3.10+; checker uses only the standard library |
| Targets | API 26; arm64-v8a → `aarch64-linux-android26`; x86_64 → `x86_64-linux-android26` |

Extract the host archive into a fresh directory, retaining its sources and
notices. The official host distribution includes runtime/library sources; the
separate source archive is pinned for source delivery. Validate downloads:

```powershell
python tools/check_tls_dependencies.py --archive build/tools/go1.27.2.windows-amd64.zip --archive build/tools/go1.27.2.src.tar.gz
python tools/check_tls_dependencies.py --go build/tools/go/bin/go.exe
python tools/check_source_checkout.py
```

Linux uses the locked `go1.27.2.linux-amd64.tar.gz` and `bin/go`. Installed Go's
LICENSE, PATENTS, vendor module list and each vendored license/grant are checked.
Archive verification separately authenticates the complete downloaded bytes
against the lock. This does not rebuild Go's compiler from bootstrap sources.

## Independently build the production library

From a fresh source checkout/export, use empty output directories and your own
tool paths. No Gradle or Wireshark prebuilt library is needed for this build:

```powershell
$tlsGo = (Resolve-Path build/tools/go/bin/go.exe).Path
$tlsNdk = Join-Path $env:ANDROID_HOME 'ndk/27.0.12077973'
python native_build/scripts/build_tls_engine.py --ndk $tlsNdk --abi arm64-v8a --go $tlsGo --output build/tls-rebuild/arm64-v8a
python native_build/scripts/build_tls_engine.py --ndk $tlsNdk --abi x86_64 --go $tlsGo --output build/tls-rebuild/x86_64
```

Linux/WSL uses **Linux** Go and NDK binaries:

```bash
python3 native_build/scripts/build_tls_engine.py \
  --ndk "$ANDROID_NDK_HOME" --abi arm64-v8a --go "$TLS_GO" \
  --output build/tls-rebuild/arm64-v8a
python3 native_build/scripts/build_tls_engine.py \
  --ndk "$ANDROID_NDK_HOME" --abi x86_64 --go "$TLS_GO" \
  --output build/tls-rebuild/x86_64
```

Production disables module downloads: `GOTOOLCHAIN=local`, `GOWORK=off`,
`GOENV=off`, `GOPROXY=off`, `GOSUMDB=off`, cleared GOFLAGS/GOEXPERIMENT and
`-mod=readonly`. Each output has isolated `go-cache`/`go-mod-cache` directories.
It uses `-trimpath -buildvcs=false -buildmode=c-shared`, no `tlsprobe` tag,
NDK external linking, 16KiB max/common page sizes and the fixed SONAME
`liblayanalyzer_tls.so`.

Only after checking the actual ELF architecture, LOADs, public dependencies,
SONAME, ABI exports, production metadata and module graph does the builder
emit `build-manifest.json`. The output also contains the `.so`, cgo-generated
header and public `la_tls_bridge.h`; only the `.so` is staged in an ON APK.
The manifest records the library hash/size and relative source paths with
per-file SHA-256, a sorted path+digest tree hash, Go executable and NDK tool
hashes, NDK source.properties hash, Python version, sanitized command/environment,
and selected local and standard-library vendor packages. The source inventory
includes module tests/probes for source delivery, even though production excludes
them. Build manifests contain no absolute local paths or private material.

Identify a build by its application commit and these input hashes; a tree hash
does not replace complete source or a signature. Different host compilers may
produce different output bytes; cross-host bit-identical builds are not promised.
Gradle strips release libraries, so record final APK entry hashes separately
from the unstripped independent build. Keep manifests with release evidence.

## Check the actual package

Use the existing JDK17/Gradle8.6/AGP8.4.1 and SDK setup. Debug/release stay
arm64-v8a and emulator stays x86_64. From the repository root:

```powershell
.\gradlew.bat -I tools/runtime_license_inventory.init.gradle assembleRelease :app:exportRuntimeLicenseInventory "-PlayanalyzerTlsGo=$tlsGo" --offline

python tools/check_runtime_licenses.py --inventory build/license-audit/releaseRuntimeClasspath.json --apk app/build/outputs/apk/release/app-release-unsigned.apk
python tools/check_tls_dependencies.py --go $tlsGo --expect-tls on --apk app/build/outputs/apk/release/app-release-unsigned.apk --report build/tls-rebuild/apk-licenses.json
```

Use the actual signed/unsigned filename. `--offline` requires cached Android
dependencies. For OFF build with `-PlayanalyzerEnableTls=false` and check with
`--expect-tls off`. Extra Go notices in OFF APKs are intentional. These checks
compare actual APK license bytes and Go build info, rejecting external modules,
wrong Go version/module/entry point, probe tags and wrong engine presence.
They do not replace TLS-405's DEX/ELF closure, signing, secrets or device checks.

`tools/stage_release.py` now validates explicit ON/OFF library sets using a newly
exported runtime inventory: ON requires `liblayanalyzer_tls.so` and OFF excludes it.
Unknown libraries are rejected. See [release packaging](../../docs/release-packaging.md). Keep toolchains, signing keys, capture secrets and generated libraries out of Git.

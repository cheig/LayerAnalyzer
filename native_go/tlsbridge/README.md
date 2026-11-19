# TLS bridge

Distribution inventory, offline licenses, independent production rebuild commands
and source/artifact hashes: [REBUILD.md](REBUILD.md) and
[dependencies.json](dependencies.json). go-mitmproxy/mitmproxy are research
references only; no third-party proxy source or external Go modules are used.

## Production ABI

[include/la_tls_bridge.h](include/la_tls_bridge.h) is the production C ABI v1.
It is separate from the debug probe ABI. Build without `tlsprobe` to produce
`liblayanalyzer_tls.so`; it has no fixed fixture CA, automatic listener, or
default platform/DNS fallback. The production manager is assembled by
`internal/engine/assembly`: a start builds the run — CA-backed leaf
store, protected dialer, secret sink, connection pipeline and authenticated
gateway — and opens exactly one loopback listener, whose port and token it
returns. A start whose frozen policy is missing or disabled returns `NOT_READY`
and opens nothing, so a capture that could only forward traffic never announces
readiness. Loading the library, querying capabilities and stopping a stopped
engine all still create no listener, worker or CA.

The `layanalyzerEnableTls` Gradle property defaults to **true**, as does CMake
`LAYANALYZER_ENABLE_TLS`. OFF APKs do not contain the Go library and return
`UNSUPPORTED` from all five production JNI methods. ON capability queries do
not load Go; only an explicit start request loads the fixed library name.
Active proxying remains off until the user enables it. OFF builds are for
development checks only. P0 probes remain isolated test interfaces.

```powershell
.\gradlew.bat assembleDebug assembleEmulator -PlayanalyzerEnableTls=true '-PlayanalyzerTlsGo=<absolute Go 1.27.2 executable>'
.\gradlew.bat assembleDebug assembleEmulator -PlayanalyzerEnableTls=false
```

`layanalyzerTlsPython` optionally selects Python (defaults to python on Windows,
python3 elsewhere). ON builds invoke `native_build/scripts/build_tls_engine.py`
for the variant's existing ABI and audit the generated ELF before packaging.
debug/release remain arm64-v8a, emulator remains x86_64. Outputs and manifests
stay in ignored `build/tls-production/<variant>`, without modifying bundled libs.
The script also accepts explicit `--ndk`, `--abi`, `--go`, `--output` on Linux.

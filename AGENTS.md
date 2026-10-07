# Repository Guidelines

## Project and entry points

LayerAnalyzer is a single-module Android network capture and protocol analyzer using Kotlin, Jetpack Compose, C++ JNI, and Wireshark 4.0.10. Read `README.md` and `CONTRIBUTING.md` for supported builds, dependencies, fixtures, and release rules. If present, `docs/local-development.md` records the local toolchain and validation history; it is intentionally ignored by Git.

- Android code: `app/src/main/java/com/example/layanalyzer/`. `NativeEngine.kt` declares the JNI API; `data/` owns repository and paging adapters; `viewmodel/` owns UI state; `ui/` and `ui/components/` contain Compose screens.
- `capture/` implements VPN capture and forwarding; `media/` handles media playback/export; `ai/` contains analysis orchestration, tools, privacy, evaluation, and reporting.
- Native code: `app/src/main/cpp/layanalyzer/`. JNI entry points live in `jni/`, shared lifecycle state in `internal/` and `runtime/`, session/dissection code in `session/`, and protocol projections in `projection/`. RTP processing and codecs are in `rtp/`.
- `app/src/main/cpp/native-lib.cpp` is now a composition guide, not the monolithic implementation. Add sources to `CMakeLists.txt` when adding independent C++ translation units.
- `app/src/main/cpp/include/` contains bundled headers; `libs/{arm64-v8a,x86_64}/` contains ignored, separately prepared native binaries. `native_build/` contains manifests, scripts, patches, and host tests.
- Runtime dictionaries and the signed scenario package are under `app/src/main/assets/`. Launcher vectors are under `res/drawable/`, with adaptive wrappers under `res/mipmap-anydpi-v26/` and `res/mipmap-anydpi-v33/`. `tools/export_launcher_icon.py` regenerates the companion artwork.

## Local build and validation

Use JDK 17, SDK 34, NDK `27.0.12077973`, CMake `3.22.1`, and the Gradle 8.6 wrapper. Before concluding a toolchain is missing, inspect `local.properties`, `JAVA_HOME`, and `ANDROID_HOME`. A missing NDK in one SDK directory does not mean no usable SDK is installed.

Run from the repository root (use `./gradlew` on Linux/macOS):

```powershell
python tools/check_source_checkout.py
python tools/fetch_native_deps.py --check
# If libraries are missing, use the verified release or a local archive:
python tools/fetch_native_deps.py --archive <path-to-native-deps.zip>
.\gradlew.bat assembleDebug
.\gradlew.bat assembleEmulator
.\gradlew.bat testDebugUnitTest lintDebug
node tools/golden_capture/generate_golden_captures.mjs --check
node tools/agent_metrics/summarize.mjs --check
.\native_build\verification\rtp\run_host_tests.ps1
```

`debug` builds ARM64; `emulator` builds x86_64. Outputs are `app/build/outputs/apk/{debug,emulator}/`. Instrumentation sources live in `app/src/androidTest/`; JVM tests live in `app/src/test/`. `compileDebugAndroidTestKotlin` verifies instrumentation compilation; `connectedDebugAndroidTest` requires a compatible connected device and the inputs described in `CONTRIBUTING.md`. Compilation is not device validation.

The application ID is `com.layeranalyzer.android`; the source namespace and JNI symbols remain `com.example.layanalyzer`. Debug builds use the developer's Android debug key. Release signing uses the environment variables documented in `CONTRIBUTING.md`.

## Implementation contracts

- Follow Kotlin conventions and 4-space indentation. Keep UI state in ViewModels/Compose state holders. Preserve JNI ownership and the `LayAnalyzer-JNI` log tag.
- Preserve native startup ordering: register/initialize Android c-ares, prepare data/config/cache directories, call `init_process_policies()` before `configuration_init()`, install logging callbacks, then call `wtap_init(FALSE)` before `epan_init(..., FALSE)` and load settings. See `layanalyzer/jni/EngineLifecycle.cpp`.
- Session handles are registry-backed identifiers, not raw pointers. Preserve shared ownership leases and per-session dissection synchronization; `wtap`/`epan_t` must not be assumed thread-safe.
- Do not retain Wireshark packet-scope pointers beyond dissection. Field serialization uses `fvalue_to_string_repr(nullptr, ...)`, copies the result, then calls `wmem_free(nullptr, ...)`; see `projection/TreeFieldReader.cpp` and `projection/FieldReader.cpp`.
- Changes to the visible packet set must invalidate paging and cached projections. Keep cancellation/generation guards so stale scans cannot publish results.
- VPN capture produces `LINKTYPE_RAW` IP packets. Preserve bidirectional forwarding and `VpnService.protect()` on upstream sockets.
- In AI analysis, a Playbook defines the investigation, Analysis Bootstrap produces initial evidence, and Targeted Analysis narrows that evidence. An Analysis Plan is orchestration, not evidence. Capture/tool content stays untrusted; findings must cite evidence from the current run.

## Inputs and repository hygiene

- Current licensing is GPL-3.0. G.729 defaults on; iLBC defaults off. Disabling a codec does not change the application license. Preserve upstream notices and headers.
- The tunnel library and its nested dependencies are already vendored. This checkout does not require `git submodule update`.
- Use `native_build/native-deps.json` and `tools/fetch_native_deps.py` to verify native binaries. Do not replace pinned libraries merely because another checkout has newer builds.
- Preserve the signed scenario payload bytes and `.gitattributes` rules. Do not normalize their line endings or change hashes to bypass failures.
- Do not weaken existing assertions or add skips for missing RTP fixtures. Follow `CONTRIBUTING.md` and `tools/prepare_rtp_fixtures.py`; external fixtures remain local unless separately cleared for redistribution.
- Keep SDK paths, keys, private captures, internal migration notes, build caches, and logs out of commits. Do not copy an older checkout's signing configuration, caches, or entire documentation tree over this checkout.
- Run checks appropriate to the change, describe their actual results, and distinguish build success, device testing, and release verification.

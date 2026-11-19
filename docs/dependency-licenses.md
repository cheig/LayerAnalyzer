# Android runtime license review

The reviewed `releaseRuntimeClasspath` contains **126 components**, of which
**96 have JAR/AAR artifacts**. The other 30 are BOMs or multiplatform metadata
redirects. [dependency-licenses.json](dependency-licenses.json) records the exact
coordinates, artifact SHA-256 values, license identifiers, and version-specific
POM/source evidence. The complete coordinate table is also in
[THIRD_PARTY_NOTICES.md](../THIRD_PARTY_NOTICES.md).

This review covers the resolved Release classpath before R8 removes unused code.
It does not infer that every class reaches the final DEX. Test dependencies and
debug-only Compose tooling are outside this Release inventory. Updating a
dependency requires a new review, including its transitive dependencies.

## Review results

| Components | License and retained notices | Evidence reviewed |
|---|---|---|
| AndroidX, Compose and Material Components | Apache-2.0; source copyright attributions in `Android-runtime-NOTICES.txt` | Exact-version Google Maven POMs, AAR/JAR contents (including nested JARs), and published source JARs |
| ConstraintLayout and constraintlayout-solver 2.0.1 | Apache-2.0, Android Open Source Project attribution | Published POMs and binaries; Google Maven source JAR URLs return 404, so source headers were checked at the upstream `2.0.1` tag instead |
| Guava listenablefuture 1.0 | Apache-2.0, The Guava Authors | Source JAR, POM and inherited `guava-parent:26.0-android` license; upstream `v26.0/COPYING` |
| Error Prone annotations 2.15.0 | Apache-2.0, The Error Prone Authors | POM, source JAR, parent POM and upstream `v2.15.0/COPYING` |
| JetBrains annotations 23.0.0 | Apache-2.0, JetBrains | POM, source JAR and `23.0.0/LICENSE.txt` |
| Kotlin stdlib 1.9.23; stdlib-jdk7 and stdlib-jdk8 1.9.10 | Apache-2.0; BSL-1.0 for Boost-derived JVM math; `Kotlin-COPYRIGHT.txt` | POMs, source JARs, both tags' `license/` directories and third-party mapping |
| kotlinx.coroutines 1.7.3 | Apache-2.0; complete `kotlinx-coroutines-NOTICE.txt` | POMs, source JARs, `1.7.3/LICENSE.txt` and `1.7.3/license/NOTICE.txt` |
| OkHttp 4.12.0 | Apache-2.0; Public Suffix List data is MPL-2.0, with original `OkHttp-publicsuffix-NOTICE.txt` and full MPL text | POM, binary/source JARs, `parent-4.12.0/LICENSE.txt` and the unmodified publicsuffix resource/NOTICE |
| Okio JVM 3.6.0 | Apache-2.0, Square and ASF-derived source attribution | POMs, JAR/source JAR and `parent-3.6.0/LICENSE.txt` |
| commonmark-java 0.22.0 | BSD-2-Clause, Atlassian | Binary/source JAR `META-INF/LICENSE.txt` and parent POM; existing notice retained, plus a byte-identical standalone license asset |

The review looked for LICENSE, COPYRIGHT and NOTICE files in the distributed
artifacts and their source archives. The reviewed AndroidX distributions do not contain
a separate NOTICE; their POM declarations and source copyright/license headers
were checked instead. The non-AndroidX upstream license locations listed above
were also checked. A missing NOTICE in one archive is not a claim that every
Apache-licensed project has no NOTICE.

Kotlin's upstream `license/NOTICE.txt` explicitly concerns the **compiler
distribution**. That compiler is a build tool, not an APK runtime library, so the
compiler notice and compiler/plugin/test-only licenses are not attributed to the
Android runtime. The identical `COPYRIGHT.txt` from v1.9.23 and v1.9.10 is retained.
The stdlib attribution additionally covers GWT-derived collections,
Guava-derived unsigned utilities, and Boost-derived `MathJVM.kt`. Full BSL-1.0 is
included even though its object-code exception permits omitting it from binaries.

Apache Harmony-derived headers in AndroidX multidex, OkHttp and Okio are retained
as ASF attributions. Compose `FastFloatParser.kt` credits the Apache-licensed
fast_float and fast_double_parser implementations. OkHttp's Public Suffix List
notice is copied unchanged; the MPL license is not replaced by OkHttp's Apache
license.

## TLS-406 runtime inventory refresh (2026-10-16)

The real release resolution had advanced beyond the old 123-component review.
This review follows the existing build; no dependency version was changed.
42 current coordinates needed new version evidence: annotation-experimental
1.4.1, collection 1.4.4, Compose 1.7.5/BOM 2024.10.01, Material3 1.3.1,
graphics-path 1.0.1 and lifecycle-runtime-compose 2.8.7. All exact POMs declare
Apache-2.0. The 22 artifact-bearing coordinates also have source-JAR evidence;
collection-ktx's source JAR is intentionally empty (manifest only). Source
copyright statements, including 2024 AOSP and JetBrains notices, are retained
in `Android-runtime-NOTICES.txt` and both main notice documents. Files named
`Copyright.kt` are Material icons, not extra license texts; no separate NOTICE
was found in these source JARs. Complete Apache-2.0 remains bundled.

The graphics-path AAR also contains `libandroidx.graphics.path.so`, which was
already packaged before TLS-406. Native C++ review uses revision
`8a05a22af450d589ef911d772a001a49dcb05b71` linked by the official 1.0.1
release notes, rather than a moving branch. All implementation headers use
Apache-2.0, including AOSP/Filament math attributions; the CMake file and export
map have no separate notice. The manifest records exact POM/source-JAR and
native-source hashes. This is an upstream AAR, not another Wireshark prebuilt
or a new local native fork. No bit-identical native reconstruction is claimed.

## Native notice corrections

TLS-201 adds an optional Go **1.27.2** runtime/standard-library binary,
`liblayanalyzer_tls.so`, outside the Gradle JVM classpath inventory above.
Its pinned toolchain archives and hashes are in
[`native_go/tlsbridge/toolchain-lock.json`](../native_go/tlsbridge/toolchain-lock.json).
The official toolchain's BSD-3-Clause `LICENSE` is copied unchanged to
`app/src/main/assets/licenses/Go.txt` and is available in the existing offline
license reader. There are no third-party Go module dependencies or copied
proxy implementations. TLS builds default ON; the notice may remain present
in OFF APKs. TLS-406 also retains the unmodified Go `PATENTS` as
`Go-PATENTS.txt`; both assets are now hash-checked in the reviewed manifest.
Go's internal vendored `golang.org/x/{crypto,net,sys,text}` versions and
identical BSD/patent texts are checked against
`native_go/tlsbridge/dependencies.json`. They belong to the Go distribution,
outside Gradle's 126-component inventory. Exact source/host archive checksums,
an independent rebuild, and source-to-artifact provenance are described in
[the TLS rebuild guide](../native_go/tlsbridge/REBUILD.md).
`tools/check_runtime_licenses.py` also checks the TLS source inventory and fails
when an unreviewed module, vendor tree or license change is introduced.

The existing GPL/LGPL, commonmark BSD, and native license texts remain intact.
The following supplemental notices are included in the same offline reader:

| Material | Review and resulting asset |
|---|---|
| nlohmann/json 3.11.3 | The upstream `LICENSE.MIT` itself says 2013–2022 and is unchanged. `nlohmann-json-copyrights.txt` retains all five distinct SPDX copyright statements from the bundled header, including its 2013–2023 statement and the credited Abseil helper. |
| libyaml 0.2.5 / hev build wrapper | All eight vendored C files match upstream 0.2.5 after line-ending comparison. `libyaml-upstream.txt` and vendored `UPSTREAM-LICENSE` preserve Ingy döt Net and Kirill Simonov's original MIT text. The existing hev MIT license remains separate. |
| lwIP vendored revision `8c69dfbe537835d5f2a5fd8c08c859f667b108ea` | `lwip.txt` is unchanged. `lwip-source-notices.txt` retains the 100 distinct copyright/license comment blocks and their source paths, including notices for optional and platform-specific code. This does not assert that PPP or every other optional feature is enabled. |
| NDK 27.0.12077973 runtime | `NDK-runtime.txt` includes complete compiler-rt, libc++, libc++abi and libunwind license texts, LLVM exceptions, legacy MIT/NCSA texts and available CREDITS.TXT files. Source revision is `3c92011b600bdf70424e2547594dd461fe411a41`, from the installed NDK's `clang_source_info.md` (LLVM 18.0.1 / r522817). The first three license texts also match byte sequences in its bundled toolchain NOTICE; libunwind's text comes from that exact source revision. |

These additions are a notice review. They do not establish the build provenance
or complete corresponding-source delivery of the nine pinned native projects.
The limitations in `native_build/native-sources.json` still apply. Source
availability and final distribution checks remain separate release work.

## Packaging and offline reading

The official English Apache-2.0 text was obtained from
<https://www.apache.org/licenses/LICENSE-2.0.txt>. Its complete bytes are retained
in `app/src/main/assets/licenses/Apache-2.0.txt`, and the full text is appended to
both copies of THIRD_PARTY_NOTICES. The two notice files are byte-identical.

The existing Gradle exclusion of `META-INF/{AL2.0,LGPL2.1}` is retained. Explicit
license assets supply the full texts instead of relying on transitive JAR
resource packaging. No new dependency or license plugin is used. LayerAnalyzer
remains GPL-3.0; G.729 and iLBC defaults are unchanged.

The existing Third-party notices dialog reads the notice document and every
`assets/licenses/*.txt` file as UTF-8, without network access. It skips license
texts already included verbatim in the main document and renders paragraphs in
a lazy list, allowing long legal texts to be read without a single oversized
text layout. The asset byte hashes are preserved across Git checkouts by
explicit `.gitattributes` rules.

## Rechecking a build

From the repository root (use `./gradlew` on Linux/macOS):

```powershell
python tools/check_source_checkout.py
.\gradlew.bat -I tools/runtime_license_inventory.init.gradle :app:exportRuntimeLicenseInventory --console=plain
python tools/check_runtime_licenses.py --inventory build/license-audit/releaseRuntimeClasspath.json
.\gradlew.bat assembleRelease
python tools/check_runtime_licenses.py --inventory build/license-audit/releaseRuntimeClasspath.json --apk app/build/outputs/apk/release/app-release.apk
```

Without release signing configured, Gradle may name the output
`app-release-unsigned.apk`; pass that actual path to the check. The APK check
compares every reviewed license asset, both the main notice and Wireshark's
COPYING with the source bytes. It does not verify APK signing or device behavior.
Use `--offline` for Gradle only when the dependencies are already cached.

The source check verifies notice parity, reviewed license hashes and embedded
full texts. The inventory check additionally fails if a resolved component,
version or artifact hash differs from the review. Neither command updates the
review automatically. To update it, inspect exact-version upstream license and
notice evidence, preserve required texts, update the manifest/table, rebuild,
inspect the APK and verify the offline reader on Android.

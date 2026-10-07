# LayerAnalyzer Third-Party Notices

LayerAnalyzer is distributed under the GNU General Public License, version 3
(GPL-3.0). The complete application license is in the repository-root LICENSE.
G.729 decoding through bcg729 is enabled by default. Disabling a codec does not
change the application license. Dependencies retain their individual licenses.

This file is identical to the notices shipped in the application at
app/src/main/assets/THIRD_PARTY_NOTICES.txt. Upstream copyright headers and
license texts are retained with the vendored source and runtime data.

## LayerAnalyzer authorship

Original LayerAnalyzer code: Copyright (c) 2026 cheig.
Original author and maintainer: cheig (https://github.com/cheig).
Upstream project: https://github.com/cheig/LayerAnalyzer

This attribution covers original LayerAnalyzer code authored by cheig. Other
contributors and third-party authors retain copyright in their respective work.
The project authorship notice does not replace the component notices below.

## Components

| Component | Licence | Upstream source | In this repository |
|---|---|---|---|
| Wireshark 4.0.10 (wiretap, epan, wsutil) | GPL-2.0-or-later | https://www.wireshark.org/download/src/ | Pinned external native bundle; engine data files and `wireshark-data/COPYING` under `app/src/main/assets/` |
| GLib (glib, gobject, gmodule, gthread) | LGPL-2.1-or-later | https://download.gnome.org/sources/glib/ | Source included in the native source archive; inputs under `native_build/external/`, built by `native_build/scripts/build_glib.sh` |
| libgcrypt and libgpg-error | LGPL-2.1-or-later, with separately identified GPL components | https://gnupg.org/software/ | Source included in the native source archive; built by `native_build/scripts/build_gcrypt.sh` |
| c-ares | MIT | https://c-ares.org/ | Source included in the native source archive; built by `native_build/scripts/build_c_ares.sh` |
| libffi | MIT | https://github.com/libffi/libffi | Included in the corresponding native source archive; built by `native_build/scripts/build_all.sh` |
| PCRE2 | 3-clause BSD | https://github.com/PCRE2Project/pcre2 | Included in the corresponding native source archive; built by `native_build/scripts/build_all.sh` |
| zlib | zlib licence | https://zlib.net/ | Included in the corresponding native source archive; built by `native_build/scripts/build_all.sh` |
| GNU libiconv | LGPL-2.1-or-later | https://www.gnu.org/software/libiconv/ | Included in the corresponding native source archive; built by `native_build/scripts/build_all.sh` |
| nlohmann/json 3.11.3 | MIT (with credited Apache-2.0 helper) | https://github.com/nlohmann/json | Vendored header at `app/src/main/cpp/include/nlohmann/json.hpp` |
| hev-socks5-tunnel and hev-task-system | MIT | https://github.com/heiher/hev-socks5-tunnel | Vendored source and licence files (including expanded nested submodules) under `app/src/main/cpp/third_party/hev-socks5-tunnel/` |
| lwIP | BSD-3-Clause core; per-file notices for optional code | https://savannah.nongnu.org/projects/lwip/ | Vendored under `app/src/main/cpp/third_party/hev-socks5-tunnel/third-part/lwip/` |
| libyaml | MIT | https://github.com/yaml/libyaml | Vendored under `app/src/main/cpp/third_party/hev-socks5-tunnel/third-part/yaml/` |
| doctest | MIT | https://github.com/doctest/doctest | Vendored header-only copy at `native_build/verification/rtp/host_tests/doctest.h` |
| AndroidX, Jetpack Compose, Material Components, Kotlin and kotlinx.coroutines | Apache-2.0; Kotlin math includes BSL-1.0 code | https://cs.android.com/ and https://github.com/JetBrains/kotlin | Gradle/Android platform dependencies, not vendored source |
| commonmark-java 0.22.0 | 2-clause BSD | https://github.com/commonmark/commonmark-java | Gradle dependency for report Markdown parsing; licence included in the in-app notices |
| spandsp (G.722 / G.726 subset) | LGPL-2.1 | https://github.com/freeswitch/spandsp | Vendored subset at `app/src/main/cpp/third_party/spandsp-lite/` (source and `COPYING`) |
| bcg729 (G.729 / G.729A / G.729B) | GPL-3.0 | https://github.com/BelledonneCommunications/bcg729 | Vendored at `app/src/main/cpp/third_party/bcg729/` (source and `COPYING`); statically linked when G.729 is enabled |
| libilbc (iLBC) | 3-clause BSD | https://chromium.googlesource.com/external/webrtc | Vendored subset at `app/src/main/cpp/third_party/libilbc/` (source and `COPYING`); statically linked when iLBC is enabled |
| OkHttp and Okio | Apache-2.0; OkHttp Public Suffix List data is MPL-2.0 | https://square.github.io/okhttp/ | Gradle runtime dependencies |
| JUnit 4 and Hamcrest | EPL-1.0 and BSD-3-Clause | https://junit.org/junit4/ | Test dependencies only |

## Corresponding source

Application source, JNI integration, native build scripts, and local patches:
https://github.com/cheig/LayerAnalyzer

The native source archive is intended to accompany the binary bundle at:
https://github.com/cheig/LayerAnalyzer_libs/releases/tag/wireshark-4.0.10-r1

Archive: native-sources-wireshark-4.0.10-r2.tar.gz.
The SHA-256 and exact upstream archive checksums or commits are recorded in
native_build/native-sources.json. Binary archive and per-library checksums are
recorded in native_build/native-deps.json. Obtain the manifest from the same
application release as the binary being used.

The source archive preserves the available source inputs and local Android changes
for all nine dependency projects listed below, plus build scripts and patches.
The 29 porting references in app/src/main/cpp/third_party/wireshark-reference/
are additional reference material and are not a substitute for this archive.

| Component | License | Exact upstream source | Android changes |
|---|---|---|---|
| glib-2.80.0 | LGPL-2.1-or-later | https://download.gnome.org/sources/glib/2.80/glib-2.80.0.tar.xz | `gio/gdbusprivate.c`, `gio/gkeyfilesettingsbackend.c`, `gio/glib-compile-schemas.c`, `gio/gnetworking.h.in`, `gio/gunixmounts.c`, `gio/xdgmime/xdgmime.c`, `girepository/compiler/meson.build`, `glib/gcharset.c`, `glib/glibintl.h`, `glib/gthreadprivate.h`, `glib/gtimezone.c`, `glib/gtypes.h`, `glib/gutils.c`, `glib/tests/meson.build`, `meson.build` |
| libffi-3.4.6 | MIT | https://github.com/libffi/libffi/releases/tag/v3.4.6 | No source modifications recorded |
| libgcrypt-1.11.0 | LGPL-2.1-or-later (library) | https://www.gnupg.org/ftp/gcrypt/libgcrypt/libgcrypt-1.11.0.tar.bz2 | No source modifications recorded |
| libgpg-error-1.50 | LGPL-2.1-or-later (library) | https://www.gnupg.org/ftp/gcrypt/libgpg-error/libgpg-error-1.50.tar.bz2 | `configure`; Android lock-object headers are also included |
| libiconv-1.17 | LGPL-2.1-or-later (library) | https://ftp.gnu.org/pub/gnu/libiconv/libiconv-1.17.tar.gz | No source modifications recorded |
| pcre2-10.42 | BSD-3-Clause | https://github.com/PCRE2Project/pcre2/releases/tag/pcre2-10.42 | No source modifications recorded |
| zlib-1.3.1 | Zlib | https://zlib.net/fossils/zlib-1.3.1.tar.gz | `zconf.h` |
| wireshark-4.0.10 | GPL-2.0-or-later | https://gitlab.com/wireshark/wireshark/-/tree/f5c7c25a81ebd5e2cd431f9e2d424586c6250812 | `cmake/modules/UseLemon.cmake`, `wsutil/ws_pipe.c`; upstream Git archive version metadata retained |
| c-ares-1.34.4 | MIT | https://github.com/c-ares/c-ares/tree/b82840329a4081a1f1b125e6e6b760d4e1237b52 | No source modifications recorded |

The GLib build produces libglib-2.0, libgobject-2.0, libgmodule-2.0, and
libgthread-2.0. GNU dependency distributions include separately licensed tools
and files; their COPYING, COPYING.LIB, and per-file notices remain authoritative.

For modified binaries, provide the matching application and library source,
patches, and build material under the relevant GPL/LGPL terms. The public
application build can relink the supplied LGPL sources and static libraries;
use your own Android signing key for a modified APK. Original publisher signing
keys are not supplied.

The nine source inputs and local patches have been audited, and both ABIs have
been rebuilt from the r2 archive with the documented build-script adjustments.
The pinned r1 binaries match retained original build outputs. Build configuration,
path metadata, and binary differences are recorded in docs/native-provenance.md
and native_build/provenance/wireshark-4.0.10-r1.json. This does not claim byte-identical
reproduction or completion of security and release verification. The r2 archive
must be accompanied by the rebuild adjustments listed in native-sources.json.
Verify public download availability before distributing binaries with these links.

## Vendored sources

bcg729 1.1.1 is statically linked when G.729 is enabled. Its source, GPL-3.0 text,
are in app/src/main/cpp/third_party/bcg729/; the upstream checksum is below.

The spandsp G.722/G.726 subset retains LGPL-2.1 and is statically linked. Its
source and COPYING are in
app/src/main/cpp/third_party/spandsp-lite/.

The optional libilbc decoder retains BSD-3-Clause. Its source,
six compatibility headers, and COPYING are in app/src/main/cpp/third_party/libilbc/.

The tunnel and nested dependencies are exported from these exact revisions.
The upstream Windows-only precompiled wintun.dll is excluded; the Android build
does not use it. Its upstream license and source notices are retained.
Public symbolic-link headers are included as regular copies so source archives
also work on Windows; the original implementations and copyright notices remain.

- `app/src/main/cpp/third_party/hev-socks5-tunnel`: `00c7eb9ad7ca381b0f1fee880abc1077fe9b93be`.
- `app/src/main/cpp/third_party/hev-socks5-tunnel/src/core`: `ee0f24505d344f14b14624fa2249e6ccfaed138b`.
- `app/src/main/cpp/third_party/hev-socks5-tunnel/third-part/hev-task-system`: `8d83bbbf79557138726c8ee5a5fae99cbb978d61`.
- `app/src/main/cpp/third_party/hev-socks5-tunnel/third-part/lwip`: `8c69dfbe537835d5f2a5fd8c08c859f667b108ea`.
- `app/src/main/cpp/third_party/hev-socks5-tunnel/third-part/yaml`: `efa36117a8646d26d12b58e05bac472d7854a70d`.

## Vendored codec provenance and build adaptations

These are source subsets compiled by app/src/main/cpp/CMakeLists.txt and the RTP
host-test CMakeLists.txt. The application remains GPL-3.0 with either codec flag;
the individual upstream licenses below are unchanged.

| Component | Upstream revision / archive | Archive SHA-256 |
|---|---|---|
| bcg729 | https://codeload.github.com/BelledonneCommunications/bcg729/tar.gz/refs/tags/1.1.1 | `68599a850535d1b182932b3f86558ac8a76d4b899a548183b062956c5fdc916d` |
| spandsp | https://codeload.github.com/freeswitch/spandsp/tar.gz/8f1e1646bdec99eac5fd2cd92c35563f736b9b89 | `1cb9a0ee3a68a20e84db9702cb82ac643b27e15820e74eb5a69511952dfa27b2` |
| WebRTC iLBC | https://chromium.googlesource.com/external/webrtc/+archive/e99f6879f6ae1c8c53f9ce7024abb33ce3173795/modules/audio_coding/codecs/ilbc.tar.gz | `db0adb99584e42f0edb457af3609353426cbb4ef8c15b3a319c5092899732cb7` |
| WebRTC signal processing | https://chromium.googlesource.com/external/webrtc/+archive/e99f6879f6ae1c8c53f9ce7024abb33ce3173795/common_audio/signal_processing.tar.gz | `cb941c97596646b14596c8625c7902f50f31e7581ac18d5631d6adfe793b98cc` |
| WebRTC square root helper | https://chromium.googlesource.com/external/webrtc/+archive/e99f6879f6ae1c8c53f9ce7024abb33ce3173795/common_audio/third_party/spl_sqrt_floor.tar.gz | `1e5536b323ba2694628629ce2cca8082b45d02a46b740564fde69cf4c14b0e22` |

bcg729 retains its 26 C files, 30 internal headers and two public headers. Its
COPYING is upstream LICENSE.txt (GPL-3.0). CMake leaves HAVE_CONFIG_H undefined
because the source subset does not use an Autotools-generated config.h.

The spandsp subset retains G.722, G.726, bitstream and allocation support (five C
files and 16 headers). Its source retains LGPL-2.1. Upstream COPYING also carries
GPL text for upstream components not used here; that text is preserved. CMake
provides configuration definitions and a build-local sys/time.h shim for MSVC.
Integer and bit-operation helpers stay with the subset; Android uses system headers.

The iLBC subset retains the WebRTC BSD license and the separate public-domain
notice in common_audio/third_party/spl_sqrt_floor/LICENSE. Six local compatibility
headers under rtc_base/ and absl/ provide architecture, sanitizer, compile-assert,
runtime-check, saturated-cast and attribute definitions; upstream codec sources
are retained. RTC_CHECK is always active; RTC_DCHECK is disabled under NDEBUG.
CMake uses portable signal-processing code rather than the upstream platform
assembly. The exact source lists and compile definitions are in the two CMake
files; disabled codecs do not change the application's GPL-3.0 license.

## Test captures

The 16 agent golden captures are generated by
tools/golden_capture/generate_golden_captures.mjs. The AMR fixtures use synthetic
test signals. Third-party Wireshark Wiki RTP captures and their derived media
are temporarily withheld from redistribution and can be supplied locally. Their attachment
licenses have not been established; the Wireshark application license alone
does not establish redistribution rights for those captures. See CONTRIBUTING.md and native_build/verification/rtp/fixtures.json.

## License texts included in the APK

The application carries native dependency license texts under assets/licenses/,
Wireshark's COPYING under assets/wireshark-data/, and the complete GPL-3.0 text
under assets/licenses/LayerAnalyzer-GPL-3.0.txt. Vendored source distributions also
retain their original license and copyright files.

## commonmark-java 0.22.0

Copyright (c) 2015, Atlassian Pty Ltd
All rights reserved.

Redistribution and use in source and binary forms, with or without
modification, are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.

* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

## Resolved Android runtime dependencies

The table below records the exact Gradle releaseRuntimeClasspath resolution.
There are 123 components: 94 with JAR/AAR artifacts and 29 metadata-only
components (BOMs and multiplatform redirects). Metadata rows are not additional
libraries in the APK. R8 may remove unused classes; this notice conservatively
covers the complete resolved runtime classpath. Test and debug-only tooling are
not part of this Release inventory.

The matching artifact hashes, exact-version POM/source evidence and review notes
are in docs/dependency-licenses.json and docs/dependency-licenses.md. Regenerate
the resolution using tools/runtime_license_inventory.init.gradle when changing
dependencies; a dependency inventory does not replace license texts or source.

All rows are Apache-2.0 except commonmark (BSD-2-Clause). Kotlin stdlib includes
Boost-licensed JVM math code (BSL-1.0). OkHttp includes MPL-2.0 Public Suffix List
data. Google Guava listenablefuture and Error Prone annotations, as well as
JetBrains annotations and kotlinx.coroutines, are included in this review.

| Resolved coordinate | Artifact kind |
|---|---|
| androidx.activity:activity-compose:1.9.3 | AAR |
| androidx.activity:activity-ktx:1.9.3 | AAR |
| androidx.activity:activity:1.9.3 | AAR |
| androidx.annotation:annotation-experimental:1.4.0 | AAR |
| androidx.annotation:annotation-jvm:1.8.1 | JAR |
| androidx.annotation:annotation:1.8.1 | Metadata only |
| androidx.appcompat:appcompat-resources:1.7.0 | AAR |
| androidx.appcompat:appcompat:1.7.0 | AAR |
| androidx.arch.core:core-common:2.2.0 | JAR |
| androidx.arch.core:core-runtime:2.2.0 | AAR |
| androidx.autofill:autofill:1.0.0 | AAR |
| androidx.cardview:cardview:1.0.0 | AAR |
| androidx.collection:collection-jvm:1.4.0 | JAR |
| androidx.collection:collection-ktx:1.4.0 | JAR |
| androidx.collection:collection:1.4.0 | Metadata only |
| androidx.compose.animation:animation-android:1.6.6 | AAR |
| androidx.compose.animation:animation-core-android:1.6.6 | AAR |
| androidx.compose.animation:animation-core:1.6.6 | Metadata only |
| androidx.compose.animation:animation:1.6.6 | Metadata only |
| androidx.compose.foundation:foundation-android:1.6.6 | AAR |
| androidx.compose.foundation:foundation-layout-android:1.6.6 | AAR |
| androidx.compose.foundation:foundation-layout:1.6.6 | Metadata only |
| androidx.compose.foundation:foundation:1.6.6 | Metadata only |
| androidx.compose.material3:material3-android:1.2.1 | AAR |
| androidx.compose.material3:material3:1.2.1 | Metadata only |
| androidx.compose.material:material-icons-core-android:1.6.6 | AAR |
| androidx.compose.material:material-icons-core:1.6.6 | Metadata only |
| androidx.compose.material:material-icons-extended-android:1.6.6 | AAR |
| androidx.compose.material:material-icons-extended:1.6.6 | Metadata only |
| androidx.compose.material:material-ripple-android:1.6.6 | AAR |
| androidx.compose.material:material-ripple:1.6.6 | Metadata only |
| androidx.compose.runtime:runtime-android:1.6.6 | AAR |
| androidx.compose.runtime:runtime-saveable-android:1.6.6 | AAR |
| androidx.compose.runtime:runtime-saveable:1.6.6 | Metadata only |
| androidx.compose.runtime:runtime:1.6.6 | Metadata only |
| androidx.compose.ui:ui-android:1.6.6 | AAR |
| androidx.compose.ui:ui-geometry-android:1.6.6 | AAR |
| androidx.compose.ui:ui-geometry:1.6.6 | Metadata only |
| androidx.compose.ui:ui-graphics-android:1.6.6 | AAR |
| androidx.compose.ui:ui-graphics:1.6.6 | Metadata only |
| androidx.compose.ui:ui-text-android:1.6.6 | AAR |
| androidx.compose.ui:ui-text:1.6.6 | Metadata only |
| androidx.compose.ui:ui-tooling-preview-android:1.6.6 | AAR |
| androidx.compose.ui:ui-tooling-preview:1.6.6 | Metadata only |
| androidx.compose.ui:ui-unit-android:1.6.6 | AAR |
| androidx.compose.ui:ui-unit:1.6.6 | Metadata only |
| androidx.compose.ui:ui-util-android:1.6.6 | AAR |
| androidx.compose.ui:ui-util:1.6.6 | Metadata only |
| androidx.compose.ui:ui:1.6.6 | Metadata only |
| androidx.compose:compose-bom:2024.04.01 | Metadata only |
| androidx.concurrent:concurrent-futures:1.1.0 | JAR |
| androidx.constraintlayout:constraintlayout-solver:2.0.1 | JAR |
| androidx.constraintlayout:constraintlayout:2.0.1 | AAR |
| androidx.coordinatorlayout:coordinatorlayout:1.1.0 | AAR |
| androidx.core:core-ktx:1.13.1 | AAR |
| androidx.core:core:1.13.1 | AAR |
| androidx.cursoradapter:cursoradapter:1.0.0 | AAR |
| androidx.customview:customview-poolingcontainer:1.0.0 | AAR |
| androidx.customview:customview:1.1.0 | AAR |
| androidx.documentfile:documentfile:1.0.0 | AAR |
| androidx.drawerlayout:drawerlayout:1.1.1 | AAR |
| androidx.dynamicanimation:dynamicanimation:1.0.0 | AAR |
| androidx.emoji2:emoji2-views-helper:1.3.0 | AAR |
| androidx.emoji2:emoji2:1.3.0 | AAR |
| androidx.fragment:fragment:1.5.4 | AAR |
| androidx.interpolator:interpolator:1.0.0 | AAR |
| androidx.legacy:legacy-support-core-utils:1.0.0 | AAR |
| androidx.lifecycle:lifecycle-common-java8:2.8.7 | JAR |
| androidx.lifecycle:lifecycle-common-jvm:2.8.7 | JAR |
| androidx.lifecycle:lifecycle-common:2.8.7 | Metadata only |
| androidx.lifecycle:lifecycle-livedata-core-ktx:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-livedata-core:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-livedata-ktx:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-livedata:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-process:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-runtime-android:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-runtime-ktx-android:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-runtime-ktx:2.8.7 | Metadata only |
| androidx.lifecycle:lifecycle-runtime:2.8.7 | Metadata only |
| androidx.lifecycle:lifecycle-viewmodel-android:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-viewmodel-compose-android:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-viewmodel-compose:2.8.7 | Metadata only |
| androidx.lifecycle:lifecycle-viewmodel-ktx:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-viewmodel-savedstate:2.8.7 | AAR |
| androidx.lifecycle:lifecycle-viewmodel:2.8.7 | AAR |
| androidx.loader:loader:1.0.0 | AAR |
| androidx.localbroadcastmanager:localbroadcastmanager:1.0.0 | AAR |
| androidx.multidex:multidex:2.0.1 | AAR |
| androidx.paging:paging-common-ktx:3.2.1 | JAR |
| androidx.paging:paging-common:3.2.1 | JAR |
| androidx.paging:paging-compose:3.2.1 | AAR |
| androidx.paging:paging-runtime:3.2.1 | AAR |
| androidx.print:print:1.0.0 | AAR |
| androidx.profileinstaller:profileinstaller:1.3.1 | AAR |
| androidx.recyclerview:recyclerview:1.2.1 | AAR |
| androidx.resourceinspection:resourceinspection-annotation:1.0.1 | JAR |
| androidx.savedstate:savedstate-ktx:1.2.1 | AAR |
| androidx.savedstate:savedstate:1.2.1 | AAR |
| androidx.startup:startup-runtime:1.1.1 | AAR |
| androidx.tracing:tracing:1.0.0 | AAR |
| androidx.transition:transition:1.5.0 | AAR |
| androidx.vectordrawable:vectordrawable-animated:1.1.0 | AAR |
| androidx.vectordrawable:vectordrawable:1.1.0 | AAR |
| androidx.versionedparcelable:versionedparcelable:1.1.1 | AAR |
| androidx.viewpager2:viewpager2:1.0.0 | AAR |
| androidx.viewpager:viewpager:1.0.0 | AAR |
| com.google.android.material:material:1.12.0 | AAR |
| com.google.errorprone:error_prone_annotations:2.15.0 | JAR |
| com.google.guava:listenablefuture:1.0 | JAR |
| com.squareup.okhttp3:okhttp:4.12.0 | JAR |
| com.squareup.okio:okio-jvm:3.6.0 | JAR |
| com.squareup.okio:okio:3.6.0 | Metadata only |
| org.commonmark:commonmark:0.22.0 | JAR |
| org.jetbrains.kotlin:kotlin-bom:1.8.22 | Metadata only |
| org.jetbrains.kotlin:kotlin-stdlib-common:1.9.23 | Metadata only |
| org.jetbrains.kotlin:kotlin-stdlib-jdk7:1.9.10 | JAR |
| org.jetbrains.kotlin:kotlin-stdlib-jdk8:1.9.10 | JAR |
| org.jetbrains.kotlin:kotlin-stdlib:1.9.23 | JAR |
| org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3 | JAR |
| org.jetbrains.kotlinx:kotlinx-coroutines-bom:1.7.3 | Metadata only |
| org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.7.3 | JAR |
| org.jetbrains.kotlinx:kotlinx-coroutines-core:1.7.3 | Metadata only |
| org.jetbrains:annotations:23.0.0 | JAR |

## Additional runtime license materials

Android NDK r27 supplies libc++_shared and compiler runtime support, licensed
under Apache-2.0 WITH LLVM-exception with retained legacy MIT/NCSA texts. The
complete runtime notices and available CREDITS.TXT files are in
assets/licenses/NDK-runtime.txt. This is separate from the pinned native bundle.

The original nlohmann/json LICENSE.MIT is unchanged; supplemental copyright
statements from the bundled 3.11.3 header are in nlohmann-json-copyrights.txt.
libyaml-upstream.txt retains Ingy döt Net and Kirill Simonov's libyaml 0.2.5
license, in addition to the existing hev build-system license in libyaml.txt.
lwip-source-notices.txt retains the individual source notices, including optional
code, alongside the unchanged core BSD license in lwip.txt.

The in-app Third-party notices dialog reads these notices and every text in
assets/licenses/ offline. Identical texts already present here are not repeated.
The existing META-INF/AL2.0 and LGPL2.1 Gradle exclusions remain; explicit asset
copies supply those licenses instead. The application remains GPL-3.0.

## Upstream runtime notices and license texts

The kotlinx.coroutines NOTICE below is copied unchanged from tag 1.7.3.
Kotlin's license/NOTICE.txt at v1.9.23 and v1.9.10 explicitly applies to the
compiler distribution, which is not shipped in the APK. Its identical runtime
COPYRIGHT.txt is retained below; compiler/plugin/test-only third-party licenses
are not attributed to the Android standard library.

OkHttp 4.12.0's publicsuffixes.gz is unmodified. Its original NOTICE is retained
both in the library resource and below. The list can be obtained from the URL
in that notice. The exact list entries shipped in this version can also be
recovered using the publicsuffix resource format and reader in the matching
upstream source tag:
https://github.com/square/okhttp/tree/parent-4.12.0/okhttp/src/main

### Android-runtime-NOTICES.txt

Android/JVM runtime attributions

Coordinates below are resolved releaseRuntimeClasspath components.
Copyright statements are retained from their exact published source
archives; Apache-2.0 applies except for the separately identified
commonmark BSD license, Kotlin Boost-derived math, and the MPL-2.0
Public Suffix List data in OkHttp. Full texts accompany these notices.

androidx.activity:activity-compose:1.9.3
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.activity:activity:1.9.3
Copyright (C) 2020 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.annotation:annotation-experimental:1.4.0
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project

androidx.annotation:annotation-jvm:1.8.1
Copyright (C) 2013 The Android Open Source Project
Copyright (C) 2014 The Android Open Source Project
Copyright (C) 2015 The Android Open Source Project
Copyright (C) 2016 The Android Open Source Project
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2020 The Android Open Source Project
Copyright (C) 2021 The Android Open Source Project
Copyright (C) 2022 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2023 The Android Open Source Project
Copyright 2024 The Android Open Source Project

androidx.appcompat:appcompat-resources:1.7.0
Copyright (C) 2014 The Android Open Source Project
Copyright (C) 2015 The Android Open Source Project
Copyright (C) 2018 The Android Open Source Project
Copyright (C) 2019 The Android Open Source Project
Copyright 2016 The Android Open Source Project
Copyright 2021 The Android Open Source Project

androidx.appcompat:appcompat:1.7.0
Copyright (C) 2006 The Android Open Source Project
Copyright (C) 2010 The Android Open Source Project
Copyright (C) 2011 The Android Open Source Project
Copyright (C) 2012 The Android Open Source Project
Copyright (C) 2013 The Android Open Source Project
Copyright (C) 2014 The Android Open Source Project
Copyright (C) 2015 Google Inc.
Copyright (C) 2015 The Android Open Source Project
Copyright (C) 2016 The Android Open Source Project
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2021 The Android Open Source Project
Copyright 2017 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project

androidx.arch.core:core-common:2.2.0
Copyright 2018 The Android Open Source Project

androidx.arch.core:core-runtime:2.2.0
Copyright (C) 2017 The Android Open Source Project

androidx.autofill:autofill:1.0.0
Copyright 2019 The Android Open Source Project

androidx.cardview:cardview:1.0.0
Copyright 2018 The Android Open Source Project

androidx.collection:collection-jvm:1.4.0
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2019 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.animation:animation-android:1.6.6
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project

androidx.compose.animation:animation-core-android:1.6.6
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.foundation:foundation-android:1.6.6
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.foundation:foundation-layout-android:1.6.6
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project

androidx.compose.material3:material3-android:1.2.1
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project
Copyright 2024 The Android Open Source Project

androidx.compose.material:material-icons-core-android:1.6.6
Copyright 2020 The Android Open Source Project
Copyright 2024 The Android Open Source Project

androidx.compose.material:material-icons-extended-android:1.6.6
Copyright 2024 The Android Open Source Project

androidx.compose.material:material-ripple-android:1.6.6
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project

androidx.compose.runtime:runtime-android:1.6.6
Copyright 2016-2019 JetBrains s.r.o.
Copyright 2016-2020 JetBrains s.r.o.
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.runtime:runtime-saveable-android:1.6.6
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project

androidx.compose.ui:ui-android:1.6.6
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.ui:ui-geometry-android:1.6.6
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project

androidx.compose.ui:ui-graphics-android:1.6.6
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.ui:ui-text-android:1.6.6
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2020 The Android Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.ui:ui-tooling-preview-android:1.6.6
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.ui:ui-unit-android:1.6.6
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.compose.ui:ui-util-android:1.6.6
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.concurrent:concurrent-futures:1.1.0
Copyright 2018 The Android Open Source Project

androidx.constraintlayout:constraintlayout-solver:2.0.1
Copyright (C) 2015 The Android Open Source Project

androidx.constraintlayout:constraintlayout:2.0.1
Copyright (C) 2015 The Android Open Source Project

androidx.coordinatorlayout:coordinatorlayout:1.1.0
Copyright 2018 The Android Open Source Project

androidx.core:core-ktx:1.13.1
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2018 The Android Open Source Project
Copyright (C) 20188 The Android Open Source Project
Copyright (C) 2019 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2022 The Android Open Source Project

androidx.core:core:1.13.1
Copyright (C) 2009 The Android Open Source Project
Copyright (C) 2011 The Android Open Source Project
Copyright (C) 2012 The Android Open Source Project
Copyright (C) 2013 The Android Open Source Project
Copyright (C) 2014 The Android Open Source Project
Copyright (C) 2015 The Android Open Source Project
Copyright (C) 2016 The Android Open Source Project
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2018 The Android Open Source Project
Copyright (C) 2019 The Android Open Source Project
Copyright (C) 2021 The Android Open Source Project
Copyright (C) 2022 The Android Open Source Project
Copyright (C) 2023 The Android Open Source Project
Copyright 2015 The Android Open Source Project
Copyright 2017 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.cursoradapter:cursoradapter:1.0.0
Copyright 2018 The Android Open Source Project

androidx.customview:customview-poolingcontainer:1.0.0
Copyright 2021 The Android Open Source Project

androidx.customview:customview:1.1.0
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project

androidx.documentfile:documentfile:1.0.0
Copyright 2018 The Android Open Source Project

androidx.drawerlayout:drawerlayout:1.1.1
Copyright 2018 The Android Open Source Project

androidx.dynamicanimation:dynamicanimation:1.0.0
Copyright (C) 2017 The Android Open Source Project

androidx.emoji2:emoji2-views-helper:1.3.0
Copyright 2021 The Android Open Source Project

androidx.emoji2:emoji2:1.3.0
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project

androidx.fragment:fragment:1.5.4
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project

androidx.interpolator:interpolator:1.0.0
Copyright 2018 The Android Open Source Project

androidx.legacy:legacy-support-core-utils:1.0.0
Copyright 2018 The Android Open Source Project

androidx.lifecycle:lifecycle-common-jvm:2.8.7
Copyright (C) 2017 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project

androidx.lifecycle:lifecycle-livedata-core:2.8.7
Copyright (C) 2017 The Android Open Source Project
Copyright 2018 The Android Open Source Project

androidx.lifecycle:lifecycle-livedata:2.8.7
Copyright (C) 2017 The Android Open Source Project
Copyright 2019 The Android Open Source Project

androidx.lifecycle:lifecycle-process:2.8.7
Copyright (C) 2017 The Android Open Source Project
Copyright 2021 The Android Open Source Project

androidx.lifecycle:lifecycle-runtime-android:2.8.7
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2024 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2024 The Android Open Source Project

androidx.lifecycle:lifecycle-viewmodel-android:2.8.7
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2024 The Android Open Source Project
Copyright 2017 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2023 The Android Open Source Project
Copyright 2024 The Android Open Source Project

androidx.lifecycle:lifecycle-viewmodel-compose-android:2.8.7
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2024 The Android Open Source Project

androidx.lifecycle:lifecycle-viewmodel-savedstate:2.8.7
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2021 The Android Open Source Project

androidx.lifecycle:lifecycle-viewmodel:2.8.7
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2024 The Android Open Source Project
Copyright 2017 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2024 The Android Open Source Project

androidx.loader:loader:1.0.0
Copyright 2018 The Android Open Source Project

androidx.localbroadcastmanager:localbroadcastmanager:1.0.0
Copyright 2018 The Android Open Source Project

androidx.multidex:multidex:2.0.1
Copyright (C) 2013 The Android Open Source Project
Copyright (C) 2014 The Android Open Source Project

androidx.paging:paging-common:3.2.1
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.paging:paging-compose:3.2.1
Copyright 2020 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.paging:paging-runtime:3.2.1
Copyright (C) 2017 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project

androidx.print:print:1.0.0
Copyright 2018 The Android Open Source Project

androidx.profileinstaller:profileinstaller:1.3.1
Copyright (C) 2021 The Android Open Source Project
Copyright 2021 The Android Open Source Project
Copyright 2022 The Android Open Source Project

androidx.recyclerview:recyclerview:1.2.1
Copyright 2018 The Android Open Source Project
Copyright 2020 The Android Open Source Project

androidx.resourceinspection:resourceinspection-annotation:1.0.1
Copyright 2021 The Android Open Source Project

androidx.savedstate:savedstate-ktx:1.2.1
Copyright 2020 The Android Open Source Project

androidx.savedstate:savedstate:1.2.1
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project

androidx.startup:startup-runtime:1.1.1
Copyright 2020 The Android Open Source Project

androidx.tracing:tracing:1.0.0
Copyright 2020 The Android Open Source Project

androidx.transition:transition:1.5.0
Copyright (C) 2016 The Android Open Source Project
Copyright (C) 2017 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2023 The Android Open Source Project

androidx.vectordrawable:vectordrawable-animated:1.1.0
Copyright (C) 2015 The Android Open Source Project
Copyright (C) 2017 The Android Open Source Project

androidx.vectordrawable:vectordrawable:1.1.0
Copyright (C) 2015 The Android Open Source Project

androidx.versionedparcelable:versionedparcelable:1.1.1
Copyright 2018 The Android Open Source Project

androidx.viewpager2:viewpager2:1.0.0
Copyright 2017 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project

androidx.viewpager:viewpager:1.0.0
Copyright 2018 The Android Open Source Project

com.google.android.material:material:1.12.0
Copyright (C) 2014 The Android Open Source Project
Copyright (C) 2015 The Android Open Source Project
Copyright (C) 2016 The Android Open Source Project
Copyright (C) 2017 The Android Open Source Project
Copyright (C) 2018 The Android Open Source Project
Copyright (C) 2019 The Android Open Source Project
Copyright (C) 2020 The Android Open Source Project
Copyright (C) 2021 The Android Open Source Project
Copyright (C) 2022 The Android Open Source Project
Copyright (C) 2023 The Android Open Source Project
Copyright 2017 The Android Open Source Project
Copyright 2018 The Android Open Source Project
Copyright 2019 The Android Open Source Project
Copyright 2020 The Android Open Source Project
Copyright 2022 The Android Open Source Project
Copyright 2023 The Android Open Source Project

com.google.errorprone:error_prone_annotations:2.15.0
Copyright 2014 The Error Prone Authors.
Copyright 2015 The Error Prone Authors.
Copyright 2016 The Error Prone Authors.
Copyright 2017 The Error Prone Authors.
Copyright 2021 The Error Prone Authors.

com.google.guava:listenablefuture:1.0
Copyright (C) 2007 The Guava Authors

com.squareup.okhttp3:okhttp:4.12.0
Copyright (C) 2010 The Android Open Source Project
Copyright (C) 2011 The Android Open Source Project
Copyright (C) 2012 Square, Inc.
Copyright (C) 2012 The Android Open Source Project
Copyright (C) 2013 Square, Inc.
Copyright (C) 2014 Square, Inc.
Copyright (C) 2015 Square, Inc.
Copyright (C) 2016 Square, Inc.
Copyright (C) 2017 Square, Inc.
Copyright (C) 2018 Square, Inc.
Copyright (C) 2019 Square, Inc.
Copyright (C) 2020 Square, Inc.
Copyright 2013 Twitter, Inc.

com.squareup.okio:okio-jvm:3.6.0
Copyright (C) 2014 Square, Inc.
Copyright (C) 2015 Square, Inc.
Copyright (C) 2016 Square, Inc.
Copyright (C) 2017 Square, Inc.
Copyright (C) 2018 Square, Inc.
Copyright (C) 2019 Square, Inc.
Copyright (C) 2020 Square, Inc.
Copyright (C) 2020 Square, Inc. and others.
Copyright (C) 2021 Square, Inc.
Copyright (C) 2023 Square, Inc.
Copyright 2014 Square Inc.

org.jetbrains.kotlin:kotlin-stdlib:1.9.23
Copyright 2007 Google Inc.
Copyright 2010-2015 JetBrains s.r.o.
Copyright 2010-2016 JetBrains s.r.o.
Copyright 2010-2017 JetBrains s.r.o.
Copyright 2010-2018 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license
Copyright 2010-2018 JetBrains s.r.o. and Kotlin Programming Language contributors.
Copyright 2010-2019 JetBrains s.r.o. and Kotlin Programming Language contributors.
Copyright 2010-2020 JetBrains s.r.o. and Kotlin Programming Language contributors.
Copyright 2010-2021 JetBrains s.r.o. and Kotlin Programming Language contributors.
Copyright 2010-2022 JetBrains s.r.o. and Kotlin Programming Language contributors.
Copyright 2010-2023 JetBrains s.r.o. and Kotlin Programming Language contributors.
Copyright 2011 The Guava Authors

org.jetbrains.kotlinx:kotlinx-coroutines-android:1.7.3
Copyright 2016-2021 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.

org.jetbrains.kotlinx:kotlinx-coroutines-core-jvm:1.7.3
Copyright 2016-2020 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
Copyright 2016-2021 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
Copyright 2016-2022 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.
Copyright 2016-2023 JetBrains s.r.o. Use of this source code is governed by the Apache 2.0 license.

org.jetbrains:annotations:23.0.0
Copyright 2000-2020 JetBrains s.r.o.
Copyright 2000-2021 JetBrains s.r.o.

Additional attributions

Kotlin 1.9.23: JVM MathJVM.kt includes code derived from Boost special
math functions. Copyright Eric Ford & Hubert Holin 2001.
Kotlin collections: Derived from GWT, (C) 2007-08 Google Inc.
Kotlin UnsignedUtils.kt: Derived from Guava, (C) 2011 The Guava Authors.
Source: https://github.com/JetBrains/kotlin/blob/v1.9.23/license/README.md

Compose ui-graphics 1.6.6 FastFloatParser.kt credits fast_float and
fast_double_parser (Apache-2.0).
https://github.com/fastfloat/fast_float
https://github.com/lemire/fast_double_parser/

Apache Software Foundation attribution retained from AndroidX
multidex ZipUtil.java, OkHttp OkHostnameVerifier.kt and Okio sources
including Base64.kt and ZipFiles.kt (Apache Harmony-derived code):

/*
 * Licensed to the Apache Software Foundation (ASF) under one or more
 * contributor license agreements.  See the NOTICE file distributed with
 * this work for additional information regarding copyright ownership.
 * The ASF licenses this file to You under the Apache License, Version 2.0
 * (the "License"); you may not use this file except in compliance with
 * the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
/* Apache Harmony HEADER because the code in this class comes mostly from ZipFile, ZipEntry and
 * ZipConstants from android libcore.
 */

### Kotlin-COPYRIGHT.txt

/*
 * Copyright 2010-2023 JetBrains s.r.o. and Kotlin Programming Language contributors.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

### kotlinx-coroutines-NOTICE.txt

=========================================================================
==  NOTICE file corresponding to the section 4 d of                    ==
==  the Apache License, Version 2.0,                                   ==
==  in this case for the kotlinx.coroutines library.                   ==
=========================================================================

kotlinx.coroutines library.
Copyright 2016-2021 JetBrains s.r.o and respective authors and developers

### OkHttp-publicsuffix-NOTICE.txt

Note that publicsuffixes.gz is compiled from The Public Suffix List:
https://publicsuffix.org/list/public_suffix_list.dat

It is subject to the terms of the Mozilla Public License, v. 2.0:
https://mozilla.org/MPL/2.0/

### Apache-2.0.txt


                                 Apache License
                           Version 2.0, January 2004
                        http://www.apache.org/licenses/

   TERMS AND CONDITIONS FOR USE, REPRODUCTION, AND DISTRIBUTION

   1. Definitions.

      "License" shall mean the terms and conditions for use, reproduction,
      and distribution as defined by Sections 1 through 9 of this document.

      "Licensor" shall mean the copyright owner or entity authorized by
      the copyright owner that is granting the License.

      "Legal Entity" shall mean the union of the acting entity and all
      other entities that control, are controlled by, or are under common
      control with that entity. For the purposes of this definition,
      "control" means (i) the power, direct or indirect, to cause the
      direction or management of such entity, whether by contract or
      otherwise, or (ii) ownership of fifty percent (50%) or more of the
      outstanding shares, or (iii) beneficial ownership of such entity.

      "You" (or "Your") shall mean an individual or Legal Entity
      exercising permissions granted by this License.

      "Source" form shall mean the preferred form for making modifications,
      including but not limited to software source code, documentation
      source, and configuration files.

      "Object" form shall mean any form resulting from mechanical
      transformation or translation of a Source form, including but
      not limited to compiled object code, generated documentation,
      and conversions to other media types.

      "Work" shall mean the work of authorship, whether in Source or
      Object form, made available under the License, as indicated by a
      copyright notice that is included in or attached to the work
      (an example is provided in the Appendix below).

      "Derivative Works" shall mean any work, whether in Source or Object
      form, that is based on (or derived from) the Work and for which the
      editorial revisions, annotations, elaborations, or other modifications
      represent, as a whole, an original work of authorship. For the purposes
      of this License, Derivative Works shall not include works that remain
      separable from, or merely link (or bind by name) to the interfaces of,
      the Work and Derivative Works thereof.

      "Contribution" shall mean any work of authorship, including
      the original version of the Work and any modifications or additions
      to that Work or Derivative Works thereof, that is intentionally
      submitted to Licensor for inclusion in the Work by the copyright owner
      or by an individual or Legal Entity authorized to submit on behalf of
      the copyright owner. For the purposes of this definition, "submitted"
      means any form of electronic, verbal, or written communication sent
      to the Licensor or its representatives, including but not limited to
      communication on electronic mailing lists, source code control systems,
      and issue tracking systems that are managed by, or on behalf of, the
      Licensor for the purpose of discussing and improving the Work, but
      excluding communication that is conspicuously marked or otherwise
      designated in writing by the copyright owner as "Not a Contribution."

      "Contributor" shall mean Licensor and any individual or Legal Entity
      on behalf of whom a Contribution has been received by Licensor and
      subsequently incorporated within the Work.

   2. Grant of Copyright License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      copyright license to reproduce, prepare Derivative Works of,
      publicly display, publicly perform, sublicense, and distribute the
      Work and such Derivative Works in Source or Object form.

   3. Grant of Patent License. Subject to the terms and conditions of
      this License, each Contributor hereby grants to You a perpetual,
      worldwide, non-exclusive, no-charge, royalty-free, irrevocable
      (except as stated in this section) patent license to make, have made,
      use, offer to sell, sell, import, and otherwise transfer the Work,
      where such license applies only to those patent claims licensable
      by such Contributor that are necessarily infringed by their
      Contribution(s) alone or by combination of their Contribution(s)
      with the Work to which such Contribution(s) was submitted. If You
      institute patent litigation against any entity (including a
      cross-claim or counterclaim in a lawsuit) alleging that the Work
      or a Contribution incorporated within the Work constitutes direct
      or contributory patent infringement, then any patent licenses
      granted to You under this License for that Work shall terminate
      as of the date such litigation is filed.

   4. Redistribution. You may reproduce and distribute copies of the
      Work or Derivative Works thereof in any medium, with or without
      modifications, and in Source or Object form, provided that You
      meet the following conditions:

      (a) You must give any other recipients of the Work or
          Derivative Works a copy of this License; and

      (b) You must cause any modified files to carry prominent notices
          stating that You changed the files; and

      (c) You must retain, in the Source form of any Derivative Works
          that You distribute, all copyright, patent, trademark, and
          attribution notices from the Source form of the Work,
          excluding those notices that do not pertain to any part of
          the Derivative Works; and

      (d) If the Work includes a "NOTICE" text file as part of its
          distribution, then any Derivative Works that You distribute must
          include a readable copy of the attribution notices contained
          within such NOTICE file, excluding those notices that do not
          pertain to any part of the Derivative Works, in at least one
          of the following places: within a NOTICE text file distributed
          as part of the Derivative Works; within the Source form or
          documentation, if provided along with the Derivative Works; or,
          within a display generated by the Derivative Works, if and
          wherever such third-party notices normally appear. The contents
          of the NOTICE file are for informational purposes only and
          do not modify the License. You may add Your own attribution
          notices within Derivative Works that You distribute, alongside
          or as an addendum to the NOTICE text from the Work, provided
          that such additional attribution notices cannot be construed
          as modifying the License.

      You may add Your own copyright statement to Your modifications and
      may provide additional or different license terms and conditions
      for use, reproduction, or distribution of Your modifications, or
      for any such Derivative Works as a whole, provided Your use,
      reproduction, and distribution of the Work otherwise complies with
      the conditions stated in this License.

   5. Submission of Contributions. Unless You explicitly state otherwise,
      any Contribution intentionally submitted for inclusion in the Work
      by You to the Licensor shall be under the terms and conditions of
      this License, without any additional terms or conditions.
      Notwithstanding the above, nothing herein shall supersede or modify
      the terms of any separate license agreement you may have executed
      with Licensor regarding such Contributions.

   6. Trademarks. This License does not grant permission to use the trade
      names, trademarks, service marks, or product names of the Licensor,
      except as required for reasonable and customary use in describing the
      origin of the Work and reproducing the content of the NOTICE file.

   7. Disclaimer of Warranty. Unless required by applicable law or
      agreed to in writing, Licensor provides the Work (and each
      Contributor provides its Contributions) on an "AS IS" BASIS,
      WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
      implied, including, without limitation, any warranties or conditions
      of TITLE, NON-INFRINGEMENT, MERCHANTABILITY, or FITNESS FOR A
      PARTICULAR PURPOSE. You are solely responsible for determining the
      appropriateness of using or redistributing the Work and assume any
      risks associated with Your exercise of permissions under this License.

   8. Limitation of Liability. In no event and under no legal theory,
      whether in tort (including negligence), contract, or otherwise,
      unless required by applicable law (such as deliberate and grossly
      negligent acts) or agreed to in writing, shall any Contributor be
      liable to You for damages, including any direct, indirect, special,
      incidental, or consequential damages of any character arising as a
      result of this License or out of the use or inability to use the
      Work (including but not limited to damages for loss of goodwill,
      work stoppage, computer failure or malfunction, or any and all
      other commercial damages or losses), even if such Contributor
      has been advised of the possibility of such damages.

   9. Accepting Warranty or Additional Liability. While redistributing
      the Work or Derivative Works thereof, You may choose to offer,
      and charge a fee for, acceptance of support, warranty, indemnity,
      or other liability obligations and/or rights consistent with this
      License. However, in accepting such obligations, You may act only
      on Your own behalf and on Your sole responsibility, not on behalf
      of any other Contributor, and only if You agree to indemnify,
      defend, and hold each Contributor harmless for any liability
      incurred by, or claims asserted against, such Contributor by reason
      of your accepting any such warranty or additional liability.

   END OF TERMS AND CONDITIONS

   APPENDIX: How to apply the Apache License to your work.

      To apply the Apache License to your work, attach the following
      boilerplate notice, with the fields enclosed by brackets "[]"
      replaced with your own identifying information. (Don't include
      the brackets!)  The text should be enclosed in the appropriate
      comment syntax for the file format. We also recommend that a
      file or class name and description of purpose be included on the
      same "printed page" as the copyright notice for easier
      identification within third-party archives.

   Copyright [yyyy] [name of copyright owner]

   Licensed under the Apache License, Version 2.0 (the "License");
   you may not use this file except in compliance with the License.
   You may obtain a copy of the License at

       http://www.apache.org/licenses/LICENSE-2.0

   Unless required by applicable law or agreed to in writing, software
   distributed under the License is distributed on an "AS IS" BASIS,
   WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
   See the License for the specific language governing permissions and
   limitations under the License.

### Boost-1.0.txt

Boost Software License - Version 1.0 - August 17th, 2003

Permission is hereby granted, free of charge, to any person or organization
obtaining a copy of the software and accompanying documentation covered by
this license (the "Software") to use, reproduce, display, distribute,
execute, and transmit the Software, and to prepare derivative works of the
Software, and to permit third-parties to whom the Software is furnished to
do so, all subject to the following:

The copyright notices in the Software and this entire statement, including
the above license grant, this restriction and the following disclaimer,
must be included in all copies of the Software, in whole or in part, and
all derivative works of the Software, unless such copies or derivative
works are solely in the form of machine-executable object code generated by
a source language processor.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE, TITLE AND NON-INFRINGEMENT. IN NO EVENT
SHALL THE COPYRIGHT HOLDERS OR ANYONE DISTRIBUTING THE SOFTWARE BE LIABLE
FOR ANY DAMAGES OR OTHER LIABILITY, WHETHER IN CONTRACT, TORT OR OTHERWISE,
ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
DEALINGS IN THE SOFTWARE.
### MPL-2.0.txt

Mozilla Public License Version 2.0
==================================

1. Definitions
--------------

1.1. "Contributor"
    means each individual or legal entity that creates, contributes to
    the creation of, or owns Covered Software.

1.2. "Contributor Version"
    means the combination of the Contributions of others (if any) used
    by a Contributor and that particular Contributor's Contribution.

1.3. "Contribution"
    means Covered Software of a particular Contributor.

1.4. "Covered Software"
    means Source Code Form to which the initial Contributor has attached
    the notice in Exhibit A, the Executable Form of such Source Code
    Form, and Modifications of such Source Code Form, in each case
    including portions thereof.

1.5. "Incompatible With Secondary Licenses"
    means

    (a) that the initial Contributor has attached the notice described
        in Exhibit B to the Covered Software; or

    (b) that the Covered Software was made available under the terms of
        version 1.1 or earlier of the License, but not also under the
        terms of a Secondary License.

1.6. "Executable Form"
    means any form of the work other than Source Code Form.

1.7. "Larger Work"
    means a work that combines Covered Software with other material, in
    a separate file or files, that is not Covered Software.

1.8. "License"
    means this document.

1.9. "Licensable"
    means having the right to grant, to the maximum extent possible,
    whether at the time of the initial grant or subsequently, any and
    all of the rights conveyed by this License.

1.10. "Modifications"
    means any of the following:

    (a) any file in Source Code Form that results from an addition to,
        deletion from, or modification of the contents of Covered
        Software; or

    (b) any new file in Source Code Form that contains any Covered
        Software.

1.11. "Patent Claims" of a Contributor
    means any patent claim(s), including without limitation, method,
    process, and apparatus claims, in any patent Licensable by such
    Contributor that would be infringed, but for the grant of the
    License, by the making, using, selling, offering for sale, having
    made, import, or transfer of either its Contributions or its
    Contributor Version.

1.12. "Secondary License"
    means either the GNU General Public License, Version 2.0, the GNU
    Lesser General Public License, Version 2.1, the GNU Affero General
    Public License, Version 3.0, or any later versions of those
    licenses.

1.13. "Source Code Form"
    means the form of the work preferred for making modifications.

1.14. "You" (or "Your")
    means an individual or a legal entity exercising rights under this
    License. For legal entities, "You" includes any entity that
    controls, is controlled by, or is under common control with You. For
    purposes of this definition, "control" means (a) the power, direct
    or indirect, to cause the direction or management of such entity,
    whether by contract or otherwise, or (b) ownership of more than
    fifty percent (50%) of the outstanding shares or beneficial
    ownership of such entity.

2. License Grants and Conditions
--------------------------------

2.1. Grants

Each Contributor hereby grants You a world-wide, royalty-free,
non-exclusive license:

(a) under intellectual property rights (other than patent or trademark)
    Licensable by such Contributor to use, reproduce, make available,
    modify, display, perform, distribute, and otherwise exploit its
    Contributions, either on an unmodified basis, with Modifications, or
    as part of a Larger Work; and

(b) under Patent Claims of such Contributor to make, use, sell, offer
    for sale, have made, import, and otherwise transfer either its
    Contributions or its Contributor Version.

2.2. Effective Date

The licenses granted in Section 2.1 with respect to any Contribution
become effective for each Contribution on the date the Contributor first
distributes such Contribution.

2.3. Limitations on Grant Scope

The licenses granted in this Section 2 are the only rights granted under
this License. No additional rights or licenses will be implied from the
distribution or licensing of Covered Software under this License.
Notwithstanding Section 2.1(b) above, no patent license is granted by a
Contributor:

(a) for any code that a Contributor has removed from Covered Software;
    or

(b) for infringements caused by: (i) Your and any other third party's
    modifications of Covered Software, or (ii) the combination of its
    Contributions with other software (except as part of its Contributor
    Version); or

(c) under Patent Claims infringed by Covered Software in the absence of
    its Contributions.

This License does not grant any rights in the trademarks, service marks,
or logos of any Contributor (except as may be necessary to comply with
the notice requirements in Section 3.4).

2.4. Subsequent Licenses

No Contributor makes additional grants as a result of Your choice to
distribute the Covered Software under a subsequent version of this
License (see Section 10.2) or under the terms of a Secondary License (if
permitted under the terms of Section 3.3).

2.5. Representation

Each Contributor represents that the Contributor believes its
Contributions are its original creation(s) or it has sufficient rights
to grant the rights to its Contributions conveyed by this License.

2.6. Fair Use

This License is not intended to limit any rights You have under
applicable copyright doctrines of fair use, fair dealing, or other
equivalents.

2.7. Conditions

Sections 3.1, 3.2, 3.3, and 3.4 are conditions of the licenses granted
in Section 2.1.

3. Responsibilities
-------------------

3.1. Distribution of Source Form

All distribution of Covered Software in Source Code Form, including any
Modifications that You create or to which You contribute, must be under
the terms of this License. You must inform recipients that the Source
Code Form of the Covered Software is governed by the terms of this
License, and how they can obtain a copy of this License. You may not
attempt to alter or restrict the recipients' rights in the Source Code
Form.

3.2. Distribution of Executable Form

If You distribute Covered Software in Executable Form then:

(a) such Covered Software must also be made available in Source Code
    Form, as described in Section 3.1, and You must inform recipients of
    the Executable Form how they can obtain a copy of such Source Code
    Form by reasonable means in a timely manner, at a charge no more
    than the cost of distribution to the recipient; and

(b) You may distribute such Executable Form under the terms of this
    License, or sublicense it under different terms, provided that the
    license for the Executable Form does not attempt to limit or alter
    the recipients' rights in the Source Code Form under this License.

3.3. Distribution of a Larger Work

You may create and distribute a Larger Work under terms of Your choice,
provided that You also comply with the requirements of this License for
the Covered Software. If the Larger Work is a combination of Covered
Software with a work governed by one or more Secondary Licenses, and the
Covered Software is not Incompatible With Secondary Licenses, this
License permits You to additionally distribute such Covered Software
under the terms of such Secondary License(s), so that the recipient of
the Larger Work may, at their option, further distribute the Covered
Software under the terms of either this License or such Secondary
License(s).

3.4. Notices

You may not remove or alter the substance of any license notices
(including copyright notices, patent notices, disclaimers of warranty,
or limitations of liability) contained within the Source Code Form of
the Covered Software, except that You may alter any license notices to
the extent required to remedy known factual inaccuracies.

3.5. Application of Additional Terms

You may choose to offer, and to charge a fee for, warranty, support,
indemnity or liability obligations to one or more recipients of Covered
Software. However, You may do so only on Your own behalf, and not on
behalf of any Contributor. You must make it absolutely clear that any
such warranty, support, indemnity, or liability obligation is offered by
You alone, and You hereby agree to indemnify every Contributor for any
liability incurred by such Contributor as a result of warranty, support,
indemnity or liability terms You offer. You may include additional
disclaimers of warranty and limitations of liability specific to any
jurisdiction.

4. Inability to Comply Due to Statute or Regulation
---------------------------------------------------

If it is impossible for You to comply with any of the terms of this
License with respect to some or all of the Covered Software due to
statute, judicial order, or regulation then You must: (a) comply with
the terms of this License to the maximum extent possible; and (b)
describe the limitations and the code they affect. Such description must
be placed in a text file included with all distributions of the Covered
Software under this License. Except to the extent prohibited by statute
or regulation, such description must be sufficiently detailed for a
recipient of ordinary skill to be able to understand it.

5. Termination
--------------

5.1. The rights granted under this License will terminate automatically
if You fail to comply with any of its terms. However, if You become
compliant, then the rights granted under this License from a particular
Contributor are reinstated (a) provisionally, unless and until such
Contributor explicitly and finally terminates Your grants, and (b) on an
ongoing basis, if such Contributor fails to notify You of the
non-compliance by some reasonable means prior to 60 days after You have
come back into compliance. Moreover, Your grants from a particular
Contributor are reinstated on an ongoing basis if such Contributor
notifies You of the non-compliance by some reasonable means, this is the
first time You have received notice of non-compliance with this License
from such Contributor, and You become compliant prior to 30 days after
Your receipt of the notice.

5.2. If You initiate litigation against any entity by asserting a patent
infringement claim (excluding declaratory judgment actions,
counter-claims, and cross-claims) alleging that a Contributor Version
directly or indirectly infringes any patent, then the rights granted to
You by any and all Contributors for the Covered Software under Section
2.1 of this License shall terminate.

5.3. In the event of termination under Sections 5.1 or 5.2 above, all
end user license agreements (excluding distributors and resellers) which
have been validly granted by You or Your distributors under this License
prior to termination shall survive termination.

************************************************************************
*                                                                      *
*  6. Disclaimer of Warranty                                           *
*  -------------------------                                           *
*                                                                      *
*  Covered Software is provided under this License on an "as is"       *
*  basis, without warranty of any kind, either expressed, implied, or  *
*  statutory, including, without limitation, warranties that the       *
*  Covered Software is free of defects, merchantable, fit for a        *
*  particular purpose or non-infringing. The entire risk as to the     *
*  quality and performance of the Covered Software is with You.        *
*  Should any Covered Software prove defective in any respect, You     *
*  (not any Contributor) assume the cost of any necessary servicing,   *
*  repair, or correction. This disclaimer of warranty constitutes an   *
*  essential part of this License. No use of any Covered Software is   *
*  authorized under this License except under this disclaimer.         *
*                                                                      *
************************************************************************

************************************************************************
*                                                                      *
*  7. Limitation of Liability                                          *
*  --------------------------                                          *
*                                                                      *
*  Under no circumstances and under no legal theory, whether tort      *
*  (including negligence), contract, or otherwise, shall any           *
*  Contributor, or anyone who distributes Covered Software as          *
*  permitted above, be liable to You for any direct, indirect,         *
*  special, incidental, or consequential damages of any character      *
*  including, without limitation, damages for lost profits, loss of    *
*  goodwill, work stoppage, computer failure or malfunction, or any    *
*  and all other commercial damages or losses, even if such party      *
*  shall have been informed of the possibility of such damages. This   *
*  limitation of liability shall not apply to liability for death or   *
*  personal injury resulting from such party's negligence to the       *
*  extent applicable law prohibits such limitation. Some               *
*  jurisdictions do not allow the exclusion or limitation of           *
*  incidental or consequential damages, so this exclusion and          *
*  limitation may not apply to You.                                    *
*                                                                      *
************************************************************************

8. Litigation
-------------

Any litigation relating to this License may be brought only in the
courts of a jurisdiction where the defendant maintains its principal
place of business and such litigation shall be governed by laws of that
jurisdiction, without reference to its conflict-of-law provisions.
Nothing in this Section shall prevent a party's ability to bring
cross-claims or counter-claims.

9. Miscellaneous
----------------

This License represents the complete agreement concerning the subject
matter hereof. If any provision of this License is held to be
unenforceable, such provision shall be reformed only to the extent
necessary to make it enforceable. Any law or regulation which provides
that the language of a contract shall be construed against the drafter
shall not be used to construe this License against a Contributor.

10. Versions of the License
---------------------------

10.1. New Versions

Mozilla Foundation is the license steward. Except as provided in Section
10.3, no one other than the license steward has the right to modify or
publish new versions of this License. Each version will be given a
distinguishing version number.

10.2. Effect of New Versions

You may distribute the Covered Software under the terms of the version
of the License under which You originally received the Covered Software,
or under the terms of any subsequent version published by the license
steward.

10.3. Modified Versions

If you create software not governed by this License, and you want to
create a new license for such software, you may create and use a
modified version of this License if you rename the license and remove
any references to the name of the license steward (except to note that
such modified license differs from this License).

10.4. Distributing Source Code Form that is Incompatible With Secondary
Licenses

If You choose to distribute Source Code Form that is Incompatible With
Secondary Licenses under the terms of this version of the License, the
notice described in Exhibit B of this License must be attached.

Exhibit A - Source Code Form License Notice
-------------------------------------------

  This Source Code Form is subject to the terms of the Mozilla Public
  License, v. 2.0. If a copy of the MPL was not distributed with this
  file, You can obtain one at https://mozilla.org/MPL/2.0/.

If it is not possible or desirable to put the notice in a particular
file, then You may include the notice in a location (such as a LICENSE
file in a relevant directory) where a recipient would be likely to look
for such a notice.

You may add additional accurate notices of copyright ownership.

Exhibit B - "Incompatible With Secondary Licenses" Notice
---------------------------------------------------------

  This Source Code Form is "Incompatible With Secondary Licenses", as
  defined by the Mozilla Public License, v. 2.0.

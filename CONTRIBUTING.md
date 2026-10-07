# Contributing / 贡献指南

欢迎提交问题和 Pull Request。请说明可复现步骤、Android 版本、ABI、预期结果和实际结果；优先提供最小合成抓包，不要附带真实用户流量、凭据或未脱敏日志。

Please include reproduction steps, Android version, ABI, expected behavior, and actual behavior. Prefer minimal synthetic captures. Contributions are distributed under the project's GPL-3.0 license; third-party files retain their original licenses and attribution.

## 开发与验证

先按 [README.md](README.md) 安装工具链并运行 `python tools/fetch_native_deps.py`。Kotlin 使用 4 空格缩进；状态保留在 ViewModel 或 Compose 状态容器中。JNI 集成位于 `app/src/main/cpp/`，Android 日志标签为 `LayAnalyzer-JNI`。

```powershell
.\gradlew.bat testDebugUnitTest lintDebug assembleDebug assembleEmulator
.\gradlew.bat compileDebugAndroidTestKotlin
node tools/golden_capture/generate_golden_captures.mjs --check
node tools/agent_metrics/summarize.mjs --check
.\native_build\verification\rtp\run_host_tests.ps1
```

Linux/macOS 使用 `./gradlew`。主机 C++ 测试也可用 CMake 直接构建，见英文 README。设备测试使用 `connectedDebugAndroidTest`，需要已连接的 ARM64 Android 设备；编译测试源码不等于完成设备测试。

x86_64 模拟器使用同一源码的 Emulator instrumentation 变体，Compose 测试 Activity 已包含在该开发变体中：

```powershell
.\gradlew.bat -PlayanalyzerTestBuildType=emulator assembleEmulator assembleEmulatorAndroidTest
.\gradlew.bat -PlayanalyzerTestBuildType=emulator connectedEmulatorAndroidTest
```

`layanalyzerTestBuildType` 默认是 `debug`，只接受 `debug` / `emulator`；不要将 Debug 的测试 APK 当作 Emulator 的完整 UI 测试入口。Release 不包含 Compose 测试 Activity。VPN 捕获会固定使用启动时选定的物理网络，避免 VPN 成为默认网络后错误切换上游；该网络失联时停止捕获并标记证据不完整。

PR 请描述用户可见的变化、验证命令和结果，并说明是否影响 ABI、原生依赖或许可证。UI 修改附截图。请保持已有测试断言，不要通过跳过失败或放宽校验隐藏回归。

更新 Gradle 运行依赖时，按 [运行依赖许可核对](docs/dependency-licenses.md) 重新导出实际
`releaseRuntimeClasspath`，复核上游通知，并检查 APK 中的许可证全文和离线阅读入口。

## 测试数据

`tools/golden_capture/generate_golden_captures.mjs` 生成 16 个确定性的协议场景、SHA-256 清单和期望值。地址使用 RFC 5737 文档地址，域名使用 `.invalid`，不包含真实通信记录。应用冒烟测试使用的 `app/src/main/assets/test.pcap` 是其中 `ims_call_success` 场景的副本，由同一脚本生成并校验。两个 AMR 夹具由 `gen_amr_rtp_fixture.py` 使用独立编码器和合成信号生成。

以下外部样本及其派生结果暂缓随本仓库分发，待取得明确再分发依据后复核：`sip_g711a_bidirectional`、`g711u_loss_reorder`、`rtp_no_signal`、`srtp`、`sip_rtp_g722`、`sip_rtp_g726`、`sip_rtp_g729`、`sip_rtp_opus`、`sip_rtp_ilbc`。其来源为 [Wireshark SampleCaptures](https://gitlab.com/wireshark/wireshark/-/wikis/SampleCaptures)，原始附件未逐文件标注再分发条款。Wireshark 程序的许可证不能直接作为这些附件的授权依据。

依赖这些文件的设备测试保留原有断言，输入缺失时报错，不会因外部样本缺失而自动跳过。单元测试、原生算法测试及 16 个合成场景不依赖外部样本。若自行取得了适用的使用授权，可在本机准备以下输入；`.gitignore` 会排除外部样本和派生文件：

| 本地输入 | 来源或生成入口 |
|---|---|
| `sip_g711a_bidirectional.pcap` | SampleCaptures 的 `SIP_DTMF2.cap`，只改文件名 |
| `rtp_no_signal.pcap` | `RTP_L16_monaural_sample.pcapng`，用 `editcap -F pcap` 转换 |
| `srtp.pcap` | `Asterisk_ZFONE_XLITE.pcap`，只改文件名 |
| `g711u_loss_reorder.pcap` | `native_build/verification/rtp/make_fixture_g711u_loss_reorder.ps1`，从 `sip-rtp-g711.pcap` 派生 |
| G.722/G.726/G.729/Opus/iLBC | `native_build/verification/rtp/make_fixtures_m4.ps1`，下载时校验固定 SHA-256 |
| 流统计期望值 | `native_build/verification/rtp/make_golden_m1.ps1`，需要 tshark 4.0.10 |
| 参考音频 | `native_build/verification/rtp/make_golden_m4.ps1 -FfmpegPath <ffmpeg路径>` |

抓包放入 `app/src/androidTest/assets/rtp/`，参考结果放入其 `golden/` 子目录。[fixtures.json](native_build/verification/rtp/fixtures.json) 记录 25 个现有输入的 SHA-256、来源及派生关系。取得适用的使用授权后，可以从已有本地 RTP 目录补齐；工具先检查整套输入，再复制：

```powershell
python tools/prepare_rtp_fixtures.py --from-dir <本地RTP目录>
python tools/prepare_rtp_fixtures.py --check
.\gradlew.bat connectedDebugAndroidTest
```

全新克隆缺少 19 个暂缓分发的输入时，`--check` 会明确失败。两个 AMR 抓包及其四个派生文件已随源码保留。补齐输入与编译设备测试均不等于设备测试通过；测试仍可能因设备编码能力等原有条件跳过，须逐项报告。G.711 三种时序模式的手工参考 WAV 为另一组可选输入：使用 Wireshark 4.0.10 打开 G.711A 样本，在 Telephony → RTP → RTP Player 中分别选择 jitter buffer 50 ms、RTP timestamp、uninterrupted 模式导出 WAV，文件名按 `RtpAudioDecodeTest.goldenFile` 的约定放入 `golden/`。

参考 PCM 默认裁取前三秒、小端 16 位。AMR 参考使用 ffmpeg 的 libopencore-amr 解码器；ffmpeg 内置解码器对这组输入与其相关系数为 AMR-NB 0.9689、AMR-WB 0.9938，不能混用。iLBC 波形比较保留原有 N/A 条件和结构断言。Opus 参考 pre-skip 为 0；G.726 参考使用 RFC 3551 打包，AAL2 不与它进行逐字节比较。生成命令、工具版本及结果应随验证记录保存。

不要直接修改已有期望值，应从输入重新生成，并解释行为差异。手工合成音视频可使用 `make_manual_fixtures.ps1`，输出默认位于忽略的 `build/verification/rtp/manual-fixtures/`。

## 原生依赖重建

[native-sources.json](native_build/native-sources.json) 固定对应源码包和 SHA-256。先下载、校验，再解压到独立目录；包中已经应用 Android 源码修改，补丁也单独保留在 `native_build/patches/local-build/`，不要重复应用这些源码补丁。

```sh
python tools/check_native_source_archive.py --archive /path/to/native-sources-wireshark-4.0.10-r2.tar.gz
```

当前固定的 r2 归档需要另行应用 [构建兼容补丁](native_build/patches/rebuild/r2-build-compatibility.patch)：在每份独立解压目录的根目录执行 `patch -p1 < /path/to/LayerAnalyzer/native_build/patches/rebuild/r2-build-compatibility.patch`。它只修改构建脚本，修复 CMake 3.22.1 / NDK r27 下 x86_64 PCRE2 的策略错误、ARM64 c-ares 的 16 KB 链接参数，并避免已有 GLib 源码时重复下载。补丁哈希记录在源码清单的 `rebuildAdjustments` 中；不要把旧归档描述为已经包含这些修复。

依赖 Linux/WSL2、Linux 版 NDK `27.0.12077973`、C/C++ 主机编译器、CMake `3.22.1`、Ninja、Meson、Make、pkg-config、Python，以及常见的 Autotools 工具。本次验证使用 Meson 1.10.0、Ninja 1.10.1、Make 4.3、GCC 11.4.0、Python 3.10.12、pkg-config 0.29.2。设置 `ANDROID_NDK_HOME` 指向 Linux NDK，并确认 `cmake --version` 使用上述版本。在解压目录中按以下顺序构建：

| ABI | 脚本顺序（相对 `native_build/scripts/`） |
|---|---|
| `arm64-v8a` | `build_all.sh` → `build_gcrypt.sh` → `build_c_ares.sh` → `build_glib.sh` → `rebuild_wireshark_4.0.10.sh` |
| `x86_64` | `build_basic_libs_x86_64.sh` → `build_gcrypt_x86_64.sh` → `build_task3_x86_64.sh` → `build_task4_x86_64.sh` |

两个 ABI 使用不同的输出目录：`native_build/output/` 和 `native_build/output_x86_64/`。建议为不同 ABI 分别解压一份源码，避免 Autotools 的原地配置互相影响。构建后将依赖清单中的 14 个库从对应 `lib/` 目录复制到应用的 `app/src/main/cpp/libs/<abi>/`。

更新依赖时，必须同时核对对应源码、补丁、头文件、Wireshark 数据文件、两组 ABI 和校验清单，并检查每个动态库的所有 LOAD 段满足 16 KB 对齐。固定库与独立重建库的对应记录、编译配置差异及验证边界见 [原生来源与重建记录](docs/native-provenance.md)。双 ABI 已完成本地干净重建；完整重建尚未纳入 CI，也不承诺字节级重现。应用仍使用 `native-deps.json` 固定的 r1 库；独立候选通过验证后，需结合安全维护决定是否更换交付版本。

## 固定字节与签名

大多数 JSON/JSONL 文件使用 LF。`app/src/main/assets/scenario_package/` 中 manifest 固定的四个规则载荷签名时使用 CRLF；`.gitattributes` 对它们设置 `-text`，使克隆和源码归档都保留相同字节。不要格式化或重算清单来绕过校验；修改规则内容需要按规则包签名流程更新。`python tools/check_source_checkout.py` 检查这些输入和原生源码入口。

## 正式签名与发布

正式密钥保存在仓库外并单独备份。不要把 `.jks`、密码或 Base64 密钥放进提交。应用构建读取以下环境变量：

| 环境变量 | 内容 |
|---|---|
| `LAYERANALYZER_KEYSTORE_PATH` | 密钥库文件路径 |
| `LAYERANALYZER_KEYSTORE_PASSWORD` | 密钥库密码 |
| `LAYERANALYZER_KEY_ALIAS` | 密钥别名 |
| `LAYERANALYZER_KEY_PASSWORD` | 密钥密码 |

配置后运行 `assembleRelease`；分发渠道需要 AAB 时再运行 `bundleRelease`。GitHub Actions 的对应 Repository secrets 为 `RELEASE_KEYSTORE_BASE64`、`RELEASE_KEYSTORE_PASSWORD`、`RELEASE_KEY_ALIAS`、`RELEASE_KEY_PASSWORD`。普通 PR 的检查不读取签名 Secrets。

当前打包继续使用 Wireshark 4.0.10 / r1 二进制及 r2 对应源码；升级和安全补丁回移不作为本次打包前置条件，已知问题保留在 [安全维护评估](docs/wireshark-security-maintenance.md)。维护者设置 Repository variable `ENABLE_APK_PACKAGING=true` 后，只有推送 `v*` tag、前置检查通过才会生成签名 APK 附件及 GitHub Release 草稿；`workflow_dispatch` 不执行 package。标签必须等于 `v` 加 APK 的 `versionName`，新版本递增 `versionCode`，并准备 `docs/releases/<tag>.md`。CI 额外运行 Release 单元测试、lint、版本/ABI/不可调试检查、正式证书与 v2 签名验证、APK 16 KB ZIP 对齐检查。自动发布只生成 APK 和 SHA256SUMS；商店需要 AAB 时另外执行本地 `bundleRelease`。

发布附件仅为 `LayerAnalyzer-<架构>-<版本>.apk` 和 `SHA256SUMS`，从同一 staging 目录生成、校验和上传；例如 `LayerAnalyzer-arm64-v8a-1.0.0.apk`。源码、原生对应源码、构建与许可材料通过 Release 说明中的固定提交/版本链接提供，许可证全文仍随 APK 打包。实际依赖清单仅用于构建校验，不上传源码包、SBOM 或额外清单。详见 [发布附件流程](docs/release-packaging.md)。独立 `release-draft` job 从同次运行的 artifact 创建草稿，核对远端附件集合和哈希；仅该 job 拥有 `contents: write`，不读取签名 Secrets。工作流不会发布 Release，也不覆盖已发布附件。下载本次 CI APK 完成设备验收并记录结果后，再手工发布草稿。正式证书公开指纹固定在 `tools/release-signing-certificate.sha256`；私钥应与本地正式版相同。原生 ZIP 与源码包使用固定 tag 和 SHA-256；更新时创建新版本，不覆盖已经发布的文件。

## 其他工具

`tools/agent_metrics/summarize.mjs --jsonl <文件或目录> --format json --out <路径>` 汇总诊断计数，`--check` 校验合成数据与固定期望结果。新的诊断指标需要同步注册到脚本的 `METRICS` 表。

`tools/collect_baseline.py --label <标签> --out-dir baselines` 从已连接设备收集诊断信息，结果保持本地。`native_build/scripts/sign_scenario_package.py` 用于签署场景规则包，使用独立的 RSA 密钥，与 APK 签名无关。

# LayerAnalyzer

[English](README.en.md)

LayerAnalyzer 是一个基于 Wireshark 4.0.10 的 Android 网络抓包与分析工具，使用 Kotlin、Jetpack Compose 和 C++ JNI 实现。

原作者与维护者：[cheig](https://github.com/cheig)。原项目仓库：[cheig/LayerAnalyzer](https://github.com/cheig/LayerAnalyzer)。原创代码 Copyright (c) 2026 cheig；作者与贡献说明见 [AUTHORS.md](AUTHORS.md)，版权说明见 [COPYRIGHT](COPYRIGHT)。

当前固定原生库尚未回移安全修复，4.0 系列已停止上游维护；已知问题、未决项和安装包验收边界见 [安全维护评估](docs/wireshark-security-maintenance.md)。

## 功能

- 打开 PCAP/PCAPNG，分页浏览数据包、协议树、字节数据和 Wireshark 显示过滤结果。
- 查看协议统计、通信关系、TCP/UDP 流，提取 HTTP 对象。
- 通过 Android VPN 接口采集设备流量；启用时需要用户授予 VPN 权限。
- 分析 SIP、RTP 和 RTCP，查看流统计与通话关系，播放或导出支持的音频与视频。
- 可选的 AI 辅助分析：配置自己的服务和 API 密钥，通过隐私模式控制发送给模型的数据；结论包含可核查的数据包证据。

Android 8.0（API 26）及以上。正式安装包面向 ARM64；开发构建同时支持 x86_64 模拟器。

## 应用截图

点击截图可查看原图。

| 数据包列表 | 协议解析 | 字节视图 |
|:---:|:---:|:---:|
| <a href="assets/images/Screenshot_2026-10-05-12-50-42-652_com.layeranalyzer.android-edit.jpg"><img src="assets/images/Screenshot_2026-10-05-12-50-42-652_com.layeranalyzer.android-edit.jpg" width="240" alt="数据包列表，展示 SIP 与 H.264 数据包摘要"></a> | <a href="assets/images/Screenshot_2026-10-05-12-51-00-179_com.layeranalyzer.android-edit.jpg"><img src="assets/images/Screenshot_2026-10-05-12-51-00-179_com.layeranalyzer.android-edit.jpg" width="240" alt="数据包协议树，展开 SIP 与 SDP 字段"></a> | <a href="assets/images/Screenshot_2026-10-05-13-04-58-044_com.layeranalyzer.android-edit.jpg"><img src="assets/images/Screenshot_2026-10-05-13-04-58-044_com.layeranalyzer.android-edit.jpg" width="240" alt="数据包字节视图，展示十六进制与 ASCII 内容"></a> |

| 洞察与分析工具 | VPN 流量抓取 | 视频预览 |
|:---:|:---:|:---:|
| <a href="assets/images/Screenshot_2026-10-05-13-03-30-323_com.layeranalyzer.android-edit.jpg"><img src="assets/images/Screenshot_2026-10-05-13-03-30-323_com.layeranalyzer.android-edit.jpg" width="240" alt="洞察页面，展示文件概况、场景模板和协议分析工具"></a> | <a href="assets/images/Screenshot_2026-10-05-13-04-05-274_com.layeranalyzer.android-edit.jpg"><img src="assets/images/Screenshot_2026-10-05-13-04-05-274_com.layeranalyzer.android-edit.jpg" width="240" alt="VPN 流量快照，配置应用范围、自动停止和抓包大小上限"></a> | <a href="assets/images/Screenshot_2026-10-05-12-51-26-626_com.layeranalyzer.android-edit.jpg"><img src="assets/images/Screenshot_2026-10-05-12-51-26-626_com.layeranalyzer.android-edit.jpg" width="240" alt="RTP 视频预览，支持播放控制和跳转到关联数据包"></a> |

| AI 分析过程 | AI 分析报告 | AI 模型设置 |
|:---:|:---:|:---:|
| <a href="assets/images/Screenshot_2026-10-05-12-52-41-074_com.layeranalyzer.android.jpg"><img src="assets/images/Screenshot_2026-10-05-12-52-41-074_com.layeranalyzer.android.jpg" width="240" alt="AI 分析过程，展示媒体流分析的工具调用与进度"></a> | <a href="assets/images/Screenshot_2026-10-05-12-58-21-989_com.layeranalyzer.android-edit.jpg"><img src="assets/images/Screenshot_2026-10-05-12-58-21-989_com.layeranalyzer.android-edit.jpg" width="240" alt="AI 分析报告，包含媒体流结论、数据包引用和不确定性说明"></a> | <a href="assets/images/Screenshot_2026-10-05-13-00-32-735_com.layeranalyzer.android-edit.jpg"><img src="assets/images/Screenshot_2026-10-05-13-00-32-735_com.layeranalyzer.android-edit.jpg" width="240" alt="AI 模型设置，配置自定义供应商、重试次数和请求超时"></a> |

## 安装

从 [GitHub Releases](https://github.com/cheig/LayerAnalyzer/releases) 下载 ARM64 安装包及 SHA256SUMS，具体版本的验证范围见对应发布说明。本仓库提供完整应用源码。当前打包继续使用固定的 Wireshark 4.0.10 / r1 原生库，升级和安全补丁回移作为后续维护工作。开发构建入口见下文，已知问题见 [安全维护评估](docs/wireshark-security-maintenance.md)。

应用内通过“偏好设置 → 关于 LayerAnalyzer”查看作者与项目地址，支持复制地址及打开项目仓库。

## 构建

需要 JDK 17、Android SDK 34、NDK `27.0.12077973`、CMake `3.22.1` 和 Python 3.10+。可通过 Android Studio 的 SDK Manager 安装 Android 工具链。设置 `ANDROID_HOME`，或在未跟踪的 `local.properties` 中指定 `sdk.dir`。

```powershell
git clone https://github.com/cheig/LayerAnalyzer.git
cd LayerAnalyzer
python tools/fetch_native_deps.py
.\gradlew.bat assembleDebug
```

Linux/macOS 使用 `./gradlew`。原生库下载脚本按 [依赖清单](native_build/native-deps.json) 校验压缩包及每个库的 SHA-256，无需 GitHub Token。所有隧道库源码已包含在仓库中，无需初始化子模块。

| 用途 | Windows 命令 | 产物 |
|---|---|---|
| ARM64 调试 | `.\gradlew.bat assembleDebug` | `app/build/outputs/apk/debug/app-debug.apk` |
| x86_64 模拟器 | `.\gradlew.bat assembleEmulator` | `app/build/outputs/apk/emulator/app-emulator.apk` |
| 安装 ARM64 调试版 | `.\gradlew.bat installDebug` | 安装到已连接设备 |
| 安装模拟器版 | `.\gradlew.bat installEmulator` | 安装到 x86_64 模拟器 |

调试构建使用开发机自己的默认 Android 调试密钥。正式构建通过环境变量配置签名，详见 [CONTRIBUTING.md](CONTRIBUTING.md)。不同签名的安装包不能直接覆盖更新。

固定依赖 Release 同时提供二进制 ZIP、完整原生源码、构建补丁、许可材料和 SHA256SUMS。下载无需 GitHub Token；持有该 ZIP 时也可运行 `python tools/fetch_native_deps.py --archive <ZIP路径>`，校验标准相同。

## 原生依赖与源码

Wireshark 及依赖的预编译库单独存放在 [LayerAnalyzer_libs](https://github.com/cheig/LayerAnalyzer_libs/releases/tag/wireshark-4.0.10-r1)。ZIP 约 154 MiB，解压约 577 MiB，包含 `arm64-v8a` 和 `x86_64` 两组库。

[对应源码清单](native_build/native-sources.json) 记录完整原生源码包的地址、校验值、上游版本与本地修改。源码包包含 Wireshark、GLib、libgcrypt、libgpg-error、c-ares、libffi、PCRE2、zlib、libiconv 的源码，以及 Android 构建脚本和补丁。29 个 Wireshark 参考文件另外保留在 `app/src/main/cpp/third_party/wireshark-reference/`，不替代完整源码包。

原生依赖重建需要 Linux 或 WSL2 和 Linux 版 NDK。固定 r2 源码包需要先应用已记录的构建脚本兼容补丁，具体入口及依赖顺序见 [CONTRIBUTING.md](CONTRIBUTING.md#原生依赖重建)。两种 ABI 已完成独立重建，来源证据、配置差异及验证边界见 [原生来源与重建记录](docs/native-provenance.md)。常规应用构建仍使用已经固定并校验的 r1 预编译库；不承诺字节完全相同的重建结果。

## 验证与贡献

```powershell
.\gradlew.bat testDebugUnitTest lintDebug
node tools/golden_capture/generate_golden_captures.mjs --check
node tools/agent_metrics/summarize.mjs --check
.\native_build\verification\rtp\run_host_tests.ps1
```

工具自检需要 Node.js 18+；原生算法测试需要主机 C++ 编译器和 CMake。测试数据、可选外部样本和贡献方式见 [CONTRIBUTING.md](CONTRIBUTING.md)。安全问题请按 [SECURITY.md](SECURITY.md) 私下报告。

## 许可证与使用范围

LayerAnalyzer 按 **GNU GPL 第 3 版（GPL-3.0）**发布，完整条款见 [LICENSE](LICENSE)。G.729 解码器 bcg729 默认开启；关闭 `-PlayanalyzerEnableG729=false` 只会禁用该编码器，不改变本项目许可证。iLBC 默认关闭，可通过 `-PlayanalyzerEnableIlbc=true` 启用。

Wireshark、GLib、spandsp、bcg729 等组件继续适用各自的许可证，详见 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。分发修改后的程序或二进制时，请履行相应的源码和版权声明义务。

仅分析你有权访问的网络和数据。抓包、诊断日志及导出内容可能包含敏感信息；启用远程 AI 服务前请检查所选隐私模式。AI 分析应结合原始证据核实。本软件按许可证约定不提供担保。

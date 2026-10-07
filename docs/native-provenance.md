# Native source and build provenance

核对日期：2026-10-06。适用范围为 `native-deps-wireshark-4.0.10-r1.zip` 与
`native-sources-wireshark-4.0.10-r2.tar.gz`。本记录不表示已经修复 Wireshark 安全问题或完成远端发布。

## 固定输入与验证结果

应用继续使用 [native-deps.json](../native_build/native-deps.json) 固定的 r1 库。
九个源码项目、19 份本地源码补丁和额外支持文件已逐文件核对；两个 ABI 均已从独立解压目录完成构建。
重建需要应用下述构建脚本兼容补丁。新产物保持为独立候选，没有替换应用固定库。

| 输入 | SHA-256 |
|---|---|
| 固定原生二进制 r1 | `617468873eea9b69bd430736b1419fe684b871d0ddbe81a6d94258086b132c7d` |
| 固定原生源码 r2 | `a58ef11f89f6ad8c961ad0963dba92feb51d5c48f067a491a339fe1e1b647ecd` |
| 本次独立重建候选 ZIP | `2eda03a925658bee5a72c16e6bca9bbd6e804cddcca36bb5d965efd188e56204` |

候选 ZIP 的哈希用于识别本次本地验证产物，不是新增的公开下载入口。
[机器可读记录](../native_build/provenance/wireshark-4.0.10-r1.json) 包含两个 ABI 的逐库哈希、
原输出匹配结果、ELF 段比较、动态依赖、工具链、组件配置和构建脚本哈希。

固定的 28 个库全部与保留的原构建输出逐字节一致。原构建目录中的源码与 r2 归档只存在三处预期差异：
zlib 的 Makefile 由 configure 生成；Wireshark 的 `tools/make-version.py` 和
`packaging/source/git-export-release.sh.in` 在归档时正确展开了 Git export-subst 元数据。
归档不需要原始 `.git`。保留的配置、逐文件核对及本次干净重建共同支持来源对应关系；
不存在当年生成的签名构建证明，也不承诺字节级重现。

## 九个组件及源码修改

| 组件 | 精确输入 | 本地源码修改 / 支持文件 |
|---|---|---|
| Wireshark | 4.0.10，`f5c7c25a81ebd5e2cd431f9e2d424586c6250812` | 2 个文件：Host Lemon 使用方式、Android `sysconf(_SC_OPEN_MAX)` |
| GLib | 2.80.0 | 15 个 Android/禁用 NLS 适配文件；空 `.patched` 标记 |
| libgcrypt | 1.11.0 | 无源码修改 |
| libgpg-error | 1.50 | configure 的弱线程宏修改；6 个 Android 锁结构支持头文件 |
| c-ares | 1.34.4，`b82840329a4081a1f1b125e6e6b760d4e1237b52` | 无源码修改 |
| libffi | 3.4.6 | 无源码修改 |
| PCRE2 | 10.42 | 无源码修改 |
| zlib | 1.3.1 | configure 生成的 zconf.h 差异 |
| libiconv | 1.17 | 无源码修改 |

各上游归档 SHA-256、组件归档树哈希及新增文件哈希见
[native-sources.json](../native_build/native-sources.json)。19 个文件差异与
`native_build/patches/local-build/` 中的补丁逐项一致，补丁已应用在 r2 源码中。
Wireshark 和 c-ares 的部分文本相对 Git 导出仅有 CRLF/LF 差异；逐组件树哈希使用归档实际字节，
源码差异核对单独识别行尾差异，没有修改归档。

六个 libgpg-error 支持头文件已包含在原归档，本次补充到清单的 `addedFiles`：
两个 aarch64 文件彼此相同，保存 Android 锁结构定义；四个通用/x86_64 文件与上游
`lock-obj-pub.x86_64-unknown-linux-gnu.h` 逐字节相同。原脚本会为 x86_64 再复制这些定义。
它们是构建输入，不能因未列入早期 `modifiedFiles` 而遗漏。

## 构建入口与修正

完整顺序及安装步骤见 [CONTRIBUTING.md](../CONTRIBUTING.md#原生依赖重建)。本次使用 Linux NDK
27.0.12077973、Android API 26、Clang/LLD 18.0.1、CMake 3.22.1、Meson 1.10.0、Ninja 1.10.1。
两个 ABI 分别解压，避免原地 Autotools 配置互相覆盖；构建依赖来自各自输出目录。

r2 归档没有重打包，使用前须应用
[r2-build-compatibility.patch](../native_build/patches/rebuild/r2-build-compatibility.patch)。它仅修改三个脚本：

- x86_64 PCRE2：明确 `CMP0057=NEW`，解决 NDK r27 的 `IN_LIST` 配置错误。原 x86_64 记录使用 CMake 4.2.1，并另设过 `CMAKE_POLICY_VERSION_MINIMUM=3.5`；本次按文档统一验证 3.22.1。
- ARM64 c-ares：显式传入 16 KB shared linker flags。单独设置环境 `LDFLAGS` 在此 CMake/NDK 配置中没有保留下来，原脚本的干净输出只有 4 KB 对齐。修复后仅重新编译 c-ares，并复验所有输出。
- ARM64 GLib：已有完整源码目录时不再下载一次上游 tarball。

兼容补丁的哈希记录在 `rebuildAdjustments`。早期归档内的 `SOURCE_MANIFEST.json` 是当时快照；
本次补充的树哈希、支持文件及兼容补丁记录位于应用仓库清单，必须与 r2 一起提供。
若后续重新打包这些材料，应创建新的源码修订，不覆盖固定 r2。

构建配置保留原有 ABI 差异：ARM64 Wireshark 是 Release，x86_64 是 RelWithDebInfo；
两者都有 NDK 调试信息，但优化级别和 Wireshark assertion/debug 宏不同。
ARM64 PCRE2 使用 Autotools 并启用 JIT，x86_64 使用 CMake 默认关闭 JIT。
这些差异不应通过只比较跨 ABI 哈希来判断。脚本中的 `ENABLE_GCRYPT=OFF` 不是有效的禁用证据：
Wireshark 4.0.10 不使用这个选项，实际库仍链接 libgcrypt。

## 二进制差异的解释

| 对象 | 核对结果 |
|---|---|
| ARM64 14 个输出 | 6 个逐字节相同，8 个不同，与历史计数一致；本次使用 r2 实际重建重新确认 |
| x86_64 14 个输出 | 5 个逐字节相同，9 个不同；已完成全量重建 |
| 两种 ABI 的 gmodule/gobject/gthread | 所有分配段相同；差异限于调试信息、部分符号表 |
| ARM64 c-ares（对齐修复后） | 代码和数据段相同；差异为调试信息、符号表、build-id |
| x86_64 Wireshark / wiretap | 除 build-id 外的所有分配段相同；其余差异是调试信息 |
| x86_64 PCRE2 静态库 | 27 个目标文件的分配段全部相同；归档字节不同 |
| 两种 ABI 的 GLib / wsutil | `.rodata` 中识别到构建时安装目录差异，伴随地址布局/重定位及调试信息差异 |
| x86_64 c-ares | `.rodata` 中识别到两个 assertion 的源码路径差异，伴随布局/重定位及调试信息差异 |
| ARM64 Wireshark / wiretap | 原库链接 Android 系统 `libz.so`，脚本干净重建链接随包 `libz.a`；这是实际链接配置变化 |

ARM64 新 wiretap 增加了静态 zlib 的导出符号，没有删除旧导出符号。其他动态库的已定义符号集合保持一致。
路径字符串的差异是直接观察结果；没有将所有存在机器码差异的库宣称为逐指令等价。
未发现归档与已核对源文件之间未记录的功能源码修改。

新旧两套库的所有 20 个动态库均已检查 LOAD 段对齐；最终重建候选全部满足 16 KB。
每个 ELF 的架构、SONAME 和 NEEDED 记录在 JSON 中。无论是否保留现有库，
未来修改组件后都应复验实际链接、依赖闭包和应用行为，不能只检查 SHA-256 是否相同。

## 应用验证与交付边界

本次候选在从提交 `f848d155c390dc875131e6c261dd8ff2672c8e49` 导出的独立应用目录中验证。
该目录替换原生依赖清单/库，使用独立测试 application ID，并同步本次测试入口修正；正式应用的固定库、签名和用户数据未替换。
修正将 Golden 资产从测试 APK 读取，并等待 Application 已有的引擎初始化，避免测试重复注册 Wireshark 字段。
测试的协议、会话和 Mock Agent 断言保持原样，没有添加跳过条件。

| 检查 | 结果 |
|---|---|
| 独立源码导出的 ARM64 / x86_64 APK、测试 APK | 构建通过；121 个 Gradle 任务全部执行 |
| JVM 测试 | 2179 项通过，失败/错误/跳过均为 0 |
| Debug lint | 无错误，125 Warning、13 Information |
| x86_64 / Android 16 模拟器，候选库 | 11 项设备测试完成，10 项通过；Mock Agent 调用数断言期望 2、实际 3 |
| x86_64 / 原 r1 对照 | 同一 Mock Agent 断言失败；16 个 Golden 抓包的原生协议检查通过 |
| ARM64 / Android 16 真机，候选库 | 初始化和两项聚焦检查通过；Golden 检查及后续并发压力检查出现停滞，已停止测试 |
| ARM64 / 原 r1 对照 | 同一 Golden 测试也停滞，120 秒后停止；不能判为设备验收通过 |

真机两项已通过检查为 TCP Boolean 字段统计和重复详情读取。它们不能替代未完成的 Golden / 并发验收。
上述对照表明当前问题并非仅在重建库上出现，尚未确定 ARM64 停滞的根因。
因此候选集成验收未通过，不能将其标记为可直接替换的发布依赖，也没有放宽 Mock Agent 调用数断言。

当前结论不包括 Wireshark 安全补丁验收、外部 RTP 夹具的完整回归、正式签名发布、
最终源码归档或匿名下载验证。原库和重建候选都保留 4.0.10 功能源码基线；
重建本身不会修复已知漏洞。最终分发版本应在安全维护方案确定后选择。

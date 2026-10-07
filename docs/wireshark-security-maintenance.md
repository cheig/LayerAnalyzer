# Wireshark 安全维护评估

评估日期：2026-10-06。当前固定依赖仍是 **Wireshark 4.0.10 / 原生二进制 r1**，没有集成安全修复。
本记录交付风险清单、回移可行性证据和后续验证方案；不表示安装包已经通过安全验收。

## 当前结论

2026-10-07 更新：**当前 APK 打包继续使用 Wireshark 4.0.10；升级和安全补丁回移不作为本次打包前置条件**。
当前 r1 二进制和 r2 对应源码保持不变；部分安全补丁试验不进入交付基线。
升级、漏洞适用性审查、回移和漏洞回归继续作为后续维护任务，以下未修复及未决状态保持。
最终 Release 构建、签名、许可、设备验证及附件对应关系仍需验收，流程见 [发布附件说明](release-packaging.md)。
此次决定替代 2026-10-06 因安全整改暂缓正式 APK 的安排；此前的安全评估证据继续保留。
保留 4.0.10 作为长期二进制基线，需要承担停止维护后的漏洞适用性审查、回移和回归工作；
仅回移最初报告的三个 CVE，或升级到 4.0.17，都不足以证明已经处理当前已知风险。

官方 [生命周期](https://www.wireshark.org/docs/wsug_html_chunked/ChIntroReleaseLifeCycle.html)
记载 4.0 系列于 **2024-08-28** 停止支持；[4.0.17 发布说明](https://www.wireshark.org/docs/relnotes/wireshark-4.0.17.html)
明确它是最后一个 4.0 版本。评估日官方安全公告列出的受维护修复版本为 4.6.9 / 4.4.19。
这些是迁移比较对象，尚未在本项目中编译或验收，不能直接替换固定库。

## 公告覆盖与未决范围

已保存并核对官方索引中 2023–2026 年的 **162 项公告**，截至 `wnpa-sec-2026-110`。
完整 [逐项表](wireshark-security-advisories.md) 和 [机器可读清单](../native_build/security/wireshark-4.0.10-review.json)
包含 CVE、官方版本范围、修复候选、构建证据和处理状态。

| 状态 | 数量 | 含义 |
|---|---:|---|
| 基线已含官方修复 | 27 | 官方修复版本早于 4.0.10 |
| 官方范围含 4.0.10，当前库未修复 | 8 | 相关组件在两种 ABI 中存在，见下表 |
| 当前 APK 的触发路径排除 | 15 | Editcap、sharkd、ciscodump、Qt profile import、Wireshark codec plugins；依据见清单 |
| 后续修复与旧源码匹配，待验证 | 3 | 已人工检查危险代码，不能因公告没列 4.0 而排除 |
| 尚需完成适用性审查 | 109 | 保留为未决项，不视为不受影响 |

这是公告盘点和部分适用性核查，**不是完整漏洞闭环**。停止维护后，公告常只列受支持系列，
不能用版本范围缺少 4.0 来证明安全。清单也不替代 GLib、PCRE2、c-ares、编解码器及其他依赖的独立审查。
上游有些公告存在缺损的 issue 链接、不可公开读取的 issue 或正文不完整；相应项保留未决状态。

| 公告 / CVE | 组件与入口 | 4.0 分支修复提交 | 处理 |
|---|---|---|---|
| [2023-28](https://www.wireshark.org/security/wnpa-sec-2023-28.html) / CVE-2023-6174 | SSH，报文解析 | `28ad7bdb6711e7f9d9a42c4b495d16ca7cb2d9b4` | 待回移、编译和回归 |
| [2023-29](https://www.wireshark.org/security/wnpa-sec-2023-29.html) / CVE-2023-6175 | NetScreen，文件自动识别/读取 | `160d1e454a7ea12d002e87575aa0564c586eb77d` | 待回移、编译和回归 |
| [2024-01](https://www.wireshark.org/security/wnpa-sec-2024-01.html) / CVE-2024-0208 | GVCP，报文解析 | `0a0669c9d43a586e87bc5aec6f80d16a9391055f` | 待回移、编译和回归 |
| [2024-02](https://www.wireshark.org/security/wnpa-sec-2024-02.html) / CVE-2024-0209 | IEEE 1609.2 / ASN.1 递归 | `496679c1c3f9dfaaee8ec9303e149ba3f4114ad3` | 必须一起审查生成器、生成代码及后续修正 |
| [2024-06](https://www.wireshark.org/security/wnpa-sec-2024-06.html) / CVE-2024-2955 | T.38，报文解析/重组 | `c04f268605c7035c8907d72aec0508bc487e5381` | 待回移、编译和回归 |
| [2024-07](https://www.wireshark.org/security/wnpa-sec-2024-07.html) / CVE-2024-4854 | MONGO，报文解析 | `dd5b3b36d3e2442d72e60be334d65b01653e8f92` | MONGO 适用；合并标题中的 ZigBee TLV 源文件不在 4.0.10 中 |
| [2024-10](https://www.wireshark.org/security/wnpa-sec-2024-10.html) / CVE-2024-8645 | SPRT，SIP/SDP 协商后的媒体流 | `cc67f836c01b6f55f2ff70aa4df44a1b934d7404` | 待回移、编译和回归 |
| [2024-11](https://www.wireshark.org/security/wnpa-sec-2024-11.html) / CVE-2024-8250 | NTLMSSP，认证报文解析 | `ce871c20cdc69b494d73923b99ce4410e6ffe7ab` | 待回移、编译和回归 |

另外两项明确列出 4.0.10 的公告是 CVE-2024-4853 / CVE-2024-4855（Editcap）。
它们的排除仅适用于当前 APK：APK 没有 editcap，也没有调用对应裁剪/秘密注入路径。
特别是 4855 的修复还涉及 libwiretap DSB 所有权；已核对应用不调用 `wtap_dump_*`、不重用 `dsbs_initial`，
导出由 [PcapWriter.cpp](../app/src/main/cpp/layanalyzer/export/PcapWriter.cpp) 等代码直接写 PCAP。
原生重建的 `BUILD_editcap=ON`，若另行分发其可执行文件，必须重新纳入这两项。

人工检查的三项后续风险：

- [2024-13](https://www.wireshark.org/security/wnpa-sec-2024-13.html)：AppleTalk 地址复制和 RELOAD transaction key 路径仍存在；两个修复在 4.0.10、4.0.17 上都可原样应用。
- [2025-04](https://www.wireshark.org/security/wnpa-sec-2025-04.html)：MONGO `dissect_op_msg_section` 仍计算未经该修复检查的 `1 + section_len`；上游增加负数和 `INT32_MAX` 拒绝逻辑。两个旧版本都有该代码，补丁 include 上下文需人工适配。
- [2026-110](https://www.wireshark.org/security/wnpa-sec-2026-110.html)：Catapult DCT2000 NR-UP 固定 200 字节数组与按输入字符串长度执行的填充逻辑仍存在；上游改为使用实际截断后的长度。修复在两个旧版本上均可原样应用。

以上是源码与修复对照，尚未在 APK 上执行漏洞输入；不宣称已复现，也不将补丁能应用视为修复有效。
部分上游问题涉及越界读写或内存生命周期，风险不应统一缩写成“仅会崩溃”；本项目没有完成代码执行可利用性评估。

## 实际输入与构建证据

- URI 导入经 [PacketListViewModel](../app/src/main/java/com/example/layanalyzer/viewmodel/PacketListViewModel.kt) 复制到私有目录，随后由 [PacketListJni.cpp](../app/src/main/cpp/layanalyzer/jni/PacketListJni.cpp) 调用 `wtap_open_offline(..., WTAP_TYPE_AUTO, ...)`。文件名或选择器文字不是格式白名单，NetScreen 注册在 Wiretap 自动识别表中。
- [EngineLifecycle.cpp](../app/src/main/cpp/layanalyzer/jni/EngineLifecycle.cpp) 的 `wtap_init(FALSE)` 和 `epan_init(..., FALSE)` 禁用插件加载，仍注册内置文件解析器和协议。两种固定库都具有上述 7 个协议注册符号及 `netscreen_open`；T3 两种 ABI 的编译记录也包含对应源文件。
- [WiresharkSession.cpp](../app/src/main/cpp/layanalyzer/session/WiresharkSession.cpp) 调用 `epan_dissect_run` / `epan_dissect_run_with_taps`。已有 Wireshark 异常边界能处理其正常异常，不能兜底 native 内存破坏、进程信号、无限循环或所有递归耗尽。
- VPN 输出的 RAW IP 约束只作用于 VPN 生成的文件，不能约束用户导入抓包。网络内容仍是非可信输入。
- `ENABLE_GCRYPT=OFF` 不是禁用证据：4.0.10 未使用该开关，实际库仍链接 libgcrypt。类似地，关闭某个可选解码后端不等于关闭内置协议解析器。
- 排除 Wireshark codec plugins 使用 `ENABLE_PLUGINS=OFF`、实际配置和 APK 内容；不据此排除应用自己的媒体实现。G.729 默认开、iLBC 默认关的既有策略未更改。

固定库来源和构建配置见 [原生来源记录](native-provenance.md)。上述证据支持组件存在和调用入口，
没有逐个验证每个漏洞的全部运行触发条件。

## 回移和升级的实际成本

在独立源码目录，对原始 `v4.0.10` 加上现有两份 Android 适配后，依次应用表中 8 个修复，
并在 ASN.1 修复之后加入上游修正 `5d37436c1a1efcd599a91aef94284a6929618f8e`。
9 个安全相关提交均可应用，`git diff --check` 通过；连同 Android 适配共改变 45 个文件。
该目录只是**部分修复的源码试验**，没有编译成候选库，也没有替换 r1；不能用于发布。

ASN.1 主修复改变 34 个文件，后续修正改变 19 个文件，二者有重叠。
4.0.10→4.0.17 的完整差异为 **387 个文件、13459 行新增、3676 行删除**，包括非 CVE 的递归检查和协议修正。
此外已比较 132 个上游修复候选的上下文：40 个可直接应用到 4.0.10，29 个可直接应用到 4.0.17；
它们包含已列公告及不交付的组件，不能把数量当作实际漏洞数。另有 16 个候选未取得对应 diff。
匹配失败也不证明安全，可能只是变量类型、include、其他修复或文件布局发生变化。

| 路线 | 可以保留什么 | 必须完成什么 | 评估 |
|---|---|---|---|
| 暂留 4.0.10，用于当前 APK 打包 | 当前 JNI、r1 二进制与 r2 源码、既有构建经验 | 如实披露未修复状态；完成最终 Release 与分发验收 | **2026-10-07 已选择**；升级和回移留作后续维护 |
| 4.0.10 全面回移 | 较多原有接口和行为 | 审完 109 个未决项、后续源码匹配项及非 CVE 修正；维护补丁依赖闭包 | 9 个试验补丁只是起点；需要持续承担 EOL 分支维护 |
| 改为 4.0.17 再回移 | 同系列接口，纳入累计修正 | 387 文件差异回归，仍需处理 EOL 后漏洞 | 比逐个重建早期修复依赖可能更省事，但不是当前安全终点 |
| 独立迁移到受维护系列 | 可继续跟随上游补丁发布 | JNI/epan/wiretap、字段、媒体、构建与数据文件迁移；双 ABI 回归 | 正式 APK 的长期方向建议；尚无本项目迁移耗时或兼容性结论 |

不能仅凭文件数量承诺工期。T3 本机记录中 Wireshark 单组件构建约 ARM64 132.5 秒、x86_64 135.3 秒，
属于历史实测而非本次重建；主要不确定性是适用性审查、补丁依赖和设备行为。
仅改变 Wireshark 且接口兼容时，可以复用已验证的其他依赖，重新构建受影响库及必要依赖，
无需为追求哈希相同重复重建九个组件。

## 后续安全维护的实施与验收

以下工作作为后续安全维护任务保留，不阻塞本次使用固定 r1 库打包，也不标记为已经完成。将来引入安全补丁或更换库版本时，按以下要求验证新的二进制与对应源码。

1. 为每项保留公告、精确上游提交、原始补丁哈希、Android 适配、依赖顺序、输入和结论。修复提交关联有歧义时继续标为未决。
2. 在独立候选中构建；若回移，标识为 `4.0.10 + LayerAnalyzer 安全修订/补丁集`。使用上游版本扩展及补丁清单，不冒充未修改的 4.0.10。最终库选择前不改固定清单。
3. 使用 JDK 17 / SDK 34 / Linux NDK 27.0.12077973 / CMake 3.22.1，保留并说明 ABI 优化配置。检查原生初始化顺序、共享 Session lease、同步、取消和 generation 保护。
4. 对每个适用漏洞运行修复前/后的输入对照；崩溃/耗时输入置于独立测试进程或设备测试包，以外部 watchdog 限制时间和资源。单次和多次读取、建树、过滤、重组都要覆盖。正常拒绝畸形输入是可接受结果；仅“不崩溃一次”不足以验收。
5. 已取得 SSH、GVCP、T.38、2024/2025 MONGO 的 5 份官方 fuzz 文件和 SHA-256，尚未执行，保存在本地证据目录。NetScreen、ASN.1、SPRT、NTLMSSP 等仍需核实适用回归输入及触发条件；无法取得时明确覆盖缺口。外部输入不随公开源码重新分发。
6. 运行项目 Golden 16 场景、JVM、lint、RTP host 及适用的设备协议/媒体测试，保留原断言。核对过滤、字段/专家信息、SIP/RTP/RTCP、codec 映射、导出播放及 VPN 双向流量；缺少外部夹具按原规则报告。
7. 验证双 ABI 加载、导出符号、动态依赖、ELF LOAD 和 APK 16 KB 对齐；同步真正改变的头文件、数据字典和版本标识。正式发布另做 Release 构建、签名和离线许可检查。
8. 将新库与对应源码生成新的不可变修订；同步归档、28 库哈希、补丁及许可清单。最终发布说明列出已修复项、未决项、未执行项和版本。预览标签不消除已知漏洞。

上述安全候选的验收独立于应用功能回归；更换原生库时仍需验证新库，不能直接沿用固定 r1 库的设备结果。

## 持续维护建议

由维护者在每次上游安全发布后及每次 APK 发布前更新此清单；尚未建立自动监测或响应时限承诺。
保留本次索引快照哈希，记录每次新增公告的审查日期。已接受的修复需记录对应二进制修订和回归结果；
仅有补丁文件、免责声明、构建成功或“预览版”标签均不能将状态改为已修复。

package com.example.layanalyzer.model

import java.util.Locale

/**
 * 一个编码的解码路由（RTP4-KT-02，卡片路由表）。
 *
 * [NATIVE] 交给 JNI 的 `decodeRtpAudio`；[MEDIACODEC] 走
 * `extractRtpCodecFrames` → `MediaCodecAudioDecoder` → `renderRtpAudioFromPcm`
 * 三段；[UNSUPPORTED] 不做任何解码，直接进结果的 `unsupported` 列表。
 *
 * 与原生 `layanalyzer/rtp/codecs/RtpDecoderFactory.h` 的「原生解码集合」是同一个
 * 划分：`extractRtpCodecFrames` 对 [NATIVE] 的编码一律回 `error="nativeDecode"`，
 * 所以两张表必须一致（RTP4-NAT-06 的注释写明了这条规则）。
 */
enum class RtpCodecRoute { NATIVE, MEDIACODEC, UNSUPPORTED }

/**
 * 一种导出格式（RTP4-KT-03 的「编码 → 可用格式」表）。
 *
 * [mimeType] 是卡片固定的五个 MIME 之一；[extension] 是文件后缀，`null` 表示后缀由
 * 具体编码决定（裸流用 `rtpRawExtension`，见 `model/RtpModels.kt`）。
 *
 * [containerFormat] 是 `exportRtpContainer` 请求里的 `format` 字段（原生侧只接受
 * `amr`/`awb`/`opus`，且**必须与该流的编码一致**，否则回
 * `error="format does not match the stream codec."`）；非容器格式为 `null`。
 */
enum class RtpExportFormat(
    val extension: String?,
    val mimeType: String,
    val containerFormat: String?
) {
    WAV("wav", "audio/wav", null),
    RAW(null, "application/octet-stream", null),
    AMR("amr", "audio/amr", "amr"),
    AWB("awb", "audio/amr-wb", "awb"),
    OPUS("opus", "audio/ogg", "opus");

    /** 是否走 `exportRtpContainer`（AMR / AMR-WB / Opus）。 */
    val isContainer: Boolean get() = containerFormat != null
}

/**
 * 「这个构建能不能解码」的运行时答案（RTP4-KT-05），来自原生
 * `NativeEngine.getRtpCodecCapabilities()`：
 * `{"audio":[...],"video":[...],"g729":true,"ilbc":false}`。
 *
 * 与 [RtpCodecCatalog.Entry.idSupported] 的分工**必须分清**：
 *
 *  - [RtpCodecCatalog.Entry.idSupported] 是**静态**的「本 App 设计上支持解码」，
 *    由 Kotlin 目录自己说了算。它对 G.729 和 iLBC 也是 `true`，因为这两个编码
 *    在本迭代是实现了的 —— 只是可能没编进这个构建。
 *  - 本类是**这个构建**的事实：`g729` / `ilbc` 是 `LAYANALYZER_ENABLE_G729`
 *    （RTP4-BLD-02）与 `LAYANALYZER_ENABLE_ILBC`（RTP4-NAT-08）的编译期取值。
 *    PT 映射对话框的置灰、以及 [RtpCodecCatalog.unavailableReason] 用的是它。
 *
 * 两者都在 `entries` 上表达，但只有本类能在真机上把「这个 App 不支持」和
 * 「这个构建没编进来」区分开：JVM 单测问不了 JNI，所以只能靠仪器测试
 * （`RtpCodecConsistencyTest`）把两边对上。
 *
 * [audio] / [video] 是原生两张表（`core/RtpCodecNames.h`）的原样拷贝；它们是
 * 一致性测试的断言对象，不是 UI 的判据 —— UI 用布尔值，因为拿不到原生回答时
 * [UNKNOWN] 的布尔值能让对话框 fail-open（见 [RtpCodecCatalog.unavailableReason]）。
 */
data class RtpCodecCapabilities(
    val audio: Set<String>,
    val video: Set<String>,
    val g729: Boolean,
    val ilbc: Boolean
) {
    /** 大小写不敏感，与 [RtpCodecCatalog.byId] / [RtpCodecCatalog.route] 同口径。 */
    fun hasAudio(id: String): Boolean = audio.any { it.equals(id, ignoreCase = true) }

    companion object {
        /**
         * 「拿不到原生回答」时的取值：两个可选编码都当作已在构建里，于是
         * [RtpCodecCatalog.unavailableReason] 一条都不会置灰 —— 这是卡片 §2.5
         * 要求的 fail-open（拿不到列表时不要把整个对话框锁死）。`audio` / `video`
         * 留空是诚实的：确实不知道。
         */
        val UNKNOWN = RtpCodecCapabilities(
            audio = emptySet(),
            video = emptySet(),
            g729 = true,
            ilbc = true
        )
    }
}

/** 一条编码被置灰的原因（RTP4-KT-05）；文案由 UI 从 `strings.xml` 取。 */
enum class RtpCodecUnavailableReason {
    /** `LAYANALYZER_ENABLE_G729=OFF` 的构建；文案与原生 `rtp_decodability_reason()` 一致。 */
    G729_NOT_IN_BUILD,

    /** `LAYANALYZER_ENABLE_ILBC` 未定义（默认构建）；文案同上。 */
    ILBC_NOT_IN_BUILD
}

/**
 * M1 的 PT 手动映射编码候选表（RTP1-KT-04），RTP4-KT-05 补全到本迭代的全部编码。
 *
 * 规范 ID 与默认时钟频率必须与 layanalyzer/rtp/core/RtpCodecNames.cpp
 * 的规范 ID 表一致：原生 `layanalyzer/rtp/core/RtpCodecNames.{h,cpp}` 用的是同一张表
 * （C13），JSON 里的 `codec` 字段一律用这里的规范 ID。
 *
 * [Entry.idSupported] 是**静态**的「本 App 设计上支持解码」：本迭代所有
 * `route != UNSUPPORTED` 的条目都是 `true`，为 `false` 的只剩 H264 / H265
 * （视频，尚未接入任何解码管线）。这个标记**不回答**「本构建有没有链接
 * G.729 / iLBC」—— 那是运行时问题，见 [RtpCodecCapabilities] 与
 * [unavailableReason]。为 false 的条目在对话框里仍然可以选（卡片「暂不支持解码，
 * 选择后仅用于统计」）；因构建开关而不可用的条目才会被置灰（RTP4-KT-05）。
 *
 * [Entry.needsSdpParams] 列出「不解这些 SDP `fmtp` 参数就解不对」的参数名
 * （AMR 的 `octet-align`、Opus 的 `sprop-stereo`）；空集表示不需要。它记录的是
 * **参数名**而不是布尔值，因为调用方要拿名字去查 fmtp（RTP3-NAT-04 的
 * `readRtpSetupInfo`），而且日志里只允许出现名字、不允许出现值（README §4.5.5）。
 *
 * [Entry.label] 用字面量（参照 [DecodeAsScope.Port] 的既有做法）。
 */
object RtpCodecCatalog {

    data class Entry(
        val id: String,
        val label: String,
        val clockRate: Int,
        val channels: Int = 1,
        val idSupported: Boolean,
        val clockRateEditable: Boolean = false,
        val route: RtpCodecRoute,
        val needsSdpParams: Set<String> = emptySet()
    )

    /**
     * 候选表（顺序即下拉顺序）：G.711A/U、L16、AMR、AMR-WB、opus、G722、g729、
     * iLBC、G.726 两个打包族、H264、H265。
     *
     * 时钟频率照 README §4.3（注意 G.722 的 RTP 时钟是 8000，采样率才是 16000）。
     */
    val entries: List<Entry> = listOf(
        Entry("g711A", "G.711A", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry("g711U", "G.711U", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry("L16", "L16", 44100, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry(
            "AMR", "AMR", 8000, idSupported = true,
            route = RtpCodecRoute.MEDIACODEC,
            needsSdpParams = setOf("octet-align")
        ),
        Entry(
            "AMR-WB", "AMR-WB", 16000, idSupported = true,
            clockRateEditable = true, route = RtpCodecRoute.MEDIACODEC
        ),
        Entry(
            "opus", "opus", 48000, idSupported = true,
            route = RtpCodecRoute.MEDIACODEC,
            needsSdpParams = setOf("sprop-stereo")
        ),
        Entry("g722", "G722", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry("g729", "g729", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry("iLBC", "iLBC", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry("G726-16", "G726-16", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry("G726-24", "G726-24", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry("G726-32", "G726-32", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry("G726-40", "G726-40", 8000, idSupported = true, route = RtpCodecRoute.NATIVE),
        Entry(
            "AAL2-G726-16", "AAL2-G726-16", 8000, idSupported = true,
            route = RtpCodecRoute.NATIVE
        ),
        Entry(
            "AAL2-G726-24", "AAL2-G726-24", 8000, idSupported = true,
            route = RtpCodecRoute.NATIVE
        ),
        Entry(
            "AAL2-G726-32", "AAL2-G726-32", 8000, idSupported = true,
            route = RtpCodecRoute.NATIVE
        ),
        Entry(
            "AAL2-G726-40", "AAL2-G726-40", 8000, idSupported = true,
            route = RtpCodecRoute.NATIVE
        ),
        Entry("H264", "H264", 90000, idSupported = false, route = RtpCodecRoute.UNSUPPORTED),
        Entry("H265", "H265", 90000, idSupported = false, route = RtpCodecRoute.UNSUPPORTED)
    )

    /** 大小写不敏感地查找规范 ID；未命中返回 null。 */
    fun byId(id: String): Entry? =
        entries.firstOrNull { it.id.equals(id, ignoreCase = true) }

    /**
     * 该条目**在这个构建里**能不能解码；不能时给出置灰原因，能（或无从判断）时为 null。
     *
     * 只认两个编译期开关（[RtpCodecCapabilities.g729] / [RtpCodecCapabilities.ilbc]），
     * 与原生 `rtp_decodability_reason()` 的「此构建未包含 X」是同一件事的两种表述 ——
     * 原生报 `unsupported`，这里把下拉项置灰，两边说的是同一句话。
     *
     * `capabilities` 是 [RtpCodecCapabilities.UNKNOWN] 时一条都不置灰：拿不到原生
     * 列表不该让用户什么都选不了（fail-open，卡片 §2.5）。
     *
     * H264 / H265 不走这条：它们不是「这个构建没有」，而是本来就没接解码管线，
     * 继续用 [Entry.idSupported] 的统计提示，保持可选。
     */
    fun unavailableReason(
        id: String,
        capabilities: RtpCodecCapabilities
    ): RtpCodecUnavailableReason? {
        return when {
            id.equals("g729", ignoreCase = true) && !capabilities.g729 ->
                RtpCodecUnavailableReason.G729_NOT_IN_BUILD
            id.equals("iLBC", ignoreCase = true) && !capabilities.ilbc ->
                RtpCodecUnavailableReason.ILBC_NOT_IN_BUILD
            else -> null
        }
    }

    /**
     * 编码名 → 解码路由（RTP4-KT-02 的卡片路由表，大小写不敏感，与 [byId] 同一口径）。
     *
     * 查询表比 [entries] 宽：路由必须能在**任何**规范 ID 上回答。RTP4-KT-05 把
     * `G726-16`/`AAL2-G726-32` 等 README §4.3 的编码都补进了 [entries]，所以今天
     * 下面那条兜底对它们已经不会触发；保留它是为了让这条契约不依赖 UI 候选表的
     * 内容（候选表以后若再被裁剪，路由仍然答得出来）。表外的名字一律
     * [RtpCodecRoute.UNSUPPORTED]。
     *
     * `g729` 固定是 [RtpCodecRoute.NATIVE]：这个构建有没有链接 bcg729 只有原生层
     * 知道，路由不做预判——构建未包含时由 `decodeRtpAudio` 的 `unsupported`
     * 原因文案回答（卡片第 3 条）。
     */
    fun route(codec: String): RtpCodecRoute {
        val id = codec.trim()
        if (id.isEmpty()) return RtpCodecRoute.UNSUPPORTED
        byId(id)?.let { return it.route }
        // README §4.3 里原生解码、但当前 UI 候选表没列的编码。
        return if (NATIVE_ONLY_IDS.contains(id.lowercase(Locale.US))) {
            RtpCodecRoute.NATIVE
        } else {
            RtpCodecRoute.UNSUPPORTED
        }
    }

    /**
     * 编码 → 可用导出格式（RTP4-KT-03 的卡片表，大小写不敏感，口径与 [byId] 一致）。
     *
     *  | 编码 | 可用格式 |
     *  |---|---|
     *  | 所有可解码编码 | [RtpExportFormat.WAV] |
     *  | `g711A`/`g711U`/`L16`/`g722`/`G726-*`/`AAL2-G726-*`/`g729` | [RtpExportFormat.RAW] |
     *  | `AMR` | [RtpExportFormat.AMR] |
     *  | `AMR-WB` | [RtpExportFormat.AWB] |
     *  | `opus` | [RtpExportFormat.OPUS] |
     *
     * 「可解码」的口径就是 [route]：原生能解的（`NATIVE`）与走 MediaCodec 的
     * （`MEDIACODEC`）都算，[RtpCodecRoute.UNSUPPORTED] 的编码一个格式都没有。
     *
     * 别名口径与 [byId] 完全一致：只认 [entries] 里的规范 ID（大小写不敏感），
     * `PCMA`/`G729A` 这类别名**不在**这里展开 —— 流上的 `codec` 早就被原生
     * `RtpCodecNames::canonical()` 归一化成规范 ID（C13），格式表不需要第二套别名表。
     *
     * 两处与卡片的字面表述有意不同，都是为了「表与管线一致」——格式菜单里出现的
     * 按钮必须真的能导出成功：
     *
     *  - [RtpExportFormat.RAW] 多了 `L16`。卡片把裸流写成「G.711/G.722/G.726/G.729」，
     *    但 `rtpRawExtension` 从 RTP2-KT-02 起就支持 `L16`，去掉它会让 G.711 线性
     *    编码的流在格式菜单里凭空少一个入口。
     *  - [RtpExportFormat.RAW] 不含 `iLBC`。卡片没有列它，且原生 `RtpDecoderFactory`
     *    的原生解码集合里 iLBC 与 G.722/G.726/G.729 并列，格式表要跟的是导出管线
     *    （`rtpRawExtension`）而不是解码集合，所以这里按卡片办。
     */
    fun exportFormats(codec: String): Set<RtpExportFormat> {
        val id = codec.trim()
        if (id.isEmpty()) return emptySet()
        val canonical = (byId(id)?.id ?: id).lowercase(Locale.US)
        val formats = linkedSetOf<RtpExportFormat>()
        if (route(id) != RtpCodecRoute.UNSUPPORTED) formats += RtpExportFormat.WAV
        if (canonical in RAW_EXPORT_IDS) formats += RtpExportFormat.RAW
        when (canonical) {
            "amr" -> formats += RtpExportFormat.AMR
            "amr-wb" -> formats += RtpExportFormat.AWB
            "opus" -> formats += RtpExportFormat.OPUS
        }
        return formats
    }

    /**
     * 编码的原生容器导出格式；没有（或编码在表外）时为 `null`。
     *
     * `exportRtpContainer` 的原生侧会校验 `format` 与该流的编码是否一致，所以调用方
     * **必须**用这里返回的格式去拼请求，不能自己按编码猜一个（把 AMR-WB 的流按
     * `format="amr"` 导出会被原生层拒绝）。
     */
    fun containerFormat(codec: String): RtpExportFormat? =
        exportFormats(codec).firstOrNull { it.isContainer }

    /**
     * 小写规范 ID 的原生解码集合里、[entries] 之外的那部分。
     *
     * `iLBC` 在这里是有依据的：卡片 m4.md 的 NAT-06 第 5 条把 iLBC 与
     * G.722/G.726/G.729 并列为「原生直接解码」，而 `RtpJni.cpp` 的
     * `resolve_codec_frames_stream` 正是按这个集合对 `extractRtpCodecFrames`
     * 回 `nativeDecode`，两张表必须一致。
     *
     * RTP4-KT-05 把这些 id 也补进了 [entries]（对话框里现在能选到它们），所以
     * 下面这条兜底对它们已经不再触发。保留而不是删掉，是因为 [route] 的契约是
     * 「任何规范 ID 都要答得出来」，而这个答案不应该取决于 UI 候选表当前收录了谁。
     */
    private val NATIVE_ONLY_IDS: Set<String> = setOf(
        "g726-16", "g726-24", "g726-32", "g726-40",
        "aal2-g726-16", "aal2-g726-24", "aal2-g726-32", "aal2-g726-40",
        "ilbc"
    )

    /**
     * 有裸流表示的编码（小写规范 ID），与 `rtpRawExtension` 一一对应
     * （RTP4-KT-03 补齐了 G.722 / G.726 / AAL2-G726 / G.729）。
     */
    private val RAW_EXPORT_IDS: Set<String> = setOf(
        "g711a", "g711u", "l16",
        "g722", "g729",
        "g726-16", "g726-24", "g726-32", "g726-40",
        "aal2-g726-16", "aal2-g726-24", "aal2-g726-32", "aal2-g726-40"
    )
}

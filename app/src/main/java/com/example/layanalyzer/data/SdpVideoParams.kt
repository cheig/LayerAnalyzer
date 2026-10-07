// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import android.util.Base64
import java.util.Locale

/**
 * 一个视频流在 SDP `a=fmtp` 里声明的参数集（RTP5-KT-00）。
 *
 * [sps] / [pps] / [vps] 是**已经解码好的**参数集字节（不含起始码，就是 SDP 里 Base64
 * 的原样字节），空列表表示「这个流在这个 SDP 里没有声明」。卡片只要求保留第一个 SPS
 * 与第一个 PPS，所以每个列表最多一项，详见 [SdpVideoParams]。
 *
 * [packetizationMode] / [profileLevelId] / [donDiff] 分别是 `packetization-mode`、
 * `profile-level-id`、`sprop-max-don-diff` 的取值；键不存在、值为空或解析不出来时为
 * `null`（fail-closed：不猜默认值）。`null` 与 `0` 是两件事，调用方必须区分。
 *
 * 注意 `ByteArray` 的 `equals` 是**引用比较**，所以本 data class 自动生成的
 * `equals`/`hashCode` 对三个字节列表只在同一实例时才相等。要比较内容请逐项
 * `assertArrayEquals`（单测就是这么做的），不要用 `assertEquals(sets1, sets2)`。
 * 卡片冻结了这个数据类，不在这里覆盖 `equals`。
 */
data class VideoParamSets(
    val sps: List<ByteArray>,
    val pps: List<ByteArray>,
    val vps: List<ByteArray>,
    val packetizationMode: Int?,
    val profileLevelId: String?,
    val donDiff: Int?
)

/**
 * 从 SDP 的 `a=fmtp:<pt> <参数>` 里取出视频参数集（RTP5-KT-00）。
 *
 * 三条卡片没写、这里必须选一条的决定，写下来免得后来者猜：
 *
 * 1. **Base64 的解码接缝。** 卡片指定用 `android.util.Base64.decode(value, Base64.DEFAULT)`，
 *    但本模块没有 Robolectric、也没有 `isReturnDefaultValues`，JVM 单测里碰任何
 *    `android.*` 都会抛「not mocked」。所以解码这一步做成了一个可注入的参数：
 *    [from] 保持卡片冻结的签名，内部走生产默认值 [androidBase64Decode]（就是卡片指定的
 *    Android 解码器）；[parse] 多一个 `decode` 参数供单测注入 `java.util.Base64`。
 *    同一个做法仓库里已有先例（`data/AnalysisWorkspaceCodec.kt`、
 *    `viewmodel/RtpHeuristicPreferenceOps.kt`，以及 `RtpCodecRouteTest` 里那条
 *    「`MediaCodecAudioDecoder` 在 JVM 单测里连第一条日志都打不出来」的注释），
 *    这里只是把它用在 Base64 上。接缝的契约：[decode] 在输入非法时**可以**抛
 *    `IllegalArgumentException`（`android.util.Base64` 与 `java.util.Base64` 都是这么做的），
 *    [parse] 会把异常当成解码失败，绝不外传。
 *
 * 2. **计数，而不是日志。** 卡片要求把「多于前两个的参数集」写进日志；但本文件里一次
 *    `android.util.Log` 都不能出现（同上，单测执行到就会炸），而且 README §4.5.5 禁止
 *    打印 fmtp 的**值**。所以 [parse] 把计数放在 [ParseResult] 里返回，由将来的调用链
 *    （`RtpViewModel` / `RtpRepository`）在拿到结果时打日志 —— 只打编码名与计数，永远
 *    不打参数集内容、也不打 fmtp 原文。
 *
 * 3. **`payloadType` 目前不参与任何解析规则。** 规则按编码名（H264 / H265 / PS）分支，
 *    fmtp 属于哪个 PT 在调用方读的时候就已经确定了。参数保留（签名冻结，不能删），
 *    并且**确实用到了**：[ParseResult.payloadType] 把它带回去，调用方打日志时不必再抄
 *    一遍自己传进来的 PT。将来若真的出现「同一编码名、不同 PT 走不同规则」的需求，
 *    扩展点也在这里。
 *
 * **依赖尚未落地。** 卡片「调用链」一段假定 RTP3-NAT-04 已经提供 `readRtpSetupInfo`
 * 来按帧号读出 SDP，但该 JNI 入口**在本仓库里还不存在**（`NativeEngine.kt` 里没有声明，
 * `RtpJni.cpp` 里只有两处 TODO 注释指向它）。所以今天没有任何地方能拿到 fmtp 的**值**
 * 来调用本对象，本文件与它的单测先独立交付，接线留给 `readRtpSetupInfo` 落地之后。
 * 卡片与 README §2 C16 都禁止改 `CommunicationJni.cpp` / `CommunicationAnalysis`
 * （那里刻意只保留参数名、不带值），不要为了接线去那里找 fmtp 的值。
 */
object SdpVideoParams {

    /**
     * [parse] 的结果：公开的 [VideoParamSets] 加上**只给日志用**的计数与 PT。
     *
     * 计数与参数集分开，是为了让「打日志」和「拿参数集」两件事在类型上就分得开：
     * 调用方不该把 [extraParameterSetCount] 之类当成参数集的一部分。
     */
    internal data class ParseResult(
        /** 这次解析对应的 PT；本次不参与任何规则，只为了让调用方的日志不必再抄一遍。 */
        val payloadType: Int,
        val sets: VideoParamSets,
        /** H.264 里多于前两个、被丢弃的 SPS / PPS 个数（卡片要求进日志的计数）。 */
        val extraSpsCount: Int = 0,
        val extraPpsCount: Int = 0,
        /** 键存在但解不出来的项数（键缺失或值为空不算）。 */
        val undecodableCount: Int = 0
    ) {
        /** 卡片说的「其余写进日志的计数里」就是它。 */
        val extraParameterSetCount: Int get() = extraSpsCount + extraPpsCount

        /**
         * 是否至少拿到了一个参数集。调用方报「缺少参数集」用的就是它 —— 三个列表全空
         * 意味着这次 SDP 帮不上忙（可能是 PS、可能是 Base64 全坏、也可能本来就没有 fmtp），
         * 具体是哪一种由 [extraParameterSetCount] / [undecodableCount] 区分。
         */
        val hasParameterSets: Boolean
            get() = sets.sps.isNotEmpty() || sets.pps.isNotEmpty() || sets.vps.isNotEmpty()
    }

    /**
     * fmtpValues 来自 readRtpSetupInfo 的 sdp[].fmtp（分号分隔的原始字符串）
     *
     * 生产入口，签名由卡片冻结。内部委托给 [parse]，用 [androidBase64Decode] 当解码器；
     * 这个方法本身不做任何判断，全部规则都在 [parse] 里（这样单测能覆盖到每一条）。
     */
    fun from(payloadType: Int, encodingName: String, fmtp: String?): VideoParamSets =
        parse(payloadType, encodingName, fmtp).sets

    /**
     * [from] 的实际实现，多一个可注入的 [decode]。
     *
     * 失败一律表现为「空」，从不抛异常：Base64 非法、键缺失、值不是数字，结果都是对应的
     * 字段为空 / `null`，由调用方按「缺少参数集」处理（卡片明确要求）。
     *
     * @param decode Base64 解码器；生产默认是 Android 的，单测注入 `java.util.Base64`。
     *   允许抛 `IllegalArgumentException`，本方法会吞掉并当成失败。
     */
    internal fun parse(
        payloadType: Int,
        encodingName: String,
        fmtp: String?,
        decode: (String) -> ByteArray? = ::androidBase64Decode
    ): ParseResult {
        val params = parseFmtp(fmtp)

        // 标量参数只在认识的编码上取值；PS 与表外的编码名下面提前返回，全部为空。
        // 卡片对 PS 的要求就是「全部为空」，所以连这三个也不给它。
        val kind = videoKind(encodingName)
        if (kind == VideoKind.PS || kind == VideoKind.OTHER) {
            return ParseResult(payloadType, emptySets())
        }

        val sps = mutableListOf<ByteArray>()
        val pps = mutableListOf<ByteArray>()
        val vps = mutableListOf<ByteArray>()
        var extraSps = 0
        var extraPps = 0
        var undecodable = 0

        when (kind) {
            VideoKind.H264 -> {
                // `sprop-parameter-sets=<b64>,<b64>[,...]`：第 1 项按约定是 SPS、第 2 项是 PPS。
                val items = params["sprop-parameter-sets"]
                    ?.split(',')
                    ?.map { it.trim() }
                    ?.filter { it.isNotEmpty() }
                    .orEmpty()

                if (items.isNotEmpty() && !decodeInto(items[0], sps, decode)) undecodable++
                if (items.size > 1 && !decodeInto(items[1], pps, decode)) undecodable++
                // 第 3 项起只计数、不解码：它们注定被丢弃，解码一遍只是浪费。
                // 分类按偶数下标 SPS、奇数下标 PPS —— 卡片说的「3 个一组交替」
                // （SPS,PPS,SPS | PPS,SPS,PPS …）落在同一套奇偶上；而且无论按哪种分组读，
                // 被保留的都只有第 1 个 SPS 与第 1 个 PPS，分类只影响日志里的计数。
                for (index in 2 until items.size) {
                    if (index % 2 == 0) extraSps++ else extraPps++
                }
            }

            VideoKind.H265 -> {
                // 三个彼此独立的键，值是 Base64（卡片如此规定，按单个值处理，不按逗号切）。
                // 键必须**存在**才计入 undecodable：没写这一项与写了但解不出来是两回事，
                // 只有后者是「解不出来的项」。`parseFmtp` 已经丢掉了空值，所以这里
                // `?.let` 拿到的就是「键存在且值非空」。
                params["sprop-vps"]?.let { if (!decodeInto(it, vps, decode)) undecodable++ }
                params["sprop-sps"]?.let { if (!decodeInto(it, sps, decode)) undecodable++ }
                params["sprop-pps"]?.let { if (!decodeInto(it, pps, decode)) undecodable++ }
            }

            VideoKind.PS, VideoKind.OTHER -> Unit // 上面已经提前返回，这里只是让 when 穷尽
        }

        return ParseResult(
            payloadType = payloadType,
            sets = VideoParamSets(
                sps = sps,
                pps = pps,
                vps = vps,
                packetizationMode = params["packetization-mode"]?.toIntOrNull(),
                profileLevelId = params["profile-level-id"],
                donDiff = params["sprop-max-don-diff"]?.toIntOrNull()
            ),
            extraSpsCount = extraSps,
            extraPpsCount = extraPps,
            undecodableCount = undecodable
        )
    }

    /** 卡片要求的空结果：PS 与表外编码名都走它。 */
    private fun emptySets() = VideoParamSets(
        sps = emptyList(),
        pps = emptyList(),
        vps = emptyList(),
        packetizationMode = null,
        profileLevelId = null,
        donDiff = null
    )

    /** 卡片列举的三种编码；表外的名字一律 [OTHER]，按 fail-closed 全空处理。 */
    private enum class VideoKind { H264, H265, PS, OTHER }

    /**
     * 编码名 → 规则分支。大小写不敏感，别名照 README §4.3 的规范 ID 表
     * （`H265` 也接受 `HEVC`，`PS` 也接受 `MP2P`）—— 和 `RtpCodecCatalog.byId` 同一口径，
     * 免得同一个编码在两个地方认不同的名字。
     */
    private fun videoKind(encodingName: String): VideoKind =
        when (encodingName.trim().lowercase(Locale.US)) {
            "h264" -> VideoKind.H264
            "h265", "hevc" -> VideoKind.H265
            "ps", "mp2p" -> VideoKind.PS
            else -> VideoKind.OTHER
        }

    /**
     * 解码一项 Base64 并放进 [sink]；返回 true 表示这一项真的解出来了。
     *
     * 键缺失、值为空、Base64 非法、解出来是 0 字节，四者都返回 false 且什么都不放进
     * [sink]：对调用方来说它们是同一件事（这一项为空），分开报没有意义。
     */
    private fun decodeInto(
        value: String?,
        sink: MutableList<ByteArray>,
        decode: (String) -> ByteArray?
    ): Boolean {
        if (value.isNullOrEmpty()) return false
        val bytes = try {
            decode(value)
        } catch (ignored: IllegalArgumentException) {
            // 卡片：Base64 解码失败 → 该项为空，不要抛异常。
            null
        }
        if (bytes == null || bytes.isEmpty()) return false
        sink += bytes
        return true
    }

    /**
     * `a=fmtp` 的值 → 小写键名到原始值的表（键名统一小写，取值保持原样）。
     *
     * 容忍两种上游写法（单测覆盖）：分隔符 `;` 两边的空白任意，键的顺序任意。
     * 下面这些一律跳过，而不是报错：
     *
     *  - 空段（`;;`、结尾的 `;`）：SDP 里很常见。
     *  - 没有 `=` 的段：本对象用不到「只有名字的参数」（AMR 的 `octet-align` 那种），
     *    跳过比猜一个值安全。
     *  - 值为空的段：解出来会是 0 字节的「参数集」，那是假的，不如当没有。
     *  - 重复键只认第一个：SDP 不允许重复，出现了说明上游有问题，取第一个最可预期。
     *
     * 分隔符取**第一个** `=`：Base64 的填充字符就是 `=`，只能用第一个来切开键与值。
     */
    private fun parseFmtp(fmtp: String?): Map<String, String> {
        if (fmtp.isNullOrBlank()) return emptyMap()
        val out = LinkedHashMap<String, String>()
        for (part in fmtp.split(';')) {
            val item = part.trim()
            if (item.isEmpty()) continue
            val separator = item.indexOf('=')
            if (separator <= 0) continue
            val key = item.substring(0, separator).trim().lowercase(Locale.US)
            val value = item.substring(separator + 1).trim()
            if (value.isEmpty()) continue
            if (!out.containsKey(key)) out[key] = value
        }
        return out
    }

    /**
     * 生产环境的 Base64 解码，卡片指定用 `android.util.Base64.decode(value, Base64.DEFAULT)`。
     *
     * **不要在 JVM 单测的执行路径上走到这里**：本模块的 `android.*` 是 not mocked 的桩，
     * 调用会抛 `RuntimeException` 而不是 `IllegalArgumentException`，本方法接不住。
     * 单测请用 [parse] 的 `decode` 参数（`java.util.Base64`）—— 这也是接缝存在的理由。
     */
    private fun androidBase64Decode(value: String): ByteArray? = try {
        Base64.decode(value, Base64.DEFAULT)
    } catch (ignored: IllegalArgumentException) {
        null
    }
}

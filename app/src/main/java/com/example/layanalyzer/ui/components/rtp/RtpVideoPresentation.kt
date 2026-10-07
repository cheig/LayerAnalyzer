// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.model.RtpVideoExportFormat
import com.example.layanalyzer.model.RtpVideoExportResult
import com.example.layanalyzer.model.rtpVideoCodecId
import java.util.Locale

/**
 * RTP5-UI-01：视频流在「RTP 流」列表上的纯展示决策。
 *
 * 与 `RtpVideoPreviewTimeline.kt` 同一个理由分出来：这里一个 `android.*` 类型都不出现，
 * 所以「哪条流算视频」「菜单里该出现哪几种产物」「摘要上那几个数字怎么写」可以在 JVM 上
 * 钉住。Compose 那一半（对话框、菜单项、SAF 目的地）在 `RtpVideoExportActions.kt`。
 *
 * ### 为什么编码集合是 {H264, H265, PS}
 *
 * 原生的 `kSupportedVideoCodecs`（`RtpCodecNames.h`）就是这三个，RTP5-NAT-01 把它接进
 * `rtp_decodability()` 之后，这三条流的 `decodable` 都是 `Yes` —— 也就是说**流列表已经
 * 会把它们当成「能解码」**，卡片菜单必须自己把它们分流到视频那一组，否则「播放」和
 * 「导出 WAV」都会出现在一条解不出声音的流上（音频那条管线里没有视频解码器）。
 *
 * 别名（`HEVC` 之类）**不在这里展开**，与 [rtpVideoCodecId] 同口径：流上的 `codec` 早就被
 * 原生 `RtpCodecNames::canonical()` 归一化成规范 ID 了（C13），这里再收一套别名只会让
 * 「是不是视频」和「能不能导出」这两件事有两套名字表。
 */

/** 规范 ID 里的三个视频编码（小写，见类注释）。 */
private val RTP_VIDEO_CODEC_IDS = setOf("h264", "h265", "ps")

/**
 * 这条流是不是视频。大小写不敏感，只认规范 ID（见类注释）。
 *
 * **「是不是视频」与「能不能导出」是两件事**：`PS`（GB28181）是视频，但要先由用户或 SDP
 * 解析出真正的编码（H.264 / H.265）才谈得上导出，所以 [rtpVideoExportFormats] 对它是空表。
 * 卡片上那条「视频」标签只看这个函数，导出菜单看的是后者。
 */
fun rtpStreamIsVideo(codec: String): Boolean =
    codec.trim().lowercase(Locale.US) in RTP_VIDEO_CODEC_IDS

/**
 * 视频导出对话框里给这条流列出的产物；编码不是 H.264/H.265 时是空表。
 *
 * 两个取值都在的条件完全相同（`rtpVideoFileName` 只按编码 ID 取名），所以这里不需要第二个
 * 判据：返回空表就等于「这条流一个视频产物都导不出来」，对话框据此说明原因而不是给一个
 * 按下去必然失败的按钮（README §4.5.4）。
 */
fun rtpVideoExportFormats(codec: String): List<RtpVideoExportFormat> =
    if (rtpVideoCodecId(codec) == null) {
        emptyList()
    } else {
        listOf(RtpVideoExportFormat.MP4, RtpVideoExportFormat.RAW)
    }

/**
 * 点整张卡片（不是 ⋮ 菜单）时该做什么。
 *
 * ### 为什么音频流与视频流必须在这里分开
 *
 * 卡片点击原先打开的是 `RtpPlayerScreen` —— 那是个**音频**播放器：
 * `RtpViewModel.decodePlayer()` 调的是 `repository.decodeAudio()`，经
 * `RtpCodecCatalog.route()` 分流，而 H264/H265 在那张表里是
 * `RtpCodecRoute.UNSUPPORTED`（视频没有音频解码器）。于是一条 H.264 流点进去必然
 * 落到 `RtpPlayerScreen` 的「不支持的流」分区里 —— 那个页面不是在说这条流坏了，
 * 是说「走错了门」。菜单那一侧早就用 [rtpStreamIsVideo] 分流了，整卡点击漏了。
 *
 * 三种结果：
 *
 *  - [RtpStreamCardTap.OpenAudioPlayer] —— 音频流，行为与从前完全一致。
 *  - [RtpStreamCardTap.OpenVideoPreview] —— 视频流**且**已有可预览的 MP4
 *    （[previewReady] 与 [hasPreviewFile] 的交集，与 ⋮ 菜单里「应用内预览」同一个判据）。
 *  - [RtpStreamCardTap.PrepareAndPreview] —— 视频流但还没有可播的 MP4：**顺手封装一份**
 *    再进预览页（`RtpViewModel.prepareVideoPreview`）。中间产物只写缓存，不弹 SAF、
 *    不落用户可见的文件。
 *
 * ### 为什么第三种是「自动导出」而不是「提示去用菜单」
 *
 * 原来的 `ExplainVideo` 分支给的是一句「请用卡片菜单里的『导出 MP4』或『外部播放』」。
 * 这句话本身没错，但**用户点的是卡片，不是菜单** —— 让他自己去找菜单、再点一次、
 * 再选格式、再选保存位置（SAF），点一下变四步。这不是「说清楚了下一步」，
 * 是把下一步原样退回去。
 *
 * `prepareVideoPreview` 复用的是 [RtpViewModel] 里 SAF 导出**同一段**封装实现
 * （`exportVideoSource`），所以封装参数、fail-closed 的失败原因、`.vidx` 的写法全都
 * 一致，代价只是一次本地封装的时间。真正要「存成文件给别的应用看」仍然走 ⋮ 菜单，
 * 那一步的落盘语义一个字没改。
 *
 * **不能退回音频播放器**：那条路后面是 `decodeAudio()`，H.264 在
 * `RtpCodecCatalog.route()` 里是 UNSUPPORTED，于是又落回「不支持的流」分区 ——
 * 等于用两层错误盖住一个本来能修好的问题。封装失败时 UI 显示 `RtpVideoOpenUiState.Error`
 * 里的原文（缺参数集 / 代际过期 / 会话已关闭），既不静默回退也不生成空文件。
 *
 * [previewReady] 与 [hasPreviewFile] 分成两个参数而不是合成一个，是为了让调用方不必
 * 知道它们是两个不同的来源（`RtpVideoPreviewAvailability` 答「这台设备能不能播」，
 * 宿主的记账答「这份 MP4 属于哪条流」，后者没有流 id）。合成一个布尔就等于逼调用方
 * 在 UI 层重新实现一遍这个交集，而那正是这次出问题的形状。
 *
 * ### 这里**不**查 `rtpVideoExportFormats`
 *
 * 一个容易加错的额外判据：`PS`（GB28181）的导出格式表是空的，于是「PS 永远不能预览」。
 * 加了这一层之后，整卡点击就会与 ⋮ 菜单的「应用内预览」说法不一致 —— 后者的判据是
 * `previewReady && id in previewStreamIds`，不查导出格式表（见 `RtpStreamsScreen.kt`），
 * 于是会出现「菜单里没有预览项、点卡片却进了预览页」。**两个入口必须说同一句话**，
 * 所以这里与菜单严格同口径。现实中对 PS 不可达：导出菜单项对它置灰，MP4 永远导不出，
 * 宿主也就永远不会记账。
 */
enum class RtpStreamCardTap {
    /** 音频流：打开音频播放器（RTP2-UI-02 的原行为）。 */
    OpenAudioPlayer,

    /** 视频流且 MP4 现在能播：直接进 RTP5-KT-03 的预览页。 */
    OpenVideoPreview,

    /**
     * 视频流但还没有可播的 MP4：先在缓存里封装一份，再进预览页。
     *
     * 与 [OpenVideoPreview] 的区别只是**要不要先准备文件**，进的是同一个预览页；
     * 准备失败时不会退到 [OpenAudioPlayer]，那条路后面是音频解码器。
     */
    PrepareAndPreview
}

/**
 * 整卡点击的归属；[RtpVideoMenu]（`RtpStreamsScreen.kt`）与它同名，说的同一件事。
 *
 * 判据的顺序不能换：先问「是不是视频」（[rtpStreamIsVideo]），再问「能不能播」。
 * 反过来写会让一条 `codec` 为空、实际是 SRTP 的流在 `previewReady` 为真时也去开预览页。
 */
fun rtpStreamCardTap(
    codec: String,
    previewReady: Boolean,
    hasPreviewFile: Boolean
): RtpStreamCardTap = when {
    !rtpStreamIsVideo(codec) -> RtpStreamCardTap.OpenAudioPlayer
    previewReady && hasPreviewFile -> RtpStreamCardTap.OpenVideoPreview
    else -> RtpStreamCardTap.PrepareAndPreview
}

/**
 * 导出摘要里的分辨率文本（`1280×720`），**宽高不可用时是 null**。
 *
 * 用 `×`（U+00D7）而不是 `x`：这是分辨率的标准写法，与 `strings.xml` 里那些数值文案同形。
 *
 * 不可用时**不写 0×0 也不写封装器的 1280×720 回退**（[RtpVideoExportResult.widthKnown]）：
 * 那两个数字看起来都像「读出来的」——`0×0` 是胡说，`1280×720` 是 KT-01 为了让 `MediaMuxer`
 * 有轨道尺寸而选的缺省值，不是这条流的分辨率。调用方拿到 null 时显示「未知」。
 */
fun rtpVideoResolutionText(result: RtpVideoExportResult): String? =
    if (result.widthKnown) "${result.width}×${result.height}" else null

/**
 * `unsupportedNalCounts` → 一行可读文本（`FU-B 2 · STAP-B 1`）。
 *
 * 计数为 0 的包型**不出现**：原生预置了四个恒为 0 的键（`STAP-B`/`MTAP16`/`FU-B`/`PACI`），
 * 全列出来会让每一份摘要都挂着四个 0，真正数到的那个反而被淹掉。整张表全 0（或为空）时
 * 返回空串，调用方只显示总数 —— 「一个不支持的包型都没有」不该写成一行 `0`。
 *
 * 按包型名排序（大小写不敏感）而不是按原生 JSON 的键序：契约说这个映射可以出现契约之外的
 * 键（NAT-05 decision 14），而 JSON 对象的键序不是契约的一部分，同一份数据每次渲染都要
 * 长得一样。
 */
fun rtpVideoUnsupportedNalText(counts: Map<String, Long>): String =
    counts.entries
        .filter { it.value > 0L }
        .sortedBy { it.key.lowercase(Locale.US) }
        .joinToString(separator = " · ") { (type, count) -> "$type $count" }

/**
 * 导出摘要里「不支持的包型」那一行的值：**先总数**，数到了具体包型时再跟上括号里的明细
 * （`3 (FU-B 2 · STAP-B 1)`）。
 *
 * 总数取自 [RtpVideoExportResult.unsupportedNalPackets] 而不是明细的和：那是「这一行说的
 * 是什么」的权威数字（契约里预置的四个键恒为 0，明细只列数到的），明细是它的展开。
 * 一个不支持的包型都没有时就是 `0` 这个字符，不写一对空的括号。
 */
fun rtpVideoUnsupportedNalSummary(result: RtpVideoExportResult): String {
    val breakdown = rtpVideoUnsupportedNalText(result.unsupportedNalCounts)
    val total = result.unsupportedNalPackets
    return if (breakdown.isEmpty()) total.toString() else "$total ($breakdown)"
}

package com.example.layanalyzer.media

import com.example.layanalyzer.data.RtpStreamDirection
import com.example.layanalyzer.data.VoipCall
import com.example.layanalyzer.model.RtpCodecCatalog
import com.example.layanalyzer.model.RtpDecodability
import com.example.layanalyzer.model.RtpExportFormat
import com.example.layanalyzer.model.RtpStream
import com.example.layanalyzer.model.rtpVideoCodecId

/**
 * RTP5-KT-04：「导出 MP4（含音频）」这个入口到底能不能给。
 *
 * 卡片要的是「依赖 M3、M4-KT-04，未满足时不显示该选项」，也就是说 UI-01 需要一个
 * **可以据以隐藏**的信号。和 RTP5-KT-03 的
 * [com.example.layanalyzer.model.RtpVideoPreviewAvailability] 一样，这里不是布尔值：
 * 五个非 `Ready` 取值是五件不同的事，把它们压成一个 `false` 只会让下一个人重新去猜
 * 「为什么不能」。
 *
 *  - [NoCall]：这条视频流没有被 M3 关联到任何呼叫（或者调用方根本没有 M3 的结果）。
 *  - [CallHasNoAudio]：关联到了，但这个呼叫里没有可渲染成 WAV 的音频流。
 *  - [NoRenderedWav]：有音频流，但它渲染不出 WAV（`decodable` 不是 `yes`）。
 *  - [NoVideoExport]：视频这半也出不了 ES（编码不是 H.264/H.265，或者流不可解码）。
 *  - [NoAacEncoder]：设备没有 AAC 编码器（M4-KT-04 的依赖）。
 *  - [Ready]：两路都有，可以合成。
 *
 * **这是一个能力问题，不是一次动作**：回答它不许产生任何文件，也不许调用编码器 ——
 * 所以这里不渲染 WAV（[NoRenderedWav] 看的是流自己的 `decodable`，那是原生扫描早就
 * 给出的结论），也不编码 AAC（[NoAacEncoder] 来自一次 `MediaCodecList` **查询**，
 * 见 [AacEncoderProbe]）。真正动手的是 `RtpViewModel.exportAudioVideo`。
 *
 * [aacEncoderAvailable] 为 `null` 表示**查询本身失败**，与 KT-02 的
 * `RtpVideoDecoderAvailability.UNKNOWN` 同一口径：这时判 [Ready]（fail-open）——
 * 查不出来不等于没有，因为一次查询异常就把功能藏起来，用户没有任何办法绕过它。
 * 真到导出时编码器仍然可能拒绝（`AacExporter` 会回 `noEncoder`），那是另一层，
 * 也是这条 fail-open 的兜底。
 */
sealed interface RtpAvMuxAvailability {
    /** 这条视频流不在任何 M3 呼叫里。 */
    data object NoCall : RtpAvMuxAvailability

    /** 呼叫在，但里面没有可渲染的音频流。 */
    data class CallHasNoAudio(val callId: String) : RtpAvMuxAvailability

    /** 音频流在，但它渲染不出 WAV（`decodable` 不是 `yes`）。 */
    data class NoRenderedWav(val audioStreamId: String) : RtpAvMuxAvailability

    /** 视频这半出不了 ES（不是 H.264/H.265，或者流不可解码）。 */
    data object NoVideoExport : RtpAvMuxAvailability

    /** 这台设备没有 AAC 编码器。 */
    data object NoAacEncoder : RtpAvMuxAvailability

    /** 可以合成：[audioStreamId] 就是要渲染成 WAV 的那条流。 */
    data class Ready(val callId: String, val audioStreamId: String) : RtpAvMuxAvailability
}

/**
 * 音视频合成的可用性判定（RTP5-KT-04），纯函数。
 *
 * 判定顺序是刻意的，也就是本文件列出的顺序：**先问「有没有呼叫」，再问「呼叫里有没有
 * 音频」，再问「音频能不能出 WAV」，再问「视频能不能出 ES」，最后才问设备能力**。前四
 * 条问的都是这次请求自己的事实，最后一条问的是设备：一次「没导出」被报成「设备不行」
 * 会让人去查错方向，反过来也一样。
 *
 * M3 的关联**不在这里重新推导**（README §4.5 的精神，也是卡片「依赖 M3」的意思）：
 * [calls] 就是 `RtpCallLinker.link(...)` 的结果，本函数只在里面**找**这条视频流所属的
 * 呼叫（[linkedCallFor]），不拿时间窗、地址或端口自己再判一次。
 *
 * [videoStream] 是视频流（[rtpVideoCodecId] 判它是不是 H.264/H.265）；音频流由
 * [primaryAudioStream] 选出来，规则与 `RtpCallLinker.mosFor` 选「主方向那条流」一致：
 * `FORWARD` → `REVERSE` → 第一条。
 *
 * 视频这半的事实（编码、可解码性）全部读自**调用方交进来的那条流**：它就是调用方
 * 要导出的那一条，生产里与 M3 结果里的那个对象是同一个（扫描结果只有一份）。呼叫的
 * 查找只按 id 匹配（[linkedCallFor]），音频流则只能来自呼叫自己的流表。
 */
fun rtpAvMuxAvailability(
    videoStream: RtpStream,
    calls: List<VoipCall>,
    aacEncoderAvailable: Boolean?
): RtpAvMuxAvailability {
    val call = linkedCallFor(videoStream.id, calls) ?: return RtpAvMuxAvailability.NoCall
    val audioStream = primaryAudioStream(call)
        ?: return RtpAvMuxAvailability.CallHasNoAudio(call.callId)
    if (audioStream.decodable != RtpDecodability.YES) {
        return RtpAvMuxAvailability.NoRenderedWav(audioStream.id)
    }
    if (rtpVideoCodecId(videoStream.codec) == null ||
        videoStream.decodable != RtpDecodability.YES
    ) {
        return RtpAvMuxAvailability.NoVideoExport
    }
    if (aacEncoderAvailable == false) return RtpAvMuxAvailability.NoAacEncoder
    return RtpAvMuxAvailability.Ready(callId = call.callId, audioStreamId = audioStream.id)
}

/**
 * [videoStreamId] 所属的那个呼叫，取自 M3 已经算好的结果。
 *
 * 这是**查找**而不是重新关联：`RtpCallLinker` 已经按它的四张表决定了一条流落在哪个
 * 呼叫上，这里只回答「哪条呼叫的流表里有它」。一条流最多只会在一个呼叫里（关联器保证
 * 了这一点），所以取第一个命中即可；没有命中就是 [RtpAvMuxAvailability.NoCall]。
 */
fun linkedCallFor(videoStreamId: String, calls: List<VoipCall>): VoipCall? =
    calls.firstOrNull { call -> call.streams.any { it.stream.id == videoStreamId } }

/**
 * 这个呼叫用来做音轨的那条音频流：`FORWARD` 优先，其次 `REVERSE`，再没有就取第一条。
 *
 * 与 `RtpCallLinker.mosFor` 取「呼叫主方向那条流」是同一口径 —— 卡片说的是一路音频
 * 合成进视频，而一个呼叫里最多有两条音频流（两个方向），选主方向是有依据的那一个。
 */
fun primaryAudioStream(call: VoipCall): RtpStream? {
    val audio = call.streams.filter { isAudioStream(it.stream) }
    return (
        audio.firstOrNull { it.direction == RtpStreamDirection.FORWARD }
            ?: audio.firstOrNull { it.direction == RtpStreamDirection.REVERSE }
            ?: audio.firstOrNull()
        )?.stream
}

/**
 * 这个编码在本仓库能渲染出 WAV 吗 —— 也就是「这条流是不是音轨」。
 *
 * 「是音频」的定义就是「导出表里有 WAV」：`RtpCodecCatalog.exportFormats` 是本仓库
 * 唯一一张「这个编码能出什么」的表，用它比另造一套编解码器种类判断更不容易与导出
 * 管线脱节 —— 视频编码（H264/H265）与事件编码（telephone-event）在那张表里都没有
 * WAV，正是因为它们渲染不出音频。
 */
private fun isAudioStream(stream: RtpStream): Boolean =
    RtpExportFormat.WAV in RtpCodecCatalog.exportFormats(stream.codec)

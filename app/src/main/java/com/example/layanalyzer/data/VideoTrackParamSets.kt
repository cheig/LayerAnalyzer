package com.example.layanalyzer.data

import com.example.layanalyzer.model.RtpVideoCodecData
import java.util.Base64

/**
 * RTP5-KT-02：交给视频封装器的参数集，以及它的两个来源之间的顺序。
 *
 * 顺序是：调用方给的 [preferred]（SDP 的 `a=fmtp`，RTP5-KT-00 的 `SdpVideoParams.from`
 * 结果）优先；它给不出来时用原生 `exportRtpVideo` 结果里的 [reported]（`csd`）。
 *
 * **为什么 `csd` 可以当第二个来源。** KT-01 的卡片写的是「参数集直接用 KT-00 的结果
 * （**不要**从 ES 里重新扫）」—— 那条规则针对的是「不要在封装器里再长出一套自己的
 * 参数集扫描器」，而 `csd` 不是扫描：它是**生产方**（原生 `exportRtpVideo`）对「我刚
 * 写出的 ES 开头带的是哪组参数集」的权威回答，与它据以算出 `width`/`height` 的是同一组
 * 字节（RTP5-NAT-05 decision 7/10）。用它填 `csd-0`/`csd-1` 既不与那条规则冲突，也不需要
 * 在这里读 SDP、更不需要造字节。
 *
 * 而且没有这第二个来源，KT-01 自己的验收用例走不到：卡片要求「一个带 SDP
 * `sprop-parameter-sets`、一个**带内** SPS/PPS」两个 H.264 夹具都导出 MP4，而带内那个
 * 没有 SDP；封装器对缺 SPS/PPS 是 fail-closed（回 `missingParameterSets`），于是没有
 * 这条兜底时**每一条** MP4 导出都会失败。今天 SDP 这一路在本仓库里没有任何调用方能给
 * 出值（RTP3-NAT-04 的 `readRtpSetupInfo` 还不存在），`csd` 这一路就是唯一能成功的来源。
 *
 * **别把两个 `paramSets` 混为一谈。** 请求里的 `paramSets` 是「**注入**：这条流自己
 * 缺参数集时由 SDP 补到流开头」，只有 SDP 给得出；本函数返回的是「**这条轨道是什么**」
 * 的描述，生产方对后者的回答就在 [reported] 里。所以
 * [RtpRepository.buildVideoExportRequest] 依旧只在调用方真的给了值时写出那个请求键，
 * 本函数只决定封装器拿到什么，不改请求。
 *
 * 两个来源都为空时返回空组：封装器对它 fail-closed（`missingParameterSets`），
 * 也就是「哪里都找不到参数集」仍然是一条明确的失败，绝不会变成一个坏 MP4。
 */
internal fun videoTrackParamSets(
    preferred: VideoParamSets?,
    reported: RtpVideoCodecData
): VideoParamSets =
    if (preferred != null && preferred.hasAnyParameterSet()) {
        // 调用方给了就听调用方的：SDP 是权威值，也是卡片点名的来源。
        preferred
    } else {
        reported.toParamSets()
    }

/**
 * `exportRtpVideo` 结果里的 `csd`（[videoTrackParamSets] 的第二个来源）→
 * [VideoParamSets]。三个值各自 Base64 解一次；`null`、空串、解出来是 0 字节，
 * 三者都当作「没有这一组」。
 *
 * Base64 用 `java.util.Base64` 而不是 `android.util.Base64`：minSdk 是 26，两者的标准
 * 字母表与填充规则一致（`java.util` 的**解码**器也接受无填充输入），而 `java.util`
 * 这个不碰 `android.*` —— 于是本函数与上游的顺序规则可以被 JVM 单测直接钉住，不必再开
 * 一道解码接缝。`data/SdpVideoParams.kt` 之所以用 `android.util.Base64` 加一个可注入的
 * `decode` 参数，是因为 KT-00 的卡片点名了那个调用；这里没有那条约束。
 *
 * `packetizationMode` / `profileLevelId` / `donDiff` 一律 `null`：`csd` 只说字节，不带
 * fmtp 的标量。`donDiff` 也只影响**请求**（H.265 的 DONL 拒绝），与轨道描述无关。
 *
 * 解不出来的项**丢掉**（不猜、不抛）：结果是那一组为空，封装器随即对该编码 fail-closed。
 */
internal fun RtpVideoCodecData.toParamSets(): VideoParamSets = VideoParamSets(
    sps = sps.decodeCsdEntry(),
    pps = pps.decodeCsdEntry(),
    vps = vps.decodeCsdEntry(),
    packetizationMode = null,
    profileLevelId = null,
    donDiff = null
)

/** 一项 `csd` → 0 或 1 个参数集字节；`null`、空串、空字节与非法的 Base64 都是「没有」。 */
private fun String?.decodeCsdEntry(): List<ByteArray> {
    if (isNullOrEmpty()) return emptyList()
    val bytes = try {
        Base64.getDecoder().decode(this)
    } catch (_: IllegalArgumentException) {
        null
    }
    return if (bytes == null || bytes.isEmpty()) emptyList() else listOf(bytes)
}

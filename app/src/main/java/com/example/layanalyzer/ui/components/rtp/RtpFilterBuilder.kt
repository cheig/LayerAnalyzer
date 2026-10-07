// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.model.RtpStream
import java.util.Locale

/**
 * 把一个 [RtpStream] 转成只包含它的显示过滤器（RTP1-UI-02）。
 *
 * 纯函数对象：不依赖 Android、不是 `@Composable`、不使用 `stringResource`，因此可以在
 * 普通 JVM 单测里直接断言字符串。
 *
 * 字段顺序固定：
 * `ip.src==… && udp.srcport==… && ip.dst==… && udp.dstport==… && rtp.ssrc==0x…`；
 * 地址字符串含 `:`（IPv6）时把 `ip.src`/`ip.dst` 换成 `ipv6.src`/`ipv6.dst`，其余不变。
 * `ssrc` 一律用 `String.format(Locale.US, "0x%08x", …)` 重新格式化（不复用 [RtpStream.ssrcHex]），
 * 保证小写、补足 8 位。过滤器里**不含** `rtp.setup-frame`。
 */
object RtpFilterBuilder {

    /** 生成只包含这一条流的显示过滤器。地址是 IPv6 时用 `ipv6.*`，否则用 `ip.*`。 */
    fun forStream(stream: RtpStream): String {
        val isIpv6 = stream.src.contains(':') || stream.dst.contains(':')
        val srcField = if (isIpv6) "ipv6.src" else "ip.src"
        val dstField = if (isIpv6) "ipv6.dst" else "ip.dst"
        val ssrcHex = String.format(Locale.US, "0x%08x", stream.ssrc)
        return "$srcField==${stream.src} && udp.srcport==${stream.srcPort} && " +
            "$dstField==${stream.dst} && udp.dstport==${stream.dstPort} && rtp.ssrc==$ssrcHex"
    }
}

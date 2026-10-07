package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.data.VoipCall

/**
 * 把一通 [VoipCall] 转成只包含它的显示过滤器（RTP3-UI-04「过滤此呼叫」）。
 *
 * 纯函数对象：不依赖 Android、不是 `@Composable`、不使用 `stringResource`，因此可以在
 * 普通 JVM 单测里直接断言字符串。单条流的字段由 [RtpFilterBuilder.forStream] 生成
 * （**不重复实现**），这里只负责把若干条流与 SIP 的 `Call-ID` 用 ` || ` 拼起来。
 *
 * 输出形状（` || ` 作为分隔符，流的部分一律加括号，保证 `&&` 的优先级不会被拆散）：
 *
 * ```
 * sip.Call-ID == "abcd" || (ip.src==… && …) || (…)
 * ```
 *
 * ### 三条规则
 *
 * 1. `callId` 非空时作为第一个条件；`"` 与 `\` 前加 `\` 转义（Wireshark 过滤器字符串
 *    语法）。空（或只有空白）的 `callId` 直接省略该条件，只用流的部分。
 * 2. 流数超过 [MAX_STREAMS_IN_FILTER] 时不生成流条件——21 个 `(...)` 拼出来的过滤器既
 *    没人读得懂，编译也慢——只保留 `Call-ID` 条件并置 `truncated = true`，由 UI 明说
 *    「只用了 Call-ID 部分」。**流一条都不会被静默丢掉**：要么全在，要么由 `truncated`
 *    显式告知。
 * 3. 既没有 `Call-ID` 又没有流（或流超过上限且没有 `Call-ID` 可退）时返回空字符串 +
 *    `truncated = false`，UI 据此禁用按钮。**空过滤器恒有 `truncated == false`**：
 *    没有任何东西可截断。
 *
 * 上限截断只按**流条数**算（`call.streams.size`），不做去重——同一 Ssrc 被关联两次是
 * 关联器的事，这里照数算，避免引入第二套判断。
 */
object VoipFilterBuilder {

    /** 过滤器里最多放多少条流；超过就退化成只按 `Call-ID` 过滤（见类注释规则 2）。 */
    const val MAX_STREAMS_IN_FILTER = 20

    /** 条件分隔符：Wireshark 读得懂、人也读得懂的 ` || `。 */
    private const val OR = " || "

    /**
     * @property filter 可直接交给显示过滤器的字符串；为空表示没有可过滤的条件（UI 禁用按钮）。
     * @property truncated 是否因为流数超限而**没有**写入流条件（UI 提示用户只用了 `Call-ID`）。
     */
    data class Result(val filter: String, val truncated: Boolean)

    /** 生成只包含这一通呼叫的显示过滤器。 */
    fun forCall(call: VoipCall): Result {
        val callId = callIdCondition(call.callId)

        if (call.streams.size > MAX_STREAMS_IN_FILTER) {
            // 规则 2/3：超过上限只留 Call-ID；没有 Call-ID 就什么都留不下。
            return if (callId == null) Result("", false) else Result(callId, true)
        }

        val parts = ArrayList<String>(call.streams.size + 1)
        if (callId != null) parts += callId
        // 每条流用 RtpFilterBuilder 生成，再用括号包住，保证与 Call-ID 的 || 优先级正确。
        for (linked in call.streams) {
            parts += "(${RtpFilterBuilder.forStream(linked.stream)})"
        }
        return Result(parts.joinToString(OR), false)
    }

    /**
     * `sip.Call-ID == "…"`；`callId` 为空或只有空白时返回 `null`（调用方跳过该条件）。
     * 字符串字面量按 Wireshark 规则转义：先 `\` 后 `"`，顺序不能反。
     */
    private fun callIdCondition(callId: String): String? {
        if (callId.isBlank()) return null
        val escaped = callId.replace("\\", "\\\\").replace("\"", "\\\"")
        return "sip.Call-ID == \"$escaped\""
    }
}

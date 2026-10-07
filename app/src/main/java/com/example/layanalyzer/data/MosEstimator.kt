package com.example.layanalyzer.data

/**
 * 一次 MOS 估算的结果（RTP3-KT-03）。
 *
 * [mos] 永远只是**估算值**，不是测量值：E-model 给的是「在给定丢包与时延下，
 * 该编码的主观质量期望分」，因此 [isEstimate] 恒为 `true`，UI 必须照此标注
 * （卡片禁止把 MOS 当成实测值）。
 *
 * @param mos 估算出的 MOS（1.0–4.5）。
 * @param r 夹到 `[0, 100]` 之后的 R 值（传输等级因子），[mos] 就是由它换算来的。
 * @param isEstimate 恒为 `true`，见上文。
 * @param codec 调用方传入的编码标识，原样回填（大小写、空白都不动）。
 * @param lossPercent 调用方传入的丢包百分比，原样回填（内部计算用的是夹到
 *   `0..100` 之后的值，见 [MosEstimate.ieEff]）。
 * @param oneWayDelayMs 调用方传入的单向时延（毫秒），原样回填。
 * @param ieEff 代入公式的 `Ie_eff`（已把 `Ppl` 夹到 `0..100`）。
 * @param inputs 计算输入的字符串快照，键固定为
 *   `codec` / `lossPercent` / `oneWayDelayMs` / `delaySource`，供 UI 展示「估算依据」。
 */
data class MosEstimate(val mos: Double, val r: Double, val isEstimate: Boolean = true,
                       val codec: String, val lossPercent: Double, val oneWayDelayMs: Double,
                       val ieEff: Double, val inputs: Map<String, String>)

/**
 * 简化 E-model 的 MOS 估算（RTP3-KT-03）。
 *
 * 只实现窄带语音最常用的那一支：`R = 93.2 − Id − Ie_eff`，`R` 再按标准多项式换成 MOS。
 * 没有查表命中的编码（宽带的 G.722 / AMR-WB / opus，以及 `telephone-event` 之类的事件流）
 * 一律返回 `null`，由 UI 显示「不适用」——**不允许**拿窄带公式硬套宽带编码。
 *
 * R 为负（时延和丢包把质量压到 0 以下）时 `mos == 1.0` 且 `r == 0.0`。
 *
 * ### Ie / Bpl 数值出处
 *
 * [impairment] 里的 Ie（设备损伤因子）与 Bpl（丢包健壮性因子）取自
 * **ITU-T Recommendation G.113 (02/2001)，附录 I（Appendix I）表 I.1**——即 E-model 文献里
 * 通用的那张「Ie / Bpl 取值表」。本项目引用的是该 02/2001 版的数值，后续版本沿用同一组取值。
 *
 * - `g711A` / `g711U`：`Ie = 0.0`、`Bpl = 25.1`。G.711 在表里分「有 PLC」和「无 PLC」两列，
 *   两者的 Ie 都是 0，差别只在 Bpl（无 PLC 那一列的 Bpl 远小于 25.1）。这里取 **有 PLC** 的一列，
 *   因为本项目的 G.711 播放路径会对丢失的帧做丢包隐藏（PLC）：按无 PLC 列取值会把丢包的影响
 *   估得过大，与用户实际听到的质量不符。
 * - `g729`：`Ie = 11.0`、`Bpl = 19.0`，对应表里 **G.729A + VAD** 那一行。
 *
 * 表里没有的编码不做插值、不做外推：G.722（宽带）、AMR-WB、opus 以及各种事件流直接返回 `null`。
 *
 * @see defaultOneWayDelayMs
 */
object MosEstimator {

    /**
     * [estimate] 在调用方拿不到 RTCP 时使用的 `delaySource` 取值：
     * 单向时延是 [defaultOneWayDelayMs] 这个缺省值，不是实测值。
     */
    const val DEFAULT_DELAY_SOURCE = "default"

    /** Ie / Bpl 表（ITU-T G.113 (02/2001) 附录 I 表 I.1，见类注释）。 */
    private val impairment = mapOf(
        "g711A" to (0.0 to 25.1),   // G.711 + PLC（Bpl = 25.1 的“有 PLC”一列）
        "g711U" to (0.0 to 25.1),
        "g729"  to (11.0 to 19.0)   // G.729A + VAD
    )

    /**
     * 估算 [codec] 在丢包率 [lossPercent]（0–100 的百分比）、单向时延 [oneWayDelayMs] 毫秒下的 MOS。
     *
     * 编码按 [codec] `trim()` 之后**大小写不敏感**地与 [impairment] 的键匹配
     * （规范 ID 见 `RtpCodecCatalog`，所以 `"g711a"` 与 `"g711A"` 命中同一行）；
     * 没有窄带 Ie 值的编码（G.722、AMR-WB、opus、`telephone-event`、空串等）返回 `null`。
     *
     * [lossPercent] 会先被夹到 `0..100` 再代入 `Ie_eff` 公式；返回对象里的
     * [MosEstimate.lossPercent] / [MosEstimate.oneWayDelayMs] / [MosEstimate.codec] 原样回填调用方的入参，
     * 实际参与计算的口径记在 [MosEstimate.ieEff] 与 [MosEstimate.inputs] 里。
     */
    fun estimate(codec: String, lossPercent: Double, oneWayDelayMs: Double,
                 delaySource: String = DEFAULT_DELAY_SOURCE): MosEstimate? {
        val (ie, bpl) = impairment.entries
            .firstOrNull { it.key.equals(codec.trim(), ignoreCase = true) }
            ?.value
            ?: return null

        // 2. Ie_eff = Ie + (95 - Ie) * Ppl / (Ppl + Bpl)，Ppl 先夹到 0..100。
        val ppl = lossPercent.coerceIn(0.0, 100.0)
        val ieEff = ie + (95.0 - ie) * ppl / (ppl + bpl)

        // 3. Id = 0.024 * d + 0.11 * (d - 177.3) 仅在 d > 177.3 时生效。
        val d = oneWayDelayMs
        val id = 0.024 * d + (if (d > 177.3) 0.11 * (d - 177.3) else 0.0)

        // 4. R 夹到 [0, 100]；夹过之后 R 不可能为负，第 5 步的负值分支只是兜底。
        val r = (93.2 - id - ieEff).coerceIn(0.0, 100.0)

        // 5. MOS = 1 + 0.035R + R(R-60)(100-R) * 7e-6，夹到 [1.0, 4.5]。
        val mos = if (r < 0.0) 1.0 else mosFromR(r)

        return MosEstimate(
            mos = mos,
            r = r,
            isEstimate = true,
            codec = codec,
            lossPercent = lossPercent,
            oneWayDelayMs = oneWayDelayMs,
            ieEff = ieEff,
            inputs = mapOf(
                "codec" to codec,
                "lossPercent" to lossPercent.toString(),
                "oneWayDelayMs" to oneWayDelayMs.toString(),
                "delaySource" to delaySource
            )
        )
    }

    /**
     * 缺省单向时延：没有 RTCP 时用 100 ms（含抖动）。
     *
     * 用这个值时 [estimate] 的 `delaySource` 应传 [DEFAULT_DELAY_SOURCE]，这样 UI 能区分
     * 「时延是实测的」还是「时延是缺省假设的」。
     */
    fun defaultOneWayDelayMs(): Double = 100.0

    /** 标准的 R → MOS 多项式，结果夹到 `[1.0, 4.5]`。 */
    private fun mosFromR(r: Double): Double =
        (1.0 + 0.035 * r + r * (r - 60.0) * (100.0 - r) * 7e-6).coerceIn(1.0, 4.5)
}

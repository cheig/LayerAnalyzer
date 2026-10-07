package com.example.layanalyzer.ui.components.rtp

import com.example.layanalyzer.media.VidxEntry
import com.example.layanalyzer.media.isCorrupt

/**
 * RTP5-KT-03：某一时刻正在显示的那个访问单元。
 *
 * [index] 是它在 `.vidx` 里的下标（也就是它在 MP4 里的样本序号），[entry] 是那一条记录 ——
 * 包号（`entry.firstFrame`）由调用方从 [entry] 里取，本文件只负责「哪一个」。
 */
data class RtpVideoPreviewAccessUnit(
    val index: Int,
    val entry: VidxEntry
)

/**
 * RTP5-KT-03：进度条上的一段损坏区间，归一化到 `[startFraction, endFraction)`。
 *
 * 用**比例**而不是毫秒或像素：进度条的宽度由布局决定，本文件不碰任何 `android.*` 类型，
 * 所以绘制方拿到的是「占总时长的百分之几」，乘自己的宽度即可。
 */
data class RtpVideoPreviewSpan(
    val startFraction: Float,
    val endFraction: Float
)

/**
 * RTP5-KT-03：播放位置 → 正在显示的访问单元，用 `.vidx` 的 `ptsUs` 二分。
 *
 * 卡片原文是「用 `.vidx` 的 `first_frame` 二分查找显示当前帧对应的数据包号」。真正被二分的
 * 键是**展示时间** `ptsUs`（`.vidx` 是按展示顺序写的，这正是二分要求的单调性），
 * `first_frame` 是这次查找的**结果** —— 找到那一条记录之后，它的 `firstFrame` 就是「当前帧
 * 对应的数据包号」。
 *
 * 时间原点是共用的，这一点由 RTP5-NAT-03 保证而不是这里猜的：`VideoSamplePlan` 的注释写明
 * 「NAT-03 numbers PTS from the first access unit's own timestamp, so the first sample is at
 * 0」，所以 MediaPlayer 报回来的 0 毫秒就是第一条 `ptsUs`，不需要再加任何偏移。
 *
 * 边界口径（每一条都有单测钉住）：
 *  - 空列表 → `null`（没有可显示的帧）。
 *  - `positionUs` 早于第一条 `ptsUs` → `null`。**不是**夹到第 0 条：那时屏幕上确实还没有
 *    任何一帧，把第 0 条报出来是在编一个不存在的对应关系。
 *  - `positionUs` 正好等于某条 `ptsUs` → 就是那一条（比较用 `<=`，「此刻开始显示的」）。
 *  - 最后一条之后 → 仍然是最后一条：它一直显示到播放结束（`MediaMuxer` 会在最后一个样本
 *    自己的时长上补齐，所以时长的尾巴本来就在这个 AU 里）。
 *  - 单条列表 → 只要 `positionUs >= ptsUs` 就是它，之前是 `null`。
 *
 * **非单调的 `ptsUs`**：本函数不做修复也不排序。`.vidx` 由 NAT-03 按展示顺序写，正常就是
 * 非递减的；真出现逆序时（B 帧流、人工构造的索引），二分在逆序数组上落点由数组形状决定，
 * 本函数照实返回它落到的那个下标，**不**事后回退去猜「更靠前的那一条」—— 修复是
 * `VideoSamplePlan` 的职责（`+1` 微秒），索引这一侧保持一致地照抄文件内容。单测把逆序输入
 * 的落点逐个钉死，这样它是「一个决定」而不是「一个巧合」。
 *
 * 由此还有一个已知的、微秒量级的偏差值得写下来：**MP4 里的时间轴是修过的，这里比较的是
 * `.vidx` 里的原值**。封装器把等于或小于前一个的 PTS 推成 `previous + 1`，所以 B 帧流里
 * 播放器报的位置可能比原值大出「修了几次」那么多微秒。它只在一个时间点上会改变结论 ——
 * 位置正好落在两条记录之间那 1 微秒里；要把它也消灭掉，得让封装器把修复后的时间写回索引，
 * 那是 KT-01/NAT-05 的事，不是这里偷偷加偏移能解决的。
 */
fun rtpPreviewAccessUnitAt(
    positionUs: Long,
    entries: List<VidxEntry>
): RtpVideoPreviewAccessUnit? {
    val index = bisectLastAtMost(entries, positionUs) { it.ptsUs }
    if (index < 0) return null
    return RtpVideoPreviewAccessUnit(index = index, entry = entries[index])
}

/**
 * RTP5-KT-03：「跳到数据包」的反向查找：数据包号 → 播放位置，用 `firstFrame` 二分。
 *
 * 返回的是**包含该数据包的那个访问单元**的 `ptsUs`，也就是把它拖到进度条上应该跳到的位置。
 * 一个 AU 覆盖的包号区间是 `[firstFrame, 下一个 AU 的 firstFrame)`：丢失的包不会出现在任何
 * 一条记录里，但它仍然落在前一个 AU 的区间内，所以命中的是「它本该属于的那一帧」。
 *
 * 边界口径：
 *  - 空列表 → `null`；`frame` 早于第一条 `firstFrame` → `null`（预览里没有这一包对应的时间）。
 *  - 正好等于某条 `firstFrame` → 就是那一条（`<=`，区间的左端是闭的）。
 *  - 最后一个 AU 之后的包（含丢包造成的空洞尾段）→ 最后一个 AU 的 `ptsUs`。
 *  - `firstFrame` 逆序时与 [rtpPreviewAccessUnitAt] 同一口径：不打补丁，照实返回二分的落点。
 */
fun rtpPreviewSeekUsForFrame(
    frame: Long,
    entries: List<VidxEntry>
): Long? {
    val index = bisectLastAtMost(entries, frame) { it.firstFrame.toLong() }
    if (index < 0) return null
    return entries[index].ptsUs
}

/**
 * RTP5-KT-03：进度条上要标红的那几段，按 `[start, end)` 归一化到总时长。
 *
 * 一个损坏访问单元占的时间是 `[它的 ptsUs, 下一个 AU 的 ptsUs)`，最后一条到 [durationUs]
 * 为止（`MediaMuxer` 会在最后一个样本自己的时长上补齐，所以时长本来就比最后一个 PTS 大出
 * 一帧，最后一段不是零长度）。相邻的两段（前一段的结束正好是后一段的开始）**合并成一段**，
 * 这样连续损坏的几帧画出来是一整条红线，而不是一串边界重叠的矩形。
 *
 * 零长度与零时长（这两个都是「不除零」的硬性要求，不是顺手写的保护）：
 *  - `durationUs <= 0` 或列表为空 → **空列表**。比例的分母是 0 时，「哪一段是红的」没有
 *    任何意义，返回空表比返回一段 `[0, 1)` 的满屏红更诚实：满屏红会看起来像「整段都坏了」。
 *  - 单独一段在夹取之后 `end <= start`（两条记录的 `ptsUs` 相同、或者 PTS 逆序、或者它已经
 *    落在时长之外）→ **丢掉这一段**：它在进度条上的宽度是 0 像素，画不出来。丢掉**不等于**
 *    「这里没坏」—— 损坏帧的数量是另一条信息（调用方按 `isCorrupt` 数），本函数只回答
 *    「哪些区间看得见」。
 */
fun rtpPreviewCorruptSpans(
    entries: List<VidxEntry>,
    durationUs: Long
): List<RtpVideoPreviewSpan> {
    if (entries.isEmpty() || durationUs <= 0L) return emptyList()

    val intervals = ArrayList<Pair<Long, Long>>()
    entries.forEachIndexed { index, entry ->
        if (!entry.isCorrupt) return@forEachIndexed
        // 下一段的开始就是这一段的结束；最后一段一直画到总时长。
        val nextUs = entries.getOrNull(index + 1)?.ptsUs ?: durationUs
        val startUs = entry.ptsUs.coerceIn(0L, durationUs)
        // 先把结束夹到不早于开始（PTS 逆序时 nextUs < startUs），再夹到时长之内。
        val endUs = nextUs.coerceIn(startUs, durationUs)
        if (endUs > startUs) {
            intervals += startUs to endUs
        }
    }

    val merged = ArrayList<Pair<Long, Long>>(intervals.size)
    intervals.forEach { (startUs, endUs) ->
        val last = merged.lastOrNull()
        when {
            // 相接（`startUs == last.second`）或重叠都算一段。
            last == null || startUs > last.second -> merged += startUs to endUs
            endUs > last.second -> merged[merged.size - 1] = last.first to endUs
            else -> Unit
        }
    }

    return merged.map { (startUs, endUs) ->
        RtpVideoPreviewSpan(
            startFraction = (startUs.toDouble() / durationUs.toDouble()).toFloat(),
            endFraction = (endUs.toDouble() / durationUs.toDouble()).toFloat()
        )
    }
}

/**
 * 对 `entries` 做二分，返回最后一个满足 `key(entry) <= target` 的下标；一个都没有时 -1。
 *
 * 就是 `upper_bound` 减一：`low` 停在「第一个大于 target 的位置」上。`entries` 非空但 target
 * 比第一个键还小时 `low == 0`，减一得 -1 —— 这正是两个查找函数共用的「它之前没有东西」。
 */
private inline fun bisectLastAtMost(
    entries: List<VidxEntry>,
    target: Long,
    key: (VidxEntry) -> Long
): Int {
    var low = 0
    var high = entries.size
    while (low < high) {
        val mid = (low + high) ushr 1
        if (key(entries[mid]) <= target) low = mid + 1 else high = mid
    }
    return low - 1
}

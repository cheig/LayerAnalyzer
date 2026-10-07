package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.model.AnalyzerPreferences

/**
 * RTP 启发式偏好的纯决策逻辑（RTP1-KT-03）。
 *
 * `PacketListViewModel` 需要 `Context` 才能构造，而本项目没有 Robolectric，
 * 所以持久化键名与更新路径上的两个决策点放在这里，便于离线单测。
 */
internal object RtpHeuristicPreferenceOps {
    /** 分析器首选项的 SharedPreferences 文件；[PREFERENCE_KEY] 只是其中一个键。 */
    const val PREFERENCE_FILE = "analyzer_preferences"

    /** 本开关的键名；`LayerAnalyzerApplication` 启动恢复时使用同一个键。 */
    const val PREFERENCE_KEY = "rtpHeuristicEnabled"

    /** 只有值真的变了才需要调 JNI 并失效分析结果。 */
    fun changed(current: AnalyzerPreferences, next: AnalyzerPreferences): Boolean =
        current.rtpHeuristicEnabled != next.rtpHeuristicEnabled

    /** fail-closed：原生没接受就不生效，[error] 非空时回到旧值。 */
    fun resolve(previous: AnalyzerPreferences, attempted: AnalyzerPreferences, error: String): AnalyzerPreferences =
        if (error.isEmpty()) attempted else previous
}

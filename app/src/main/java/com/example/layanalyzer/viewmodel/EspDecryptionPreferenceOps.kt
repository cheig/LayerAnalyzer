// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.model.AnalyzerPreferences
import com.example.layanalyzer.model.EspDecryptionMode

/**
 * ESP NULL 解密偏好的纯决策逻辑。
 *
 * 与 [RtpHeuristicPreferenceOps] 同构：`PacketListViewModel` 需要 `Context`
 * 才能构造，而本项目没有 Robolectric，所以持久化键名、取值解析与更新路径上的
 * 两个决策点放在这里，便于离线单测。
 */
internal object EspDecryptionPreferenceOps {
    /** 分析器首选项的 SharedPreferences 文件；[PREFERENCE_KEY] 只是其中一个键。 */
    const val PREFERENCE_FILE = "analyzer_preferences"

    /** 本选项的键名；`LayerAnalyzerApplication` 启动恢复时使用同一个键。 */
    const val PREFERENCE_KEY = "espDecryptionMode"

    /** 缺省策略：打开抓包时先探测，只有确认是 NULL 加密才解密。 */
    val DEFAULT_MODE: EspDecryptionMode = EspDecryptionMode.Probe

    /** 只有值真的变了才需要调 JNI 并失效分析结果。 */
    fun changed(current: AnalyzerPreferences, next: AnalyzerPreferences): Boolean =
        current.espDecryptionMode != next.espDecryptionMode

    /** 持久化的是枚举名；缺失或认不出来一律回落到 [DEFAULT_MODE]。 */
    fun parse(stored: String?): EspDecryptionMode =
        stored?.let { name -> EspDecryptionMode.values().firstOrNull { it.name == name } }
            ?: DEFAULT_MODE

    /** fail-closed：原生没接受就不生效，[error] 非空时回到旧值。 */
    fun resolve(
        previous: AnalyzerPreferences,
        attempted: AnalyzerPreferences,
        error: String
    ): AnalyzerPreferences = if (error.isEmpty()) attempted else previous
}

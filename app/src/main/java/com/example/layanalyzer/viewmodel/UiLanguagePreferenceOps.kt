package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.model.UiLanguage

/**
 * 界面语言首选项的纯逻辑部分。
 *
 * 刻意不引用任何 Android 类型：语言解析与"要不要重建 Activity"的判断都能在
 * JVM 单测里跑（项目没有 Robolectric，SharedPreferences 也不可在单测里实例化）。
 * 真正碰 [android.content.Context] 的两件事——读偏好与调用
 * `AppCompatDelegate.setApplicationLocales`——留在调用方。
 *
 * 与 [EspDecryptionPreferenceOps] 共用同一个 SharedPreferences 文件
 * （[PREFERENCE_FILE]），不新开第三个偏好文件。
 */
internal object UiLanguagePreferenceOps {
    /** 分析器首选项的 SharedPreferences 文件，与 [EspDecryptionPreferenceOps.PREFERENCE_FILE] 同址。 */
    const val PREFERENCE_FILE = EspDecryptionPreferenceOps.PREFERENCE_FILE

    /** 本选项的键名。 */
    const val PREFERENCE_KEY = "uiLanguage"

    /** 缺省策略：跟随系统。 */
    val DEFAULT_LANGUAGE: UiLanguage = UiLanguage.SYSTEM

    /** 持久化的是 [UiLanguage.tag]；缺失或认不出来一律回落到 [DEFAULT_LANGUAGE]。 */
    fun parse(stored: String?): UiLanguage = UiLanguage.fromTag(stored)

    /** 存回 SharedPreferences 的值；[UiLanguage.SYSTEM] 存空串而不是枚举名。 */
    fun persistValue(language: UiLanguage): String = language.tag

    /**
     * 只有语言真的变了才需要重建界面。
     *
     * 语言不影响抓包会话、分析结果或任何 JNI 调用，所以这里纯粹是避免
     * "点了当前语言 → 无谓的 Activity 重建"。
     */
    fun changed(current: UiLanguage, next: UiLanguage): Boolean = current != next

    /**
     * 是否需要调用 `setApplicationLocales`。
     *
     * [UiLanguage.SYSTEM] 对应"清空覆盖列表"（`LocaleListCompat.getEmptyLocaleList()`），
     * 这和"从未设置过"是同一个状态，所以也返回 false——首次启动无需动 locale，
     * 由系统自己解析。
     */
    fun needsLocaleOverride(language: UiLanguage): Boolean = language != UiLanguage.SYSTEM
}

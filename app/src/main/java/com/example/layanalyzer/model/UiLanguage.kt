// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.model

/**
 * 界面语言选项。
 *
 * 标签是 BCP 47 语言标签，直接交给 `AppCompatDelegate.setApplicationLocales`；
 * [SYSTEM] 用空串表示"不覆盖系统设置"，也是 `LocaleListCompat.getEmptyLocaleList()`
 * 的期望值。
 *
 * 枚举名与持久化值（[tag]）刻意解耦：改枚举名不会丢用户的已保存选择。
 */
enum class UiLanguage(val tag: String) {
    /** 跟随系统 locale；不调用 setApplicationLocales 覆盖。 */
    SYSTEM(""),

    /** 简体中文。 */
    CHINESE("zh-CN"),

    /** 英文。 */
    ENGLISH("en");

    companion object {
        /**
         * 容错解析：认不出来的存储值一律回落到 [SYSTEM]，不静默猜一个语言。
         *
         * 空串（未设置过）与 null（无 pref 文件）都回落到 [SYSTEM]，即首次启动
         * 跟随系统，而不是强制英文。
         */
        fun fromTag(stored: String?): UiLanguage =
            values().firstOrNull { it.tag == stored } ?: SYSTEM
    }
}

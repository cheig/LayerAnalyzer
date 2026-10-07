package com.example.layanalyzer.ui

import android.content.Context
import android.content.res.Configuration
import com.example.layanalyzer.model.UiLanguage
import com.example.layanalyzer.viewmodel.UiLanguagePreferenceOps
import java.util.Locale

/**
 * 界面语言的 Android 侧落地方案。
 *
 * ## 为什么不用 AppCompatDelegate.setApplicationLocales
 *
 * 那是官方推荐 API，但它在 **API < 33 上要求宿主是 AppCompatActivity** 才会自动
 * 重建 Activity，而本项目的 [com.example.layanalyzer.MainActivity] 是
 * `ComponentActivity`，minSdk 又是 26 —— 那样切了语言不会立刻生效，还得自己补
 * 一次重建，等于两套机制。
 *
 * 这里改用 [Context.createConfigurationContext]覆写基座 context：
 * **运行时切换和冷启动走的是同一条代码路径**，所以"切换后看到的"与"重启后看到的"
 * 必然一致，不会出现两个机制各说各话。代价是一次 Activity 重建，而
 * `ComponentActivity` 的 ViewModelStore 跨重建保留，抓包会话与分析结果不受影响。
 *
 * 纯逻辑（[UiLanguage] 的解析、"是否真变了"）在
 * [UiLanguagePreferenceOps] 里，那部分无 Android 依赖、可 JVM 单测。
 */
internal object UiLanguageApplier {

    /**
     * 把 [UiLanguage]应用到 [base] 的配置上。
     *
     * [UiLanguage.SYSTEM] 返回原 context，不做任何包装：首次启动（未设置过语言）
     * 因此完全跟随系统，且不额外分配一个 Configuration。
     */
    fun apply(base: Context, language: UiLanguage): Context {
        if (!UiLanguagePreferenceOps.needsLocaleOverride(language)) return base
        val locale = Locale.forLanguageTag(language.tag)
        val configuration = Configuration(base.resources.configuration).apply {
            setLocale(locale)
            setLayoutDirection(locale)
        }
        return base.createConfigurationContext(configuration)
    }

    /** 读取已保存的界面语言；缺省或损坏的值回落到跟随系统。 */
    fun stored(context: Context): UiLanguage {
        val preferences = context.getSharedPreferences(
            UiLanguagePreferenceOps.PREFERENCE_FILE,
            Context.MODE_PRIVATE
        )
        return UiLanguagePreferenceOps.parse(
            preferences.getString(UiLanguagePreferenceOps.PREFERENCE_KEY, null)
        )
    }

    /**
     * 持久化用户的语言选择。
     *
     * 用 `apply()` 而非 `commit()`：语言设置不值得阻塞调用方的主线程 I/O，
     * 且进程被杀时未落盘的只是一个"下次启动少应用一次 locale"的状态。
     */
    fun persist(context: Context, language: UiLanguage) {
        context.getSharedPreferences(UiLanguagePreferenceOps.PREFERENCE_FILE, Context.MODE_PRIVATE)
            .edit()
            .putString(UiLanguagePreferenceOps.PREFERENCE_KEY, UiLanguagePreferenceOps.persistValue(language))
            .apply()
    }
}

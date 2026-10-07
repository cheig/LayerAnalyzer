package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.model.UiLanguage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * [UiLanguagePreferenceOps] 与 [UiLanguage] 的纯 JVM 单测。
 *
 * 真正的 SharedPreferences 往返与 `setApplicationLocales` 调用需要
 * `Context`，本项目没有 Robolectric，故这两处不在覆盖范围内（见报告的
 * 「未执行项」）。这里锁住的是**解析的fail-closed 语义**与
 * **"只有真变了才重建" 的判定**——前者决定一个损坏的存储值会不会让应用
 * 悄悄换成另一种语言，后者决定切语言会不会误伤业务状态。
 */
class UiLanguagePreferenceOpsTest {

    @Test
    fun `the ui language preference shares the analyzer preferences file and has its own key`() {
        assertEquals("analyzer_preferences", UiLanguagePreferenceOps.PREFERENCE_FILE)
        assertEquals("uiLanguage", UiLanguagePreferenceOps.PREFERENCE_KEY)
    }

    @Test
    fun `an unset or absent preference follows the system locale`() {
        assertEquals(UiLanguage.SYSTEM, UiLanguagePreferenceOps.DEFAULT_LANGUAGE)
        assertEquals(UiLanguage.SYSTEM, UiLanguagePreferenceOps.parse(null))
        assertEquals(UiLanguage.SYSTEM, UiLanguagePreferenceOps.parse(""))
    }

    @Test
    fun `an unrecognised stored tag falls back to the system locale rather than guessing`() {
        // 枚举名不是合法存储值（旧版本或手改 prefs 都可能出现）。
        assertEquals(UiLanguage.SYSTEM, UiLanguagePreferenceOps.parse("CHINESE"))
        assertEquals(UiLanguage.SYSTEM, UiLanguagePreferenceOps.parse("fr-FR"))
        assertEquals(UiLanguage.SYSTEM, UiLanguagePreferenceOps.parse("zh_CN"))
    }

    @Test
    fun `every language round trips through its persisted tag`() {
        UiLanguage.values().forEach { language ->
            assertEquals(language, UiLanguagePreferenceOps.parse(UiLanguagePreferenceOps.persistValue(language)))
        }
    }

    @Test
    fun `the system option persists as an empty tag so the override can be cleared`() {
        // 空串是 LocaleListCompat.getEmptyLocaleList() 的"无覆盖"表达。
        assertEquals("", UiLanguagePreferenceOps.persistValue(UiLanguage.SYSTEM))
        assertEquals("zh-CN", UiLanguagePreferenceOps.persistValue(UiLanguage.CHINESE))
        assertEquals("en", UiLanguagePreferenceOps.persistValue(UiLanguage.ENGLISH))
    }

    @Test
    fun `only an actual language change asks for a locale override`() {
        assertFalse(
            UiLanguagePreferenceOps.needsLocaleOverride(UiLanguagePreferenceOps.DEFAULT_LANGUAGE)
        )
        assertTrue(UiLanguagePreferenceOps.needsLocaleOverride(UiLanguage.CHINESE))
        assertTrue(UiLanguagePreferenceOps.needsLocaleOverride(UiLanguage.ENGLISH))
    }

    @Test
    fun `reselecting the current language is not a change`() {
        UiLanguage.values().forEach { language ->
            assertFalse(UiLanguagePreferenceOps.changed(language, language))
        }
        assertTrue(UiLanguagePreferenceOps.changed(UiLanguage.SYSTEM, UiLanguage.ENGLISH))
        assertTrue(UiLanguagePreferenceOps.changed(UiLanguage.CHINESE, UiLanguage.ENGLISH))
        assertTrue(UiLanguagePreferenceOps.changed(UiLanguage.ENGLISH, UiLanguage.SYSTEM))
    }

    @Test
    fun `the language tags are the ones the locale override API expects`() {
        // 这三个值直接进 LocaleListCompat.forLanguageTags，错了会静默无效。
        assertEquals("", UiLanguage.SYSTEM.tag)
        assertEquals("zh-CN", UiLanguage.CHINESE.tag)
        assertEquals("en", UiLanguage.ENGLISH.tag)
    }
}

// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.data.TlsCaptureExportKind
import com.example.layanalyzer.ui.components.TlsCaptureExportDialog
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import java.io.File
import java.util.Locale
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.After

class TlsCaptureExportUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private var original: Configuration? = null
    @Suppress("DEPRECATION")
    @After fun restoreLocale() { original?.let { config ->
        compose.runOnUiThread { compose.activity.resources.updateConfiguration(config, compose.activity.resources.displayMetrics) }
    } }
    @Test fun chineseLight() = walk("zh", false)
    @Test fun chineseDark() = walk("zh", true)
    @Test fun englishLight() = walk("en", false)
    @Test fun englishDark() = walk("en", true)

    private fun walk(language: String, dark: Boolean) {
        assertEquals(360, compose.activity.resources.configuration.screenWidthDp)
        val config = Configuration(compose.activity.resources.configuration).apply { setLocale(Locale(language)) }
        original = Configuration(compose.activity.resources.configuration)
        // Android Dialog creates its own ContextThemeWrapper from the Activity resources.
        @Suppress("DEPRECATION")
        compose.runOnUiThread { compose.activity.resources.updateConfiguration(config, compose.activity.resources.displayMetrics) }
        val context = compose.activity.createConfigurationContext(config)
        fun label(id: Int) = context.getString(id)
        var filtered by mutableStateOf(false)
        var shown by mutableStateOf(true)
        var selected: Pair<TlsCaptureExportKind, Boolean>? = null
        compose.setContent {
            CompositionLocalProvider(LocalContext provides context, LocalConfiguration provides config) {
                LayerAnalyzerTheme(darkTheme = dark) {
                    if (shown) TlsCaptureExportDialog(filtered, { kind, confirmed -> selected = kind to confirmed }, { shown = false })
                }
            }
        }
        fun shot(name: String) {
            compose.waitForIdle()
            Thread.sleep(200)
            val output = File(compose.activity.getExternalFilesDir(null), "tls-311/screenshots").apply { mkdirs() }
            val bitmap = InstrumentationRegistry.getInstrumentation().uiAutomation.takeScreenshot()
            File(output, "$language-${if (dark) "dark" else "light"}-$name.png").outputStream().use {
                assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it))
            }
            bitmap.recycle()
        }
        fun readable(id: Int) {
            val text = label(id)
            val layouts = mutableListOf<TextLayoutResult>()
            compose.onNodeWithText(text, useUnmergedTree = true).performScrollTo().assertIsDisplayed()
                .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
            assertTrue(layouts.isNotEmpty())
            layouts.forEach { layout ->
                assertEquals(text.length, layout.getLineEnd(layout.lineCount - 1))
                for (line in 0 until layout.lineCount) {
                    assertFalse(layout.isLineEllipsized(line))
                    assertTrue(layout.getLineRight(line) <= layout.size.width + 1f)
                    assertTrue(layout.getLineBottom(line) <= layout.size.height + 1f)
                }
            }
        }
        fun choose(id: Int) = compose.onNodeWithText(label(id)).performScrollTo().performClick()
        val save = label(R.string.tls_capture_export_save)
        compose.onNodeWithText(label(R.string.tls_capture_export_original)).assertIsSelected()
        readable(R.string.tls_capture_export_original_hint)
        shot("01-default")
        compose.onNodeWithText(save).performClick()
        assertEquals(TlsCaptureExportKind.OriginalCapture to false, selected)
        choose(R.string.tls_capture_export_complete)
        compose.onNodeWithText(save).assertIsNotEnabled()
        readable(R.string.tls_capture_export_warning)
        shot("02-warning")
        readable(R.string.tls_capture_export_confirm)
        compose.onNode(isToggleable()).performScrollTo().performClick()
        compose.onNodeWithText(save).assertIsEnabled().performClick()
        assertEquals(TlsCaptureExportKind.CompleteDecryptableSession to true, selected)
        compose.runOnIdle { filtered = true }
        readable(R.string.tls_capture_export_filtered_warning)
        compose.onNodeWithText(save).assertIsNotEnabled()
        shot("03-filtered-disabled")
        choose(R.string.tls_capture_export_plaintext)
        readable(R.string.tls_capture_export_plaintext_hint)
        shot("04-plaintext")
        compose.onNodeWithText(label(R.string.tls_capture_export_choose_content)).performClick()
        assertEquals(TlsCaptureExportKind.SelectedPlaintext to false, selected)
        compose.onNodeWithText(label(R.string.cancel)).performClick()
        compose.onNodeWithText(label(R.string.tls_capture_export_title)).assertDoesNotExist()
    }
}

// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.pm.ActivityInfo
import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.ui.components.TlsKeyLogImportDialog
import com.example.layanalyzer.ui.components.TlsUsageHelpButton
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.TlsKeyLogImportState
import java.io.File
import java.util.Locale
import org.junit.Assert.*
import org.junit.After
import org.junit.Rule
import org.junit.Test

/** Device windows with activity-only locale/rotation and Compose 360dp/150% fonts.
 * No system setting, user preference, capture, CA or network is changed.
 */
class ReleaseHelpLayoutTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private var original: Configuration? = null
    private var previousOrientation = ActivityInfo.SCREEN_ORIENTATION_UNSPECIFIED

    @After fun restore() {
        original?.let { saved ->
            compose.runOnUiThread {
                // Preserve the real, current orientation. Restoring the pre-rotation
                // configuration can make a subsequent rotation wait on a fabricated value.
                val restored = Configuration(compose.activity.resources.configuration).apply {
                    setLocales(saved.locales)
                    fontScale = saved.fontScale
                }
                @Suppress("DEPRECATION")
                compose.activity.resources.updateConfiguration(restored, compose.activity.resources.displayMetrics)
                compose.activity.requestedOrientation = previousOrientation
            }
        }
    }

    @Test fun chineseLightPortrait() = walk("zh", false, false)
    @Test fun chineseDarkPortrait() = walk("zh", true, false)
    @Test fun englishLightPortrait() = walk("en", false, false)
    @Test fun englishDarkPortrait() = walk("en", true, false)
    @Test fun chineseLightLandscape() = walk("zh", false, true)
    @Test fun chineseDarkLandscape() = walk("zh", true, true)
    @Test fun englishLightLandscape() = walk("en", false, true)
    @Test fun englishDarkLandscape() = walk("en", true, true)

    private fun walk(language: String, dark: Boolean, landscape: Boolean) {
        original = Configuration(compose.activity.resources.configuration)
        previousOrientation = compose.activity.requestedOrientation
        val orientation = if (landscape) Configuration.ORIENTATION_LANDSCAPE else Configuration.ORIENTATION_PORTRAIT
        compose.runOnUiThread {
            compose.activity.requestedOrientation = if (landscape) ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE
                else ActivityInfo.SCREEN_ORIENTATION_PORTRAIT
        }
        compose.waitUntil(10000) { compose.activity.resources.configuration.orientation == orientation }
        val metrics = compose.activity.resources.displayMetrics
        val density = minOf(metrics.widthPixels, metrics.heightPixels) / 360f
        val config = Configuration(compose.activity.resources.configuration).apply {
            setLocale(Locale(language))
            fontScale = 1.5f
        }
        // Nested Dialog windows resolve resources from the Activity as well.
        compose.runOnUiThread {
            @Suppress("DEPRECATION")
            compose.activity.resources.updateConfiguration(config, metrics)
        }
        val context = compose.activity.createConfigurationContext(config)
        var passive by mutableStateOf(false)
        var unexpectedActions = 0
        compose.setContent {
            CompositionLocalProvider(LocalContext provides context, LocalConfiguration provides config,
                LocalDensity provides Density(density, 1.5f)) {
                LayerAnalyzerTheme(darkTheme = dark) {
                    Surface {
                        if (passive) TlsKeyLogImportDialog(TlsKeyLogImportState(), true,
                            { unexpectedActions++ }, { unexpectedActions++ },
                            { unexpectedActions++ }, { unexpectedActions++ })
                        else Column { TlsUsageHelpButton() }
                    }
                }
            }
        }
        fun text(id: Int) = context.getString(id)
        fun screenshot(entry: String, position: String) {
            compose.waitForIdle()
            Thread.sleep(350) // Dialog WindowManager animations are outside Compose's clock.
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val directory = File(instrumentation.targetContext.getExternalFilesDir(null), "r08-help").apply { mkdirs() }
            val bitmap = requireNotNull(instrumentation.uiAutomation.takeScreenshot())
            File(directory, "$language-$dark-$landscape-$entry-$position.png").outputStream().use {
                assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it))
            }
            bitmap.recycle()
        }
        for (entry in listOf("active", "passive")) {
            compose.runOnIdle { passive = entry == "passive" }
            val help = compose.onNodeWithText(text(R.string.tls_usage_help_title))
            if (entry == "passive") help.performScrollTo()
            help.performClick()
            screenshot(entry, "first")
            // A paragraph can be taller than the landscape viewport at 150% fonts.
            // Verify its layout and scroll reachability instead of requiring it all on screen.
            for (id in listOf(R.string.tls_usage_help_status, R.string.tls_usage_help_prepare, R.string.tls_usage_help_ca,
                R.string.tls_usage_help_capture, R.string.tls_usage_help_analysis, R.string.tls_usage_help_export,
                R.string.tls_usage_help_cleanup, R.string.tls_usage_help_limits, R.string.tls_usage_help_errors)) {
                val layouts = mutableListOf<TextLayoutResult>()
                compose.onNodeWithText(text(id), useUnmergedTree = true).performScrollTo()
                    .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
                assertTrue(layouts.isNotEmpty())
                layouts.forEach { assertFalse("Text clipped: ${context.resources.getResourceEntryName(id)}", it.hasVisualOverflow) }
            }
            val scroll = compose.onNode(hasScrollAction() and hasAnyDescendant(hasText(text(R.string.tls_usage_help_errors))))
            scroll.performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, 100000f) }
            compose.waitForIdle()
            val range = scroll.fetchSemanticsNode().config[androidx.compose.ui.semantics.SemanticsProperties.VerticalScrollAxisRange]
            assertEquals(range.maxValue(), range.value(), 1f)
            screenshot(entry, "last")
            compose.onAllNodesWithText(text(R.string.close)).onLast().performClick()
            compose.onNodeWithText(text(R.string.tls_usage_help_errors)).assertDoesNotExist()
        }
        assertEquals(0, unexpectedActions)
    }
}

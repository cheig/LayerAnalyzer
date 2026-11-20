// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Surface
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.semantics.SemanticsProperties
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.StateRestorationTester
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsValidator
import com.example.layanalyzer.ui.components.*
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import com.example.layanalyzer.viewmodel.TlsKeyLogImportState
import java.io.File
import java.util.Locale
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test
import org.junit.After
import org.junit.Before
import org.junit.Assume.assumeTrue

/** Real device rendering of both production help entry points; no network or assets. */
class TlsUsageHelpUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    private var original: Configuration? = null
    @Before fun requireIsolatedTarget() {
        assumeTrue("Manual TLS-407 layout matrix requires its isolated installation", compose.activity.packageName == "com.layeranalyzer.android.tls407")
    }
    @After fun restoreLocale() { original?.let {
        @Suppress("DEPRECATION")
        compose.runOnUiThread { compose.activity.resources.updateConfiguration(it, compose.activity.resources.displayMetrics) }
    } }
    @Test fun chineseLight() = walk("zh", false)
    @Test fun chineseDark() = walk("zh", true)
    @Test fun englishLight() = walk("en", false)
    @Test fun englishDark() = walk("en", true)

    private fun walk(language: String, dark: Boolean) {
        val physical = compose.activity.resources.configuration
        assertEquals(1.5f, physical.fontScale)
        if (physical.orientation == Configuration.ORIENTATION_PORTRAIT) assertEquals(360, physical.screenWidthDp)
        else assertTrue(physical.screenHeightDp <= 360)
        val config = Configuration(physical).apply { setLocale(Locale(language)) }
        original = Configuration(physical)
        // Dialog windows read the Activity resources, not just the parent LocalContext.
        @Suppress("DEPRECATION")
        compose.runOnUiThread { compose.activity.resources.updateConfiguration(config, compose.activity.resources.displayMetrics) }
        val context = compose.activity.createConfigurationContext(config)
        var passive by mutableStateOf(false)
        var featureBuilt by mutableStateOf(BuildConfig.TLS_ENABLED)
        var editable by mutableStateOf(true)
        var draft by mutableStateOf(TlsCaptureSettings())
        var unexpectedActions = 0
        val restore = StateRestorationTester(compose)
        restore.setContent {
            CompositionLocalProvider(LocalContext provides context, LocalConfiguration provides config) {
                LayerAnalyzerTheme(darkTheme = dark) {
                    Surface(Modifier.fillMaxSize()) {
                        if (passive) {
                            TlsKeyLogImportDialog(TlsKeyLogImportState(), true,
                                { unexpectedActions++ }, { unexpectedActions++ },
                                { unexpectedActions++ }, { unexpectedActions++ })
                        } else {
                            Column(Modifier.verticalScroll(rememberScrollState())) {
                                TlsCaptureSettingsSection(draft,
                                    TlsSettingsStatus(featureBuilt, TlsCaState.MISSING, false),
                                    TlsCaptureSettingsValidator.validate(draft, emptyList()), editable,
                                    onSettingsChange = { unexpectedActions++ })
                            }
                        }
                    }
                }
            }
        }
        fun text(id: Int) = context.getString(id)
        fun shot(name: String) {
            compose.waitForIdle()
            Thread.sleep(350) // WindowManager animations are outside Compose's idle clock.
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val dir = File(instrumentation.targetContext.getExternalFilesDir(null), "tls-407/help").apply { mkdirs() }
            val bitmap = instrumentation.uiAutomation.takeScreenshot()
            File(dir, "$language-${if (dark) "dark" else "light"}-${config.orientation}-$name.png").outputStream().use {
                assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it))
            }
            bitmap.recycle()
        }
        fun open() {
            compose.onNodeWithText(text(R.string.tls_usage_help_title)).performScrollTo().performClick()
            Thread.sleep(350)
            compose.waitForIdle()
            shot("opened-${if (passive) "passive" else "active"}")
            compose.onNodeWithText(text(R.string.tls_usage_help_status)).assertIsDisplayed()
        }
        fun readable(id: Int) {
            val layouts = mutableListOf<TextLayoutResult>()
            compose.onNodeWithText(text(id), useUnmergedTree = true).performScrollTo()
                .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
            assertTrue(layouts.isNotEmpty())
            layouts.forEach { assertFalse("Overflow: ${context.resources.getResourceEntryName(id)}", it.hasVisualOverflow) }
        }
        for (entry in listOf("active", "passive")) {
            compose.runOnIdle { passive = entry == "passive" }
            open()
            shot("$entry-first")
            for (id in listOf(R.string.tls_usage_help_prepare, R.string.tls_usage_help_ca,
                R.string.tls_usage_help_capture, R.string.tls_usage_help_analysis,
                R.string.tls_usage_help_export, R.string.tls_usage_help_cleanup,
                R.string.tls_usage_help_limits, R.string.tls_usage_help_errors)) readable(id)
            val scroll = compose.onNode(hasScrollAction() and hasAnyDescendant(hasText(text(R.string.tls_usage_help_errors))))
            scroll.performSemanticsAction(SemanticsActions.ScrollBy) { it(0f, 100000f) }
            compose.waitForIdle()
            val range = scroll.fetchSemanticsNode().config[SemanticsProperties.VerticalScrollAxisRange]
            assertEquals(range.maxValue(), range.value(), 1f)
            shot("$entry-last")
            // StateRestorationTester owns the activity composition's registry, not
            // the separate passive dialog window's registry. Its rotation is checked in MainActivity.
            if (!passive) restore.emulateSavedInstanceStateRestore()
            compose.onNodeWithText(text(R.string.tls_usage_help_errors)).assertExists()
            // The help window is the last dialog; the passive parent also has Close.
            compose.onAllNodesWithText(text(R.string.close)).onLast().performClick()
            compose.onNodeWithText(text(R.string.tls_usage_help_errors)).assertDoesNotExist()
            open()
            assertTrue(InstrumentationRegistry.getInstrumentation().uiAutomation.performGlobalAction(1))
            compose.waitUntil(3000) {
                compose.onAllNodesWithText(text(R.string.tls_usage_help_errors)).fetchSemanticsNodes().isEmpty()
            }
            compose.onNodeWithText(text(R.string.tls_usage_help_errors)).assertDoesNotExist()
        }
        compose.runOnIdle { passive = false; editable = false; draft = draft.copy(enabled = true) }
        open()
        compose.onNodeWithText(text(R.string.close)).performClick()
        compose.runOnIdle { featureBuilt = false; editable = true; draft = draft.copy(enabled = false) }
        open()
        shot("feature-unavailable")
        compose.onNodeWithText(text(R.string.close)).performClick()
        compose.runOnIdle { assertEquals(0, unexpectedActions) }
    }
}

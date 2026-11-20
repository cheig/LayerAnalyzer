// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer

import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.Button
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.*
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.dp
import androidx.test.platform.app.InstrumentationRegistry
import com.example.layanalyzer.capture.TlsInterceptionPolicy
import com.example.layanalyzer.capture.tls.TlsCaState
import com.example.layanalyzer.model.*
import com.example.layanalyzer.ui.components.*
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import java.io.File
import java.util.Locale
import org.junit.Assert.*
import org.junit.Rule
import org.junit.Test

/** Production settings component and start-validation gate, localized in a test
 * activity without modifying saved preferences. NOT_AVAILABLE is an injected
 * capability projection, not a claim to have executed a TLS-OFF APK.
 */
class TlsQuicPolicyUiTest {
    @get:Rule val compose = createAndroidComposeRule<ComponentActivity>()
    @Test fun chineseLight() = walk("zh", false)
    @Test fun chineseDark() = walk("zh", true)
    @Test fun englishLight() = walk("en", false)
    @Test fun englishDark() = walk("en", true)

    private fun walk(language: String, dark: Boolean) {
        assertEquals(360, compose.activity.resources.configuration.screenWidthDp)
        assertEquals(1.25f, compose.activity.resources.configuration.fontScale)
        val config = Configuration(compose.activity.resources.configuration).apply { setLocale(Locale(language)) }
        val context = compose.activity.createConfigurationContext(config)
        val applications = listOf(context.packageName)
        var draft by mutableStateOf(TlsCaptureSettings())
        var editable by mutableStateOf(true)
        var status by mutableStateOf(TlsSettingsStatus(true, TlsCaState.READY, false, true))
        compose.setContent {
            CompositionLocalProvider(LocalContext provides context, LocalConfiguration provides config) {
                LayerAnalyzerTheme(darkTheme = dark) {
                    Surface(Modifier.fillMaxSize()) {
                        Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp)) {
                            TlsCaptureSettingsSection(draft, status,
                                TlsCaptureSettingsValidator.validate(draft, applications), editable,
                                onSettingsChange = { draft = it })
                            Button(onClick = {}, enabled = editable && (!draft.enabled || status.featureBuilt) && TlsInterceptionPolicy.canStart(
                                LiveCaptureSettings(tls = draft, allowedApplications = applications))) {
                                Text("TLS-314 start gate")
                            }
                        }
                    }
                }
            }
        }
        fun text(id: Int) = context.getString(id)
        // Rows do not create semantic parents; use the component's documented
        // switch order: TLS enabled, QUIC policy, retain secrets.
        fun toggle(id: Int) = compose.onAllNodes(isToggleable())[if (id == R.string.tls_capture_enable) 0 else 1]
        fun shot(name: String) {
            compose.waitForIdle()
            Thread.sleep(300) // let the real window/scroll animation settle
            val instrumentation = InstrumentationRegistry.getInstrumentation()
            val folder = File(instrumentation.targetContext.getExternalFilesDir(null), "tls-314/screenshots").apply { mkdirs() }
            val bitmap = instrumentation.uiAutomation.takeScreenshot()
            File(folder, "$language-${if (dark) "dark" else "light"}-$name.png").outputStream().use {
                assertTrue(bitmap.compress(Bitmap.CompressFormat.PNG, 100, it))
            }
            bitmap.recycle()
        }
        fun show(id: Int, name: String) {
            compose.onNodeWithText(text(id)).performScrollTo()
            shot(name)
            readable(text(id))
        }
        toggle(R.string.tls_capture_enable).assertIsOff()
        show(R.string.tls_capture_ipv6_not_captured, "01-default-ipv6")
        toggle(R.string.tls_capture_enable).performScrollTo().performClick()
        compose.runOnIdle { draft = draft.copy(hostScope = TlsHostScope.SelectedApplicationsCandidates) }
        toggle(R.string.tls_capture_quic_label).performScrollTo().assertIsOff()
        compose.onNodeWithText(text(R.string.tls_capture_quic_impact)).assertDoesNotExist()
        shot("02-preserve")
        toggle(R.string.tls_capture_quic_label).performClick()
        compose.runOnIdle { assertEquals(QuicPolicy.BlockSelectedUdp443, draft.quicPolicy) }
        show(R.string.tls_capture_quic_rule, "03-block-rule")
        show(R.string.tls_capture_quic_impact, "04-network-impact")
        show(R.string.tls_capture_quic_ipv6_bypass, "05-ipv6-bypass")
        compose.onNodeWithText("TLS-314 start gate").performScrollTo().assertIsEnabled()

        compose.runOnIdle { draft = draft.copy(hostScope = TlsHostScope.ExplicitHosts, includeHosts = listOf("fixture.example.invalid")) }
        show(R.string.tls_capture_quic_scope_undecidable, "06-domain-scope-refused")
        compose.onNodeWithText(text(R.string.tls_capture_quic_rule)).assertDoesNotExist()
        compose.onNodeWithText("TLS-314 start gate").performScrollTo().assertIsNotEnabled()
        compose.runOnIdle { draft = draft.copy(hostScope = TlsHostScope.SelectedApplicationsCandidates,
            bypassHosts = listOf("bypass.example.invalid")) }
        show(R.string.tls_capture_quic_scope_undecidable, "07-bypass-scope-refused")
        compose.onNodeWithText("TLS-314 start gate").performScrollTo().assertIsNotEnabled()

        compose.runOnIdle { draft = draft.copy(bypassHosts = emptyList()); editable = false }
        toggle(R.string.tls_capture_quic_label).performScrollTo().assertIsOn().assertIsNotEnabled()
        shot("08-running-disabled")
        compose.runOnIdle {
            editable = true
            draft = draft.copy(quicPolicy = QuicPolicy.Preserve)
            status = status.copy(featureBuilt = false, quicInterceptionAvailable = false)
        }
        show(R.string.tls_capture_quic_disabled_reason, "09-feature-unavailable")
        toggle(R.string.tls_capture_quic_label).assertIsNotEnabled()
    }

    private fun readable(value: String) {
        val layouts = mutableListOf<TextLayoutResult>()
        compose.onNodeWithText(value, useUnmergedTree = true).performScrollTo().assertIsDisplayed()
            .performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
        assertTrue(layouts.isNotEmpty())
        layouts.forEach { layout ->
            assertEquals(value.length, layout.getLineEnd(layout.lineCount - 1))
            // Compose can retain a paragraph constraint wider than its actual
            // text box (CJK: paragraph 984px, box 928px). Check glyph line bounds,
            // not hasVisualOverflow's comparison of those two container widths.
            assertTrue(layout.getLineBottom(layout.lineCount - 1) <= layout.size.height + 1f)
            for (line in 0 until layout.lineCount) {
                assertFalse(layout.isLineEllipsized(line))
                assertTrue(layout.getLineLeft(line) >= -1f)
                assertTrue("line $line exceeds text box", layout.getLineRight(line) <= layout.size.width + 1f)
            }
        }
    }
}

package com.example.layanalyzer

import android.content.res.Configuration
import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Box
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.layout.width
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.runtime.Composable
import androidx.compose.runtime.CompositionLocalProvider
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.platform.LocalConfiguration
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.platform.LocalDensity
import androidx.compose.ui.semantics.SemanticsActions
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performSemanticsAction
import androidx.compose.ui.text.TextLayoutResult
import androidx.compose.ui.unit.Density
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.CaptureHealthSummary
import com.example.layanalyzer.model.HealthCard
import com.example.layanalyzer.model.HealthSeverity
import com.example.layanalyzer.ui.components.AgentFindingCard
import com.example.layanalyzer.ui.components.AnalysisDashboard
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import java.io.File
import java.util.Locale
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

@RunWith(AndroidJUnit4::class)
class AnalyzerCardLayoutTest {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private fun show(dark: Boolean, fontScale: Float, language: String, content: @Composable () -> Unit) {
        val config = Configuration(compose.activity.resources.configuration).apply {
            setLocale(Locale.forLanguageTag(language))
        }
        val context = compose.activity.createConfigurationContext(config)
        compose.setContent {
            val density = LocalDensity.current
            CompositionLocalProvider(
                LocalContext provides context,
                LocalConfiguration provides config,
                LocalDensity provides Density(density.density, fontScale)
            ) {
                LayerAnalyzerTheme(darkTheme = dark) {
                    Surface(Modifier.fillMaxSize(), color = MaterialTheme.colorScheme.background) {
                        Box(Modifier.fillMaxSize()) {
                            Column(Modifier.width(360.dp).verticalScroll(rememberScrollState()).padding(16.dp)) {
                                content()
                            }
                        }
                    }
                }
            }
        }
    }

    private fun screenshot(name: String) {
        val directory = File(compose.activity.getExternalFilesDir(null), "card-style").apply { mkdirs() }
        File(directory, "$name.png").outputStream().use { output ->
            assertTrue(compose.onRoot().captureToImage().asAndroidBitmap().compress(Bitmap.CompressFormat.PNG, 100, output))
        }
    }

    private fun findingRemainsReadable(dark: Boolean, fontScale: Float, language: String) {
        val title = if (language == "zh") {
            "服务端响应阶段出现连续重传，需要结合往返时延进一步确认原因"
        } else {
            "Repeated retransmissions during the server response require a closer look at round-trip latency"
        }
        val hypothesis = "response-retransmission-hypothesis"
        val recommendation = "Compare the acknowledgement sequence with the server capture."
        var openedFrame: Long? = null
        var saved = false
        val finding = AgentFinding(
            id = "layout-regression",
            title = title,
            severity = AgentFindingSeverity.Warning,
            confidence = AgentConfidence.High,
            polarity = AgentFindingPolarity.Negative,
            hypothesisId = hypothesis,
            conclusion = "The response is retransmitted before the cumulative acknowledgement arrives.",
            evidence = listOf(
                AgentEvidence(type = AgentEvidenceType.Frame, frameNumber = 128L, sourceToolCallId = "layout-call"),
                AgentEvidence(type = AgentEvidenceType.Frame, frameNumber = 142L, sourceToolCallId = "layout-call")
            ),
            recommendations = listOf(recommendation)
        )
        show(dark, fontScale, language) {
            AgentFindingCard(finding, onFrameClick = { openedFrame = it }, onSaveToWorkspace = { saved = true })
        }
        val titleNode = compose.onNodeWithText(title).assertIsDisplayed()
        val layouts = mutableListOf<TextLayoutResult>()
        titleNode.performSemanticsAction(SemanticsActions.GetTextLayoutResult) { it(layouts) }
        assertTrue(layouts.isNotEmpty())
        assertTrue(layouts.first().lineCount > 1)
        assertFalse(layouts.first().hasVisualOverflow)
        val hypothesisBounds = compose.onNodeWithText(hypothesis, useUnmergedTree = true).fetchSemanticsNode().boundsInRoot
        assertTrue(titleNode.fetchSemanticsNode().boundsInRoot.top >= hypothesisBounds.bottom)
        screenshot("finding-$language-${if (dark) "dark" else "light"}")

        val context = compose.activity.createConfigurationContext(Configuration(compose.activity.resources.configuration).apply {
            setLocale(Locale.forLanguageTag(language))
        })
        compose.onNodeWithText(recommendation).assertDoesNotExist()
        compose.onNodeWithText(context.getString(R.string.agent_finding_details_show)).performScrollTo().performClick()
        compose.onNodeWithText(recommendation).performScrollTo().assertIsDisplayed()
        compose.onNodeWithText(context.getString(R.string.agent_evidence_frame, 142L)).performScrollTo().performClick()
        compose.runOnIdle { assertEquals(142L, openedFrame) }
        compose.onNodeWithText(context.getString(R.string.agent_save_to_workspace)).performScrollTo().performClick()
        compose.runOnIdle { assertTrue(saved) }
        compose.onNodeWithText(context.getString(R.string.agent_finding_details_hide)).performScrollTo().performClick()
        compose.onNodeWithText(recommendation).assertDoesNotExist()
    }

    private fun groupedSummaryKeepsActions(dark: Boolean) {
        var openedFrame: Long? = null
        var appliedFilter: String? = null
        val summary = CaptureHealthSummary(cards = listOf(
            HealthCard("tcp", "TCP 重传", "3", "响应阶段需要进一步检查", HealthSeverity.Warning, 128L, "tcp.analysis.retransmission"),
            HealthCard("dns", "DNS", "24 ms", "当前范围内未发现高严重性问题", HealthSeverity.Healthy)
        ))
        show(dark, 1f, "zh") {
            AnalysisDashboard(summary, null, emptyList(), {}, { appliedFilter = it }, {}, { openedFrame = it }, {})
        }
        compose.onNodeWithText("TCP 重传").assertIsDisplayed()
        screenshot("summary-${if (dark) "dark" else "light"}")
        val context = compose.activity.createConfigurationContext(Configuration(compose.activity.resources.configuration).apply {
            setLocale(Locale.CHINESE)
        })
        compose.onNodeWithText(context.getString(R.string.view_frame, 128L)).performClick()
        compose.runOnIdle { assertEquals(128L, openedFrame) }
        compose.onNodeWithContentDescription(context.getString(R.string.generate_filter)).performClick()
        compose.runOnIdle { assertEquals("tcp.analysis.retransmission", appliedFilter) }
        compose.onNodeWithText("24 ms").performScrollTo().assertIsDisplayed()
    }

    @Test fun longFindingTitleInLightTheme() = findingRemainsReadable(false, 1f, "en")
    @Test fun longFindingTitleWithLargeTextInDarkTheme() = findingRemainsReadable(true, 1.5f, "zh")
    @Test fun summaryActionsInLightTheme() = groupedSummaryKeepsActions(false)
    @Test fun summaryActionsInDarkTheme() = groupedSummaryKeepsActions(true)
}

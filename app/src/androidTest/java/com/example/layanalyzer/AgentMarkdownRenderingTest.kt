package com.example.layanalyzer

import android.graphics.Bitmap
import androidx.activity.ComponentActivity
import androidx.compose.foundation.layout.Column
import androidx.compose.foundation.layout.fillMaxSize
import androidx.compose.foundation.layout.padding
import androidx.compose.foundation.rememberScrollState
import androidx.compose.foundation.verticalScroll
import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Surface
import androidx.compose.material3.Text
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.asAndroidBitmap
import androidx.compose.ui.test.assertHasNoClickAction
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.captureToImage
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.onRoot
import androidx.compose.ui.test.performClick
import androidx.compose.ui.unit.dp
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.ui.components.AgentFindingCard
import com.example.layanalyzer.ui.components.AgentMarkdownText
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

@RunWith(AndroidJUnit4::class)
class AgentMarkdownRenderingTest {
    @get:Rule
    val compose = createAndroidComposeRule<ComponentActivity>()

    private val firstParagraph = "注册请求已到达服务端，但收到 403 拒绝响应。"
    private val secondParagraph = "当前证据支持服务端拒绝注册，具体策略原因仍需结合日志确认。"

    private fun showReport(dark: Boolean) {
        compose.setContent {
            LayerAnalyzerTheme(darkTheme = dark) {
                Surface(Modifier.fillMaxSize()) {
                    Column(Modifier.verticalScroll(rememberScrollState()).padding(16.dp)) {
                        Text("AI 分析报告", style = MaterialTheme.typography.titleLarge)
                        AgentMarkdownText("## 分析摘要\n\n**$firstParagraph**\n\n$secondParagraph")
                        AgentFindingCard(
                            finding = AgentFinding(
                                id = "sample",
                                title = "服务端拒绝注册",
                                severity = AgentFindingSeverity.Warning,
                                confidence = AgentConfidence.High,
                                conclusion = "### 关键观察\n\n- 请求方法为 `REGISTER`\n- 响应字段 `sip.Status-Code` 为 **403**\n\n" +
                                    "> 抓包未包含服务端日志，暂时无法确定具体拒绝策略。",
                                evidence = listOf(AgentEvidence(
                                    type = AgentEvidenceType.Frame, frameNumber = 42,
                                    observation = "REGISTER 响应为 403", sourceToolCallId = "sample-call"
                                ))
                            ),
                            onFrameClick = {}
                        )
                        Text("建议下一步", style = MaterialTheme.typography.titleSmall)
                        AgentMarkdownText("1. **核对账号与服务端策略**\n2. 结合日志复查，并重新抓取完整注册流程。")
                    }
                }
            }
        }
        val first = compose.onNodeWithText(firstParagraph).assertIsDisplayed().fetchSemanticsNode()
        val second = compose.onNodeWithText(secondParagraph).assertIsDisplayed().fetchSemanticsNode()
        assertTrue("Paragraph spacing was lost", second.boundsInRoot.top > first.boundsInRoot.bottom)
        compose.onNodeWithText("请求方法为 REGISTER").assertIsDisplayed()
        compose.onNodeWithText("响应字段 sip.Status-Code 为 403").assertIsDisplayed()
        val screenshot = File(compose.activity.getExternalFilesDir(null), "markdown-report-${if (dark) "dark" else "light"}.png")
        screenshot.outputStream().use {
            compose.onRoot().captureToImage().asAndroidBitmap().compress(Bitmap.CompressFormat.PNG, 100, it)
        }
    }

    @Test fun reportRendersInLightTheme() = showReport(dark = false)
    @Test fun reportRendersInDarkTheme() = showReport(dark = true)

    @Test
    fun markdownLinksStayInertWhileEvidenceKeepsItsCallback() {
        var openedFrame: Long? = null
        compose.setContent {
            LayerAnalyzerTheme {
                AgentFindingCard(
                    finding = AgentFinding(
                        title = "Finding",
                        conclusion = "[Open website](https://example.invalid)\n\n![Image label](https://tracker.invalid/image)",
                        evidence = listOf(AgentEvidence(
                            type = AgentEvidenceType.Frame, frameNumber = 42, sourceToolCallId = "sample-call"
                        ))
                    ),
                    onFrameClick = { openedFrame = it }
                )
            }
        }
        compose.onNodeWithText("Open website").assertIsDisplayed().assertHasNoClickAction()
        compose.onNodeWithText("Image label").assertIsDisplayed().assertHasNoClickAction()
        compose.onNodeWithText(compose.activity.getString(R.string.agent_evidence_frame, 42L)).performClick()
        compose.runOnIdle { assertEquals(42L, openedFrame) }
    }
}

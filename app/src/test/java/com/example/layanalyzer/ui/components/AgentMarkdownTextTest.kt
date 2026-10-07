package com.example.layanalyzer.ui.components

import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import com.example.layanalyzer.ai.markdown.ReportMarkdown
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentMarkdownTextTest {
    @Test
    fun inlineStylesPreserveProtocolFieldsAndNestedEmphasis() {
        val node = ReportMarkdown.parse("**响应 *异常***：`tcp.analysis.retransmission`，port_name").firstChild
        val text = reportInlineText(node, Color.Gray)
        assertEquals("响应 异常：tcp.analysis.retransmission，port_name", text.text)
        assertTrue(text.spanStyles.any { it.item.fontWeight == FontWeight.Bold })
        assertTrue(text.spanStyles.any { it.item.fontFamily == FontFamily.Monospace })
    }

    @OptIn(androidx.compose.ui.text.ExperimentalTextApi::class)
    @Test
    fun linksImagesReferencesAndHtmlCannotBecomeActions() {
        val markdown = "[打开](intent://evil) ![图片](https://tracker.invalid/x) " +
            "[引用][target] <https://example.invalid> <img src='https://tracker.invalid/y'>\n\n" +
            "[target]: file:///secret"
        val text = reportInlineText(ReportMarkdown.parse(markdown).firstChild, Color.Gray)
        assertEquals("打开 图片 引用 https://example.invalid ", text.text)
        assertTrue(text.getStringAnnotations(0, text.length).isEmpty())
        assertTrue(text.getUrlAnnotations(0, text.length).isEmpty())
        assertFalse(text.text.contains("tracker.invalid"))
        assertFalse(text.text.contains("secret"))
    }

    @Test
    fun hardBreaksSurviveWhileSoftBreaksFlowWithinParagraph() {
        val text = reportInlineText(ReportMarkdown.parse("first\nsecond  \nthird").firstChild, Color.Gray)
        assertEquals("first second\nthird", text.text)
    }

    @Test
    fun collapsedPreviewRemovesMarkupAndSeparatesBlocks() {
        assertEquals(
            "注册失败 重传 tcp.analysis.retransmission 第二项 建议检查",
            ReportMarkdown.preview("## **注册失败**\n\n- 重传 `tcp.analysis.retransmission`\n- 第二项\n\n> 建议检查")
        )
        assertEquals("旧报告，没有格式。", ReportMarkdown.preview("旧报告，没有格式。"))
    }
}

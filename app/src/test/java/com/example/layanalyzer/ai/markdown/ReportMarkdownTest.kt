// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.markdown

import com.example.layanalyzer.ai.privacy.AgentPrivacyPolicy
import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.ai.serialization.AgentJsonDecodeResult
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentReport
import org.commonmark.node.BulletList
import org.commonmark.node.Paragraph
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

class ReportMarkdownTest {
    @Test
    fun paragraphBreaksAndFormattingSurviveSanitizationAndPersistence() {
        val prose = "**注册失败**，响应为 `403`。\n\n需要检查服务端策略。\n\n- 已收到响应\n- 原因尚待确认"
        val safe = AgentPrivacyPolicy.sanitizeReportText(prose)
        assertEquals(prose, safe)
        val report = AgentReport(summary = safe, findings = listOf(AgentFinding(conclusion = safe)))
        val decoded = AgentJsonCodec.decodeReport(AgentJsonCodec.encodeReport(report))
        assertEquals(report, (decoded as AgentJsonDecodeResult.Success).value)
        val blocks = ReportMarkdown.parse(safe).children().toList()
        assertEquals(3, blocks.size)
        assertTrue(blocks[0] is Paragraph && blocks[1] is Paragraph && blocks[2] is BulletList)
    }

    @Test
    fun exportedListItemKeepsParagraphAndNestedListInsideOneItem() {
        val markdown = ReportMarkdown.listItem("**检查配置**\n\n先检查服务端。\n\n- 核对策略\n- 重新抓包")
        val list = ReportMarkdown.parse(markdown).firstChild as BulletList
        assertEquals(1, list.children().count())
        val blocks = list.firstChild.children().toList()
        assertEquals(3, blocks.size)
        assertTrue(blocks.last() is BulletList)
    }

    @Test
    fun providersOwnListMarkersAreNotDuplicated() {
        assertEquals("- 第一项\n- 第二项", ReportMarkdown.listItem("- 第一项\n- 第二项"))
        assertEquals("  1. 第一项\n  2. 第二项", ReportMarkdown.listItem("1. 第一项\n2. 第二项", "  - "))
    }
}

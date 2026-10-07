// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.HealthSeverity
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

class CaptureHealthAnalyzerTest {
    private val file = FileSessionInfo("golden.pcap", 2048, "pcap", 20, "/tmp/golden.pcap")

    @Test
    fun `protocol presence without failures remains healthy`() {
        val summary = CaptureHealthAnalyzer.summarize(
            file,
            CaptureStatistics(dnsSummaryTotal = 4, tlsSummaryTotal = 5, httpSummaryTotal = 8),
            ExpertInfoSummary(analyzed = true)
        )

        assertEquals(HealthSeverity.Healthy, summary.cards.first { it.id == "dns" }.severity)
        assertEquals(HealthSeverity.Healthy, summary.cards.first { it.id == "tls" }.severity)
        assertEquals(HealthSeverity.Healthy, summary.cards.first { it.id == "http" }.severity)
    }

    @Test
    fun `explicit failures are actionable and preserve first frame`() {
        val summary = CaptureHealthAnalyzer.summarize(
            file,
            CaptureStatistics(dnsFailureTotal = 2, dnsFirstFailureFrame = 17),
            ExpertInfoSummary(analyzed = true)
        )
        val dns = summary.cards.first { it.id == "dns" }

        assertEquals(HealthSeverity.Error, dns.severity)
        assertEquals(17L, dns.frameNumber)
    }

    @Test
    fun `truncated captures are visible in file health`() {
        val summary = CaptureHealthAnalyzer.summarize(
            file,
            CaptureStatistics(packetCount = 20, capturedByteCount = 1000, truncatedPacketCount = 3),
            ExpertInfoSummary(analyzed = true)
        )
        val health = summary.cards.first { it.id == "file" }

        assertEquals(HealthSeverity.Warning, health.severity)
        assertTrue(health.detail.contains("3 truncated"))
    }

    @Test
    fun `card labels are supplied by the caller so the UI and the model can differ`() {
        val chinese = CaptureHealthAnalyzer.Labels(
            fileHealth = "文件体检",
            noDnsEvents = "未发现 DNS 事件",
            noTlsEvents = "未发现 TLS/SSL 事件",
            noHttpEvents = "未发现 HTTP 事件",
            noExpertInfo = "未发现 Expert 信息",
            tapToViewFrames = "点击查看相关帧"
        )
        val summary = CaptureHealthAnalyzer.summarize(
            file = file,
            statistics = CaptureStatistics(dnsSummaryTotal = 0, tlsSummaryTotal = 0, httpSummaryTotal = 0),
            expert = ExpertInfoSummary(analyzed = true),
            scope = AnalysisScope.CompleteFile,
            labels = chinese
        )

        assertEquals("文件体检", summary.cards.first { it.id == "file" }.title)
        assertEquals("未发现 DNS 事件", summary.cards.first { it.id == "dns" }.detail)
        assertEquals("未发现 TLS/SSL 事件", summary.cards.first { it.id == "tls" }.detail)
        assertEquals("未发现 HTTP 事件", summary.cards.first { it.id == "http" }.detail)
        assertEquals("未发现 Expert 信息", summary.cards.first { it.id == "expert" }.detail)
    }

    @Test
    fun `the default labels are English so the model never sees UI-language text`() {
        val summary = CaptureHealthAnalyzer.summarize(
            file = file,
            statistics = CaptureStatistics(dnsSummaryTotal = 0, tlsSummaryTotal = 0, httpSummaryTotal = 0),
            expert = ExpertInfoSummary(analyzed = true),
            scope = AnalysisScope.CompleteFile
        )

        assertEquals("Capture health", summary.cards.first { it.id == "file" }.title)
        assertEquals("No DNS events found", summary.cards.first { it.id == "dns" }.detail)
        // The model must never see UI-language text.  Match CJK specifically
        // rather than "non-ASCII": the cards join fields with '·' (U+00B7),
        // which is non-ASCII and perfectly correct in an English string.
        val cjk = Regex("[\\u4e00-\\u9fff]")
        summary.cards.forEach { card ->
            listOf(card.title, card.value, card.detail).forEach { text ->
                assertFalse("card ${card.id} carries CJK text: $text", cjk.containsMatchIn(text))
            }
        }
    }
}

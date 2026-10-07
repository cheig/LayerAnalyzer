// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CaptureHealthSummary
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.HealthCard
import com.example.layanalyzer.model.HealthSeverity
import com.example.layanalyzer.model.FileSessionInfo
import java.util.Locale

/** Converts raw Wireshark statistics into action-oriented cards. */
object CaptureHealthAnalyzer {
    /**
     * 文案由调用方传入，因为 [CaptureHealthSummary] 有两个消费方且语言需求相反：
     * UI 要跟随界面语言，喂给模型的那份应保持英文。
     * 写死在一个地方必然让其中一边泄漏另一种语言。
     */
    data class Labels(
        val fileHealth: String,
        val noDnsEvents: String,
        val noTlsEvents: String,
        val noHttpEvents: String,
        val noExpertInfo: String,
        val tapToViewFrames: String
    )

    /** 喂给模型的英文文案：模型输入用英文更稳，也不该被界面语言污染。 */
    val DEFAULT_LABELS = Labels(
        fileHealth = "Capture health",
        noDnsEvents = "No DNS events found",
        noTlsEvents = "No TLS/SSL events found",
        noHttpEvents = "No HTTP events found",
        noExpertInfo = "No Expert information found",
        tapToViewFrames = "Tap to view related frames"
    )

    fun summarize(
        file: FileSessionInfo,
        statistics: CaptureStatistics,
        expert: ExpertInfoSummary,
        scope: AnalysisScope = AnalysisScope.CompleteFile,
        labels: Labels = DEFAULT_LABELS
    ): CaptureHealthSummary {
        val dns = statistics.dnsSummaryTotal
        val http = statistics.httpSummaryTotal
        val tls = statistics.tlsSummaryTotal
        val tcpSignals = statistics.tcpSummaryTotal
        val first = statistics.tcpSummaries.firstOrNull()
        val firstDns = statistics.dnsSummaries.firstOrNull()
        val firstTls = statistics.tlsSummaries.firstOrNull()
        val firstHttp = statistics.httpSummaries.firstOrNull()
        val returned = listOf(
            statistics.dnsSummaries.size to dns,
            statistics.httpSummaries.size to http,
            statistics.tlsSummaries.size to tls,
            statistics.tcpSummaries.size to tcpSignals
        )
        val cards = listOf(
            HealthCard(
                "file", labels.fileHealth, "${file.frameCount} frames", "${file.fileType.uppercase()} · ${file.encapsulation} · ${file.sizeBytes} bytes · ${statistics.capturedByteCount} captured bytes${if (statistics.truncatedPacketCount > 0) " · ${statistics.truncatedPacketCount} truncated" else ""}",
                severity = when { file.frameCount == 0 -> HealthSeverity.Error; statistics.truncatedPacketCount > 0 -> HealthSeverity.Warning; else -> HealthSeverity.Healthy },
                returned = statistics.packetCount, total = file.frameCount
            ),
            HealthCard("dns", "DNS", "$dns events · ${statistics.dnsFailureTotal} failures", if (dns == 0) labels.noDnsEvents else "${statistics.dnsQueries} queries · ${statistics.dnsResponses} responses · avg ${String.format(Locale.US, "%.1f", statistics.dnsAverageResponseMs)} ms", failureSeverity(statistics.dnsFailureTotal), statistics.dnsFirstFailureFrame ?: firstDns?.frameNumber, "dns", returned[0].first, returned[0].second, dns > statistics.dnsSummaries.size),
            HealthCard("tcp", "TCP", "$tcpSignals signals · ${statistics.tcpRetransmissions} retrans", if (tcpSignals == 0) "SYN ${statistics.tcpSyn} · SYN/ACK ${statistics.tcpSynAck} · RTT ${String.format(Locale.US, "%.1f", statistics.tcpAverageRttMs)} ms" else "RST ${statistics.tcpResets} · dup ACK ${statistics.tcpDuplicateAcks} · zero window ${statistics.tcpZeroWindows}", severityFor(tcpSignals), first?.frameNumber, "tcp.analysis.retransmission || tcp.analysis.duplicate_ack || tcp.flags.reset == 1", returned[3].first, returned[3].second, tcpSignals > statistics.tcpSummaries.size),
            HealthCard("tls", "TLS", "$tls events · ${statistics.tlsAlertTotal} alerts", if (tls == 0) labels.noTlsEvents else "versions ${statistics.tlsVersions.keys.take(3).joinToString(", ")} · SNI ${statistics.tlsSni.size}", failureSeverity(statistics.tlsAlertTotal), statistics.tlsFirstAlertFrame ?: firstTls?.frameNumber, "tls", returned[2].first, returned[2].second, tls > statistics.tlsSummaries.size),
            HealthCard("http", "HTTP", "$http events · ${statistics.httpErrorTotal} errors", if (http == 0) labels.noHttpEvents else "statuses ${statistics.httpStatusCodes.keys.take(4).joinToString(", ")} · hosts ${statistics.httpHosts.size}", failureSeverity(statistics.httpErrorTotal), statistics.httpFirstErrorFrame ?: firstHttp?.frameNumber, "http", returned[1].first, returned[1].second, http > statistics.httpSummaries.size),
            HealthCard("expert", "Expert", "${expert.errorPackets} errors · ${expert.warningPackets} warnings", if (expert.totalItems == 0) labels.noExpertInfo else labels.tapToViewFrames, when { expert.errorPackets > 0 -> HealthSeverity.Error; expert.warningPackets > 0 -> HealthSeverity.Warning; else -> HealthSeverity.Healthy }, expert.items.firstOrNull()?.frameNumber, null, expert.items.size, expert.totalItems, expert.truncated)
        )
        return CaptureHealthSummary(scope = scope, cards = cards, generatedAtMillis = System.currentTimeMillis())
    }

    private fun severityFor(count: Int) = when { count > 0 -> HealthSeverity.Warning; else -> HealthSeverity.Healthy }
    private fun failureSeverity(count: Int) = when { count > 0 -> HealthSeverity.Error; else -> HealthSeverity.Healthy }
}

// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentTokenUsage
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test
import java.util.Calendar
import java.util.Locale
import java.util.TimeZone

class ProtocolAgentScreenFormattingTest {
    @Test
    fun formatsSavedSessionTimeForHistoryRows() {
        val timeZone = TimeZone.getTimeZone("Asia/Shanghai")
        val savedAtMillis = Calendar.getInstance(timeZone, Locale.US).run {
            clear()
            set(2026, Calendar.AUGUST, 14, 9, 30)
            timeInMillis
        }

        assertEquals(
            "2026-08-14 09:30",
            formatAgentSavedSessionTime(savedAtMillis, Locale.US, timeZone)
        )
        assertNull(formatAgentSavedSessionTime(0L, Locale.US, timeZone))
    }

    @Test
    fun formatsTokenCountsForTheRunSummary() {
        assertEquals("999", formatAgentTokenCount(999))
        assertEquals("3.1k", formatAgentTokenCount(3_100))
        assertEquals("12.4k", formatAgentTokenCount(12_400))
        assertEquals("1.3m", formatAgentTokenCount(1_250_000))
    }

    @Test
    fun interactionUsageSeparatesCacheCreationFromUncachedInput() {
        val breakdown = modelInteractionUsageBreakdown(
            AgentTokenUsage(
                inputTokens = 60,
                cachedInputTokens = 20,
                cacheCreationTokens = 10,
                outputTokens = 7
            )
        )

        assertEquals(60, breakdown.totalInputTokens)
        assertEquals(30, breakdown.uncachedInputTokens)
        assertEquals(20, breakdown.cachedInputTokens)
        assertEquals(10, breakdown.cacheCreationTokens)
        assertEquals(7, breakdown.outputTokens)
    }

    @Test
    fun cacheHitRateUsesNormalizedTotalInputAsItsDenominator() {
        assertEquals("33.3%", formatAgentCacheHitRate(20, 60))
        assertEquals("0.0%", formatAgentCacheHitRate(0, 0))
    }

    @Test
    fun interactionTimingUsesRequestStartForTotalAndFirstToken() {
        val breakdown = modelInteractionTimingBreakdown(
            AgentModelInteraction(
                id = "interaction-1",
                request = AgentModelRequest("request-1"),
                response = AgentModelResponse.Final("{}"),
                startedAtMillis = 1_000L,
                firstTokenAtMillis = 1_240L,
                completedAtMillis = 2_500L
            )
        )

        assertEquals(1_500L, breakdown.responseDurationMillis)
        assertEquals(240L, breakdown.timeToFirstTokenMillis)
    }

    @Test
    fun formatsSubsecondAndSecondInteractionDurations() {
        assertEquals("999 ms", formatAgentDurationMillis(999L))
        assertEquals("1 s", formatAgentDurationMillis(1_000L))
        assertEquals("1.3 s", formatAgentDurationMillis(1_250L))
    }

    // ------------------------------------------------- report anchor invariants

    private fun plan(
        rounds: List<AgentTranscriptRound>,
        expandedRoundKey: String? = null,
        fallbackReport: AgentReport? = null
    ) = agentListItemPlan(
        rounds = rounds,
        expandedRoundKey = expandedRoundKey,
        fallbackReport = fallbackReport,
        showScenarioPackage = true,
        showGatewayAccount = true,
        interruptedJobRunId = "run-1",
        showSuggestions = true,
        hasToolActivity = true,
        isRunning = false,
        error = null,
        showPartialReportWarning = false,
        completionWarningMessage = null,
        tokenUsage = null,
        isCancelled = false,
        singleSummaryMode = false
    )

    @Test
    fun planAnchorPointsAtTheFirstReportHeaderWhereverItSits() {
        // Interrupted-job and partial-report-warning sit between the fixed head
        // and the rounds; the plan-derived index must account for both, which is
        // exactly what the old hand-mirrored counter got wrong.
        val messages = listOf(
            AgentConversationItem("q1", AgentConversationRole.User, "Q1"),
            AgentConversationItem(
                "a1",
                AgentConversationRole.Assistant,
                "A1",
                report = AgentReport("done")
            )
        )
        val rounds = buildTranscriptRounds(messages)

        val p = plan(rounds, expandedRoundKey = "q1")

        val anchorKey = requireNotNull(p.reportAnchorKey)
        val anchorIndex = p.indexOfFirst { it.key == anchorKey }
        assertEquals("report-q1-header", anchorKey)
        assertEquals(p[anchorIndex].key, anchorKey)
        assertTrue(anchorIndex > 5)
    }

    @Test
    fun planWithoutRendersFallsBackToTheMainAreaReportAnchor() {
        val p = plan(emptyList(), fallbackReport = AgentReport("old archive"))

        assertEquals("report-header", p.reportAnchorKey)
    }

    @Test
    fun planWithNoReportAnywhereHasNoAnchor() {
        val rounds = buildTranscriptRounds(
            listOf(AgentConversationItem("q1", AgentConversationRole.User, "Q1"))
        )

        assertNull(plan(rounds).reportAnchorKey)
    }
}

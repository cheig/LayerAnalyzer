package com.example.layanalyzer.ui.components

import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentConversationRound
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentTranscriptRoundsTest {

    private fun user(id: String, text: String, at: Long = 0L) = AgentConversationItem(
        id = id, role = AgentConversationRole.User, content = text, createdAtMillis = at
    )

    private fun assistant(id: String, text: String, report: AgentReport? = null) =
        AgentConversationItem(
            id = id, role = AgentConversationRole.Assistant, content = text, report = report
        )

    private fun error(id: String, text: String) = AgentConversationItem(
        id = id, role = AgentConversationRole.Error, content = text
    )

    private fun tool(id: String) = AgentConversationItem(
        id = id, role = AgentConversationRole.Tool, content = "tool payload"
    )

    private fun report(summary: String = "conclusion") = AgentReport(summary = summary)

    // --------------------------------------------------------- ① 多轮定界

    @Test
    fun `three questions split into three rounds with their own bubbles`() {
        val messages = listOf(
            user("r1:q", "First question"),
            tool("r1:t"),
            assistant("r1:a", "First answer"),
            error("r1:e", "transient"),
            user("r2:q", "Second question"),
            assistant("r2:a", "Second answer"),
            user("r3:q", "Third question"),
            error("r3:e", "final failure")
        )

        val rounds = buildTranscriptRounds(messages)

        assertEquals(3, rounds.size)
        assertEquals(listOf("r1:q", "r2:q", "r3:q"), rounds.map { it.key })
        assertEquals(listOf("First question", "Second question", "Third question"), rounds.map { it.question })
        assertEquals(
            listOf(listOf("r1:q", "r1:a", "r1:e"), listOf("r2:q", "r2:a"), listOf("r3:q", "r3:e")),
            rounds.map { round -> round.messages.map { it.id } }
        )
    }

    // --------------------------------------------------------- ② Tool 过滤口径

    @Test
    fun `tool bubbles are filtered inside the derivation and never join a round`() {
        val raw = listOf(
            user("q1", "Q"),
            tool("t1"),
            assistant("a1", "A")
        )

        val rounds = buildTranscriptRounds(raw)

        assertEquals(listOf("q1", "a1"), rounds.single().messages.map { it.id })
    }

    // --------------------------------------------------------- ③ 前置孤儿合成轮

    @Test
    fun `orphan messages before the first user bubble form a defensive leading round`() {
        val messages = listOf(
            error("orphan-1", "stray failure"),
            assistant("orphan-2", "stray note"),
            user("q1", "The real question")
        )

        val rounds = buildTranscriptRounds(messages)

        assertEquals(2, rounds.size)
        assertEquals("orphan-1", rounds[0].key)
        // The defensive round has no question; its head message is not a User bubble.
        assertEquals("stray failure", rounds[0].messages.first().content)
        assertEquals(listOf("orphan-1", "orphan-2"), rounds[0].messages.map { it.id })
        assertEquals("q1", rounds[1].key)
        assertEquals("The real question", rounds[1].question)
    }

    // --------------------------------------------------------- ④ 空 id key 兜底

    @Test
    fun `blank ids fall back to positional round keys`() {
        val messages = listOf(
            user("", "First"),
            user("", "Second")
        )

        val rounds = buildTranscriptRounds(messages)

        assertEquals("round-1", rounds[0].key)
        assertEquals("round-2", rounds[1].key)
    }

    // --------------------------------------------------------- ⑤ 内嵌报告提取

    @Test
    fun `a round's report comes from its conclusion bubble`() {
        val embedded = report("round one done")
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "working"),
            assistant("a1-final", "round one done", report = embedded),
            user("q2", "Q2"),
            assistant("a2", "still working")
        )

        val rounds = buildTranscriptRounds(messages)

        assertEquals(embedded, rounds[0].report)
        assertNull(rounds[1].report)
    }

    // ------------------------------------------- ⑥ currentReport 三分律

    @Test
    fun `current report already embedded in a round is not attached again`() {
        val embedded = report("embedded")
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "done", report = embedded),
            user("q2", "Q2")
        )

        val rounds = buildTranscriptRounds(messages, currentReport = embedded)

        assertEquals(embedded, rounds[0].report)
        assertNull(rounds[1].report)
    }

    @Test
    fun `a partial report rides on the last round even when that round is newer`() {
        val partial = report("partial").copy(completeness = AgentReportCompleteness.Partial)
        // The partial-report path emits only an Error bubble, never a report bubble.
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "done", report = report("older complete")),
            user("q2", "Q2"),
            error("e2", "model failed")
        )

        val rounds = buildTranscriptRounds(messages, currentReport = partial)

        assertEquals(partial, rounds.last().report)
        assertEquals(report("older complete"), rounds[0].report)
    }

    @Test
    fun `an old report still on screen during a follow-up is not misattached to the new round`() {
        // While a follow-up runs, uiState.report is the previous round's
        // report, which its conclusion bubble already carries.
        val prior = report("prior conclusion")
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "prior conclusion", report = prior),
            user("q2", "Q2"),
            assistant("a2", "thinking")
        )

        val rounds = buildTranscriptRounds(messages, currentReport = prior)

        assertEquals(prior, rounds[0].report)
        assertNull(rounds[1].report)
    }

    @Test
    fun `a report with no messages at all yields no rounds`() {
        // Pre-schema-3 archives persisted only the report. The screen's
        // main-area fallback must render it, so the function must not invent a
        // message-less round.
        val rounds = buildTranscriptRounds(emptyList(), currentReport = report())

        assertTrue(rounds.isEmpty())
    }

    @Test
    fun `a report without any transcript still yields no rounds even when messages list is empty`() {
        assertTrue(buildTranscriptRounds(visibleMessages = emptyList(), currentReport = report("only")).isEmpty())
    }

    // --------------------------------------------------------- ⑦ 空输入

    @Test
    fun `empty input yields empty rounds`() {
        assertTrue(buildTranscriptRounds(emptyList()).isEmpty())
    }

    // --------------------------------------------------- 陈旧展开 key 行为

    @Test
    fun `a stale expanded key matches nothing and the plan renders every round collapsed`() {
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "A1", report = report()),
            user("q2", "Q2")
        )
        val rounds = buildTranscriptRounds(messages)

        val plan = agentListItemPlan(
            rounds = rounds,
            expandedRoundKey = "round-from-another-session",
            fallbackReport = null,
            showScenarioPackage = false,
            showGatewayAccount = false,
            interruptedJobRunId = null,
            showSuggestions = false,
            hasToolActivity = false,
            isRunning = false,
            error = null,
            showPartialReportWarning = false,
            completionWarningMessage = null,
            tokenUsage = null,
            isCancelled = false,
            singleSummaryMode = false
        )

        assertEquals(2, plan.count { it.kind == AgentListItemKind.RoundHeader })
        assertEquals(0, plan.count { it.kind == AgentListItemKind.RoundMessage })
        assertEquals(0, plan.count { it.kind == AgentListItemKind.ReportHeader })
    }

    // --------------------------------------------------------- plan 结构

    @Test
    fun `plan covers conditional entries including interrupted-job and partial-report-warning`() {
        val messages = listOf(
            user("q1", "Q1"),
            error("e1", "failed")
        )
        val rounds = buildTranscriptRounds(
            messages,
            currentReport = report("partial").copy(completeness = AgentReportCompleteness.Partial)
        )
        val error = AgentError(AgentErrorCode.INTERNAL_ERROR, "boom")

        val plan = agentListItemPlan(
            rounds = rounds,
            expandedRoundKey = "q1",
            fallbackReport = null,
            showScenarioPackage = true,
            showGatewayAccount = true,
            interruptedJobRunId = "run-9",
            showSuggestions = true,
            hasToolActivity = true,
            isRunning = true,
            error = error,
            showPartialReportWarning = true,
            completionWarningMessage = "stopped early",
            tokenUsage = com.example.layanalyzer.model.AgentTokenUsage(1, 2),
            isCancelled = false,
            singleSummaryMode = true
        )

        val keys = plan.map { it.key }
        assertEquals(
            listOf(
                "scope", "model", "scenario-package", "gateway-account",
                "interrupted-job-run-9", "suggestions",
                // The expanded round: header, question bubble, its error bubble,
                // then the report sections (the test report has no findings).
                "round-q1", "q1", "e1",
                "report-q1-header", "report-q1-partial", "report-q1-no-findings",
                "report-q1-coverage",
                "tool-activity", "phase", "error", "partial-report-warning",
                "completion-warning", "token-usage", "single-summary-mode"
            ),
            keys
        )
        // Cancelled absent; header expanded flag flows through.
        assertFalse(plan.any { it.kind == AgentListItemKind.Cancelled })
        val header = plan.filterIsInstance<AgentRoundHeaderSpec>().single()
        assertTrue(header.expanded)
        assertTrue(header.running)
        assertEquals(1, header.ordinal)
    }

    @Test
    fun `plan scroll anchor points at the expanded round's report header`() {
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "A1", report = report("first")),
            user("q2", "Q2"),
            assistant("a2", "A2", report = report("second"))
        )
        val rounds = buildTranscriptRounds(messages)

        val collapsed = agentListItemPlan(
            rounds = rounds, expandedRoundKey = null, fallbackReport = null,
            showScenarioPackage = false, showGatewayAccount = false,
            interruptedJobRunId = null, showSuggestions = false,
            hasToolActivity = false, isRunning = false, error = null,
            showPartialReportWarning = false, completionWarningMessage = null,
            tokenUsage = null, isCancelled = false, singleSummaryMode = false
        )
        assertNull(collapsed.reportAnchorKey)

        val expanded = agentListItemPlan(
            rounds = rounds, expandedRoundKey = "q2", fallbackReport = null,
            showScenarioPackage = false, showGatewayAccount = false,
            interruptedJobRunId = null, showSuggestions = false,
            hasToolActivity = false, isRunning = false, error = null,
            showPartialReportWarning = false, completionWarningMessage = null,
            tokenUsage = null, isCancelled = false, singleSummaryMode = false
        )
        assertEquals("report-q2-header", expanded.reportAnchorKey)
    }

    @Test
    fun `expanded round hides the conclusion bubble but keeps question and progress bubbles`() {
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "progress"),
            assistant("a1-final", "final", report = report())
        )
        val rounds = buildTranscriptRounds(messages)

        val plan = agentListItemPlan(
            rounds = rounds, expandedRoundKey = "q1", fallbackReport = null,
            showScenarioPackage = false, showGatewayAccount = false,
            interruptedJobRunId = null, showSuggestions = false,
            hasToolActivity = false, isRunning = false, error = null,
            showPartialReportWarning = false, completionWarningMessage = null,
            tokenUsage = null, isCancelled = false, singleSummaryMode = false
        )

        val messageKeys = plan.filterIsInstance<AgentRoundMessageSpec>().map { it.key }
        assertEquals(listOf("q1", "a1"), messageKeys)
    }

    @Test
    fun `fallback report renders only when rounds are empty`() {
        val fallback = report("old archive")

        val withoutRounds = agentListItemPlan(
            rounds = emptyList(), expandedRoundKey = null, fallbackReport = fallback,
            showScenarioPackage = false, showGatewayAccount = false,
            interruptedJobRunId = null, showSuggestions = false,
            hasToolActivity = false, isRunning = false, error = null,
            showPartialReportWarning = false, completionWarningMessage = null,
            tokenUsage = null, isCancelled = false, singleSummaryMode = false
        )
        assertEquals(
            listOf(AgentListItemKind.Scope, AgentListItemKind.Model) +
                agentReportSpecs(fallback, "report", readOnly = false).map { it.kind },
            withoutRounds.map { it.kind }
        )

        val withRounds = agentListItemPlan(
            rounds = buildTranscriptRounds(listOf(user("q1", "Q1"))),
            expandedRoundKey = null, fallbackReport = fallback,
            showScenarioPackage = false, showGatewayAccount = false,
            interruptedJobRunId = null, showSuggestions = false,
            hasToolActivity = false, isRunning = false, error = null,
            showPartialReportWarning = false, completionWarningMessage = null,
            tokenUsage = null, isCancelled = false, singleSummaryMode = false
        )
        assertFalse(withRounds.any { it.key.startsWith("report") })
    }

    @Test
    fun `historical round reports are read-only and carry their own key prefix`() {
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "A1", report = report("first").copy(findings = listOf(AgentFinding(id = "f1", title = "t")))),
            user("q2", "Q2"),
            assistant("a2", "A2", report = report("second").copy(findings = listOf(AgentFinding(id = "f1", title = "t"))))
        )
        val rounds = buildTranscriptRounds(messages)

        val plan = agentListItemPlan(
            rounds = rounds, expandedRoundKey = "q2", fallbackReport = null,
            showScenarioPackage = false, showGatewayAccount = false,
            interruptedJobRunId = null, showSuggestions = false,
            hasToolActivity = false, isRunning = false, error = null,
            showPartialReportWarning = false, completionWarningMessage = null,
            tokenUsage = null, isCancelled = false, singleSummaryMode = false
        )

        // Expanding the second round must not surface the first round's
        // report sections: single-expand keeps one report in the plan.
        assertEquals(1, plan.count { it.kind == AgentListItemKind.ReportHeader })
        val finding = plan.filterIsInstance<AgentReportFindingSpec>().single()
        assertEquals("report-q2-finding-0-f1", finding.key)
        assertFalse(finding.readOnly)

        val firstExpanded = agentListItemPlan(
            rounds = rounds, expandedRoundKey = "q1", fallbackReport = null,
            showScenarioPackage = false, showGatewayAccount = false,
            interruptedJobRunId = null, showSuggestions = false,
            hasToolActivity = false, isRunning = false, error = null,
            showPartialReportWarning = false, completionWarningMessage = null,
            tokenUsage = null, isCancelled = false, singleSummaryMode = false
        )
        val historical = firstExpanded.filterIsInstance<AgentReportFindingSpec>().single()
        assertEquals("report-q1-finding-0-f1", historical.key)
        assertTrue(historical.readOnly)
    }

    // ----------------------------------------------------- 孤儿归档判定

    @Test
    fun `orphan archive keeps only rounds no round list carries`() {
        val current = report("current")
        val embeddedPrior = report("embedded prior")
        val messages = listOf(
            user("q1", "Q1"),
            assistant("a1", "embedded prior", report = embeddedPrior),
            user("q2", "Q2"),
            error("e2", "partial failure")
        )
        val rounds = buildTranscriptRounds(messages, currentReport = current)
        val retryOrphan = AgentConversationRound("retried", report("retry report"), 5L)
        val pastReports = listOf(
            AgentConversationRound("Q1", embeddedPrior, 1L),
            retryOrphan
        )

        val orphans = orphanArchivedRounds(rounds, currentReport = current, pastReports = pastReports)

        assertEquals(listOf(retryOrphan), orphans)
    }

    // ---------------------------------------------------- 恢复后的 key 稳定

    @Test
    fun `restored prefix keeps round keys stable across a save-resume cycle`() {
        val live = buildTranscriptRounds(
            listOf(user("run1:message-0", "Q"), assistant("run1:message-1", "A"))
        )
        val restored = buildTranscriptRounds(
            listOf(
                user("restored:run1:message-0", "Q"),
                assistant("restored:run1:message-1", "A")
            )
        )

        assertEquals(
            live.map { it.key },
            restored.map { it.key.removePrefix("restored:") }
        )
    }

    // ------------------------------------------------------ 证据覆盖徽标 spec

    @Test
    fun `the report plan ends with exactly one coverage spec carrying the report`() {
        // EVL-UI-07: the coverage spec is appended unconditionally, after the
        // limitations and next-steps sections, even when the report is clean.
        val target = report("coverage").copy(limitations = listOf("one limit"))

        val specs = agentReportSpecs(target, "report", readOnly = true)
        val coverage = specs.filterIsInstance<AgentReportCoverageSpec>().single()
        assertEquals("report-coverage", coverage.key)
        assertEquals(target, coverage.report)
        assertTrue(coverage.readOnly)
        assertEquals(AgentListItemKind.ReportCoverage, specs.last().kind)
        assertTrue(
            specs.indexOfFirst { it.kind == AgentListItemKind.ReportCoverage } >
                specs.indexOfFirst { it.kind == AgentListItemKind.ReportLimitations }
        )

        val live = agentReportSpecs(target, "report", readOnly = false)
        assertFalse(live.filterIsInstance<AgentReportCoverageSpec>().single().readOnly)
    }
}

// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness

/**
 * The built-in demo scripts.
 *
 * Each one covers a path the Agent stack has to handle correctly, and each is
 * written to be readable as documentation of that path.  Tool names match the
 * Phase 0 registry (`AgentToolRegistry.phase0`), so a script drives real host
 * tools rather than invented ones.
 *
 * Note what the scripts assert about the *host*: the confidence and completeness
 * values below are what a model claims, not what the run ends up with.  AI-06's
 * EvidenceValidator is expected to downgrade them when the evidence does not
 * hold up, and these scripts are deliberately shaped so that it can.
 */
object MockModelScriptLibrary {

    const val CAPTURE_OVERVIEW_SUCCESS = "capture_overview_success"
    const val INVALID_FILTER_RECOVERY = "invalid_filter_recovery"
    const val CANCELLATION = "cancellation"
    const val MAX_STEPS = "max_steps"
    const val SESSION_CHANGED = "session_changed"

    private const val OVERVIEW_TOOL = "get_capture_overview"
    private const val EXPERT_TOOL = "get_expert_info"
    private const val VALIDATE_FILTER_TOOL = "validate_display_filter"

    /** Long enough for a UI test to observe WaitingForModel and press Cancel. */
    private const val CANCELLABLE_DELAY_MILLIS = 5_000L

    /** Comfortably past the default AgentPolicy.maxSteps. */
    private const val MAX_STEPS_TURNS = 16

    val all: List<MockModelScript> by lazy {
        listOf(
            captureOverviewSuccess(),
            invalidFilterRecovery(),
            cancellation(),
            maxSteps(),
            sessionChanged()
        )
    }

    private val byId: Map<String, MockModelScript> by lazy { all.associateBy { it.id } }

    val ids: List<String>
        get() = all.map { it.id }

    fun find(scriptId: String): MockModelScript? = byId[scriptId]

    fun require(scriptId: String): MockModelScript = requireNotNull(byId[scriptId]) {
        "Unknown mock model script: $scriptId. Available: ${ids.joinToString()}"
    }

    /** The happy path after the host has already supplied bounded bootstrap evidence. */
    private fun captureOverviewSuccess() = MockModelScript(
        id = CAPTURE_OVERVIEW_SUCCESS,
        description = "Host bootstrap overview/Expert evidence, then a structured report.",
        expectedRequests = listOf(
            MockRequestExpectation(
                requiredToolDefinitions = setOf(OVERVIEW_TOOL, EXPERT_TOOL),
                minMessageCount = 1
            )
        ),
        responses = listOf(
            MockScriptedResponse.final(
                AgentReport(
                    summary = "The capture is dominated by TCP with a small number of " +
                        "retransmissions reported by Expert Info.",
                    findings = listOf(
                        AgentFinding(
                            id = "finding-retransmissions",
                            title = "TCP retransmissions present",
                            severity = AgentFindingSeverity.Warning,
                            confidence = AgentConfidence.Medium,
                            conclusion = "Expert Info reports TCP retransmissions, which is " +
                                "consistent with loss on the path.",
                            evidence = listOf(
                                AgentEvidence(
                                    type = AgentEvidenceType.ExpertInfo,
                                    observation = "Expert Info lists TCP retransmission entries.",
                                    sourceToolCallId = "host-bootstrap-expert-2",
                                    displayFilter = "tcp.analysis.retransmission"
                                ),
                                AgentEvidence(
                                    type = AgentEvidenceType.Statistic,
                                    observation = "TCP is the dominant protocol in the hierarchy.",
                                    sourceToolCallId = "host-bootstrap-overview-1",
                                    metric = "protocolHierarchyTotal",
                                    observedValue = "2"
                                )
                            ),
                            recommendations = listOf(
                                "Filter on tcp.analysis.retransmission to review the affected streams."
                            )
                        )
                    ),
                    recommendedNextSteps = listOf("Inspect the retransmitted TCP streams."),
                    completeness = AgentReportCompleteness.Complete
                )
            )
        )
    )

    /**
     * The model proposes a filter the engine rejects, is told so, and recovers.
     *
     * Turn 1 asks for a filter with a typo, so `validate_display_filter` answers
     * `valid: false` as a *successful* result.  Turn 2 must therefore still see a
     * tool result rather than an error, which is what the expectation checks.
     */
    private fun invalidFilterRecovery() = MockModelScript(
        id = INVALID_FILTER_RECOVERY,
        description = "Rejected display filter, corrected filter, then a report.",
        expectedRequests = listOf(
            MockRequestExpectation(requiredToolDefinitions = setOf(VALIDATE_FILTER_TOOL)),
            MockRequestExpectation(
                expectedToolName = VALIDATE_FILTER_TOOL,
                expectedToolCallId = "call-bad-filter"
            ),
            MockRequestExpectation(
                expectedToolName = VALIDATE_FILTER_TOOL,
                expectedToolCallId = "call-good-filter"
            )
        ),
        responses = listOf(
            MockScriptedResponse.tool(
                toolCallId = "call-bad-filter",
                toolName = VALIDATE_FILTER_TOOL,
                // "tcp.portt" is not a field: a syntax rejection, not a crash.
                arguments = mapOf("filter" to "tcp.portt == 443")
            ),
            MockScriptedResponse.tool(
                toolCallId = "call-good-filter",
                toolName = VALIDATE_FILTER_TOOL,
                arguments = mapOf("filter" to "tcp.port == 443")
            ),
            MockScriptedResponse.final(
                AgentReport(
                    summary = "The first display filter was invalid; the corrected filter " +
                        "tcp.port == 443 compiles.",
                    findings = listOf(
                        AgentFinding(
                            id = "finding-filter-corrected",
                            title = "Display filter corrected",
                            severity = AgentFindingSeverity.Info,
                            confidence = AgentConfidence.Low,
                            conclusion = "tcp.port == 443 is the valid form of the intended filter.",
                            evidence = listOf(
                                AgentEvidence(
                                    type = AgentEvidenceType.DisplayFilter,
                                    observation = "The engine accepted tcp.port == 443.",
                                    sourceToolCallId = "call-good-filter",
                                    displayFilter = "tcp.port == 443"
                                )
                            )
                        )
                    ),
                    limitations = listOf("No packets were read; only filter syntax was checked."),
                    completeness = AgentReportCompleteness.Partial
                )
            )
        )
    )

    /**
     * A slow first turn, so a UI test can cancel while the run waits on a model.
     *
     * The delay is served with a cancellable suspend, so both cancellation paths
     * work: coroutine cancellation, and an explicit `cancel(requestId)`.
     */
    private fun cancellation() = MockModelScript(
        id = CANCELLATION,
        description = "Delays the first response so cancellation can be exercised.",
        responses = listOf(
            MockScriptedResponse.tool(
                toolCallId = "call-overview",
                toolName = OVERVIEW_TOOL,
                delayMillis = CANCELLABLE_DELAY_MILLIS
            ),
            MockScriptedResponse.final(
                AgentReport(
                    summary = "Reached only if the run was never cancelled.",
                    completeness = AgentReportCompleteness.Partial
                ),
                delayMillis = CANCELLABLE_DELAY_MILLIS
            )
        )
    )

    /**
     * A model that never stops asking for tools, so the host's step ceiling is
     * what ends the run.  There is no Final here on purpose: the only way this
     * script terminates is MAX_STEPS_REACHED, and if the loop ever ran past the
     * scripted turns it would get a `script_exhausted` failure instead — which is
     * also a legitimate way for the test to notice the ceiling did not hold.
     */
    private fun maxSteps() = MockModelScript(
        id = MAX_STEPS,
        description = "Requests a tool on every turn; never returns a final report.",
        responses = List(MAX_STEPS_TURNS) { turn ->
            MockScriptedResponse.tool(
                toolCallId = "call-overview-$turn",
                toolName = OVERVIEW_TOOL,
                arguments = mapOf("scope" to "complete_file")
            )
        }
    )

    /**
     * The capture is swapped underneath the run: the first tool call succeeds,
     * the second comes back SESSION_CHANGED from the host, and the model then
     * reports what it can.  The scripted `Failure` covers the case where the
     * loop asks the model one more time after the session died.
     */
    private fun sessionChanged() = MockModelScript(
        id = SESSION_CHANGED,
        description = "A tool call after the capture session changed.",
        expectedRequests = listOf(
            null,
            MockRequestExpectation(expectedToolCallId = "call-overview")
        ),
        responses = listOf(
            MockScriptedResponse.tool(
                toolCallId = "call-overview",
                toolName = OVERVIEW_TOOL
            ),
            MockScriptedResponse.tool(
                toolCallId = "call-expert",
                toolName = EXPERT_TOOL
            ),
            MockScriptedResponse.failure(
                AgentError(
                    code = AgentErrorCode.SESSION_CHANGED,
                    userMessage = "The capture changed while the analysis was running.",
                    retryable = false,
                    details = mapOf("reason" to "session_changed")
                )
            )
        )
    )
}

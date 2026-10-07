// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import androidx.activity.ComponentActivity
import androidx.compose.ui.test.assertIsDisplayed
import androidx.compose.ui.test.assertIsNotEnabled
import androidx.compose.ui.test.assertIsSelected
import androidx.compose.ui.test.hasText
import androidx.compose.ui.test.junit4.createAndroidComposeRule
import androidx.compose.ui.test.onNodeWithContentDescription
import androidx.compose.ui.test.onNodeWithTag
import androidx.compose.ui.test.onNodeWithText
import androidx.compose.ui.test.performClick
import androidx.compose.ui.test.performScrollTo
import androidx.compose.ui.test.performScrollToNode
import androidx.compose.ui.test.performTextInput
import androidx.test.ext.junit.runners.AndroidJUnit4
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentLocalDataUsage
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentSavedSessionSummary
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolActivityStatus
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.DisplayFilterUiState
import com.example.layanalyzer.model.FileSessionInfo
import com.example.layanalyzer.model.ProtocolAgentUiState
import com.example.layanalyzer.model.AgentReportProvenance
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ui.components.AgentTestTags
import com.example.layanalyzer.ui.components.ProtocolAgentScreen
import com.example.layanalyzer.ui.theme.LayerAnalyzerTheme
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.runner.RunWith

/**
 * AI-08 §9.  These drive the screen through the states a real run passes
 * through, because the risks here are behavioural rather than visual: a cancel
 * that fires twice, a question resubmitted after a rebuild, or a report that
 * hides why it stopped.
 */
@RunWith(AndroidJUnit4::class)
class ProtocolAgentScreenTest {

    @get:Rule
    val composeRule = createAndroidComposeRule<ComponentActivity>()

    private val file = FileSessionInfo(
        displayName = "ims-registration.pcap",
        sizeBytes = 2_048L,
        fileType = "pcap",
        frameCount = 120,
        localPath = "/data/captures/ims-registration.pcap"
    )
    private val playbooks = listOf(
        AgentPlaybook.generalCaptureHealth(),
        AgentPlaybook.generalCaptureHealth().copy(
            id = "ims-registration-failure",
            version = 2,
            title = "IMS registration failure",
            intentHints = listOf("ims registration")
        )
    )

    private fun string(id: Int): String = composeRule.activity.getString(id)

    private fun string(id: Int, vararg args: Any): String =
        composeRule.activity.getString(id, *args)

    private fun setScreen(
        state: ProtocolAgentUiState,
        currentFile: FileSessionInfo? = file,
        displayFilter: DisplayFilterUiState = DisplayFilterUiState(),
        settings: AgentSettings = AgentSettings(),
        onPrivacyModeChange: (AgentPrivacyMode) -> Unit = {},
        onSubmitQuestion: (String, AnalysisScope) -> Unit = { _, _ -> },
        onContinueConversation: (String) -> Unit = {},
        onCancel: () -> Unit = {},
        onRetry: () -> Unit = {},
        onFrameClick: (Long) -> Unit = {},
        savedSessions: List<AgentSavedSessionSummary> = emptyList(),
        localDataUsage: AgentLocalDataUsage = AgentLocalDataUsage()
    ) {
        composeRule.setContent {
            LayerAnalyzerTheme {
                ProtocolAgentScreen(
                    uiState = state,
                    currentFile = currentFile,
                    displayFilter = displayFilter,
                    settings = settings,
                    onPrivacyModeChange = onPrivacyModeChange,
                    onSubmitQuestion = { question, scope, _, _ -> onSubmitQuestion(question, scope) },
                    onContinueConversation = onContinueConversation,
                    onCancel = onCancel,
                    onRetry = onRetry,
                    onNewConversation = {},
                    onClearTransientError = {},
                    playbooks = playbooks,
                    onFrameClick = onFrameClick,
                    savedSessions = savedSessions,
                    localDataUsage = localDataUsage
                )
            }
        }
    }

    /** Opens the composer's privacy-mode menu, where the two modes live. */
    private fun openPrivacyMenu() {
        composeRule
            .onNodeWithContentDescription(string(R.string.agent_privacy_switch))
            .performClick()
    }

    // ------------------------------------------------------------- states
    @Test
    fun withoutCaptureShowsOpenCapturePrompt() {
        setScreen(ProtocolAgentUiState(), currentFile = null)

        composeRule.onNodeWithText(string(R.string.agent_no_capture)).assertIsDisplayed()
    }

    @Test
    fun idleShowsPlaybookScenariosAndDisabledSend() {
        setScreen(ProtocolAgentUiState())

        composeRule.onNodeWithText("General capture health").assertIsDisplayed()
        composeRule.onNodeWithText("IMS registration failure").assertIsDisplayed()
        composeRule.onNodeWithContentDescription(string(R.string.agent_send)).assertIsNotEnabled()
    }

    @Test
    fun composerChoosesRedactedOrUnredactedDataWithoutLocalOnlyOption() {
        var selected: AgentPrivacyMode? = null
        setScreen(
            ProtocolAgentUiState(),
            settings = AgentSettings(privacyMode = AgentPrivacyMode.RedactedMetadata),
            onPrivacyModeChange = { selected = it }
        )

        // The modes live behind a chip so the composer stays one row tall.
        openPrivacyMenu()
        composeRule.onNodeWithTag(AgentTestTags.PRIVACY_REDACTED).assertIsSelected()
        composeRule.onNodeWithTag(AgentTestTags.PRIVACY_UNREDACTED).performClick()

        assertEquals(AgentPrivacyMode.UnredactedMetadata, selected)
        openPrivacyMenu()
        composeRule.onNodeWithTag(AgentTestTags.PRIVACY_UNREDACTED).assertIsSelected()
        composeRule.onNodeWithText(string(R.string.agent_privacy_local_only)).assertDoesNotExist()
    }

    @Test
    fun privacyModeIsLockedWhileAConversationIsOpen() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                messages = listOf(
                    AgentConversationItem(
                        id = "m1",
                        role = AgentConversationRole.User,
                        content = "question"
                    )
                ),
                report = report()
            )
        )

        // The menu still opens while locked, so the user can read which mode
        // the open conversation is running under; both options are inert.
        openPrivacyMenu()
        composeRule.onNodeWithTag(AgentTestTags.PRIVACY_REDACTED).assertIsNotEnabled()
        composeRule.onNodeWithTag(AgentTestTags.PRIVACY_UNREDACTED).assertIsNotEnabled()
    }

    @Test
    fun blankQuestionIsNotSubmittedButTrimmedTextIs() {
        var submitted: String? = null
        var submitCount = 0
        setScreen(ProtocolAgentUiState(), onSubmitQuestion = { q, _ ->
            submitted = q
            submitCount += 1
        })

        composeRule.onNodeWithTag(AgentTestTags.QUESTION_INPUT).performTextInput("   ")
        composeRule.onNodeWithContentDescription(string(R.string.agent_send)).assertIsNotEnabled()
        assertEquals(0, submitCount)

        composeRule.onNodeWithTag(AgentTestTags.QUESTION_INPUT)
            .performTextInput("why did registration fail?")
        composeRule.onNodeWithContentDescription(string(R.string.agent_send)).performClick()

        assertEquals(1, submitCount)
        assertEquals("why did registration fail?", submitted)
    }

    @Test
    fun scenarioChipSubmitsAQuestionThatMatchesItsPlaybook() {
        var submitted: String? = null
        setScreen(ProtocolAgentUiState(), onSubmitQuestion = { q, _ -> submitted = q })

        composeRule.onNodeWithText("IMS registration failure").performClick()

        assertEquals("Analyze this capture: ims registration", submitted)
    }

    @Test
    fun runningShowsActiveToolAndReplacesSendWithStop() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.RunningTool,
                activeTool = runningActivity(),
                toolActivities = listOf(runningActivity()),
                completedSteps = 1
            )
        )

        composeRule.onNodeWithText(string(R.string.agent_tool_expert_info)).assertIsDisplayed()
        // A run in flight cannot have a second question queued behind it.
        composeRule.onNodeWithContentDescription(string(R.string.agent_stop)).assertIsDisplayed()
        composeRule.onNodeWithContentDescription(string(R.string.agent_send)).assertDoesNotExist()
    }

    @Test
    fun cancelFiresExactlyOncePerClick() {
        var cancels = 0
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.RunningTool,
                activeTool = runningActivity(),
                toolActivities = listOf(runningActivity())
            ),
            onCancel = { cancels += 1 }
        )

        composeRule.onNodeWithContentDescription(string(R.string.agent_stop)).performClick()

        assertEquals(1, cancels)
    }

    @Test
    fun cancelledKeepsCompletedTrajectoryAndOffersRetry() {
        var retries = 0
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Cancelled,
                toolActivities = listOf(succeededActivity()),
                completedSteps = 1
            ),
            onRetry = { retries += 1 }
        )

        composeRule.onNodeWithText(string(R.string.agent_phase_cancelled)).assertIsDisplayed()
        // The finished step stays on screen so the work is not silently lost.
        composeRule.onNodeWithContentDescription(string(R.string.expand)).performClick()
        composeRule.onNodeWithText(string(R.string.agent_tool_capture_overview)).assertIsDisplayed()

        composeRule.onNodeWithText(string(R.string.retry)).performClick()
        assertEquals(1, retries)
    }

    @Test
    fun failedShowsActionableSuggestionForErrorCode() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Failed,
                error = AgentError(
                    code = AgentErrorCode.MAX_STEPS_REACHED,
                    userMessage = "The analysis stopped early.",
                    retryable = true
                )
            )
        )

        composeRule.onNodeWithText("The analysis stopped early.").assertIsDisplayed()
        composeRule.onNodeWithText(string(R.string.agent_error_suggestion_budget)).assertIsDisplayed()
    }

    @Test
    fun nonRetryableErrorHidesRetry() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Failed,
                error = AgentError(
                    code = AgentErrorCode.NO_CAPTURE,
                    userMessage = "Open a capture first.",
                    retryable = false
                )
            )
        )

        composeRule.onNodeWithText(string(R.string.retry)).assertDoesNotExist()
    }

    // ------------------------------------------------------------- report

    @Test
    fun completedReportShowsFindingSeverityAndEvidence() {
        setScreen(ProtocolAgentUiState(phase = AgentRunPhase.Completed, report = report()))

        composeRule.onNodeWithText("401 Unauthorized was never answered").assertIsDisplayed()
        composeRule.onNodeWithText(string(R.string.agent_severity_error), substring = true)
            .assertIsDisplayed()
        composeRule.onNodeWithText(string(R.string.agent_evidence_frame, 42)).assertIsDisplayed()
        // Formatted through the resource so the assertion holds in any locale.
        composeRule
            .onNodeWithText(string(R.string.agent_report_scenario, "IMS registration failure"))
            .assertIsDisplayed()
    }

    @Test
    fun hostConfirmedToolResultsStayOutOfTheFindingsList() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                report = report().copy(
                    findings = listOf(
                        AgentFinding(
                            id = "host-confirmed-1",
                            title = "Host-confirmed get_capture_overview result",
                            severity = AgentFindingSeverity.Info,
                            confidence = AgentConfidence.Low,
                            conclusion = "Returned 120 frames."
                        ),
                        finding()
                    )
                )
            )
        )

        composeRule.onNodeWithText("Host-confirmed get_capture_overview result").assertDoesNotExist()
        composeRule.onNodeWithText("401 Unauthorized was never answered").assertIsDisplayed()
    }

    @Test
    fun reportWithOnlyHostConfirmedToolResultsShowsTheEmptyPlaceholder() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                report = report().copy(
                    findings = listOf(
                        AgentFinding(
                            id = "host-confirmed-1",
                            title = "Host-confirmed get_capture_overview result",
                            severity = AgentFindingSeverity.Info,
                            confidence = AgentConfidence.Low,
                            conclusion = "Returned 120 frames."
                        )
                    )
                )
            )
        )

        composeRule.onNodeWithText(string(R.string.agent_report_no_findings))
            .performScrollTo()
            .assertIsDisplayed()
        composeRule.onNodeWithText("Host-confirmed get_capture_overview result").assertDoesNotExist()
    }

    @Test
    fun findingKeepsPrimaryEvidenceVisibleAndFoldsSupportingDetails() {
        setScreen(ProtocolAgentUiState(phase = AgentRunPhase.Completed, report = report()))

        composeRule.onNodeWithText(string(R.string.agent_evidence_frame, 42)).assertIsDisplayed()
        composeRule.onNodeWithText("The retry may have been sent on another interface.")
            .assertDoesNotExist()

        composeRule.onNodeWithText(string(R.string.agent_finding_details_show))
            .performScrollTo()
            .performClick()

        composeRule.onNodeWithText("The retry may have been sent on another interface.")
            .performScrollTo()
            .assertIsDisplayed()
        composeRule.onNodeWithText(string(R.string.agent_finding_details_hide)).assertIsDisplayed()
    }

    @Test
    fun partialReportStatesWhyItStopped() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                report = report().copy(
                    completeness = AgentReportCompleteness.Partial,
                    limitations = listOf("Only the first 500 frames were scanned.")
                )
            )
        )

        // A partial run must not be presented in the same shape as a finished one.
        composeRule.onNodeWithText(string(R.string.agent_report_completeness_partial))
            .assertIsDisplayed()
        composeRule.onNodeWithText(string(R.string.agent_report_partial_explanation))
            .assertIsDisplayed()
        composeRule.onNodeWithText("Only the first 500 frames were scanned.").assertIsDisplayed()
    }

    @Test
    fun clickingEvidenceFrameOpensThatFrame() {
        val opened = mutableListOf<Long>()
        setScreen(
            ProtocolAgentUiState(phase = AgentRunPhase.Completed, report = report()),
            onFrameClick = { opened += it }
        )

        composeRule.onNodeWithContentDescription(string(R.string.agent_evidence_open_frame, 42))
            .performClick()

        assertEquals(listOf(42L), opened)
    }

    @Test
    fun evidenceWithoutFrameIsNotClickable() {
        val opened = mutableListOf<Long>()
        val filterOnly = AgentEvidence(
            type = AgentEvidenceType.DisplayFilter,
            displayFilter = "sip.Method == \"REGISTER\"",
            observation = "registration attempts",
            sourceToolCallId = "call-done"
        )
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                report = report().copy(
                    findings = listOf(finding().copy(evidence = listOf(filterOnly)))
                )
            ),
            onFrameClick = { opened += it }
        )

        composeRule.onNodeWithText("sip.Method", substring = true).performClick()

        // A filter citation has no packet to open; clicking must do nothing
        // rather than jump to an arbitrary frame.
        assertTrue(opened.isEmpty())
    }

    @Test
    fun manyFindingsRenderLazily() {
        val many = (1..80).map { index ->
            finding().copy(id = "finding-$index", title = "Finding number $index")
        }
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                report = report().copy(findings = many)
            )
        )

        composeRule.onNodeWithTag(AgentTestTags.REPORT_LIST).assertIsDisplayed()
        composeRule.onNodeWithText("Finding number 1").assertIsDisplayed()
        // Proves the report is lazily composed: a far off-screen card does not exist.
        composeRule.onNodeWithText("Finding number 80").assertDoesNotExist()
    }

    // -------------------------------------------------------- conversation

    @Test
    fun completedReportFoldsConversationHistoryUntilRequested() {
        val state = ProtocolAgentUiState(
            phase = AgentRunPhase.Completed,
            messages = listOf(
                AgentConversationItem(
                    id = "question",
                    role = AgentConversationRole.User,
                    content = "Why did registration fail?"
                ),
                AgentConversationItem(
                    id = "analysis",
                    role = AgentConversationRole.Assistant,
                    content = "I checked the registration exchange."
                )
            ),
            report = report()
        )
        setScreen(state)

        composeRule.onNodeWithText("I checked the registration exchange.").assertDoesNotExist()
        // The round accordion keeps one collapsible unit per asked question;
        // the summary line hides the conclusion until the round is expanded.
        val roundTitle = string(R.string.agent_round_title, 1, "Why did registration fail?")
        composeRule.onNodeWithTag(AgentTestTags.REPORT_LIST)
            .performScrollToNode(hasText(roundTitle))
        composeRule.onNodeWithText(roundTitle).performClick()

        composeRule.onNodeWithText("I checked the registration exchange.")
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun localDataDetailsStayBehindHistoryEntry() {
        setScreen(
            state = ProtocolAgentUiState(),
            localDataUsage = AgentLocalDataUsage(cacheEntryCount = 2, cacheBytes = 2_048L)
        )

        composeRule.onNodeWithText(string(R.string.agent_local_data_title)).assertDoesNotExist()
        val historyTitle = string(R.string.agent_history_and_data_title)
        composeRule.onNodeWithTag(AgentTestTags.REPORT_LIST)
            .performScrollToNode(hasText(historyTitle))
        composeRule.onNodeWithText(historyTitle).performClick()

        composeRule.onNodeWithText(string(R.string.agent_local_data_title))
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun savedSessionHistoryShowsWhenConversationWasSaved() {
        val savedAtMillis = 1_723_630_500_000L
        val expectedTimestamp = java.text.SimpleDateFormat(
            "yyyy-MM-dd HH:mm",
            java.util.Locale.getDefault()
        ).format(java.util.Date(savedAtMillis))
        setScreen(
            state = ProtocolAgentUiState(),
            savedSessions = listOf(
                AgentSavedSessionSummary(
                    conversationId = "conv_12345678",
                    captureFingerprint = "fingerprint-a",
                    captureDisplayName = file.displayName,
                    userQuestion = "Why did registration fail?",
                    summary = "IMS registration did not complete.",
                    findingCount = 1,
                    savedAtMillis = savedAtMillis,
                    sizeBytes = 2_048L
                )
            )
        )

        val historyTitle = string(R.string.agent_history_and_data_title)
        composeRule.onNodeWithTag(AgentTestTags.REPORT_LIST)
            .performScrollToNode(hasText(historyTitle))
        composeRule.onNodeWithText(historyTitle).performClick()

        composeRule.onNodeWithText(expectedTimestamp, substring = true)
            .performScrollTo()
            .assertIsDisplayed()
    }

    @Test
    fun followUpUsesContinueRatherThanNewAnalysis() {
        var continued: String? = null
        var submitted = 0
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                messages = listOf(
                    AgentConversationItem(
                        id = "m1",
                        role = AgentConversationRole.User,
                        content = "why did registration fail?"
                    )
                ),
                report = report()
            ),
            onSubmitQuestion = { _, _ -> submitted += 1 },
            onContinueConversation = { continued = it }
        )

        composeRule.onNodeWithTag(AgentTestTags.QUESTION_INPUT)
            .performTextInput("which frame proves it?")
        composeRule.onNodeWithContentDescription(string(R.string.agent_send)).performClick()

        assertEquals("which frame proves it?", continued)
        assertEquals(0, submitted)
    }

    @Test
    fun toolResultMessageIsHiddenBecauseTheStepTraceAlreadyShowsIt() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                messages = listOf(
                    AgentConversationItem(
                        id = "t1",
                        role = AgentConversationRole.Tool,
                        content = "5 expert warnings",
                        toolName = "get_expert_info",
                        untrustedCaptureData = true
                    )
                )
            )
        )

        composeRule.onNodeWithText("5 expert warnings").assertDoesNotExist()
        composeRule.onNodeWithText(string(R.string.agent_capture_derived)).assertDoesNotExist()
    }

    @Test
    fun modelInteractionIsShownInsideAnalysisStepsWithoutStandaloneSection() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                toolActivities = listOf(succeededActivity()),
                modelInteractions = listOf(toolCallInteraction())
            )
        )

        composeRule.onNodeWithText(string(R.string.agent_model_interactions_count, 1))
            .assertDoesNotExist()
        composeRule.onNodeWithText(string(R.string.agent_model_interaction_step, 1))
            .assertDoesNotExist()

        composeRule.onNodeWithContentDescription(string(R.string.expand)).performClick()

        composeRule.onNodeWithText(string(R.string.agent_tool_capture_overview)).assertIsDisplayed()
        composeRule.onNodeWithText(string(R.string.agent_model_interaction_step, 1))
            .assertIsDisplayed()
        composeRule.onNodeWithText(string(R.string.agent_model_interactions_count, 1))
            .assertDoesNotExist()

        composeRule.onNodeWithContentDescription(string(R.string.agent_model_interaction_view))
            .performClick()
        composeRule.onNodeWithText(string(R.string.agent_model_interaction_title))
            .assertIsDisplayed()
    }

    @Test
    fun toolTraceShowsCountsAndTruncationButNotArgumentValues() {
        setScreen(
            ProtocolAgentUiState(
                phase = AgentRunPhase.Completed,
                toolActivities = listOf(
                    succeededActivity().copy(
                        argumentsSummary = "sip.Call-ID == \"abc@10.0.0.1\"",
                        returnedCount = 50,
                        totalCount = 500,
                        truncated = true
                    )
                )
            )
        )

        // The trace is compact by default; the same control reveals all steps.
        composeRule.onNodeWithText(string(R.string.agent_tool_counts, 50, 500), substring = true)
            .assertDoesNotExist()
        composeRule.onNodeWithContentDescription(string(R.string.expand)).performClick()
        composeRule.onNodeWithText(string(R.string.agent_tool_counts, 50, 500), substring = true)
            .assertIsDisplayed()
        composeRule.onNodeWithText(string(R.string.agent_tool_truncated), substring = true)
            .assertIsDisplayed()
    }

    // -------------------------------------------------------------- fixtures

    private fun runningActivity() = AgentToolActivity(
        toolCallId = "call-running",
        toolName = "get_expert_info",
        status = AgentToolActivityStatus.Running,
        argumentsSummary = "severity",
        startedAtMillis = 1_000L
    )

    private fun succeededActivity() = AgentToolActivity(
        toolCallId = "call-done",
        toolName = "get_capture_overview",
        status = AgentToolActivityStatus.Succeeded,
        argumentsSummary = "scope",
        startedAtMillis = 1_000L,
        completedAtMillis = 1_250L,
        returnedCount = 1,
        totalCount = 1
    )

    private fun toolCallInteraction() = AgentModelInteraction(
        id = "interaction-1",
        turn = 1,
        request = AgentModelRequest(requestId = "request-1"),
        response = AgentModelResponse.ToolCalls(
            calls = listOf(
                AgentToolCall(
                    toolCallId = "call-done",
                    toolName = "get_capture_overview"
                )
            )
        )
    )

    private fun finding() = AgentFinding(
        id = "finding-1",
        title = "401 Unauthorized was never answered",
        severity = AgentFindingSeverity.Error,
        confidence = AgentConfidence.High,
        conclusion = "The UE never sent a second REGISTER after the challenge.",
        evidence = listOf(
            AgentEvidence(
                type = AgentEvidenceType.Frame,
                frameNumber = 42L,
                observation = "401 Unauthorized",
                sourceToolCallId = "call-done"
            )
        ),
        alternatives = listOf("The retry may have been sent on another interface.")
    )

    private fun report() = AgentReport(
        summary = "IMS registration did not complete.",
        findings = listOf(finding()),
        provenance = AgentReportProvenance(playbookVersion = "ims-registration-failure@2"),
        completeness = AgentReportCompleteness.Complete
    )
}

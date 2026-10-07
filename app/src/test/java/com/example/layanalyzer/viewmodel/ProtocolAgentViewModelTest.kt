// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.ai.agent.AgentSettings
import com.example.layanalyzer.ai.agent.AgentSettingsStore
import com.example.layanalyzer.ai.agent.MutableAgentSettingsStore
import com.example.layanalyzer.ai.agent.PromptAssembler
import com.example.layanalyzer.ai.agent.ProtocolAnalysisAgent
import com.example.layanalyzer.ai.cache.AgentToolCache
import com.example.layanalyzer.ai.client.AiModelCapabilities
import com.example.layanalyzer.ai.client.AiModelErrors
import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScript
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.ai.client.MockScriptedResponse
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.AgentPlaybookCheck
import com.example.layanalyzer.ai.playbook.AgentPlaybookFailureBranch
import com.example.layanalyzer.ai.playbook.AgentPlaybookStore
import com.example.layanalyzer.ai.playbook.InMemoryPlaybookUsageStore
import com.example.layanalyzer.ai.playbook.PlaybookUsageStore
import com.example.layanalyzer.ai.playbook.ScenarioOrigin
import com.example.layanalyzer.ai.playbook.ScenarioQuarantineEvent
import com.example.layanalyzer.ai.playbook.ScenarioQuarantineEventChannel
import com.example.layanalyzer.ai.playbook.ScenarioRulesOverlay
import com.example.layanalyzer.ai.playbook.ScenarioThreshold
import com.example.layanalyzer.ai.playbook.ScenarioValidationCodes
import com.example.layanalyzer.ai.playbook.ScenarioValidationError
import com.example.layanalyzer.ai.playbook.TestScenarioPackages
import com.example.layanalyzer.ai.playbook.UserScenarioPlaybookStore
import com.example.layanalyzer.ai.playbook.UserScenarioStore
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.model.AgentAnalysisMode
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentTokenUsage
import com.example.layanalyzer.model.AnalysisJobPhase
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import kotlinx.coroutines.CoroutineScope
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.SupervisorJob
import kotlinx.coroutines.cancel
import kotlinx.coroutines.delay
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import com.example.layanalyzer.model.AgentModelMessageRole
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * AI-07 coverage.
 *
 * The tests drive a real [ProtocolAnalysisAgent] over scripted models rather
 * than a stubbed Agent, so the state sequences asserted here are the ones the
 * production loop actually emits.  The ViewModel is given its own scope instead
 * of viewModelScope, which is what lets these run as plain JVM tests with no
 * Main dispatcher.
 *
 * Runs are awaited with [awaitIdle] rather than assumed to finish inline: parts
 * of the coordinator's lease handling hop to [Dispatchers.Default], so a
 * scripted run is fast but not synchronous.
 */
class ProtocolAgentViewModelTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun aSuccessfulRunEndsCompletedWithAReportAndToolActivities() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            val state = viewModel.uiState.value
            assertEquals(AgentRunPhase.Completed, state.phase)
            assertNotNull(state.report)
            assertNull(state.error)
            assertNull(state.activeTool)
            assertEquals(2, state.toolActivities.size)
            assertEquals(AnalysisJobPhase.Completed, viewModel.analysisJob.value.phase)
            // The run's identity reaches the UI so a transcript can be keyed to it.
            assertNotNull(state.conversationId)
            assertNotNull(state.runId)
        }
    }

    @Test
    fun aSuccessfulRunIsAutomaticallySavedAsARegularSession() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("auto-saved-session")
            )
            val viewModel = viewModel(
                harness = harness,
                script = MockModelScriptLibrary.require(
                    MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
                ),
                sessionStore = store
            )

            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()

            assertEquals(1, store.count())
            assertEquals(1, viewModel.savedSessions.value.size)
            assertFalse(store.listAll().single().autoSaved)

            val reopened = viewModel(
                harness = harness,
                script = MockModelScriptLibrary.require(
                    MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
                ),
                sessionStore = store
            )
            // The saved list loads asynchronously now, so wait for the
            // startup refresh to publish before reading it.
            reopened.awaitSavedSessions(1)
            assertFalse(reopened.savedSessions.value.single().autoSaved)
        }
    }

    @Test
    fun unredactedRunIsAutomaticallySaved() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("unredacted-session")
            )
            val settings = TestSettingsStore(
                AgentSettings(privacyMode = AgentPrivacyMode.UnredactedMetadata)
            )
            val viewModel = viewModel(
                harness = harness,
                script = MockModelScriptLibrary.require(
                    MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
                ),
                sessionStore = store,
                settingsStore = settings
            )

            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()

            // Unredacted conversations are saved automatically like any other.
            // Credentials are excluded by the persistence contract.
            assertEquals(1, store.count())
            assertFalse(store.listAll().single().autoSaved)
        }
    }

    @Test
    fun reopeningASavedSessionRestoresTheConversationAndAllowsAFollowUp() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("resumed-session")
            )
            val viewModel = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store
            )

            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()

            val original = viewModel.uiState.value
            assertTrue(original.messages.isNotEmpty())

            // A second ViewModel over the same store stands in for relaunching
            // the app: nothing is carried over in memory.
            val reopened = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store
            )
            assertTrue(reopened.uiState.value.messages.isEmpty())

            // The saved list loads asynchronously now; wait for it to publish.
            reopened.awaitSavedSessions(1)
            val saved = reopened.savedSessions.value.single()
            assertTrue(saved.isResumable)
            reopened.restoreSavedSession(saved.conversationId)

            // The conversation comes back on screen rather than in the
            // read-only dialog, and it is ready to continue.
            assertNull(reopened.restoredSession.value)
            val restored = reopened.uiState.value
            assertEquals(
                original.messages.map { it.content },
                restored.messages.map { it.content }
            )
            assertEquals(
                original.modelInteractions.size,
                restored.modelInteractions.size
            )
            assertEquals(original.report?.summary, restored.report?.summary)
            assertEquals(AgentRunPhase.Completed, restored.phase)
            assertTrue(restored.canContinue)

            reopened.continueConversation("And what should I do about it?")
            // A resumed conversation is already in the Completed phase, so wait
            // for the run to start before waiting for it to finish; otherwise
            // awaitIdle returns on the restored state and asserts nothing.
            reopened.awaitRunning()
            reopened.awaitIdle()

            // The follow-up extends the restored transcript instead of
            // starting over, which is what proves the conversation survived.
            val after = reopened.uiState.value.messages
            assertTrue(after.size > restored.messages.size)
            assertTrue(
                "The restored turns must survive the follow-up",
                after.map { it.content }.containsAll(restored.messages.map { it.content })
            )
        }
    }

    @Test
    fun resumingTwiceKeepsTheTranscriptStable() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("twice-resumed-session")
            )
            val viewModel = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store
            )

            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()

            // The saved list loads asynchronously now; wait for it to publish.
            viewModel.awaitSavedSessions(1)
            val conversationId = viewModel.savedSessions.value.single().conversationId
            viewModel.restoreSavedSession(conversationId)
            val firstResume = viewModel.uiState.value.messages

            // Reopening a resumed conversation must not keep re-prefixing the
            // ids it read back or fork another history entry.
            assertEquals(1, store.count())
            assertEquals(conversationId, viewModel.savedSessions.value.single().conversationId)
            viewModel.restoreSavedSession(conversationId)

            assertEquals(
                firstResume.map { it.id },
                viewModel.uiState.value.messages.map { it.id }
            )
            assertEquals(
                firstResume.map { it.content },
                viewModel.uiState.value.messages.map { it.content }
            )
        }
    }

    @Test
    fun deletingASavedSessionRemovesTheFileAndRefreshesTheHistoryCards() = runBlocking {
        harness().use { harness ->
            // Resume ViewModel work on this event loop, like the UI thread.
            // Unconfined can finish fast IO before the immediate marker assertion.
            val scope = CoroutineScope(coroutineContext + SupervisorJob())
            try {
                val store = com.example.layanalyzer.data.AgentSessionStore(
                    temporaryFolder.newFolder("deleted-session")
                )
                val viewModel = viewModel(
                    harness = harness,
                    script = repeatedOverviewScript(),
                    sessionStore = store,
                    externalScope = scope
                )

                viewModel.submitQuestion("What is wrong?")
                viewModel.awaitSavedSessions(1)
                viewModel.awaitIdle()
                viewModel.awaitLocalDataUsage(1)
                val conversationId = viewModel.savedSessions.value.single().conversationId

                viewModel.deleteSavedSession(conversationId)
                // No suspension here: deletion is queued while the row and
                // marker must already reflect the tap, before any file IO.
                assertTrue(viewModel.savedSessions.value.isEmpty())
                assertTrue(viewModel.deletingSavedSessionIds.value.contains(conversationId))
                assertNotNull(store.load(conversationId))

                viewModel.awaitNoDeleteInFlight()
                viewModel.awaitSavedSessions(0)
                // The usage refresh follows marker clearing. A minimum-count
                // wait for zero returns immediately, so wait for the exact count.
                withTimeout(AWAIT_TIMEOUT_MILLIS) {
                    while (viewModel.localDataUsage.value.savedSessionCount != 0) delay(POLL_MILLIS)
                }
                assertTrue(viewModel.deletingSavedSessionIds.value.isEmpty())
                assertNull(store.load(conversationId))
                assertEquals(0, store.count())
                assertTrue(viewModel.savedSessions.value.isEmpty())
                assertEquals(0, viewModel.localDataUsage.value.savedSessionCount)
            } finally {
                scope.cancel()
            }
        }
    }

    @Test
    fun aFailedDeleteSurfacesAnErrorAndClearsTheInFlightMarker() = runBlocking {
        harness().use { harness ->
            val directory = temporaryFolder.newFolder("failed-delete")
            val store = com.example.layanalyzer.data.AgentSessionStore(directory)
            val viewModel = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store
            )

            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()
            viewModel.awaitSavedSessions(1)
            val conversationId = viewModel.savedSessions.value.single().conversationId

            // Force the delete to fail: the session file becomes a non-empty
            // directory, which File.delete() refuses to remove.
            val sessionFile = directory.listFiles()!!.single { it.isFile }
            assertTrue(sessionFile.delete())
            assertTrue(sessionFile.mkdirs())
            java.io.File(sessionFile, "blocked").writeText("keep")

            viewModel.deleteSavedSession(conversationId)
            // The failed delete must not strand the optimistic removal: the
            // error bar appears and the in-flight marker clears.
            viewModel.awaitNoDeleteInFlight()
            withTimeout(AWAIT_TIMEOUT_MILLIS) {
                while (viewModel.uiState.value.transientError == null) delay(POLL_MILLIS)
            }
            assertEquals(
                "saved_session_delete_failed",
                viewModel.uiState.value.transientError?.details?.get("reason")
            )
            assertTrue(viewModel.deletingSavedSessionIds.value.isEmpty())
        }
    }

    @Test
    fun conversationKeepsItsPrivacyModeUntilANewConversationStarts() = runBlocking {
        harness().use { harness ->
            val settings = TestSettingsStore(AgentSettings())
            val viewModel = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                settingsStore = settings
            )

            viewModel.updatePrivacyMode(AgentPrivacyMode.UnredactedMetadata)
            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()

            assertEquals(AgentPrivacyMode.UnredactedMetadata, viewModel.uiState.value.privacyMode)
            assertTrue(viewModel.uiState.value.modelInteractions.isNotEmpty())
            assertTrue(
                viewModel.uiState.value.modelInteractions.all {
                    it.request.privacyMode == AgentPrivacyMode.UnredactedMetadata
                }
            )

            viewModel.updatePrivacyMode(AgentPrivacyMode.RedactedMetadata)
            viewModel.continueConversation("What should I inspect next?")
            viewModel.awaitIdle()

            assertEquals(AgentPrivacyMode.UnredactedMetadata, settings.settings.privacyMode)
            assertTrue(
                viewModel.uiState.value.modelInteractions.all {
                    it.request.privacyMode == AgentPrivacyMode.UnredactedMetadata
                }
            )

            viewModel.startNewConversation()
            viewModel.updatePrivacyMode(AgentPrivacyMode.RedactedMetadata)

            assertEquals(AgentPrivacyMode.RedactedMetadata, settings.settings.privacyMode)
            assertEquals(AgentPrivacyMode.RedactedMetadata, viewModel.uiState.value.privacyMode)
        }
    }

    @Test
    fun completedRunPublishesProviderTokenUsageToTheUiState() = runBlocking {
        harness().use { harness ->
            val usage = AgentTokenUsage(
                inputTokens = 12_400,
                outputTokens = 3_100,
                cachedInputTokens = 2_000
            )
            val script = MockModelScript(
                id = "ui-token-usage",
                responses = listOf(
                    MockScriptedResponse.tool(
                        toolCallId = "call-overview",
                        toolName = "get_capture_overview"
                    ),
                    MockScriptedResponse(
                        com.example.layanalyzer.model.AgentModelResponse.Final(
                            report = AgentReport(summary = "Done."),
                            usage = usage
                        )
                    )
                )
            )
            val viewModel = viewModel(harness, script)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            assertEquals(usage, viewModel.uiState.value.tokenUsage)
        }
    }

    @Test
    fun theVisibleTranscriptHoldsTheQuestionAndTheToolSteps() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            val messages = viewModel.uiState.value.messages
            assertEquals("User", messages.first().role.name)
            // Tool transcript items stay marked untrusted: their content comes
            // from a capture file an attacker may have shaped.
            val toolItems = messages.filter { it.toolCallId != null }
            assertTrue(toolItems.isNotEmpty())
            assertTrue(toolItems.all { it.untrustedCaptureData })
        }
    }

    @Test
    fun theRunRetainsEachModelRequestAndResponseForInspection() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            val interactions = viewModel.uiState.value.modelInteractions
            assertEquals(1, interactions.size)
            assertTrue(interactions.all { it.request.messages.isNotEmpty() })
            assertTrue(interactions.any { it.response is com.example.layanalyzer.model.AgentModelResponse.Final })
            assertTrue(interactions.single().request.messages.any {
                it.toolCallId == "host-bootstrap-overview-1" && it.untrustedCaptureData
            })
        }
    }

    @Test
    fun exhaustedModelRetriesStateTheFailureOnTheReportWithoutABubble() = runBlocking {
        harness().use { harness ->
            val script = MockModelScript(
                id = "ui-model-retry-status",
                responses = listOf(
                    MockScriptedResponse.tool(
                        toolCallId = "call-overview",
                        toolName = "get_capture_overview"
                    ),
                    MockScriptedResponse.failure(AiModelErrors.unavailable("first_failure")),
                    MockScriptedResponse.failure(AiModelErrors.unavailable("second_failure")),
                    MockScriptedResponse.failure(AiModelErrors.unavailable("final_failure"))
                )
            )
            val viewModel = viewModel(
                harness = harness,
                script = script,
                policy = AgentPolicy(maxModelRetries = 2)
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            assertEquals(AgentRunPhase.FailedWithPartialReport, viewModel.uiState.value.phase)
            val messages = viewModel.uiState.value.messages
            // All three attempts ran, and the run ends with a report to show, so
            // its failure is stated by the report itself (partial-result warning
            // + error card) rather than by a "分析失败" bubble.  A retry the run
            // makes on the way somewhere is a step-level event either way, so
            // neither the attempts nor the terminal error reach the
            // conversation as an Error message.
            assertTrue(
                "expected no Error bubble, got " + messages.filter {
                    it.role == AgentConversationRole.Error
                },
                messages.none { it.role == AgentConversationRole.Error }
            )
            assertTrue(messages.none { it.content.contains("Retrying (") })
            // The failure is still legible from the state the card renders.
            assertEquals(2, viewModel.uiState.value.error?.details?.get("retryCount"))
            // The failed attempts stay inspectable on the step list, so each one
            // is recorded as a failed model interaction. The run makes at least
            // the two configured retries plus the attempt that exhausts them.
            val failedInteractions = viewModel.uiState.value.modelInteractions.count {
                it.response is com.example.layanalyzer.model.AgentModelResponse.Failure
            }
            assertTrue(
                "expected at least 3 failed model interactions, got $failedInteractions",
                failedInteractions >= 3
            )
        }
    }

    /**
     * The bubble is the fallback for the one run that has nothing to show.
     *
     * A model that refuses before any report exists ends the run without a
     * validated report, so the failure has no report to live in and stays in
     * the conversation.  Without this case the rule "a report on screen means
     * no failure bubble" could be over-applied into silence.
     */
    @Test
    fun aRefusedRunWithNoReportStillRaisesTheFailureBubble() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(
                harness = harness,
                script = MockModelScript(
                    id = "ui-refusal-bubble",
                    responses = listOf(
                        MockScriptedResponse.refusal("I cannot analyse this capture.")
                    )
                ),
                policy = AgentPolicy(maxModelRetries = 0)
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            assertEquals(AgentRunPhase.Failed, viewModel.uiState.value.phase)
            val errorMessages = viewModel.uiState.value.messages.filter {
                it.role == AgentConversationRole.Error
            }
            assertEquals(1, errorMessages.size)
            assertEquals(
                AgentErrorCode.MODEL_UNAVAILABLE,
                errorMessages.single().error?.code
            )
        }
    }

    @Test
    fun aBlankQuestionIsRefusedAsATransientErrorAndStartsNoRun() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.submitQuestion("   ")

            assertEquals(AgentRunPhase.Idle, viewModel.uiState.value.phase)
            assertEquals(
                AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                viewModel.uiState.value.transientError?.code
            )
            assertTrue(viewModel.uiState.value.messages.isEmpty())

            viewModel.clearTransientError()
            assertNull(viewModel.uiState.value.transientError)
        }
    }

    @Test
    fun submittingWithNoCaptureOpenIsRefusedBeforeTheAgentRuns() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)
            harness.coordinator.invalidateSession()

            viewModel.submitQuestion("Why is this capture slow?")

            assertEquals(AgentErrorCode.NO_CAPTURE, viewModel.uiState.value.transientError?.code)
            assertEquals(AgentRunPhase.Idle, viewModel.uiState.value.phase)
        }
    }

    /**
     * The single-session rule: a second submit while a run is in flight is
     * refused, not queued, and does not replace the first run.
     */
    @Test
    fun aSecondSubmitWhileRunningIsRefusedRatherThanStartingASecondAgent() = runBlocking {
        harness().use { harness ->
            // A slow first model turn holds the run open across the second submit.
            val viewModel = viewModel(harness, MockModelScriptLibrary.CANCELLATION)

            viewModel.submitQuestion("First question?")
            viewModel.awaitRunning()

            viewModel.submitQuestion("Second question?")

            assertEquals(
                "concurrent_run",
                viewModel.uiState.value.transientError?.details?.get("reason")
            )
            // Still the first run: one session, one question.
            assertTrue(viewModel.uiState.value.isRunning)
            assertEquals(1, viewModel.uiState.value.messages.count { it.role.name == "User" })

            viewModel.cancel()
        }
    }

    @Test
    fun cancelMovesToCancelledAndStopsTheAgent() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CANCELLATION)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitRunning()
            viewModel.cancel()

            assertEquals(AgentRunPhase.Cancelled, viewModel.uiState.value.phase)
            assertEquals(AnalysisJobPhase.Cancelled, viewModel.analysisJob.value.phase)
            assertNull(viewModel.uiState.value.activeTool)
            assertFalse(viewModel.uiState.value.isRunning)
        }
    }

    @Test
    fun cancelIsIgnoredWhenNothingIsRunning() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.cancel()

            assertEquals(AgentRunPhase.Idle, viewModel.uiState.value.phase)
        }
    }

    /**
     * Rotation recreates the Composable, not the ViewModel.  Re-reading the
     * state is all a recomposition does, and it must not resubmit or lose the
     * finished report.
     */
    @Test
    fun rereadingTheStateDoesNotRestartTheRunOrLoseTheReport() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            val afterFirst = viewModel.uiState.value

            assertEquals(afterFirst, viewModel.uiState.value)
            assertNotNull(viewModel.uiState.value.report)
            assertEquals(afterFirst.messages.size, viewModel.uiState.value.messages.size)
        }
    }

    @Test
    fun closingTheCaptureEndsTheRunWithSessionChanged() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CANCELLATION)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitRunning()

            harness.coordinator.invalidateSession()

            assertEquals(AgentRunPhase.Failed, viewModel.uiState.value.phase)
            assertEquals(AgentErrorCode.SESSION_CHANGED, viewModel.uiState.value.error?.code)
            assertEquals(AgentErrorCode.SESSION_CHANGED.name, viewModel.analysisJob.value.errorCode)
            assertNull(viewModel.uiState.value.report)
        }
    }

    @Test
    fun aCompletedReportIsClearedWhenTheCaptureIsClosed() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            assertNotNull(viewModel.uiState.value.report)

            harness.coordinator.invalidateSession()

            // A report about a capture that is no longer open must not remain on
            // screen as though it described the next one.
            assertNull(viewModel.uiState.value.report)
            assertTrue(viewModel.uiState.value.messages.isEmpty())
        }
    }

    @Test
    fun retryKeepsTheConversationAndOnlyChangesTheRun() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, repeatedOverviewScript())

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            val firstConversationId = viewModel.uiState.value.conversationId
            val firstRunId = viewModel.uiState.value.runId
            assertNotNull(firstConversationId)
            assertNotNull(firstRunId)

            viewModel.retry()
            viewModel.awaitIdle()

            val after = viewModel.uiState.value
            // Same conversation, new run: a retry must not fork a second
            // history file for the same question.
            assertEquals(firstConversationId, after.conversationId)
            assertNotEquals(firstRunId, after.runId)
            assertEquals(
                "Why is this capture slow?",
                after.messages.first { it.role.name == "User" }.content
            )
            // The failed attempt's transcript is replaced, not stacked above the
            // second answer.
            assertEquals(1, after.messages.count { it.role.name == "User" })
        }
    }

    @Test
    fun retryDoesNotForkASecondSavedConversation() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("retry-same-conversation")
            )
            val viewModel = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            val conversationId = viewModel.uiState.value.conversationId

            viewModel.retry()
            viewModel.awaitIdle()

            // One conversation, two runs: the retry updated the single file.
            assertEquals(1, store.count())
            val saved = store.listAll().single()
            assertEquals(conversationId, saved.conversationId)
        }
    }

    @Test
    fun aFollowUpKeepsTheConversationIdAndAddsARun() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("follow-up-same-conversation")
            )
            val viewModel = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store
            )

            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()
            val conversationId = viewModel.uiState.value.conversationId

            viewModel.continueConversation("And what should I do about it?")
            viewModel.awaitRunning()
            viewModel.awaitIdle()

            assertEquals(conversationId, viewModel.uiState.value.conversationId)
            assertEquals(1, store.count())
            val saved = store.load(conversationId!!)!!
            assertTrue(saved.runIds.size >= 2)
        }
    }

    /** Two distinct report summaries so each round's conclusion is identifiable. */
    private fun twoRoundScript(): MockModelScript = MockModelScript(
        id = "two-rounds",
        responses = listOf(
            MockScriptedResponse.final(AgentReport(summary = "First round conclusion.")),
            MockScriptedResponse.final(AgentReport(summary = "Second round conclusion.")),
            MockScriptedResponse.final(AgentReport(summary = "Third round conclusion."))
        )
    )

    @Test
    fun aFollowUpArchivesThePriorRoundAndBothReportsStayReachable() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, twoRoundScript())

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            assertEquals("First round conclusion.", viewModel.uiState.value.report?.summary)
            assertTrue(viewModel.uiState.value.pastReports.isEmpty())

            viewModel.continueConversation("And what should I do about it?")
            viewModel.awaitIdle()

            val state = viewModel.uiState.value
            assertEquals("Second round conclusion.", state.report?.summary)
            // The first round moved to the archive instead of being overwritten.
            assertEquals(1, state.pastReports.size)
            assertEquals(
                "First round conclusion.",
                state.pastReports.single().report.summary
            )
        }
    }

    @Test
    fun aResumedConversationRestoresItsArchiveAndDeduplicatesOnFollowUp() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("resumed-archive")
            )
            // One shared model client stands in for the same provider across
            // the relaunch, so the scripted rounds keep their order.
            val modelClient = MockAiModelClient(twoRoundScript())
            fun launchViewModel() = ProtocolAgentViewModel(
                agent = agent(harness, modelClient),
                coordinator = harness.coordinator,
                settings = settings(),
                externalScope = CoroutineScope(Dispatchers.Unconfined),
                sessionStore = store
            )

            val original = launchViewModel()
            original.submitQuestion("Why is this capture slow?")
            original.awaitIdle()
            original.continueConversation("And what should I do about it?")
            original.awaitIdle()
            val conversationId = requireNotNull(original.uiState.value.conversationId)

            // A second ViewModel over the same store stands in for relaunching.
            val reopened = launchViewModel()
            reopened.restoreSavedSession(conversationId)

            val restored = reopened.uiState.value
            assertEquals("Second round conclusion.", restored.report?.summary)
            assertEquals(1, restored.pastReports.size)
            assertEquals(
                "First round conclusion.",
                restored.pastReports.single().report.summary
            )

            // The follow-up must archive the current report exactly once even
            // though its archived form was just decoded from disk.
            reopened.continueConversation("And the final answer?")
            reopened.awaitRunning()
            reopened.awaitIdle()

            val after = reopened.uiState.value
            assertEquals("Third round conclusion.", after.report?.summary)
            assertEquals(2, after.pastReports.size)
            assertEquals(
                listOf(
                    "First round conclusion.",
                    "Second round conclusion."
                ),
                after.pastReports.map { it.report.summary }
            )
            // The persisted file keeps the same shape: newest report on top,
            // archive below, no duplicates.
            val saved = store.load(conversationId)!!
            assertEquals("Third round conclusion.", saved.report.summary)
            assertEquals(2, saved.rounds.size)
        }
    }

    @Test
    fun aRetryArchivesTheScreenReportAndKeepsEarlierRoundsReachable() = runBlocking {
        harness().use { harness ->
            val script = MockModelScript(
                id = "retry-with-archive",
                responses = listOf(
                    MockScriptedResponse.final(AgentReport(summary = "First round conclusion.")),
                    MockScriptedResponse.final(AgentReport(summary = "Second round conclusion.")),
                    MockScriptedResponse.final(AgentReport(summary = "Retry concluded."))
                )
            )
            val viewModel = viewModel(harness, script)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            viewModel.continueConversation("And what caused finding 1?")
            viewModel.awaitIdle()
            assertEquals(listOf("First round conclusion."), viewModel.uiState.value.pastReports.map { it.report.summary })

            // Retrying answers the same question again; the report on screen
            // moves to the archive instead of vanishing.
            viewModel.retry()
            viewModel.awaitIdle()

            val state = viewModel.uiState.value
            assertEquals("Retry concluded.", state.report?.summary)
            assertEquals(
                listOf(
                    "First round conclusion.",
                    "Second round conclusion."
                ),
                state.pastReports.map { it.report.summary }
            )
        }
    }

    @Test
    fun resumingAnInterruptedJobRestoresTheVisibleTranscriptAndArchive() = runBlocking {
        harness().use { harness ->
            val jobsFolder = temporaryFolder.newFolder("interrupted-jobs")
            val jobStore = com.example.layanalyzer.data.AnalysisJobStore(jobsFolder)
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("interrupted-session")
            )
            val viewModel = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store,
                jobStore = jobStore
            )

            // A first round completes and auto-saves the whole conversation.
            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            val conversationId = requireNotNull(viewModel.uiState.value.conversationId)
            val savedMessages = viewModel.uiState.value.messages
            assertTrue(savedMessages.isNotEmpty())
            assertEquals(1, store.count())

            // The process then dies mid-follow-up: a leftover checkpoint that a
            // fresh process flips to interrupted at startup.
            val fingerprint = harness.coordinator.state.value.fileFingerprint
            assertTrue(
                jobStore.write(
                    com.example.layanalyzer.data.AnalysisJobCheckpoint(
                        conversationId = conversationId,
                        runId = "run-interrupted",
                        captureFingerprint = fingerprint,
                        captureLocalPath = "whatever",
                        question = "And what should I do about it?",
                        checkpoint = com.example.layanalyzer.data.AnalysisCheckpoint.Queued
                    )
                )
            )
            assertEquals(1, jobStore.markInterruptedOnStartup())

            // A second ViewModel stands in for the relaunch.
            val reopened = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store,
                jobStore = jobStore
            )
            reopened.refreshInterruptedJob()
            // The scan now runs on Dispatchers.IO; wait for publication.
            reopened.awaitInterruptedJob(conversationId)
            val banner = reopened.interruptedJob.value
            assertEquals(conversationId, banner?.conversationId)

            reopened.resumeInterruptedJob()
            reopened.awaitRunning()
            reopened.awaitIdle()

            // The resumed run replays the restored visible transcript instead
            // of starting the screen from nothing: the earlier round the user
            // was returning to stays on screen under its restored ids.
            val after = reopened.uiState.value.messages
            assertTrue(
                "The restored rounds must survive the resume",
                after.map { it.content }.containsAll(savedMessages.map { it.content })
            )
            assertEquals(
                savedMessages.map { "restored:${it.id}" },
                after.take(savedMessages.size).map { it.id }
            )
            assertEquals("Completed", reopened.analysisJob.value.phase.name)
        }
    }

    @Test
    fun restoringAConversationFromAnotherCaptureIsRefused() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("other-capture-restore")
            )
            // A saved conversation that belongs to a different capture entirely.
            store.save(
                com.example.layanalyzer.model.AgentSavedSession(
                    conversationId = "conv-other",
                    captureFingerprint = "fingerprint-not-open",
                    userQuestion = "about another file",
                    report = com.example.layanalyzer.model.AgentReport(
                        summary = "unrelated",
                        provenance = com.example.layanalyzer.model.AgentReportProvenance(
                            captureFingerprint = "fingerprint-not-open"
                        )
                    ),
                    savedAtMillis = 1_000L
                )
            ).getOrThrow()
            val viewModel = viewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                sessionStore = store
            )

            viewModel.restoreSavedSession("conv-other")

            // The fingerprint gate refuses the restore instead of restoring a
            // transcript whose frames describe a file that is not open.
            assertNotNull(viewModel.uiState.value.transientError)
            assertTrue(viewModel.uiState.value.messages.isEmpty())
            assertNull(viewModel.restoredSession.value)
        }
    }

    @Test
    fun retryWithoutAPreviousQuestionIsRefused() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.retry()

            assertEquals(
                "no_previous_question",
                viewModel.uiState.value.transientError?.details?.get("reason")
            )
            assertEquals(AgentRunPhase.Idle, viewModel.uiState.value.phase)
        }
    }

    @Test
    fun aFollowUpKeepsTheTranscriptOfTheSameCapture() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, repeatedOverviewScript())

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            val firstMessageCount = viewModel.uiState.value.messages.size
            assertTrue(firstMessageCount > 0)

            viewModel.continueConversation("And which stream is worst?")
            viewModel.awaitIdle()

            val messages = viewModel.uiState.value.messages
            assertTrue(messages.size > firstMessageCount)
            assertEquals(2, messages.count { it.role.name == "User" })
        }
    }

    @Test
    fun aFollowUpSendsPreviousContextAndReusesTheToolCache() = runBlocking {
        harness().use { harness ->
            val modelClient = MockAiModelClient(repeatedOverviewScript())
            val toolCache = AgentToolCache(directory = null)
            val viewModel = ProtocolAgentViewModel(
                agent = agent(harness, modelClient, toolCache = toolCache),
                coordinator = harness.coordinator,
                settings = settings(),
                externalScope = CoroutineScope(Dispatchers.Unconfined)
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            viewModel.continueConversation("What caused finding 1?")
            viewModel.awaitIdle()

            val followUpRequest = modelClient.observedRequests.first { request ->
                request.messages.any { message ->
                    message.role == com.example.layanalyzer.model.AgentModelMessageRole.User &&
                        message.content.contains(PromptAssembler.CONTINUATION_NOTICE)
                }
            }
            // The full prior round is replayed: its question and its validated
            // conclusion appear as verbatim messages, replacing the old
            // summary-only section.
            assertTrue(
                followUpRequest.messages.any { message ->
                    message.role == AgentModelMessageRole.User &&
                        message.content == "Why is this capture slow?"
                }
            )
            assertTrue(
                followUpRequest.messages.any { message ->
                    message.role == AgentModelMessageRole.Assistant &&
                        message.content.contains(
                            "TCP dominates the capture and Expert Info reports retransmissions."
                        )
                }
            )
            assertFalse(
                followUpRequest.messages.any { message ->
                    message.content.startsWith(PromptAssembler.HOST_PRIOR_CONTEXT_HEADER)
                }
            )
            // With the prior round replayed, the follow-up skips the host
            // bootstrap: the only bootstrap tool results in the request are the
            // two replayed from history (overview + expert), and every model
            // message sits before the fresh continuation question.
            assertEquals(
                2,
                followUpRequest.messages.count { message ->
                    message.toolCallId?.startsWith("host-bootstrap") == true &&
                        message.role == com.example.layanalyzer.model.AgentModelMessageRole.Tool
                }
            )
            val continuationIndex = followUpRequest.messages.indexOfFirst { message ->
                message.role == AgentModelMessageRole.User &&
                    message.content.contains(PromptAssembler.CONTINUATION_NOTICE)
            }
            assertTrue(
                followUpRequest.messages.take(continuationIndex).all { message ->
                    message.toolCallId?.startsWith("host-bootstrap") != true ||
                        message.role == com.example.layanalyzer.model.AgentModelMessageRole.Tool ||
                        message.role == com.example.layanalyzer.model.AgentModelMessageRole.Assistant
                }
            )
            // No tool ran after the replayed history: nothing was re-executed.
            assertTrue(
                followUpRequest.messages.drop(continuationIndex).none { message ->
                    message.role == com.example.layanalyzer.model.AgentModelMessageRole.Tool
                }
            )
        }
    }

    /**
     * P2: automatic save must carry the sanitized transcript, so the exact
     * request a restarted process sends for its first follow-up can be
     * asserted end to end through the store.
     */
    @Test
    fun killProcessReopenReplaysTheFullSavedTranscriptIntoTheFollowUp() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("kill-process-replay")
            )
            val modelClient = MockAiModelClient(repeatedOverviewScript())
            fun launchViewModel() = ProtocolAgentViewModel(
                agent = agent(harness, modelClient),
                coordinator = harness.coordinator,
                settings = settings(),
                externalScope = CoroutineScope(Dispatchers.Unconfined),
                sessionStore = store
            )

            val viewModel = launchViewModel()
            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()

            // Nothing survives in memory across the relaunch, so the sanitized
            // transcript on disk is the only thing the follow-up can replay.
            val savedConversationId = requireNotNull(viewModel.uiState.value.conversationId)
            val savedOnDisk = requireNotNull(store.load(savedConversationId))
            assertTrue(savedOnDisk.conversationTranscript.isNotEmpty())
            assertFalse(
                savedOnDisk.conversationTranscript.any { message ->
                    message.role == AgentModelMessageRole.System ||
                        !message.reasoningContent.isNullOrEmpty()
                }
            )

            val reopened = launchViewModel()
            reopened.restoreSavedSession(savedConversationId)
            reopened.continueConversation("And what should I do about it?")
            reopened.awaitRunning()
            reopened.awaitIdle()

            assertEquals(AgentRunPhase.Completed, reopened.uiState.value.phase)
            val followUpRequest = modelClient.observedRequests.last { request ->
                request.messages.any { message ->
                    message.role == AgentModelMessageRole.User &&
                        message.content.contains(PromptAssembler.CONTINUATION_NOTICE)
                }
            }
            // History sits between the System prompt and the fresh question.
            assertEquals(AgentModelMessageRole.System, followUpRequest.messages.first().role)
            val continuationIndex = followUpRequest.messages.indexOfFirst { message ->
                message.role == AgentModelMessageRole.User &&
                    message.content.contains(PromptAssembler.CONTINUATION_NOTICE)
            }
            val firstRoundQuestionIndex = followUpRequest.messages.indexOfFirst { message ->
                message.role == AgentModelMessageRole.User &&
                    message.content == "What is wrong?"
            }
            assertTrue(firstRoundQuestionIndex > 0)
            assertTrue(firstRoundQuestionIndex < continuationIndex)
            assertTrue(
                followUpRequest.messages.take(continuationIndex).any { message ->
                    message.role == AgentModelMessageRole.Assistant &&
                        message.content.contains(
                            "TCP dominates the capture and Expert Info reports retransmissions."
                        )
                }
            )
            // Both bootstrap results arrive replayed from the saved round; the
            // resumed run did not execute them again.
            assertEquals(
                2,
                followUpRequest.messages.count { message ->
                    message.toolCallId?.startsWith("host-bootstrap") == true &&
                        message.role == AgentModelMessageRole.Tool
                }
            )
            assertFalse(
                followUpRequest.messages.any { message ->
                    message.content.startsWith(PromptAssembler.HOST_PRIOR_CONTEXT_HEADER)
                }
            )
        }
    }

    /**
     * A v4 archive has no replayable transcript: the follow-up must degrade to
     * the prior-context summary instead of losing the answer silently.
     */
    @Test
    fun resumingASchemaFourArchiveDegradesToTheSummaryPath() = runBlocking {
        harness().use { harness ->
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("v4-degrade")
            )
            val modelClient = MockAiModelClient(repeatedOverviewScript())
            fun launchViewModel() = ProtocolAgentViewModel(
                agent = agent(harness, modelClient),
                coordinator = harness.coordinator,
                settings = settings(),
                externalScope = CoroutineScope(Dispatchers.Unconfined),
                sessionStore = store
            )

            val viewModel = launchViewModel()
            viewModel.submitQuestion("What is wrong?")
            viewModel.awaitIdle()

            // Hand the persisted file back its pre-v5 shape: version four and
            // no transcript field at all.
            val savedConversationId = requireNotNull(viewModel.uiState.value.conversationId)
            val file = store.storageDirectory.listFiles()!!
                .single { it.name.endsWith(".json") }
            file.writeText(
                org.json.JSONObject(file.readText()).apply {
                    remove("conversationTranscript")
                    put("schemaVersion", 4)
                }.toString()
            )

            val reopened = launchViewModel()
            reopened.restoreSavedSession(savedConversationId)
            assertTrue(requireNotNull(store.load(savedConversationId)).conversationTranscript.isEmpty())

            reopened.continueConversation("And what should I do about it?")
            reopened.awaitRunning()
            reopened.awaitIdle()

            assertEquals(AgentRunPhase.Completed, reopened.uiState.value.phase)
            // No continuation notice anywhere: nothing was replayed.
            assertFalse(
                modelClient.observedRequests.any { request ->
                    request.messages.any { message ->
                        message.role == AgentModelMessageRole.User &&
                            message.content.contains(PromptAssembler.CONTINUATION_NOTICE)
                    }
                }
            )
            // The degraded path still tells the model what round one concluded.
            val degradeRequest = modelClient.observedRequests.last()
            assertTrue(
                degradeRequest.messages.any { message ->
                    message.content.startsWith(PromptAssembler.HOST_PRIOR_CONTEXT_HEADER)
                }
            )
        }
    }

    @Test
    fun aFollowUpKeepsARecoveredFinalSummaryVisibleAfterAnInvestigationFailure() = runBlocking {
        harness().use { harness ->
            val script = MockModelScript(
                id = "follow-up-recovered-summary",
                responses = listOf(
                    MockScriptedResponse.final(
                        AgentReport(summary = "The first analysis completed.")
                    ),
                    MockScriptedResponse.failure(AiModelErrors.unavailable("provider_error")),
                    MockScriptedResponse.final(
                        AgentReport(summary = "The follow-up answer was recovered.")
                    )
                )
            )
            val viewModel = viewModel(
                harness = harness,
                script = script,
                policy = AgentPolicy(maxModelRetries = 0)
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            viewModel.continueConversation("What caused the issue?")
            viewModel.awaitIdle()

            val state = viewModel.uiState.value
            assertEquals(AgentRunPhase.FailedWithPartialReport, state.phase)
            assertEquals(
                "The follow-up answer was recovered.",
                state.report?.summary
            )
            assertEquals(AgentReportCompleteness.Incomplete, state.report?.completeness)
            assertEquals(AgentErrorCode.MODEL_UNAVAILABLE, state.error?.code)
            // The recovered report is on screen, so its failure is stated by the
            // report itself (partial-result warning + error card) and raises no
            // "分析失败" bubble above it.
            assertTrue(
                "expected no Error bubble beside the recovered report",
                state.messages.none { it.role == AgentConversationRole.Error }
            )
        }
    }

    @Test
    fun aFollowUpIsRefusedOnceTheCaptureIsGone() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, repeatedOverviewScript())

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            harness.coordinator.invalidateSession()
            viewModel.continueConversation("And which stream is worst?")

            // Closing the capture already cleared the conversation, so this can
            // only be read as a new question with nothing open.
            assertEquals(AgentErrorCode.NO_CAPTURE, viewModel.uiState.value.transientError?.code)
            assertTrue(viewModel.uiState.value.messages.isEmpty())
        }
    }

    @Test
    fun startNewConversationClearsTheTranscriptAndTheJobState() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()
            assertTrue(viewModel.uiState.value.messages.isNotEmpty())

            viewModel.startNewConversation()

            assertEquals(AgentRunPhase.Idle, viewModel.uiState.value.phase)
            assertTrue(viewModel.uiState.value.messages.isEmpty())
            assertNull(viewModel.uiState.value.report)
            assertEquals(AnalysisJobPhase.Completed, viewModel.analysisJob.value.phase)
        }
    }

    /**
     * AI-07 §4.5: the Agent publishes its own job state and never writes to
     * PacketListViewModel's, so the two banners cannot overwrite each other.
     */
    @Test
    fun runningPhasesMapToOneRunningJobPhase() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, MockModelScriptLibrary.CANCELLATION)

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitRunning()

            assertEquals(AnalysisJobPhase.Running, viewModel.analysisJob.value.phase)
            assertNotNull(viewModel.analysisJob.value.message)
            assertEquals(AnalysisScope.CompleteFile, viewModel.analysisJob.value.scope)

            viewModel.cancel()
        }
    }

    @Test
    fun aTextOnlyModelIsShownAsSingleSummaryMode() = runBlocking {
        harness().use { harness ->
            // AI-13 limits a prose-only model to one overview and one report
            // request instead of presenting it as a full Agent run.
            val viewModel = viewModel(
                harness,
                MockModelScript(
                    id = "prose-only",
                    capabilities = AiModelCapabilities.TEXT_ONLY,
                    responses = listOf(
                        MockScriptedResponse.final(
                            AgentReport(
                                summary = "One bounded summary.",
                                completeness = AgentReportCompleteness.Partial
                            )
                        )
                    )
                )
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)
            assertEquals(AgentAnalysisMode.SingleSummary, viewModel.uiState.value.analysisMode)
            assertEquals(AgentReportCompleteness.Partial, viewModel.uiState.value.report?.completeness)
            assertEquals(AnalysisJobPhase.Completed, viewModel.analysisJob.value.phase)
        }
    }

    @Test
    fun anIncompleteCompletedReportExposesItsHostStopReason() = runBlocking {
        harness().use { harness ->
            val script = MockModelScript(
                id = "step-limited",
                responses = listOf(
                    MockScriptedResponse.final(AgentReport(summary = "Stopped with a usable summary."))
                )
            )
            val viewModel = viewModel(
                harness,
                script,
                policy = AgentPolicy(maxSteps = 1)
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitIdle()

            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)
            assertEquals(
                AgentErrorCode.MAX_STEPS_REACHED,
                viewModel.uiState.value.completionWarning?.code
            )
            assertEquals(
                AgentErrorCode.MAX_STEPS_REACHED.name,
                viewModel.analysisJob.value.errorCode
            )
        }
    }

    /**
     * What onCleared delegates to: cancelling releases the model request and the
     * native operation, which is the part that must not outlive the ViewModel.
     */
    @Test
    fun cancellingReleasesTheModelAndNativeWork() = runBlocking {
        harness().use { harness ->
            val agent = agent(harness, MockModelScriptLibrary.require(MockModelScriptLibrary.CANCELLATION))
            val viewModel = ProtocolAgentViewModel(
                agent = agent,
                coordinator = harness.coordinator,
                settings = settings(),
                externalScope = CoroutineScope(Dispatchers.Unconfined)
            )

            viewModel.submitQuestion("Why is this capture slow?")
            viewModel.awaitRunning()
            assertTrue(agent.isRunning)

            viewModel.cancel()

            assertFalse(agent.isRunning)
        }
    }

    /**
     * The consent prompt is what the user reads before the first cloud call, so
     * it must carry the configured provider/model display names, not the
     * generated "provider-<millis>" ids.
     */
    /**
     * A follow-up that pauses on the consent prompt must not lose the history
     * it was about to replay: acceptConsent re-enters startRun, and the run it
     * starts carries the committed transcript — not a fresh conversation.
     */
    @Test
    fun acceptingConsentOnAFollowUpStillReplaysThePriorTranscript() = runBlocking {
        harness().use { harness ->
            val providerId = "provider-1755000000000"
            val settingsStore = TestSettingsStore(
                AgentSettings(
                    providerId = providerId,
                    modelId = "glm-4",
                    gatewayBaseUrl = "https://open.example.cn/api",
                    byokConfigured = true,
                    providers = listOf(
                        com.example.layanalyzer.ai.agent.AgentProviderConfig(
                            id = providerId,
                            name = "云上模型",
                            baseUrl = "https://open.example.cn/api",
                            models = listOf(
                                com.example.layanalyzer.ai.agent.AgentModelConfig(id = "glm-4")
                            ),
                            apiKeyConfigured = true
                        )
                    )
                )
            )
            val modelClient = MockAiModelClient(repeatedOverviewScript())
            val viewModel = ProtocolAgentViewModel(
                agent = agent(harness, modelClient),
                coordinator = harness.coordinator,
                settings = settingsStore,
                externalScope = CoroutineScope(Dispatchers.Unconfined)
            )

            // The first question is also held for consent; answer once.
            viewModel.submitQuestion("Why is this capture slow?")
            assertNotNull(viewModel.consentPrompt.value)
            viewModel.acceptConsent()
            viewModel.awaitIdle()

            // Clear the accepted version so the *follow-up* prompts again; this
            // isolates the acceptConsent path from the first-question path.
            settingsStore.update(settingsStore.settings.copy(firstUseConsentVersion = null))

            viewModel.continueConversation("What caused finding 1?")
            assertNotNull(viewModel.consentPrompt.value)
            viewModel.acceptConsent()
            viewModel.awaitIdle()

            val followUpRequest = modelClient.observedRequests.last { request ->
                request.messages.any { message ->
                    message.role == AgentModelMessageRole.User &&
                        message.content.contains("What caused finding 1?")
                }
            }
            assertTrue(
                followUpRequest.messages.any { message ->
                    message.role == AgentModelMessageRole.User &&
                        message.content.contains(PromptAssembler.CONTINUATION_NOTICE)
                }
            )
            assertTrue(
                followUpRequest.messages.any { message ->
                    message.role == AgentModelMessageRole.User &&
                        message.content == "Why is this capture slow?"
                }
            )
            // The visible transcript also survives the consent detour.
            assertEquals(2, viewModel.uiState.value.messages.count { it.role.name == "User" })
        }
    }

    @Test
    fun consentPromptCarriesTheConfiguredProviderAndModelNames() = runBlocking {
        harness().use { harness ->
            val providerId = "provider-1755000000000"
            val settingsStore = TestSettingsStore(
                AgentSettings(
                    providerId = providerId,
                    modelId = "glm-4",
                    gatewayBaseUrl = "https://open.example.cn/api",
                    byokConfigured = true,
                    providers = listOf(
                        com.example.layanalyzer.ai.agent.AgentProviderConfig(
                            id = providerId,
                            name = "智谱AI",
                            baseUrl = "https://open.example.cn/api",
                            models = listOf(
                                com.example.layanalyzer.ai.agent.AgentModelConfig(
                                    id = "glm-4",
                                    name = "GLM-4 旗舰"
                                )
                            ),
                            apiKeyConfigured = true
                        )
                    )
                )
            )
            val viewModel = viewModel(
                harness = harness,
                script = MockModelScriptLibrary.require(
                    MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
                ),
                settingsStore = settingsStore
            )

            viewModel.submitQuestion("Why is this capture slow?")

            val prompt = viewModel.consentPrompt.value
            assertNotNull(prompt)
            assertEquals(providerId, prompt!!.providerId)
            assertEquals("智谱AI", prompt.providerName)
            assertEquals("glm-4", prompt.modelId)
            assertEquals("GLM-4 旗舰", prompt.modelName)
            assertFalse(viewModel.uiState.value.isRunning)
        }
    }

    // ------------------------------------------------- SRE-RUN-02: playbookId

    /**
     * The chip path: an explicit playbook id travels with the submission even
     * when the question text matches none of that playbook's intent hints.
     */
    @Test
    fun aChipSubmissionCarriesTheExplicitPlaybookIdThroughTheRun() = runBlocking {
        harness().use { harness ->
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(), playbookStoreWithExtraScenario()
            )

            viewModel.submitQuestion(
                "Why is this capture slow?",
                playbookId = "tcp-retransmission-deep-dive"
            )
            viewModel.awaitIdle()

            assertEquals(
                "tcp-retransmission-deep-dive@3",
                viewModel.lastRunRecord.value?.playbookVersion
            )
        }
    }

    /** The override belongs to the submission, not the conversation. */
    @Test
    fun aFollowUpDropsTheExplicitPlaybookOverrideAndFallsBackToTextMatching() = runBlocking {
        harness().use { harness ->
            // Both turns carry a small scripted delay: with an otherwise
            // synchronous harness the follow-up would finish inline inside
            // continueConversation, leaving awaitRunning nothing to observe.
            val viewModel = playbookViewModel(
                harness, observedOverviewScript(), playbookStoreWithExtraScenario()
            )

            viewModel.submitQuestion(
                "Why is this capture slow?",
                playbookId = "tcp-retransmission-deep-dive"
            )
            viewModel.awaitIdle()
            assertEquals(
                "tcp-retransmission-deep-dive@3",
                viewModel.lastRunRecord.value?.playbookVersion
            )

            // The follow-up is free text and passes no id, so the selection
            // degrades to the question-text match: the general playbook.
            viewModel.continueConversation("What should I inspect next?")
            viewModel.awaitRunning()
            viewModel.awaitIdle()

            assertEquals(
                "general-capture-health@1",
                viewModel.lastRunRecord.value?.playbookVersion
            )
        }
    }

    /** A chip submission paused by the consent prompt keeps its id on accept. */
    @Test
    fun acceptingConsentOnAChipSubmissionKeepsTheExplicitPlaybookOverride() = runBlocking {
        harness().use { harness ->
            val providerId = "provider-1755000000000"
            val settingsStore = TestSettingsStore(
                AgentSettings(
                    providerId = providerId,
                    modelId = "glm-4",
                    gatewayBaseUrl = "https://open.example.cn/api",
                    byokConfigured = true,
                    providers = listOf(
                        com.example.layanalyzer.ai.agent.AgentProviderConfig(
                            id = providerId,
                            name = "云上模型",
                            baseUrl = "https://open.example.cn/api",
                            models = listOf(
                                com.example.layanalyzer.ai.agent.AgentModelConfig(id = "glm-4")
                            ),
                            apiKeyConfigured = true
                        )
                    )
                )
            )
            val viewModel = playbookViewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                playbookStore = playbookStoreWithExtraScenario(),
                settingsStore = settingsStore
            )

            viewModel.submitQuestion(
                "Why is this capture slow?",
                playbookId = "tcp-retransmission-deep-dive"
            )
            assertNotNull(viewModel.consentPrompt.value)
            viewModel.acceptConsent()
            viewModel.awaitIdle()

            // Without the pending-run preservation the acceptance would degrade
            // to the question-text match (the general playbook) instead.
            assertEquals(
                "tcp-retransmission-deep-dive@3",
                viewModel.lastRunRecord.value?.playbookVersion
            )
        }
    }

    /** A resumed run replays the checkpoint's question as free text. */
    @Test
    fun resumingAnInterruptedJobDoesNotCarryTheExplicitPlaybookOverride() = runBlocking {
        harness().use { harness ->
            val jobsFolder = temporaryFolder.newFolder("interrupted-jobs-playbook")
            val jobStore = com.example.layanalyzer.data.AnalysisJobStore(jobsFolder)
            val store = com.example.layanalyzer.data.AgentSessionStore(
                temporaryFolder.newFolder("interrupted-session-playbook")
            )
            val playbookStore = playbookStoreWithExtraScenario()
            val viewModel = playbookViewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                playbookStore = playbookStore,
                sessionStore = store,
                jobStore = jobStore
            )

            // The chip path ran once with the explicit id before the process
            // died, so the conversation on disk was framed by that override.
            viewModel.submitQuestion(
                "Why is this capture slow?",
                playbookId = "tcp-retransmission-deep-dive"
            )
            viewModel.awaitIdle()
            assertEquals(
                "tcp-retransmission-deep-dive@3",
                viewModel.lastRunRecord.value?.playbookVersion
            )
            val conversationId = requireNotNull(viewModel.uiState.value.conversationId)

            // A leftover follow-up checkpoint that a fresh process flips to
            // interrupted at startup.
            val fingerprint = harness.coordinator.state.value.fileFingerprint
            assertTrue(
                jobStore.write(
                    com.example.layanalyzer.data.AnalysisJobCheckpoint(
                        conversationId = conversationId,
                        runId = "run-interrupted",
                        captureFingerprint = fingerprint,
                        captureLocalPath = "whatever",
                        question = "And what should I do about it?",
                        checkpoint = com.example.layanalyzer.data.AnalysisCheckpoint.Queued
                    )
                )
            )
            assertEquals(1, jobStore.markInterruptedOnStartup())

            // A second ViewModel stands in for the relaunch.
            val reopened = playbookViewModel(
                harness = harness,
                script = repeatedOverviewScript(),
                playbookStore = playbookStore,
                sessionStore = store,
                jobStore = jobStore
            )
            reopened.refreshInterruptedJob()
            reopened.awaitInterruptedJob(conversationId)

            reopened.resumeInterruptedJob()
            reopened.awaitRunning()
            reopened.awaitIdle()

            // The resume passes no id: the checkpoint's question matches no
            // hint, so the run falls back to the general playbook rather than
            // resurrecting the dead submission's chip selection.
            assertEquals(
                "general-capture-health@1",
                reopened.lastRunRecord.value?.playbookVersion
            )
        }
    }

    // --------------------------------------- SRE-RUN-03: scenario management

    /**
     * The copy is store-minted content: a `user-` id from [generateCopyId],
     * the overlay extras stripped, and the source's content otherwise intact.
     */
    @Test
    fun copyingAScenarioStripsTheOverlayAndMintsAUserId() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val overlay = ScenarioRulesOverlay(
                thresholds = listOf(
                    ScenarioThreshold(
                        id = "capture.health.attentionpercent",
                        playbookId = "general-capture-health",
                        value = 5L,
                        unit = "percent",
                        region = "any",
                        notes = "Review signal only."
                    )
                ),
                recommendedFilters = mapOf("general-capture-health" to listOf("tcp.port == 5060"))
            )
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios, overlay),
                userScenarios = userScenarios
            )
            assertEquals(
                listOf("general-capture-health"),
                viewModel.playbooks.value.map { it.id }
            )

            viewModel.copyScenario("general-capture-health")
            viewModel.awaitPlaybooksCount(2)

            val source = viewModel.playbooks.value.single { it.id == "general-capture-health" }
            val copy = viewModel.playbooks.value.single { it.id != "general-capture-health" }
            // The generateCopyId contract: one `user-` prefix in front of the
            // source id plus the `-copy` suffix.
            assertEquals("user-general-capture-health-copy", copy.id)
            assertEquals(ScenarioOrigin.User, copy.origin)
            assertTrue(copy.thresholds.isEmpty())
            assertTrue(copy.recommendedFilters.isEmpty())
            assertEquals(source.title, copy.title)
            assertEquals(source.intentHints, copy.intentHints)
            assertEquals(source.initialTools, copy.initialTools)
            assertEquals(source.checks, copy.checks)
            assertEquals(source.requiredLimitations, copy.requiredLimitations)
            // The copy persisted on the user layer without opening the editor.
            assertTrue(viewModel.editingScenario.value == null)
            assertEquals(
                listOf("user-general-capture-health-copy"),
                userScenarios.load().map { it.id }
            )
        }
    }

    @Test
    fun deletingAUserScenarioRemovesItOptimisticallyAndThenFromTheStore() = runBlocking {
        harness().use { harness ->
            val scope = CoroutineScope(coroutineContext + SupervisorJob())
            try {
                val userScenarios = userScenarioStore()
                assertEquals(
                    emptyMap<String, ScenarioValidationError>(),
                    userScenarios.save(userScenario("user-rtp-check"))
                )
                val viewModel = playbookViewModel(
                    harness, repeatedOverviewScript(),
                    mergedPlaybookStore(userScenarios),
                    userScenarios = userScenarios,
                    externalScope = scope
                )
                assertEquals(
                    listOf("general-capture-health", "user-rtp-check"),
                    viewModel.playbooks.value.map { it.id }
                )

                viewModel.deleteScenario("user-rtp-check")
                // Assert the synchronous UI change before this event loop
                // runs the queued deletion; fast IO cannot erase the marker.
                assertFalse(
                    viewModel.playbooks.value.any { it.id == "user-rtp-check" }
                )
                assertTrue(viewModel.deletingScenarioIds.value.contains("user-rtp-check"))
                assertTrue(userScenarios.load().any { it.id == "user-rtp-check" })
                viewModel.awaitNoScenarioDeleteInFlight()

                assertFalse(userScenarios.load().any { it.id == "user-rtp-check" })
                assertTrue(viewModel.deletingScenarioIds.value.isEmpty())
                assertEquals(
                    listOf("general-capture-health"),
                    viewModel.playbooks.value.map { it.id }
                )

                // The preset lock: a built-in id is a silent no-op everywhere.
                viewModel.deleteScenario("general-capture-health")
                assertTrue(viewModel.deletingScenarioIds.value.isEmpty())
                assertEquals(
                    listOf("general-capture-health"),
                    viewModel.playbooks.value.map { it.id }
                )
                assertTrue(userScenarios.load().isEmpty())
            } finally {
                scope.cancel()
            }
        }
    }

    @Test
    fun deletingAUserScenarioAlsoClearsItsUsageCount() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            assertEquals(
                emptyMap<String, ScenarioValidationError>(),
                userScenarios.save(userScenario("user-rtp-check"))
            )
            val usage = InMemoryPlaybookUsageStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                usageStore = usage,
                userScenarios = userScenarios
            )

            viewModel.recordPlaybookUsage("user-rtp-check")
            assertEquals(1, usage.usage.value.getValue("user-rtp-check"))

            viewModel.deleteScenario("user-rtp-check")
            viewModel.awaitNoScenarioDeleteInFlight()

            assertFalse(usage.usage.value.containsKey("user-rtp-check"))
        }
    }

    /**
     * SRE-EDITOR-03: the scenario editor's Initial tools whitelist is the
     * playbook store's own tool set, so the editor can only ever offer tools a
     * save will accept.
     */
    @Test
    fun scenarioToolWhitelistComesFromThePlaybookStore() = runBlocking {
        harness().use { harness ->
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                playbookStoreWithExtraScenario()
            )

            assertEquals(TestScenarioPackages.availableTools, viewModel.scenarioToolWhitelist)
        }
    }

    /** Without a playbook store (asset-free JVM tests) the whitelist is empty. */
    @Test
    fun scenarioToolWhitelistIsEmptyWithoutAPlaybookStore() = runBlocking {
        harness().use { harness ->
            val viewModel = viewModel(harness, repeatedOverviewScript())

            assertTrue(viewModel.scenarioToolWhitelist.isEmpty())
        }
    }

    @Test
    fun savingANewScenarioClosesTheEditorAndPersistsItWithAMintedId() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val draft = requireNotNull(viewModel.editingScenario.value)
            assertTrue(draft.isNew)
            assertEquals("", draft.playbook.id)
            assertEquals(0, draft.playbook.version)
            assertEquals(ScenarioOrigin.User, draft.playbook.origin)

            // OPT-DRAFT-01: the controlled flow — edits land in the draft,
            // then the save request itself carries nothing.
            viewModel.setDraftPlaybook(
                filledScenarioDraft(draft.playbook, title = "My RTP Check")
            )
            viewModel.saveScenario()
            viewModel.awaitEditingScenario(open = false)
            viewModel.awaitPlaybooksCount(2)

            // The id was minted from the title and the version is store-owned.
            val saved = userScenarios.load().single()
            assertEquals("user-my-rtp-check", saved.id)
            assertEquals(1, saved.version)
            assertEquals("My RTP Check", saved.title)
            assertEquals(ScenarioOrigin.User, saved.origin)
            assertTrue(
                viewModel.playbooks.value.any { it.id == "user-my-rtp-check" }
            )
        }
    }

    @Test
    fun aRejectedSaveSurfacesTheFieldErrorsAndWritesNothing() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val draft = requireNotNull(viewModel.editingScenario.value)

            viewModel.setDraftPlaybook(
                draft.playbook.copy(title = "", intentHints = emptyList())
            )
            viewModel.saveScenario()
            viewModel.awaitScenarioValidationErrors()

            val errored = requireNotNull(viewModel.editingScenario.value)
            // OPT-ERR-01: the draft carries the store's stable reason codes
            // (code + args, never prose) keyed by the same field paths.
            assertEquals(
                ScenarioValidationError(ScenarioValidationCodes.STRING_BLANK),
                errored.validationErrors["title"]
            )
            assertEquals(
                ScenarioValidationError(ScenarioValidationCodes.INTENT_HINTS_REQUIRED),
                errored.validationErrors["intentHints"]
            )
            // A rejected save never reaches the disk, and the editor stays open.
            assertTrue(userScenarios.load().isEmpty())
            // OPT-DRAFT-01: the write-back lands on the same editor session
            // (same epoch) and freezes what the store saw into
            // validatedPlaybook, the snapshot the per-field error comparison
            // reads instead of the now-live playbook.
            assertEquals(draft.epoch, errored.epoch)
            assertEquals("", errored.validatedPlaybook?.title)
            assertEquals(emptyList<String>(), errored.validatedPlaybook?.intentHints)
        }
    }

    // ------------------------------------ OPT-DRAFT-01: controlled draft + epoch

    /**
     * OPT-DRAFT-01: the editor is a controlled component and the ViewModel
     * draft is the single source of the editing input.  Field-by-field
     * updates — the shape of the editor's per-keystroke callbacks — all
     * land in the draft, which is what a recreated activity (rotation)
     * re-reads with the typed content intact; the open event's epoch pins
     * through every copy, and nothing persists along the way.
     */
    @Test
    fun perFieldDraftUpdatesAllLiveInTheViewModelDraft() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val opened = requireNotNull(viewModel.editingScenario.value)
            assertTrue(opened.epoch > 0)

            var playbook = opened.playbook
            playbook = playbook.copy(title = "RTP stream check")
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(intentHints = listOf("rtp quality", "jitter"))
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(protocols = listOf("rtp"))
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(initialTools = listOf("get_capture_overview"))
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(requiredFields = listOf("frame.number"))
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(
                checks = listOf(
                    AgentPlaybookCheck(
                        "check-1",
                        "Read the jitter statistics",
                        listOf("get_statistics")
                    )
                )
            )
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(successPath = listOf("Report the jitter spread"))
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(
                failureBranches = listOf(
                    AgentPlaybookFailureBranch(
                        "A query fails",
                        emptyList(),
                        "State the missing coverage."
                    )
                )
            )
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(
                requiredLimitations = listOf("Conclusions require tool evidence.")
            )
            viewModel.setDraftPlaybook(playbook)
            playbook = playbook.copy(outputSections = listOf("summary", "limitations"))
            viewModel.setDraftPlaybook(playbook)

            // A recreated editor collects the flow afresh: the ViewModel
            // holds every field the user typed.
            val typed = requireNotNull(viewModel.editingScenario.value)
            assertNotEquals(opened, typed)
            assertEquals(playbook, typed.playbook)
            assertEquals("RTP stream check", typed.playbook.title)
            assertEquals(listOf("rtp quality", "jitter"), typed.playbook.intentHints)
            assertEquals(listOf("rtp"), typed.playbook.protocols)
            assertEquals(listOf("get_capture_overview"), typed.playbook.initialTools)
            assertEquals(listOf("frame.number"), typed.playbook.requiredFields)
            assertEquals("Read the jitter statistics", typed.playbook.checks.single().description)
            assertEquals(listOf("Report the jitter spread"), typed.playbook.successPath)
            assertEquals("State the missing coverage.", typed.playbook.failureBranches.single().limitation)
            assertEquals(
                listOf("Conclusions require tool evidence."),
                typed.playbook.requiredLimitations
            )
            assertEquals(listOf("summary", "limitations"), typed.playbook.outputSections)
            // Editing is the same editor session: the open event's epoch
            // survives every copy, and no save has run, so the validation
            // side of the draft stays empty and nothing reached the disk.
            assertEquals(opened.epoch, typed.epoch)
            assertTrue(typed.validationErrors.isEmpty())
            assertNull(typed.validatedPlaybook)
            assertTrue(userScenarios.load().isEmpty())
        }
    }

    /**
     * OPT-DRAFT-01: with a controlled draft every keystroke replaces the
     * draft object, so the save write-back must key on the epoch, not on
     * reference identity — a rejection arriving after the user kept typing
     * while the IO ran still lands, keeps the live content, and only freezes
     * the submitted snapshot for the per-field error comparison.
     */
    @Test
    fun aRejectionLandsAfterTheDraftWasEditedWhileTheSaveWasInFlight() = runBlocking {
        harness().use { harness ->
            val store = LatchingUserScenarioStore()
            store.outcome = mapOf(
                "title" to ScenarioValidationError(ScenarioValidationCodes.STRING_BLANK)
            )
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(store),
                userScenarios = store
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val opened = requireNotNull(viewModel.editingScenario.value)
            viewModel.setDraftPlaybook(filledScenarioDraft(opened.playbook, title = ""))
            viewModel.saveScenario()
            assertTrue(store.awaitSaveEntered())

            // The controlled editor keeps reporting while the IO runs: the
            // open draft is a new object by the time the rejection arrives,
            // which is exactly what the old `=== draft` guard would have
            // dropped on the floor.
            viewModel.setDraftPlaybook(
                requireNotNull(viewModel.editingScenario.value).playbook.copy(
                    title = "Edited while saving"
                )
            )
            store.releaseSave()
            viewModel.awaitScenarioValidationErrors()

            val errored = requireNotNull(viewModel.editingScenario.value)
            assertEquals(opened.epoch, errored.epoch)
            assertEquals(
                ScenarioValidationError(ScenarioValidationCodes.STRING_BLANK),
                errored.validationErrors["title"]
            )
            assertEquals("Edited while saving", errored.playbook.title)
            assertEquals("", errored.validatedPlaybook?.title)
            assertEquals(0, viewModel.scenarioSaveCompleted.value)
        }
    }

    /**
     * OPT-DRAFT-01: the epoch guard keeps the pre-existing cancellation
     * semantics — a rejection from a save still in flight when the editor
     * was cancelled must not resurrect it.
     */
    @Test
    fun aStaleRejectionDoesNotResurrectADismissedEditor() = runBlocking {
        harness().use { harness ->
            val store = LatchingUserScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(store),
                userScenarios = store
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val opened = requireNotNull(viewModel.editingScenario.value)
            viewModel.setDraftPlaybook(filledScenarioDraft(opened.playbook, title = ""))
            viewModel.saveScenario()
            assertTrue(store.awaitSaveEntered())

            viewModel.dismissEditingScenario()
            store.outcome = mapOf(
                "title" to ScenarioValidationError(ScenarioValidationCodes.STRING_BLANK)
            )
            store.releaseSave()
            delay(SETTLE_MILLIS)

            assertNull(viewModel.editingScenario.value)
            assertEquals(0, viewModel.scenarioSaveCompleted.value)
        }
    }

    /**
     * OPT-DRAFT-01: dismissing and reopening the editor (or opening any
     * other draft) mints a new epoch, so an old save's rejection can never
     * bleed into the fresh editor session.
     */
    @Test
    fun aStaleRejectionNeverTouchesAReopenedDraft() = runBlocking {
        harness().use { harness ->
            val store = LatchingUserScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(store),
                userScenarios = store
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val first = requireNotNull(viewModel.editingScenario.value)
            viewModel.setDraftPlaybook(filledScenarioDraft(first.playbook, title = ""))
            viewModel.saveScenario()
            assertTrue(store.awaitSaveEntered())

            // Cancel, then open a different scenario: a brand-new editor
            // session with a strictly newer epoch.
            viewModel.dismissEditingScenario()
            viewModel.startEditScenario(userScenario("user-rtp-check"))
            val reopened = requireNotNull(viewModel.editingScenario.value)
            assertTrue(reopened.epoch > first.epoch)

            store.outcome = mapOf(
                "title" to ScenarioValidationError(ScenarioValidationCodes.STRING_BLANK)
            )
            store.releaseSave()
            delay(SETTLE_MILLIS)

            val stillOpen = requireNotNull(viewModel.editingScenario.value)
            assertEquals(reopened.epoch, stillOpen.epoch)
            assertTrue(stillOpen.validationErrors.isEmpty())
            assertNull(stillOpen.validatedPlaybook)
            assertEquals("user-rtp-check", stillOpen.playbook.id)
        }
    }

    /** OPT-DRAFT-01: a late editor callback with no open draft is inert. */
    @Test
    fun updatingTheDraftWithoutAnOpenEditorChangesNothing() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            assertNull(viewModel.editingScenario.value)
            viewModel.updateDraft { draft -> draft.copy(playbook = draft.playbook.copy(title = "nowhere")) }
            assertNull(viewModel.editingScenario.value)
            assertTrue(userScenarios.load().isEmpty())
        }
    }

    // ------------------------------------ SRE-EDITOR-06: save-completed signal

    /**
     * SRE-EDITOR-06: only a successful save bumps the save-completed counter.
     * The UI reads the counter to raise the "Scenario saved" notice, so a
     * field rejection or a failed write must leave it alone — both keep the
     * editor open and report through the draft's errors or a transient error.
     */
    @Test
    fun aSuccessfulSaveBumpsTheScenarioSaveCompletedCounter() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            assertEquals(0, viewModel.scenarioSaveCompleted.value)
            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val draft = requireNotNull(viewModel.editingScenario.value)

            viewModel.setDraftPlaybook(
                filledScenarioDraft(draft.playbook, title = "My RTP Check")
            )
            viewModel.saveScenario()
            viewModel.awaitEditingScenario(open = false)
            viewModel.awaitPlaybooksCount(2)
            viewModel.awaitScenarioSaveCompleted(1)

            // A second successful save keeps the counter monotonically rising.
            viewModel.startEditScenario(
                viewModel.playbooks.value.single { it.id == "user-my-rtp-check" }
            )
            viewModel.awaitEditingScenario(open = true)
            viewModel.setDraftPlaybook(
                requireNotNull(viewModel.editingScenario.value).playbook.copy(
                    title = "My RTP check, renamed"
                )
            )
            viewModel.saveScenario()
            viewModel.awaitEditingScenario(open = false)
            viewModel.awaitScenarioSaveCompleted(2)
        }
    }

    /**
     * OPT-SAVE-01: five Save taps — the first parked inside the store's IO
     * window by the latch so the other four really do arrive "in flight" —
     * complete exactly one store save and bump the save-completed counter
     * (the "Scenario saved" notice) exactly once.  Without the in-flight
     * guard every tap would run its own complete save: on a real store the
     * version would jump five times for one edit.  The in-flight flag itself
     * is asserted while the latch holds the window open, and is released
     * once the save settles.
     */
    @Test
    fun fiveRapidSaveTapsWhileOneIsInFlightCompleteExactlyOneStoreSave() = runBlocking {
        harness().use { harness ->
            val store = LatchingUserScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(store),
                userScenarios = store
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            viewModel.setDraftPlaybook(
                filledScenarioDraft(
                    requireNotNull(viewModel.editingScenario.value).playbook,
                    title = "My RTP Check"
                )
            )

            viewModel.saveScenario()
            assertTrue(store.awaitSaveEntered())
            assertTrue(viewModel.savingScenario.value)
            // Four more taps land while the first save is still parked in the
            // IO window — the same burst a rapid clicker produces.
            viewModel.saveScenario()
            viewModel.saveScenario()
            viewModel.saveScenario()
            viewModel.saveScenario()

            store.releaseSave()
            viewModel.awaitEditingScenario(open = false)
            viewModel.awaitScenarioSaveCompleted(1)
            // The flag clears only after the whole save flow — reload
            // included — has finished.
            withTimeout(AWAIT_TIMEOUT_MILLIS) {
                while (viewModel.savingScenario.value) delay(POLL_MILLIS)
            }

            assertEquals(1, store.saveCalls.get())
            delay(SETTLE_MILLIS)
            assertEquals(1, viewModel.scenarioSaveCompleted.value)
            assertFalse(viewModel.savingScenario.value)

            // A later save starts normally: the refusal lasted only for the
            // in-flight window, it is not a one-way latch.  (The latch store
            // loads nothing, so this reopens the new-scenario path rather
            // than looking the saved chip up in the merged list.)
            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            viewModel.setDraftPlaybook(
                filledScenarioDraft(
                    requireNotNull(viewModel.editingScenario.value).playbook,
                    title = "A second scenario"
                )
            )
            viewModel.saveScenario()
            viewModel.awaitEditingScenario(open = false)
            viewModel.awaitScenarioSaveCompleted(2)
            assertEquals(2, store.saveCalls.get())
        }
    }

    @Test
    fun aFieldRejectedSaveDoesNotBumpTheScenarioSaveCompletedCounter() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val draft = requireNotNull(viewModel.editingScenario.value)

            viewModel.setDraftPlaybook(
                draft.playbook.copy(title = "", intentHints = emptyList())
            )
            viewModel.saveScenario()
            viewModel.awaitScenarioValidationErrors()

            assertEquals(0, viewModel.scenarioSaveCompleted.value)
        }
    }

    @Test
    fun aFailedScenarioWriteDoesNotBumpTheScenarioSaveCompletedCounter() = runBlocking {
        harness().use { harness ->
            val throwingStore = ThrowingUserScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(throwingStore),
                userScenarios = throwingStore
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val draft = requireNotNull(viewModel.editingScenario.value)

            viewModel.setDraftPlaybook(
                draft.playbook.copy(
                    title = "My RTP Check",
                    intentHints = listOf("rtp check")
                )
            )
            viewModel.saveScenario()
            // The write failure surfaces as a transient error and the editor
            // stays open — and the success counter stays untouched.
            withTimeout(AWAIT_TIMEOUT_MILLIS) {
                while (viewModel.uiState.value.transientError == null) delay(POLL_MILLIS)
            }
            assertNotNull(viewModel.editingScenario.value)
            assertEquals(0, viewModel.scenarioSaveCompleted.value)
        }
    }

    @Test
    fun editingAUserScenarioKeepsItsIdAndBumpsTheVersionWhileBuiltInsStayLocked() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            assertEquals(
                emptyMap<String, ScenarioValidationError>(),
                userScenarios.save(userScenario("user-rtp-check"))
            )
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            viewModel.startEditScenario(
                viewModel.playbooks.value.single { it.id == "user-rtp-check" }
            )
            viewModel.awaitEditingScenario(open = true)
            val draft = requireNotNull(viewModel.editingScenario.value)
            assertFalse(draft.isNew)
            assertEquals("user-rtp-check", draft.playbook.id)
            assertTrue(draft.validationErrors.isEmpty())

            viewModel.setDraftPlaybook(draft.playbook.copy(title = "RTP check, renamed"))
            viewModel.saveScenario()
            viewModel.awaitEditingScenario(open = false)

            // The id is immutable once saved; only the version moves.
            val edited = userScenarios.load().single()
            assertEquals("user-rtp-check", edited.id)
            assertEquals("RTP check, renamed", edited.title)
            assertEquals(2, edited.version)

            // The preset lock: a built-in scenario never opens the editor.
            viewModel.startEditScenario(
                viewModel.playbooks.value.single { it.id == "general-capture-health" }
            )
            assertNull(viewModel.editingScenario.value)
        }
    }

    @Test
    fun dismissingTheEditorDiscardsTheDraftWithoutPersistingIt() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            // OPT-DRAFT-01: content typed into the ViewModel draft is still
            // discarded on cancel — the draft stays memory-only, and a
            // scenario with real input on a store that would persist it
            // would prove the point, but cancelling must write nothing.
            val opened = requireNotNull(viewModel.editingScenario.value)
            viewModel.setDraftPlaybook(
                filledScenarioDraft(opened.playbook, title = "Half-typed check")
            )
            viewModel.dismissEditingScenario()

            assertNull(viewModel.editingScenario.value)
            assertTrue(userScenarios.load().isEmpty())
        }
    }

    /** Without the user layer every management event is a no-op. */
    @Test
    fun withoutTheUserLayerTheScenarioEventsDoNothing() = runBlocking {
        harness().use { harness ->
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                playbookStoreWithExtraScenario()
            )

            viewModel.startNewScenario()
            assertNull(viewModel.editingScenario.value)

            viewModel.deleteScenario("user-rtp-check")
            assertTrue(viewModel.deletingScenarioIds.value.isEmpty())

            viewModel.copyScenario("general-capture-health")
            viewModel.dismissEditingScenario()
            assertNull(viewModel.editingScenario.value)
        }
    }

    // --------------------------------------- SRE-EDITOR-01: editor draft modes

    /**
     * SRE-EDITOR-01: "View details" is origin-blind — both a built-in preset
     * and a user scenario open the editor read-only, and dismissing such a
     * draft clears it without persisting anything.
     */
    @Test
    fun viewingAScenarioOpensItReadOnlyForBothOrigins() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            assertEquals(
                emptyMap<String, ScenarioValidationError>(),
                userScenarios.save(userScenario("user-rtp-check"))
            )
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )
            viewModel.awaitPlaybooksCount(2)

            viewModel.startViewScenario(
                viewModel.playbooks.value.single { it.id == "general-capture-health" }
            )
            val builtInDraft = requireNotNull(viewModel.editingScenario.value)
            assertTrue(builtInDraft.readOnly)
            assertFalse(builtInDraft.isNew)
            assertTrue(builtInDraft.validationErrors.isEmpty())
            assertEquals("general-capture-health", builtInDraft.playbook.id)
            assertEquals(ScenarioOrigin.BuiltIn, builtInDraft.playbook.origin)

            // A second view event replaces the draft in the single slot.
            viewModel.startViewScenario(
                viewModel.playbooks.value.single { it.id == "user-rtp-check" }
            )
            val userDraft = requireNotNull(viewModel.editingScenario.value)
            assertTrue(userDraft.readOnly)
            assertFalse(userDraft.isNew)
            assertEquals("user-rtp-check", userDraft.playbook.id)

            viewModel.dismissEditingScenario()
            assertNull(viewModel.editingScenario.value)
            // Viewing never reaches the user layer.
            assertEquals(
                listOf("user-rtp-check"),
                userScenarios.load().map { it.id }
            )
        }
    }

    /** SRE-EDITOR-01: only the view flow mints read-only drafts; editing stays editable. */
    @Test
    fun newAndEditDraftsStayEditable() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            assertEquals(
                emptyMap<String, ScenarioValidationError>(),
                userScenarios.save(userScenario("user-rtp-check"))
            )
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )
            viewModel.awaitPlaybooksCount(2)

            viewModel.startNewScenario()
            val newDraft = requireNotNull(viewModel.editingScenario.value)
            assertFalse(newDraft.readOnly)
            assertTrue(newDraft.isNew)

            viewModel.startEditScenario(
                viewModel.playbooks.value.single { it.id == "user-rtp-check" }
            )
            val editDraft = requireNotNull(viewModel.editingScenario.value)
            assertFalse(editDraft.readOnly)
            assertFalse(editDraft.isNew)
        }
    }

    // ------------------------------------------------- SRE-RUN-04: gap pins

    /**
     * SRE-RUN-04: a save must not only add the new chip but keep the
     * sortedByUsage order intact — recorded usage counts descend first and the
     * zero-count scenarios keep the reloaded base order, with the freshly
     * saved one landing at its own base position instead of the front.
     */
    @Test
    fun savingANewScenarioKeepsTheUsageSortedOrderOfTheChips() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            assertEquals(
                emptyMap<String, ScenarioValidationError>(),
                userScenarios.save(userScenario("user-alpha-check", title = "Alpha check"))
            )
            assertEquals(
                emptyMap<String, ScenarioValidationError>(),
                userScenarios.save(userScenario("user-bravo-check", title = "Bravo check"))
            )
            val usage = InMemoryPlaybookUsageStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                usageStore = usage,
                userScenarios = userScenarios
            )
            // Base order before any usage: built-ins first, then the user
            // layer in its file order.
            assertEquals(
                listOf("general-capture-health", "user-alpha-check", "user-bravo-check"),
                viewModel.playbooks.value.map { it.id }
            )

            // A non-trivial usage map: two picks of bravo, one of general.
            viewModel.recordPlaybookUsage("user-bravo-check")
            viewModel.recordPlaybookUsage("user-bravo-check")
            viewModel.recordPlaybookUsage("general-capture-health")
            assertEquals(
                listOf("user-bravo-check", "general-capture-health", "user-alpha-check"),
                viewModel.playbooks.value.map { it.id }
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val draft = requireNotNull(viewModel.editingScenario.value)
            viewModel.setDraftPlaybook(
                filledScenarioDraft(
                    draft.playbook,
                    title = "My Charlie Check",
                    intentHints = listOf("charlie check")
                )
            )
            viewModel.saveScenario()
            viewModel.awaitEditingScenario(open = false)
            viewModel.awaitPlaybooksCount(4)
            val savedId = userScenarios.load().single { it.title == "My Charlie Check" }.id

            // The full order is what sortedByUsage derives from the reloaded
            // base sequence: bravo (2) then general (1) ride their counts, and
            // among the zero-count scenarios the pre-existing alpha keeps its
            // base position ahead of the freshly appended charlie — the save
            // neither resets nor erodes the usage order.
            assertEquals(
                listOf(
                    "user-bravo-check",
                    "general-capture-health",
                    "user-alpha-check",
                    savedId
                ),
                viewModel.playbooks.value.map { it.id }
            )
        }
    }

    /**
     * SRE-RUN-04: the SRE-RUN pipeline pinned end to end — a scenario saved
     * through the editor joins the chips after the reload, and a chip
     * submission with its minted id runs exactly that playbook at the
     * store-assigned first version, even though the question text matches
     * none of its intent hints.
     */
    @Test
    fun aSavedScenarioRunsUnderItsOwnIdWhenSubmittedExplicitly() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            viewModel.startNewScenario()
            viewModel.awaitEditingScenario(open = true)
            val draft = requireNotNull(viewModel.editingScenario.value)
            // The hints deliberately match nothing in the question below, so
            // only the explicit id can select this scenario.
            viewModel.setDraftPlaybook(
                filledScenarioDraft(
                    draft.playbook,
                    title = "Signal hunt",
                    intentHints = listOf("signal hunt")
                )
            )
            viewModel.saveScenario()
            viewModel.awaitEditingScenario(open = false)
            viewModel.awaitPlaybooksCount(2)
            val savedId = userScenarios.load().single().id
            assertTrue(viewModel.playbooks.value.any { it.id == savedId })

            viewModel.submitQuestion(
                "Why is this capture slow?",
                playbookId = savedId
            )
            viewModel.awaitIdle()

            // First save of the id: the store assigned version 1.
            assertEquals(
                "$savedId@1",
                viewModel.lastRunRecord.value?.playbookVersion
            )
            assertEquals(AgentRunPhase.Completed, viewModel.uiState.value.phase)
        }
    }

    /**
     * SRE-RUN-04: a stale chip id — the playbook was just deleted — degrades
     * to the question-text match instead of failing the run, the ViewModel
     * side of the store's MERGE-04 explicit-id fallback.
     */
    @Test
    fun submittingADeletedScenarioIdFallsBackToTextMatching() = runBlocking {
        harness().use { harness ->
            val userScenarios = userScenarioStore()
            assertEquals(
                emptyMap<String, ScenarioValidationError>(),
                userScenarios.save(userScenario("user-rtp-check"))
            )
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarios),
                userScenarios = userScenarios
            )

            viewModel.deleteScenario("user-rtp-check")
            viewModel.awaitNoScenarioDeleteInFlight()
            assertFalse(
                viewModel.playbooks.value.any { it.id == "user-rtp-check" }
            )

            viewModel.submitQuestion(
                "Why is this capture slow?",
                playbookId = "user-rtp-check"
            )
            viewModel.awaitIdle()

            // The deleted id is a miss in the merged list, so the run falls
            // through to the general playbook the text match would pick.
            assertEquals(
                "general-capture-health@1",
                viewModel.lastRunRecord.value?.playbookVersion
            )
        }
    }

    // ------------------------------------------ OPT-QNT-01: quarantine notice

    /**
     * The store can quarantine a corrupt user scenario file while the
     * Application object graph is still being built — before any ViewModel
     * exists — and it reports the same reason code once per unreadable file.
     * The buffered channel must deliver that first event to the ViewModel and
     * the consumer-side dedupe must surface one notice per distinct code.
     */
    @Test
    fun quarantineEventsBufferedBeforeTheViewModelStartsAnnounceOncePerCode() = runBlocking {
        val quarantine = ScenarioQuarantineEventChannel()
        quarantine.publish(ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED))
        quarantine.publish(ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED))
        harness().use { harness ->
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarioStore()),
                quarantineEvents = quarantine
            )

            viewModel.awaitQuarantineCodes(1)
            assertEquals(
                listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED),
                viewModel.scenarioQuarantineCodes.value
            )
        }
    }

    /**
     * A quarantine observed after startup appends only when the reason code is
     * new: a repeat of an already-announced code (another unreadable file with
     * the same failure, a re-published event) never raises a second notice,
     * while a distinct code does.
     */
    @Test
    fun aQuarantineOnlyAnnouncesDistinctReasonCodes() = runBlocking {
        val quarantine = ScenarioQuarantineEventChannel()
        harness().use { harness ->
            val viewModel = playbookViewModel(
                harness, repeatedOverviewScript(),
                mergedPlaybookStore(userScenarioStore()),
                quarantineEvents = quarantine
            )
            assertEquals(emptyList<String>(), viewModel.scenarioQuarantineCodes.value)

            quarantine.publish(ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED))
            viewModel.awaitQuarantineCodes(1)

            quarantine.publish(ScenarioQuarantineEvent(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED))
            quarantine.publish(ScenarioQuarantineEvent("user_scenario_other"))
            viewModel.awaitQuarantineCodes(2)
            // A settle window: the duplicate must not sneak in late.
            delay(SETTLE_MILLIS)
            assertEquals(
                listOf(UserScenarioPlaybookStore.QUARANTINE_DECODE_FAILED, "user_scenario_other"),
                viewModel.scenarioQuarantineCodes.value
            )
        }
    }

    /** Wait until [expected] quarantine notices are visible to the UI. */
    private suspend fun ProtocolAgentViewModel.awaitQuarantineCodes(expected: Int) {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (scenarioQuarantineCodes.value.size < expected) delay(POLL_MILLIS)
        }
    }

    // ------------------------------------------------------------------ setup

    /** Wait until no run is in flight, so a terminal state can be asserted. */
    private suspend fun ProtocolAgentViewModel.awaitIdle() {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (uiState.value.isRunning) delay(POLL_MILLIS)
        }
    }

    private suspend fun ProtocolAgentViewModel.awaitRunning() {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (!uiState.value.isRunning) delay(POLL_MILLIS)
        }
    }

    /**
     * Wait until the saved-sessions list publishes [expected] entries.
     *
     * Refreshes run asynchronously on [Dispatchers.IO] since the delete-path
     * jank fix; tests that read [ProtocolAgentViewModel.savedSessions] right
     * after an event must await this publication instead of assuming it.
     */
    private suspend fun ProtocolAgentViewModel.awaitSavedSessions(expected: Int) {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (savedSessions.value.size != expected) delay(POLL_MILLIS)
        }
    }

    /**
     * Wait until every in-flight saved-session delete has settled.
     *
     * The delete path updates the history list and usage card optimistically
     * now, so their awaits no longer imply the delete itself has finished;
     * assertions on the store must wait on the marker instead.
     */
    private suspend fun ProtocolAgentViewModel.awaitNoDeleteInFlight() {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (deletingSavedSessionIds.value.isNotEmpty()) delay(POLL_MILLIS)
        }
    }

    /** Wait until the local-data usage card reflects [minSessions] sessions. */
    private suspend fun ProtocolAgentViewModel.awaitLocalDataUsage(minSessions: Int) {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (localDataUsage.value.savedSessionCount < minSessions) delay(POLL_MILLIS)
        }
    }

    /**
     * Wait until the interrupted-job banner reflects a checkpoint for
     * [conversationId], or clears when [conversationId] is null.
     *
     * Refreshes run asynchronously on [Dispatchers.IO] since the restore-page
     * freeze fix; tests that read [ProtocolAgentViewModel.interruptedJob]
     * right after an event must await this publication instead of assuming
     * it.
     */
    private suspend fun ProtocolAgentViewModel.awaitInterruptedJob(conversationId: String?) {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (interruptedJob.value?.conversationId != conversationId) delay(POLL_MILLIS)
        }
    }

    /**
     * Wait until the merged chip list publishes [expected] entries.
     *
     * The scenario management events reload the merged list asynchronously on
     * Dispatchers.IO, so a test that reads [ProtocolAgentViewModel.playbooks]
     * right after an event must await this publication instead of assuming it.
     */
    private suspend fun ProtocolAgentViewModel.awaitPlaybooksCount(expected: Int) {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (playbooks.value.size != expected) delay(POLL_MILLIS)
        }
    }

    /** Wait until the scenario editor is open ([open]) or closed. */
    private suspend fun ProtocolAgentViewModel.awaitEditingScenario(open: Boolean) {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while ((editingScenario.value != null) != open) delay(POLL_MILLIS)
        }
    }

    /**
     * Wait until every in-flight scenario delete has settled.
     *
     * The delete clears the marker only after its IO window (delete, usage
     * clear, reload) completed, so an empty marker also implies the reload ran.
     */
    private suspend fun ProtocolAgentViewModel.awaitNoScenarioDeleteInFlight() {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (deletingScenarioIds.value.isNotEmpty()) delay(POLL_MILLIS)
        }
    }

    /** Wait until the open draft carries its first field rejections. */
    private suspend fun ProtocolAgentViewModel.awaitScenarioValidationErrors() {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (editingScenario.value?.validationErrors?.isEmpty() != false) delay(POLL_MILLIS)
        }
    }

    /**
     * OPT-DRAFT-01: replace the draft's playbook through the same controlled
     * path the editor uses — a field change goes through
     * [ProtocolAgentViewModel.updateDraft], and the save request itself
     * then carries no payload.
     */
    private fun ProtocolAgentViewModel.setDraftPlaybook(playbook: AgentPlaybook) {
        updateDraft { draft -> draft.copy(playbook = playbook) }
    }

    /**
     * Wait until the save-completed counter has reached [count].
     *
     * The counter bumps inside the async save flow, so a test that reads
     * [ProtocolAgentViewModel.scenarioSaveCompleted] right after a save event
     * must await this publication instead of assuming it.
     */
    private suspend fun ProtocolAgentViewModel.awaitScenarioSaveCompleted(count: Int) {
        withTimeout(AWAIT_TIMEOUT_MILLIS) {
            while (scenarioSaveCompleted.value < count) delay(POLL_MILLIS)
        }
    }

    private suspend fun harness() = AgentToolTestHarness.create(frameCount = 120) {
        expert = ExpertInfoSummary(
            errorPackets = 0,
            warningPackets = 1,
            items = listOf(
                ExpertInfoItem(
                    frameNumber = 7L,
                    label = "This frame is a (suspected) retransmission",
                    filter = "tcp.analysis.retransmission",
                    severity = "warning",
                    start = 0,
                    length = 0
                )
            ),
            totalItems = 1
        )
    }

    private fun viewModel(
        harness: AgentToolTestHarness,
        scriptId: String
    ): ProtocolAgentViewModel = viewModel(harness, MockModelScriptLibrary.require(scriptId))

    private fun viewModel(
        harness: AgentToolTestHarness,
        script: MockModelScript,
        policy: AgentPolicy = AgentPolicy(),
        sessionStore: com.example.layanalyzer.data.AgentSessionStore? = null,
        settingsStore: AgentSettingsStore = settings(),
        jobStore: com.example.layanalyzer.data.AnalysisJobStore? = null,
        externalScope: CoroutineScope = CoroutineScope(Dispatchers.Unconfined)
    ): ProtocolAgentViewModel = ProtocolAgentViewModel(
        agent = agent(harness, script, policy),
        coordinator = harness.coordinator,
        settings = settingsStore,
        externalScope = externalScope,
        sessionStore = sessionStore,
        jobStore = jobStore
    )

    private fun agent(
        harness: AgentToolTestHarness,
        script: MockModelScript,
        policy: AgentPolicy = AgentPolicy()
    ) = agent(harness, MockAiModelClient(script), policy)

    private fun agent(
        harness: AgentToolTestHarness,
        modelClient: MockAiModelClient,
        policy: AgentPolicy = AgentPolicy(),
        toolCache: AgentToolCache? = null
    ) = ProtocolAnalysisAgent(
        repository = harness.repository,
        registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
        modelClient = modelClient,
        policy = policy,
        toolCache = toolCache
    )

    /**
     * SRE-RUN-02: the agent and the ViewModel must share one selector instance,
     * mirroring the production wiring where the ViewModel fills its chip list
     * from the same store the agent resolves ids against.
     */
    private fun playbookViewModel(
        harness: AgentToolTestHarness,
        script: MockModelScript,
        playbookStore: AgentPlaybookStore,
        settingsStore: AgentSettingsStore = settings(),
        sessionStore: com.example.layanalyzer.data.AgentSessionStore? = null,
        jobStore: com.example.layanalyzer.data.AnalysisJobStore? = null,
        usageStore: PlaybookUsageStore? = null,
        userScenarios: UserScenarioStore? = null,
        quarantineEvents: ScenarioQuarantineEventChannel? = null,
        externalScope: CoroutineScope = CoroutineScope(Dispatchers.Unconfined)
    ): ProtocolAgentViewModel = ProtocolAgentViewModel(
        agent = ProtocolAnalysisAgent(
            repository = harness.repository,
            registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
            modelClient = MockAiModelClient(script),
            playbookStore = playbookStore
        ),
        coordinator = harness.coordinator,
        settings = settingsStore,
        externalScope = externalScope,
        sessionStore = sessionStore,
        jobStore = jobStore,
        playbookStore = playbookStore,
        playbookUsageStore = usageStore,
        userScenarios = userScenarios,
        quarantineEvents = quarantineEvents
    )

    /**
     * The minimal general playbook plus one extra scenario whose intent hint
     * ("retransmission deep dive") none of these tests' questions contain, so
     * only the explicit-id path can reach it.
     */
    private fun playbookStoreWithExtraScenario(
        extraPlaybookId: String = "tcp-retransmission-deep-dive",
        extraVersion: Int = 3
    ): AgentPlaybookStore {
        val general = JSONObject(TestScenarioPackages.MINIMAL_PLAYBOOKS)
            .getJSONArray("playbooks")
            .getJSONObject(0)
        val json = JSONObject()
            .put("schemaVersion", AgentPlaybookStore.SCHEMA_VERSION)
            .put(
                "playbooks",
                JSONArray()
                    .put(general)
                    .put(
                        JSONObject(general.toString())
                            .put("id", extraPlaybookId)
                            .put("version", extraVersion)
                            .put("intentHints", JSONArray().put("retransmission deep dive"))
                    )
            )
        return AgentPlaybookStore(
            assetLoader = { json.toString() },
            availableTools = TestScenarioPackages.availableTools
        )
    }

    /**
     * SRE-RUN-03: a filesDir-backed user scenario layer over a fresh
     * directory.  The built-in id set mirrors the minimal package the merged
     * store decodes, so a user scenario can never take over a built-in id.
     */
    private fun userScenarioStore(): UserScenarioPlaybookStore = UserScenarioPlaybookStore(
        directory = temporaryFolder.newFolder("user-scenarios"),
        availableTools = TestScenarioPackages.availableTools,
        builtInPlaybookIds = { setOf("general-capture-health") }
    )

    /**
     * SRE-EDITOR-06: a user layer whose save always fails on the disk write,
     * exercising the `onFailure` branch of the save flow (the transient error)
     * without a real filesystem fault.
     */
    private class ThrowingUserScenarioStore : UserScenarioStore {
        override fun load(): List<AgentPlaybook> = emptyList()

        override fun save(scenario: AgentPlaybook): Map<String, ScenarioValidationError> =
            throw java.io.IOException("simulated scenario write failure")

        override fun delete(playbookId: String) = Unit

        override fun generateScenarioId(title: String): String = "user-throwing"

        override fun generateCopyId(sourceId: String): String = "user-throwing-copy"
    }

    /**
     * OPT-DRAFT-01: a user layer whose save parks inside the IO window
     * until the test releases it, making "the draft was edited (or
     * dismissed, or replaced) while a save was in flight" deterministic
     * instead of a dispatcher race.  A test that forgot to release waits
     * out its own timeout here rather than hanging the suite, and the save
     * then answers with whatever [outcome] it was given.  [saveCalls] counts
     * the save requests that actually reached the store, which is what
     * OPT-SAVE-01's repeat-tap refusal is pinned on.
     */
    private class LatchingUserScenarioStore : UserScenarioStore {
        private val entered = java.util.concurrent.CountDownLatch(1)
        private val release = java.util.concurrent.CountDownLatch(1)

        /** Save requests that entered the store's IO window. */
        val saveCalls = java.util.concurrent.atomic.AtomicInteger()

        /** The field-rejection map the pending save answers with. */
        @Volatile
        var outcome: Map<String, ScenarioValidationError> = emptyMap()

        /** True once a save call is parked in the IO window. */
        fun awaitSaveEntered(): Boolean =
            entered.await(AWAIT_TIMEOUT_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS)

        fun releaseSave() {
            release.countDown()
        }

        override fun load(): List<AgentPlaybook> = emptyList()

        override fun save(scenario: AgentPlaybook): Map<String, ScenarioValidationError> {
            saveCalls.incrementAndGet()
            entered.countDown()
            release.await(AWAIT_TIMEOUT_MILLIS, java.util.concurrent.TimeUnit.MILLISECONDS)
            return outcome
        }

        override fun delete(playbookId: String) = Unit

        override fun generateScenarioId(title: String): String = "user-latching"

        override fun generateCopyId(sourceId: String): String = "user-latching-copy"
    }

    /**
     * The merged store must be built with the *same* [UserScenarioStore]
     * instance the ViewModel receives, mirroring the production wiring: only
     * then does [AgentPlaybookStore.reload] fold the user layer back into the
     * chips.
     */
    private fun mergedPlaybookStore(
        userScenarios: UserScenarioStore,
        overlay: ScenarioRulesOverlay = ScenarioRulesOverlay.EMPTY
    ): AgentPlaybookStore = AgentPlaybookStore(
        assetLoader = { TestScenarioPackages.MINIMAL_PLAYBOOKS },
        availableTools = TestScenarioPackages.availableTools,
        overlay = overlay,
        userScenarios = userScenarios
    )

    /** A caller-side user scenario; version and origin are store-assigned on save. */
    private fun userScenario(id: String, title: String = "RTP check"): AgentPlaybook =
        AgentPlaybook(
            id = id,
            version = 1,
            title = title,
            intentHints = listOf("rtp check"),
            protocols = listOf("any"),
            initialTools = listOf("get_capture_overview"),
            requiredFields = emptyList(),
            checks = listOf(
                AgentPlaybookCheck("health", "Read the overview", listOf("get_statistics"))
            ),
            successPath = listOf("Read the overview first"),
            failureBranches = listOf(
                AgentPlaybookFailureBranch("A query fails", emptyList(), "State the incomplete coverage.")
            ),
            requiredLimitations = listOf("Conclusions require tool evidence."),
            outputSections = listOf("summary", "limitations"),
            origin = ScenarioOrigin.User
        )

    /** Fills the blank draft from [ProtocolAgentViewModel.startNewScenario] with valid content. */
    private fun filledScenarioDraft(
        blank: AgentPlaybook,
        title: String = "My RTP Check",
        intentHints: List<String> = listOf("rtp check")
    ): AgentPlaybook = blank.copy(
        title = title,
        intentHints = intentHints,
        protocols = listOf("any"),
        initialTools = listOf("get_capture_overview"),
        checks = listOf(
            AgentPlaybookCheck("health", "Read the overview", listOf("get_statistics"))
        ),
        successPath = listOf("Read the overview first"),
        failureBranches = listOf(
            AgentPlaybookFailureBranch("A query fails", emptyList(), "State the incomplete coverage.")
        ),
        requiredLimitations = listOf("Conclusions require tool evidence."),
        outputSections = listOf("summary", "limitations")
    )

    private fun settings() = object : AgentSettingsStore {
        override val modelScriptId = MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS
        override val privacyMode = AgentPrivacyMode.RedactedMetadata
    }

    private class TestSettingsStore(initial: AgentSettings) : MutableAgentSettingsStore {
        private val state = MutableStateFlow(initial)

        override val settings: AgentSettings
            get() = state.value
        override val settingsFlow: StateFlow<AgentSettings> = state

        override fun update(settings: AgentSettings) {
            state.value = settings
        }
    }

    /**
     * The overview trajectory, with per-pass tool call ids so a retry or a
     * follow-up has a second set of turns to consume from the same client.
     */
    private fun overviewTurn() =
        MockScriptedResponse.final(
            AgentReport(
                summary = "TCP dominates the capture and Expert Info reports retransmissions.",
                completeness = AgentReportCompleteness.Partial
            )
        )

    private fun repeatedOverviewScript(): MockModelScript = MockModelScript(
        id = "repeated-overview",
        description = "The overview trajectory, twice.",
        responses = listOf(overviewTurn(), overviewTurn())
    )

    /**
     * The overview trajectory with a per-turn delay, so a run has an observable
     * in-flight window even without a session store's IO dispatch to yield on.
     */
    private fun observedOverviewScript(): MockModelScript = MockModelScript(
        id = "observed-overview",
        description = "The overview trajectory, twice, with a visible running window.",
        responses = listOf(
            overviewTurn().copy(delayMillis = 50L),
            overviewTurn().copy(delayMillis = 50L)
        )
    )

    private companion object {
        const val AWAIT_TIMEOUT_MILLIS = 10_000L
        const val POLL_MILLIS = 5L
        /** A quiet window after which an unpublished event is really absent. */
        const val SETTLE_MILLIS = 100L
    }
}

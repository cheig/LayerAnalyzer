package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.AiModelCapabilities
import com.example.layanalyzer.ai.client.AiModelClient
import com.example.layanalyzer.ai.client.AiModelErrors
import com.example.layanalyzer.ai.client.AgentHttpRequest
import com.example.layanalyzer.ai.client.AgentHttpResponse
import com.example.layanalyzer.ai.client.AgentHttpTransport
import com.example.layanalyzer.ai.client.AgentTruncationTarget
import com.example.layanalyzer.ai.client.AnthropicModelClient
import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScript
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.ai.client.MockScriptedResponse
import com.example.layanalyzer.ai.client.StreamChunk
import com.example.layanalyzer.ai.audit.AgentDiagnosticsRecorder
import com.example.layanalyzer.ai.audit.AgentDiagnosticsSession
import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.AgentPlaybookCheck
import com.example.layanalyzer.ai.privacy.AgentPrivacyPolicy
import com.example.layanalyzer.ai.tools.AgentTool
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.ai.tools.AgentToolRunner
import com.example.layanalyzer.ai.tools.CaptureOverviewTool
import com.example.layanalyzer.ai.tools.DeclareAnalysisPlanTool
import com.example.layanalyzer.ai.tools.SubmitReportTool
import com.example.layanalyzer.ai.tools.DelegateInvestigationTool
import com.example.layanalyzer.ai.tools.ExpertInfoTool
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.ai.tools.FakeTool
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentAnalysisMode
import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentToolActivityStatus
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentTokenUsage
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeoutOrNull
import java.nio.charset.StandardCharsets
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import org.json.JSONObject
import org.junit.Assert.assertArrayEquals
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
class AgentLoopTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    // ------------------------------------------------------------ happy path

    @Test
    fun multipleToolCallsProduceAValidatedReport() = runBlocking {
        AgentToolTestHarness.create(frameCount = 100).use { harness ->
            val client = scriptedClient(
                MockScriptedResponse.tool("call-1", "get_capture_overview"),
                MockScriptedResponse.tool("call-2", "get_expert_info"),
                MockScriptedResponse.final(
                    AgentReport(
                        summary = "Two steps ran.",
                        findings = listOf(
                            finding(
                                evidence = listOf(
                                    AgentEvidence(
                                        type = AgentEvidenceType.Statistic,
                                        observation = "TCP dominates.",
                                        sourceToolCallId = "call-1",
                                        metric = "protocolHierarchy",
                                        observedValue = "tcp"
                                    ),
                                    AgentEvidence(
                                        type = AgentEvidenceType.ExpertInfo,
                                        observation = "Frame 7 reports a retransmission.",
                                        sourceToolCallId = "call-2",
                                        frameNumber = 7L
                                    )
                                ),
                                confidence = AgentConfidence.High
                            )
                        ),
                        completeness = AgentReportCompleteness.Complete
                    )
                )
            )
            val recorder = PhaseRecorder()

            val outcome = loop(harness, client, listener = recorder).run(
                question = "What is wrong with this capture?",
                snapshot = harness.snapshot,
                privacyMode = AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentReportCompleteness.Complete, completed.report.completeness)
            assertEquals(1, completed.report.findings.size)
            assertEquals(2, completed.report.findings.single().evidence.size)
            assertEquals(AgentConfidence.High, completed.report.findings.single().confidence)
            assertEquals(listOf("call-1", "call-2"), completed.report.provenance.toolCallIds)

            // Preparing → WaitingForModel → RunningTool → WaitingForModel → ...
            assertEquals(AgentRunPhase.Preparing, recorder.phases.first())
            assertEquals(AgentRunPhase.Completed, recorder.phases.last())
            assertTrue(recorder.phases.contains(AgentRunPhase.ValidatingReport))
        }
    }

    @Test
    fun toolResultsEnterTheConversationMarkedUntrusted() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        calls = listOf(AgentToolCall("call-1", "get_capture_overview")),
                        reasoningContent = "Inspect the capture overview before answering."
                    ),
                    AgentModelResponse.Final(report = AgentReport(summary = "Done."), reportJson = null, json = null)
                )
            )

            loop(harness, client).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val lastRequest = client.requests.last()
            val toolMessage = lastRequest.messages.last { it.role == AgentModelMessageRole.Tool }
            val assistantMessage = lastRequest.messages.last {
                it.role == AgentModelMessageRole.Assistant
            }
            assertTrue(toolMessage.untrustedCaptureData)
            assertEquals("call-1", toolMessage.toolCallId)
            assertEquals("call-1", assistantMessage.toolCalls.single().toolCallId)
            assertEquals(
                "Inspect the capture overview before answering.",
                assistantMessage.reasoningContent
            )
            assertTrue(lastRequest.messages.indexOf(assistantMessage) < lastRequest.messages.indexOf(toolMessage))
            // The system prompt is never marked untrusted.
            val system = lastRequest.messages.first { it.role == AgentModelMessageRole.System }
            assertFalse(system.untrustedCaptureData)
        }
    }

    @Test
    fun multipleThinkingToolTurnsRetainEachAssistantReasoningMessage() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        calls = listOf(AgentToolCall("call-1", "get_capture_overview")),
                        assistantContent = "Checking the overview.",
                        reasoningContent = "Inspect the overview first."
                    ),
                    AgentModelResponse.ToolCalls(
                        calls = listOf(AgentToolCall("call-2", "get_expert_info")),
                        assistantContent = "Checking expert information.",
                        reasoningContent = "Now inspect warnings."
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Done."))
                )
            )

            loop(harness, client).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertEquals(3, client.requests.size)
            val secondRequestAssistants = client.requests[1].messages.filter {
                it.role == AgentModelMessageRole.Assistant && it.toolCalls.isNotEmpty()
            }
            assertEquals(
                listOf("Inspect the overview first."),
                secondRequestAssistants.map { it.reasoningContent }
            )
            val thirdRequestAssistants = client.requests[2].messages.filter {
                it.role == AgentModelMessageRole.Assistant && it.toolCalls.isNotEmpty()
            }
            assertEquals(
                listOf("Inspect the overview first.", "Now inspect warnings."),
                thirdRequestAssistants.map { it.reasoningContent }
            )
            assertEquals(
                listOf("Checking the overview.", "Checking expert information."),
                thirdRequestAssistants.map { it.content }
            )
        }
    }

    @Test
    fun firstModelRequestContainsHostBootstrapOverviewAsAValidToolTurn() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    mapOf(
                        "frameCount" to 10,
                        "expertErrorCount" to 0,
                        "expertWarningCount" to 0
                    ),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val client = RecordingClient(
                listOf(AgentModelResponse.Final(AgentReport(summary = "Bootstrap received.")))
            )
            val agentLoop = loop(
                harness = harness,
                client = client,
                tools = listOf(overview),
                bootstrapEnabled = true
            )

            val outcome = agentLoop.run(
                "Analyze this capture",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            assertEquals(1, overview.executionCount)
            assertEquals(listOf("host-bootstrap-overview-1"), outcome.report.provenance.toolCallIds)
            assertEquals("1", agentLoop.diagnosticAttributes()["bootstrapToolCount"])
            assertEquals("0", agentLoop.diagnosticAttributes()["modelRequestsBeforeFirstEvidence"])
            assertEquals("1", agentLoop.diagnosticAttributes()["modelRequestCount"])

            val request = client.requests.single()
            val assistant = request.messages.single {
                it.role == AgentModelMessageRole.Assistant &&
                    it.toolCalls.singleOrNull()?.toolCallId == "host-bootstrap-overview-1"
            }
            val tool = request.messages.single {
                it.role == AgentModelMessageRole.Tool &&
                    it.toolCallId == "host-bootstrap-overview-1"
            }
            assertTrue(request.messages.indexOf(assistant) < request.messages.indexOf(tool))
            assertEquals("", assistant.reasoningContent)
            assertTrue(tool.untrustedCaptureData)
            val system = request.messages.first { it.role == AgentModelMessageRole.System }
            assertFalse(system.untrustedCaptureData)
            assertFalse(system.content.contains("\"expertErrorCount\""))
        }
    }

    @Test
    fun bootstrapAddsOnlyTwentyErrorWarningExpertEntriesWhenCountsAreNonZero() = runBlocking {
        AgentToolTestHarness.create {
            expert = ExpertInfoSummary(
                errorPackets = 15,
                warningPackets = 12,
                items = buildList {
                    repeat(12) { index ->
                        add(expertItem(index + 1L, "warning"))
                    }
                    repeat(15) { index ->
                        add(expertItem(index + 101L, "error"))
                    }
                    add(expertItem(999L, "note"))
                },
                totalItems = 28,
                truncated = false,
                analyzed = true
            )
        }.use { harness ->
            val client = RecordingClient(
                listOf(AgentModelResponse.Final(AgentReport(summary = "Bootstrap received.")))
            )
            val agentLoop = loop(
                harness = harness,
                client = client,
                tools = listOf(
                    CaptureOverviewTool(Dispatchers.Unconfined),
                    ExpertInfoTool(Dispatchers.Unconfined)
                ),
                bootstrapEnabled = true
            )

            agentLoop.run(
                "Analyze this capture",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val request = client.requests.single()
            val expertAssistant = request.messages.single {
                it.role == AgentModelMessageRole.Assistant &&
                    it.toolCalls.singleOrNull()?.toolCallId == "host-bootstrap-expert-2"
            }
            assertEquals(
                mapOf(
                    "severities" to listOf("error", "warning"),
                    "offset" to 0,
                    "limit" to 20
                ),
                expertAssistant.toolCalls.single().arguments
            )
            val expertResult = request.messages.single {
                it.role == AgentModelMessageRole.Tool &&
                    it.toolCallId == "host-bootstrap-expert-2"
            }.toolResult
            @Suppress("UNCHECKED_CAST")
            val items = requireNotNull(expertResult?.data?.get("items")) as List<Map<String, Any?>>
            assertEquals(20, items.size)
            assertEquals(15, items.take(15).count { it["severity"] == "error" })
            assertTrue(items.none { it["severity"] == "note" || it["severity"] == "chat" })
            assertEquals("2", agentLoop.diagnosticAttributes()["bootstrapToolCount"])
        }
    }

    @Test
    fun textOnlyModelReusesTheSameBootstrapWithoutRunningOverviewTwice() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    mapOf("expertErrorCount" to 0, "expertWarningCount" to 0),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val client = RecordingClient(
                responses = listOf(AgentModelResponse.Final(AgentReport(summary = "One summary."))),
                capabilities = AiModelCapabilities.TEXT_ONLY
            )

            val agentLoop = loop(
                harness,
                client,
                tools = listOf(overview),
                bootstrapEnabled = true
            )
            agentLoop.run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(AgentAnalysisMode.SingleSummary, agentLoop.analysisMode)
            assertEquals(1, overview.executionCount)
            assertEquals(1, client.requests.size)
            assertTrue(client.requests.single().toolDefinitions.isEmpty())
            assertTrue(client.requests.single().messages.any {
                it.toolCallId == "host-bootstrap-overview-1" && it.untrustedCaptureData
            })
        }
    }

    @Test
    fun bootstrapSessionFailureStopsBeforeAnyModelRequest() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.failure(
                    AgentError(
                        code = AgentErrorCode.NO_CAPTURE,
                        userMessage = "No capture is open.",
                        retryable = false
                    )
                )
            }
            val client = RecordingClient(
                listOf(AgentModelResponse.Final(AgentReport(summary = "Must not run.")))
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(overview),
                bootstrapEnabled = true
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(
                AgentStopReason.SessionChanged,
                (outcome as AgentRunOutcome.Completed).stopReason
            )
            assertTrue(client.requests.isEmpty())
        }
    }

    @Test
    fun theModelIsGivenOnlyWhitelistedToolDefinitions() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(AgentModelResponse.Final(report = AgentReport(summary = "Done."), reportJson = null, json = null))
            )

            loop(harness, client).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val names = client.requests.single().toolDefinitions.map { it.name }
            assertEquals(listOf("get_capture_overview", "get_expert_info"), names.sorted())
        }
    }

    // ---------------------------------------------------------- failure paths

    @Test
    fun unknownToolIsReportedToTheModelWithoutEndingTheRun() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "read_file"))),
                    AgentModelResponse.Final(
                        report = AgentReport(summary = "Recovered."),
                        reportJson = null,
                        json = null
                    )
                )
            )

            val agentLoop = loop(harness, client)
            val outcome = agentLoop.run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals("(rejected)", agentLoop.activities().single().toolName)
            // The model got an error back and was allowed to continue.
            val toolMessage = client.requests.last().messages.last { it.role == AgentModelMessageRole.Tool }
            assertEquals(
                AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                toolMessage.toolResult?.error?.code
            )
        }
    }

    @Test
    fun duplicateToolCallIdIsRejectedAndTheToolRunsOnlyOnce() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("ok" to true), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.Final(report = AgentReport(summary = "Done."), reportJson = null, json = null)
                )
            )

            loop(harness, client, tools = listOf(tool)).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertEquals(1, tool.executionCount)
            val replayResult = client.requests.last().messages.last { it.role == AgentModelMessageRole.Tool }
            assertEquals(
                AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                replayResult.toolResult?.error?.code
            )
            assertEquals(
                "duplicate_tool_call_id",
                replayResult.toolResult?.error?.details?.get("reason")
            )
        }
    }

    @Test
    fun repeatedDuplicateToolCallIdsConsumeTheInvalidArgumentBudget() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("ok" to true), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.Final(report = AgentReport(summary = "Should not be reached."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxInvalidArgumentRetries = 1)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.InvalidArguments, completed.stopReason)
            // Three investigation requests plus one no-tools forced summary.
            assertEquals("duplicate budget was bypassed", 4, client.requests.size)
            assertEquals(1, tool.executionCount)
        }
    }

    @Test
    fun toolTimeoutDoesNotEndTheRun() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val slow = FakeTool("get_capture_overview", timeoutMillis = 30L) { _, _ ->
                delay(10_000L)
                error("unreachable")
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.Final(
                        report = AgentReport(summary = "Reported despite the timeout."),
                        reportJson = null,
                        json = null
                    )
                )
            )

            val outcome = loop(harness, client, tools = listOf(slow)).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            // The failed read did not end the run; the model's own final report
            // did, so the report counts as Complete.  The failed step is still
            // named in the limitations.
            assertEquals(AgentReportCompleteness.Complete, completed.report.completeness)
            assertTrue(completed.report.limitations.any { it.contains("did not complete") })
        }
    }

    @Test
    fun modelFailureEndsTheRunWithAPartialReport() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.Failure(AiModelErrors.unavailable("upstream_down"))
                )
            )

            val outcome = loop(
                harness,
                client,
                policy = AgentPolicy(maxModelRetries = 0)
            ).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val failed = outcome as AgentRunOutcome.FailedWithPartialReport
            assertEquals(AgentErrorCode.MODEL_UNAVAILABLE, failed.error.code)
            val report = requireNotNull(failed.report) { "a partial report is expected" }
            assertEquals(AgentReportCompleteness.Incomplete, report.completeness)
            // The confirmed step is still reported to the user.
            assertTrue(report.limitations.any { it.contains("get_capture_overview") })
        }
    }

    @Test
    fun successfulForcedSummaryAfterInvestigationFailurePreservesFailureSemantics() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val messages = mutableListOf<AgentConversationItem>()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Failure(AiModelErrors.unavailable("provider_error")),
                    AgentModelResponse.Final(
                        AgentReport(summary = "Recovered only from confirmed evidence.")
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                policy = AgentPolicy(maxModelRetries = 0),
                listener = object : AgentRunListener {
                    override fun onMessage(item: AgentConversationItem) {
                        messages += item
                    }
                }
            ).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val failed = outcome as AgentRunOutcome.FailedWithPartialReport
            assertEquals(AgentErrorCode.MODEL_UNAVAILABLE, failed.error.code)
            assertEquals("Recovered only from confirmed evidence.", failed.report.summary)
            assertEquals(AgentReportCompleteness.Incomplete, failed.report.completeness)
            assertEquals(3, client.requests.size)
            assertTrue(client.requests.last().toolDefinitions.isEmpty())
            // The run still has a report to show, so the failure belongs to the
            // report (its partial-result warning) and raises no conversation
            // bubble beside the conclusion the run did produce.
            assertTrue(messages.none { it.role == AgentConversationRole.Error })
        }
    }

    @Test
    fun retryableModelFailureRetriesTheSameTurnWithoutRepeatingTools() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Failure(
                        AiModelErrors.unavailable(
                            "upstream_down",
                            mapOf("remoteCode" to "UPSTREAM_503", "remoteMessage" to "temporary outage")
                        )
                    ),
                    AgentModelResponse.Failure(AiModelErrors.unavailable("upstream_down")),
                    AgentModelResponse.Final(AgentReport(summary = "Recovered after retry."))
                )
            )
            val delays = mutableListOf<Long>()
            val visibleMessages = mutableListOf<AgentConversationItem>()

            val outcome = loop(
                harness,
                client,
                tools = listOf(overview),
                policy = AgentPolicy(maxModelRetries = 2),
                listener = object : AgentRunListener {
                    override fun onMessage(item: AgentConversationItem) {
                        visibleMessages += item
                    }
                },
                suspendDelay = { delays += it }
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            // Two transient failures, two configured retries: the run recovers
            // on the last one instead of degrading to a partial report.
            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Recovered after retry.", completed.report.summary)
            assertEquals(1, overview.executionCount)
            assertEquals(4, client.requests.size)
            val retryLayouts = client.requests.drop(1).map(::messageCacheBreakpointLayout)
            assertEquals(1, retryLayouts.distinct().size)
            assertEquals(listOf("Tool:call-1"), retryLayouts.first())
            // Both configured retries stay available to this one logical request.
            assertEquals(listOf(500L, 1_000L), delays)
            // A retry this run recovers from is a step-level event and raises no
            // conversation bubble. The failed attempts stay auditable as model
            // interactions on the step list, so the transcript must not carry
            // "analysis failed" beside the report the same run produced.
            assertTrue(visibleMessages.none { it.role == AgentConversationRole.Error })
            assertTrue(visibleMessages.none { it.content.contains("Retrying (") })
            assertTrue(visibleMessages.none { it.content.contains("UPSTREAM_503") })
        }
    }

    @Test
    fun outputTruncationRetryExpandsTheGenerationBudget() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val planTool = DeclareAnalysisPlanTool()
            val overview = defaultTools().first()
            val client = RecordingClient(
                responses = listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "plan-1",
                                DeclareAnalysisPlanTool.NAME,
                                mapOf(
                                    "goal" to "Inspect the trace",
                                    "steps" to listOf(
                                        mapOf(
                                            "tool" to "get_capture_overview",
                                            "purpose" to "Establish the baseline"
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    AgentModelResponse.Failure(
                        AiModelErrors.outputTruncated(AgentTruncationTarget.ToolCalls)
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Recovered with more output room."))
                ),
                capabilities = AiModelCapabilities(
                    maxContextTokens = 128_000,
                    maxOutputTokens = 8_192
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, overview)
            ).run("Inspect this trace", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals(3, client.requests.size)
            assertEquals(AgentOutputBudget.TOOL_SELECTION_TOKENS, client.requests[1].maxOutputTokens)
            assertEquals(AgentOutputBudget.FINAL_REPORT_TOKENS, client.requests[2].maxOutputTokens)
        }
    }

    @Test
    fun anthropicLogicalPrefixIsByteStableThroughTheLatestSharedBreakpoint() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val schema = mapOf(
                "type" to "object",
                "additionalProperties" to false,
                "properties" to mapOf(
                    "turn" to mapOf("type" to "integer")
                ),
                "required" to listOf("turn")
            )
            val overview = FakeTool("get_capture_overview", schema = schema) { arguments, context ->
                context.success(
                    mapOf("turn" to arguments["turn"]),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val client = RecordingClient(
                responses = (1..4).map { turn ->
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                toolCallId = "prefix-call-$turn",
                                toolName = "get_capture_overview",
                                arguments = mapOf("turn" to turn)
                            )
                        )
                    )
                } + AgentModelResponse.Final(AgentReport(summary = "Prefix stable."))
            )

            val outcome = loop(harness, client, tools = listOf(overview)).run(
                "Build a stable multi-turn prefix",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals(5, client.requests.size)
            // Request 2 contains two completed turns; request 3 appends a third.
            // The previous newest breakpoint (prefix-call-2) remains shared.
            val previous = anthropicLogicalBlocks(client.requests[2])
            val next = anthropicLogicalBlocks(client.requests[3])
            val previousBreakpoint = previous.indexOfLast { block ->
                block.cacheBreakpoint && block.toolCallId == "prefix-call-2"
            }
            val nextBreakpoint = next.indexOfLast { block ->
                block.cacheBreakpoint && block.toolCallId == "prefix-call-2"
            }

            assertTrue(previousBreakpoint >= 0)
            assertTrue(nextBreakpoint >= 0)
            assertTrue(previous.count { it.cacheBreakpoint } <= 4)
            assertTrue(next.count { it.cacheBreakpoint } <= 4)
            assertArrayEquals(
                logicalPrefixBytes(previous.take(previousBreakpoint + 1)),
                logicalPrefixBytes(next.take(nextBreakpoint + 1))
            )
        }
    }

    @Test
    fun transientFailureUsesAllFiveConfiguredRetries() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    )
                ) + List(6) {
                    AgentModelResponse.Failure(AiModelErrors.unavailable("upstream_down"))
                } + AgentModelResponse.Final(AgentReport(summary = "Recovered in finalization."))
            )
            val delays = mutableListOf<Long>()

            val outcome = loop(
                harness,
                client,
                tools = listOf(overview),
                policy = AgentPolicy(maxModelRetries = 5),
                suspendDelay = { delays += it }
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertTrue(outcome is AgentRunOutcome.FailedWithPartialReport)
            assertEquals(listOf(500L, 1_000L, 2_000L, 4_000L, 4_000L), delays)
            // Tool turn, original failed request, five retries, then finalization.
            assertEquals(8, client.requests.size)
            assertEquals(1, overview.executionCount)
        }
    }

    @Test
    fun theForcedSummaryItselfIsNotRetried() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    )
                ) + List(6) {
                    AgentModelResponse.Failure(AiModelErrors.unavailable("upstream_down"))
                }
            )
            val delays = mutableListOf<Long>()

            val outcome = loop(
                harness,
                client,
                policy = AgentPolicy(maxModelRetries = 2),
                suspendDelay = { delays += it }
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertTrue(outcome is AgentRunOutcome.FailedWithPartialReport)
            // The first turn selects a tool; the second investigation request
            // then spends its original attempt plus the two configured retries.
            // The forced summary that follows is the bounded recovery hand-off
            // itself, so it gets exactly one attempt — retrying it would spend
            // the same escape hatch twice, and its own failure already degrades
            // to a synthesized report.
            assertEquals(5, client.requests.size)
            assertEquals(listOf(500L, 1_000L), delays)
            assertEquals(
                listOf(false, false, false, false, true),
                client.requests.map { it.toolDefinitions.isEmpty() }
            )
        }
    }

    @Test
    fun retriesDoNotConsumeTheWholeRunLogicalRequestBudget() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Failure(AiModelErrors.unavailable("temporary_failure")),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Third logical request ran."))
                )
            )

            val outcome = loop(
                harness,
                client,
                policy = AgentPolicy(maxModelRequests = 3, maxModelRetries = 2),
                suspendDelay = {}
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Third logical request ran.", completed.report.summary)
            assertEquals(4, client.requests.size)
            assertTrue(client.requests.last().toolDefinitions.isNotEmpty())
        }
    }

    @Test
    fun repeatedInvalidArgumentsEndTheRunBeforeTheTurnCeiling() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            // extraArg is not in the tool schema, so every call is rejected as
            // INVALID_TOOL_ARGUMENTS without ever consuming a step.
            val client = RecordingClient(
                (1..12).map { index ->
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-$index", "get_capture_overview", mapOf("extraArg" to 1)))
                    )
                }
            )

            val outcome = loop(
                harness,
                client,
                policy = AgentPolicy(maxInvalidArgumentRetries = 2)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val failed = outcome as AgentRunOutcome.FailedWithPartialReport
            assertEquals(AgentErrorCode.INTERNAL_ERROR, failed.error.code)
            assertEquals(AgentReportCompleteness.Incomplete, failed.report.completeness)
            // Two retries are allowed; the third consecutive rejection stops it.
            assertEquals(4, client.requests.size)
            assertTrue(failed.report.recommendedNextSteps.isNotEmpty())
        }
    }

    @Test
    fun aValidCallResetsTheInvalidArgumentRetryBudget() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("bad-1", "get_capture_overview", mapOf("extraArg" to 1)))
                    ),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("good-1", "get_capture_overview"))),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("bad-2", "get_capture_overview", mapOf("extraArg" to 1)))
                    ),
                    AgentModelResponse.Final(report = AgentReport(summary = "Recovered."))
                )
            )

            val outcome = loop(
                harness,
                client,
                policy = AgentPolicy(maxInvalidArgumentRetries = 1)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            // The two rejections are not consecutive, so the run completes.
            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals(AgentStopReason.ModelFinal, (outcome as AgentRunOutcome.Completed).stopReason)
        }
    }

    @Test
    fun unparseableFinalReportFallsBackToConfirmedFacts() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.Final(report = null, reportJson = "not json at all", json = null)
                )
            )

            val outcome = loop(harness, client).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentReportCompleteness.Incomplete, completed.report.completeness)
            assertTrue(completed.report.findings.isNotEmpty())
        }
    }

    @Test
    fun aTextOnlyModelUsesTheBoundedSingleSummaryFallback() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                responses = listOf(AgentModelResponse.Final(AgentReport(summary = "One overview summary."))),
                capabilities = AiModelCapabilities.TEXT_ONLY
            )

            val loop = loop(harness, client)
            val outcome = loop.run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentAnalysisMode.SingleSummary, loop.analysisMode)
            assertEquals(1, client.requests.size)
            assertTrue(client.requests.single().toolDefinitions.isEmpty())
            assertEquals(AgentReportCompleteness.Partial, completed.report.completeness)
        }
    }

    @Test
    fun generalPlaybookDoesNotAllowPacketDetailBeforeOverview() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 10), returnedCount = 1L, totalCount = 1L)
            }
            val detail = FakeTool("get_packet_fields") { _, context ->
                context.success(mapOf("frames" to listOf(1L)), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("detail-first", "get_packet_fields"))),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("overview", "get_capture_overview"))),
                    AgentModelResponse.Final(AgentReport(summary = "Overview completed."))
                )
            )

            val outcome = loop(harness, client, tools = listOf(overview, detail)).run(
                "Analyze the main problem.",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals(0, detail.executionCount)
            assertEquals(1, overview.executionCount)
            assertEquals(3, client.requests.size)
        }
    }

    // ----------------------------------------------------------- host budgets

    @Test
    fun stepLimitEndsTheRunWithAnIncompleteReport() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("ok" to true), returnedCount = 1L, totalCount = 1L)
            }
            // The model never returns a Final; only the host's ceiling stops it.
            // The script must outlast the ceiling, or an exhausted script — not
            // the budget — is what would end the run.
            val client = MockAiModelClient(
                MockModelScript(
                    id = "endless",
                    responses = List(40) { index ->
                        MockScriptedResponse.tool("call-$index", "get_capture_overview")
                    }
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 4, maxConsecutiveIdenticalToolCalls = 20)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val failed = outcome as AgentRunOutcome.FailedWithPartialReport
            assertEquals(AgentErrorCode.INTERNAL_ERROR, failed.error.code)
            assertEquals(AgentReportCompleteness.Incomplete, failed.report.completeness)
            assertEquals(4, tool.executionCount)
            assertTrue(failed.report.limitations.any { it.contains("step limit") })
            assertTrue(failed.report.recommendedNextSteps.isNotEmpty())
            assertTrue(client.observedRequests.last().toolDefinitions.isEmpty())
        }
    }

    /**
     * OPT-VAL-01-01 rule 1 on the real loop: a step-budget stop that leaves a
     * declared plan step unexecuted must say so in the finished report —
     * naming the tool and the purpose the model itself promised.
     */
    @Test
    fun stepBudgetStopSurfacesUnexecutedDeclaredPlanStepAsLimitation() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            // Same shape as stepLimitEndsTheRunWithAnIncompleteReport, with a
            // two-step plan up front and only step 1 ever executed.
            val client = MockAiModelClient(
                MockModelScript(
                    id = "plan-cut-short",
                    responses = listOf(
                        MockScriptedResponse.tool(
                            toolCallId = "plan-1",
                            toolName = DeclareAnalysisPlanTool.NAME,
                            arguments = mapOf(
                                "goal" to "Inspect the trace",
                                "steps" to listOf(
                                    mapOf(
                                        "tool" to "get_capture_overview",
                                        "purpose" to "establish the baseline"
                                    ),
                                    mapOf(
                                        "tool" to "get_expert_info",
                                        "purpose" to "check TCP retransmissions"
                                    )
                                )
                            )
                        )
                    ) + List(39) { index ->
                        MockScriptedResponse.tool("call-$index", "get_capture_overview")
                    }
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool()) + defaultTools(),
                policy = AgentPolicy(maxSteps = 4, maxConsecutiveIdenticalToolCalls = 20)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val report = when (outcome) {
                is AgentRunOutcome.Completed -> outcome.report
                is AgentRunOutcome.FailedWithPartialReport -> outcome.report
                else -> error("expected a report-bearing outcome, got $outcome")
            }
            assertTrue(
                report.limitations.any {
                    it == "Plan step \"get_expert_info\" (check TCP retransmissions) was not " +
                        "executed before the run stopped (MaxStepsReached)."
                }
            )
            // The executed step is not a gap and must not be reported as one.
            assertTrue(report.limitations.none { it.contains("Plan step \"get_capture_overview\"") })
        }
    }

    @Test
    fun defaultBudgetAllowsAWorkflowLongerThanTwelveToolCalls() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("ok" to true), returnedCount = 1L, totalCount = 1L)
            }
            val client = MockAiModelClient(
                MockModelScript(
                    id = "long-workflow",
                    responses = List(16) { index ->
                        MockScriptedResponse.tool("call-$index", "get_capture_overview")
                    } + MockScriptedResponse.final(
                        AgentReport(summary = "The longer workflow completed.")
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxConsecutiveIdenticalToolCalls = 20)
            ).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(16, tool.executionCount)
            assertEquals(AgentStopReason.ModelFinal, completed.stopReason)
            assertEquals("The longer workflow completed.", completed.report.summary)
        }
    }

    @Test
    fun longRunRetainsOnlyTheLatestFiveCompleteToolTurns() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    mapOf("noise" to "x".repeat(10_000)),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val responses = List(8) { index ->
                AgentModelResponse.ToolCalls(
                    listOf(AgentToolCall("call-$index", "get_capture_overview"))
                )
            } + AgentModelResponse.Final(AgentReport(summary = "Done."))
            // A 2_000-token ceiling clears the ~641-token initial system prompt
            // (a smaller window makes the planner return partial on turn 1 and
            // the run stops at ContextLimit before any model call), yet the
            // ~2_600-token payload turns trip the compaction threshold after a
            // few calls.  The default client's huge window would never compact
            // this short run at all.
            val client = RecordingClient(
                responses,
                capabilities = AiModelCapabilities(maxContextTokens = 2_000, maxOutputTokens = 100)
            )

            val outcome = loop(
                harness = harness,
                client = client,
                tools = listOf(tool),
                policy = AgentPolicy(maxConsecutiveIdenticalToolCalls = 20)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertTrue(outcome is AgentRunOutcome.Completed)
            // The final summary turn drops tool definitions, so look at the
            // last *tool-calling* request to see the compacted transcript.
            val transcriptRequests = client.requests.filter { it.toolDefinitions.isNotEmpty() }
            assertTrue(transcriptRequests.isNotEmpty())
            val finalMessages = transcriptRequests.last().messages
            assertEquals(1, finalMessages.count { it.role == AgentModelMessageRole.System })
            // Re-compaction is append-only: each firing adds one immutable
            // discovery note beside the earlier ones rather than rewriting them,
            // so this short run accumulates more than one note.
            val discoveryNotes = finalMessages.filter {
                it.content.startsWith(AgentConversationCompactor.DISCOVERY_NOTE_HEADER)
            }
            discoveryNotes.forEach { discoveryNote ->
                assertEquals(AgentModelMessageRole.User, discoveryNote.role)
                assertTrue(discoveryNote.untrustedCaptureData)
            }
            // The oldest evidence has been folded into a note.
            if (discoveryNotes.isNotEmpty()) {
                assertTrue(discoveryNotes.any { it.content.contains("call-0") })
            }
            assertTrue(
                finalMessages.any {
                    it.role == AgentModelMessageRole.User && it.content == "Question?"
                }
            )
            val retainedTurns = finalMessages.count { it.role == AgentModelMessageRole.Tool }
            // The live transcript never holds more than the five retained
            // tool turns; the wire shows three at the end because the latest
            // compaction had not yet been mirrored into it (see below).
            assertTrue(retainedTurns in 1..5)
            assertTrue(finalMessages.size <= 17)
            finalMessages.filter { it.role == AgentModelMessageRole.Tool }.forEach { toolMessage ->
                assertTrue(
                    finalMessages.any { message ->
                        message.role == AgentModelMessageRole.Assistant &&
                            message.toolCalls.any { it.toolCallId == toolMessage.toolCallId }
                    }
                )
            }
            // The LIVE transcript (what the next turn would compact) always
            // retains the latest five complete tool turns; only the wire copy
            // seen by this run's last request trails it.
            assertTrue(tool.executionCount >= 8)
        }
    }

    @Test
    fun contextCompactionIsWrittenBackBeforeTheNextModelTurn() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    data = mapOf("noise" to "x".repeat(20_000)),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val client = RecordingClient(
                responses = listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("large-result", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Done."))
                ),
                capabilities = AiModelCapabilities(
                    maxContextTokens = 4_000,
                    maxOutputTokens = 200
                )
            )

            val outcome = loop(harness, client, tools = listOf(tool)).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            val compacted = client.requests.last().messages.single {
                it.toolCallId == "large-result"
            }
            assertEquals("Earlier tool result compacted by host.", compacted.content)
            assertFalse(compacted.toolResult?.data.toString().contains("noise"))
        }
    }

    @Test
    fun exhaustedStepBudgetGetsOneToolFreeFinalSummary() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    data = mapOf("frameCount" to 1),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val client = MockAiModelClient(
                MockModelScript(
                    id = "budget-summary",
                    responses = List(4) { index ->
                        MockScriptedResponse.tool("call-$index", "get_capture_overview")
                    } + MockScriptedResponse.final(
                        AgentReport(summary = "The collected evidence explains the capture.")
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 4, maxConsecutiveIdenticalToolCalls = 20)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.MaxStepsReached, completed.stopReason)
            assertEquals("The collected evidence explains the capture.", completed.report.summary)
            assertEquals(AgentReportCompleteness.Incomplete, completed.report.completeness)
            assertEquals(4, tool.executionCount)
            assertTrue(client.observedRequests.last().toolDefinitions.isEmpty())
        }
    }

    @Test
    fun cumulativeTokenBudgetGetsOneToolFreeFinalSummary() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        calls = listOf(AgentToolCall("token-call", "get_capture_overview")),
                        usage = AgentTokenUsage(
                            inputTokens = 100,
                            cachedInputTokens = 50,
                            outputTokens = 10
                        )
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Summarized at the cost limit."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(
                    maxSteps = 4,
                    maxCumulativeInputTokens = 55L
                )
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.ContextLimit, completed.stopReason)
            assertEquals("Summarized at the cost limit.", completed.report.summary)
            assertEquals(1, tool.executionCount)
            assertEquals(2, client.requests.size)
            assertTrue(client.requests.last().toolDefinitions.isEmpty())
        }
    }

    @Test
    fun forcedSummaryUsesACompactedContextAfterTheHostStopsTheRun() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_expert_info") { _, context ->
                context.success(
                    data = mapOf(
                        "items" to (1..12).map { frame ->
                            mapOf(
                                "frameNumber" to frame.toLong(),
                                "displayFilter" to "tcp.analysis.retransmission ".repeat(40)
                            )
                        }
                    ),
                    returnedCount = 12L,
                    totalCount = 12L
                )
            }
            val client = RecordingClient(
                responses = listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("evidence", "get_expert_info"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Recovered from the context stop."))
                ),
                capabilities = AiModelCapabilities(
                    maxContextTokens = 3_000,
                    maxOutputTokens = 200
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 1)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.MaxStepsReached, completed.stopReason)
            assertEquals("Recovered from the context stop.", completed.report.summary)
            assertEquals(2, client.requests.size)
            assertTrue(client.requests.last().toolDefinitions.isEmpty())
        }
    }

    @Test
    fun forcedSummaryUsesTheBoundedRecoveryBudgetWhenSupported() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                responses = listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("evidence", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Summarized."))
                ),
                capabilities = AiModelCapabilities(
                    maxContextTokens = 100_000,
                    maxOutputTokens = 100_000
                )
            )

            loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 1)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertEquals(AgentOutputBudget.FORCED_SUMMARY_TOKENS, client.requests.last().maxOutputTokens)
            assertTrue(client.requests.last().toolDefinitions.isEmpty())
        }
    }

    @Test
    fun truncatedForcedSummaryReturnsTheSynthesizedEvidenceAsAPartialFailure() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("evidence", "get_capture_overview"))
                    ),
                    AgentModelResponse.Failure(AiModelErrors.outputTruncated())
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 1)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(listOf("evidence"), completed.report.provenance.toolCallIds)
            assertEquals(AgentReportCompleteness.Incomplete, completed.report.completeness)
            assertTrue(completed.report.limitations.contains("forced_summary_unavailable"))
        }
    }

    @Test
    fun malformedForcedSummaryIsRepairedExactlyOnce() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("evidence", "get_capture_overview"))
                    ),
                    AgentModelResponse.Failure(
                        AiModelErrors.malformed("invalid_report_envelope")
                    ),
                    AgentModelResponse.Final(
                        AgentReport(summary = "The repaired report is valid.")
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 1)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("The repaired report is valid.", completed.report.summary)
            assertEquals(3, client.requests.size)
            assertTrue(client.requests[1].toolDefinitions.isEmpty())
            assertTrue(client.requests[2].toolDefinitions.isEmpty())
            assertTrue(
                client.requests[2].messages.last().content.contains(
                    "format repair",
                    ignoreCase = true
                )
            )
        }
    }

    @Test
    fun malformedForcedSummaryAndRepairCompleteWithPreservedPartialReport() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("evidence", "get_capture_overview"))
                    ),
                    AgentModelResponse.Failure(AiModelErrors.malformed("no_json_object")),
                    AgentModelResponse.Failure(AiModelErrors.malformed("invalid_json"))
                )
            )
            val controller = controller(harness, client)

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 1),
                controller = controller
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(3, client.requests.size)
            assertEquals(AgentRunPhase.Completed, controller.phase)
            assertEquals(listOf("evidence"), completed.report.provenance.toolCallIds)
            assertTrue(completed.report.findings.isNotEmpty())
            assertEquals(AgentReportCompleteness.Incomplete, completed.report.completeness)
            assertTrue(completed.report.limitations.contains("forced_summary_unavailable"))
            assertTrue(
                completed.report.limitations.contains(
                    "forced_summary_error=MODEL_RESPONSE_MALFORMED"
                )
            )
        }
    }

    @Test
    fun repeatedToolQueriesTriggerAForcedSummaryInsteadOfBurningTheRun() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = MockAiModelClient(
                MockModelScript(
                    id = "repeated-query",
                    responses = List(3) { index ->
                        MockScriptedResponse.tool("call-$index", "get_capture_overview")
                    } + MockScriptedResponse.final(
                        AgentReport(summary = "The repeated query was safely summarized.")
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 20, maxConsecutiveIdenticalToolCalls = 3)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.RepeatedToolCall, completed.stopReason)
            assertEquals("The repeated query was safely summarized.", completed.report.summary)
            assertEquals(3, tool.executionCount)
            assertTrue(client.observedRequests.last().toolDefinitions.isEmpty())
        }
    }

    @Test
    fun normalizedIdenticalToolArgumentsStillTriggerTheRepeatedQueryGuard() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "call-1",
                                "get_capture_overview",
                                linkedMapOf("filter" to "tcp", "limit" to 10)
                            )
                        )
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "call-2",
                                "get_capture_overview",
                                linkedMapOf("limit" to 10, "filter" to "tcp")
                            )
                        )
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Repeated query summarized."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxConsecutiveIdenticalToolCalls = 2)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.RepeatedToolCall, completed.stopReason)
            assertEquals(2, tool.executionCount)
            assertTrue(client.requests.last().toolDefinitions.isEmpty())
        }
    }

    @Test
    fun modelRequestUsesItsOwnTimeoutAfterTheRunHasBeenOpenForOverTwoMinutes() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(AgentModelResponse.Final(report = AgentReport(summary = "Done."), reportJson = null, json = null))
            )
            var now = 0L
            val policy = AgentPolicy(
                maxSteps = 3,
                maxModelRequestTimeoutMillis = AgentPolicy.DEFAULT_MAX_STEP_TIMEOUT_MILLIS
            )

            loop(harness, client, policy = policy, clock = { now += 121_000L; now }).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val request = client.requests.single()
            assertEquals(policy.maxModelRequestTimeoutMillis, request.timeoutMillis)
            assertNotNull("a response schema is expected", request.responseSchema)
        }
    }

    // ---------------------------------------------------------- cancellation

    @Test
    fun cancellingWhileWaitingForTheModelEndsInCancelledOnce() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val entered = CompletableDeferred<Unit>()
            val client = object : TestClient() {
                override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
                    entered.complete(Unit)
                    awaitCancellation()
                }
            }
            val controller = controller(harness, client)
            val loop = loop(harness, client, controller = controller)

            val job = async(Dispatchers.Default) {
                loop.run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            }
            entered.await()
            controller.cancel()
            job.cancel()

            assertEquals(AgentRunPhase.Cancelled, controller.phase)
            // A second cancel must not move the run out of Cancelled again.
            controller.cancel()
            assertEquals(AgentRunPhase.Cancelled, controller.phase)
        }
    }

    @Test
    fun cancellingWhileAToolRunsPropagatesCancellation() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val entered = CompletableDeferred<Unit>()
            val blocking = FakeTool("get_capture_overview", timeoutMillis = 60_000L) { _, _ ->
                entered.complete(Unit)
                awaitCancellation()
            }
            val client = RecordingClient(
                listOf(AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))))
            )
            val controller = controller(harness, client)
            val loop = loop(harness, client, tools = listOf(blocking), controller = controller)

            val job = async(Dispatchers.Default) {
                loop.run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)
            }
            entered.await()
            job.cancel()

            val failure = runCatching { job.await() }.exceptionOrNull()
            assertTrue(failure is kotlinx.coroutines.CancellationException)
        }
    }

    @Test
    fun cancellationSignalFromTheModelProducesAPartialReport() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(AgentModelResponse.Failure(AiModelErrors.cancelled("req-1")))
            )
            val controller = controller(harness, client)

            val outcome = loop(harness, client, controller = controller).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val failed = outcome as AgentRunOutcome.FailedWithPartialReport
            assertEquals(AgentErrorCode.CANCELLED, failed.error.code)
            assertNotNull(failed.report)
            assertEquals(AgentReportCompleteness.Incomplete, failed.report.completeness)
            assertEquals(AgentRunPhase.FailedWithPartialReport, controller.phase)
        }
    }

    @Test
    fun cancelledForcedSummaryPreservesConfirmedEvidence() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("evidence", "get_capture_overview"))
                    ),
                    AgentModelResponse.Failure(AiModelErrors.cancelled("forced-summary"))
                )
            )
            val controller = controller(harness, client)

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 1),
                controller = controller
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(listOf("evidence"), completed.report.provenance.toolCallIds)
            assertTrue(completed.report.findings.isNotEmpty())
            assertEquals(AgentReportCompleteness.Incomplete, completed.report.completeness)
            assertTrue(completed.report.limitations.contains("forced_summary_unavailable"))
            assertEquals(AgentRunPhase.Completed, controller.phase)
        }
    }

    @Test
    fun modelFinalThatOmitsSuccessfulToolEvidenceGetsHostObservation() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("evidence", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(
                        AgentReport(
                            summary = "No relevant fields were obtained.",
                            findings = emptyList()
                        )
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(tool),
                policy = AgentPolicy(maxSteps = 4)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertTrue(completed.report.findings.any { finding ->
                finding.evidence.any { evidence -> evidence.sourceToolCallId == "evidence" }
            })
            // Host bookkeeping goes to limitations; the model-authored summary
            // shown to the user stays untouched.
            assertTrue(completed.report.limitations.any { it.contains("Host verification retained") })
            assertEquals("No relevant fields were obtained.", completed.report.summary)
        }
    }

    @Test
    fun cancellationCancelsTheModelRequestAndNativeWork() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(emptyList())
            val controller = controller(harness, client)
            val requestId = controller.nextRequestId()

            controller.cancel()

            assertEquals(listOf(requestId), client.cancelledRequestIds)
            assertTrue(controller.isCancelled)
            assertEquals(AgentRunPhase.Cancelled, controller.phase)
        }
    }

    // -------------------------------------------------------- session changes

    @Test
    fun sessionChangeDuringAToolCallPreventsCompletion() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview") { _, context ->
                // The user closes the capture midway through the read.
                harness.coordinator.invalidateSession()
                context.success(mapOf("frameCount" to 10))
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("call-1", "get_capture_overview"))),
                    AgentModelResponse.Final(
                        report = AgentReport(
                            summary = "Should not be reported as complete.",
                            completeness = AgentReportCompleteness.Complete
                        ),
                        reportJson = null,
                        json = null
                    )
                )
            )

            val outcome = loop(harness, client, tools = listOf(tool)).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.SessionChanged, completed.stopReason)
            assertEquals(AgentReportCompleteness.Incomplete, completed.report.completeness)
            // The model never got a second turn after the session died.
            assertEquals(1, client.requests.size)
        }
    }

    // ------------------------------------------------------ advanced loop

    @Test
    fun streamingClientPublishesBoundedUpdatesAndClearsThemAtCompletion() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val updates = mutableListOf<String>()
            val client = object : TestClient(
                capabilities = AiModelCapabilities.PHASE0.copy(streaming = true)
            ) {
                override suspend fun respondStreaming(
                    request: AgentModelRequest,
                    onChunk: suspend (StreamChunk) -> Unit
                ): AgentModelResponse {
                    onChunk(StreamChunk.TextDelta("partial "))
                    onChunk(StreamChunk.TextDelta("report intent://open"))
                    onChunk(StreamChunk.TextDelta("x".repeat(17_000)))
                    val response = AgentModelResponse.Final(AgentReport(summary = "Done."))
                    onChunk(StreamChunk.Done(response))
                    return response
                }
            }
            val listener = object : AgentRunListener {
                override fun onStreamingUpdate(text: String) {
                    updates += text
                }
            }

            val outcome = loop(harness, client, listener = listener).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            assertTrue(updates.any { it.contains("partial report") })
            assertTrue(updates.any { it.contains(AgentPrivacyPolicy.BLOCKED_URI) })
            assertTrue(updates.filter { it.isNotEmpty() }.all { it.length <= 16_000 })
            assertEquals("", updates.last())
        }
    }

    @Test
    fun streamingInteractionRecordsResponseAndFirstTokenTiming() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            var now = 1_000L
            val interactions = mutableListOf<AgentModelInteraction>()
            val usage = AgentTokenUsage(
                inputTokens = 120,
                cachedInputTokens = 80,
                outputTokens = 24
            )
            val client = object : TestClient(
                capabilities = AiModelCapabilities.PHASE0.copy(streaming = true)
            ) {
                override suspend fun respondStreaming(
                    request: AgentModelRequest,
                    onChunk: suspend (StreamChunk) -> Unit
                ): AgentModelResponse {
                    now = 1_125L
                    onChunk(StreamChunk.TextDelta("D"))
                    now = 1_450L
                    return AgentModelResponse.Final(
                        report = AgentReport(summary = "Done."),
                        usage = usage
                    ).also { onChunk(StreamChunk.Done(it)) }
                }
            }
            val listener = object : AgentRunListener {
                override fun onModelInteraction(interaction: AgentModelInteraction) {
                    interactions += interaction
                }
            }

            val outcome = loop(
                harness = harness,
                client = client,
                listener = listener,
                clock = { now }
            ).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            val interaction = interactions.single()
            assertEquals(1_000L, interaction.startedAtMillis)
            assertEquals(1_125L, interaction.firstTokenAtMillis)
            assertEquals(1_450L, interaction.completedAtMillis)
            assertEquals(450L, interaction.responseDurationMillis)
            assertEquals(125L, interaction.timeToFirstTokenMillis)
            assertEquals(usage, interaction.response.usage)
        }
    }

    @Test
    fun differentToolsOverlapWhileCallsToTheSameToolRemainSerial() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val firstAStarted = CompletableDeferred<Unit>()
            val bStarted = CompletableDeferred<Unit>()
            val activeA = AtomicInteger(0)
            val maxActiveA = AtomicInteger(0)
            val overlapObserved = AtomicBoolean(false)
            val toolA = FakeTool("get_capture_overview") { _, context ->
                val active = activeA.incrementAndGet()
                maxActiveA.updateAndGet { previous -> maxOf(previous, active) }
                if (!firstAStarted.isCompleted) firstAStarted.complete(Unit)
                val overlapped = withTimeoutOrNull(500L) {
                    bStarted.await()
                    true
                } ?: false
                overlapObserved.set(overlapped)
                delay(20)
                activeA.decrementAndGet()
                context.success(mapOf("ok" to true), 1, 1)
            }
            val toolB = FakeTool("get_expert_info") { _, context ->
                firstAStarted.await()
                bStarted.complete(Unit)
                context.success(mapOf("ok" to true), 1, 1)
            }
            val client = RecordingClient(
                responses = listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall("a-1", "get_capture_overview", mapOf("limit" to 1)),
                            AgentToolCall("b-1", "get_expert_info"),
                            AgentToolCall("a-2", "get_capture_overview", mapOf("limit" to 2))
                        )
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Done."))
                ),
                capabilities = AiModelCapabilities.PHASE0.copy(parallelToolCalls = true)
            )

            val outcome = loop(harness, client, tools = listOf(toolA, toolB)).run(
                "Parallel calls?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals(2, toolA.executionCount)
            assertEquals(1, toolB.executionCount)
            assertEquals(1, maxActiveA.get())
            assertTrue(overlapObserved.get())
        }
    }

    @Test
    fun reportWithMultipleRejectedCitationsGetsOnlyOneRevisionTurn() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val original = AgentReport(
                summary = "Needs revision.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported one",
                                sourceToolCallId = "missing-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported two",
                                sourceToolCallId = "missing-2"
                            )
                        )
                    )
                )
            )
            val revised = AgentReport(
                summary = "Revised.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "overview returned data",
                                sourceToolCallId = "call-1"
                            )
                        )
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(
                        report = original,
                        reasoningContent = "Revise using only verified evidence."
                    ),
                    AgentModelResponse.Final(revised)
                )
            )

            val outcome = loop(harness, client).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            assertEquals("Needs revision.", outcome.report.summary)
            assertEquals(
                listOf("call-1"),
                outcome.report.findings.single().evidence.map { it.sourceToolCallId }
            )
            assertEquals(3, client.requests.size)
            // A revision returns findings only, so the narrow schema is used.
            assertEquals(
                AgentPrompt.REVISED_FINDINGS_SCHEMA,
                client.requests.last().responseSchema
            )
            // The revision request follows the Finalizing contract: no tools
            // are offered, so the model cannot answer with an unexecutable
            // tool-call batch instead of the corrected findings.
            assertTrue(client.requests.last().toolDefinitions.isEmpty())
            val revisionPrompt = client.requests.last().messages.last().content
            val revisionAssistant = client.requests.last().messages.last {
                it.role == AgentModelMessageRole.Assistant
            }
            assertEquals(
                "Revise using only verified evidence.",
                revisionAssistant.reasoningContent
            )
            assertTrue(revisionPrompt.contains("unknown_source=2"))
            assertTrue(revisionPrompt.contains(FINDING_ID))
            assertFalse(revisionPrompt.contains("missing-1"))
            assertFalse(revisionPrompt.contains("missing-2"))
        }
    }

    @Test
    fun aFailedRevisionKeepsTheReportThatWasAlreadyValidated() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val original = AgentReport(
                summary = "Kept despite the failed revision.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "supported",
                                sourceToolCallId = "call-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported one",
                                sourceToolCallId = "missing-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported two",
                                sourceToolCallId = "missing-2"
                            )
                        )
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(original),
                    AgentModelResponse.Failure(gatewayTimeout())
                )
            )

            val outcome = loop(
                harness,
                client,
                policy = AgentPolicy(maxModelRetries = 0),
                suspendDelay = {}
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            // The revision was an improvement attempt, not a precondition: the
            // validated report survives instead of collapsing to a synthesized one.
            assertTrue(outcome is AgentRunOutcome.Completed)
            val report = (outcome as AgentRunOutcome.Completed).report
            assertEquals("Kept despite the failed revision.", report.summary)
            assertEquals(
                listOf("call-1"),
                report.findings.single().evidence.map { it.sourceToolCallId }
            )
            assertTrue(report.limitations.any { it.contains("could not be completed") })
        }
    }

    @Test
    fun aGatewayTimeoutUsesTheConfiguredRetriesAndShrinksToTheFloor() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    )
                ) + List(6) { AgentModelResponse.Failure(gatewayTimeout()) },
                capabilities = AiModelCapabilities(
                    maxContextTokens = 1_000_000,
                    maxOutputTokens = 384_000
                )
            )

            val outcome = loop(
                harness,
                client,
                policy = AgentPolicy(maxModelRetries = 5),
                suspendDelay = {}
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertTrue(outcome is AgentRunOutcome.FailedWithPartialReport)
            // One tool turn, the original attempt, three shrinking retries that
            // reach the floor, then the single forced-summary hand-off. The
            // remaining two configured retries are deliberately not spent: a
            // proxy deadline is fixed, so once the allowance can no longer
            // shrink a byte-identical replay cannot pass either.
            assertEquals(6, client.requests.size)
            val attempts = client.requests.drop(1).take(4).map { it.maxOutputTokens }
            assertEquals(listOf(8_192, 4_096, 2_048, 1_024), attempts)
            assertTrue(attempts.all { it >= ModelRetryPolicy.MIN_RETRY_OUTPUT_TOKENS })
        }
    }

    @Test
    fun aSingleRejectedCitationIsRemovedWithoutSpendingARevisionTurn() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val original = AgentReport(
                summary = "One bad citation only.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "supported",
                                sourceToolCallId = "call-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported",
                                sourceToolCallId = "missing-1"
                            )
                        )
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(original)
                )
            )

            val outcome = loop(harness, client).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            // minRejectionsForRevision defaults to 2, so one rejection is simply
            // dropped rather than costing a whole extra model turn.
            assertEquals(2, client.requests.size)
            assertEquals(
                listOf("call-1"),
                outcome.report.findings.single().evidence.map { it.sourceToolCallId }
            )
        }
    }

    /**
     * A model may answer the revision request with tool calls (it wants more
     * evidence before correcting the rejected findings).  The revision turn
     * ships no tools and Revising permits no tool turn, so the batch cannot
     * run — but the validated report must survive instead of the refused
     * RunningTool transition ending the whole run as a fake user cancellation.
     */
    @Test
    fun revisionAnsweredWithToolCallsKeepsTheValidatedReport() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    data = mapOf("frameCount" to 100),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val expert = FakeTool("get_expert_info") { _, context ->
                context.success(
                    data = mapOf("items" to emptyList<Any?>()),
                    returnedCount = 0L,
                    totalCount = 0L
                )
            }
            val original = AgentReport(
                summary = "Kept when the revision went investigating.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "supported",
                                sourceToolCallId = "call-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported one",
                                sourceToolCallId = "missing-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported two",
                                sourceToolCallId = "missing-2"
                            )
                        )
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(original),
                    // The revision answer is a tool-call batch, not findings.
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-2", "get_expert_info"))
                    )
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )
            val controller = controller(harness, client)

            val outcome = loop(
                harness,
                client,
                tools = listOf(overview, expert),
                controller = controller,
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            // The run completes with the pre-revision report — never Cancelled.
            assertTrue(outcome is AgentRunOutcome.Completed)
            val report = (outcome as AgentRunOutcome.Completed).report
            assertEquals("Kept when the revision went investigating.", report.summary)
            assertEquals(
                listOf("call-1"),
                report.findings.single().evidence.map { it.sourceToolCallId }
            )
            assertTrue(report.limitations.any { it.contains("could not be completed") })
            assertEquals(AgentRunPhase.Completed, controller.phase)
            // The unexecutable batch spends nothing: no fourth request, no tool run.
            assertEquals(3, client.requests.size)
            assertEquals(0, expert.executionCount)
            // The decision is visible in the diagnostics log instead of the run
            // silently ending — this is what made the field failure undebuggable.
            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            assertTrue(
                (0 until events.length()).map { events.getJSONObject(it) }.any {
                    it.getString("eventType") == "Validation" &&
                        it.getString("status") == "revision_tool_calls"
                }
            )
        }
    }

    /**
     * A model that reports through submit_report may answer the revision the
     * same way even though the request ships no tools.  That call carries the
     * corrected findings, so it is decoded inline — never executed — and
     * merged into the report the host already validated.
     */
    @Test
    fun revisionAnsweredWithSubmitReportToolCallMergesTheRevision() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val original = AgentReport(
                summary = "Needs revision.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported one",
                                sourceToolCallId = "missing-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported two",
                                sourceToolCallId = "missing-2"
                            )
                        )
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(original),
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "revise-1",
                                SubmitReportTool.NAME,
                                mapOf(
                                    "summary" to "Ignored: the host keeps its summary.",
                                    "findings" to listOf(
                                        mapOf(
                                            "id" to FINDING_ID,
                                            "title" to "A finding",
                                            "severity" to "Warning",
                                            "confidence" to "Medium",
                                            "conclusion" to "A conclusion.",
                                            "evidence" to listOf(
                                                mapOf(
                                                    "type" to "Observation",
                                                    "observation" to "overview returned data",
                                                    "sourceToolCallId" to "call-1"
                                                )
                                            )
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )

            val outcome = loop(harness, client).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            // The submitted findings replace the rejected ones; the summary the
            // host already validated is kept, exactly as a plain revision would.
            assertEquals("Needs revision.", outcome.report.summary)
            assertEquals(
                listOf("call-1"),
                outcome.report.findings.single().evidence.map { it.sourceToolCallId }
            )
            assertEquals(3, client.requests.size)
        }
    }

    /**
     * A budget ceiling crossed while a revision is pending ends the improvement
     * turn, not the analysis: the validated report is kept instead of the host
     * synthesizing a weaker fallback report.
     */
    @Test
    fun budgetExhaustedDuringPendingRevisionKeepsTheValidatedReport() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val original = AgentReport(
                summary = "Kept when the budget ended the revision.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "supported",
                                sourceToolCallId = "call-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported one",
                                sourceToolCallId = "missing-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported two",
                                sourceToolCallId = "missing-2"
                            )
                        )
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(original)
                )
            )

            val outcome = loop(
                harness,
                client,
                // The revision is requested after the second (last allowed)
                // request, so the next turn's budget check ends the run.
                policy = AgentPolicy(maxModelRequests = 2)
            ).run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            assertTrue(outcome is AgentRunOutcome.Completed)
            val report = (outcome as AgentRunOutcome.Completed).report
            assertEquals("Kept when the budget ended the revision.", report.summary)
            assertTrue(report.limitations.any { it.contains("could not be completed") })
            assertEquals(2, client.requests.size)
        }
    }

    /**
     * A revision answer that decodes to nothing usable must not fall through
     * to the full-report path: that would replace the validated report with a
     * synthesized fallback over a mere improvement attempt.
     */
    @Test
    fun unusableRevisionAnswerKeepsTheValidatedReport() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val original = AgentReport(
                summary = "Kept despite the unusable revision.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "supported",
                                sourceToolCallId = "call-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported one",
                                sourceToolCallId = "missing-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported two",
                                sourceToolCallId = "missing-2"
                            )
                        )
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(original),
                    AgentModelResponse.Final(reportJson = "not a findings object {{{")
                )
            )

            val outcome = loop(harness, client).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            val report = (outcome as AgentRunOutcome.Completed).report
            assertEquals("Kept despite the unusable revision.", report.summary)
            assertEquals(
                listOf("call-1"),
                report.findings.single().evidence.map { it.sourceToolCallId }
            )
            assertTrue(report.limitations.any { it.contains("could not be completed") })
            assertEquals(3, client.requests.size)
        }
    }

    @Test
    fun declaredPlanDrivesProgressButCannotBecomeReportEvidence() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val planTool = DeclareAnalysisPlanTool()
            val overview = defaultTools().first()
            val plans = mutableListOf<Pair<AgentAnalysisPlan, Int>>()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "plan-1",
                                DeclareAnalysisPlanTool.NAME,
                                mapOf(
                                    "goal" to "Assess capture health",
                                    "steps" to listOf(
                                        mapOf(
                                            "tool" to "get_capture_overview",
                                            "purpose" to "Read capture health indicators"
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(
                        AgentReport(
                            summary = "Planned analysis complete.",
                            findings = listOf(
                                finding(
                                    listOf(
                                        AgentEvidence(
                                            AgentEvidenceType.Observation,
                                            observation = "overview returned data",
                                            sourceToolCallId = "call-1"
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )
            val listener = object : AgentRunListener {
                override fun onAnalysisPlan(plan: AgentAnalysisPlan, completedSteps: Int) {
                    plans += plan to completedSteps
                }
            }

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, overview),
                listener = listener
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            assertEquals(listOf(0, 1), plans.map { it.second })
            assertEquals(listOf("call-1"), outcome.report.provenance.toolCallIds)
            assertFalse(outcome.report.provenance.toolCallIds.contains("plan-1"))
        }
    }

    @Test
    fun planStepsMayRunOutOfOrderAndExtraCallsDoNotMasqueradeAsRepeatedQueries() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val planTool = DeclareAnalysisPlanTool()
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 10), returnedCount = 1L, totalCount = 1L)
            }
            val expert = FakeTool("get_expert_info") { _, context ->
                context.success(mapOf("warningCount" to 1), returnedCount = 1L, totalCount = 1L)
            }
            val statistics = FakeTool("get_statistics") { _, context ->
                context.success(mapOf("packetCount" to 10), returnedCount = 1L, totalCount = 1L)
            }
            val summaries = FakeTool("query_packet_summaries") { _, context ->
                context.success(mapOf("packetCount" to 2), returnedCount = 2L, totalCount = 2L)
            }
            val progress = mutableListOf<Int>()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "plan-1",
                                DeclareAnalysisPlanTool.NAME,
                                mapOf(
                                    "goal" to "Inspect the trace",
                                    "steps" to listOf(
                                        mapOf(
                                            "tool" to "get_capture_overview",
                                            "purpose" to "Establish the baseline"
                                        ),
                                        mapOf(
                                            "tool" to "get_expert_info",
                                            "purpose" to "Check anomalies"
                                        ),
                                        mapOf(
                                            "tool" to "get_capture_overview",
                                            "purpose" to "Recheck the baseline after anomalies"
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("statistics-1", "get_statistics"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("summaries-1", "query_packet_summaries"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-2", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Out-of-order plan summarized."))
                )
            )
            val listener = object : AgentRunListener {
                override fun onAnalysisPlan(plan: AgentAnalysisPlan, completedSteps: Int) {
                    progress += completedSteps
                }
            }

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, overview, expert, statistics, summaries),
                listener = listener
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.PlanComplete, completed.stopReason)
            assertEquals("Out-of-order plan summarized.", completed.report.summary)
            assertEquals(listOf(0, 1, 2, 3), progress)
            assertEquals(2, overview.executionCount)
            assertEquals(1, expert.executionCount)
            assertEquals(1, statistics.executionCount)
            assertEquals(1, summaries.executionCount)
        }
    }

    /** A plan step declared before any result exists cannot anticipate truncation. */
    private fun truncatedExpertPlanDeclaration() = AgentModelResponse.ToolCalls(
        listOf(
            AgentToolCall(
                "plan-1",
                DeclareAnalysisPlanTool.NAME,
                mapOf(
                    "goal" to "Check anomalies",
                    "steps" to listOf(
                        mapOf(
                            "tool" to "get_expert_info",
                            "purpose" to "Read expert diagnostics"
                        )
                    )
                )
            )
        )
    )

    /** Paged tool whose every result leaves a continuable paging gap. */
    private fun truncatedPagedExpertTool() = FakeTool(
        name = "get_expert_info",
        schema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "offset" to mapOf("type" to "integer", "minimum" to 0),
                "limit" to mapOf("type" to "integer", "minimum" to 1, "maximum" to 100)
            )
        )
    ) { arguments, context ->
        val offset = (arguments["offset"] as? Number)?.toLong() ?: 0L
        context.success(
            data = mapOf(
                "offset" to offset,
                "limit" to 100,
                "returned" to 100,
                "total" to 228,
                "truncated" to true
            ),
            returnedCount = 100L,
            totalCount = 228L,
            truncated = true
        )
    }

    @Test
    fun planCompletionWithRecoverableTruncationGrantsGapFillTurns() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val expert = truncatedPagedExpertTool()
            val client = RecordingClient(
                listOf(
                    truncatedExpertPlanDeclaration(),
                    // Completes the plan's only step — but the result is
                    // truncated with a usable paging continuation.
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    // Gap-fill turn: continue the truncated read.
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall("expert-2", "get_expert_info", mapOf("offset" to 100))
                        )
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Gaps filled."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool(), expert)
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.ModelFinal, completed.stopReason)
            assertEquals("Gaps filled.", completed.report.summary)
            assertEquals(2, expert.executionCount)
        }
    }

    @Test
    fun gapFillTurnsAreBoundedByPolicy() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val expert = truncatedPagedExpertTool()
            val client = RecordingClient(
                listOf(
                    truncatedExpertPlanDeclaration(),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    // The single granted gap-fill turn.
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall("expert-2", "get_expert_info", mapOf("offset" to 100))
                        )
                    ),
                    // Consumed by the forced-summary handoff, not by another turn.
                    AgentModelResponse.Final(AgentReport(summary = "Bounded gap fill."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool(), expert),
                policy = AgentPolicy(maxPlanGapFillTurns = 1)
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.PlanComplete, completed.stopReason)
            assertEquals(2, expert.executionCount)
        }
    }

    @Test
    fun planCompletionWithoutUsableContinuationStopsAsBefore() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            // Truncated, but with no paging echo and nothing omitted to re-read:
            // the continuation resolves to available=false.
            val expert = FakeTool("get_expert_info") { _, context ->
                context.success(
                    data = mapOf("returned" to 1, "total" to 1, "payloadTruncated" to true),
                    returnedCount = 1L,
                    totalCount = 1L,
                    truncated = true
                )
            }
            val client = RecordingClient(
                listOf(
                    truncatedExpertPlanDeclaration(),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "No gap fill."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool(), expert)
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.PlanComplete, completed.stopReason)
            assertEquals(1, expert.executionCount)
        }
    }

    /**
     * The observed failure: the grant was spent on a fresh line of investigation
     * while the truncated evidence sat unread. An off-purpose call must be
     * refused, must not run, and must not cost the grant.
     */
    @Test
    fun gapFillTurnSpentOnNewInvestigationIsRefusedAndNotCharged() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val expert = truncatedPagedExpertTool()
            val summaries = FakeTool("query_packet_summaries") { _, context ->
                context.success(mapOf("frames" to listOf(1L)), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    truncatedExpertPlanDeclaration(),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    // A new direction, not a continuation: refused, uncharged.
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("new-1", "query_packet_summaries"))
                    ),
                    // The grant survived, so the real continuation still runs.
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall("expert-2", "get_expert_info", mapOf("offset" to 100))
                        )
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Gap filled after refusal."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool(), expert, summaries)
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Gap filled after refusal.", completed.report.summary)
            // The off-purpose tool never executed...
            assertEquals(0, summaries.executionCount)
            // ...and the continuation it would have displaced still did.
            assertEquals(2, expert.executionCount)
        }
    }

    /** A refused off-purpose call reports why, so the model can correct course. */
    @Test
    fun refusedGapFillCallExplainsThePermittedPurpose() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val expert = truncatedPagedExpertTool()
            val summaries = FakeTool("query_packet_summaries") { _, context ->
                context.success(mapOf("frames" to listOf(1L)), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    truncatedExpertPlanDeclaration(),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("new-1", "query_packet_summaries"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Stopped."))
                )
            )

            val agentLoop = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool(), expert, summaries)
            )
            agentLoop.run("Inspect this trace", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val refused = agentLoop.activities().single { it.toolCallId == "new-1" }
            assertEquals(AgentToolActivityStatus.Failed, refused.status)
        }
    }

    /**
     * A gap-fill read can itself come back truncated. Stranding that new gap
     * while turns remain would recreate the problem the grant exists to solve.
     */
    @Test
    fun truncationDiscoveredDuringGapFillRenewsTheGrantWithinTheSameTotal() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val expert = truncatedPagedExpertTool()
            val client = RecordingClient(
                listOf(
                    truncatedExpertPlanDeclaration(),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-2", "get_expert_info", mapOf("offset" to 100)))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-3", "get_expert_info", mapOf("offset" to 200)))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Renewed."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool(), expert),
                policy = AgentPolicy(maxPlanGapFillTurns = 3)
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Renewed.", completed.report.summary)
            // Every result is truncated, so each fill creates the next gap: the
            // grant renews rather than expiring after its first use.
            assertEquals(3, expert.executionCount)
        }
    }

    /** Off-purpose turns are free, so something else has to bound them. */
    @Test
    fun repeatedOffPurposeGapFillTurnsEventuallyWithdrawTheGrant() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val expert = truncatedPagedExpertTool()
            val summaries = FakeTool("query_packet_summaries") { _, context ->
                context.success(mapOf("frames" to listOf(1L)), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    truncatedExpertPlanDeclaration(),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("off-1", "query_packet_summaries"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("off-2", "query_packet_summaries"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Withdrawn."))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool(), expert, summaries)
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.PlanComplete, completed.stopReason)
            assertEquals(0, summaries.executionCount)
        }
    }

    /**
     * Submitting the report is always allowed. Screening it as off-purpose would
     * make the enforcement block the very thing the grant is meant to end in.
     */
    @Test
    fun reportSubmissionDuringGapFillIsNotTreatedAsOffPurpose() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val expert = truncatedPagedExpertTool()
            val client = RecordingClient(
                listOf(
                    truncatedExpertPlanDeclaration(),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("expert-1", "get_expert_info"))
                    ),
                    // The grant is open, and the model chooses to finish instead.
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "submit-1",
                                SubmitReportTool.NAME,
                                mapOf(
                                    "summary" to "Enough evidence gathered.",
                                    "questionAlignment" to emptyList<Any?>(),
                                    "findings" to emptyList<Any?>()
                                )
                            )
                        )
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(DeclareAnalysisPlanTool(), SubmitReportTool(), expert)
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.ModelFinal, completed.stopReason)
            assertEquals("Enough evidence gathered.", completed.report.summary)
        }
    }

    @Test
    fun validPlanAndTargetedSiblingCallsRunInOneModelTurnAfterBootstrap() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val planTool = DeclareAnalysisPlanTool()
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    mapOf("expertErrorCount" to 0, "expertWarningCount" to 0),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val statistics = FakeTool("get_statistics") { _, context ->
                context.success(mapOf("packetCount" to 10), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall("statistics-1", "get_statistics"),
                            AgentToolCall(
                                "plan-1",
                                DeclareAnalysisPlanTool.NAME,
                                mapOf(
                                    "goal" to "Assess the baseline anomaly",
                                    "steps" to listOf(
                                        mapOf(
                                            "tool" to "get_statistics",
                                            "purpose" to "Quantify the anomaly"
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    AgentModelResponse.Final(
                        AgentReport(
                            summary = "Targeted analysis complete.",
                            findings = listOf(
                                finding(
                                    listOf(
                                        AgentEvidence(
                                            AgentEvidenceType.Statistic,
                                            observation = "Statistics returned data.",
                                            sourceToolCallId = "statistics-1"
                                        )
                                    )
                                )
                            )
                        )
                    )
                )
            )

            val outcome = loop(
                harness = harness,
                client = client,
                tools = listOf(planTool, overview, statistics),
                bootstrapEnabled = true
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            assertEquals(1, overview.executionCount)
            assertEquals(1, statistics.executionCount)
            assertEquals(2, client.requests.size)
            val assistant = client.requests.last().messages.last {
                it.role == AgentModelMessageRole.Assistant &&
                    it.toolCalls.any { call -> call.toolCallId == "plan-1" }
            }
            assertEquals(
                listOf("plan-1", "statistics-1"),
                assistant.toolCalls.map { it.toolCallId }
            )
            assertEquals(
                listOf("host-bootstrap-overview-1", "statistics-1"),
                outcome.report.provenance.toolCallIds
            )
        }
    }

    @Test
    fun invalidPlanBlocksSiblingCallsAndReturnsAStructuredError() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val planTool = DeclareAnalysisPlanTool()
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    mapOf("expertErrorCount" to 0, "expertWarningCount" to 0),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val statistics = FakeTool("get_statistics") { _, context ->
                context.success(mapOf("packetCount" to 10), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "plan-1",
                                DeclareAnalysisPlanTool.NAME,
                                mapOf(
                                    "goal" to "Use an unavailable tool",
                                    "steps" to listOf(
                                        mapOf("tool" to "read_file", "purpose" to "Bypass the host")
                                    )
                                )
                            ),
                            AgentToolCall("statistics-1", "get_statistics")
                        )
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Plan was rejected."))
                )
            )

            val outcome = loop(
                harness = harness,
                client = client,
                tools = listOf(planTool, overview, statistics),
                bootstrapEnabled = true
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            assertEquals(0, statistics.executionCount)
            assertEquals(listOf("host-bootstrap-overview-1"), outcome.report.provenance.toolCallIds)
            val blocked = client.requests.last().messages.single {
                it.role == AgentModelMessageRole.Tool && it.toolCallId == "statistics-1"
            }.toolResult
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, blocked?.error?.code)
            assertEquals("invalid_analysis_plan", blocked?.error?.details?.get("reason"))
            assertTrue(client.requests.last().messages.any {
                it.role == AgentModelMessageRole.User &&
                    it.content == AgentPrompt.INVALID_ANALYSIS_PLAN_NUDGE
            })
        }
    }

    @Test
    fun delegatedInvestigationUsesIsolatedTranscriptAndSharesEvidenceLedger() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val delegate = DelegateInvestigationTool()
            val overview = defaultTools().first()
            val childReport = AgentReport(
                summary = "Child confirmed overview data.",
                findings = listOf(
                    finding(
                        listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "overview returned data",
                                sourceToolCallId = "child-overview"
                            )
                        )
                    )
                )
            )
            val mainReport = childReport.copy(summary = "Main used delegated evidence.")
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "delegate-1",
                                DelegateInvestigationTool.NAME,
                                mapOf("goal" to "Inspect capture health", "maxTurns" to 3)
                            )
                        )
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("child-overview", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(childReport),
                    AgentModelResponse.Final(mainReport)
                )
            )

            val outcome = loop(harness, client, tools = listOf(delegate, overview)).run(
                "Delegate this investigation",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            assertEquals("Main used delegated evidence.", outcome.report.summary)
            assertEquals(listOf("child-overview"), outcome.report.provenance.toolCallIds)
            assertFalse(client.requests[1].toolDefinitions.any {
                it.name == DelegateInvestigationTool.NAME
            })
            assertFalse(client.requests[1].messages.any { message ->
                message.toolCallId == "delegate-1"
            })
        }
    }

    @Test
    fun delegatedReportOnItsLastAllowedRequestIsComplete() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "delegate-1",
                                DelegateInvestigationTool.NAME,
                                mapOf("goal" to "Inspect capture health")
                            )
                        )
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Child completed.")),
                    AgentModelResponse.Final(AgentReport(summary = "Parent completed."))
                )
            )

            loop(
                harness = harness,
                client = client,
                tools = listOf(DelegateInvestigationTool()),
                policy = AgentPolicy(maxDelegatedModelRequests = 1)
            ).run(
                "Delegate this investigation",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val delegateResult = client.requests.last().messages
                .first { it.toolCallId == "delegate-1" }
                .toolResult
            assertEquals(false, delegateResult?.data?.get("delegateIncomplete"))
            assertFalse(delegateResult?.truncated == true)
        }
    }

    @Test
    fun delegatedModelTimeoutReturnsToolErrorAndParentLoopContinues() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val enteredChildRequest = CompletableDeferred<Unit>()
            val requests = mutableListOf<AgentModelRequest>()
            val requestCount = AtomicInteger(0)
            val client = object : TestClient() {
                override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
                    requests += request
                    return when (requestCount.getAndIncrement()) {
                        0 -> AgentModelResponse.ToolCalls(
                            listOf(
                                AgentToolCall(
                                    "delegate-1",
                                    DelegateInvestigationTool.NAME,
                                    mapOf("goal" to "Inspect the capture")
                                )
                            )
                        )
                        1 -> {
                            enteredChildRequest.complete(Unit)
                            awaitCancellation()
                        }
                        else -> AgentModelResponse.Final(
                            AgentReport(summary = "Parent recovered from delegate timeout.")
                        )
                    }
                }
            }
            val controller = controller(harness, client)

            val outcome = withTimeoutOrNull(2_000L) {
                loop(
                    harness = harness,
                    client = client,
                    tools = listOf(DelegateInvestigationTool()),
                    policy = AgentPolicy(maxDelegatedInvestigationTimeoutMillis = 40L),
                    controller = controller
                ).run(
                    "Delegate this investigation",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )
            }

            assertTrue(enteredChildRequest.isCompleted)
            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals(AgentRunPhase.Completed, controller.phase)
            assertFalse(controller.isCancelled)
            assertEquals(3, requests.size)
            val timeoutResult = requests.last().messages
                .first { it.toolCallId == "delegate-1" }
                .toolResult
            assertTrue(timeoutResult?.success == true)
            assertEquals(true, timeoutResult?.data?.get("delegateIncomplete"))
            assertEquals("timeout", timeoutResult?.data?.get("incompleteReason"))
        }
    }

    @Test
    fun delegatedRetriesDoNotConsumeChildRequestBudgetAndPreserveParentFinalRequest() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val requests = mutableListOf<AgentModelRequest>()
            val client = object : TestClient() {
                override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
                    requests += request
                    return when (requests.size) {
                        1 -> AgentModelResponse.ToolCalls(
                            listOf(
                                AgentToolCall(
                                    "delegate-1",
                                    DelegateInvestigationTool.NAME,
                                    mapOf("goal" to "Inspect the capture")
                                )
                            )
                        )
                        in 2..5 -> AgentModelResponse.Failure(
                            AiModelErrors.unavailable(reason = "transient_child_failure")
                        )
                        else -> AgentModelResponse.Final(
                            AgentReport(summary = "Parent retained its final request.")
                        )
                    }
                }
            }

            val outcome = loop(
                harness = harness,
                client = client,
                tools = listOf(DelegateInvestigationTool()),
                policy = AgentPolicy(
                    maxModelRequests = 3,
                    maxDelegatedModelRequests = 1,
                    reservedParentModelRequests = 1
                )
            ).run(
                "Delegate this investigation",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed

            assertEquals("Parent retained its final request.", outcome.report.summary)
            // One parent request, one delegated logical request with three
            // retries, and the reserved parent final request.
            assertEquals(6, requests.size)
            val delegateResult = requests.last().messages
                .first { it.toolCallId == "delegate-1" }
                .toolResult
            assertEquals(true, delegateResult?.data?.get("delegateIncomplete"))
            assertEquals("budget", delegateResult?.data?.get("incompleteReason"))
        }
    }

    /**
     * The report's normal transport is the tool channel.
     *
     * Three consecutive device runs failed because the model answered a
     * tool-selection turn with prose containing hand-written JSON, and the host
     * had no way to accept it. Routing the report through submit_report gives
     * every turn one shape, so there is nothing left to misjudge.
     */
    @Test
    fun submitReportToolCompletesTheRunWithItsArguments() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val planTool = DeclareAnalysisPlanTool()
            val overview = defaultTools().first()
            val expert = defaultTools()[1]
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "plan-1",
                                DeclareAnalysisPlanTool.NAME,
                                mapOf(
                                    "goal" to "Inspect the trace",
                                    "steps" to listOf(
                                        mapOf(
                                            "tool" to "get_capture_overview",
                                            "purpose" to "Establish the baseline"
                                        ),
                                        mapOf(
                                            "tool" to "get_expert_info",
                                            "purpose" to "Read engine findings"
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    // The plan still has a step left, so this is an ordinary
                    // tool-selection turn — exactly where the device runs failed.
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "report-1",
                                SubmitReportTool.NAME,
                                mapOf(
                                    "summary" to "Submitted over the tool channel.",
                                    "questionAlignment" to emptyList<Any?>(),
                                    "findings" to emptyList<Any?>()
                                )
                            )
                        )
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), overview, expert)
            ).run("Inspect this trace", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Submitted over the tool channel.", completed.report.summary)
            assertEquals(AgentStopReason.ModelFinal, completed.stopReason)
        }
    }

    /**
     * The plan running out is not the end of the run any more.
     *
     * PlanComplete hands off to the bounded forced summary, and a model that has
     * learned to answer through submit_report will use it there too. That call is
     * the report, so it completes the run instead of being rejected as a
     * forced-summary contract violation.
     */
    @Test
    fun submitReportIsHonouredDuringTheForcedSummaryHandoff() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val planTool = DeclareAnalysisPlanTool()
            val overview = defaultTools().first()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "plan-1",
                                DeclareAnalysisPlanTool.NAME,
                                mapOf(
                                    "goal" to "Inspect the trace",
                                    "steps" to listOf(
                                        mapOf(
                                            "tool" to "get_capture_overview",
                                            "purpose" to "Establish the baseline"
                                        )
                                    )
                                )
                            )
                        )
                    ),
                    // Completes the one declared step, so the run stops with
                    // PlanComplete and asks for a forced summary next.
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    // The forced-summary turn answers with the report tool.
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "report-1",
                                SubmitReportTool.NAME,
                                mapOf(
                                    "summary" to "Submitted during the forced summary.",
                                    "findings" to emptyList<Any?>()
                                )
                            )
                        )
                    )
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), overview)
            ).run("Inspect this trace", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Submitted during the forced summary.", completed.report.summary)
        }
    }

    // ---------------------------------------------------- conversation history

    @Test
    fun finalTranscriptReplaysTheWholeRunIncludingItsConclusion() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = scriptedClient(
                MockScriptedResponse.tool("call-1", "get_capture_overview"),
                MockScriptedResponse.final(AgentReport(summary = "The capture is healthy."))
            )
            val agentLoop = loop(harness, client)

            agentLoop.run("What is wrong?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val transcript = agentLoop.transcript()
            // system block, user question, assistant tool call, tool result,
            // assistant conclusion.
            assertEquals(
                listOf(
                    AgentModelMessageRole.System,
                    AgentModelMessageRole.User,
                    AgentModelMessageRole.Assistant,
                    AgentModelMessageRole.Tool,
                    AgentModelMessageRole.Assistant
                ),
                transcript.map { it.role }
            )
            assertEquals("What is wrong?", transcript[1].content)
            assertEquals(
                "The capture is healthy.",
                transcript.last().content
            )
            // A completed run's tool result stays marked untrusted.
            assertTrue(transcript[3].untrustedCaptureData)
        }
    }

    @Test
    fun sanitizedTranscriptStripsSystemReasoningAndCacheHints() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        calls = listOf(AgentToolCall("call-1", "get_capture_overview")),
                        reasoningContent = "Chain-of-thought from the live run."
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Done."))
                )
            )

            val agentLoop = loop(harness, client)
            agentLoop.run("Question?", harness.snapshot, AgentPrivacyMode.RedactedMetadata)

            val sanitized = agentLoop.sanitizedTranscript()
            assertTrue(sanitized.none { it.role == AgentModelMessageRole.System })
            assertTrue(sanitized.none { !it.reasoningContent.isNullOrBlank() })
            assertTrue(sanitized.none { it.cacheControl != null })
            // The trust marker survives: downstream consumers rely on it.
            assertTrue(sanitized.any { it.untrustedCaptureData })
            // And the run itself still replays reasoning to its own provider.
            assertTrue(
                client.requests.last().messages.any {
                    !it.reasoningContent.isNullOrBlank()
                }
            )
        }
    }

    @Test
    fun aFollowUpRunReplaysHistoryBeforeItsOwnQuestion() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = scriptedClient(
                MockScriptedResponse.final(AgentReport(summary = "Follow-up answer."))
            )

            val history = listOf(
                AgentModelMessage.user("Why is this capture slow?"),
                AgentModelMessage.assistant(content = "Prior conclusion."),
                AgentModelMessage.system("stale system block that must not survive"),
                com.example.layanalyzer.model.AgentModelMessage.fromToolResult(
                    com.example.layanalyzer.model.AgentToolResult(
                        toolCallId = "old-call-1",
                        toolName = "get_capture_overview",
                        success = true,
                        data = mapOf("frameCount" to 10)
                    ),
                    content = "{}"
                ).withCacheBreakpoint()
            )

            loop(harness, client).run(
                question = "And which stream is worst?",
                snapshot = harness.snapshot,
                privacyMode = AgentPrivacyMode.RedactedMetadata,
                history = ConversationHistorySanitizer.sanitize(history)
            )

            val request = client.observedRequests.single()
            val roles = request.messages.map { it.role }
            // History is dropped of system messages and ordered before the new
            // question; the fresh system block leads the sequence.
            assertTrue(roles.indexOf(AgentModelMessageRole.System) == 0)
            assertTrue(request.messages.none { it.content == "stale system block that must not survive" })
            assertTrue(request.messages.none { it.cacheControl != null && it.role != AgentModelMessageRole.System })
            val continuationIndex = request.messages.indexOfFirst {
                it.role == AgentModelMessageRole.User &&
                    it.content.contains(PromptAssembler.CONTINUATION_NOTICE)
            }
            assertTrue(continuationIndex > 0)
            assertTrue(request.messages[continuationIndex].content.startsWith("And which stream is worst?"))
            // The old tool result is present as history.
            assertTrue(
                request.messages.any {
                    it.role == AgentModelMessageRole.Tool && it.toolCallId == "old-call-1"
                }
            )
        }
    }

    @Test
    fun followUpWithASuccessfulOverviewInHistorySkipsHostBootstrap() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 10), returnedCount = 1L, totalCount = 1L)
            }
            val client = scriptedClient(
                MockScriptedResponse.final(AgentReport(summary = "Answered from history."))
            )
            val recorder = PhaseRecorder()
            val history = listOf(
                AgentModelMessage.user("Why is this capture slow?"),
                com.example.layanalyzer.model.AgentModelMessage.fromToolResult(
                    com.example.layanalyzer.model.AgentToolResult(
                        toolCallId = "host-bootstrap-overview-1",
                        toolName = "get_capture_overview",
                        success = true,
                        data = mapOf("frameCount" to 10)
                    ),
                    content = "{}"
                )
            )

            val outcome = loop(
                harness = harness,
                client = client,
                tools = listOf(overview),
                bootstrapEnabled = true,
                listener = recorder
            ).run(
                question = "Go deeper on the worst stream.",
                snapshot = harness.snapshot,
                privacyMode = AgentPrivacyMode.RedactedMetadata,
                history = history
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals(0, overview.executionCount)
            // The first model request carries no freshly injected bootstrap.
            val messages = client.observedRequests.single().messages
            assertTrue(messages.none { it.toolCallId?.startsWith("host-bootstrap") == true &&
                it.role == AgentModelMessageRole.Assistant })
        }
    }

    @Test
    fun oversizedHistoryIsCompactedBeforeTheFirstModelRequest() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = scriptedClient(
                MockScriptedResponse.final(AgentReport(summary = "Fit after compaction."))
            )
            // Many heavy prior turns against a small reported context window.
            val heavyResult = com.example.layanalyzer.model.AgentModelMessage.fromToolResult(
                com.example.layanalyzer.model.AgentToolResult(
                    toolCallId = "heavy-1",
                    toolName = "get_expert_info",
                    success = true,
                    data = mapOf("items" to (1..60).map { mapOf("frameNumber" to it.toLong(), "text" to "payload".repeat(40)) }),
                    returnedCount = 60L,
                    totalCount = 60L
                ),
                content = "{}"
            )
            val history = buildList {
                add(AgentModelMessage.user("Initial question."))
                repeat(30) { index ->
                    add(AgentModelMessage.assistant(toolCalls = listOf(AgentToolCall("turn-$index", "get_expert_info"))))
                    add(heavyResult.copy(toolCallId = "heavy-$index"))
                }
            }

            val agentLoop = loop(harness, client)
            val outcome = agentLoop.run(
                question = "Summarise everything so far.",
                snapshot = harness.snapshot,
                privacyMode = AgentPrivacyMode.RedactedMetadata,
                history = history
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            val request = client.observedRequests.first()
            // The sent request must be far smaller than the raw history: old
            // tool results were folded into discovery notes instead.
            assertTrue(
                "expected entry compaction",
                request.messages.count { it.role == AgentModelMessageRole.Tool } <
                    history.count { it.role == AgentModelMessageRole.Tool } ||
                    agentLoop.diagnosticAttributes()["historyCompactedAtEntry"] == "true"
            )
            assertTrue(
                request.messages.any {
                    it.untrustedCaptureData &&
                        it.content.startsWith(AgentConversationCompactor.DISCOVERY_NOTE_HEADER)
                }
            )
        }
    }

    /**
     * Both continuation-history signals must reach the persisted diagnostics
     * log, not merely the in-memory attribute map: entry compaction as a
     * history configuration record, and a history-skipped host bootstrap as an
     * AnalysisBootstrap record whose status names the reason.
     */
    @Test
    fun diagnosticsExposeEntryCompactionAndSkippedBootstrap() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 10), returnedCount = 1L, totalCount = 1L)
            }
            val client = scriptedClient(
                MockScriptedResponse.final(AgentReport(summary = "Continued from history."))
            )
            val heavyResult = com.example.layanalyzer.model.AgentModelMessage.fromToolResult(
                com.example.layanalyzer.model.AgentToolResult(
                    toolCallId = "heavy-1",
                    toolName = "get_expert_info",
                    success = true,
                    data = mapOf("items" to (1..60).map { mapOf("frameNumber" to it.toLong(), "text" to "payload".repeat(40)) }),
                    returnedCount = 60L,
                    totalCount = 60L
                ),
                content = "{}"
            )
            val history = buildList {
                add(AgentModelMessage.user("Initial question."))
                repeat(30) { index ->
                    add(AgentModelMessage.assistant(toolCalls = listOf(AgentToolCall("turn-$index", "get_expert_info"))))
                    add(heavyResult.copy(toolCallId = "heavy-$index"))
                }
                add(
                    com.example.layanalyzer.model.AgentModelMessage.fromToolResult(
                        com.example.layanalyzer.model.AgentToolResult(
                            toolCallId = "host-bootstrap-overview-1",
                            toolName = "get_capture_overview",
                            success = true,
                            data = mapOf("frameCount" to 10)
                        ),
                        content = "{}"
                    )
                )
            }
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )
            val agentLoop = loop(
                harness,
                client,
                tools = listOf(overview),
                bootstrapEnabled = true,
                diagnostics = recorder.beginRun(sessionId = "run_test")
            )
            val outcome = agentLoop.run(
                question = "Go deeper on the worst stream.",
                snapshot = harness.snapshot,
                privacyMode = AgentPrivacyMode.RedactedMetadata,
                history = history
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            assertEquals(0, overview.executionCount)
            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
                .let { array -> (0 until array.length()).map { array.getJSONObject(it) } }

            val historyEvent = events.first {
                it.getString("eventType") == "Configuration" &&
                    it.getString("status") == "history"
            }
            assertEquals(
                "true",
                historyEvent.getJSONObject("attributes").getString("historyCompactedAtEntry")
            )

            val skipEvent = events.single {
                it.getString("eventType") == "AnalysisBootstrap" &&
                    it.getString("status") == "skipped_prior_context"
            }
            assertEquals(
                "true",
                skipEvent.getJSONObject("attributes").getString("historyCompactedAtEntry")
            )
        }
    }

    /**
     * OPT-EVAL-04-01: a run whose citations were rejected and whose rejections
     * bought a revision turn must surface the three quality metrics on its
     * RunMetrics event, as counts only.
     */
    @Test
    fun runMetricsRecordCitationRejectionsRevisionAndConfidenceDistribution() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val original = AgentReport(
                summary = "Needs revision.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "supported",
                                sourceToolCallId = "call-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported one",
                                sourceToolCallId = "missing-1"
                            ),
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "unsupported two",
                                sourceToolCallId = "missing-2"
                            )
                        )
                    )
                )
            )
            val revised = AgentReport(
                summary = "Revised.",
                findings = listOf(
                    finding(
                        evidence = listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "overview returned data",
                                sourceToolCallId = "call-1"
                            )
                        )
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(report = original),
                    AgentModelResponse.Final(revised)
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertTrue(outcome is AgentRunOutcome.Completed)

            val attributes = runMetricsAttributes(recorder)
            // Round one submitted 3 citations and lost 2 to unknown_source;
            // the merged revision resubmitted 1 supported citation: 2 / (3 + 1).
            assertEquals("0.5000", attributes.getString("citationRejectionRate"))
            assertEquals("1", attributes.getString("revisionTriggered"))
            // The merged final report is the one surviving Medium finding.
            assertEquals(
                "High:0,Medium:1,Low:0,Unknown:0",
                attributes.getString("confidenceDistribution")
            )
            // Counts only: no finding title, conclusion or citation id rides
            // on the event.
            val raw = attributes.toString()
            assertFalse(raw.contains("Needs revision."))
            assertFalse(raw.contains("unsupported"))
            assertFalse(raw.contains("missing-1"))
        }
    }

    /**
     * OPT-EVAL-04-01: an ordinary run without rejections or revision records
     * the same three attributes with zero values and must not throw.
     */
    @Test
    fun runMetricsRecordZeroQualityMetricsForACleanRun() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-2", "get_expert_info"))
                    ),
                    AgentModelResponse.Final(
                        AgentReport(
                            summary = "Nothing rejected.",
                            findings = listOf(
                                finding(
                                    evidence = listOf(
                                        AgentEvidence(
                                            type = AgentEvidenceType.Statistic,
                                            observation = "TCP dominates.",
                                            sourceToolCallId = "call-1",
                                            metric = "protocolHierarchy",
                                            observedValue = "tcp"
                                        ),
                                        AgentEvidence(
                                            type = AgentEvidenceType.ExpertInfo,
                                            observation = "Frame 7 reports a retransmission.",
                                            sourceToolCallId = "call-2",
                                            frameNumber = 7L
                                        )
                                    ),
                                    confidence = AgentConfidence.High
                                )
                            ),
                            completeness = AgentReportCompleteness.Complete
                        )
                    )
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertTrue(outcome is AgentRunOutcome.Completed)

            val attributes = runMetricsAttributes(recorder)
            assertEquals("0.0000", attributes.getString("citationRejectionRate"))
            assertEquals("0", attributes.getString("revisionTriggered"))
            assertEquals(
                "High:1,Medium:0,Low:0,Unknown:0",
                attributes.getString("confidenceDistribution")
            )
        }
    }

    /**
     * OPT-VAL-04-03: a run whose submitted report holds one declared-Negative
     * finding and one declared-Positive finding whose own citation claims an
     * absence must surface the polarity double-track counters — the declared
     * count and the `polarity_claim_conflict` rejection count — on its
     * RunMetrics event, as counts only.
     */
    @Test
    fun runMetricsRecordPolarityDeclaredAndConflictCounts() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val negativeFinding = AgentFinding(
                id = "finding-neg",
                title = "Absence claim",
                severity = AgentFindingSeverity.Warning,
                confidence = AgentConfidence.Medium,
                conclusion = "An absence holds.",
                polarity = AgentFindingPolarity.Negative,
                evidence = listOf(
                    AgentEvidence(
                        AgentEvidenceType.Observation,
                        observation = "Counters were tallied across the capture.",
                        sourceToolCallId = "call-1"
                    )
                )
            )
            val positiveFinding = AgentFinding(
                id = "finding-pos",
                title = "Presence claim contradicted",
                severity = AgentFindingSeverity.Warning,
                confidence = AgentConfidence.Medium,
                conclusion = "A presence holds.",
                polarity = AgentFindingPolarity.Positive,
                evidence = listOf(
                    AgentEvidence(
                        AgentEvidenceType.Observation,
                        observation = "No retransmissions were observed.",
                        sourceToolCallId = "call-1"
                    )
                )
            )
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(
                        report = AgentReport(
                            summary = "Polarity report.",
                            findings = listOf(negativeFinding, positiveFinding),
                            completeness = AgentReportCompleteness.Complete
                        )
                    )
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertTrue(outcome is AgentRunOutcome.Completed)

            val attributes = runMetricsAttributes(recorder)
            // One declared-Negative finding among the citations submitted this
            // round, and one conflict rejection raised against the Positive
            // finding's self-contradicting citation.
            assertEquals("1", attributes.getString("negativePolarityDeclared"))
            assertEquals("1", attributes.getString("negativePolarityConflict"))
            // Counts only: no observation prose rides on the event.
            val raw = attributes.toString()
            assertFalse(raw.contains("No retransmissions were observed."))
            assertFalse(raw.contains("Counters were tallied"))
        }
    }

    /** The single RunMetrics event's attributes, from the persisted export. */
    private fun runMetricsAttributes(recorder: AgentDiagnosticsRecorder): JSONObject {
        val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
        return (0 until events.length())
            .map { events.getJSONObject(it) }
            .single { it.getString("eventType") == "RunMetrics" }
            .getJSONObject("attributes")
    }

    // ------------------------------------------- playbook check coverage gate
    // (OPT-VAL-01-02)

    private fun twoCheckPlaybook(): AgentPlaybook = AgentPlaybook(
        id = "tcp-health",
        version = 1,
        title = "TCP health",
        intentHints = listOf("capture health"),
        protocols = listOf("tcp"),
        initialTools = emptyList(),
        requiredFields = emptyList(),
        checks = listOf(
            AgentPlaybookCheck("check-a", "Find TCP retransmissions", listOf("get_expert_info")),
            AgentPlaybookCheck("check-b", "Read conversation endpoints", listOf("query_packet_summaries"))
        ),
        successPath = emptyList(),
        failureBranches = emptyList(),
        requiredLimitations = emptyList(),
        outputSections = emptyList()
    )

    private fun checkBoundPlanDeclaration(): AgentToolCall = AgentToolCall(
        "plan-1",
        DeclareAnalysisPlanTool.NAME,
        mapOf(
            "goal" to "Assess capture health",
            "steps" to listOf(
                mapOf(
                    "tool" to "get_expert_info",
                    "purpose" to "Find retransmissions",
                    "checkId" to "check-a"
                ),
                mapOf(
                    "tool" to "query_packet_summaries",
                    "purpose" to "Read the endpoints",
                    "checkId" to "check-b"
                )
            )
        )
    )

    private fun legacyPlanDeclaration(): AgentToolCall = AgentToolCall(
        "plan-1",
        DeclareAnalysisPlanTool.NAME,
        mapOf(
            "goal" to "Assess capture health",
            "steps" to listOf(
                mapOf("tool" to "get_expert_info", "purpose" to "Find retransmissions")
            )
        )
    )

    private fun submitCall(id: String, summary: String) = AgentToolCall(
        id,
        SubmitReportTool.NAME,
        mapOf(
            "summary" to summary,
            "findings" to emptyList<Any?>(),
            "questionAlignment" to emptyList<Any?>()
        )
    )

    private val gapLimitationA =
        "Playbook check \"check-a\" (Find TCP retransmissions) was not covered " +
            "before the report was finalized."
    private val gapLimitationB =
        "Playbook check \"check-b\" (Read conversation endpoints) was not covered " +
            "before the report was finalized."

    private fun gateTools(): Triple<DeclareAnalysisPlanTool, FakeTool, FakeTool> = Triple(
        DeclareAnalysisPlanTool(),
        FakeTool("get_expert_info") { _, context ->
            context.success(
                mapOf("items" to listOf(mapOf("frameNumber" to 7L, "severity" to "warning"))),
                returnedCount = 1L,
                totalCount = 1L
            )
        },
        FakeTool("query_packet_summaries") { _, context ->
            context.success(mapOf("frames" to listOf(3L)), returnedCount = 1L, totalCount = 1L)
        }
    )

    /**
     * Gate core (OPT-VAL-01-02): the first submit is refused once, naming
     * both uncovered check ids as this call's tool error; the model then
     * really runs one missing check's tool and re-submits.  The second submit
     * is accepted, the covered check contributes no gap limitation, and the
     * still-uncovered one does — plus the diagnostics the §2.3 rule demands.
     */
    @Test
    fun playbookCheckGateRefusesTheFirstSubmitAndAcceptsTheFixedResubmission() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val (planTool, expert, summaries) = gateTools()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Premature report."))),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("expert-1", "get_expert_info"))),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-2", "Final report.")))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), expert, summaries),
                playbook = twoCheckPlaybook(),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Final report.", completed.report.summary)
            assertEquals(AgentStopReason.ModelFinal, completed.stopReason)
            assertEquals(1, expert.executionCount)
            assertTrue(completed.report.limitations.contains(gapLimitationB))
            assertFalse(completed.report.limitations.any { it.contains("check-a") })

            // The refused submit reached the model as this call's tool error,
            // naming both check ids with the structured gap list.
            val rejected = client.requests[2].messages.single {
                it.role == AgentModelMessageRole.Tool && it.toolCallId == "submit-1"
            }.toolResult
            assertNotNull(rejected)
            assertFalse(rejected!!.success)
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, rejected.error?.code)
            assertEquals(
                "playbook_check_coverage_gap",
                rejected.error?.details?.get("reason")
            )
            val gapIds = (rejected.error?.details?.get("uncoveredChecks") as? List<*>)
                ?.map { (it as Map<*, *>)["id"] }
            assertEquals(listOf("check-a", "check-b"), gapIds)
            assertTrue(rejected.error?.userMessage?.contains("\"check-a\"") == true)
            assertTrue(rejected.error?.userMessage?.contains("\"check-b\"") == true)

            // Diagnostics: one rejection record, and the accepted second
            // submit says so with its disposition, ids, and gap count only.
            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val eventList = (0 until events.length()).map { events.getJSONObject(it) }
            val rejection = eventList.single {
                it.optString("status") == "playbook_check_coverage_rejected"
            }
            assertEquals(
                "check-a,check-b",
                rejection.getJSONObject("attributes").getString("uncoveredCheckIds")
            )
            val submitted = eventList.single {
                it.optString("status") == "report_submitted"
            }.getJSONObject("attributes")
            assertEquals("finalized_with_gaps", submitted.getString("checkCoverage"))
            assertEquals("check-b", submitted.getString("uncoveredCheckIds"))
            assertEquals("1", runMetricsAttributes(recorder).getString("planCoverageGaps"))
        }
    }

    /**
     * The model's other legal exit: re-submit unchanged.  Accepted — the gate
     * refuses exactly once per run — and every still-uncovered check is
     * narrated as a host-authored limitation.
     */
    @Test
    fun playbookCheckGateFinalizesAnUnchangedResubmissionWithGapLimitations() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val (planTool, expert, summaries) = gateTools()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "As-is report."))),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-2", "As-is report.")))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), expert, summaries),
                playbook = twoCheckPlaybook()
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("As-is report.", completed.report.summary)
            assertEquals(3, client.requests.size)
            assertTrue(completed.report.limitations.contains(gapLimitationA))
            assertTrue(completed.report.limitations.contains(gapLimitationB))
            assertEquals(0, expert.executionCount)
        }
    }

    /**
     * Escape valve (policy.enforcePlaybookCheckCoverage = false): the first
     * submit is accepted unchanged — no rejection event, no extra
     * attributes on `report_submitted` (its pre-gate byte shape), no gap
     * limitation, and the metric reads a pinned 0.
     */
    @Test
    fun playbookCheckCoverageValveOffRestoresThePreGateBehaviour() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val (planTool, expert, summaries) = gateTools()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Valve-off report.")))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), expert, summaries),
                policy = AgentPolicy(enforcePlaybookCheckCoverage = false),
                playbook = twoCheckPlaybook(),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Valve-off report.", completed.report.summary)
            assertEquals(2, client.requests.size)
            assertFalse(completed.report.limitations.any { it.contains("Playbook check") })

            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val eventList = (0 until events.length()).map { events.getJSONObject(it) }
            assertTrue(eventList.none { it.optString("status") == "playbook_check_coverage_rejected" })
            val submitted = eventList.single { it.optString("status") == "report_submitted" }
                .getJSONObject("attributes")
            assertFalse(submitted.has("checkCoverage"))
            assertFalse(submitted.has("playbookCheckGaps"))
            assertEquals("0", runMetricsAttributes(recorder).getString("planCoverageGaps"))
        }
    }

    /** Free questions get no rule 2: a non-matching question never gates. */
    @Test
    fun freeQuestionsSkipThePlaybookCheckGate() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val (planTool, expert, summaries) = gateTools()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Free-form report.")))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), expert, summaries),
                playbook = twoCheckPlaybook()
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Free-form report.", completed.report.summary)
            assertEquals(2, client.requests.size)
            assertFalse(completed.report.limitations.any { it.contains("Playbook check") })
        }
    }

    /**
     * Degradation per the optional-with-default contract: a playbook-hit run
     * whose plan carries no checkId cannot be attributed, so the host records
     * the gaps as limitations on the first submit instead of refusing.
     */
    @Test
    fun legacyPlanWithoutCheckIdsRecordsLimitationsInsteadOfRefusing() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val (planTool, expert, summaries) = gateTools()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(legacyPlanDeclaration())),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Legacy report.")))
                )
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), expert, summaries),
                playbook = twoCheckPlaybook()
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Legacy report.", completed.report.summary)
            assertEquals(2, client.requests.size)
            assertTrue(completed.report.limitations.contains(gapLimitationA))
            assertTrue(completed.report.limitations.contains(gapLimitationB))
        }
    }

    /**
     * OPT-VAL-01-02 RunMetrics attribute: the count of playbook checks still
     * uncovered at report acceptance rides the metrics event, counts and
     * stable ids only — never check descriptions or report prose.
     */
    @Test
    fun runMetricsCarriesPlaybookCheckCoverageGapCount() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val (planTool, expert, summaries) = gateTools()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(legacyPlanDeclaration())),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Counted report.")))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), expert, summaries),
                playbook = twoCheckPlaybook(),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertTrue(outcome is AgentRunOutcome.Completed)

            val attributes = runMetricsAttributes(recorder)
            assertEquals("2", attributes.getString("planCoverageGaps"))
            // Counts and ids only: no check description or report text.
            val raw = attributes.toString()
            assertFalse(raw.contains("Find TCP retransmissions"))
            assertFalse(raw.contains("Counted report."))

            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val submitted = (0 until events.length())
                .map { events.getJSONObject(it) }
                .single { it.optString("status") == "report_submitted" }
                .getJSONObject("attributes")
            assertEquals("unattributable_gaps", submitted.getString("checkCoverage"))
            assertEquals("check-a,check-b", submitted.getString("uncoveredCheckIds"))
        }
    }

    /**
     * OPT-VAL-01-03 matrix, case 5: a refused model that re-declares its plan.
     * Exercises the replace semantics of [AgentLoop]'s acceptDeclaredPlan —
     * the second declaration clears the completed/successful step tracking, so
     * coverage is recomputed from the replacement plan's own indices — while
     * also pinning two accounting decisions from the task spec: the refusal
     * consumes no plan step (the progress list shows no event for the refused
     * submits) and counts as no invalid-argument retry (a genuine bad-argument
     * call follows it on a 1-retry budget; if the refusal had also counted,
     * the second failure would exceed the budget and stop the run).
     */
    @Test
    fun rejectedModelCanReDeclareACheckBoundPlanAndSubmitWithCleanCoverage() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val (planTool, expert, summaries) = gateTools()
            // Not in any plan: its bad-arguments rejection touches neither the
            // plan tracker nor the tool body.
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 3L), returnedCount = 1L, totalCount = 1L)
            }
            val planProgress = mutableListOf<Pair<Int, Int>>()
            val listener = object : AgentRunListener {
                override fun onAnalysisPlan(plan: AgentAnalysisPlan, completedSteps: Int) {
                    planProgress += plan.steps.size to completedSteps
                }
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Premature report."))),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("bad-1", "get_capture_overview", mapOf("extraArg" to 1)))
                    ),
                    // Replacement plan: three steps so the two covering calls
                    // below do NOT complete the plan — a completed plan drops
                    // the later submit turn before the gate can see it.
                    AgentModelResponse.ToolCalls(listOf(checkBoundReplacementPlanDeclaration())),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("summaries-1", "query_packet_summaries"))
                    ),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("expert-1", "get_expert_info"))),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-2", "Re-planned report.")))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), expert, summaries, overview),
                policy = AgentPolicy(maxInvalidArgumentRetries = 1),
                listener = listener,
                playbook = twoCheckPlaybook(),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Analyze capture health",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Re-planned report.", completed.report.summary)
            assertEquals(AgentStopReason.ModelFinal, completed.stopReason)
            // Every scripted turn was spent: neither the refusal nor the one
            // genuine bad-argument call ended the run on the 1-retry budget.
            assertEquals(7, client.requests.size)
            assertEquals(0, overview.executionCount) // bad-1 was refused before the tool
            assertEquals(1, expert.executionCount)
            assertEquals(1, summaries.executionCount)

            // Declared 2 steps → (only the refusal and the unplanned bad call
            // in between, no progress) → re-declared 3 steps back at 0 → the
            // two executed steps.  The reset to 0 is acceptDeclaredPlan's
            // clearing of the completed/successful sets.
            assertEquals(listOf(2 to 0, 3 to 0, 3 to 1, 3 to 2), planProgress)

            // Coverage from the replacement plan: both checks covered, so the
            // acceptance narrates nothing — and the still-unexecuted third
            // step is silent because ModelFinal keeps rule 1 off.
            assertTrue(completed.report.limitations.none { it.contains("Playbook check") })
            assertTrue(completed.report.limitations.none { it.contains("Plan step") })

            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val eventList = (0 until events.length()).map { events.getJSONObject(it) }
            // The refusal happened exactly once, before the re-declaration.
            assertEquals(1, eventList.count {
                it.optString("status") == "playbook_check_coverage_rejected"
            })
            val submitted = eventList.single {
                it.optString("status") == "report_submitted"
            }.getJSONObject("attributes")
            assertEquals("covered", submitted.getString("checkCoverage"))
            assertEquals("0", runMetricsAttributes(recorder).getString("planCoverageGaps"))
        }
    }

    /**
     * OPT-VAL-01-03 matrix, case 6: "自由问题只做规则 1" as a combined
     * scenario.  A non-matching question on the gated playbook, a check-bound
     * plan left partially executed, and a step-budget cut — rule 1 must
     * narrate the unexecuted step while rule 2 stays entirely absent: no
     * coverage limitation, no gate diagnostic, no submit at all.
     */
    @Test
    fun freeQuestionCutShortKeepsRuleOneLimitationsWithoutGatingOnChecks() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val (planTool, expert, summaries) = gateTools()
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 3L), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("expert-1", "get_expert_info"))),
                    AgentModelResponse.ToolCalls(listOf(AgentToolCall("overview-1", "get_capture_overview"))),
                    AgentModelResponse.Final(AgentReport(summary = "Cut-short free report."))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(planTool, SubmitReportTool(), expert, summaries, overview),
                policy = AgentPolicy(maxSteps = 2),
                playbook = twoCheckPlaybook(),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.MaxStepsReached, completed.stopReason)
            assertEquals("Cut-short free report.", completed.report.summary)
            assertEquals(4, client.requests.size)
            assertEquals(1, expert.executionCount)

            // Rule 1: the unexecuted summaries step is narrated with its plan
            // purpose, and the executed expert step is not.
            assertTrue(
                completed.report.limitations.any {
                    it == "Plan step \"query_packet_summaries\" (Read the endpoints) was not " +
                        "executed before the run stopped (MaxStepsReached)."
                }
            )
            assertTrue(completed.report.limitations.none { it.contains("Plan step \"get_expert_info\"") })
            // Rule 2: a free question is outside the gate — even though this
            // run would leave check-b uncovered on every shape of the verdict.
            assertTrue(completed.report.limitations.none { it.contains("Playbook check") })

            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val eventList = (0 until events.length()).map { events.getJSONObject(it) }
            assertTrue(eventList.none { it.optString("status").startsWith("playbook_check_coverage") })
            assertTrue(eventList.none { it.optString("status") == "report_submitted" })
            assertEquals("0", runMetricsAttributes(recorder).getString("planCoverageGaps"))
        }
    }

    /**
     * OPT-VAL-01-03 matrix, case 7: valve-off regression equivalence.  The
     * *same* script whose second turn the gate refuses when on — check-bound
     * plan, submit with zero checks executed, fix, resubmit — must complete
     * on the FIRST submit with enforcement off, and the `report_submitted`
     * record must keep its exact pre-gate shape: only the two original
     * attributes, no coverage disposition, ids, rejection event, limitation,
     * or metric.
     */
    @Test
    fun valveOffAcceptsTheWouldBeRejectedScriptOnTheFirstSubmitWithThePreGateRecordShape() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val (planTool, expert, summaries) = gateTools()
                val client = RecordingClient(
                    listOf(
                        AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                        AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Valve-off first submit."))),
                        AgentModelResponse.ToolCalls(listOf(AgentToolCall("expert-1", "get_expert_info"))),
                        AgentModelResponse.ToolCalls(listOf(submitCall("submit-2", "Never reached.")))
                    )
                )
                val recorder = AgentDiagnosticsRecorder(
                    directory = temporaryFolder.newFolder(),
                    clock = { 1_000L }
                )

                val outcome = loop(
                    harness,
                    client,
                    tools = listOf(planTool, SubmitReportTool(), expert, summaries),
                    policy = AgentPolicy(enforcePlaybookCheckCoverage = false),
                    playbook = twoCheckPlaybook(),
                    diagnostics = recorder.beginRun(sessionId = "run_test")
                ).run(
                    "Analyze capture health",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )

                val completed = outcome as AgentRunOutcome.Completed
                assertEquals("Valve-off first submit.", completed.report.summary)
                // The two turns the on-valve run spends on refusal and fix
                // are never requested: the first submit already ends the run.
                assertEquals(2, client.requests.size)
                assertEquals(0, expert.executionCount)
                assertTrue(completed.report.limitations.none { it.contains("Playbook check") })

                val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
                val eventList = (0 until events.length()).map { events.getJSONObject(it) }
                assertTrue(eventList.none { it.optString("status").startsWith("playbook_check_coverage") })
                val submitted = eventList.single {
                    it.optString("status") == "report_submitted"
                }.getJSONObject("attributes")
                // Byte-for-byte where observable: the record carries exactly
                // the attributes it had before the gate existed.
                assertEquals(
                    setOf("transport", "findingCount"),
                    submitted.keySet().toSet()
                )
                assertEquals("0", runMetricsAttributes(recorder).getString("planCoverageGaps"))
            }
        }

    /**
     * OPT-VAL-01-03 matrix, case 8: the gate never evaluates a delegated
     * child's calls.  The parent declares a check-bound plan and executes
     * nothing, then delegates; the child's rogue submit would be maximally
     * gate-eligible (attributable plan, zero covered checks) were it not for
     * the delegation guard — orchestration inside a child is refused as
     * `delegation_recursion_blocked`, and no gate artefact appears anywhere.
     */
    @Test
    fun delegatedChildSubmitAttemptIsRefusedAsForbiddenOrchestrationNotByTheCoverageGate() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val (planTool, expert, summaries) = gateTools()
                val childReport = AgentReport(summary = "Child investigation finished.")
                val parentReport = childReport.copy(summary = "Parent used the child run.")
                val client = RecordingClient(
                    listOf(
                        AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                        AgentModelResponse.ToolCalls(
                            listOf(
                                AgentToolCall(
                                    "delegate-1",
                                    DelegateInvestigationTool.NAME,
                                    mapOf("goal" to "Read the endpoints", "maxTurns" to 3)
                                )
                            )
                        ),
                        AgentModelResponse.ToolCalls(
                            listOf(submitCall("child-submit-1", "Child submit attempt."))
                        ),
                        AgentModelResponse.Final(childReport),
                        AgentModelResponse.Final(parentReport)
                    )
                )
                val recorder = AgentDiagnosticsRecorder(
                    directory = temporaryFolder.newFolder(),
                    clock = { 1_000L }
                )

                val outcome = loop(
                    harness,
                    client,
                    tools = listOf(planTool, SubmitReportTool(), expert, summaries, DelegateInvestigationTool()),
                    playbook = twoCheckPlaybook(),
                    diagnostics = recorder.beginRun(sessionId = "run_test")
                ).run(
                    "Analyze capture health",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )

                val completed = outcome as AgentRunOutcome.Completed
                assertEquals("Parent used the child run.", completed.report.summary)

                // The child's transcript (request 4, index 3) carries the
                // refusal of its submit: the delegation block, not a coverage
                // gap.  The parent never sees the child's orchestration probe.
                val blocked = client.requests[3].messages
                    .single { it.toolCallId == "child-submit-1" }
                    .toolResult
                assertNotNull(blocked)
                assertFalse(blocked!!.success)
                assertEquals(
                    "delegation_recursion_blocked",
                    blocked.error?.details?.get("reason")
                )

                val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
                val eventList = (0 until events.length()).map { events.getJSONObject(it) }
                assertTrue(eventList.none { it.optString("status").startsWith("playbook_check_coverage") })
                assertTrue(eventList.none { it.optString("status") == "report_submitted" })
                // The parent's own final report narrates no check gaps: rule 2
                // only speaks at an accepted gated submit, and rule 1 stays
                // silent for the ModelFinal both reports carry.
                assertTrue(completed.report.limitations.none { it.contains("Playbook check") })
                assertTrue(completed.report.limitations.none { it.contains("Plan step") })
                assertEquals("0", runMetricsAttributes(recorder).getString("planCoverageGaps"))
            }
        }

    /** The re-declared counterpart of [checkBoundPlanDeclaration] (case 5). */
    private fun checkBoundReplacementPlanDeclaration(): AgentToolCall = AgentToolCall(
        "plan-2",
        DeclareAnalysisPlanTool.NAME,
        mapOf(
            "goal" to "Assess capture health after re-plan",
            "steps" to listOf(
                mapOf(
                    "tool" to "query_packet_summaries",
                    "purpose" to "Read the endpoints",
                    "checkId" to "check-b"
                ),
                mapOf(
                    "tool" to "get_expert_info",
                    "purpose" to "Find retransmissions",
                    "checkId" to "check-a"
                ),
                mapOf(
                    "tool" to "query_packet_summaries",
                    "purpose" to "Re-read the endpoints",
                    "checkId" to "check-b"
                )
            )
        )
    )

    // ---------------------------------------- OPT-VAL-02-03 signal coverage gate

    /**
     * A baseline payload that mints exactly two signals — one health_problems
     * and one protocol_share — the same shapes OPT-VAL-02-02 pins in its
     * annotation tests.
     */
    private val twoSignalOverviewData: Map<String, Any?> = mapOf(
        "frameCount" to 100,
        "health" to mapOf(
            "internet" to mapOf("problems" to 3, "severity" to "warning")
        ),
        "protocolHierarchy" to listOf(
            mapOf("name" to "TCP", "packetPercent" to 61.0)
        )
    )

    private fun signalOverviewTool(): FakeTool = FakeTool("get_capture_overview") { _, context ->
        context.success(twoSignalOverviewData, returnedCount = 1L, totalCount = 1L)
    }

    /** The ids the extractor gives [twoSignalOverviewData], in host order. */
    private fun twoSignalIds(): List<String> = AgentSignalExtractor().extract(
        listOf(
            HostCallPayload(
                toolCallId = "overview-1",
                toolName = "get_capture_overview",
                success = true,
                data = twoSignalOverviewData
            )
        )
    ).signalIds

    private fun signalGapLineOf(signalId: String): String =
        "Host-enumerated overview signal $signalId "

    private fun submitCallCovering(id: String, summary: String, signalIds: List<String>) =
        AgentToolCall(
            id,
            SubmitReportTool.NAME,
            mapOf(
                "summary" to summary,
                "questionAlignment" to emptyList<Any?>(),
                "findings" to listOf(
                    mapOf(
                        "id" to "finding-sig",
                        "title" to "Reviewed the baseline",
                        "severity" to "Warning",
                        "confidence" to "Medium",
                        "conclusion" to "Both families were reviewed.",
                        "polarity" to "Positive",
                        "evidence" to listOf(
                            mapOf(
                                "type" to "Observation",
                                "observation" to "Baseline families reviewed.",
                                "sourceToolCallId" to "overview-1"
                            )
                        ),
                        "relatedSignals" to signalIds
                    )
                )
            )
        )

    /** The `report_submitted` attributes of the single accepted submit. */
    private fun reportSubmittedAttributes(recorder: AgentDiagnosticsRecorder): JSONObject {
        val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
        return (0 until events.length())
            .map { events.getJSONObject(it) }
            .single { it.optString("status") == "report_submitted" }
            .getJSONObject("attributes")
    }

    private fun diagnosticsStatuses(recorder: AgentDiagnosticsRecorder): List<String> {
        val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
        return (0 until events.length()).map { events.getJSONObject(it).optString("status") }
    }

    /**
     * Gate core (OPT-VAL-02-03) on a free question — rule 3 is *not*
     * playbook-scoped: the first submit ignores both enumerated signals and
     * is refused once, naming their ids; the resubmit attaches them through
     * a finding's relatedSignals and is accepted with no gap limitation.
     */
    @Test
    fun signalCoverageGateRefusesASubmitThatIgnoresTheEnumeratedSignalsAndAcceptsTheFixedResubmission() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val ids = twoSignalIds()
                assertEquals(2, ids.size)
                val client = RecordingClient(
                    listOf(
                        AgentModelResponse.ToolCalls(
                            listOf(AgentToolCall("overview-1", "get_capture_overview"))
                        ),
                        AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Premature."))),
                        AgentModelResponse.ToolCalls(
                            listOf(submitCallCovering("submit-2", "Covered report.", ids))
                        )
                    )
                )
                val recorder = AgentDiagnosticsRecorder(
                    directory = temporaryFolder.newFolder(),
                    clock = { 1_000L }
                )

                val outcome = loop(
                    harness,
                    client,
                    tools = listOf(SubmitReportTool(), signalOverviewTool()),
                    diagnostics = recorder.beginRun(sessionId = "run_test")
                ).run(
                    "Inspect this trace",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )

                val completed = outcome as AgentRunOutcome.Completed
                assertEquals("Covered report.", completed.report.summary)
                assertEquals(3, client.requests.size)

                // The refusal reached the model as this call's tool error,
                // naming both signal ids with their kind/value short form.
                val rejected = client.requests[2].messages.single {
                    it.role == AgentModelMessageRole.Tool && it.toolCallId == "submit-1"
                }.toolResult
                assertNotNull(rejected)
                assertFalse(rejected!!.success)
                assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, rejected.error?.code)
                assertEquals(
                    "signal_coverage_gap",
                    rejected.error?.details?.get("reason")
                )
                val gapIds = (rejected.error?.details?.get("unaddressedSignals") as? List<*>)
                    ?.map { (it as Map<*, *>)["id"] }
                assertEquals(ids, gapIds)
                assertTrue(rejected.error?.userMessage?.contains(ids[0]) == true)
                assertTrue(rejected.error?.userMessage?.contains(ids[1]) == true)

                // Accepted resubmission: exactly one rejection record, and the
                // final report narrates no signal gap.
                assertEquals(1, diagnosticsStatuses(recorder).count { it == "signal_coverage_rejected" })
                assertTrue(
                    completed.report.limitations.none { it.contains(signalGapLineOf(ids[0])) }
                )
                val submitted = reportSubmittedAttributes(recorder)
                assertEquals("covered", submitted.getString("signalCoverage"))
                assertEquals("1", submitted.getString("findingCount"))
                assertEquals("0", runMetricsAttributes(recorder).getString("signalCoverageGaps"))
            }
        }

    /**
     * The model's other legal exit: re-submit unchanged.  Accepted — one shot
     * per run across both coverage kinds — and every still-unaddressed signal
     * is narrated by the rule-3 net as a host-authored limitation.
     */
    @Test
    fun signalCoverageGateFinalizesAnUnchangedResubmissionWithGapLimitations() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val ids = twoSignalIds()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "As-is report."))),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-2", "As-is report.")))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(SubmitReportTool(), signalOverviewTool()),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("As-is report.", completed.report.summary)
            assertEquals(3, client.requests.size)
            for (id in ids) {
                assertTrue(
                    "limitation for $id",
                    completed.report.limitations.any { line ->
                        line.startsWith(signalGapLineOf(id)) &&
                            line.endsWith("was not addressed by any finding.")
                    }
                )
            }

            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val rejection = (0 until events.length())
                .map { events.getJSONObject(it) }
                .single { it.optString("status") == "signal_coverage_rejected" }
                .getJSONObject("attributes")
            assertEquals("signal_coverage_gap", rejection.getString("reason"))
            assertEquals(ids.joinToString(","), rejection.getString("unaddressedSignalIds"))

            val submitted = reportSubmittedAttributes(recorder)
            assertEquals("finalized_with_gaps", submitted.getString("signalCoverage"))
            assertEquals("2", submitted.getString("signalCoverageGaps"))
            assertEquals(ids.joinToString(","), submitted.getString("unaddressedSignalIds"))
            assertEquals("2", runMetricsAttributes(recorder).getString("signalCoverageGaps"))
        }
    }

    /**
     * Degradation per design §5.2's 降级兼容 bullet and §3's contract: when
     * the client negotiated structured output off and the submitted report
     * uses none of the agent-report-2 structured fields, the gaps generate
     * limitations but never a refusal — the text-shaped path cannot deadlock
     * a revision on a field it may not have.
     */
    @Test
    fun signalCoverageGateRecordsLimitationsWithoutRefusingWhenStructuredOutputIsUnavailable() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val ids = twoSignalIds()
                val client = RecordingClient(
                    listOf(
                        AgentModelResponse.ToolCalls(
                            listOf(AgentToolCall("overview-1", "get_capture_overview"))
                        ),
                        AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Plain report.")))
                    ),
                    capabilities = AiModelCapabilities(structuredOutput = false)
                )
                val recorder = AgentDiagnosticsRecorder(
                    directory = temporaryFolder.newFolder(),
                    clock = { 1_000L }
                )

                val outcome = loop(
                    harness,
                    client,
                    tools = listOf(SubmitReportTool(), signalOverviewTool()),
                    diagnostics = recorder.beginRun(sessionId = "run_test")
                ).run(
                    "Inspect this trace",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )

                val completed = outcome as AgentRunOutcome.Completed
                assertEquals("Plain report.", completed.report.summary)
                // No refusal: the run spent exactly its two scripted turns.
                assertEquals(2, client.requests.size)
                assertTrue(diagnosticsStatuses(recorder).none { it == "signal_coverage_rejected" })
                for (id in ids) {
                    assertTrue(
                        "limitation for $id",
                        completed.report.limitations.any { it.startsWith(signalGapLineOf(id)) }
                    )
                }
                val submitted = reportSubmittedAttributes(recorder)
                assertEquals("unattributable_gaps", submitted.getString("signalCoverage"))
                // The metric counts the degradation path too.
                assertEquals("2", runMetricsAttributes(recorder).getString("signalCoverageGaps"))
            }
        }

    /**
     * The other attribution branch, pinned: a backend that negotiated
     * structured output off is still refused over a report that *proves*
     * the channel by using it — a finding carrying `relatedSignals` that
     * covers one signal and ignores the other is a model choice, not a
     * capability gap, so the gate names only the still-unaddressed id.
     */
    @Test
    fun structuredFieldsInASubmittedReportAttributeTheGateEvenWithoutTheCapability() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val ids = twoSignalIds()
                val client = RecordingClient(
                    listOf(
                        AgentModelResponse.ToolCalls(
                            listOf(AgentToolCall("overview-1", "get_capture_overview"))
                        ),
                        AgentModelResponse.ToolCalls(
                            listOf(submitCallCovering("submit-1", "Half covered.", ids.take(1)))
                        ),
                        AgentModelResponse.ToolCalls(
                            listOf(submitCallCovering("submit-2", "Fully covered.", ids))
                        )
                    ),
                    capabilities = AiModelCapabilities(structuredOutput = false)
                )
                val recorder = AgentDiagnosticsRecorder(
                    directory = temporaryFolder.newFolder(),
                    clock = { 1_000L }
                )

                val outcome = loop(
                    harness,
                    client,
                    tools = listOf(SubmitReportTool(), signalOverviewTool()),
                    diagnostics = recorder.beginRun(sessionId = "run_test")
                ).run(
                    "Inspect this trace",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )

                val completed = outcome as AgentRunOutcome.Completed
                assertEquals("Fully covered.", completed.report.summary)
                assertEquals(1, diagnosticsStatuses(recorder).count { it == "signal_coverage_rejected" })
                val rejected = client.requests[2].messages.single {
                    it.role == AgentModelMessageRole.Tool && it.toolCallId == "submit-1"
                }.toolResult
                assertEquals("signal_coverage_gap", rejected!!.error?.details?.get("reason"))
                val gapIds = (rejected.error?.details?.get("unaddressedSignals") as? List<*>)
                    ?.map { (it as Map<*, *>)["id"] }
                assertEquals(listOf(ids[1]), gapIds)
                assertTrue(
                    completed.report.limitations.none { it.contains(signalGapLineOf(ids[1])) }
                )
                assertEquals("0", runMetricsAttributes(recorder).getString("signalCoverageGaps"))
            }
        }

    /**
     * A report that arrives as a free-text Final (no `submit_report` at all)
     * can never be refused — there is no acceptance site — so rule 3 speaks
     * only through the validation net, with the same limitation prose.
     */
    @Test
    fun freeTextFinalReportsNeverMeetARefusalButTheNetStillEnumeratesTheirGaps() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val ids = twoSignalIds()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Prose conclusion."))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(signalOverviewTool()),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Prose conclusion.", completed.report.summary)
            assertTrue(diagnosticsStatuses(recorder).none { it == "signal_coverage_rejected" })
            assertTrue(diagnosticsStatuses(recorder).none { it == "report_submitted" })
            for (id in ids) {
                assertTrue(
                    "limitation for $id",
                    completed.report.limitations.any { it.startsWith(signalGapLineOf(id)) }
                )
            }
        }
    }

    /**
     * The one-shot is joint across the two coverage kinds and the refusal
     * lists both gap kinds: a playbook-hit run whose plan bound two checks
     * (executed neither) and whose baseline enumerated two signals meets a
     * single refusal naming checks and signals, then an unchanged resubmit
     * is accepted with both kinds of limitation.
     */
    @Test
    fun unifiedGateRefusesOnceNamingBothCheckAndSignalGapsAndRecordsBothDispositions() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val (planTool, expert, summaries) = gateTools()
                val ids = twoSignalIds()
                val client = RecordingClient(
                    listOf(
                        AgentModelResponse.ToolCalls(listOf(checkBoundPlanDeclaration())),
                        AgentModelResponse.ToolCalls(
                            listOf(AgentToolCall("overview-1", "get_capture_overview"))
                        ),
                        AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Both kinds open."))),
                        AgentModelResponse.ToolCalls(listOf(submitCall("submit-2", "Both kinds open.")))
                    )
                )
                val recorder = AgentDiagnosticsRecorder(
                    directory = temporaryFolder.newFolder(),
                    clock = { 1_000L }
                )

                val outcome = loop(
                    harness,
                    client,
                    tools = listOf(planTool, SubmitReportTool(), expert, summaries, signalOverviewTool()),
                    playbook = twoCheckPlaybook(),
                    diagnostics = recorder.beginRun(sessionId = "run_test")
                ).run(
                    "Analyze capture health",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )

                val completed = outcome as AgentRunOutcome.Completed
                assertEquals("Both kinds open.", completed.report.summary)
                // One refusal, two lists.
                val rejected = client.requests[3].messages.single {
                    it.role == AgentModelMessageRole.Tool && it.toolCallId == "submit-1"
                }.toolResult
                assertFalse(rejected!!.success)
                assertEquals(
                    "playbook_check_coverage_gap,signal_coverage_gap",
                    rejected.error?.details?.get("reason")
                )
                assertNotNull(rejected.error?.details?.get("uncoveredChecks"))
                assertNotNull(rejected.error?.details?.get("unaddressedSignals"))
                assertTrue(rejected.error?.userMessage?.contains("check-a") == true)
                assertTrue(rejected.error?.userMessage?.contains(ids[0]) == true)

                // Exactly one rejection record of each kind, none a second time.
                val statuses = diagnosticsStatuses(recorder)
                assertEquals(1, statuses.count { it == "playbook_check_coverage_rejected" })
                assertEquals(1, statuses.count { it == "signal_coverage_rejected" })

                // Accepted resubmit narrates both kinds.
                assertTrue(completed.report.limitations.any { it.contains(gapLimitationA) })
                for (id in ids) {
                    assertTrue(
                        completed.report.limitations.any { it.startsWith(signalGapLineOf(id)) }
                    )
                }
                val submitted = reportSubmittedAttributes(recorder)
                assertEquals("finalized_with_gaps", submitted.getString("checkCoverage"))
                assertEquals("finalized_with_gaps", submitted.getString("signalCoverage"))
                val metrics = runMetricsAttributes(recorder)
                assertEquals("2", metrics.getString("planCoverageGaps"))
                assertEquals("2", metrics.getString("signalCoverageGaps"))
            }
        }

    /**
     * Escape valve (policy.enforceSignalCoverage = false): with signals
     * enumerated and a submit ignoring all of them, the first submit is
     * accepted, no rejection record exists, the `report_submitted` attributes
     * keep their exact pre-gate byte shape, no gap limitation is narrated,
     * and the metric stays 0 — the rule is inert end to end.
     */
    @Test
    fun signalCoverageValveOffAcceptsTheFirstSubmitWithThePreGateRecordShape() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val ids = twoSignalIds()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Valve-off report.")))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(SubmitReportTool(), signalOverviewTool()),
                policy = AgentPolicy(enforceSignalCoverage = false),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val completed = outcome as AgentRunOutcome.Completed
            assertEquals("Valve-off report.", completed.report.summary)
            assertEquals(2, client.requests.size)
            assertTrue(diagnosticsStatuses(recorder).none { it == "signal_coverage_rejected" })
            assertTrue(completed.report.limitations.none { it.contains(signalGapLineOf(ids.first())) })
            val submitted = reportSubmittedAttributes(recorder)
            assertEquals(setOf("transport", "findingCount"), submitted.keySet().toSet())
            assertEquals("0", runMetricsAttributes(recorder).getString("signalCoverageGaps"))
        }
    }

    /** A run that enumerated no signals gives the gate nothing to say. */
    @Test
    fun submitOnARunWithoutEnumeratedSignalsKeepsThePreGateRecordShape() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val quietOverview = FakeTool("get_capture_overview") { _, context ->
                context.success(mapOf("frameCount" to 3L), returnedCount = 1L, totalCount = 1L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Quiet report.")))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(SubmitReportTool(), quietOverview),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(outcome is AgentRunOutcome.Completed)
            val submitted = reportSubmittedAttributes(recorder)
            assertEquals(setOf("transport", "findingCount"), submitted.keySet().toSet())
            assertEquals("0", runMetricsAttributes(recorder).getString("signalCoverageGaps"))
        }
    }

    /**
     * OPT-VAL-02-03 RunMetrics attribute: the count of signals still
     * unaddressed at report acceptance rides the metrics event as a number —
     * the ids live on the `report_submitted` diagnostic, never here.
     */
    @Test
    fun runMetricsCarriesSignalCoverageGapCount() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val ids = twoSignalIds()
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("overview-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-1", "Counted report."))),
                    AgentModelResponse.ToolCalls(listOf(submitCall("submit-2", "Counted report.")))
                )
            )
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.newFolder(),
                clock = { 1_000L }
            )

            val outcome = loop(
                harness,
                client,
                tools = listOf(SubmitReportTool(), signalOverviewTool()),
                diagnostics = recorder.beginRun(sessionId = "run_test")
            ).run(
                "Inspect this trace",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertTrue(outcome is AgentRunOutcome.Completed)

            val attributes = runMetricsAttributes(recorder)
            assertEquals("2", attributes.getString("signalCoverageGaps"))
            // Counts only: ids and prose ride other records.
            val raw = attributes.toString()
            assertFalse(raw.contains("sig-"))
            assertFalse(raw.contains("Host-enumerated"))
            val submitted = reportSubmittedAttributes(recorder)
            assertEquals(ids.joinToString(","), submitted.getString("unaddressedSignalIds"))
        }
    }

    // -------------------------------------------------------------- utilities

    // ------------------------------------------------- OPT-VAL-02-02 wiring

    /**
     * The annotation line exactly as design §5.2 pins it — literal, on purpose:
     * a wording change must fail loudly here, not silently ride along with a
     * production constant.
     */
    private fun hostSignalsLineOf(signalIds: List<String>): String =
        "\nhost-signals: [" + signalIds.joinToString(", ") + "] " +
            "(host-generated bookkeeping, not capture text)"

    /** The signal set one annotated baseline tool message says it carries. */
    private fun extractFromBaselineMessage(message: AgentModelMessage): AgentSignalSet =
        AgentSignalExtractor().extract(
            listOf(
                HostCallPayload(
                    toolCallId = message.toolCallId.orEmpty(),
                    toolName = message.toolName.orEmpty(),
                    success = true,
                    data = checkNotNull(message.toolResult?.data)
                )
            )
        )

    @Test
    fun bootstrapOverviewToolMessageEndsWithAHostSignalsLineEnumeratingItsSignals() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val overviewData = mapOf(
                    "frameCount" to 100,
                    "expertErrorCount" to 0,
                    "expertWarningCount" to 0,
                    "health" to mapOf(
                        "internet" to mapOf("problems" to 3, "severity" to "warning")
                    ),
                    "protocolHierarchy" to listOf(
                        mapOf("name" to "TCP", "packetPercent" to 61.0)
                    )
                )
                val overview = FakeTool("get_capture_overview") { _, context ->
                    context.success(overviewData, returnedCount = 1L, totalCount = 1L)
                }
                val client = RecordingClient(
                    listOf(AgentModelResponse.Final(AgentReport(summary = "Annotated.")))
                )

                loop(harness, client, tools = listOf(overview), bootstrapEnabled = true).run(
                    "Analyze this capture",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )

                val tool = client.requests.single().messages.single {
                    it.role == AgentModelMessageRole.Tool &&
                        it.toolCallId == "host-bootstrap-overview-1"
                }
                val expected = extractFromBaselineMessage(tool)
                // One health_problems and one protocol_share signal, host order.
                assertEquals(2, expected.signals.size)
                assertTrue(
                    "tool message must end with the host-signals line",
                    tool.content.endsWith(hostSignalsLineOf(expected.signalIds))
                )
                assertEquals(1, Regex("host-signals: ").findAll(tool.content).count())
                // The annotation is a line beside the payload, not a rewrite of
                // it: what precedes the line is still the tool's JSON result.
                val json = JSONObject(tool.content.substringBeforeLast("\nhost-signals: "))
                assertEquals(100, json.getInt("frameCount"))
                // Host bookkeeping: the message itself keeps the structural
                // untrusted marker, and its prose marks the appended line's
                // provenance; ids only, no payload text.
                assertTrue(tool.untrustedCaptureData)
                assertTrue(
                    tool.content.contains(
                        "(host-generated bookkeeping, not capture text)"
                    )
                )
                assertTrue(expected.signalIds.all { it.startsWith("sig-") })
            }
        }

    @Test
    fun baselineMessageWithNoSignalsStillPinsAnEmptyHostSignalsLine() = runBlocking {
        // Decision (a) of OPT-VAL-02-02, pinned: the host always says it
        // enumerated. A missing line cannot tell "nothing found" from "never
        // looked", and the unconditional rule keeps the later coverage gate's
        // reading simple; the cost is one ~15-token line.
        AgentToolTestHarness.create().use { harness ->
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(
                    mapOf("frameCount" to 1, "expertErrorCount" to 0, "expertWarningCount" to 0),
                    returnedCount = 1L,
                    totalCount = 1L
                )
            }
            val client = RecordingClient(
                listOf(AgentModelResponse.Final(AgentReport(summary = "Quiet capture.")))
            )

            loop(harness, client, tools = listOf(overview), bootstrapEnabled = true).run(
                "Analyze this capture",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )

            val tool = client.requests.single().messages.single {
                it.role == AgentModelMessageRole.Tool &&
                    it.toolCallId == "host-bootstrap-overview-1"
            }
            assertTrue(extractFromBaselineMessage(tool).isEmpty)
            assertTrue(
                tool.content.endsWith(
                    "\nhost-signals: [] (host-generated bookkeeping, not capture text)"
                )
            )
        }
    }

    @Test
    fun bootstrapExpertToolMessageCarriesTheCumulativeSetTheOverviewMessageDoesNot() =
        runBlocking {
            AgentToolTestHarness.create().use { harness ->
                val overviewData = mapOf(
                    "frameCount" to 100,
                    "expertErrorCount" to 5,
                    "expertWarningCount" to 0,
                    "health" to mapOf(
                        "internet" to mapOf("problems" to 3, "severity" to "warning")
                    ),
                    "protocolHierarchy" to listOf(
                        mapOf("name" to "TCP", "packetPercent" to 61.0)
                    )
                )
                val expertData = mapOf(
                    "groups" to listOf(
                        mapOf("count" to 5, "severity" to "error", "groupKey" to "error/dns"),
                        mapOf("count" to 2, "severity" to "warning", "groupKey" to "warning/http")
                    )
                )
                val overview = FakeTool("get_capture_overview") { _, context ->
                    context.success(overviewData, returnedCount = 1L, totalCount = 1L)
                }
                val expert = FakeTool("get_expert_info", schema = ANY_ARGS_SCHEMA) { _, context ->
                    context.success(expertData, returnedCount = 2L, totalCount = 2L)
                }
                val client = RecordingClient(
                    listOf(AgentModelResponse.Final(AgentReport(summary = "Annotated.")))
                )

                loop(
                    harness = harness,
                    client = client,
                    tools = listOf(overview, expert),
                    bootstrapEnabled = true
                ).run(
                    "Analyze this capture",
                    harness.snapshot,
                    AgentPrivacyMode.RedactedMetadata
                )

                val messages = client.requests.single().messages
                val overviewTool = messages.single {
                    it.toolCallId == "host-bootstrap-overview-1" &&
                        it.role == AgentModelMessageRole.Tool
                }
                val expertTool = messages.single {
                    it.toolCallId == "host-bootstrap-expert-2" &&
                        it.role == AgentModelMessageRole.Tool
                }
                val overviewSet = extractFromBaselineMessage(overviewTool)
                val union = AgentSignalExtractor().extract(
                    listOf(
                        HostCallPayload(
                            toolCallId = "host-bootstrap-overview-1",
                            toolName = "get_capture_overview",
                            data = checkNotNull(overviewTool.toolResult?.data)
                        ),
                        HostCallPayload(
                            toolCallId = "host-bootstrap-expert-2",
                            toolName = "get_expert_info",
                            data = checkNotNull(expertTool.toolResult?.data)
                        )
                    )
                )
                // Decision (b), pinned: the expert message carries the full
                // set at that point of the run, expert groups first.
                assertEquals(4, union.signals.size)
                assertEquals(
                    AgentSignalExtractor.KIND_EXPERT_GROUP,
                    union.signals.first().kind
                )
                assertTrue(expertTool.content.endsWith(hostSignalsLineOf(union.signalIds)))
                // And the overview message is not rewritten after the fact:
                // it shows only what was known when it was appended, and none
                // of the expert-only ids.
                assertTrue(overviewTool.content.endsWith(hostSignalsLineOf(overviewSet.signalIds)))
                val expertOnlyIds = union.signalIds - overviewSet.signalIds.toSet()
                assertEquals(2, expertOnlyIds.size)
                expertOnlyIds.forEach { id ->
                    assertFalse(overviewTool.content.contains(id))
                }
            }
        }

    @Test
    fun modelReRunsUpdateTheCumulativeSetAndACappedSetNamesSignalsCapped() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val overviewData = mapOf(
                "frameCount" to 500,
                "health" to buildMap {
                    repeat(21) { index ->
                        put(
                            "family$index",
                            mapOf("problems" to index + 1, "severity" to "warning")
                        )
                    }
                }
            )
            val expertData = mapOf(
                "groups" to listOf(
                    mapOf("count" to 7, "severity" to "error", "groupKey" to "error/g1"),
                    mapOf("count" to 4, "severity" to "warning", "groupKey" to "warning/g2")
                )
            )
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(overviewData, returnedCount = 1L, totalCount = 1L)
            }
            val expert = FakeTool("get_expert_info", schema = ANY_ARGS_SCHEMA) { _, context ->
                context.success(expertData, returnedCount = 2L, totalCount = 2L)
            }
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-1", "get_capture_overview"))
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("call-2", "get_expert_info"))
                    ),
                    AgentModelResponse.Final(AgentReport(summary = "Done."))
                )
            )
            val agentLoop = loop(harness, client, tools = listOf(overview, expert))

            val outcome = agentLoop.run(
                "Question?",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            )
            assertTrue(outcome is AgentRunOutcome.Completed)

            val finalTranscript = client.requests.last().messages
            val overviewTool = finalTranscript.single {
                it.toolCallId == "call-1" && it.role == AgentModelMessageRole.Tool
            }
            val expertTool = finalTranscript.single {
                it.toolCallId == "call-2" && it.role == AgentModelMessageRole.Tool
            }
            val overviewSet = extractFromBaselineMessage(overviewTool)
            val union = AgentSignalExtractor().extract(
                listOf(
                    HostCallPayload("call-1", "get_capture_overview", data = overviewData),
                    HostCallPayload("call-2", "get_expert_info", data = expertData)
                )
            )
            // 21 health candidates from the first message cap to 19 + one
            // trailing signals_capped meta-signal; the union of 23 candidates
            // caps to 2 expert-group signals, 17 health signals and a
            // differently-worded (hence differently-identified) cap.
            assertEquals(AgentSignalExtractor.MAX_SIGNALS, overviewSet.signals.size)
            assertEquals(
                AgentSignalExtractor.KIND_SIGNALS_CAPPED,
                overviewSet.signals.last().kind
            )
            assertTrue(overviewTool.content.endsWith(hostSignalsLineOf(overviewSet.signalIds)))
            assertEquals(AgentSignalExtractor.MAX_SIGNALS, union.signals.size)
            assertEquals(
                AgentSignalExtractor.KIND_SIGNALS_CAPPED,
                union.signals.last().kind
            )
            assertNotEquals(
                overviewSet.signalIds.last(),
                union.signalIds.last()
            )
            assertTrue(expertTool.content.endsWith(hostSignalsLineOf(union.signalIds)))
            // The run set the next task's gate will read is exactly what the
            // last annotation showed the model.
            assertEquals(union, agentLoop.currentRunSignals)
        }
    }

    @Test
    fun delegatedBaselineCallsContributeNeitherAnnotationsNorRunSignals() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val childVisibleSignals = mapOf(
                "frameCount" to 10,
                "health" to mapOf(
                    "internet" to mapOf("problems" to 3, "severity" to "warning")
                )
            )
            val delegate = DelegateInvestigationTool()
            val overview = FakeTool("get_capture_overview") { _, context ->
                context.success(childVisibleSignals, returnedCount = 1L, totalCount = 1L)
            }
            val childReport = AgentReport(
                summary = "Child confirmed overview data.",
                findings = listOf(
                    finding(
                        listOf(
                            AgentEvidence(
                                AgentEvidenceType.Observation,
                                observation = "overview returned data",
                                sourceToolCallId = "child-overview"
                            )
                        )
                    )
                )
            )
            val mainReport = childReport.copy(summary = "Main used delegated evidence.")
            val client = RecordingClient(
                listOf(
                    AgentModelResponse.ToolCalls(
                        listOf(
                            AgentToolCall(
                                "delegate-1",
                                DelegateInvestigationTool.NAME,
                                mapOf("goal" to "Inspect capture health", "maxTurns" to 3)
                            )
                        )
                    ),
                    AgentModelResponse.ToolCalls(
                        listOf(AgentToolCall("child-overview", "get_capture_overview"))
                    ),
                    AgentModelResponse.Final(childReport),
                    AgentModelResponse.Final(mainReport)
                )
            )
            val agentLoop = loop(harness, client, tools = listOf(delegate, overview))

            val outcome = agentLoop.run(
                "Delegate this investigation",
                harness.snapshot,
                AgentPrivacyMode.RedactedMetadata
            ) as AgentRunOutcome.Completed
            assertEquals("Main used delegated evidence.", outcome.report.summary)

            // The child's own overview message (in the child's transcript, the
            // second request) carries no annotation…
            val childToolMessage = client.requests[2].messages.single {
                it.toolCallId == "child-overview" && it.role == AgentModelMessageRole.Tool
            }
            assertFalse(childToolMessage.content.contains("host-signals:"))
            // …the parent transcript carries none either (it made no baseline
            // call of its own)…
            val parentFinalRequest = client.requests.last()
            assertFalse(
                parentFinalRequest.messages.any { it.content.contains("host-signals:") }
            )
            // …and the run set the OPT-VAL-02-03 gate reads holds the model
            // to nothing it was never shown.
            assertTrue(agentLoop.currentRunSignals.isEmpty)
        }
    }

    private fun loop(
        harness: AgentToolTestHarness,
        client: AiModelClient,
        tools: List<AgentTool> = defaultTools(),
        policy: AgentPolicy = AgentPolicy(),
        controller: AgentRunController = controller(harness, client),
        listener: AgentRunListener? = null,
        clock: () -> Long = { System.currentTimeMillis() },
        suspendDelay: suspend (Long) -> Unit = { },
        playbook: AgentPlaybook = AgentPlaybook.generalCaptureHealth(),
        bootstrapEnabled: Boolean = false,
        diagnostics: AgentDiagnosticsSession? = null
    ): AgentLoop {
        val runPolicy = policy.copy(analysisBootstrapEnabled = bootstrapEnabled)
        val budget = AgentBudgetTracker(runPolicy, clock)
        return AgentLoop(
            toolRunner = AgentToolRunner(
                registry = AgentToolRegistry(tools),
                repository = harness.repository,
                policy = runPolicy,
                budget = budget,
                clock = clock
            ),
            modelClient = client,
            controller = controller,
            policy = runPolicy,
            listener = listener,
            playbook = playbook,
            clock = clock,
            suspendDelay = suspendDelay,
            retryJitter = { 0.0 },
            diagnostics = diagnostics
        )
    }

    private fun controller(harness: AgentToolTestHarness, client: AiModelClient) =
        AgentRunController(
            identity = AgentRunIdentity(
                conversationId = "conv_test",
                runId = "run_test"
            ),
            modelClient = client,
            repository = harness.repository
        )

    private fun defaultTools(): List<AgentTool> = listOf(
        FakeTool("get_capture_overview") { _, context ->
            context.success(
                data = mapOf("frameCount" to 100, "protocolHierarchy" to listOf("tcp", "udp")),
                returnedCount = 2L,
                totalCount = 2L
            )
        },
        FakeTool("get_expert_info") { _, context ->
            context.success(
                data = mapOf("items" to listOf(mapOf("frameNumber" to 7L, "severity" to "warning"))),
                returnedCount = 1L,
                totalCount = 1L
            )
        }
    )

    /** The shape CloudAiModelClient produces for an ALB 504 with an HTML body. */
    private fun gatewayTimeout() = AiModelErrors.unavailable(
        AiModelErrors.GATEWAY_TIMEOUT_REASON,
        mapOf("httpStatus" to 504)
    )

    private fun finding(
        evidence: List<AgentEvidence>,
        confidence: AgentConfidence = AgentConfidence.Medium
    ) = AgentFinding(
        id = FINDING_ID,
        title = "A finding",
        severity = AgentFindingSeverity.Warning,
        confidence = confidence,
        conclusion = "A conclusion.",
        evidence = evidence
    )

    private fun expertItem(frame: Long, severity: String) = ExpertInfoItem(
        frameNumber = frame,
        label = "Expert $severity at $frame",
        filter = "frame.number == $frame",
        severity = severity,
        start = 0,
        length = 0
    )

    private fun scriptedClient(vararg responses: MockScriptedResponse): MockAiModelClient =
        MockAiModelClient(MockModelScript(id = "test-script", responses = responses.toList()))

    private fun messageCacheBreakpointLayout(request: AgentModelRequest): List<String> =
        request.messages.mapNotNull { message ->
            if (message.role == AgentModelMessageRole.System || message.cacheControl == null) {
                null
            } else {
                "${message.role.name}:${message.toolCallId.orEmpty()}"
            }
        }

    /** Provider cache order is tools, then system blocks, then message content blocks. */
    private fun anthropicLogicalBlocks(request: AgentModelRequest): List<AnthropicLogicalBlock> {
        val encoder = AnthropicModelClient(
            apiBaseUrl = "https://api.anthropic.com",
            transport = EncodingOnlyTransport,
            providerId = "prefix-test",
            modelId = "claude-opus-5",
            apiKeyProvider = { "unused" }
        )
        val body = JSONObject(encoder.encodeRequest(request))
        return buildList {
            val tools = body.getJSONArray("tools")
            for (index in 0 until tools.length()) {
                add(
                    AnthropicLogicalBlock(
                        layer = "tools",
                        serialized = tools.getJSONObject(index).toString()
                    )
                )
            }
            val system = body.getJSONArray("system")
            for (index in 0 until system.length()) {
                val block = system.getJSONObject(index)
                add(
                    AnthropicLogicalBlock(
                        layer = "system",
                        serialized = block.toString(),
                        cacheBreakpoint = block.has("cache_control")
                    )
                )
            }
            val messages = body.getJSONArray("messages")
            for (messageIndex in 0 until messages.length()) {
                val message = messages.getJSONObject(messageIndex)
                val role = message.getString("role")
                val content = message.getJSONArray("content")
                for (blockIndex in 0 until content.length()) {
                    val block = content.getJSONObject(blockIndex)
                    add(
                        AnthropicLogicalBlock(
                            layer = "messages",
                            serialized = "$role:${block}",
                            toolCallId = block.optString("tool_use_id").takeIf(String::isNotBlank),
                            cacheBreakpoint = block.has("cache_control")
                        )
                    )
                }
            }
        }
    }

    private fun logicalPrefixBytes(blocks: List<AnthropicLogicalBlock>): ByteArray = blocks
        .joinToString(separator = "\u0000") { block ->
            "${block.layer}\u0001${block.serialized}"
        }
        .toByteArray(StandardCharsets.UTF_8)

    private data class AnthropicLogicalBlock(
        val layer: String,
        val serialized: String,
        val toolCallId: String? = null,
        val cacheBreakpoint: Boolean = false
    )

    private object EncodingOnlyTransport : AgentHttpTransport {
        override suspend fun execute(request: AgentHttpRequest): AgentHttpResponse =
            AgentHttpResponse(statusCode = 500)

        override fun cancel(requestId: String) = Unit
    }

    private class PhaseRecorder : AgentRunListener {
        val phases = mutableListOf<AgentRunPhase>()
        override fun onPhaseChanged(phase: AgentRunPhase) {
            phases += phase
        }
    }

    private companion object {
        /** Id shared by [finding] and the revision merge assertions. */
        const val FINDING_ID = "finding-1"

        /**
         * Schema for fakes standing in for `get_expert_info`: the host's
         * bootstrap call sends `severities`/`offset`/`limit`, which
         * [FakeTool]'s default schema (additionalProperties = false) would
         * reject before the call ever reaches the body.
         */
        val ANY_ARGS_SCHEMA: Map<String, Any?> = mapOf(
            "type" to "object",
            "additionalProperties" to true
        )

        /** Accepts the `scope` argument the AI-05 demo scripts send. */
        val SCOPE_SCHEMA: Map<String, Any?> = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "scope" to mapOf(
                    "type" to "string",
                    "enum" to listOf("complete_file", "current_filter")
                )
            )
        )
    }

    /** A client that answers from a fixed list and records what it was asked. */
    private open class TestClient(
        override val id: String = "test-model",
        override val capabilities: AiModelCapabilities = AiModelCapabilities.PHASE0
    ) : AiModelClient {
        val cancelledRequestIds = mutableListOf<String>()

        override suspend fun respond(request: AgentModelRequest): AgentModelResponse =
            AgentModelResponse.Failure(AiModelErrors.contract("no_response_configured"))

        override fun cancel(requestId: String) {
            cancelledRequestIds += requestId
        }
    }

    private class RecordingClient(
        private val responses: List<AgentModelResponse>,
        capabilities: AiModelCapabilities = AiModelCapabilities.PHASE0
    ) : TestClient(capabilities = capabilities) {
        val requests = mutableListOf<AgentModelRequest>()

        override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
            val index = requests.size
            requests += request
            return responses.getOrElse(index) {
                AgentModelResponse.Failure(
                    AgentError(
                        code = AgentErrorCode.INTERNAL_ERROR,
                        userMessage = "The test script ran out of responses.",
                        retryable = false,
                        details = mapOf("turn" to index)
                    )
                )
            }
        }
    }
}

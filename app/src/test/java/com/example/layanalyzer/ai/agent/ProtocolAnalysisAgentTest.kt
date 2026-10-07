package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.client.MockAiModelClient
import com.example.layanalyzer.ai.client.MockModelScriptLibrary
import com.example.layanalyzer.ai.client.AiModelCapabilities
import com.example.layanalyzer.ai.client.AiModelClient
import com.example.layanalyzer.ai.client.MockModelScript
import com.example.layanalyzer.ai.client.MockScriptedResponse
import com.example.layanalyzer.ai.audit.AgentDiagnosticsRecorder
import com.example.layanalyzer.ai.playbook.AgentPlaybookStore
import com.example.layanalyzer.ai.playbook.TestScenarioPackages
import com.example.layanalyzer.ai.tools.AgentToolRegistry
import com.example.layanalyzer.ai.tools.AgentToolTestHarness
import com.example.layanalyzer.ai.tools.FakeTool
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentRunPhase
import com.example.layanalyzer.model.AgentTokenUsage
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CaptureStatistics
import com.example.layanalyzer.model.ExpertInfoItem
import com.example.layanalyzer.model.ExpertInfoSummary
import com.example.layanalyzer.model.ProtocolStat
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.async
import kotlinx.coroutines.awaitCancellation
import kotlinx.coroutines.delay
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicInteger

/**
 * End-to-end coverage of the public entry point, driven by the AI-05 demo
 * scripts against the real Phase 0 tools.
 */
class ProtocolAnalysisAgentTest {

    @get:Rule
    val temporaryFolder = TemporaryFolder()

    @Test
    fun theCaptureOverviewScriptRunsTheWholeLoop() = runBlocking {
        AgentToolTestHarness.create(frameCount = 120) {
            statisticsByFilter = mapOf("" to statistics())
            expert = ExpertInfoSummary(
                errorPackets = 0,
                warningPackets = 2,
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
        }.use { harness ->
            val agent = agent(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            val result = agent.run(
                question = "Why is this capture slow?",
                scope = AnalysisScope.CompleteFile,
                privacyMode = AgentPrivacyMode.RedactedMetadata
            )

            val outcome = result.outcome as AgentRunOutcome.Completed
            assertEquals(AgentStopReason.ModelFinal, outcome.stopReason)
            assertEquals(
                listOf("host-bootstrap-overview-1", "host-bootstrap-expert-2"),
                result.toolCallIds
            )
            assertEquals(2, result.activities.size)
            assertTrue(result.activities.all { it.error == null })

            // The script's report cites both tool calls, so both survive.
            val finding = outcome.report.findings.single()
            assertEquals(2, finding.evidence.size)
            assertEquals("mock:capture_overview_success", outcome.report.provenance.modelId)
            assertEquals(AgentPrompt.VERSION, outcome.report.provenance.promptVersion)
            assertEquals("general-capture-health@1", outcome.report.provenance.playbookVersion)
            assertEquals(harness.snapshot.captureFingerprint, outcome.report.provenance.captureFingerprint)
        }
    }

    @Test
    fun theInvalidFilterScriptRecoversAndReportsPartial() = runBlocking {
        AgentToolTestHarness.create {
            invalidFilters = setOf("tcp.portt == 443")
        }.use { harness ->
            val agent = agent(
                harness,
                MockModelScriptLibrary.INVALID_FILTER_RECOVERY,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined)
            )

            val result = agent.run("Is TLS healthy?", privacyMode = AgentPrivacyMode.RedactedMetadata)

            val outcome = result.outcome as AgentRunOutcome.Completed
            // Both validation calls succeed as tool calls: the first simply
            // answers valid=false, which is a useful result, not a failure.
            assertEquals(
                listOf("host-bootstrap-overview-1", "call-bad-filter", "call-good-filter"),
                result.toolCallIds
            )
            val finding = outcome.report.findings.single()
            // The corrected filter was compiled by the host, so citing it stands.
            assertEquals(1, finding.evidence.size)
            assertEquals("tcp.port == 443", finding.evidence.single().displayFilter)
        }
    }

    @Test
    fun argumentSummariesNeverCarryArgumentValues() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val agent = agent(
                harness,
                MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS,
                registry = AgentToolRegistry(scriptedFakeTools())
            )

            val result = agent.run("Question?", privacyMode = AgentPrivacyMode.RedactedMetadata)

            // Bootstrap uses host-owned empty arguments; no value may appear.
            val summaries = result.activities.map { it.argumentsSummary }
            assertFalse(summaries.any { it.contains("complete_file") })
            assertTrue(summaries.all { it.isBlank() })
        }
    }

    @Test
    fun aBlankQuestionIsRefusedWithoutTouchingTheCapture() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val agent = agent(harness, MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)

            val result = agent.run("   ", privacyMode = AgentPrivacyMode.RedactedMetadata)

            val failed = result.outcome as AgentRunOutcome.Failed
            assertEquals(AgentErrorCode.INVALID_TOOL_ARGUMENTS, failed.error.code)
            assertNull(failed.report)
            assertEquals(AgentRunPhase.Idle, agent.currentPhase)
        }
    }

    @Test
    fun aSecondConcurrentRunIsRefusedRatherThanQueued() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val entered = CompletableDeferred<Unit>()
            val blocking = FakeTool(
                name = "get_capture_overview",
                timeoutMillis = 60_000L,
                schema = SCRIPTED_SCHEMA
            ) { _, _ ->
                entered.complete(Unit)
                awaitCancellation()
            }
            val agent = agent(
                harness,
                MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS,
                registry = blockingOverviewRegistry(blocking)
            )

            val first = async(Dispatchers.Default) {
                agent.run("First question?", privacyMode = AgentPrivacyMode.RedactedMetadata)
            }
            entered.await()

            val second = agent.run("Second question?", privacyMode = AgentPrivacyMode.RedactedMetadata)
            val refused = second.outcome as AgentRunOutcome.Failed
            assertEquals("concurrent_run", refused.error.details["reason"])

            agent.cancel()
            first.cancel()
        }
    }

    @Test
    fun aTrueConcurrentStartCannotBothClaimTheRunSlot() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val providerLatch = CountDownLatch(2)
            val client = BlockingFinalClient()
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = client,
                modelClientProvider = {
                    providerLatch.countDown()
                    check(providerLatch.await(2, TimeUnit.SECONDS)) {
                        "model providers did not rendezvous"
                    }
                    client
                }
            )
            val first = async(Dispatchers.Default) {
                agent.run("First question?", privacyMode = AgentPrivacyMode.RedactedMetadata)
            }
            val second = async(Dispatchers.Default) {
                agent.run("Second question?", privacyMode = AgentPrivacyMode.RedactedMetadata)
            }

            withTimeout(2_000L) {
                while (!first.isCompleted && !second.isCompleted) delay(1L)
            }
            val completed = listOf(first, second).filter { it.isCompleted }
            assertEquals(1, completed.size)
            assertEquals("concurrent_run", completed.single().await().error?.details?.get("reason"))

            client.release.complete(Unit)
            first.await()
            second.await()
            assertEquals(1, client.respondCount.get())
        }
    }

    @Test
    fun runningWithNoCaptureOpenFailsBeforeAnyModelCall() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            harness.coordinator.invalidateSession()
            val client = MockAiModelClient(
                MockModelScriptLibrary.require(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = client
            )

            val result = agent.run("Question?", privacyMode = AgentPrivacyMode.RedactedMetadata)

            val failed = result.outcome as AgentRunOutcome.Failed
            assertEquals(AgentErrorCode.NO_CAPTURE, failed.error.code)
            // The snapshot failed, so the model was never consulted.
            assertEquals(0, client.servedTurnCount)
        }
    }

    @Test
    fun unexpectedModelExceptionBecomesFailedWithAnExportedDiagnostic() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.root,
                clock = { 10_000L }
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = ThrowingModelClient,
                diagnostics = recorder
            )

            val result = agent.run("Why did this analysis fail?")
            val failed = result.outcome as AgentRunOutcome.FailedWithPartialReport
            val error = failed.error

            assertEquals(AgentErrorCode.INTERNAL_ERROR, error.code)
            assertNotNull(result.diagnosticId)
            assertEquals(result.diagnosticId, error.details["diagnosticId"])

            val exported = JSONObject(recorder.exportRedacted())
            val events = exported.getJSONArray("events")
            val modelFailure = (0 until events.length())
                .map { events.getJSONObject(it) }
                .first { it.getString("eventType") == "ModelResponse" }

            assertEquals("failed", modelFailure.getString("status"))
            assertEquals(
                "RuntimeException",
                modelFailure.getJSONObject("failure")
                    .getJSONObject("exception")
                    .getString("type")
            )
            assertEquals("failed_partial_report", events.getJSONObject(events.length() - 1).getString("status"))
        }
    }

    @Test
    fun tokenUsageIsAccumulatedAndCalibratesEachModelResponseDiagnostic() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.root,
                clock = { 15_000L }
            )
            val client = MockAiModelClient(
                MockModelScript(
                    id = "token-usage",
                    responses = listOf(
                        MockScriptedResponse(
                            AgentModelResponse.ToolCalls(
                                calls = listOf(
                                    com.example.layanalyzer.model.AgentToolCall(
                                        "call-overview",
                                        "get_capture_overview"
                                    )
                                ),
                                usage = AgentTokenUsage(
                                    inputTokens = 100,
                                    outputTokens = 10,
                                    cachedInputTokens = 40,
                                    cacheCreationTokens = 5
                                )
                            )
                        ),
                        MockScriptedResponse(
                            AgentModelResponse.Final(
                                report = AgentReport(summary = "Done."),
                                usage = AgentTokenUsage(
                                    inputTokens = 180,
                                    outputTokens = 30,
                                    cachedInputTokens = 80,
                                    cacheCreationTokens = 10
                                )
                            )
                        )
                    )
                )
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = client,
                diagnostics = recorder
            )

            val result = agent.run("Why is this capture slow?")

            assertEquals(
                AgentTokenUsage(
                    inputTokens = 280,
                    outputTokens = 40,
                    cachedInputTokens = 120,
                    cacheCreationTokens = 15
                ),
                result.tokenUsage
            )
            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val modelResponses = (0 until events.length())
                .map { events.getJSONObject(it) }
                .filter { it.getString("eventType") == "ModelResponse" }
            assertEquals(2, modelResponses.size)
            assertEquals("100", modelResponses[0].getJSONObject("attributes").getString("actualInputTokens"))
            assertEquals("40", modelResponses[0].getJSONObject("attributes").getString("cachedInputTokens"))
            assertEquals("10", modelResponses[0].getJSONObject("attributes").getString("outputTokens"))
            modelResponses.forEach { event ->
                val attributes = event.getJSONObject("attributes")
                val estimated = attributes.getString("estimatedInputTokens").toDouble()
                val actual = attributes.getString("actualInputTokens").toDouble()
                assertEquals(
                    estimated / actual,
                    attributes.getString("estimatorRatio").toDouble(),
                    0.000_001
                )
            }
            val bootstrap = (0 until events.length())
                .map { events.getJSONObject(it) }
                .first { it.getString("eventType") == "AnalysisBootstrap" }
                .getJSONObject("attributes")
            assertEquals("1", bootstrap.getString("bootstrapToolCount"))
            assertEquals("0", bootstrap.getString("modelRequestsBeforeFirstEvidence"))
            assertTrue(bootstrap.getString("bootstrapResultBytes").toLong() > 0L)

            val runMetrics = (0 until events.length())
                .map { events.getJSONObject(it) }
                .first { it.getString("eventType") == "RunMetrics" }
                .getJSONObject("attributes")
            assertEquals("2", runMetrics.getString("modelRequestCount"))
            assertEquals("0", runMetrics.getString("modelRequestsBeforeFirstEvidence"))
        }
    }

    @Test
    fun missingModelContextLimitIsRecordedAsFallbackDiagnostics() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.root,
                clock = { 16_000L }
            )
            val client = MockAiModelClient(
                MockModelScript(
                    id = "fallback-context",
                    responses = listOf(
                        MockScriptedResponse.final(AgentReport(summary = "Done."))
                    ),
                    capabilities = AiModelCapabilities.PHASE0
                )
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = client,
                diagnostics = recorder
            )

            agent.run("Which context limit is active?")

            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val configuration = (0 until events.length())
                .map { events.getJSONObject(it) }
                .first {
                    it.getString("eventType") == "Configuration" &&
                        it.optString("status") == "ready"
                }
            val attributes = configuration.getJSONObject("attributes")
            assertEquals("fallback", attributes.getString("contextLimitSource"))
            assertEquals(
                ContextPlanner.DEFAULT_CONTEXT_TOKENS.toString(),
                attributes.getString("fallbackContextTokens")
            )
        }
    }

    @Test
    fun unexpectedToolExceptionIsRecordedWithoutAbortingTheWholeLoop() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.root,
                clock = { 20_000L }
            )
            val throwingTool = FakeTool(
                name = "get_capture_overview",
                schema = SCRIPTED_SCHEMA
            ) { _, _ ->
                throw IllegalStateException("Bearer tool-secret")
            }
            val registry = AgentToolRegistry(listOf(throwingTool))
            val script = MockModelScript(
                id = "tool-exception",
                responses = listOf(
                    MockScriptedResponse.tool(
                        toolCallId = "call-overview",
                        toolName = "get_capture_overview",
                        arguments = mapOf("scope" to "complete_file")
                    ),
                    MockScriptedResponse.final(
                        AgentReport(
                            summary = "The host returned a bounded tool error.",
                            completeness = AgentReportCompleteness.Partial
                        )
                    )
                ),
                expectedRequests = listOf(
                    null,
                    com.example.layanalyzer.ai.client.MockRequestExpectation(
                        expectedToolName = "get_capture_overview",
                        expectedToolCallId = "call-overview"
                    )
                )
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = registry,
                modelClient = MockAiModelClient(script),
                diagnostics = recorder
            )

            val result = agent.run("Can the overview be collected?")
            assertTrue(result.outcome is AgentRunOutcome.Completed)

            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            val toolFailure = (0 until events.length())
                .map { events.getJSONObject(it) }
                .first { it.getString("eventType") == "ToolFinished" }
            assertEquals("failed", toolFailure.getString("status"))
            assertEquals(
                "IllegalStateException",
                toolFailure.getJSONObject("failure")
                    .getJSONObject("exception")
                    .getString("type")
            )
            assertFalse(recorder.exportRedacted().contains("tool-secret"))
        }
    }

    @Test
    fun cancelDuringAToolCallLeavesTheRunCancelledAndRestoresTheUserFilter() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            harness.source.appliedFilters.clear()
            val entered = CompletableDeferred<Unit>()
            val blocking = FakeTool(
                name = "get_capture_overview",
                timeoutMillis = 60_000L,
                schema = SCRIPTED_SCHEMA
            ) { _, _ ->
                entered.complete(Unit)
                awaitCancellation()
            }
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.root,
                clock = { 30_000L }
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = blockingOverviewRegistry(blocking),
                modelClient = MockAiModelClient(
                    MockModelScriptLibrary.require(MockModelScriptLibrary.CAPTURE_OVERVIEW_SUCCESS)
                ),
                diagnostics = recorder
            )

            val job = async(Dispatchers.Default) {
                agent.run("Question?", privacyMode = AgentPrivacyMode.RedactedMetadata)
            }
            entered.await()
            agent.cancel()
            job.cancel()
            job.join()

            assertFalse(agent.isRunning)
            // Nothing may be left applied: the run held no lease of its own here,
            // and the coordinator restores from NonCancellable when one is held.
            assertEquals("", harness.source.getAppliedDisplayFilter())
            val events = JSONObject(recorder.exportRedacted()).getJSONArray("events")
            assertEquals("RunFinished", events.getJSONObject(events.length() - 1).getString("eventType"))
            assertEquals("cancelled", events.getJSONObject(events.length() - 1).getString("status"))
        }
    }

    @Test
    fun maxStepsScriptProducesAnIncompleteReportFromTheHost() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val tool = FakeTool("get_capture_overview", schema = SCRIPTED_SCHEMA) { _, context ->
                context.success(mapOf("ok" to true), returnedCount = 1L, totalCount = 1L)
            }
            val agent = agent(
                harness,
                MockModelScriptLibrary.MAX_STEPS,
                registry = AgentToolRegistry(listOf(tool)),
                policy = AgentPolicy(maxSteps = 5, maxConsecutiveIdenticalToolCalls = 20)
            )

            val result = agent.run("Question?", privacyMode = AgentPrivacyMode.RedactedMetadata)

            val outcome = result.outcome as AgentRunOutcome.FailedWithPartialReport
            assertEquals(AgentErrorCode.INTERNAL_ERROR, outcome.error.code)
            assertEquals(AgentReportCompleteness.Incomplete, outcome.report.completeness)
            assertEquals(5, tool.executionCount)
            assertTrue(outcome.report.limitations.isNotEmpty())
        }
    }

    // -----------------------------------------------------------------
    // SRE-RUN-01: the run-level playbookId passthrough to the store.
    // -----------------------------------------------------------------

    @Test
    fun anExplicitPlaybookIdWinsEvenWhenTheQuestionTextDoesNotMatchIt() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.root,
                clock = { 25_000L }
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = MockAiModelClient(
                    MockModelScript(
                        id = "playbook-explicit",
                        responses = listOf(
                            MockScriptedResponse.final(AgentReport(summary = "Done."))
                        )
                    )
                ),
                diagnostics = recorder,
                playbookStore = playbookStoreWithExtraScenario()
            )

            val result = agent.run(
                question = "Why is this capture slow?",
                privacyMode = AgentPrivacyMode.RedactedMetadata,
                playbookId = "tcp-retransmission-deep-dive"
            )

            assertTrue(result.outcome is AgentRunOutcome.Completed)
            // The run's own diagnostics pin which playbook drove it: the
            // explicit id, whose intent hints the question never matched.
            assertEquals(
                "tcp-retransmission-deep-dive@3",
                singleRunPlaybookVersion(recorder)
            )
        }
    }

    @Test
    fun withoutAPlaybookIdSelectionStaysTheQuestionTextFallback() = runBlocking {
        AgentToolTestHarness.create().use { harness ->
            val recorder = AgentDiagnosticsRecorder(
                directory = temporaryFolder.root,
                clock = { 26_000L }
            )
            val agent = ProtocolAnalysisAgent(
                repository = harness.repository,
                registry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
                modelClient = MockAiModelClient(
                    MockModelScript(
                        id = "playbook-default",
                        responses = listOf(
                            MockScriptedResponse.final(AgentReport(summary = "Done."))
                        )
                    )
                ),
                diagnostics = recorder,
                playbookStore = playbookStoreWithExtraScenario()
            )

            val result = agent.run(
                question = "Why is this capture slow?",
                privacyMode = AgentPrivacyMode.RedactedMetadata
            )

            assertTrue(result.outcome is AgentRunOutcome.Completed)
            // No id was passed: the question matches neither non-general
            // playbook's hints, so the run falls back to the general one.
            assertEquals(
                "general-capture-health@1",
                singleRunPlaybookVersion(recorder)
            )
        }
    }

    private fun agent(
        harness: AgentToolTestHarness,
        scriptId: String,
        registry: AgentToolRegistry = AgentToolRegistry.phase0(Dispatchers.Unconfined),
        policy: AgentPolicy = AgentPolicy()
    ) = ProtocolAnalysisAgent(
        repository = harness.repository,
        registry = registry,
        modelClient = MockAiModelClient(MockModelScriptLibrary.require(scriptId)),
        policy = policy
    )

    /**
     * The minimal general playbook plus one extra scenario whose intent hints
     * ("retransmission deep dive") none of these tests' questions contain, so
     * only the explicit-id path can reach it.  The store's whitelist is the
     * shared test tool set; the extra playbook's initial tool,
     * `get_capture_overview`, is also what the phase-0 registry bootstraps.
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

    /** The one run record's playbookVersion from a redacted diagnostics export. */
    private fun singleRunPlaybookVersion(recorder: AgentDiagnosticsRecorder): String {
        val runs = JSONObject(recorder.exportRedacted()).getJSONArray("runs")
        assertEquals(1, runs.length())
        return runs.getJSONObject(0).getString("playbookVersion")
    }

    /**
     * Stand-ins for the two Phase 0 tools the demo scripts call, accepting the
     * same arguments those scripts pass so schema validation is not what the
     * test ends up measuring.
     */
    private fun scriptedFakeTools() = listOf(
        FakeTool("get_capture_overview", schema = SCRIPTED_SCHEMA) { _, context ->
            context.success(mapOf("ok" to true), returnedCount = 1L, totalCount = 1L)
        },
        FakeTool("get_expert_info", schema = SCRIPTED_SCHEMA) { _, context ->
            context.success(
                data = mapOf("items" to listOf(mapOf("frameNumber" to 7L))),
                returnedCount = 1L,
                totalCount = 1L
            )
        }
    )

    /** Keep the scripted model's advertised tool set complete while overview blocks. */
    private fun blockingOverviewRegistry(blocking: FakeTool) = AgentToolRegistry(
        listOf(
            blocking,
            FakeTool("get_expert_info", schema = SCRIPTED_SCHEMA) { _, context ->
                context.success(emptyMap(), returnedCount = 0L, totalCount = 0L)
            }
        )
    )

    private object ThrowingModelClient : AiModelClient {
        override val id: String = "mock:throwing-model"
        override val capabilities: AiModelCapabilities = AiModelCapabilities.PHASE0

        override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
            throw RuntimeException("model transport failed")
        }

        override fun cancel(requestId: String) = Unit
    }

    private class BlockingFinalClient : AiModelClient {
        override val id: String = "mock:blocking-final"
        override val capabilities: AiModelCapabilities = AiModelCapabilities.PHASE0
        val release = CompletableDeferred<Unit>()
        val respondCount = AtomicInteger(0)

        override suspend fun respond(request: AgentModelRequest): AgentModelResponse {
            respondCount.incrementAndGet()
            release.await()
            return AgentModelResponse.Final(AgentReport(summary = "Done."))
        }

        override fun cancel(requestId: String) = Unit
    }

    private companion object {
        /** Accepts the arguments the AI-05 demo scripts actually send. */
        val SCRIPTED_SCHEMA: Map<String, Any?> = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "scope" to mapOf(
                    "type" to "string",
                    "enum" to listOf("complete_file", "current_filter")
                ),
                "severities" to mapOf(
                    "type" to "array",
                    "maxItems" to 4,
                    "items" to mapOf("type" to "string")
                ),
                "limit" to mapOf("type" to "integer", "minimum" to 1, "maximum" to 100),
                "filter" to mapOf("type" to "string", "maxLength" to 2048)
            )
        )
    }

    private fun statistics() = CaptureStatistics(
        packetCount = 120,
        startTime = 0.0,
        endTime = 12.0,
        capturedByteCount = 40_000L,
        protocolHierarchy = listOf(
            ProtocolStat(
                name = "tcp",
                packetCount = 100,
                byteCount = 30_000L,
                packetPercent = 83.3,
                bytePercent = 75.0
            ),
            ProtocolStat(
                name = "udp",
                packetCount = 20,
                byteCount = 10_000L,
                packetPercent = 16.7,
                bytePercent = 25.0
            )
        ),
        tcpRetransmissions = 3
    )
}

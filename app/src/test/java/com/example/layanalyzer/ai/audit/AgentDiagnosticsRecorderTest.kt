package com.example.layanalyzer.ai.audit

import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentError
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/** AI-24 section 5: rotation, size caps and a log that carries no secrets. */
class AgentDiagnosticsRecorderTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private var now: Long = 5_000L

    private fun recorder(
        maxFileBytes: Long = 256L * 1024,
        maxFiles: Int = 3
    ) = AgentDiagnosticsRecorder(
        directory = temporaryFolder.root,
        maxFileBytes = maxFileBytes,
        maxFiles = maxFiles,
        clock = { now }
    )

    @Test
    fun `a recorded run keeps timings, counts and cache hits`() {
        recorder().record(run())

        val entry = JSONObject(logLines().single())

        assertEquals("agent-1", entry.getString("sessionId"))
        assertEquals(2, entry.getInt("totalSteps"))
        assertEquals(300L, entry.getLong("totalDurationMillis"))
        assertEquals(1, entry.getInt("cacheHits"))
        assertEquals(1, entry.getInt("truncationEvents"))
        assertEquals(3, entry.getInt("evidenceCount"))
        assertEquals(1, entry.getInt("removedEvidenceCount"))
        assertEquals("MAX_STEPS_REACHED", entry.getString("cancelReason"))
    }

    @Test
    fun `the log holds no capture fingerprint, prose or credential`() {
        recorder().record(
            run(
                fingerprint = "0123456789abcdef0123456789abcdef",
                modelId = "model-x"
            )
        )

        val raw = logLines().single()

        // The full fingerprint identifies the capture file; only a short
        // correlating prefix is written.
        assertFalse(raw.contains("0123456789abcdef0123456789abcdef"))
        assertTrue(JSONObject(raw).getString("captureRef").length <= 8)

        // Nothing in the schema can carry a question, a summary or a key.
        val allowed = setOf(
            "schema", "schemaVersion", "sessionId", "captureRef", "modelId",
            "promptVersion", "playbookVersion", "startedAtMillis",
            "completedAtMillis", "totalSteps", "totalDurationMillis",
            "cancelReason", "evidenceCount", "removedEvidenceCount",
            "evidenceFlaggedCount", "evidenceCitedCount", "citationOutsideFlagged",
            "truncationEvents", "cacheHits", "memoryPressureEvents", "tools"
        )
        val unexpected = JSONObject(raw).keys().asSequence().filterNot(allowed::contains).toList()
        assertTrue("Unexpected diagnostics fields: $unexpected", unexpected.isEmpty())
    }

    @Test
    fun `an export drops the argument hashes that are only useful locally`() {
        val subject = recorder()
        subject.record(run())

        val exported = JSONObject(subject.exportRedacted())
        val tools = exported.getJSONArray("runs")
            .getJSONObject(0)
            .getJSONArray("tools")

        assertFalse(exported.toString().contains("hash-"))
        assertFalse(tools.getJSONObject(0).has("argumentsHash"))
        // The useful, non-identifying parts survive.
        assertEquals("get_statistics", tools.getJSONObject(0).getString("toolName"))
        assertTrue(tools.getJSONObject(0).has("durationMillis"))
    }

    @Test
    fun `an export with no recorded runs is still valid JSON`() {
        val exported = JSONObject(recorder().exportRedacted())

        assertEquals(0, exported.getJSONArray("runs").length())
    }

    @Test
    fun `the log rotates once the active file reaches its size cap`() {
        val subject = recorder(maxFileBytes = 400L)

        repeat(6) { index ->
            now += 1_000L
            subject.record(run(sessionId = "agent-$index"))
        }

        val files = temporaryFolder.root.listFiles()!!.filter { it.name.startsWith("agent-diagnostics") }
        assertTrue("expected rotation, found ${files.size} file(s)", files.size > 1)
    }

    @Test
    fun `rotated files beyond the cap are deleted`() {
        val subject = recorder(maxFileBytes = 200L, maxFiles = 2)

        repeat(12) { index ->
            now += 1_000L
            subject.record(run(sessionId = "agent-$index"))
        }

        val rotated = temporaryFolder.root.listFiles()!!
            .filter { it.name.startsWith("agent-diagnostics") && it.name != "agent-diagnostics.jsonl" }
        assertTrue("kept ${rotated.size} rotated file(s)", rotated.size <= 2)
    }

    @Test
    fun `clear removes only this recorder's files and leaves foreign ones alone`() {
        val subject = recorder()
        subject.record(run())
        val foreign = temporaryFolder.newFile("not-ours.txt")
        foreign.writeText("keep me")

        subject.clear()

        assertEquals(0L, subject.totalBytes())
        assertTrue(foreign.isFile)
    }

    @Test
    fun `a null directory disables recording without throwing`() {
        val subject = AgentDiagnosticsRecorder(directory = null, clock = { now })

        subject.record(run())

        assertEquals(0L, subject.totalBytes())
        assertEquals(0, JSONObject(subject.exportRedacted()).getJSONArray("runs").length())
    }

    @Test
    fun `the AgentRunRecord overload marks the steps the cache answered`() {
        val subject = recorder()
        subject.record(
            record = AgentRunRecord(
                sessionId = "agent-9",
                captureFingerprint = "fingerprint",
                modelId = "model-x",
                promptVersion = "prompt-1",
                playbookVersion = null,
                analysisScope = "CompleteFile",
                displayFilterApplied = false,
                startedAtMillis = 0L,
                completedAtMillis = 50L,
                toolCalls = listOf(
                    AgentToolRunRecord("get_statistics", "hash-a", 10L, 1L, 1L),
                    AgentToolRunRecord("packet_search", "hash-b", 20L, 2L, 2L)
                )
            ),
            cacheHitHashes = setOf("hash-a"),
            removedEvidenceCount = 2
        )

        val entry = JSONObject(logLines().single())

        assertEquals(1, entry.getInt("cacheHits"))
        assertEquals(2, entry.getInt("removedEvidenceCount"))
        assertTrue(entry.getJSONArray("tools").getJSONObject(0).getBoolean("cacheHit"))
        assertFalse(entry.getJSONArray("tools").getJSONObject(1).getBoolean("cacheHit"))
    }

    @Test
    fun `an event stream records failures incrementally and exports only redacted context`() {
        val subject = recorder()
        val session = subject.beginRun(
            sessionId = "agent-event",
            modelId = "model-x",
            startedAtMillis = now
        )
        session.record(
            type = AgentDiagnosticsEventType.ToolStarted,
            captureFingerprint = "capture-fingerprint",
            turn = 1,
            step = 1,
            toolName = "get_statistics",
            argumentsHash = "hash-secret",
            status = "started"
        )
        session.recordFailure(
            type = AgentDiagnosticsEventType.ToolFinished,
            boundary = "tool.get_statistics",
            throwable = RuntimeException(
                "Bearer super-secret api_key=secret-value imsi=460001234567890 " +
                    "https://private.example/capture"
            ),
            toolName = "get_statistics"
        )
        session.finish(
            status = "failed",
            error = AgentError(
                code = AgentErrorCode.INTERNAL_ERROR,
                userMessage = "failed"
            )
        )

        val exported = JSONObject(subject.exportRedacted())
        val events = exported.getJSONArray("events")

        assertTrue(events.length() >= 4)
        assertEquals("RunFinished", events.getJSONObject(events.length() - 1).getString("eventType"))
        assertFalse(exported.toString().contains("hash-secret"))
        assertFalse(exported.toString().contains("super-secret"))
        assertFalse(exported.toString().contains("secret-value"))
        assertFalse(exported.toString().contains("460001234567890"))
        assertFalse(exported.toString().contains("private.example"))
        assertFalse(exported.toString().contains("capture-fingerprint"))
    }

    @Test
    fun `a failed provider response is retained as bounded diagnostic metadata`() {
        val subject = recorder()
        val session = subject.beginRun(
            sessionId = "agent-response",
            modelId = "model-x",
            startedAtMillis = now
        )
        session.recordFailure(
            type = AgentDiagnosticsEventType.ModelResponse,
            boundary = "model.respond.response",
            error = AgentError(
                code = AgentErrorCode.MODEL_UNAVAILABLE,
                userMessage = "unavailable",
                retryable = true,
                details = mapOf(
                    "reason" to "http_503",
                    "httpStatus" to 503,
                    "remoteCode" to "upstream_overloaded",
                    "remoteType" to "server_error",
                    "remoteMessage" to "provider is temporarily unavailable",
                    "remoteBody" to "retry later",
                    "failureStage" to "body_read",
                    "networkFailureKind" to "timeout",
                    "bytesReceived" to 524_289L,
                    "responseLimitBytes" to 524_288L
                )
            )
        )
        session.finish(status = "failed")

        val events = JSONObject(subject.exportRedacted()).getJSONArray("events")
        val failure = (0 until events.length())
            .map { events.getJSONObject(it) }
            .first { it.getString("eventType") == "ModelResponse" }
            .getJSONObject("failure")

        assertEquals(503, failure.getInt("providerStatus"))
        assertEquals("upstream_overloaded", failure.getString("providerCode"))
        assertEquals("server_error", failure.getString("providerType"))
        assertEquals("provider is temporarily unavailable", failure.getString("providerMessage"))
        assertEquals("body_read", failure.getString("failureStage"))
        assertEquals("timeout", failure.getString("networkFailureKind"))
        assertEquals(524_289L, failure.getLong("bytesReceived"))
        assertEquals(524_288L, failure.getLong("responseLimitBytes"))
        assertFalse(failure.has("responsePreview"))
        assertFalse(subject.exportRedacted().contains("retry later"))
    }

    @Test
    fun `starting a new recorder session marks an unfinished previous run abandoned`() {
        val subject = recorder()
        val previous = subject.beginRun("agent-old", startedAtMillis = now)
        previous.record(
            type = AgentDiagnosticsEventType.SnapshotReady,
            captureFingerprint = "old-fingerprint",
            status = "succeeded"
        )

        val current = subject.beginRun("agent-new", startedAtMillis = now + 1_000L)
        current.finish(status = "completed")

        val events = JSONObject(subject.exportRedacted()).getJSONArray("events")
        val abandoned = (0 until events.length())
            .map { events.getJSONObject(it) }
            .firstOrNull { it.getString("eventType") == "RunAbandoned" }

        assertTrue(abandoned != null)
        assertEquals("agent-old", abandoned?.getString("sessionId"))
        assertEquals("process_restart_before_terminal_event", abandoned?.getJSONObject("failure")?.getString("reason"))
    }

    @Test
    fun `a caller-supplied runId and conversationId are used verbatim`() {
        val subject = recorder()
        val session = subject.beginRun(
            sessionId = "run_abc",
            runId = "run_abc",
            conversationId = "conv_xyz",
            startedAtMillis = now
        )
        session.record(
            type = AgentDiagnosticsEventType.SnapshotReady,
            captureFingerprint = "fingerprint-a",
            status = "succeeded"
        )
        session.finish(status = "completed")

        val events = JSONObject(subject.exportRedacted()).getJSONArray("events")
        val first = events.getJSONObject(0)

        // The diagnostics runId is the exact id the agent reported, so the
        // string on an error card is the same one the log is grouped by.
        assertEquals("run_abc", first.getString("runId"))
        assertEquals("conv_xyz", first.getString("conversationId"))
    }

    private fun logLines(): List<String> = temporaryFolder.root.listFiles()!!
        .filter { it.name.startsWith("agent-diagnostics") }
        .sortedBy { it.name }
        .flatMap { it.readLines() }
        .filter { it.isNotBlank() }

    private fun run(
        sessionId: String = "agent-1",
        fingerprint: String = "fingerprint-a",
        modelId: String = "model-x"
    ) = AgentDiagnosticsRun(
        sessionId = sessionId,
        captureFingerprint = fingerprint,
        modelId = modelId,
        promptVersion = "prompt-1",
        playbookVersion = "playbook-2",
        startedAtMillis = 100L,
        completedAtMillis = 400L,
        totalSteps = 2,
        totalDurationMillis = 300L,
        cancelReason = "MAX_STEPS_REACHED",
        evidenceCount = 3,
        removedEvidenceCount = 1,
        truncationEvents = 1,
        cacheHits = 1,
        memoryPressureEvents = 0,
        toolEvents = listOf(
            AgentDiagnosticsToolEvent(
                toolName = "get_statistics",
                normalizedArgumentsHash = "hash-a",
                durationMillis = 120L,
                returnedCount = 4L,
                totalCount = 9L,
                truncated = true,
                cacheHit = true
            ),
            AgentDiagnosticsToolEvent(
                toolName = "packet_search",
                normalizedArgumentsHash = "hash-b",
                durationMillis = 80L,
                returnedCount = 2L,
                totalCount = 2L,
                truncated = false,
                cacheHit = false,
                errorCode = AgentErrorCode.TOOL_TIMEOUT
            )
        )
    )
}

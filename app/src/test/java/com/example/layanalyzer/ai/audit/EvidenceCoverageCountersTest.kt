package com.example.layanalyzer.ai.audit

import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AnalysisScope
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Rule
import org.junit.Test
import org.junit.rules.TemporaryFolder

/**
 * EVL-COVERAGE-03: the evidence-coverage receipt lands in the audit records
 * as three counters — and only as counters. The frame-number sets stay in
 * the trace's in-memory object and are never serialized.
 */
class EvidenceCoverageCountersTest {
    @get:Rule
    val temporaryFolder = TemporaryFolder()

    private var now: Long = 5_000L

    private fun diagnosticsRecorder() = AgentDiagnosticsRecorder(
        directory = temporaryFolder.root,
        clock = { now }
    )

    private fun record(
        flagged: Int = 0,
        cited: Int = 0,
        outside: Int = 0
    ) = AgentRunRecord(
        sessionId = "session-1",
        captureFingerprint = "fingerprint",
        modelId = "model-x",
        promptVersion = "prompt-1",
        playbookVersion = null,
        analysisScope = "CurrentFilter",
        displayFilterApplied = false,
        startedAtMillis = 100L,
        completedAtMillis = 400L,
        evidenceFlaggedCount = flagged,
        evidenceCitedCount = cited,
        citationOutsideFlagged = outside
    )

    @Test
    fun `a finished record keeps the coverage counters it is given`() {
        val recorder = AgentRunAuditRecorder()
        recorder.start(
            sessionId = "session-1",
            snapshot = AgentCaptureSnapshot(
                fileFingerprint = "fingerprint",
                scope = AnalysisScope.CurrentFilter,
                displayFilter = "",
                startedAtMillis = 100L
            ),
            modelId = "model-x",
            promptVersion = "prompt-1",
            playbookVersion = null,
            startedAtMillis = 100L
        )

        val record = recorder.finish(
            completedAtMillis = 400L,
            evidenceFlaggedCount = 5,
            evidenceCitedCount = 3,
            citationOutsideFlagged = 2
        )!!

        assertEquals(5, record.evidenceFlaggedCount)
        assertEquals(3, record.evidenceCitedCount)
        assertEquals(2, record.citationOutsideFlagged)
    }

    @Test
    fun `a record finished without a coverage receipt keeps every counter at zero`() {
        val recorder = AgentRunAuditRecorder()
        recorder.start(
            sessionId = "session-1",
            snapshot = AgentCaptureSnapshot(
                fileFingerprint = "fingerprint",
                scope = AnalysisScope.CurrentFilter,
                displayFilter = "",
                startedAtMillis = 100L
            ),
            modelId = "model-x",
            promptVersion = "prompt-1",
            playbookVersion = null,
            startedAtMillis = 100L
        )

        val record = recorder.finish(completedAtMillis = 400L)!!

        assertEquals(0, record.evidenceFlaggedCount)
        assertEquals(0, record.evidenceCitedCount)
        assertEquals(0, record.citationOutsideFlagged)
    }

    @Test
    fun `the AgentRunRecord overload persists the coverage counters`() {
        diagnosticsRecorder().record(
            record = record(flagged = 7, cited = 4, outside = 3)
        )

        val entry = JSONObject(logLines().single())

        assertEquals(7, entry.getInt("evidenceFlaggedCount"))
        assertEquals(4, entry.getInt("evidenceCitedCount"))
        assertEquals(3, entry.getInt("citationOutsideFlagged"))
    }

    @Test
    fun `a diagnostics run without coverage persists zero counters`() {
        diagnosticsRecorder().record(record())

        val entry = JSONObject(logLines().single())

        assertEquals(0, entry.getInt("evidenceFlaggedCount"))
        assertEquals(0, entry.getInt("evidenceCitedCount"))
        assertEquals(0, entry.getInt("citationOutsideFlagged"))
    }

    @Test
    fun `the persisted line round-trips the coverage counters as integers`() {
        diagnosticsRecorder().record(
            record = record(flagged = 12, cited = 9, outside = 3)
        )

        // Encode → JSON text → parse: the receipt survives as three integers
        // a reader can decode without knowing the writer's field order.
        val parsed = JSONObject(logLines().single())

        assertEquals(12, parsed.getInt("evidenceFlaggedCount"))
        assertEquals(9, parsed.getInt("evidenceCitedCount"))
        assertEquals(3, parsed.getInt("citationOutsideFlagged"))
    }

    @Test
    fun `the persisted counters are counts only and carry no frame numbers`() {
        // Distinctive frame numbers a serialization of the sets would leak.
        val flaggedFrames = setOf(987654321L, 123456789L)
        val citedFrames = setOf(987654321L)
        val outsideFrames = setOf(555555555L)
        diagnosticsRecorder().record(
            record = record(
                flagged = flaggedFrames.size,
                cited = citedFrames.size,
                outside = outsideFrames.size
            )
        )

        val raw = logLines().single()

        assertEquals(2, JSONObject(raw).getInt("evidenceFlaggedCount"))
        assertFalse(raw.contains("987654321"))
        assertFalse(raw.contains("123456789"))
        assertFalse(raw.contains("555555555"))
    }

    @Test
    fun `an old run line without the coverage counters still exports`() {
        val old = JSONObject()
            .put("schema", "AgentDiagnosticsRun")
            .put("schemaVersion", 2)
            .put("sessionId", "old-run")
            .put("captureRef", "abcdef12")
            .put("modelId", "model-x")
            .put("promptVersion", "prompt-1")
            .put("playbookVersion", JSONObject.NULL)
            .put("startedAtMillis", 100L)
            .put("completedAtMillis", 400L)
            .put("totalSteps", 1)
            .put("totalDurationMillis", 300L)
            .put("cancelReason", JSONObject.NULL)
            .put("evidenceCount", 2)
            .put("removedEvidenceCount", 0)
            .put("truncationEvents", 0)
            .put("cacheHits", 0)
            .put("memoryPressureEvents", 0)
            .put("tools", org.json.JSONArray())
        temporaryFolder.newFile("agent-diagnostics.jsonl").writeText(old.toString() + "\n")

        val exported = JSONObject(diagnosticsRecorder().exportRedacted())
        val runs = exported.getJSONArray("runs")

        // The export parses the old line without error and keeps the run;
        // absent counters simply mean the pre-coverage schema.
        assertEquals(1, runs.length())
        assertEquals("old-run", runs.getJSONObject(0).getString("sessionId"))
        assertFalse(runs.getJSONObject(0).has("evidenceFlaggedCount"))
        assertTrue(exported.toString().contains("AgentDiagnosticsRun"))
    }

    private fun logLines(): List<String> = temporaryFolder.root.listFiles()!!
        .filter { it.name.startsWith("agent-diagnostics") }
        .sortedBy { it.name }
        .flatMap { it.readLines() }
        .filter { it.isNotBlank() }
}

// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.audit

import com.example.layanalyzer.ai.tools.AgentToolAuditEntry
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AnalysisScope
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentRunAuditRecorderTest {
    @Test
    fun `record keeps hash and counts but has no raw tool arguments`() {
        val recorder = AgentRunAuditRecorder()
        recorder.start(
            sessionId = "session-1",
            snapshot = AgentCaptureSnapshot(
                fileFingerprint = "fingerprint",
                scope = AnalysisScope.CurrentFilter,
                displayFilter = "tcp",
                startedAtMillis = 100L
            ),
            modelId = "model",
            promptVersion = "prompt",
            playbookVersion = "playbook",
            startedAtMillis = 100L
        )
        recorder.record(
            AgentToolAuditEntry(
                toolCallId = "tool-1",
                toolName = "packet_search",
                toolVersion = "1",
                stepIndex = 1,
                success = true,
                normalizedArgumentsHash = "aabbcc",
                sensitivity = com.example.layanalyzer.model.AgentDataSensitivity.Metadata,
                returnedCount = 2L,
                totalCount = 9L,
                truncated = true,
                resultBytes = 123,
                durationMillis = 8L
            )
        )

        val record = recorder.finish(completedAtMillis = 125L)!!

        assertEquals("aabbcc", record.toolCalls.single().normalizedArgumentsHash)
        assertEquals(2L, record.toolCalls.single().returned)
        assertEquals(9L, record.toolCalls.single().total)
        assertTrue(record.toolCalls.single().truncated)
        assertEquals(25L, record.totalDurationMillis)
        assertNull(record.cancelReason)
    }
}

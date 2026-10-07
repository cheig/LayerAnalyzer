package com.example.layanalyzer.ai

import com.example.layanalyzer.ai.serialization.AgentJsonCodec
import com.example.layanalyzer.ai.serialization.AgentJsonDecodeResult
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentFindingTimelineEvent
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentProvenance
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentReportProvenance
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AgentTruncationInfo
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.asToolMessage
import kotlinx.coroutines.CancellationException
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

class AgentJsonCodecTest {
    @Test
    fun reportRoundTripPreservesEvidenceUnicodeAndLongFrame() {
        val report = AgentReport(
            summary = "注册失败：服务器返回了 4xx 响应。",
            findings = listOf(
                AgentFinding(
                    id = "f-1",
                    title = "响应异常",
                    severity = AgentFindingSeverity.Error,
                    confidence = AgentConfidence.High,
                    conclusion = "请求和响应字段相互印证。",
                    evidence = listOf(
                        AgentEvidence(
                            type = AgentEvidenceType.Field,
                            frameNumber = 9_007_199_254_740_991L,
                            displayFilter = "sip.Method == \"REGISTER\"",
                            field = "sip.Status-Code",
                            observation = "响应为 403（拒绝）",
                            sourceToolCallId = "call-1"
                        )
                    ),
                    alternatives = listOf("抓包范围可能不完整"),
                    recommendations = listOf("检查鉴权配置"),
                    timeline = listOf(
                        AgentFindingTimelineEvent(
                            stage = "Authentication challenge",
                            frameNumber = 9_007_199_254_740_991L,
                            detail = "401 observed",
                            elapsedMillis = 120L
                        )
                    )
                )
            ),
            limitations = listOf("未读取 Payload"),
            recommendedNextSteps = listOf("查看 Expert 信息"),
            provenance = AgentReportProvenance(
                captureFingerprint = "sha256:test",
                scope = AnalysisScope.CurrentFilter,
                displayFilter = "sip",
                modelId = "mock",
                promptVersion = "p1",
                playbookVersion = "pb1",
                generatedAtMillis = 1_725_000_000_123L,
                toolCallIds = listOf("call-1")
            ),
            completeness = AgentReportCompleteness.Complete
        )

        val encoded = AgentJsonCodec.encodeReport(report)
        val root = JSONObject(encoded)
        assertEquals(1, root.getInt("schemaVersion"))
        assertEquals("AgentReport", root.getString("schema"))

        val decoded = AgentJsonCodec.decodeReport(encoded)
        assertTrue(decoded is AgentJsonDecodeResult.Success)
        assertEquals(report, decoded.getOrThrow())
    }

    @Test
    fun oldJsonMayOmitOptionalFields() {
        val json = """
            {
              "schema":"AgentReport",
              "schemaVersion":1,
              "summary":"legacy",
              "findings":[{"id":"f","title":"old","severity":"Info","confidence":"Low","conclusion":"x"}]
            }
        """.trimIndent()

        val decoded = AgentJsonCodec.decodeReport(json).getOrThrow()
        assertEquals("legacy", decoded.summary)
        assertEquals(emptyList<AgentEvidence>(), decoded.findings.single().evidence)
        assertEquals(AgentReportCompleteness.Unknown, decoded.completeness)
    }

    @Test
    fun unknownFieldsAndEnumValuesAreSafe() {
        val json = """
            {
              "schema":"AgentReport",
              "schemaVersion":1,
              "summary":"未知字段不会破坏 Unicode ✓",
              "futureField":{"secret":"ignored"},
              "completeness":"from-a-future-version",
              "findings":[{"severity":"future-severity","confidence":"future-confidence","evidence":[{"type":"future-type","observation":"ok"}]}]
            }
        """.trimIndent()

        val decoded = AgentJsonCodec.decodeReport(json).getOrThrow()
        assertEquals(AgentReportCompleteness.Unknown, decoded.completeness)
        assertEquals(AgentFindingSeverity.Unknown, decoded.findings.single().severity)
        assertEquals(AgentConfidence.Unknown, decoded.findings.single().confidence)
        assertEquals(AgentEvidenceType.Unknown, decoded.findings.single().evidence.single().type)
        assertEquals("", decoded.findings.single().evidence.single().sourceToolCallId)
    }

    @Test
    fun reportAndToolResultSchemasCannotBeConfused() {
        val toolJson = AgentJsonCodec.encodeToolResult(AgentToolResult())
        val decoded = AgentJsonCodec.decodeReport(toolJson)

        assertFalse(decoded.isSuccess)
        assertNotNull(decoded.error)
        assertTrue(AgentJsonCodec.REPORT_SCHEMA != AgentJsonCodec.TOOL_RESULT_SCHEMA)
    }

    @Test
    fun toolResultCarriesSensitivityTruncationDurationAndProvenance() {
        listOf(AgentDataSensitivity.Credential, AgentDataSensitivity.Payload).forEach { sensitivity ->
            val result = AgentToolResult(
                toolCallId = "call-9",
                toolName = "query_packet_summaries",
                success = true,
                data = mapOf("frameNumber" to 4_294_967_297L, "text" to "中文"),
                truncated = true,
                sensitivity = sensitivity,
                durationMillis = 321L,
                resultBytes = 987,
                truncation = AgentTruncationInfo(
                    sourceTruncated = true,
                    payloadTruncated = true,
                    returned = 1L,
                    total = 3L,
                    omittedFrames = listOf(8L, 9L),
                    omittedPaths = listOf("frames[1..2]"),
                    continuation = mapOf("offset" to 1L)
                )
            )

            val decoded = AgentJsonCodec.decodeToolResult(
                AgentJsonCodec.encodeToolResult(result)
            ).getOrThrow()
            assertEquals(result, decoded)
            assertEquals(sensitivity, decoded.sensitivity)
            assertTrue(decoded.truncated)
            assertEquals(321L, decoded.durationMillis)
            assertEquals(987, decoded.resultBytes)
        }
    }

    @Test
    fun malformedJsonReturnsStructuredError() {
        val decoded = AgentJsonCodec.decodeReport("{not-json")
        assertFalse(decoded.isSuccess)
        assertNotNull(decoded.error)
        assertEquals("AgentReport", decoded.error?.details?.get("contract"))
    }

    @Test
    fun structuredToolErrorRoundTripsWithoutAnExceptionObject() {
        val result = AgentToolResult(
            toolCallId = "failed-call",
            toolName = "validate_display_filter",
            success = false,
            error = AgentError(
                code = AgentErrorCode.INVALID_DISPLAY_FILTER,
                userMessage = "Filter is invalid.",
                retryable = true,
                details = mapOf("field" to "filter", "position" to 12L)
            )
        )

        val decoded = AgentJsonCodec.decodeToolResult(
            AgentJsonCodec.encodeToolResult(result)
        ).getOrThrow()
        assertEquals(result.toolCallId, decoded.toolCallId)
        assertEquals(result.error?.code, decoded.error?.code)
        assertEquals(result.error?.userMessage, decoded.error?.userMessage)
        assertEquals(12L, (decoded.error?.details?.get("position") as Number).toLong())
    }

    @Test
    fun toolMessagesAreAlwaysMarkedUntrusted() {
        val fingerprint = "0123456789abcdef".repeat(4)
        val result = AgentToolResult(
            toolCallId = "c",
            toolName = "overview",
            provenance = AgentProvenance(
                captureFingerprint = fingerprint,
                localSessionReference = "host-only"
            )
        )
        val message = AgentModelMessage.fromToolResult(result)
        assertTrue(message.untrustedCaptureData)
        assertEquals("c", message.toolResult?.toolCallId)
        assertEquals(null, message.toolResult?.provenance?.localSessionReference)
        val modelProvenance = message.structuredContent?.get("provenance") as Map<*, *>
        assertFalse(modelProvenance.containsKey("localSessionReference"))
        assertFalse("capture fingerprint leaked", modelProvenance.values.any { it == fingerprint })
        assertTrue(result.asToolMessage(untrusted = false).untrustedCaptureData)
        assertFalse(AgentModelMessage.system("constraint").untrustedCaptureData)
    }

    @Test(expected = CancellationException::class)
    fun safeDecoderPropagatesCancellation() {
        AgentJsonCodec.decodeSafely<String>("test") {
            throw CancellationException("cancelled")
        }
    }
}

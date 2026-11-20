// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.data

import com.example.layanalyzer.model.*
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.util.Base64

class TlsFollowParsingTest {
    private val generation = 7L

    private fun record(direction: String = "client", bytes: ByteArray = byteArrayOf(0, 1, -1), frame: Long = 23) =
        JSONObject().put("frameNumber", frame).put("direction", direction)
            .put("fromServer", if (direction == "unknown") JSONObject.NULL else direction == "server")
            .put("byteLength", bytes.size).put("bytesBase64", Base64.getEncoder().encodeToString(bytes))

    private fun success(vararg records: JSONObject = arrayOf(record())) = JSONObject().apply {
        put("schemaVersion", 1); put("success", true); put("errorCode", JSONObject.NULL); put("error", JSONObject.NULL)
        put("protocol", "tls"); put("scope", "complete_connection"); put("dissectionGeneration", generation)
        put("directionKnown", true); put("records", JSONArray(records.toList()))
        put("truncated", false); put("incomplete", false); put("streamId", 2); put("connectionFrames", 50)
        put("byteLength", records.sumOf { it.getInt("byteLength") }); put("unavailableReason", JSONObject.NULL)
    }

    private fun failure(reason: String? = null, code: String = "NOT_READY") = success().apply {
        put("success", false); put("errorCode", code); put("error", "secret-marker")
        put("records", JSONArray()); put("byteLength", 0); put("incomplete", true)
        put("unavailableReason", reason ?: JSONObject.NULL)
    }

    private fun parse(json: JSONObject, limit: Int = TLS_FOLLOW_PREVIEW_LIMIT) =
        TlsFollowParser.parse(json.toString(), generation, limit)

    private fun fails(code: String = "INVALID_RESPONSE", block: () -> Unit) {
        val error = assertThrows(TlsFollowException::class.java, block)
        assertEquals(code, error.errorCode)
        assertFalse(error.toString().contains("secret-marker"))
        assertNull(error.cause)
    }

    @Test fun preservesTlsScopeBinaryBytesBothDirectionsAndSourceFrames() {
        val parsed = parse(success(record(), record("server", byteArrayOf(13, 10, 0), 31)))
        assertTrue(parsed.success)
        assertEquals("tls", parsed.protocol)
        assertEquals(TlsFollowScope.CompleteConnection, parsed.scope)
        assertEquals(generation, parsed.dissectionGeneration)
        assertEquals(2, parsed.streamId)
        assertEquals(50, parsed.connectionFrames)
        assertEquals(6, parsed.byteLength)
        assertEquals(listOf(23L, 31L), parsed.records.map { it.frameNumber })
        assertEquals(listOf(false, true), parsed.records.map { it.fromServer })
        assertArrayEquals(byteArrayOf(0, 1, -1), parsed.records.first().bytes)
        assertArrayEquals(byteArrayOf(13, 10, 0), parsed.records.last().bytes)
        assertFalse(parsed.truncated)
        assertFalse(parsed.incomplete)
    }

    @Test fun unknownDirectionIsRetainedAndNeverInferredFromSelectedFrame() {
        val parsed = parse(success(record("unknown")).put("directionKnown", false).put("incomplete", true))
        assertFalse(parsed.directionKnown)
        assertNull(parsed.records.single().fromServer)
        assertEquals(TlsFollowDirection.Unknown, parsed.records.single().direction)
        assertTrue(parsed.incomplete)
    }

    @Test fun truncatedAndIncompletePreviewCanBeViewedButKeepsLimits() {
        val parsed = parse(success().put("truncated", true).put("incomplete", true), 3)
        assertTrue(parsed.truncated)
        assertTrue(parsed.incomplete)
        assertTrue(PacketTlsFollowAction.fromResult(parsed).enabled)
        fails { parse(success().put("truncated", true)) }
        fails { parse(success(record("unknown")).put("directionKnown", false)) }
    }

    @Test fun missingSecretsHasAnUnavailableReasonAndNeverAnEmptySuccess() {
        val result = parse(failure("SECRETS_NOT_CONFIGURED"))
        assertFalse(result.success)
        assertEquals(TlsErrorCode.NOT_READY, result.errorCode)
        assertEquals(TlsFollowUnavailableReason.SecretsNotConfigured, result.unavailableReason)
        assertTrue(result.records.isEmpty())
        val action = PacketTlsFollowAction.fromResult(result)
        assertFalse(action.enabled)
        assertEquals(result.unavailableReason, action.unavailableReason)
        assertEquals(generation, action.dissectionGeneration)
        fails { parse(success(*emptyArray())) }
    }

    @Test fun handshakeMissingOrNoPlaintextDoesNotBecomeAReadyAction() {
        mapOf("NOT_TLS" to TlsFollowUnavailableReason.NotTls,
            "HANDSHAKE_INCOMPLETE" to TlsFollowUnavailableReason.HandshakeIncomplete,
            "NO_DECRYPTED_APPLICATION_DATA" to TlsFollowUnavailableReason.NoDecryptedApplicationData,
            "future-secret-marker" to TlsFollowUnavailableReason.Unknown).forEach { (wire, expected) ->
            val result = parse(failure(wire))
            assertEquals(expected, result.unavailableReason)
            assertFalse(PacketTlsFollowAction.fromResult(result).enabled)
            assertFalse(result.toString().contains("secret-marker"))
        }
    }

    @Test fun capabilityNotReadyUnsupportedCancelledAndStaleNeverEnableFollow() {
        listOf("UNSUPPORTED", "NOT_READY", "CANCELLED", "STALE_GENERATION", "IO_ERROR").forEach { code ->
            val result = parse(failure(code = code).apply { remove("streamId"); remove("connectionFrames"); remove("byteLength") })
            assertEquals(TlsErrorCode.fromWire(code), result.errorCode)
            assertFalse(PacketTlsFollowAction.fromResult(result).enabled)
            assertTrue(result.records.isEmpty())
        }
        assertEquals(TlsErrorCode.UNKNOWN, parse(failure(code = "future-secret-marker")).errorCode)
        assertFalse(PacketTlsFollowAction().enabled)
        assertFalse(PacketTlsFollowAction(isLoading = true).enabled)
    }

    @Test fun failuresWithPartialPlaintextAreRejectedWithoutDecodingOrLeakingIt() {
        listOf("NOT_READY", "CANCELLED", "STALE_GENERATION", "IO_ERROR").forEach { code ->
            fails { parse(failure(code = code).put("records", JSONArray().put(record().put("bytesBase64", "secret-marker")))) }
        }
        fails { parse(failure().put("byteLength", 3)) }
        fails { parse(failure().put("incomplete", false)) }
        fails { parse(failure("SECRETS_NOT_CONFIGURED", "CANCELLED")) }
    }

    @Test fun wrongGenerationIsRejectedBeforeBytesCanBePublished() {
        fails("STALE_GENERATION") { parse(success().put("dissectionGeneration", generation + 1)) }
        fails("STALE_GENERATION") { parse(failure().put("dissectionGeneration", generation - 1)) }
    }

    @Test fun cannotSubstituteTcpUdpOrFilteredScopeForTls() {
        listOf("tcp", "udp", "TLS", "").forEach { fails { parse(success().put("protocol", it)) } }
        listOf("current filtered packet set", "current_filter", "unknown").forEach {
            fails { parse(success().put("scope", it)) }
        }
    }

    @Test fun rejectsMissingFieldsMalformedEnvelopesAndCoercedBooleans() {
        listOf("schemaVersion", "success", "scope", "protocol", "dissectionGeneration", "directionKnown",
            "records", "truncated", "incomplete", "streamId", "connectionFrames", "byteLength", "errorCode",
            "error", "unavailableReason").forEach { key -> fails { parse(success().apply { remove(key) }) } }
        listOf("success", "directionKnown", "truncated", "incomplete").forEach { key ->
            fails { parse(success().put(key, "true")) }
        }
        listOf("{}", "[]", "secret-marker").forEach { fails { TlsFollowParser.parse(it, generation, 3) } }
        fails { parse(success().put("schemaVersion", 2)) }
        fails { parse(success().put("error", "secret-marker")) }
    }

    @Test fun invalidBase64NeverProducesEmptyOrShortSuccess() {
        listOf("", "!!!!", "AAH/\n", "AAH", "AA==", "secret-marker").forEach { value ->
            fails { parse(success(record().put("bytesBase64", value))) }
        }
        fails { parse(success(record(bytes = byteArrayOf(0)).put("bytesBase64", "AB=="))) }
    }

    @Test fun rejectsInconsistentDirectionInsteadOfGuessingRoles() {
        listOf(record().put("fromServer", true), record().put("direction", "unknown"),
            record().put("direction", "future"), record().put("fromServer", "false"),
            record().apply { remove("fromServer") }).forEach { fails { parse(success(it)) } }
        fails { parse(success().put("directionKnown", false).put("incomplete", true)) }
    }

    @Test fun invalidFrameNumbersAndIntegerOverflowAreRejected() {
        listOf(0L, -1L, Int.MAX_VALUE.toLong() + 1, Long.MAX_VALUE).forEach {
            fails { parse(success(record(frame = it))) }
        }
        listOf("byteLength", "streamId", "connectionFrames", "dissectionGeneration").forEach { key ->
            fails { parse(success().put(key, "3")) }
            fails { parse(success().put(key, 3.5)) }
        }
        fails { parse(success().put("streamId", Long.MAX_VALUE)) }
        fails { parse(success(record().put("byteLength", Long.MAX_VALUE))) }
    }

    @Test fun enforcesAggregateByteBudgetAndDeclaredLength() {
        val json = success(record(), record("server"))
        assertEquals(6, parse(json, 6).byteLength)
        fails { parse(json, 5) }
        fails { parse(json.put("byteLength", 5), 6) }
        fails { parse(success(record(bytes = byteArrayOf()))) }
        fails { parse(success().put("byteLength", TLS_FOLLOW_PREVIEW_LIMIT + 1)) }
    }

    @Test fun acceptsExactOneMiBLimitAndRejectsLargerRequestBeforeParsing() {
        val bytes = ByteArray(TLS_FOLLOW_PREVIEW_LIMIT) { (it % 251).toByte() }
        assertArrayEquals(bytes, parse(success(record(bytes = bytes))).records.single().bytes)
        listOf(0, -1, TLS_FOLLOW_PREVIEW_LIMIT + 1, Int.MAX_VALUE).forEach {
            fails("INVALID_ARGUMENT") { TlsFollowParser.parse("secret-marker", generation, it) }
        }
        fails("INVALID_ARGUMENT") { TlsFollowParser.parse("secret-marker", -1, 1) }
    }

    @Test fun boundsRecordOverheadAndJsonSize() {
        val small = record(bytes = byteArrayOf(1))
        val records = JSONArray(List(TLS_FOLLOW_RECORD_LIMIT) { small })
        val json = success().put("records", records).put("byteLength", TLS_FOLLOW_RECORD_LIMIT)
        assertEquals(TLS_FOLLOW_RECORD_LIMIT, parse(json).records.size)
        records.put(small)
        fails { parse(json) }
        fails { TlsFollowParser.parse(" ".repeat(4 * 1024 * 1024 + 1), generation, 1) }
    }

    @Test fun resultToStringDoesNotContainPlaintextOrBase64() {
        val bytes = "secret-marker".toByteArray()
        val result = parse(success(record(bytes = bytes)))
        assertFalse(result.toString().contains("secret-marker"))
        assertFalse(result.toString().contains(Base64.getEncoder().encodeToString(bytes)))
    }

    @Test fun legacyActionsAndResultsRemainSeparateAndNoAiPlaintextMethodIsAdded() {
        val filters = PacketFollowFilters(sipCall = "sip.Call-ID == a", udpStream = "udp.stream == 3", tcpStream = "tcp.stream == 2")
        val state = PacketContextActionsState(frameNumber = 23, followFilters = filters,
            tlsFollow = PacketTlsFollowAction.fromResult(parse(success())))
        assertEquals(filters, state.followFilters)
        assertFalse(state.followFilters.isEmpty)
        assertTrue(state.tlsFollow.enabled)
        assertTrue(PacketFollowFilters().isEmpty)
        listOf("tcp", "udp").forEach { protocol ->
            val legacy = FollowStreamResult(protocol, 2, emptyList())
            assertEquals(protocol, legacy.protocol)
            assertEquals("current filtered packet set", legacy.scope)
        }
        assertFalse(AgentReadSession::class.java.methods.any { it.name == "followTlsStream" })
    }

    @Test fun repositoryRejectsClosedOrStaleAnalysisBeforeEnteringJniAndUsesOneFrameConversion() {
        val repository = PacketRepository()
        assertThrows(StaleCaptureAnalysisException::class.java) {
            repository.followTlsStream(1, repository.currentAnalysisRevision())
        }
        assertThrows(StaleCaptureAnalysisException::class.java) {
            repository.getPacketTlsFollowAction(23, CaptureAnalysisRevision(sessionHandle = 1, ready = true))
        }
        assertEquals(0, repository.packetIndex(1))
        assertEquals(22, repository.packetIndex(23))
        assertThrows(IllegalArgumentException::class.java) { repository.packetIndex(Int.MAX_VALUE.toLong() + 1) }
    }
}

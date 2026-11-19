// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.viewmodel

import com.example.layanalyzer.data.TlsFollowParser
import com.example.layanalyzer.model.PacketTlsFollowAction
import com.example.layanalyzer.model.TLS_FOLLOW_PREVIEW_LIMIT
import com.example.layanalyzer.model.TlsErrorCode
import com.example.layanalyzer.model.TlsFollowDirection
import com.example.layanalyzer.model.TlsFollowException
import com.example.layanalyzer.model.TlsFollowRecord
import com.example.layanalyzer.model.TlsFollowResult
import com.example.layanalyzer.model.TlsFollowScope
import com.example.layanalyzer.model.TlsFollowUnavailableReason
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test

/**
 * TLS-308 host tests for the TLS follow viewer state and the bounded export envelope. They use
 * synthetic bytes/responses only; the real native streaming export and the Compose pixels are the
 * `D=TlsFollowExportTest` / `U` walkthrough, which need a device.
 */
class TlsFollowUiStateTest {
    private val generation = 7L

    private fun record(
        direction: TlsFollowDirection = TlsFollowDirection.Client,
        frame: Long = 23,
        bytes: ByteArray = byteArrayOf(0, 1, -1)
    ) = TlsFollowRecord(
        frameNumber = frame,
        direction = direction,
        fromServer = when (direction) {
            TlsFollowDirection.Client -> false
            TlsFollowDirection.Server -> true
            TlsFollowDirection.Unknown -> null
        },
        bytes = bytes
    )

    private fun result(
        records: List<TlsFollowRecord> = listOf(record()),
        success: Boolean = true,
        directionKnown: Boolean = true,
        truncated: Boolean = false,
        incomplete: Boolean = false,
        errorCode: TlsErrorCode? = null,
        reason: TlsFollowUnavailableReason? = null
    ) = TlsFollowResult(
        success = success,
        scope = TlsFollowScope.CompleteConnection,
        dissectionGeneration = generation,
        directionKnown = directionKnown,
        records = records,
        truncated = truncated,
        incomplete = incomplete,
        streamId = 2,
        connectionFrames = 50,
        errorCode = errorCode,
        unavailableReason = reason
    )

    private fun exportEnvelope(
        success: Boolean = true,
        byteLength: Long = 12,
        sha256: Any = "ab".repeat(32),
        truncated: Boolean = false,
        incomplete: Boolean = false,
        directionKnown: Boolean = true,
        errorCode: Any = JSONObject.NULL,
        reason: Any = JSONObject.NULL,
        generation: Long = this.generation
    ) = JSONObject().apply {
        put("schemaVersion", 1); put("success", success); put("errorCode", errorCode); put("error", errorCode)
        put("protocol", "tls"); put("scope", "complete_connection"); put("dissectionGeneration", generation)
        put("directionKnown", directionKnown); put("truncated", truncated); put("incomplete", incomplete)
        put("streamId", 2); put("connectionFrames", 50); put("byteLength", byteLength)
        put("unavailableReason", reason); put("sha256", sha256)
    }

    // --- Menu prompts: no key, not TLS, handshake/missing packets, session switch, errors ---

    @Test fun contextPromptCoversDisabledLoadingAndEveryUnavailableReason() {
        assertNull("An enabled action has no prompt", TlsFollowUiState.promptFor(PacketTlsFollowAction(enabled = true)))
        assertEquals(TlsFollowPrompt.Loading, TlsFollowUiState.promptFor(PacketTlsFollowAction(isLoading = true)))
        assertEquals(TlsFollowPrompt.NotTls, TlsFollowUiState.promptFor(
            PacketTlsFollowAction(unavailableReason = TlsFollowUnavailableReason.NotTls)))
        assertEquals(TlsFollowPrompt.SecretsNotConfigured, TlsFollowUiState.promptFor(
            PacketTlsFollowAction(unavailableReason = TlsFollowUnavailableReason.SecretsNotConfigured)))
        assertEquals(TlsFollowPrompt.HandshakeIncomplete, TlsFollowUiState.promptFor(
            PacketTlsFollowAction(unavailableReason = TlsFollowUnavailableReason.HandshakeIncomplete)))
        assertEquals(TlsFollowPrompt.NoDecryptedApplicationData, TlsFollowUiState.promptFor(
            PacketTlsFollowAction(unavailableReason = TlsFollowUnavailableReason.NoDecryptedApplicationData)))
        assertEquals(TlsFollowPrompt.Unavailable, TlsFollowUiState.promptFor(
            PacketTlsFollowAction(unavailableReason = TlsFollowUnavailableReason.Unknown)))
    }

    @Test fun staleGenerationAndFailuresHaveDistinctPromptsNotASilentDisable() {
        assertEquals(TlsFollowPrompt.Stale, TlsFollowUiState.promptFor(
            PacketTlsFollowAction(errorCode = TlsErrorCode.STALE_GENERATION)))
        assertEquals(TlsFollowPrompt.Unavailable, TlsFollowUiState.promptFor(
            PacketTlsFollowAction(errorCode = TlsErrorCode.NOT_READY)))
        assertEquals(TlsFollowPrompt.Unavailable, TlsFollowUiState.promptFor(PacketTlsFollowAction()))
        assertEquals(TlsFollowPrompt.Failed, TlsFollowUiState.promptFor(
            PacketTlsFollowAction(errorCode = TlsErrorCode.IO_ERROR)))
    }

    // --- Viewer banners: scope, direction, truncation and incompleteness are explicit ---

    @Test fun bannerExposesScopeDirectionTruncationAndIncompleteness() {
        val banner = TlsFollowUiState.banner(result(truncated = true, incomplete = true))
        assertEquals(TlsFollowScope.CompleteConnection, banner.scope)
        assertTrue(banner.available)
        assertTrue(banner.directionKnown)
        assertTrue(banner.truncated)
        assertTrue(banner.incomplete)

        val unknown = TlsFollowUiState.banner(
            result(records = listOf(record(TlsFollowDirection.Unknown)), directionKnown = false, incomplete = true))
        assertFalse(unknown.directionKnown)
        assertTrue(unknown.available)
    }

    @Test fun anUnavailableResultIsNeverReportedAsAvailable() {
        val missingSecrets = result(records = emptyList(), success = false,
            errorCode = TlsErrorCode.NOT_READY, reason = TlsFollowUnavailableReason.SecretsNotConfigured)
        val banner = TlsFollowUiState.banner(missingSecrets)
        assertFalse(banner.available)
        assertEquals(TlsFollowUnavailableReason.SecretsNotConfigured, banner.unavailableReason)
    }

    // --- Rendering: formats, direction filter, query; format switch never mutates the bytes ---

    @Test fun formatsAreUtf8AsciiAndHexWithoutMutatingTheBytes() {
        val bytes = byteArrayOf(0x00, 0x7f, 0x41, -1)
        assertEquals("00 7F 41 FF", TlsFollowUiState.format(bytes, TlsFollowFormat.Hex))
        assertEquals("..A.", TlsFollowUiState.format(bytes, TlsFollowFormat.Ascii))
        assertArrayEquals(byteArrayOf(0x00, 0x7f, 0x41, -1), bytes)
        assertEquals("hi", TlsFollowUiState.format("hi".toByteArray(), TlsFollowFormat.Utf8))
    }

    @Test fun asciiAndHexMapOutOfRangeBytesToDotsAndHexDigits() {
        assertEquals("Ab..", TlsFollowUiState.format(byteArrayOf(0x41, 0x62, 0x00, 0x1f), TlsFollowFormat.Ascii))
        assertEquals("41 62 00 1F", TlsFollowUiState.format(byteArrayOf(0x41, 0x62, 0x00, 0x1f), TlsFollowFormat.Hex))
    }

    @Test fun directionFilterDropsUnknownRecordsFromASideButKeepsThemInBoth() {
        val records = listOf(
            record(TlsFollowDirection.Client, frame = 1),
            record(TlsFollowDirection.Server, frame = 2),
            record(TlsFollowDirection.Unknown, frame = 3)
        )
        assertEquals(3, TlsFollowUiState.filter(records, TlsFollowDirectionFilter.Both, "", TlsFollowFormat.Utf8).size)
        assertEquals(listOf(1L), TlsFollowUiState
            .filter(records, TlsFollowDirectionFilter.Client, "", TlsFollowFormat.Utf8).map { it.frameNumber })
        assertEquals(listOf(2L), TlsFollowUiState
            .filter(records, TlsFollowDirectionFilter.Server, "", TlsFollowFormat.Utf8).map { it.frameNumber })
    }

    @Test fun queryMatchesTheCurrentlyRenderedFormatOnly() {
        val records = listOf(
            record(bytes = "Hello".toByteArray()),
            record(TlsFollowDirection.Server, frame = 2, bytes = "bye".toByteArray())
        )
        assertEquals(1, TlsFollowUiState.filter(records, TlsFollowDirectionFilter.Both, "ell", TlsFollowFormat.Utf8).size)
        // 'H' is 0x48: a hex query matches only while the viewer renders hex.
        assertEquals(1, TlsFollowUiState.filter(records, TlsFollowDirectionFilter.Both, "48", TlsFollowFormat.Hex).size)
        assertEquals(0, TlsFollowUiState.filter(records, TlsFollowDirectionFilter.Both, "48", TlsFollowFormat.Utf8).size)
        assertEquals(2, TlsFollowUiState.filter(records, TlsFollowDirectionFilter.Both, "", TlsFollowFormat.Utf8).size)
    }

    @Test fun previewLimitStaysAtOneMiB() {
        assertEquals(1024 * 1024, TlsFollowUiState.previewLimit)
        assertEquals(TLS_FOLLOW_PREVIEW_LIMIT, TlsFollowUiState.previewLimit)
    }

    // --- Export: only a real success with a digest becomes Success; cancellation never does ---

    @Test fun aFinishedExportWithADigestIsSuccessAndCarriesTruncationHonestly() {
        val outcome = TlsFollowUiState.exportOutcome(
            TlsFollowParser.parseExport(exportEnvelope(truncated = true, incomplete = true).toString(), generation, 1024)
        )
        val success = outcome as TlsFollowExportOutcome.Success
        assertEquals(12L, success.byteLength)
        assertEquals("ab".repeat(32), success.sha256)
        assertTrue(success.truncated)
        assertTrue(success.incomplete)
    }

    @Test fun cancelledExportIsNeverSuccess() {
        val cancelled = exportEnvelope(success = false, byteLength = 0, sha256 = JSONObject.NULL,
            incomplete = true, errorCode = "CANCELLED")
        val outcome = TlsFollowUiState.exportOutcome(
            TlsFollowParser.parseExport(cancelled.toString(), generation, 1024))
        assertEquals(TlsFollowExportOutcome.Cancelled, outcome)
    }

    @Test fun failedExportKeepsItsErrorCodeAndAnAbsentDigestIsNotSuccess() {
        val failed = exportEnvelope(success = false, byteLength = 0, sha256 = JSONObject.NULL,
            incomplete = true, errorCode = "IO_ERROR")
        assertEquals(TlsFollowExportOutcome.Failed(TlsErrorCode.IO_ERROR),
            TlsFollowUiState.exportOutcome(TlsFollowParser.parseExport(failed.toString(), generation, 1024)))
    }

    @Test fun malformedOrStaleExportEnvelopesAreRejectedNotCoerced() {
        val stale = exportEnvelope(generation = generation + 1)
        val error = assertThrows(TlsFollowException::class.java) {
            TlsFollowParser.parseExport(stale.toString(), generation, 1024)
        }
        assertEquals("STALE_GENERATION", error.errorCode)

        listOf(
            exportEnvelope(sha256 = "short"),
            exportEnvelope(sha256 = JSONObject.NULL),
            exportEnvelope(byteLength = 0),
            exportEnvelope(truncated = true, incomplete = false)
        ).forEach { envelope ->
            assertThrows(TlsFollowException::class.java) {
                TlsFollowParser.parseExport(envelope.toString(), generation, 1024)
            }
        }
        assertThrows(TlsFollowException::class.java) {
            TlsFollowParser.parseExport(exportEnvelope().toString(), generation, 0)
        }
    }

    @Test fun exportFileNameIsStableAndNonEmpty() {
        assertEquals("tls-stream-2-23.bin", TlsFollowUiState.defaultExportFileName(23, 2))
        assertEquals("tls-stream-23-23.bin", TlsFollowUiState.defaultExportFileName(23, null))
    }

    // --- The TCP/UDP follow contract is untouched ---

    @Test fun legacyTcpUdpFollowIsNotAffectedByTheTlsViewer() {
        val viewer = TlsFollowViewerState(frameNumber = 23, result = result())
        assertEquals(23L, viewer.frameNumber)
        assertEquals("tls", viewer.result.protocol)
        assertFalse(TlsFollowUiState::class.java.methods.any { it.name == "followStream" })
    }
}

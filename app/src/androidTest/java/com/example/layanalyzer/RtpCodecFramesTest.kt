// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File

/**
 * RTP4-NAT-06: contract-level checks for `extractRtpCodecFrames` and
 * `exportRtpContainer` against the capture fixtures that actually exist.
 *
 * WHAT IS NOT TESTED HERE, AND WHY
 * ================================
 * The card's end-to-end acceptance for this task -- `framesPath` exists,
 * `frameCount > 0`, a `.fidx` written on real data that reads back through
 * FidxFile, and `detectedAmrMode` agreeing with the fixture's SDP `octet-align`
 * -- needs an AMR-NB, an AMR-WB and an Opus capture. **None of them exists in
 * `app/src/androidTest/assets/rtp/`**: the checked-in fixtures are
 * `sip_g711a_bidirectional.pcap`, `g711u_loss_reorder.pcap`,
 * `rtp_no_signal.pcap` and `srtp.pcap` (see CONTRIBUTING.md), and all four are
 * natively-decoded or rejected codecs, so every one of them takes the
 * `nativeDecode` / `srtp` / `needsMapping` return path.
 *
 * Creating an AMR/Opus fixture is RTP4-QA-01's deliverable (CONTRIBUTING.md
 * forbids hand-editing fixtures), so this file deliberately does **not** create
 * or synthesize one, and the missing assertions are not marked `@Ignore` or
 * softened to look complete. They are simply absent, and this comment is the
 * record that they are outstanding.
 *
 * What is left is what the available fixtures genuinely support: the four
 * rejection paths the card fixes, the "always an envelope" rule, and the
 * fail-closed promise that a rejected request leaves no output behind. The
 * `.fidx` format itself is covered byte-for-byte by the host test
 * `native_build/verification/rtp/host_tests/lib/FidxFileTest.cpp`.
 */
@RunWith(AndroidJUnit4::class)
class RtpCodecFramesTest {

    @Test(timeout = 120_000)
    fun staleScanGenerationIsRejectedByBothEndpoints() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val staleGeneration = scan.getLong("scanGeneration") + 1
            val streamId = findG711AStream(scan).getString("id")

            val extractDir = requestDir("stale-extract")
            extractDir.deleteRecursively()
            val extract = extractFrames(
                session = session,
                request = JSONObject()
                    .put("scanGeneration", staleGeneration)
                    .put("streamId", streamId)
                    .toString(),
                outDir = extractDir
            )
            assertEquals("staleScan", extract.getString("error"))
            assertFalse(extract.optBoolean("cancelled", true))
            assertNoOutputFiles(extractDir)

            val exportDir = requestDir("stale-export")
            exportDir.deleteRecursively()
            val export = exportContainer(
                session = session,
                request = JSONObject()
                    .put("scanGeneration", staleGeneration)
                    .put("streamId", streamId)
                    .put("format", "amr")
                    .toString(),
                outDir = exportDir
            )
            assertEquals("staleScan", export.getString("error"))
            assertFalse(export.optBoolean("cancelled", true))
            assertNoOutputFiles(exportDir)
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 120_000)
    fun nativelyDecodedCodecIsRejected() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val streamId = findG711AStream(scan).getString("id")
            val outDir = requestDir("native-decode")
            outDir.deleteRecursively()

            val result = extractFrames(
                session = session,
                request = JSONObject()
                    .put("scanGeneration", scan.getLong("scanGeneration"))
                    .put("streamId", streamId)
                    .toString(),
                outDir = outDir
            )
            // G.711A belongs to `decodeRtpAudio`, not to this endpoint. The
            // rejection must come from the codec id, because `decodable` on
            // this very stream is "yes" only by accident -- the whole
            // native-decode set is routed here, which is what keeps this table
            // and RTP4-KT-02's route table in agreement.
            assertEquals("nativeDecode", result.getString("error"))
            assertNoOutputFiles(outDir)
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 120_000)
    fun unknownStreamIdIsRejectedAsNotFound() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val outDir = requestDir("not-found")
            outDir.deleteRecursively()

            val result = extractFrames(
                session = session,
                request = JSONObject()
                    .put("scanGeneration", scan.getLong("scanGeneration"))
                    .put("streamId", "s9999")
                    .toString(),
                outDir = outDir
            )
            assertEquals("notFound", result.getString("error"))
            assertNoOutputFiles(outDir)
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 120_000)
    fun malformedRequestReturnsErrorWithoutCrash() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            // Every one of these has to come back as a JSON envelope with a
            // non-empty `error`, never as a crash or an exception.
            val malformed = listOf(
                "",
                "{",
                "[1,2,3]",
                "\"a string\"",
                JSONObject().put("streamId", "s0").toString(),
                JSONObject()
                    .put("scanGeneration", "x")
                    .put("streamId", "s0")
                    .toString(),
                JSONObject()
                    .put("scanGeneration", -1)
                    .put("streamId", "s0")
                    .toString(),
                JSONObject()
                    .put("scanGeneration", scan.getLong("scanGeneration"))
                    .put("streamId", "")
                    .toString(),
                JSONObject()
                    .put("scanGeneration", scan.getLong("scanGeneration"))
                    .put("streamId", "s0")
                    .put("amrMode", "nope")
                    .toString(),
                JSONObject()
                    .put("scanGeneration", scan.getLong("scanGeneration"))
                    .put("streamId", "s0")
                    .put("amrOctetAligned", "yes")
                    .toString()
            )

            for (request in malformed) {
                val outDir = requestDir("malformed")
                outDir.deleteRecursively()
                val result = extractFrames(session, request, outDir)
                assertTrue(
                    "malformed request '$request' did not report an error: $result",
                    result.getString("error").isNotEmpty()
                )
                assertFalse(result.optBoolean("cancelled", true))
                assertNoOutputFiles(outDir)
            }
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 120_000)
    fun exportRtpContainerChecksFormatAndLeavesNoHalfWrittenFile() {
        val session = openCapture(TARGET_SAMPLE)
        try {
            val scan = scan(session)
            val generation = scan.getLong("scanGeneration")
            val streamId = findG711AStream(scan).getString("id")
            val outDir = requestDir("export-format")
            outDir.deleteRecursively()

            // A format outside the three is a request error.
            val badFormat = exportContainer(
                session,
                JSONObject()
                    .put("scanGeneration", generation)
                    .put("streamId", streamId)
                    .put("format", "wav")
                    .toString(),
                outDir
            )
            assertEquals("format must be amr, awb or opus.", badFormat.getString("error"))

            // A missing format is the same error.
            val missingFormat = exportContainer(
                session,
                JSONObject()
                    .put("scanGeneration", generation)
                    .put("streamId", streamId)
                    .toString(),
                outDir
            )
            assertEquals(
                "format must be amr, awb or opus.",
                missingFormat.getString("error")
            )

            // A valid format on a codec this endpoint does not own is routed
            // away before any file is opened.
            val nativeDecode = exportContainer(
                session,
                JSONObject()
                    .put("scanGeneration", generation)
                    .put("streamId", streamId)
                    .put("format", "amr")
                    .toString(),
                outDir
            )
            assertEquals("nativeDecode", nativeDecode.getString("error"))
            assertNoOutputFiles(outDir)
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 120_000)
    fun srtpStreamIsRejectedBeforeRouting() {
        val session = openCapture("srtp")
        try {
            val scan = scan(session)
            val stream = findStreamByDecodability(scan, "srtp")
            val outDir = requestDir("srtp")
            outDir.deleteRecursively()

            val result = extractFrames(
                session = session,
                request = JSONObject()
                    .put("scanGeneration", scan.getLong("scanGeneration"))
                    .put("streamId", stream.getString("id"))
                    .toString(),
                outDir = outDir
            )
            assertEquals("srtp", result.getString("error"))
            assertNoOutputFiles(outDir)
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    private fun extractFrames(
        session: Long,
        request: String,
        outDir: File
    ): JSONObject {
        val result = JSONObject(
            NativeEngine.extractRtpCodecFrames(
                session,
                request,
                outDir.absolutePath,
                null
            )
        )
        assertEnvelope(result)
        return result
    }

    private fun exportContainer(
        session: Long,
        request: String,
        outDir: File
    ): JSONObject {
        val result = JSONObject(
            NativeEngine.exportRtpContainer(session, request, outDir.absolutePath)
        )
        assertEnvelope(result)
        return result
    }

    /** RTP4-NAT-06: every return value carries the envelope, errors included. */
    private fun assertEnvelope(result: JSONObject) {
        assertEquals(
            "schemaVersion must be 1 on every return: $result",
            1,
            result.optInt("schemaVersion", -1)
        )
        assertTrue("result has no 'error' key: $result", result.has("error"))
        assertTrue("error must be a string: $result", result.opt("error") is String)
    }

    private fun assertNoOutputFiles(outDir: File) {
        assertTrue(
            "a rejected codec frame request left output behind: " +
                outDir.listFiles().orEmpty().joinToString(),
            !outDir.exists() || outDir.listFiles().orEmpty().isEmpty()
        )
    }

    private fun openCapture(sampleName: String): Long {
        val capture = copyAssetFile(
            testContext,
            "rtp/$sampleName.pcap",
            File(appContext.cacheDir, "rtp-codec-frames-$sampleName.pcap")
        )
        val session = NativeEngine.openFile(capture.absolutePath, null)
        assertNotEquals(
            "openFile failed: ${NativeEngine.getLastError()}",
            0L,
            session
        )
        return session
    }

    private fun scan(session: Long): JSONObject {
        val result = JSONObject(
            NativeEngine.scanRtpStreams(
                session,
                "{\"limitToDisplayFilter\":false}",
                null
            )
        )
        assertEquals(
            "scanRtpStreams reported an error: ${result.optString("error")}",
            "",
            result.optString("error")
        )
        assertFalse(result.optBoolean("cancelled", true))
        return result
    }

    private fun findG711AStream(scan: JSONObject): JSONObject {
        val streams = requireNotNull(scan.optJSONArray("streams"))
        for (index in 0 until streams.length()) {
            val stream = streams.getJSONObject(index)
            if (stream.optLong("ssrc") == TARGET_SSRC &&
                stream.optString("codec") == "g711A" &&
                stream.optString("decodable") == "yes"
            ) {
                return stream
            }
        }
        throw AssertionError(
            "No decodable g711A SSRC=$TARGET_SSRC stream was found: $scan"
        )
    }

    private fun findStreamByDecodability(
        scan: JSONObject,
        decodability: String
    ): JSONObject {
        val streams = requireNotNull(scan.optJSONArray("streams"))
        for (index in 0 until streams.length()) {
            val stream = streams.getJSONObject(index)
            if (stream.optString("decodable") == decodability) {
                return stream
            }
        }
        throw AssertionError("No $decodability stream was found: $scan")
    }

    private fun requestDir(name: String): File =
        File(appContext.cacheDir, "rtp-codec-frames-$name")

    @After
    fun cleanOutputs() {
        appContext.cacheDir.listFiles()
            .orEmpty()
            .filter { it.name.startsWith("rtp-codec-frames-") }
            .forEach(File::deleteRecursively)
    }

    companion object {
        private const val TARGET_SAMPLE = "sip_g711a_bidirectional"
        private const val TARGET_SSRC = 2591773570L

        private lateinit var appContext: Context
        private lateinit var testContext: Context

        @JvmStatic
        @BeforeClass
        fun initializeEngine() {
            appContext = ApplicationProvider.getApplicationContext()
            testContext = InstrumentationRegistry.getInstrumentation().context
            val application = appContext as LayerAnalyzerApplication

            var engineState = runBlocking {
                withTimeout(30_000) {
                    application.engineState.first {
                        it is EngineState.Ready ||
                            it is EngineState.Failed ||
                            it is EngineState.AwaitingSessionRestore
                    }
                }
            }
            if (engineState is EngineState.AwaitingSessionRestore) {
                application.declineSessionRestore()
                engineState = runBlocking {
                    withTimeout(30_000) {
                        application.engineState.first {
                            it is EngineState.Ready || it is EngineState.Failed
                        }
                    }
                }
            }
            assertTrue(
                (engineState as? EngineState.Failed)?.message
                    ?: "Native engine did not initialize.",
                engineState is EngineState.Ready
            )
            copyAssetFolder(
                appContext,
                "wireshark-data",
                File(appContext.filesDir, "wireshark-data")
            )
        }

        private fun copyAssetFolder(
            context: Context,
            assetPath: String,
            targetDir: File
        ) {
            targetDir.mkdirs()
            val children = context.assets.list(assetPath).orEmpty()
            if (children.isEmpty()) {
                copyAssetFile(context, assetPath, targetDir)
                return
            }
            for (child in children) {
                val childAssetPath = "$assetPath/$child"
                val grandChildren = context.assets.list(childAssetPath).orEmpty()
                if (grandChildren.isEmpty()) {
                    copyAssetFile(
                        context,
                        childAssetPath,
                        File(targetDir, child)
                    )
                } else {
                    copyAssetFolder(
                        context,
                        childAssetPath,
                        File(targetDir, child)
                    )
                }
            }
        }

        private fun copyAssetFile(
            context: Context,
            assetPath: String,
            targetFile: File
        ): File {
            targetFile.parentFile?.mkdirs()
            context.assets.open(assetPath).use { input ->
                targetFile.outputStream().use { output ->
                    input.copyTo(output)
                }
            }
            return targetFile
        }
    }
}

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
 * RTP2-NAT-07: raw payload export through the JNI boundary.
 */
@RunWith(AndroidJUnit4::class)
class RtpRawExportTest {

    @Test(timeout = 60_000)
    fun g711aSeqAndArrivalMatchAndSkipTelephoneEvents() {
        val session = openCapture("sip_g711a_bidirectional")
        try {
            val scan = scan(session)
            val stream = streamWithNonPrimaryPayloadType(scan, "g711A")
            val streamId = stream.getString("id")
            val sequence = export(session, scan, streamId, "seq")
            val arrival = export(session, scan, streamId, "arrival")

            // This fixture sends G.711A every 30 ms (240 samples/packet).
            assertSuccessfulExport(sequence, expectedPayloadSize = 240)
            assertSuccessfulExport(arrival, expectedPayloadSize = 240)
            assertEquals(
                "seq and arrival packet counts differ for a non-reordered fixture",
                sequence.getLong("packets"),
                arrival.getLong("packets")
            )
            assertTrue(
                "raw export must contain at least one G.711A payload",
                sequence.getLong("packets") > 0L
            )
            assertTrue(
                "raw export must skip non-primary telephone-event packets",
                sequence.getLong("packets") < stream.getLong("packets")
            )
            assertTrue(
                "seq and arrival outputs must match for a non-reordered fixture",
                outputFile(streamId, "seq").readBytes()
                    .contentEquals(outputFile(streamId, "arrival").readBytes())
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 60_000)
    fun g711uSeqAndArrivalDifferForReorderedPackets() {
        val session = openCapture("g711u_loss_reorder")
        try {
            val scan = scan(session)
            val stream = firstStream(scan, "g711U")
            val streamId = stream.getString("id")
            val sequence = export(session, scan, streamId, "seq")
            val arrival = export(session, scan, streamId, "arrival")

            assertSuccessfulExport(sequence, expectedPayloadSize = 160)
            assertSuccessfulExport(arrival, expectedPayloadSize = 160)
            assertEquals(
                "seq and arrival must contain the same packets",
                sequence.getLong("packets"),
                arrival.getLong("packets")
            )
            assertFalse(
                "seq and arrival outputs must differ for reordered packets",
                outputFile(streamId, "seq").readBytes()
                    .contentEquals(outputFile(streamId, "arrival").readBytes())
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    @Test(timeout = 60_000)
    fun staleGenerationAndMissingStreamFailClosed() {
        val session = openCapture("sip_g711a_bidirectional")
        try {
            val scan = scan(session)
            val streamId = firstStream(scan, "g711A").getString("id")
            val generation = scan.getLong("scanGeneration")

            val stalePath = outputFile("stale", "seq")
            val stale = JSONObject(
                NativeEngine.exportRtpPayloadRaw(
                    session,
                    JSONObject()
                        .put("scanGeneration", generation - 1L)
                        .put("streamId", streamId)
                        .put("order", "seq")
                        .toString(),
                    stalePath.absolutePath
                )
            )
            assertEquals("staleScan", stale.optString("error"))
            assertFalse(
                "stale export must not create an output file",
                stalePath.exists()
            )

            val missingPath = outputFile("missing", "seq")
            val missing = JSONObject(
                NativeEngine.exportRtpPayloadRaw(
                    session,
                    JSONObject()
                        .put("scanGeneration", generation)
                        .put("streamId", "s999")
                        .put("order", "seq")
                        .toString(),
                    missingPath.absolutePath
                )
            )
            assertEquals("notFound", missing.optString("error"))
            assertFalse(
                "missing export must not create an output file",
                missingPath.exists()
            )
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    private fun openCapture(sampleName: String): Long {
        val capture = copyAssetFile(
            testContext,
            "rtp/$sampleName.pcap",
            File(appContext.cacheDir, "rtp-raw-$sampleName.pcap")
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
        return result
    }

    private fun firstStream(scan: JSONObject, codec: String): JSONObject {
        val streams = requireNotNull(scan.optJSONArray("streams"))
        for (index in 0 until streams.length()) {
            val stream = streams.getJSONObject(index)
            if (stream.optString("codec") == codec &&
                stream.optString("decodable") == "yes"
            ) {
                return stream
            }
        }
        throw AssertionError("No decodable $codec stream was found: $scan")
    }

    private fun streamWithNonPrimaryPayloadType(
        scan: JSONObject,
        codec: String
    ): JSONObject {
        val streams = requireNotNull(scan.optJSONArray("streams"))
        for (index in 0 until streams.length()) {
            val stream = streams.getJSONObject(index)
            val payloadTypes = stream.optJSONArray("ptsSeen") ?: continue
            for (ptIndex in 0 until payloadTypes.length()) {
                val nonPrimary =
                    payloadTypes.optInt(ptIndex) !=
                        stream.optInt("primaryPayloadType")
                if (nonPrimary &&
                    stream.optString("codec") == codec &&
                    stream.optString("decodable") == "yes"
                ) {
                    return stream
                }
            }
        }
        throw AssertionError(
            "No decodable $codec stream with a non-primary PT was found: $scan"
        )
    }

    private fun export(
        session: Long,
        scan: JSONObject,
        streamId: String,
        order: String
    ): JSONObject {
        val output = outputFile(streamId, order)
        return JSONObject(
            NativeEngine.exportRtpPayloadRaw(
                session,
                JSONObject()
                    .put("scanGeneration", scan.getLong("scanGeneration"))
                    .put("streamId", streamId)
                    .put("order", order)
                    .toString(),
                output.absolutePath
            )
        )
    }

    private fun assertSuccessfulExport(result: JSONObject, expectedPayloadSize: Int) {
        assertEquals(
            "exportRtpPayloadRaw reported an error: ${result.optString("error")}",
            "",
            result.optString("error")
        )
        assertEquals(
            "unexpected raw payload byte count",
            result.getLong("packets") * expectedPayloadSize,
            result.getLong("bytes")
        )
    }

    private fun outputFile(streamId: String, order: String): File =
        File(appContext.cacheDir, "rtp-raw-export-$streamId-$order.bin")

    @After
    fun cleanOutputs() {
        appContext.cacheDir.listFiles()
            .orEmpty()
            .filter { it.name.startsWith("rtp-raw-export-") }
            .forEach { it.delete() }
    }

    companion object {
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

        private fun copyAssetFolder(context: Context, assetPath: String, targetDir: File) {
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
                    copyAssetFile(context, childAssetPath, File(targetDir, child))
                } else {
                    copyAssetFolder(context, childAssetPath, File(targetDir, child))
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

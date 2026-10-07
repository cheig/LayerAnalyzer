package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertNotEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith
import java.io.File
import kotlin.math.abs

/**
 * RTP1-QA-01: compares `scanRtpStreams` with the tshark 4.0.10 golden files.
 *
 * Streams are matched by `(src, srcPort, dst, dstPort, ssrc)` rather than by
 * array order because the native result is ordered by first frame while tshark
 * uses stream creation order.
 */
@RunWith(AndroidJUnit4::class)
class RtpStreamScanTest {

    @Test(timeout = 60_000)
    fun sipG711aBidirectionalMatchesGolden() {
        assertCaptureMatchesGolden("sip_g711a_bidirectional")
    }

    @Test(timeout = 60_000)
    fun g711uLossReorderMatchesGolden() {
        assertCaptureMatchesGolden("g711u_loss_reorder")
    }

    @Test(timeout = 60_000)
    fun rtpNoSignalMatchesGolden() {
        assertCaptureMatchesGolden("rtp_no_signal")
    }

    @Test(timeout = 60_000)
    fun srtpMatchesGolden() {
        assertCaptureMatchesGolden("srtp")
    }

    private fun assertCaptureMatchesGolden(sampleName: String) {
        val golden = JSONObject(
            readAssetText("rtp/golden/$sampleName.streams.json")
        )
        val captureFile = copyAssetFile(
            testContext,
            "rtp/$sampleName.pcap",
            File(appContext.cacheDir, "$sampleName.pcap")
        )

        var heuristicTouched = false
        try {
            val desiredHeuristic = golden.getBoolean("heuristic")
            heuristicTouched = true
            setHeuristic(sampleName, enabled = desiredHeuristic)

            val session = NativeEngine.openFile(captureFile.absolutePath, null)
            assertNotEquals(
                failure(sampleName, "<session>", "openFile", "non-zero", session),
                0L,
                session
            )
            try {
                val result = JSONObject(
                    NativeEngine.scanRtpStreams(
                        session,
                        "{\"limitToDisplayFilter\":false}",
                        null
                    )
                )
                assertEquals(
                    failure(
                        sampleName,
                        "<scan>",
                        "error",
                        "",
                        result.optString("error")
                    ),
                    "",
                    result.optString("error")
                )
                assertFalse(
                    failure(
                        sampleName,
                        "<scan>",
                        "cancelled",
                        false,
                        result.optBoolean("cancelled", true)
                    ),
                    result.optBoolean("cancelled", true)
                )
                assertEquals(
                    failure(
                        sampleName,
                        "<scan>",
                        "heuristicEnabled",
                        golden.getBoolean("heuristic"),
                        result.optBoolean("heuristicEnabled", !golden.getBoolean("heuristic"))
                    ),
                    golden.getBoolean("heuristic"),
                    result.optBoolean("heuristicEnabled", !golden.getBoolean("heuristic"))
                )

                assertStreamsMatch(sampleName, golden, result)
            } finally {
                if (session != 0L) {
                    NativeEngine.closeFile(session)
                }
            }
        } finally {
            if (heuristicTouched) {
                setHeuristic(sampleName, enabled = false)
            }
        }
    }

    private fun assertStreamsMatch(
        sampleName: String,
        golden: JSONObject,
        result: JSONObject
    ) {
        val expectedStreams = requiredArray(golden, "streams", sampleName, "<scan>")
        val actualStreams = requiredArray(result, "streams", sampleName, "<scan>")
        assertEquals(
            failure(
                sampleName,
                "<all>",
                "streamCount",
                expectedStreams.length(),
                actualStreams.length()
            ),
            expectedStreams.length(),
            actualStreams.length()
        )

        val actualByKey = linkedMapOf<StreamKey, JSONObject>()
        for (index in 0 until actualStreams.length()) {
            val stream = actualStreams.optJSONObject(index)
            assertNotNull(
                failure(
                    sampleName,
                    "<index=$index>",
                    "streamObject",
                    "JSON object",
                    actualStreams.opt(index)
                ),
                stream
            )
            val key = streamKey(stream!!, sampleName)
            val previous = actualByKey.put(key, stream)
            if (previous != null) {
                throw AssertionError(
                    failure(
                        sampleName,
                        key.toString(),
                        "duplicateStreamKey",
                        "one stream",
                        "more than one stream"
                    )
                )
            }
        }

        for (index in 0 until expectedStreams.length()) {
            val expectedStream = expectedStreams.optJSONObject(index)
            assertNotNull(
                failure(
                    sampleName,
                    "<goldenIndex=$index>",
                    "streamObject",
                    "JSON object",
                    expectedStreams.opt(index)
                ),
                expectedStream
            )
            val key = streamKey(expectedStream!!, sampleName)
            val actualStream = actualByKey.remove(key)
            assertNotNull(
                failure(sampleName, key.toString(), "stream", "present", "missing"),
                actualStream
            )
            assertStreamMatches(sampleName, key, expectedStream, actualStream!!)
        }

        if (actualByKey.isNotEmpty()) {
            throw AssertionError(
                failure(
                    sampleName,
                    actualByKey.keys.joinToString(),
                    "unexpectedStreams",
                    "none",
                    actualByKey.keys.joinToString()
                )
            )
        }
    }

    private fun assertStreamMatches(
        sampleName: String,
        key: StreamKey,
        expected: JSONObject,
        actual: JSONObject
    ) {
        assertLongField(sampleName, key, expected, actual, "packets")
        assertLongField(sampleName, key, expected, actual, "lost")

        val expectedLostPct = requiredDouble(expected, "lostPct", sampleName, key)
        val actualLostPct = requiredDouble(actual, "lostPct", sampleName, key)
        assertTrue(
            failure(
                sampleName,
                key.toString(),
                "lostPct (abs difference < 0.05)",
                expectedLostPct,
                actualLostPct
            ),
            abs(actualLostPct - expectedLostPct) < 0.05
        )

        val seqErrors = requiredLong(actual, "seqErrors", sampleName, key)
        if (requiredBoolean(expected, "problems", sampleName, key)) {
            assertTrue(
                failure(
                    sampleName,
                    key.toString(),
                    "seqErrors (must be > 0 when golden problems=true)",
                    "> 0",
                    seqErrors
                ),
                seqErrors > 0L
            )
        }

        assertCloseField(sampleName, key, expected, actual, "maxDeltaMs")
        assertCloseField(sampleName, key, expected, actual, "meanDeltaMs")

        val goldenJitterAvailable = requiredDouble(
            expected,
            "minJitterMs",
            sampleName,
            key
        ) != -1.0
        val actualJitterAvailable = requiredBoolean(
            actual,
            "jitterAvailable",
            sampleName,
            key
        )
        if (goldenJitterAvailable && actualJitterAvailable) {
            assertCloseField(sampleName, key, expected, actual, "maxJitterMs")
            assertCloseField(sampleName, key, expected, actual, "meanJitterMs")
        }

        if (sampleName == "srtp" && key in SRTP_STREAMS) {
            val expectedDecodable = "srtp"
            val actualDecodable = requiredString(
                actual,
                "decodable",
                sampleName,
                key
            )
            assertEquals(
                failure(
                    sampleName,
                    key.toString(),
                    "decodable",
                    expectedDecodable,
                    actualDecodable
                ),
                expectedDecodable,
                actualDecodable
            )
        }
    }

    private fun assertLongField(
        sampleName: String,
        key: StreamKey,
        expected: JSONObject,
        actual: JSONObject,
        field: String
    ) {
        val expectedValue = requiredLong(expected, field, sampleName, key)
        val actualValue = requiredLong(actual, field, sampleName, key)
        assertEquals(
            failure(sampleName, key.toString(), field, expectedValue, actualValue),
            expectedValue,
            actualValue
        )
    }

    private fun assertCloseField(
        sampleName: String,
        key: StreamKey,
        expected: JSONObject,
        actual: JSONObject,
        field: String
    ) {
        val expectedValue = requiredDouble(expected, field, sampleName, key)
        val actualValue = requiredDouble(actual, field, sampleName, key)
        assertTrue(
            failure(
                sampleName,
                key.toString(),
                "$field (abs difference <= 0.01)",
                expectedValue,
                actualValue
            ),
            abs(actualValue - expectedValue) <= 0.01
        )
    }

    private fun setHeuristic(sampleName: String, enabled: Boolean) {
        val response = JSONObject(NativeEngine.setRtpHeuristicEnabled(enabled))
        val error = response.optString("error")
        assertEquals(
            failure(
                sampleName,
                "<heuristic>",
                "setRtpHeuristicEnabled.error",
                "",
                error
            ),
            "",
            error
        )
        assertEquals(
            failure(
                sampleName,
                "<heuristic>",
                "setRtpHeuristicEnabled.enabled",
                enabled,
                response.optBoolean("enabled", !enabled)
            ),
            enabled,
            response.optBoolean("enabled", !enabled)
        )
        assertEquals(
            failure(
                sampleName,
                "<heuristic>",
                "setRtpHeuristicEnabled.failed.length",
                0,
                response.optJSONArray("failed")?.length() ?: 0
            ),
            0,
            response.optJSONArray("failed")?.length() ?: 0
        )
        assertEquals(
            failure(
                sampleName,
                "<heuristic>",
                "isRtpHeuristicEnabled",
                enabled,
                NativeEngine.isRtpHeuristicEnabled()
            ),
            enabled,
            NativeEngine.isRtpHeuristicEnabled()
        )
    }

    private fun streamKey(stream: JSONObject, sampleName: String): StreamKey =
        try {
            StreamKey(
                src = stream.getString("src"),
                srcPort = stream.getInt("srcPort"),
                dst = stream.getString("dst"),
                dstPort = stream.getInt("dstPort"),
                ssrc = valueAsDecimalString(stream.get("ssrc"))
            )
        } catch (error: Exception) {
            throw AssertionError(
                failure(
                    sampleName,
                    "<unreadable>",
                    "stream key (src, srcPort, dst, dstPort, ssrc)",
                    "all fields present",
                    stream
                ),
                error
            )
        }

    private fun requiredArray(
        owner: JSONObject,
        field: String,
        sampleName: String,
        key: Any
    ): JSONArray {
        val value = owner.optJSONArray(field)
        if (value == null) {
            throw AssertionError(
                failure(sampleName, key.toString(), field, "JSON array", owner.opt(field))
            )
        }
        return value
    }

    private fun requiredLong(
        stream: JSONObject,
        field: String,
        sampleName: String,
        key: Any
    ): Long {
        if (!stream.has(field)) {
            throw AssertionError(
                failure(sampleName, key.toString(), field, "present", "missing")
            )
        }
        return stream.getLong(field)
    }

    private fun requiredDouble(
        stream: JSONObject,
        field: String,
        sampleName: String,
        key: Any
    ): Double {
        if (!stream.has(field)) {
            throw AssertionError(
                failure(sampleName, key.toString(), field, "present", "missing")
            )
        }
        return stream.getDouble(field)
    }

    private fun requiredBoolean(
        stream: JSONObject,
        field: String,
        sampleName: String,
        key: Any
    ): Boolean {
        if (!stream.has(field)) {
            throw AssertionError(
                failure(sampleName, key.toString(), field, "present", "missing")
            )
        }
        return stream.getBoolean(field)
    }

    private fun requiredString(
        stream: JSONObject,
        field: String,
        sampleName: String,
        key: Any
    ): String {
        if (!stream.has(field)) {
            throw AssertionError(
                failure(sampleName, key.toString(), field, "present", "missing")
            )
        }
        return stream.getString(field)
    }

    private fun valueAsDecimalString(value: Any): String =
        if (value is Number) value.toLong().toString() else value.toString()

    private fun failure(
        sampleName: String,
        flowKey: String,
        field: String,
        expected: Any?,
        actual: Any?
    ): String = "sample=$sampleName flowKey=$flowKey field=$field expected=$expected actual=$actual"

    private data class StreamKey(
        val src: String,
        val srcPort: Int,
        val dst: String,
        val dstPort: Int,
        val ssrc: String
    ) {
        override fun toString(): String = "$src:$srcPort -> $dst:$dstPort ssrc=$ssrc"
    }

    companion object {
        private val SRTP_STREAMS = setOf(
            StreamKey(
                src = "192.168.10.41",
                srcPort = 64508,
                dst = "192.168.10.40",
                dstPort = 49848,
                ssrc = "3202413293"
            ),
            StreamKey(
                src = "192.168.10.40",
                srcPort = 49848,
                dst = "192.168.10.41",
                dstPort = 64508,
                ssrc = "3073011972"
            )
        )

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

            // The Application owns native engine initialization. Ensure the
            // asset copy is complete, but never call initEngine a second time.
            copyAssetFolder(
                appContext,
                "wireshark-data",
                File(appContext.filesDir, "wireshark-data")
            )
        }

        private fun readAssetText(assetPath: String): String =
            testContext.assets.open(assetPath).bufferedReader(Charsets.UTF_8).use { reader ->
                reader.readText()
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

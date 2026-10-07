// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer

import android.content.Context
import androidx.test.core.app.ApplicationProvider
import androidx.test.ext.junit.runners.AndroidJUnit4
import androidx.test.platform.app.InstrumentationRegistry
import java.io.File
import java.nio.ByteBuffer
import java.nio.ByteOrder
import java.util.concurrent.CountDownLatch
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.runBlocking
import kotlinx.coroutines.withTimeout
import org.json.JSONArray
import org.json.JSONObject
import org.junit.After
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.BeforeClass
import org.junit.Test
import org.junit.runner.RunWith

/**
 * RTP3-NAT-04: real Wireshark/JNI reads, without an RTP scan prerequisite.
 *
 * The card's frame 12 is a REGISTER 100 Trying with no SDP. The existing G.711
 * fixture's SDP is in frames 20/21 (200 OK) and 22/23 (ACK). Addresses/Call-ID
 * below were cross-checked with tshark 4.0.6 -T fields (raw fields only, not RTP
 * statistics goldens). AMR's frame 1 provides the INVITE+SDP case.
 *
 * Edge-case PCAPs are generated here from explicit, non-sensitive SIP/SDP text
 * on RFC 5737 addresses and .invalid domains. They test field grouping/string
 * fidelity, not media decoding, and need no external fixture or encoder.
 */
@RunWith(AndroidJUnit4::class)
class RtpSetupInfoTest {
    private val files = mutableListOf<File>()

    @After
    fun cleanFiles() {
        files.forEach { it.delete() }
    }

    @Test(timeout = 120_000)
    fun readsTheActualG711SdpFramesWithoutScanningRtp() = withFixture(G711) { session ->
        val frames = successfulRows(read(session, 20, 22))
        assertEquals(2, frames.length())
        val response = frames.getJSONObject(0)
        assertEquals(20, response.getInt("frame"))
        assertEquals("", response.getString("sipMethod"))
        assertEquals("2502", response.getString("fromUser"))
        assertEquals("2504", response.getString("toUser"))
        assertEquals("sip:2502@192.168.105.105", response.getString("fromUri"))
        assertEquals("sip:2504@192.168.105.110:5060", response.getString("toUri"))
        assertEquals("25672@192.168.105.110", response.getString("callId"))
        val formats = response.getJSONArray("sdp")
        assertEquals(listOf(8, 0, 18, 96), objects(formats).map { it.getInt("payloadType") })
        assertFormat(formats.getJSONObject(0), 8, "PCMA", 8000, 1, "")
        assertFormat(formats.getJSONObject(1), 0, "PCMU", 8000, 1, "")
        assertFormat(formats.getJSONObject(2), 18, "G729", 8000, 1, "")
        assertFormat(formats.getJSONObject(3), 96, "telephone-event", 8000, 1, "0-15")
        val ack = frames.getJSONObject(1)
        assertEquals("ACK", ack.getString("sipMethod"))
        assertEquals("sip:2504@192.168.105.105", ack.getString("toUri"))
        assertEquals(listOf(8, 96), objects(ack.getJSONArray("sdp")).map { it.getInt("payloadType") })
    }

    @Test(timeout = 120_000)
    fun readsAmrInviteAndDoesNotInventResponseMethod() = withFixture(AMR) { session ->
        val frames = successfulRows(read(session, 1, 2))
        val invite = frames.getJSONObject(0)
        assertEquals("INVITE", invite.getString("sipMethod"))
        assertEquals("caller", invite.getString("fromUser"))
        assertEquals("test", invite.getString("toUser"))
        assertEquals("sip:caller@192.0.2.10", invite.getString("fromUri"))
        assertEquals("sip:test@192.0.2.20", invite.getString("toUri"))
        assertEquals("1-1@192.0.2.10", invite.getString("callId"))
        assertFormat(invite.getJSONArray("sdp").getJSONObject(0), 97, "AMR", 8000, 1, "octet-align=1")
        assertEquals("", frames.getJSONObject(1).getString("sipMethod"))
        assertFormat(frames.getJSONObject(1).getJSONArray("sdp").getJSONObject(0),
            97, "AMR", 8000, 1, "octet-align=1")
    }

    @Test(timeout = 120_000)
    fun extractsOpusStereoFromTheMatchingRtpmapAttribute() = withFixture(OPUS) { session ->
        val row = successfulRows(read(session, 1)).getJSONObject(0)
        assertFormat(row.getJSONArray("sdp").getJSONObject(0), 99, "opus", 48000, 2, "")
    }

    @Test(timeout = 120_000)
    fun missingSdpAndUnrelatedFramesAreNotErrors() = withFixture(G711) { session ->
        // Frames 1–26 are SIP in this fixture; frame 27 is the first RTP packet.
        val rows = successfulRows(read(session, 12, 27))
        assertEquals(0, rows.getJSONObject(0).getJSONArray("sdp").length())
        assertEquals("", rows.getJSONObject(0).getString("sipMethod"))
        val unrelated = rows.getJSONObject(1)
        listOf("sipMethod", "fromUser", "fromUri", "toUser", "toUri", "callId").forEach {
            assertEquals(it, "", unrelated.getString(it))
        }
        assertEquals(0, unrelated.getJSONArray("sdp").length())
    }

    @Test(timeout = 120_000)
    fun sdpOnlyProjectionMatchesWithoutExposingSipFields() = withFixture(G711) { session ->
        val request = request(22, 20, 22)
        val full = successfulRows(JSONObject(NativeEngine.readRtpSetupInfo(session, request)))
        val projected = successfulRows(JSONObject(NativeEngine.readSdpFmtpValues(session, request)))
        assertEquals(full.length(), projected.length())
        for (i in 0 until full.length()) {
            val row = projected.getJSONObject(i)
            assertEquals(setOf("frame", "sdp"), row.keys().asSequence().toSet())
            assertEquals(full.getJSONObject(i).getInt("frame"), row.getInt("frame"))
            assertEquals(full.getJSONObject(i).getJSONArray("sdp").toString(), row.getJSONArray("sdp").toString())
        }
    }

    @Test(timeout = 120_000)
    fun preservesOrderDuplicatesAndThe64EntryBoundary() = withFixture(AMR) { session ->
        assertEquals(0, successfulRows(read(session)).length())
        val order = (0 until 64).map { if (it % 2 == 0) 2 else 1 }
        val rows = successfulRows(read(session, *order.toIntArray()))
        assertEquals(order, objects(rows).map { it.getInt("frame") })
        assertFailure(read(session, *IntArray(65) { 1 }))
    }

    @Test(timeout = 120_000)
    fun rejectsMalformedRequestsAtomicallyInBothEndpoints() = withFixture(AMR) { session ->
        val beyondEnd = NativeEngine.getFrameCount(session) + 1
        val badRequests = listOf(
            "", "{", "null", "[]", "{}", "{\"frames\":null}", "{\"frames\":1}",
            "{\"frames\":[true]}", "{\"frames\":[null]}", "{\"frames\":[\"1\"]}",
            "{\"frames\":[1.0]}", "{\"frames\":[0]}", "{\"frames\":[-1]}",
            "{\"frames\":[2147483648]}", "{\"frames\":[18446744073709551615]}",
            "{\"frames\":[18446744073709551616]}", "{\"frames\":[1,$beyondEnd]}"
        )
        badRequests.forEach { input ->
            assertFailure(JSONObject(NativeEngine.readRtpSetupInfo(session, input)))
            assertFailure(JSONObject(NativeEngine.readSdpFmtpValues(session, input)))
        }
        assertEquals(1, successfulRows(read(session, 1)).length())
    }

    @Test(timeout = 120_000)
    fun rejectsMissingAndClosedHandles() {
        assertFailure(read(0, 1))
        assertFailure(JSONObject(NativeEngine.readSdpFmtpValues(Long.MAX_VALUE, request(1))))
        val session = NativeEngine.openFile(copyFixture(AMR).absolutePath, null)
        assertTrue(session != 0L)
        NativeEngine.closeFile(session)
        assertFailure(read(session, 1))
        assertFailure(JSONObject(NativeEngine.readSdpFmtpValues(session, request(1))))
    }

    @Test(timeout = 120_000)
    fun usesPhysicalFramesIndependentlyOfTheDisplayFilter() = withFixture(G711) { session ->
        val before = successfulRows(read(session, 20, 22)).toString()
        val filter = JSONObject(NativeEngine.applyDisplayFilter(session, "frame.number == 1"))
        assertEquals("", filter.optString("error"))
        repeat(3) {
            assertEquals(before, successfulRows(read(session, 20, 22)).toString())
        }
    }

    @Test(timeout = 120_000)
    fun keepsFmtpWithItsExplicitPtAndMediaSectionEvenWhenAttributesAreReordered() {
        val body = sdp(
            "m=audio 4000 RTP/AVP 96 97",
            "a=fmtp:97 minptime=10;useinbandfec=1",
            "a=rtpmap:96 AMR/8000",
            "a=rtpmap:97 opus/48000/2",
            "a=fmtp:96 octet-align=1",
            "m=video 4002 RTP/AVP 96",
            "a=fmtp:96 packetization-mode=1",
            "a=rtpmap:96 H264/90000"
        )
        withCapture(syntheticCapture(body)) { session ->
            val formats = successfulRows(read(session, 1)).getJSONObject(0).getJSONArray("sdp")
            assertEquals(3, formats.length())
            assertFormat(formats.getJSONObject(0), 97, "opus", 48000, 2, "minptime=10;useinbandfec=1")
            assertFormat(formats.getJSONObject(1), 96, "AMR", 8000, 1, "octet-align=1")
            assertFormat(formats.getJSONObject(2), 96, "H264", 90000, 1, "packetization-mode=1")
        }
    }

    @Test(timeout = 120_000)
    fun preservesRawStringsRepeatedParametersAndOnlyReturnsWhitelistedData() {
        val parameter = "x-value=\"a\\b\""
        val body = sdp(
            "m=audio 4000 RTP/AVP 96",
            "a=rtpmap:96 X-TEST/8000",
            "a=fmtp:96 $parameter;$parameter;sprop-parameter-sets=Ab+/==,Cd+/==",
            "a=fmtp:96 mode-set=0,1,2",
            "a=x-private:DO_NOT_PROJECT_THIS_ATTRIBUTE",
            "k=clear:DO_NOT_PROJECT_THIS_KEY"
        )
        withCapture(syntheticCapture(body, "sip:al%69ce@example.invalid", "sips:bob@example.invalid")) { session ->
            val result = read(session, 1)
            val row = successfulRows(result).getJSONObject(0)
            assertEquals("sip:al%69ce@example.invalid", row.getString("fromUri"))
            assertEquals("al%69ce", row.getString("fromUser"))
            assertEquals("sips:bob@example.invalid", row.getString("toUri"))
            assertEquals("bob", row.getString("toUser"))
            assertFormat(row.getJSONArray("sdp").getJSONObject(0), 96, "X-TEST", 8000, 1,
                "$parameter;$parameter;sprop-parameter-sets=Ab+/==,Cd+/==;mode-set=0,1,2")
            assertFalse(result.toString().contains("DO_NOT_PROJECT"))
        }
    }

    @Test(timeout = 120_000)
    fun keepsUnknownMappingsUnknownAndDoesNotGuessConflictingPayloadTypes() {
        val body = sdp(
            "m=audio 4000 RTP/AVP 96 97",
            "a=fmtp:97 x-mode=1",
            "a=rtpmap:96 AMR/8000",
            "a=rtpmap:96 opus/48000/2",
            "a=fmtp:96 x-mode=2"
        )
        withCapture(syntheticCapture(body)) { session ->
            val formats = successfulRows(read(session, 1)).getJSONObject(0).getJSONArray("sdp")
            assertEquals(2, formats.length())
            assertFormat(formats.getJSONObject(0), 97, "", 0, 0, "x-mode=1")
            assertFormat(formats.getJSONObject(1), -1, "", 0, 0, "x-mode=2")
        }
    }

    @Test(timeout = 120_000)
    fun doesNotTurnMalformedExplicitChannelsIntoMonoOrG722ClockIntoSampleRate() {
        val body = sdp(
            "m=audio 4000 RTP/AVP 9 96 97",
            "a=rtpmap:9 G722/8000",
            "a=rtpmap:96 opus/48000/stereo",
            "a=rtpmap:97 opus/48000/0"
        )
        withCapture(syntheticCapture(body)) { session ->
            val formats = successfulRows(read(session, 1)).getJSONObject(0).getJSONArray("sdp")
            assertEquals(3, formats.length())
            assertFormat(formats.getJSONObject(0), 9, "G722", 8000, 1, "")
            assertFormat(formats.getJSONObject(1), 96, "opus", 48000, 0, "")
            assertFormat(formats.getJSONObject(2), 97, "opus", 48000, 0, "")
        }
    }

    @Test(timeout = 120_000)
    fun sharesTheDissectionMutexWithInteractiveDetailReadsWithoutDeadlocking() {
        withCapture(syntheticCapture(denseSdp())) { session ->
            val executor = Executors.newSingleThreadExecutor()
            try {
                val future = executor.submit<JSONObject> { read(session, *IntArray(64) { 1 }) }
                repeat(4) {
                    val detail = JSONObject(NativeEngine.getPacketDetails(session, 0))
                    assertTrue(detail.getJSONArray("children").length() > 0)
                }
                assertEquals(64, successfulRows(future.get(30, TimeUnit.SECONDS)).length())
            } finally {
                executor.shutdownNow()
                assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS))
            }
        }
    }

    @Test(timeout = 120_000)
    fun cancellationNeverReturnsPartialFrames() {
        withCapture(syntheticCapture(denseSdp())) { session ->
            val executor = Executors.newSingleThreadExecutor()
            val entered = CountDownLatch(1)
            try {
                val future = executor.submit<JSONObject> {
                    entered.countDown()
                    read(session, *IntArray(64) { 1 })
                }
                assertTrue(entered.await(5, TimeUnit.SECONDS))
                val deadline = System.nanoTime() + TimeUnit.SECONDS.toNanos(20)
                while (!future.isDone && System.nanoTime() < deadline) {
                    NativeEngine.cancelLongRunningOperations()
                    Thread.sleep(1)
                }
                val result = future.get(10, TimeUnit.SECONDS)
                assertTrue("The dense batch must observe cancellation", result.getBoolean("cancelled"))
                assertEquals("", result.getString("error"))
                assertEquals(0, result.getJSONArray("frames").length())
                assertEquals(1, successfulRows(read(session, 1)).length())
            } finally {
                executor.shutdownNow()
                assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS))
            }
        }
    }

    @Test(timeout = 120_000)
    fun closeDuringABatchDetachesTheHandleAndNeverPublishesPartialFrames() {
        val capture = syntheticCapture(denseSdp())
        val session = NativeEngine.openFile(capture.absolutePath, null)
        assertTrue(session != 0L)
        val executor = Executors.newSingleThreadExecutor()
        val entered = CountDownLatch(1)
        try {
            val future = executor.submit<JSONObject> {
                entered.countDown()
                read(session, *IntArray(64) { 1 })
            }
            assertTrue(entered.await(5, TimeUnit.SECONDS))
            NativeEngine.closeFile(session)
            val result = future.get(30, TimeUnit.SECONDS)
            // Closing may win before the lease or after the completed read. Both
            // linearizations are valid; a successful partial batch is never valid.
            if (result.getString("error").isEmpty() && !result.getBoolean("cancelled")) {
                assertEquals(64, successfulRows(result).length())
            } else {
                assertEquals(0, result.getJSONArray("frames").length())
            }
            assertFailure(read(session, 1))
        } finally {
            executor.shutdownNow()
            assertTrue(executor.awaitTermination(30, TimeUnit.SECONDS))
            NativeEngine.closeFile(session)
        }
    }

    private fun read(session: Long, vararg frames: Int): JSONObject =
        JSONObject(NativeEngine.readRtpSetupInfo(session, request(*frames)))

    private fun request(vararg frames: Int): String =
        JSONObject().put("frames", JSONArray(frames.toList())).toString()

    private fun successfulRows(result: JSONObject): JSONArray {
        assertEquals(1, result.getInt("schemaVersion"))
        assertEquals("", result.getString("error"))
        assertFalse(result.getBoolean("cancelled"))
        return result.getJSONArray("frames")
    }

    private fun assertFailure(result: JSONObject) {
        assertEquals(1, result.getInt("schemaVersion"))
        assertTrue(result.getString("error").isNotBlank())
        assertFalse(result.getBoolean("cancelled"))
        assertEquals(0, result.getJSONArray("frames").length())
    }

    private fun assertFormat(row: JSONObject, pt: Int, codec: String, rate: Int, channels: Int, fmtp: String) {
        assertEquals(pt, row.getInt("payloadType"))
        assertEquals(codec, row.getString("encodingName"))
        assertEquals(rate, row.getInt("clockRate"))
        assertEquals(channels, row.getInt("channels"))
        assertEquals(fmtp, row.getString("fmtp"))
    }

    private fun objects(array: JSONArray): List<JSONObject> =
        (0 until array.length()).map { array.getJSONObject(it) }

    private fun withFixture(name: String, block: (Long) -> Unit) = withCapture(copyFixture(name), block)

    private fun withCapture(file: File, block: (Long) -> Unit) {
        val session = NativeEngine.openFile(file.absolutePath, null)
        assertTrue("Fixture must open", session != 0L)
        try {
            block(session)
        } finally {
            NativeEngine.closeFile(session)
        }
    }

    private fun temporaryCapture(): File =
        File.createTempFile("rtp-setup-", ".pcap", appContext.cacheDir).also { files += it }

    private fun copyFixture(name: String): File = temporaryCapture().also { file ->
        testContext.assets.open("rtp/$name.pcap").use { input ->
            file.outputStream().use { output -> input.copyTo(output) }
        }
    }

    private fun sdp(vararg lines: String): String =
        (listOf("v=0", "o=- 1 1 IN IP4 192.0.2.10", "s=RTP setup test",
            "c=IN IP4 192.0.2.10", "t=0 0") + lines).joinToString("\r\n", postfix = "\r\n")

    private fun denseSdp(): String = sdp(
        "m=audio 4000 RTP/AVP 96",
        "a=rtpmap:96 X-TEST/8000",
        "a=fmtp:96 " + (0 until 1200).joinToString(";") { "p$it=abcdefghijklmnopqrstuvwxyz" }
    )

    private fun syntheticCapture(
        body: String,
        from: String = "sip:alice@example.invalid",
        to: String = "sip:bob@example.invalid"
    ): File {
        val payload = listOf(
            "INVITE $to SIP/2.0",
            "Via: SIP/2.0/UDP 192.0.2.10:5060;branch=z9hG4bK-rtp-setup",
            "From: <$from>;tag=setup",
            "To: <$to>",
            "Call-ID: rtp-setup-test@example.invalid",
            "CSeq: 1 INVITE",
            "Content-Type: application/sdp",
            "Content-Length: ${body.toByteArray(Charsets.UTF_8).size}", "", body
        ).joinToString("\r\n").toByteArray(Charsets.UTF_8)
        val packetSize = 20 + 8 + payload.size
        require(packetSize <= 65535)
        val packet = ByteBuffer.allocate(packetSize).order(ByteOrder.BIG_ENDIAN).apply {
            put(0x45.toByte()).put(0.toByte()).putShort(packetSize.toShort())
            putShort(1.toShort()).putShort(0.toShort()).put(64.toByte()).put(17.toByte())
            putShort(0.toShort())
            put(byteArrayOf(192.toByte(), 0, 2, 10))
            put(byteArrayOf(192.toByte(), 0, 2, 20))
            putShort(5060.toShort()).putShort(5060.toShort())
            putShort((8 + payload.size).toShort()).putShort(0.toShort())
            put(payload)
        }.array()
        var checksum = 0
        for (offset in 0 until 20 step 2) {
            checksum += ((packet[offset].toInt() and 0xff) shl 8) or (packet[offset + 1].toInt() and 0xff)
        }
        while (checksum ushr 16 != 0) checksum = (checksum and 0xffff) + (checksum ushr 16)
        checksum = checksum.inv() and 0xffff
        packet[10] = (checksum ushr 8).toByte()
        packet[11] = checksum.toByte()
        val pcap = ByteBuffer.allocate(24 + 16 + packet.size).order(ByteOrder.LITTLE_ENDIAN).apply {
            putInt(0xa1b2c3d4.toInt()).putShort(2.toShort()).putShort(4.toShort())
            putInt(0).putInt(0).putInt(65535).putInt(101) // LINKTYPE_RAW, IPv4/UDP
            putInt(1_700_000_000).putInt(0).putInt(packet.size).putInt(packet.size)
            put(packet)
        }.array()
        return temporaryCapture().also { it.writeBytes(pcap) }
    }

    companion object {
        private const val G711 = "sip_g711a_bidirectional"
        private const val AMR = "sip_rtp_amr_nb"
        private const val OPUS = "sip_rtp_opus"
        private lateinit var appContext: Context
        private lateinit var testContext: Context

        @JvmStatic
        @BeforeClass
        fun awaitApplicationEngine() {
            appContext = ApplicationProvider.getApplicationContext()
            testContext = InstrumentationRegistry.getInstrumentation().context
            val application = appContext as LayerAnalyzerApplication
            var state = runBlocking {
                withTimeout(30_000) {
                    application.engineState.first {
                        it is EngineState.Ready || it is EngineState.Failed || it is EngineState.AwaitingSessionRestore
                    }
                }
            }
            if (state is EngineState.AwaitingSessionRestore) {
                application.declineSessionRestore()
                state = runBlocking {
                    withTimeout(30_000) {
                        application.engineState.first { it is EngineState.Ready || it is EngineState.Failed }
                    }
                }
            }
            assertTrue((state as? EngineState.Failed)?.message ?: "Native engine did not initialize", state is EngineState.Ready)
        }
    }
}

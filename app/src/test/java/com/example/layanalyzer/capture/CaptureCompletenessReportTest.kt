package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import com.example.layanalyzer.capture.tls.*
import com.example.layanalyzer.model.TlsCaptureStatus
import org.json.JSONObject
import org.junit.Assert.*
import org.junit.Test
import java.net.InetAddress
import java.util.concurrent.CountDownLatch
import java.util.concurrent.TimeUnit

class CaptureCompletenessReportTest {
    private fun report(tls: TlsCaptureState? = null, failed: Boolean = false) =
        CaptureCompletenessReport.append(JSONObject().put("complete", true).put("writtenPackets", 4),
            SocksRuntimeLimits(), null, null, tls, failed, 1234)

    @Test fun journalBudgetLossIsSeparateFromIoFailureAndPacketCompleteness() {
        val decoded = report(TlsCaptureState(TlsCaptureStatus.STOPPED,
            journal = TlsJournalMetrics(0, 2, false, 3, 4, 0, false, false,
                fileBytes = 1024, capacityDropped = 4)))
        val journal = decoded.getJSONObject("tls").getJSONObject("journal")
        assertEquals(4L, journal.getLong("capacityDropped"))
        assertEquals(0L, journal.getLong("writeFailures"))
        assertEquals(1024L, journal.getLong("fileBytes"))
        assertTrue(decoded.getBoolean("complete"))
        assertEquals("INCOMPLETE", CaptureReportIntegrity.read(decoded).metadata)
        val reasons = decoded.getJSONObject("integrity").getJSONObject("metadata").getJSONArray("reasons").toString()
        assertTrue(reasons.contains("JOURNAL_CAPACITY_EXCEEDED"))
        assertFalse(reasons.contains("EVENTS_LOST"))
    }

    @Test fun legacyMissingDomainsAndUnknownValuesStayCompatibleAndUnknown() {
        val old = JSONObject("""{"complete":true,"socks":{"rejectedHandshakes":3},"tls":{"secretsComplete":false}}""")
        assertEquals(CaptureReportIntegrity("COMPLETE", null, null, null), CaptureReportIntegrity.read(old))
        assertEquals(3, old.getJSONObject("socks").getInt("rejectedHandshakes"))
        old.put("socksRuntime", JSONObject().put("mode", "BLOCKING").put("tcp", 64))
        assertEquals(CaptureReportIntegrity("COMPLETE", null, null, null), CaptureReportIntegrity.read(old))
        assertEquals("BLOCKING", old.getJSONObject("socksRuntime").getString("mode"))
        val unknown = JSONObject("""{"complete":true,"integrity":{"packetEvidence":{"status":"FUTURE"},"cleanup":{"status":true},"metadata":{"status":"COMPLETE"},"tlsCoverage":{"status":"DECRYPTED"}}}""")
        assertEquals(CaptureReportIntegrity(null, null, "COMPLETE", null), CaptureReportIntegrity.read(unknown))
        assertNull(CaptureReportIntegrity.read(JSONObject().put("complete", "true")).packetEvidence)
    }

    @Test fun historicalBlockingReportsRemainReadableWithoutRewritingTheirRuntime() {
        for (version in listOf(null, 1, 2)) {
            for (complete in listOf(false, true)) {
                val saved = JSONObject().put("complete", complete).put("writtenPackets", 17)
                    .put("socksRuntime", JSONObject().put("mode", "BLOCKING")
                        .put("tcp", 64).put("udp", 64).put("authentication", 64).put("tlsHandshakes", 8))
                    .put("socks", JSONObject().put("rejectedTcpSessions", 3))
                    .apply { version?.let { put("reportVersion", it) } }
                val reopened = JSONObject(saved.toString())
                val before = reopened.toMap()
                assertEquals(CaptureReportIntegrity(if (complete) "COMPLETE" else "INCOMPLETE", null, null, null),
                    CaptureReportIntegrity.read(reopened))
                assertEquals(before, reopened.toMap())
                assertEquals("BLOCKING", reopened.getJSONObject("socksRuntime").getString("mode"))
                assertEquals(17, reopened.getInt("writtenPackets"))
                assertEquals(3, reopened.getJSONObject("socks").getInt("rejectedTcpSessions"))
            }
        }
    }

    @Test fun newReportRoundTripPreservesLegacyPacketFlagAndExplainsTlsAndHistoryLoss() {
        val stats = JSONObject("""{"state":"STOPPED","snapshotAtMillis":1220,"budget":{"connections":0,"refusedHandshakes":2},"gateway":{"ready":7,"active":0},"events":{"bytesToUpstream":20,"bytesToDownstream":40,"eventsDropped":3,"eventsQueued":1,"connectionsProxied":5,"connectionsPassthrough":2,"handshakeCapacityPassthrough":2},"runtimeMetrics":{"goSecretsIncomplete":true,"goSecretsDropped":1,"probesPeakActive":7}}""")
        val tls = TlsCaptureState(TlsCaptureStatus.STOPPED,
            connections = TlsConnectionCounts(proxied = 5, passthrough = 2, connectionStatesEvicted = 1),
            traffic = TlsTrafficCounts(20, 40, 3),
            secrets = TlsSecretPersistence(4, 3, 1, TlsAssetErrorCode.IO_ERROR, null),
            engineDiagnostics = TlsEngineDiagnostics.read(stats),
            journal = TlsJournalMetrics(0, 4, false, 3, 1, 1, false, false))
        val decoded = JSONObject(report(tls).toString())
        assertTrue(decoded.getBoolean("complete"))
        assertEquals(4, decoded.getInt("writtenPackets"))
        assertEquals(CaptureReportIntegrity("COMPLETE", "COMPLETE", "INCOMPLETE", "PARTIAL"), CaptureReportIntegrity.read(decoded))
        assertEquals(20L, decoded.getJSONObject("tls").getLong("bytesToUpstream"))
        assertEquals(20L, decoded.getJSONObject("tls").getJSONObject("engine").getJSONObject("events").getLong("bytesToUpstream"))
        val reasons = decoded.getJSONObject("integrity").getJSONObject("metadata").getJSONArray("reasons").toString()
        assertTrue(reasons.contains("EVENTS_LOST"))
        assertTrue(reasons.contains("ENGINE_EVENTS_NOT_DRAINED"))
        assertTrue(reasons.contains("JOURNAL_NOT_PERSISTED"))
        assertFalse(decoded.getJSONObject("integrity").getJSONObject("tlsCoverage").getBoolean("decryptionVerified"))
    }

    @Test fun boundedHistoryIsReportedWithoutClaimingEngineEventsWereLost() {
        val tls = TlsCaptureState(TlsCaptureStatus.STOPPED,
            connections = TlsConnectionCounts(accepted = 193, eventHistoryEvicted = 91))
        val decoded = JSONObject(report(tls).toString())
        val projection = decoded.getJSONObject("tls").getJSONObject("projection")
        assertEquals(91L, projection.getLong("eventHistoryEvicted"))
        assertEquals(0L, projection.getLong("eventsDropped"))
        val reasons = decoded.getJSONObject("integrity").getJSONObject("metadata").getJSONArray("reasons").toString()
        assertFalse(reasons.contains("EVENTS_LOST"))
        assertTrue(reasons.contains("EVENT_HISTORY_TRUNCATED"))
        assertTrue(reasons.contains("ENGINE_FINAL_SNAPSHOT_UNAVAILABLE"))
        val journaled = report(tls.copy(journal = TlsJournalMetrics(0, 4, false, 1115, 0, 0, false, false)))
        assertFalse(journaled.getJSONObject("integrity").getJSONObject("metadata").getJSONArray("reasons").toString().contains("EVENT_HISTORY_TRUNCATED"))
        val lost = JSONObject(report(tls.copy(connections = tls.connections.copy(eventsDropped = 1))).toString())
        assertTrue(lost.getJSONObject("integrity").getJSONObject("metadata").getJSONArray("reasons").toString().contains("EVENTS_LOST"))
    }

    @Test fun invalidMetricsAreOmittedAndFlaggedWithoutTextOrCoercion() {
        val d = TlsEngineDiagnostics.read(JSONObject("""{"state":"UNKNOWN","budget":{"connections":"10","handshakes":-1},"events":{"eventsDropped":1.5,"connectionsProxied":3},"gateway":{"token":"sensitive"},"runtimeMetrics":{"probesActive":2,"goSecretsQueueBytes":null,"goSecretsIncomplete":"false","unknown":"sensitive"}}"""))
        assertTrue(d.invalidFields)
        assertNull(d.state)
        assertTrue(d.budget.isEmpty())
        assertEquals(mapOf("connectionsProxied" to 3L), d.events)
        assertEquals(mapOf("probesActive" to 2L), d.runtime)
        assertFalse(d.toJson().toString().contains("sensitive"))
        val outOfRange = TlsEngineDiagnostics.read(JSONObject("""{"state":"STOPPED","budget":{"connections":1025,"connectionLimit":64},"runtimeMetrics":{"certificateCacheEntries":257}}"""))
        assertTrue(outOfRange.invalidFields)
        assertEquals("INCOMPLETE", CaptureReportIntegrity.read(report(TlsCaptureState(TlsCaptureStatus.STOPPED,
            engineDiagnostics = outOfRange))).metadata)
    }

    @Test fun closeFailureIsDistinctFromCleanPacketEvidenceAndSuccessfulRelay() {
        val decoded = report(failed = true)
        assertTrue(decoded.getBoolean("complete"))
        assertEquals("INCOMPLETE", CaptureReportIntegrity.read(decoded).cleanup)
        assertTrue(decoded.getJSONObject("integrity").getJSONObject("cleanup").getJSONArray("reasons").toString().contains("SOCKS_CLOSE_FAILED"))
        val tls = TlsCaptureState(TlsCaptureStatus.STOPPED, engineDiagnostics = TlsEngineDiagnostics.read(JSONObject("""{"state":"STOPPED","events":{}}""")))
        assertEquals("NOT_VERIFIED", CaptureReportIntegrity.read(report(tls)).tlsCoverage)
    }

    @Test fun stopSnapshotSeparatesCaptureCleanupFromUninterruptibleProcessDns() {
        val started = CountDownLatch(1)
        val finish = CountDownLatch(1)
        val loopback = InetAddress.getByAddress(byteArrayOf(127, 0, 0, 1))
        DirectSocks5Server({}, {}, { started.countDown(); finish.await(5, TimeUnit.SECONDS); arrayOf(loopback) },
            generateCredentials = { SocksCredentials.of("u", "p") },
            ).use { socks ->
            socks.start(90)
            try {
                java.net.Socket(loopback, socks.port).use { client ->
                    client.soTimeout = 3000
                    client.getOutputStream().write(byteArrayOf(5, 1, 2, 1, 1, 117, 1, 112))
                    val input = java.io.DataInputStream(client.getInputStream())
                    assertEquals(5, input.readUnsignedByte()); assertEquals(2, input.readUnsignedByte())
                    assertEquals(1, input.readUnsignedByte()); assertEquals(0, input.readUnsignedByte())
                    val name = "held.invalid".toByteArray()
                    client.getOutputStream().write(byteArrayOf(5, 1, 0, 3, name.size.toByte()) + name + byteArrayOf(0, 80))
                    assertTrue(started.await(3, TimeUnit.SECONDS))
                    val live = socks.nioStats()
                    assertFalse(CaptureCompletenessReport.nioClean(live))
                    val liveReport = CaptureCompletenessReport.append(JSONObject().put("complete", true), socks.runtimeLimits,
                        socks.sessionStats(), live, null, false)
                    assertTrue(liveReport.getJSONObject("nio").getBoolean("cleanupIncomplete"))
                    socks.close()
                    val final = CaptureCompletenessReport.append(JSONObject().put("complete", true), socks.runtimeLimits,
                        socks.sessionStats(), socks.nioStats(), null, false)
                    assertEquals("COMPLETE", CaptureReportIntegrity.read(final).cleanup)
                    assertEquals(90L, final.getJSONObject("nio").getLong("networkGeneration"))
                    assertTrue(final.getJSONObject("nio").getJSONObject("dns").getBoolean("backgroundLookupsStillRunning"))
                    assertEquals(0, final.getJSONObject("nio").getJSONObject("dns").getInt("runSubscribers"))
                }
            } finally { finish.countDown() }
        }
    }

    /**
     * NIO-506: the report has to say whether the frozen tier is the accepted default or an internal
     * validation profile, rather than leaving a reader to compare numbers against a document.
     */
    @Test fun socksRuntimeNamesAcceptedCapacitySeparatelyFromValidationProfiles() {
        fun acceptance(limits: SocksRuntimeLimits) = CaptureCompletenessReport
            .append(JSONObject(), limits, null, null, null, false, 1234)
            .getJSONObject("socksRuntime")
            .getString("capacityAcceptance")
        assertEquals("DEVICE_ACCEPTED", acceptance(SocksRuntimeLimits(64, 64, 64)))
        assertEquals("VALIDATION_ONLY", acceptance(SocksRuntimeLimits(1024, 256, 128)))
        // The marker is additional, not a replacement: the frozen numbers are still reported.
        val tier = CaptureCompletenessReport.append(JSONObject(), SocksRuntimeLimits(256, 128, 128),
            null, null, null, false, 1234).getJSONObject("socksRuntime")
        assertEquals(256, tier.getInt("tcp"))
        assertEquals(128, tier.getInt("udp"))
        assertEquals(128, tier.getInt("authentication"))
    }
}

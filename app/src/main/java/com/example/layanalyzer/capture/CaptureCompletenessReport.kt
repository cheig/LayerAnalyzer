// Copyright (c) 2026 cheig; GPL-3.0.
package com.example.layanalyzer.capture

import com.example.layanalyzer.capture.socks.SocksNioServer
import com.example.layanalyzer.capture.socks.SocksNioTcpServer
import com.example.layanalyzer.capture.socks.SocksEventLoop
import com.example.layanalyzer.capture.socks.SocksRuntimeLimits
import com.example.layanalyzer.capture.tls.TlsCaptureState
import com.example.layanalyzer.model.TlsCaptureStatus
import org.json.JSONArray
import org.json.JSONObject

/** Adds diagnostics to the legacy report. PCAP completeness remains its own fact. */
internal object CaptureCompletenessReport {
    fun append(root: JSONObject, limits: SocksRuntimeLimits, sessions: SocksSessionStats?,
        nio: SocksNioTcpServer.Stats?, tls: TlsCaptureState?, closeFailed: Boolean,
        snapshotAtMillis: Long = System.currentTimeMillis()): JSONObject {
        root.put("reportVersion", 2)
        root.put("snapshotAtMillis", snapshotAtMillis)
        root.put("socksRuntime", limits.encode().put("tcpPopulation", "direct_and_tls_candidates")
            .put("eventLoopLimit", 2)
            .put("dnsWorkerLimit", 4)
            // NIO-506: the tier above 64 is an internal validation profile, not accepted capacity,
            // so a report of a capture that ran one says so instead of leaving the reader to compare
            // numbers against a document (docs/socks_nio_runtime_snapshot_2026-10-22.md).
            .put("capacityAcceptance", if (limits.deviceAccepted) "DEVICE_ACCEPTED" else "VALIDATION_ONLY"))
        nio?.let { root.put("nio", nioJson(it, snapshotAtMillis)) }
        tls?.takeIf { it.status != TlsCaptureStatus.DISABLED }?.let { root.put("tls", tlsJson(it)) }
        val cleanupReasons = mutableListOf<String>()
        if (closeFailed) cleanupReasons.add("SOCKS_CLOSE_FAILED")
        if (sessions?.running == true || listOfNotNull(sessions?.handshakes, sessions?.tcp, sessions?.udp).any { it.current != 0 })
            cleanupReasons.add("SOCKS_RESOURCES_REMAIN")
        if (nio != null && !nioClean(nio)) cleanupReasons.add("NIO_CLEANUP_INCOMPLETE")
        if (tls != null && tls.status != TlsCaptureStatus.DISABLED) {
            if (tls.engineDiagnostics?.state?.let { it != "STOPPED" }
                ?: (tls.status != TlsCaptureStatus.STOPPED))
                cleanupReasons.add("TLS_STOP_INCOMPLETE")
            val d = tls.engineDiagnostics
            if (listOf("connections", "handshakes").any { (d?.budget?.get(it) ?: 0) > 0 } ||
                listOf("authentication", "active", "acceptedCurrent").any { (d?.gateway?.get(it) ?: 0) > 0 } ||
                listOf("probesActive", "probePrefixCapacityBytes", "goSecretsQueueBytes", "goSecretsInFlightBytes").any { (d?.runtime?.get(it) ?: 0) > 0 })
                cleanupReasons.add("TLS_RESOURCES_REMAIN")
            if (tls.secretQueue?.consumerAlive == true || tls.journal?.workerAlive == true)
                cleanupReasons.add("TLS_WRITER_STILL_RUNNING")
        }
        val metadataReasons = mutableListOf<String>()
        val tlsReasons = mutableListOf<String>()
        val engine = tls?.engineDiagnostics
        if (tls != null && tls.status != TlsCaptureStatus.DISABLED) {
            val c = tls.connections
            if (c.eventsDropped > 0 || c.eventsRejected > 0 || tls.traffic.engineEventsDropped > 0)
                metadataReasons.add("EVENTS_LOST")
            // Retiring already-applied history does not undercount connections, but
            // without a journal those old transitions can no longer be audited.
            if (c.eventHistoryEvicted > 0 && tls.journal == null) metadataReasons.add("EVENT_HISTORY_TRUNCATED")
            if (c.connectionStatesEvicted > 0) metadataReasons.add("PROJECTION_STATES_EVICTED")
            if (c.eventsNotPersisted > 0 || (tls.journal?.notPersisted ?: 0) > 0 || (tls.journal?.writeFailures ?: 0) > 0)
                metadataReasons.add("JOURNAL_NOT_PERSISTED")
            if (tls.journal?.closeTimedOut == true) metadataReasons.add("JOURNAL_CLOSE_TIMED_OUT")
            if ((tls.journal?.capacityDropped ?: 0) > 0) metadataReasons.add("JOURNAL_CAPACITY_EXCEEDED")
            if ((tls.journal?.queued ?: 0) > 0 || tls.journal?.inFlight == true)
                metadataReasons.add("JOURNAL_PENDING")
            if ((engine?.events?.get("eventsQueued") ?: 0) > 0) metadataReasons.add("ENGINE_EVENTS_NOT_DRAINED")
            if ((engine?.events?.get("recordsRefused") ?: 0) > 0) metadataReasons.add("ENGINE_RECORDS_REFUSED")
            if (engine?.invalidFields == true) metadataReasons.add("ENGINE_METRICS_INVALID")
            if ((engine?.events?.get("eventsDropped") ?: 0) > 0 && "EVENTS_LOST" !in metadataReasons)
                metadataReasons.add("EVENTS_LOST")
            if (engine == null || engine.state != "STOPPED") metadataReasons.add("ENGINE_FINAL_SNAPSHOT_UNAVAILABLE")
            else if (!engine.events.keys.containsAll(listOf("connectionsAccepted", "connectionsProxied", "connectionsPassthrough", "eventsQueued")) ||
                !engine.budget.keys.containsAll(listOf("connections", "handshakes")) || engine.gateway.isEmpty() || engine.runtime.isEmpty())
                metadataReasons.add("ENGINE_METRICS_UNAVAILABLE")
            if (!tls.secretsComplete || engine?.goSecretsIncomplete == true || (engine?.events?.get("secretsIncomplete") ?: 0) > 0)
                tlsReasons.add("SECRETS_INCOMPLETE")
            if ((engine?.events?.get("handshakeCapacityPassthrough") ?: 0) > 0 || (engine?.budget?.get("refusedHandshakes") ?: 0) > 0)
                tlsReasons.add("HANDSHAKE_CAPACITY_PASSTHROUGH")
            if ((engine?.events?.get("secretsIncompletePassthrough") ?: 0) > 0)
                tlsReasons.add("SECRETS_INCOMPLETE_PASSTHROUGH")
            if ((engine?.events?.get("connectionsPassthrough") ?: tls.connections.passthrough) > 0)
                tlsReasons.add("CONNECTIONS_PASSTHROUGH")
            if ((engine?.events?.get("connectionsFailed") ?: tls.connections.failed) > 0)
                tlsReasons.add("TLS_CONNECTIONS_FAILED")
        }
        root.put("integrity", JSONObject()
            .put("packetEvidence", domain(root.opt("complete") == true, if (root.opt("complete") == true) emptyList() else listOf("PACKET_EVIDENCE_INCOMPLETE")))
            .put("cleanup", domain(cleanupReasons.isEmpty(), cleanupReasons))
            .put("metadata", domain(metadataReasons.isEmpty(), metadataReasons))
            // Saving secrets or entering relay is not proof the analyser recovered plaintext.
            .put("tlsCoverage", JSONObject().put("status", when {
                tls == null || tls.status == TlsCaptureStatus.DISABLED -> "NOT_APPLICABLE"
                tlsReasons.isNotEmpty() -> "PARTIAL"
                else -> "NOT_VERIFIED"
            }).put("reasons", JSONArray(tlsReasons)).put("decryptionVerified", false)))
        return root
    }

    private fun domain(complete: Boolean, reasons: List<String>) = JSONObject()
        .put("status", if (complete) "COMPLETE" else "INCOMPLETE").put("reasons", JSONArray(reasons))

    fun nioClean(s: SocksNioTcpServer.Stats): Boolean =
        s.server.state == SocksNioServer.State.STOPPED && !s.server.listenerRegistered &&
            s.eventLoopThreadsAlive == 0 && s.server.loops.all { it.state == SocksEventLoop.State.TERMINATED &&
                it.channels == 0 && it.resources == 0 && it.keys == 0 && it.timers == 0 &&
                it.commands == 0 && it.completions == 0 && it.cleanupFailures == 0L } &&
            (s.server.admission?.pendingReservations ?: 0) == 0 &&
            s.server.admission?.ownerLoads.orEmpty().all { it == 0 } &&
            listOfNotNull(s.server.admission?.handshakes, s.server.admission?.tcp, s.server.admission?.udp).all { it.current == 0 } &&
            (s.buffers?.reservedBytes ?: 0) == 0 && (s.buffers?.allocatedBytes ?: 0) == 0 &&
            (s.runResolver?.subscribers ?: 0) == 0 && s.runResolver?.open != true &&
            (s.udp?.queuedBytes ?: 0) == 0 && (s.udp?.scratchBytes ?: 0) == 0 &&
            (s.udp?.associations ?: 0) == 0

    private fun nioJson(s: SocksNioTcpServer.Stats, time: Long): JSONObject {
        val cfg = s.eventLoopConfig
        val dns = s.processResolver
        return JSONObject().put("snapshotVersion", s.snapshotVersion).put("captureGeneration", s.server.captureGeneration)
            .put("networkGeneration", s.runResolver?.networkGeneration ?: JSONObject.NULL)
            .put("snapshotAtMillis", time).put("serverState", s.server.state.name)
            .put("listenerRegistered", s.server.listenerRegistered).put("healthy", s.server.failure == null && s.server.loops.all {
                it.failure == null && it.callbackFailures == 0L && it.cleanupFailures == 0L })
            .put("cleanupIncomplete", !nioClean(s)).put("eventLoopThreadsAlive", s.eventLoopThreadsAlive)
            .put("acceptedClients", s.server.acceptedClients).put("rejectedTransfers", s.server.rejectedTransfers)
            .put("connectedTcpRelays", s.connectedRelays).put("connectedDirectRelays", maxOf(0, s.connectedRelays - s.gatewayRelays))
            .put("gatewayRelays", s.gatewayRelays)
            .put("failureEvents", JSONObject(s.failureEvents))
            .put("loopLimits", JSONObject().put("commands", cfg.commandCapacity).put("completions", cfg.completionCapacity)
                .put("channels", cfg.channelCapacity).put("resources", cfg.resourceCapacity).put("timers", cfg.timerCapacity)
                .put("shutdownTimeoutMillis", cfg.shutdownTimeoutMillis))
            .put("loops", JSONArray(s.server.loops.mapIndexed { index, l -> JSONObject()
                .put("index", index).put("state", l.state.name).put("commands", l.commands).put("completions", l.completions)
                .put("peakCommands", l.peakCommands).put("peakCompletions", l.peakCompletions).put("channels", l.channels)
                .put("peakChannels", l.peakChannels).put("keys", l.keys).put("resources", l.resources).put("timers", l.timers)
                .put("turns", l.turns).put("selectCalls", l.selectCalls).put("emptySelectBackoffs", l.emptySelectBackoffs)
                .put("readinessCallbacks", l.readinessCallbacks).put("rejectedCommands", l.rejectedCommands)
                .put("rejectedCompletions", l.rejectedCompletions).put("rejectedTimers", l.rejectedTimers)
                .put("callbackFailures", l.callbackFailures).put("cleanupFailures", l.cleanupFailures)
                .put("maxWorkNanos", l.maxWorkNanos).put("maxTimerLatenessNanos", l.maxTimerLatenessNanos)
                .put("healthy", l.failure == null && l.callbackFailures == 0L && l.cleanupFailures == 0L) }))
            .put("tcpBuffers", JSONObject().put("limitBytes", s.bufferCapacityBytes)
                .put("reservedBytes", s.buffers?.reservedBytes ?: 0).put("allocatedBytes", s.buffers?.allocatedBytes ?: 0)
                .put("peakAllocatedBytes", s.buffers?.peakAllocatedBytes ?: 0)
                .put("rejectedReservations", s.buffers?.rejectedReservations ?: 0).put("allocationFailures", s.buffers?.allocationFailures ?: 0))
            .put("dns", JSONObject().put("counterScope", "process_shared_across_captures")
                .put("workerLimit", s.processResolverLimits.workers).put("queueLimit", s.processResolverLimits.queuedQueries)
                .put("subscriberLimit", s.processResolverLimits.subscribers).put("subscribersPerQueryLimit", s.processResolverLimits.subscribersPerQuery)
                .put("workers", dns.workers).put("activeLookups", dns.activeLookups).put("queuedQueries", dns.queuedQueries)
                .put("peakActiveLookups", dns.peakActiveLookups).put("peakQueuedQueries", dns.peakQueuedQueries)
                .put("subscribers", dns.subscribers).put("peakSubscribers", dns.peakSubscribers).put("lookups", dns.lookups)
                .put("merged", dns.merged).put("rejected", dns.rejected).put("failed", dns.failed).put("cancelled", dns.cancelled)
                .put("abandonedResults", dns.abandonedResults).put("timedOut", dns.timedOut)
                .put("discardedCompletions", dns.discardedCompletions).put("rejectedCompletions", dns.rejectedCompletions)
                .put("callbackFailures", dns.callbackFailures).put("runOpen", s.runResolver?.open ?: false)
                .put("runSubscribers", s.runResolver?.subscribers ?: 0).put("runPeakSubscribers", s.runResolver?.peakSubscribers ?: 0)
                .put("runInFlightQueries", s.runResolver?.inFlightQueries ?: 0).put("runPeakInFlightQueries", s.runResolver?.peakInFlightQueries ?: 0)
                .put("backgroundLookupsStillRunning", dns.activeLookups > 0))
            .apply {
                s.gateway?.let { put("gatewayConnect", JSONObject().put("attempts", it.attempts).put("ready", it.ready)
                    .put("timeouts", it.timeouts).put("refusals", it.refusals)
                    .put("failuresByStage", JSONObject(it.failures.mapKeys { entry -> entry.key.name }))) }
                s.udp?.let { u -> put("udp", JSONObject().put("packetsPerAssociationLimit", 8)
                    .put("bytesPerAssociationLimit", 128 * 1024).put("globalQueueLimitBytes", 8 * 1024 * 1024)
                    .put("queuedBytes", u.queuedBytes).put("queuedPackets", u.queuedPackets)
                    .put("peakQueuedBytes", u.peakQueuedBytes).put("peakQueuedPackets", u.peakQueuedPackets)
                    .put("scratchBytes", u.scratchBytes).put("associations", u.associations)
                    .put("queueDroppedPackets", u.queueDroppedPackets).put("queueDroppedBytes", u.queueDroppedBytes)
                    .put("sendFailures", u.sendFailures).put("ambiguousEmptySends", u.ambiguousEmptySends)
                    .put("blockedDatagrams", u.traffic.blockedDatagrams).put("blockedBytes", u.traffic.blockedBytes)
                    .put("invalidDatagrams", u.traffic.invalidDatagrams).put("sourceRejectedDatagrams", u.traffic.sourceRejectedDatagrams)
                    .put("unallowedResponses", u.traffic.unallowedResponses).put("oversizedDatagrams", u.traffic.oversizedDatagrams)
                    .put("resolutionFailures", u.traffic.resolutionFailures).put("expiredAssociations", s.expiredUdp)) }
            }
    }

    fun tlsJson(s: TlsCaptureState): JSONObject = JSONObject().put("status", s.status.wireName)
        .put("errorCode", s.errorCode?.wireName ?: JSONObject.NULL).put("gatewayPort", s.gatewayPort ?: JSONObject.NULL)
        .put("acceptedConnections", s.connections.accepted).put("proxiedConnections", s.connections.proxied)
        .put("passthroughConnections", s.connections.passthrough).put("failedConnections", s.connections.failed)
        .put("secretRecordsAccepted", s.connections.secretRecordsAccepted).put("secretRecordsPersisted", s.connections.secretRecordsPersisted)
        .put("secretsComplete", s.secretsComplete).put("bytesToUpstream", s.traffic.bytesToUpstream).put("bytesToDownstream", s.traffic.bytesToDownstream)
        .put("projection", JSONObject().put("eventsDropped", s.connections.eventsDropped).put("eventsRejected", s.connections.eventsRejected)
            .put("eventsNotPersisted", s.connections.eventsNotPersisted).put("statesEvicted", s.connections.connectionStatesEvicted)
            .put("engineEventsDropped", s.traffic.engineEventsDropped)
            .put("eventHistoryEvicted", s.connections.eventHistoryEvicted))
        .apply {
            s.engineDiagnostics?.let { put("engine", it.toJson().put("connectionPopulation", "tls_candidate_subset_of_socks_tcp")) }
            s.secrets?.let { p -> put("persistence", JSONObject().put("accepted", p.accepted).put("persisted", p.persisted)
                .put("rejected", p.rejected).put("unpersisted", maxOf(0, p.accepted - p.persisted)).put("complete", p.complete)
                .put("failure", p.failure?.name ?: JSONObject.NULL).put("mitmSuspended", p.mitmSuspended)
                .put("assetPublished", p.asset != null).apply { p.asset?.watermark?.let { w ->
                    put("watermark", JSONObject().put("sequence", w.sequence).put("plaintextBytes", w.plaintextBytes).put("fileBytes", w.fileBytes)) } }) }
            s.secretQueue?.let { q -> put("secretQueue", JSONObject().put("pendingBytes", q.pendingBytes).put("pendingRecords", q.pendingRecords)
                .put("inFlightBytes", q.inFlightBytes).put("peakPendingBytes", q.peakPendingBytes).put("peakPendingRecords", q.peakPendingRecords)
                .put("peakRetainedBytes", q.peakRetainedBytes).put("queueLimitBytes", q.queueLimitBytes)
                .put("consumerAlive", q.consumerAlive).put("abandoned", q.abandoned)) }
            s.journal?.let { j -> put("journal", JSONObject().put("queued", j.queued).put("peakQueued", j.peakQueued)
                .put("inFlight", j.inFlight).put("persisted", j.persisted).put("notPersisted", j.notPersisted)
                .put("fileBytes", j.fileBytes).put("capacityDropped", j.capacityDropped)
                .put("writeFailures", j.writeFailures).put("closeTimedOut", j.closeTimedOut).put("workerAlive", j.workerAlive)) }
        }
}

/** Optional v2 domains. Missing/invalid/new values are unknown, never a success claim. */
internal data class CaptureReportIntegrity(val packetEvidence: String?, val cleanup: String?,
    val metadata: String?, val tlsCoverage: String?) {
    companion object {
        fun read(root: JSONObject): CaptureReportIntegrity {
            val integrity = root.optJSONObject("integrity")
            fun status(key: String, valid: Set<String>): String? =
                (integrity?.optJSONObject(key)?.opt("status") as? String)?.takeIf { it in valid }
            val ordinary = setOf("COMPLETE", "INCOMPLETE")
            return CaptureReportIntegrity(if (integrity?.has("packetEvidence") == true) status("packetEvidence", ordinary)
                else (root.opt("complete") as? Boolean)?.let { if (it) "COMPLETE" else "INCOMPLETE" },
                status("cleanup", ordinary), status("metadata", ordinary),
                status("tlsCoverage", setOf("NOT_APPLICABLE", "PARTIAL", "NOT_VERIFIED")))
        }
    }
}

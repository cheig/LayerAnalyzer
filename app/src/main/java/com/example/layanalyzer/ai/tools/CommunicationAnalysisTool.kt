// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentCommunicationDomain
import com.example.layanalyzer.ai.tools.dto.AgentCommunicationProjections
import com.example.layanalyzer.ai.tools.dto.AgentCoreSessionEntry
import com.example.layanalyzer.ai.tools.dto.AgentDomainTotals
import com.example.layanalyzer.ai.tools.dto.AgentMediaSessionEntry
import com.example.layanalyzer.ai.tools.dto.AgentRtcpStreamEntry
import com.example.layanalyzer.ai.tools.dto.AgentRtpStreamEntry
import com.example.layanalyzer.ai.tools.dto.AgentSipCallEntry
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.data.CoreCorrelationEngine
import com.example.layanalyzer.data.ImsRegistrationAnalyzer
import com.example.layanalyzer.data.MediaSessionCorrelator
import com.example.layanalyzer.data.SipCallSetupAnalyzer
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.CommunicationAnalysis
import com.example.layanalyzer.model.CoreSessionSummary
import com.example.layanalyzer.model.CoreProcedureTimeline
import com.example.layanalyzer.model.RtcpStreamSummary
import com.example.layanalyzer.model.RtpStreamSummary
import com.example.layanalyzer.model.SipCallSummary
import com.example.layanalyzer.model.ImsCaptureRange
import com.example.layanalyzer.model.ImsRegistrationAnalysis
import com.example.layanalyzer.model.ImsRegistrationSelection
import com.example.layanalyzer.model.MediaCaptureSnapshot
import com.example.layanalyzer.model.MediaSessionAnalysis
import com.example.layanalyzer.model.SipCallSetupAnalysis
import com.example.layanalyzer.model.SipCallSetupCaptureRange
import com.example.layanalyzer.model.SipCallSetupSelection
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * get_communication_analysis — SIP calls, IMS registrations, RTP/RTCP streams and core sessions.
 *
 * The tool returns *signalling* structure: which calls exist, when they started,
 * how they ended, and what the media streams between them looked like.  It never
 * returns a SIP body or an RTP payload — the DTOs have no field for either — so a
 * model can diagnose a failed registration or one-way audio without the capture's
 * contents entering its context.
 *
 * Selectors are applied before paging and before redaction.  That order matters
 * for `callId`: matching happens against the real Call-ID, because the alias a
 * model sees is generated per run and would never match the capture.  What the
 * model gets back is the alias.
 */
class CommunicationAnalysisTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "get_communication_analysis",
        description = "Summarise VoIP and core-network signalling: SIP calls and deterministic " +
            "IMS REGISTER stages with their " +
            "outcome and negotiated media, RTP stream quality (loss, jitter, reordering), " +
            "RTCP reports, and correlated core-network sessions. Returns metadata only, " +
            "never message bodies or media payload. A single session can carry more nested " +
            "detail than one result allows, so when the full projection would not fit, nested " +
            "structures are replaced by their counts and detail=shallow is reported; re-read one " +
            "session by callId or correlationId with detail=full for its stages, delay " +
            "contributions and transport evidence.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "properties" to mapOf(
                "domains" to mapOf(
                    "type" to "array",
                    "maxItems" to AgentCommunicationDomain.wireNames.size,
                    "items" to mapOf(
                        "type" to "string",
                        "enum" to AgentCommunicationDomain.wireNames
                    )
                ),
                "callId" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_CALL_ID_LENGTH
                ),
                "protocol" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_PROTOCOL_LENGTH
                ),
                "procedureType" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_PROCEDURE_TYPE_LENGTH
                ),
                "correlationId" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_CORRELATION_ID_LENGTH
                ),
                "startTime" to mapOf("type" to "number"),
                "endTime" to mapOf("type" to "number"),
                "timeRange" to mapOf(
                    "type" to "object",
                    "additionalProperties" to false,
                    "properties" to mapOf(
                        "startTime" to mapOf("type" to "number"),
                        "endTime" to mapOf("type" to "number"),
                        "start" to mapOf("type" to "number"),
                        "end" to mapOf("type" to "number")
                    )
                ),
                "frameNumber" to mapOf(
                    "type" to "integer",
                    "minimum" to 1
                ),
                "targetSetupMillis" to mapOf(
                    "type" to "integer",
                    "minimum" to 0
                ),
                "attentionThresholdMillis" to mapOf(
                    "type" to "integer",
                    "minimum" to 1
                ),
                "offset" to mapOf(
                    "type" to "integer",
                    "minimum" to 0
                ),
                "limit" to mapOf(
                    "type" to "integer",
                    "minimum" to 1,
                    "maximum" to MAX_LIMIT
                ),
                "includeMessages" to mapOf("type" to "boolean"),
                "detail" to mapOf(
                    "type" to "string",
                    "enum" to listOf(DETAIL_SHALLOW, DETAIL_FULL)
                ),
                "filter" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_FILTER_LENGTH
                )
            )
        ),
        // Call-IDs, IMSIs and addresses are identifiers; the privacy layer in
        // AgentToolRunner.finish aliases them before anything leaves the device.
        sensitivity = AgentDataSensitivity.Identifier,
        defaultTimeoutMillis = 30_000L,
        version = "2"
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val requestedDomains = (arguments["domains"] as? Iterable<*>)
            ?.mapNotNull { AgentCommunicationDomain.fromWire(it as? String) }
            ?.toSet()
            .orEmpty()
        val domains = requestedDomains.ifEmpty { AgentCommunicationDomain.values().toSet() }
        val callId = (arguments["callId"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        val protocol = (arguments["protocol"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        val procedureType = (arguments["procedureType"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        val correlationId = (arguments["correlationId"] as? String)?.trim()?.takeIf { it.isNotEmpty() }
        val timeRange = arguments["timeRange"] as? Map<*, *>
        val startTime = (arguments["startTime"] as? Number)?.toDouble()
            ?: timeRange?.number("startTime", "start")
        val endTime = (arguments["endTime"] as? Number)?.toDouble()
            ?: timeRange?.number("endTime", "end")
        val frameNumber = (arguments["frameNumber"] as? Number)?.toLong()?.takeIf { it > 0L }
        val targetSetupMillis = (arguments["targetSetupMillis"] as? Number)?.toLong()?.takeIf { it >= 0L }
        val attentionThresholdMillis = (arguments["attentionThresholdMillis"] as? Number)?.toLong()?.takeIf { it > 0L }
        val offset = ((arguments["offset"] as? Number)?.toInt() ?: 0).coerceAtLeast(0)
        val limit = minOf(
            (arguments["limit"] as? Number)?.toInt() ?: DEFAULT_LIMIT,
            MAX_LIMIT
        ).coerceAtLeast(1)
        val includeMessages = arguments["includeMessages"] as? Boolean ?: false
        val requestedDetail = (arguments["detail"] as? String)?.trim()?.lowercase()
        val filter = (arguments["filter"] as? String)?.trim().orEmpty()

        val mediaRequested = domains.any {
            it == AgentCommunicationDomain.Sip ||
                it == AgentCommunicationDomain.Rtp ||
                it == AgentCommunicationDomain.Rtcp
        }
        val registrationSource = if (mediaRequested) {
            when (val reading = context.repository.getImsRegistrationSourceData(context.snapshot, filter)) {
                is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
                is AgentAnalysisResult.Success -> reading.value
            }
        } else {
            null
        }
        val analysis = registrationSource?.communication ?: when (
            val reading = context.repository.getCommunicationAnalysis(context.snapshot, filter)
        ) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(reading.error)
            is AgentAnalysisResult.Success -> reading.value
        }
        context.ensureStillValid(context.snapshot)

        val selector = Selector(
            callId = callId,
            protocol = protocol,
            procedureType = procedureType,
            correlationId = correlationId,
            startTime = startTime,
            endTime = endTime,
            frameNumber = frameNumber
        )
        val registrationAnalysis = registrationSource?.let { source ->
            ImsRegistrationAnalyzer.analyze(
                timelines = source.communication.sipDialogs,
                statistics = source.statistics,
                expertInfo = source.expertInfo,
                captureRange = ImsCaptureRange(
                    firstFrame = 1L.takeIf { source.frameCount > 0 },
                    lastFrame = source.frameCount.toLong().takeIf { source.frameCount > 0 },
                    startTime = source.statistics.startTime,
                    endTime = source.statistics.endTime,
                    sipSourceTruncated = source.communication.sipTruncated,
                    expertSourceTruncated = source.expertInfo.truncated,
                    scopeIsFiltered = context.snapshot.scope == AnalysisScope.CurrentFilter ||
                        source.appliedDisplayFilter.isNotBlank(),
                    displayFilter = source.appliedDisplayFilter
                ),
                selection = ImsRegistrationSelection(
                    callIdContains = callId,
                    frameNumber = frameNumber,
                    startTime = startTime,
                    endTime = endTime
                )
            )
        }
        val callSetupAnalysis = registrationSource?.let { source ->
            SipCallSetupAnalyzer.analyze(
                timelines = source.communication.sipDialogs,
                statistics = source.statistics,
                expertInfo = source.expertInfo,
                coreEvents = source.communication.coreMessages,
                captureRange = SipCallSetupCaptureRange(
                    firstFrame = 1L.takeIf { source.frameCount > 0 },
                    lastFrame = source.frameCount.toLong().takeIf { source.frameCount > 0 },
                    startTime = source.statistics.startTime,
                    endTime = source.statistics.endTime,
                    sipSourceTruncated = source.communication.sipTruncated,
                    expertSourceTruncated = source.expertInfo.truncated,
                    scopeIsFiltered = context.snapshot.scope == AnalysisScope.CurrentFilter ||
                        source.appliedDisplayFilter.isNotBlank(),
                    displayFilter = source.appliedDisplayFilter
                ),
                selection = SipCallSetupSelection(
                    callId = callId,
                    frameNumber = frameNumber,
                    targetSetupMillis = targetSetupMillis,
                    attentionThresholdMillis = attentionThresholdMillis
                )
            )
        }
        val mediaSessions = registrationSource?.let { source ->
            MediaSessionCorrelator.correlate(
                dialogs = source.communication.sipDialogs,
                rtpStreams = source.communication.streams,
                rtcpStreams = source.communication.rtcpStreams,
                capture = mediaCaptureSnapshot(source, context.snapshot)
            )
        }.orEmpty()
        val projection = withContext(ioDispatcher) {
            project(
                analysis = analysis,
                domains = domains,
                selector = selector,
                offset = offset,
                limit = limit,
                includeMessages = includeMessages,
                registrationAnalysis = registrationAnalysis,
                callSetupAnalysis = callSetupAnalysis,
                mediaSessions = mediaSessions
            )
        }

        val data = buildMap<String, Any?> {
            put("domains", domains.map { it.wireName }.sorted())
            put("filter", filter)
            put("offset", offset)
            put("limit", limit)
            put("includeMessages", includeMessages)
            put("targetSetupMillis", targetSetupMillis)
            put("attentionThresholdMillis", attentionThresholdMillis)
            put("procedureType", procedureType)
            put("correlationId", correlationId)
            put("timeRange", timeRange)
            put("selector", selector.toAgentJson())
            putAll(projection.data)
            // Native caps its own per-domain message lists (5000 SIP / 10000
            // RTP in the current engine).  These four blocks are what stops a
            // model from reading a capped analysis as a complete one, so they
            // are always present regardless of which domains were requested.
            put("sipSource", AgentDomainTotals(analysis.sipTotal, analysis.sipTruncated).toAgentJson())
            put("rtpSource", AgentDomainTotals(analysis.rtpTotal, analysis.rtpTruncated).toAgentJson())
            put("rtcpSource", AgentDomainTotals(analysis.rtcpTotal, analysis.rtcpTruncated).toAgentJson())
            put("coreSource", AgentDomainTotals(analysis.coreTotal, analysis.coreTruncated).toAgentJson())
            put("sourceTruncated", projection.sourceTruncated)
            put("returned", projection.returned)
            put("total", projection.total)
            put("truncated", projection.truncated)
        }

        // One session can carry more nested detail than the whole allowance
        // holds, so when the full projection will not fit, narrow its *depth*
        // rather than let the byte trim cut arbitrary tails off the lists. An
        // explicit `detail` argument overrides the estimate in either direction.
        val narrowed = when {
            requestedDetail == DETAIL_FULL -> null
            !context.policy.evidenceNarrowingEnabled -> null
            requestedDetail == DETAIL_SHALLOW ||
                AgentCommunicationNarrowing.exceedsAllowance(data, context.resultByteAllowance) ->
                AgentCommunicationNarrowing.narrow(data)
            else -> null
        }
        if (narrowed != null) {
            // Only claim truncation if depth was actually removed. A shallow
            // projection of entries that had no nested detail to begin with lost
            // nothing, and marking it truncated would cap the report's
            // completeness over a difference the model cannot even observe.
            val depthRemoved = AgentCommunicationNarrowing.encodedSize(narrowed) <
                AgentCommunicationNarrowing.encodedSize(data)
            val shallow = narrowed + buildMap {
                put("detail", DETAIL_SHALLOW)
                put("depthNarrowed", depthRemoved)
                if (depthRemoved) {
                    put("truncated", true)
                    put(
                        "continuation",
                        mapOf(
                            "tool" to definition.name,
                            "detail" to DETAIL_FULL,
                            "hint" to "Nested structures were replaced by their counts. Re-read " +
                                "one session with callId or correlationId (and detail=full) for " +
                                "its stages, delay contributions and transport evidence."
                        )
                    )
                }
            }
            return context.success(
                data = shallow,
                returnedCount = projection.returned.toLong(),
                totalCount = projection.total.toLong(),
                truncated = projection.truncated || depthRemoved
            )
        }

        return context.success(
            data = data + mapOf("detail" to DETAIL_FULL),
            returnedCount = projection.returned.toLong(),
            totalCount = projection.total.toLong(),
            truncated = projection.truncated
        )
    }

    /**
     * Narrow, page and project each requested domain.
     *
     * Paging is applied per domain with the same offset/limit rather than across
     * a merged list, because the four domains answer different questions and a
     * shared cursor would let a long call list push the RTP streams off the
     * page entirely.
     */
    private fun project(
        analysis: CommunicationAnalysis,
        domains: Set<AgentCommunicationDomain>,
        selector: Selector,
        offset: Int,
        limit: Int,
        includeMessages: Boolean,
        registrationAnalysis: ImsRegistrationAnalysis?,
        callSetupAnalysis: SipCallSetupAnalysis?,
        mediaSessions: List<MediaSessionAnalysis>
    ): Projection {
        val data = mutableMapOf<String, Any?>()
        var returned = 0
        var total = 0
        var truncated = false

        fun <T, R> section(
            key: String,
            source: List<T>,
            matches: (T) -> Boolean,
            projectRow: (T) -> R,
            toJson: (R) -> Map<String, Any?>
        ) {
            val matching = source.filter(matches)
            val page = matching.drop(offset).take(limit).map(projectRow)
            data[key] = page.map(toJson)
            data["${key}Total"] = matching.size
            returned += page.size
            total += matching.size
            if (offset + page.size < matching.size) truncated = true
        }

        if (AgentCommunicationDomain.Sip in domains) {
            section(
                key = "calls",
                source = analysis.calls,
                matches = selector::matchesCall,
                projectRow = { call ->
                    AgentCommunicationProjections.call(
                        call = call,
                        includeMessages = includeMessages,
                        maxMessages = MAX_MESSAGES_PER_ENTRY
                    )
                },
                toJson = AgentSipCallEntry::toAgentJson
            )
            // A call whose messages were capped for the payload is truncation the
            // model must see, even though the call list itself fit on one page.
            if (includeMessages && analysis.calls.any { it.messages.size > MAX_MESSAGES_PER_ENTRY }) {
                truncated = true
            }
            registrationAnalysis?.let { registration ->
                data["registrationAnalyses"] = listOf(
                    AgentCommunicationProjections.registrationAnalysis(registration).toAgentJson()
                )
                data["registrationAnalysesTotal"] = 1
                returned += 1
                total += 1
            }
            callSetupAnalysis?.let { setup ->
                data["callSetupAnalysis"] = AgentCommunicationProjections.callSetupAnalysis(setup).toAgentJson()
                returned += 1
                total += 1
            }
        }

        if (AgentCommunicationDomain.Rtp in domains) {
            section(
                key = "rtpStreams",
                source = analysis.streams,
                matches = selector::matchesRtpStream,
                projectRow = { stream ->
                    AgentCommunicationProjections.rtpStream(stream)
                },
                toJson = AgentRtpStreamEntry::toAgentJson
            )
        }

        if (domains.any {
                it == AgentCommunicationDomain.Sip ||
                    it == AgentCommunicationDomain.Rtp ||
                    it == AgentCommunicationDomain.Rtcp
            }
        ) {
            section(
                key = "mediaSessions",
                source = mediaSessions,
                matches = selector::matchesMediaSession,
                projectRow = AgentCommunicationProjections::mediaSession,
                toJson = AgentMediaSessionEntry::toAgentJson
            )
        }

        if (AgentCommunicationDomain.Rtcp in domains) {
            section(
                key = "rtcpStreams",
                source = analysis.rtcpStreams,
                matches = selector::matchesRtcpStream,
                projectRow = { stream ->
                    AgentCommunicationProjections.rtcpStream(stream)
                },
                toJson = AgentRtcpStreamEntry::toAgentJson
            )
        }

        if (AgentCommunicationDomain.Core in domains) {
            val matchingSessions = analysis.coreSessions.filter(selector::matchesCoreSession)
            val sessionPage = matchingSessions.drop(offset).take(limit).map { session ->
                AgentCommunicationProjections.coreSession(
                    session = session,
                    includeMessages = includeMessages,
                    maxMessages = MAX_MESSAGES_PER_ENTRY
                )
            }
            data["coreSessions"] = sessionPage.map(AgentCoreSessionEntry::toAgentJson)
            data["coreSessionsTotal"] = matchingSessions.size

            // Keep the old session projection while exposing the graph-derived
            // procedure timeline as the primary cross-protocol view.
            val procedures = analysis.coreProcedures.ifEmpty {
                CoreCorrelationEngine.correlate(analysis.coreMessages, analysis.coreTruncated).timelines
            }
            val matchingProcedures = procedures.filter(selector::matchesCoreProcedure)
            val procedurePage = matchingProcedures.drop(offset).take(limit).map { timeline ->
                AgentCommunicationProjections.coreProcedure(
                    timeline = timeline,
                    includeMessages = includeMessages,
                    maxMessages = MAX_MESSAGES_PER_ENTRY
                )
            }
            data["coreProcedures"] = procedurePage.map(AgentCoreSessionEntry::toAgentJson)
            data["coreProceduresTotal"] = matchingProcedures.size
            returned += sessionPage.size
            total += matchingSessions.size
            if (offset + sessionPage.size < matchingSessions.size) truncated = true
            if (offset + procedurePage.size < matchingProcedures.size) truncated = true
            if (includeMessages &&
                analysis.coreSessions.any { it.messages.size > MAX_MESSAGES_PER_ENTRY } ||
                includeMessages && procedures.any { it.messages.size > MAX_MESSAGES_PER_ENTRY }
            ) {
                truncated = true
            }
        }

        val sourceTruncated = analysis.sipTruncated ||
            analysis.rtpTruncated ||
            analysis.rtcpTruncated ||
            analysis.coreTruncated

        return Projection(
            data = data,
            returned = returned,
            total = maxOf(total, returned),
            // The engine having capped its own input is reported through the
            // aggregate flag too: a complete-looking page built from a capped
            // analysis is not a complete answer.
            truncated = truncated || sourceTruncated,
            sourceTruncated = sourceTruncated
        )
    }

    /**
     * The caller's selectors, matched against unredacted values.
     *
     * Call-ID matching is case-insensitive and substring-based: a model that read
     * a Call-ID from an earlier `get_packet_fields` call may have a prefix, and
     * requiring an exact match would silently return nothing.
     */
    private data class Selector(
        val callId: String?,
        val protocol: String?,
        val procedureType: String?,
        val correlationId: String?,
        val startTime: Double?,
        val endTime: Double?,
        val frameNumber: Long?
    ) {
        fun matchesCall(call: SipCallSummary): Boolean {
            if (callId != null && !call.callId.contains(callId, ignoreCase = true)) return false
            if (frameNumber != null && call.messages.none { it.frameNumber == frameNumber }) return false
            if (protocol != null && !protocol.equals("sip", ignoreCase = true)) {
                val matchesRegister = protocol.equals("register", ignoreCase = true) && call.messages.any {
                    it.method.equals("REGISTER", ignoreCase = true) ||
                        it.cSeqMethod.equals("REGISTER", ignoreCase = true)
                }
                if (!matchesRegister && call.messages.none { it.info.contains(protocol, ignoreCase = true) }) {
                    return false
                }
            }
            return overlapsTime(call.startTime, call.endTime)
        }

        /**
         * RTP and RTCP carry no Call-ID, so a Call-ID selector excludes them
         * rather than matching everything: a model that asked about one call must
         * not be handed every stream in the capture as if it belonged to it.
         * Correlating media to a call is AI-18's job.
         */
        fun matchesRtpStream(stream: RtpStreamSummary): Boolean {
            if (callId != null) return false
            if (protocol != null && !protocol.equals("rtp", ignoreCase = true)) return false
            return true
        }

        fun matchesRtcpStream(stream: RtcpStreamSummary): Boolean {
            if (callId != null) return false
            if (protocol != null && !protocol.equals("rtcp", ignoreCase = true)) return false
            return true
        }

        fun matchesMediaSession(session: MediaSessionAnalysis): Boolean {
            if (callId != null && !session.callId.contains(callId, ignoreCase = true)) return false
            if (protocol != null && protocol.lowercase() !in MEDIA_PROTOCOLS) return false
            if (frameNumber != null && session.lines.none { line ->
                    line.offerFrame == frameNumber || line.answerFrame == frameNumber ||
                        line.directions.any { direction ->
                            direction.firstFrame == frameNumber || direction.lastFrame == frameNumber ||
                                frameNumber in direction.anomalyFrames
                        } || line.rtcp.any { report -> frameNumber in report.reportFrames }
                }
            ) {
                return false
            }
            return overlapsTime(session.startTime ?: Double.NEGATIVE_INFINITY, session.endTime ?: Double.POSITIVE_INFINITY)
        }

        fun matchesCoreSession(session: CoreSessionSummary): Boolean {
            return matchesCoreValues(
                localCorrelationId = session.localCorrelationId,
                procedure = session.procedureType,
                protocols = session.protocols.ifEmpty { listOf(session.protocol) },
                correlationValues = listOf(session.correlationValue),
                frames = session.messages.map { it.frameNumber },
                first = session.startTime,
                last = session.endTime
            )
        }

        fun matchesCoreProcedure(timeline: CoreProcedureTimeline): Boolean = matchesCoreValues(
            localCorrelationId = timeline.localCorrelationId,
            procedure = timeline.procedureType,
            protocols = timeline.messages.map { it.protocol },
            correlationValues = timeline.messages.flatMap { message ->
                listOf(message.correlationValue, message.explicitReference)
            },
            frames = timeline.messages.map { it.frameNumber },
            first = timeline.startTime,
            last = timeline.endTime
        )

        private fun matchesCoreValues(
            localCorrelationId: String,
            procedure: String,
            protocols: List<String>,
            correlationValues: List<String>,
            frames: List<Long>,
            first: Double,
            last: Double
        ): Boolean {
            if (callId != null && correlationValues.none { it.contains(callId, ignoreCase = true) }) return false
            if (correlationId != null &&
                localCorrelationId != correlationId &&
                correlationValues.none { it.contains(correlationId, ignoreCase = true) }
            ) return false
            if (protocol != null && protocols.none { it.equals(protocol, ignoreCase = true) }) return false
            if (procedureType != null && !procedureMatches(procedure, procedureType)) return false
            if (frameNumber != null && frameNumber !in frames) return false
            return overlapsTime(first, last)
        }

        private fun procedureMatches(actual: String, requested: String): Boolean {
            val normalizedActual = actual.lowercase().replace('-', '_').replace('/', '_').replace(' ', '_')
            val normalizedRequested = requested.lowercase().replace('-', '_').replace('/', '_').replace(' ', '_')
            if (normalizedActual == normalizedRequested) return true
            return when (normalizedRequested) {
                "registration", "attach" -> normalizedActual == "registration_attach"
                "authentication", "security_mode" -> normalizedActual == "authentication_security_mode"
                "session", "bearer", "pdu_session" -> normalizedActual == "session_bearer_pdu_establishment"
                "policy", "session_control" -> normalizedActual == "policy_session_control"
                "release", "detach" -> normalizedActual == "release_detach"
                else -> false
            }
        }

        /** Inclusive overlap, so a window clipping either end still matches. */
        private fun overlapsTime(from: Double, to: Double): Boolean {
            if (startTime != null && to < startTime) return false
            if (endTime != null && from > endTime) return false
            return true
        }

        /**
         * Echo the selectors back so the model can see what was actually
         * applied.  The Call-ID is returned as supplied; the privacy layer in
         * `AgentToolRunner.finish` aliases it under the `callId` key, which
         * keeps the echoed selector in the same vocabulary as the calls it
         * selected.
         */
        fun toAgentJson(): Map<String, Any?> = mapOf(
            "callId" to callId,
            "protocol" to protocol,
            "procedureType" to procedureType,
            "correlationId" to correlationId,
            "startTime" to startTime,
            "endTime" to endTime,
            "frameNumber" to frameNumber
        )
    }

    private data class Projection(
        val data: Map<String, Any?>,
        val returned: Int,
        val total: Int,
        val truncated: Boolean,
        val sourceTruncated: Boolean
    )

    private fun mediaCaptureSnapshot(
        source: com.example.layanalyzer.data.ImsRegistrationSourceData,
        snapshot: com.example.layanalyzer.model.AgentCaptureSnapshot
    ): MediaCaptureSnapshot = MediaCaptureSnapshot(
        endpoints = source.statistics.endpoints.mapTo(linkedSetOf()) { it.address },
        firstFrame = 1L.takeIf { source.frameCount > 0 },
        lastFrame = source.frameCount.toLong().takeIf { source.frameCount > 0 },
        startTime = source.statistics.startTime,
        endTime = source.statistics.endTime,
        sourceTruncated = source.communication.sipTruncated ||
            source.communication.rtpTruncated || source.communication.rtcpTruncated,
        scopeIsFiltered = snapshot.scope == AnalysisScope.CurrentFilter || source.appliedDisplayFilter.isNotBlank(),
        encryptedMediaPossible = source.communication.sipMessages.mapNotNull { it.sdp }
            .any { media -> media.mediaProtocol.contains("SAVP", ignoreCase = true) }
    )

    private companion object {
        const val DEFAULT_LIMIT = 20
        const val MAX_LIMIT = 100
        const val MAX_CALL_ID_LENGTH = 256
        const val MAX_PROTOCOL_LENGTH = 32
        const val MAX_PROCEDURE_TYPE_LENGTH = 64
        const val MAX_CORRELATION_ID_LENGTH = 128
        const val MAX_FILTER_LENGTH = 2048

        /**
         * Messages returned for one call or session when includeMessages is set.
         * A registration flow is a handful of messages; a long call can be
         * hundreds, and returning all of them would spend the whole result
         * allowance on one entry.
         */
        const val MAX_MESSAGES_PER_ENTRY = 20
        const val DETAIL_SHALLOW = "shallow"
        const val DETAIL_FULL = "full"
        val MEDIA_PROTOCOLS = setOf("sip", "sdp", "rtp", "rtcp")
    }
}

private fun Map<*, *>.number(vararg names: String): Double? = names
    .asSequence()
    .mapNotNull { name -> (this[name] as? Number)?.toDouble() }
    .firstOrNull()

// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import com.example.layanalyzer.model.CoreCorrelationAnalysis
import com.example.layanalyzer.model.CoreCorrelationConfidence
import com.example.layanalyzer.model.CoreCorrelationEdge
import com.example.layanalyzer.model.CoreCorrelationEdgeType
import com.example.layanalyzer.model.CoreCorrelationGraph
import com.example.layanalyzer.model.CoreCorrelationNode
import com.example.layanalyzer.model.CoreProcedureStage
import com.example.layanalyzer.model.CoreProcedureTimeline
import com.example.layanalyzer.model.CoreProcedureType
import com.example.layanalyzer.model.CoreSignalMessage
import java.util.Locale

/**
 * Builds deterministic cross-protocol core-network procedures from dissection facts.
 *
 * Stable identifiers create procedure components.  Temporal adjacency is retained as
 * an edge for context, but never merges components by itself; this is what prevents
 * two UEs using the same access point at the same time from becoming one session.
 */
object CoreCorrelationEngine {
    private const val TIME_ADJACENCY_SECONDS = 2.0

    fun correlate(
        messages: List<CoreSignalMessage>,
        sourceTruncated: Boolean = false
    ): CoreCorrelationAnalysis {
        if (messages.isEmpty()) {
            return CoreCorrelationAnalysis(sourceTruncated = sourceTruncated)
        }

        val ordered = messages
            .withIndex()
            .sortedWith(compareBy({ it.value.time }, { it.value.frameNumber }, { it.index }))
            .mapIndexed { index, indexed -> MessageRef(index, indexed.value) }
        val indexedEdges = buildEdges(ordered)
        val disjointSet = DisjointSet(ordered.size)
        indexedEdges
            .filter { it.edge.type != CoreCorrelationEdgeType.TimeAdjacent }
            .forEach { edge -> disjointSet.union(edge.fromIndex, edge.toIndex) }

        val components = ordered.indices
            .groupBy(disjointSet::find)
            .values
            .sortedWith(compareBy({ it.minOf { index -> ordered[index].message.time } }, { it.min() }))

        val graph = buildGraph(ordered, indexedEdges)
        val timelines = components.map { indices ->
            buildTimeline(
                indices = indices,
                ordered = ordered,
                indexedEdges = indexedEdges,
                sourceTruncated = sourceTruncated
            )
        }
        return CoreCorrelationAnalysis(
            graph = graph,
            timelines = timelines,
            sourceTruncated = sourceTruncated
        )
    }

    private fun buildEdges(ordered: List<MessageRef>): List<IndexedEdge> {
        val result = mutableListOf<IndexedEdge>()
        val seen = mutableSetOf<String>()
        val keyGroups = mutableMapOf<CorrelationIdentity, MutableList<Int>>()
        ordered.forEach { ref ->
            correlationKeys(ref.message).forEach { key ->
                val identity = CorrelationIdentity(key.relation, key.scope, key.value)
                keyGroups.getOrPut(identity) { mutableListOf() } += ref.index
            }
        }

        keyGroups.values.forEach { indices ->
            val sorted = indices.distinct().sortedBy { it }
            sorted.zipWithNext().forEach edgePair@{ (from, to) ->
                val left = ordered[from].message
                val right = ordered[to].message
                val rightKeys = correlationKeys(right)
                val key = correlationKeys(left).firstOrNull { candidate ->
                    rightKeys.any { it.relation == candidate.relation && it.scope == candidate.scope && it.value == candidate.value }
                } ?: return@edgePair
                if (!compatibleStableIdentifiers(left, right)) return@edgePair
                addEdge(
                    result = result,
                    seen = seen,
                    from = from,
                    to = to,
                    type = key.relation,
                    confidence = confidenceFor(key.relation),
                    basisFields = basisFields(left, right, rightKeys, key),
                    timeDeltaMillis = timeDeltaMillis(left.time, right.time)
                )
            }
        }

        ordered.zipWithNext().forEach { (left, right) ->
            val delta = right.message.time - left.message.time
            if (delta < 0.0 || delta > TIME_ADJACENCY_SECONDS) return@forEach
            if (!timeAdjacentCompatible(left.message, right.message)) return@forEach
            addEdge(
                result = result,
                seen = seen,
                from = left.index,
                to = right.index,
                type = CoreCorrelationEdgeType.TimeAdjacent,
                confidence = CoreCorrelationConfidence.Weak,
                basisFields = emptyList(),
                timeDeltaMillis = timeDeltaMillis(left.message.time, right.message.time)
            )
        }
        return result.sortedWith(compareBy({ it.fromIndex }, { it.toIndex }, { it.edge.type.ordinal }))
    }

    private fun addEdge(
        result: MutableList<IndexedEdge>,
        seen: MutableSet<String>,
        from: Int,
        to: Int,
        type: CoreCorrelationEdgeType,
        confidence: CoreCorrelationConfidence,
        basisFields: List<String>,
        timeDeltaMillis: Long?
    ) {
        val first = minOf(from, to)
        val second = maxOf(from, to)
        val identity = "$first:$second:${type.wireName}"
        if (!seen.add(identity)) return
        result += IndexedEdge(
            fromIndex = first,
            toIndex = second,
            edge = CoreCorrelationEdge(
                fromFrame = 0L,
                toFrame = 0L,
                type = type,
                confidence = confidence,
                basisFields = basisFields.distinct(),
                timeDeltaMillis = timeDeltaMillis
            )
        )
    }

    private fun basisFields(
        left: CoreSignalMessage,
        right: CoreSignalMessage,
        rightKeys: List<CorrelationKey>,
        selected: CorrelationKey
    ): List<String> = buildList {
        correlationKeys(left)
            .filter { candidate ->
                rightKeys.any {
                    it.relation == candidate.relation &&
                        it.scope == candidate.scope &&
                        it.value == candidate.value
                }
            }
            .mapTo(this) { it.fieldName }
        if (left.commandCode != null && left.commandCode == right.commandCode) {
            add("diameter.commandCode")
        }
        if (left.applicationId != null && left.applicationId == right.applicationId) {
            add("diameter.applicationId")
        }
        if (isEmpty()) add(selected.fieldName)
    }.distinct()

    private fun buildGraph(
        ordered: List<MessageRef>,
        indexedEdges: List<IndexedEdge>
    ): CoreCorrelationGraph {
        val signalNodes = ordered.map { ref ->
            CoreCorrelationNode(
                id = signalNodeId(ref),
                kind = "signal",
                frameNumber = ref.message.frameNumber,
                time = ref.message.time,
                protocol = ref.message.protocol
            )
        }
        val identifierNodes = ordered.flatMap { ref ->
            correlationKeys(ref.message).map { key ->
                CoreCorrelationNode(
                    id = "identifier:${key.relation.wireName}:${key.scope}:${key.value}",
                    kind = "identifier",
                    frameNumber = ref.message.frameNumber,
                    time = ref.message.time,
                    protocol = ref.message.protocol,
                    fieldName = key.fieldName,
                    value = key.value
                )
            }
        }.distinctBy { it.id }
        val endpointNodes = ordered.flatMap { ref ->
            listOf(ref.message.source, ref.message.destination)
                .filter { it.isNotBlank() }
                .map { endpoint ->
                    CoreCorrelationNode(
                        id = "endpoint:$endpoint",
                        kind = "endpoint",
                        frameNumber = ref.message.frameNumber,
                        time = ref.message.time,
                        protocol = ref.message.protocol,
                        value = endpoint
                    )
                }
        }.distinctBy { it.id }
        val timeNodes = ordered.map { ref ->
            CoreCorrelationNode(
                id = "time:${ref.index}",
                kind = "time",
                frameNumber = ref.message.frameNumber,
                time = ref.message.time,
                protocol = ref.message.protocol
            )
        }
        val edges = indexedEdges.map { indexed ->
            indexed.edge.copy(
                fromFrame = ordered[indexed.fromIndex].message.frameNumber,
                toFrame = ordered[indexed.toIndex].message.frameNumber,
                fromNodeId = signalNodeId(ordered[indexed.fromIndex]),
                toNodeId = signalNodeId(ordered[indexed.toIndex])
            )
        }
        return CoreCorrelationGraph(
            signalNodes = signalNodes,
            identifierNodes = identifierNodes,
            endpointNodes = endpointNodes,
            timeNodes = timeNodes,
            edges = edges
        )
    }

    private fun buildTimeline(
        indices: List<Int>,
        ordered: List<MessageRef>,
        indexedEdges: List<IndexedEdge>,
        sourceTruncated: Boolean
    ): CoreProcedureTimeline {
        val componentMessages = indices
            .sortedWith(compareBy({ ordered[it].message.time }, { ordered[it].message.frameNumber }))
            .map { ordered[it].message }
        val componentEdges = indexedEdges
            .filter { it.fromIndex in indices && it.toIndex in indices }
            .map { indexed ->
                indexed.edge.copy(
                    fromFrame = ordered[indexed.fromIndex].message.frameNumber,
                    toFrame = ordered[indexed.toIndex].message.frameNumber,
                    fromNodeId = signalNodeId(ordered[indexed.fromIndex]),
                    toNodeId = signalNodeId(ordered[indexed.toIndex])
                )
            }
        val procedureType = inferProcedureType(componentMessages)
        val quality = componentEdges
            .map { it.confidence }
            .filter { it != CoreCorrelationConfidence.Weak }
            .maxByOrNull { it.score }
            ?: CoreCorrelationConfidence.Weak
        val first = componentMessages.firstOrNull()
        val last = componentMessages.lastOrNull() ?: first
        val stages = componentMessages
            .groupBy(::inferStage)
            .values
            .map { stageMessages ->
                val sorted = stageMessages.sortedWith(compareBy({ it.time }, { it.frameNumber }))
                val stageEdges = componentEdges.filter { edge ->
                    val frames = sorted.map { it.frameNumber }.toSet()
                    edge.fromFrame in frames && edge.toFrame in frames
                }
                val stageQuality = stageEdges
                    .map { it.confidence }
                    .filter { it != CoreCorrelationConfidence.Weak }
                    .maxByOrNull { it.score }
                    ?: CoreCorrelationConfidence.Weak
                CoreProcedureStage(
                    stage = inferStage(sorted.first()),
                    startTime = sorted.first().time,
                    endTime = sorted.last().time,
                    frameNumbers = sorted.map { it.frameNumber },
                    messages = sorted,
                    messageTypes = sorted.map { it.messageType }.filter { it.isNotBlank() }.distinct(),
                    outcomes = sorted.map { it.outcome }.filter { it.isNotBlank() }.distinct(),
                    causes = sorted.flatMap(::failureValues).distinct(),
                    correlationQuality = stageQuality,
                    retryCount = retryCount(sorted)
                )
            }
            .sortedWith(compareBy({ it.startTime }, { it.stage }))
        val limitations = buildList {
            if (sourceTruncated) add("Core message results were truncated; the timeline is Partial.")
            if (quality == CoreCorrelationConfidence.Weak) {
                add("No stable cross-message core identifier was observed; this is a Weak candidate only.")
            }
            if (componentMessages.any { correlationKeys(it).isEmpty() }) {
                add("At least one message lacks a usable session, UE, TEID, sequence, or explicit reference field.")
            }
        }.distinct()
        return CoreProcedureTimeline(
            localCorrelationId = "core-${first?.frameNumber ?: "unknown"}",
            procedureType = procedureType,
            startTime = first?.time ?: 0.0,
            endTime = last?.time ?: first?.time ?: 0.0,
            firstFrame = first?.frameNumber,
            lastFrame = last?.frameNumber,
            messages = componentMessages,
            stages = stages,
            correlationQuality = quality,
            failureCauses = componentMessages.flatMap(::failureValues).distinct(),
            retryCount = retryCount(componentMessages),
            edges = componentEdges,
            limitations = limitations,
            partial = sourceTruncated
        )
    }

    private fun correlationKeys(message: CoreSignalMessage): List<CorrelationKey> {
        val values = linkedMapOf<String, String>()
        fun add(name: String, value: String?) {
            if (!value.isNullOrBlank()) values.putIfAbsent(name, value.trim())
        }

        add(message.correlationField, message.correlationValue)
        add("diameter.sessionId", message.sessionId)
        add("pfcp.seid", message.seid)
        add("gtp.teid", message.teid)
        add("ueId.${message.ueIdType}", message.ueId)
        add("sequenceNumber", message.sequenceNumber?.toString())
        add("procedureTransactionIdentity", message.procedureTransactionIdentity?.toString())
        add("bearerId", message.bearerId)
        add("subscriberId", message.subscriberId)
        add("explicitReference", message.explicitReference)
        message.fields.forEach { (name, value) -> add(name, value) }

        return values.mapNotNull { (fieldName, value) ->
            val relation = relationForField(fieldName) ?: return@mapNotNull null
            val normalizedField = fieldName.lowercase(Locale.US)
            val scope = when (relation) {
                CoreCorrelationEdgeType.SameSessionId -> "session:${sessionNamespace(normalizedField)}"
                CoreCorrelationEdgeType.SameTeid -> "teid"
                CoreCorrelationEdgeType.SameUeId ->
                    if (normalizedField.contains("imsi") || normalizedField.contains("supi") ||
                        normalizedField.contains("suci") || normalizedField.contains("subscriber")
                    ) {
                        "subscriber"
                    } else {
                        "ue:${ueNamespace(normalizedField)}"
                    }
                CoreCorrelationEdgeType.SameSequence ->
                    "sequence:${message.protocol.lowercase(Locale.US)}:${endpointPair(message)}:${procedureFamily(message)}"
                CoreCorrelationEdgeType.ExplicitReference -> "explicit"
                CoreCorrelationEdgeType.TimeAdjacent -> return@mapNotNull null
            }
            CorrelationKey(
                relation = relation,
                scope = scope,
                value = value.lowercase(Locale.US),
                fieldName = fieldName
            )
        }.distinctBy { listOf(it.relation, it.scope, it.value) }
    }

    private fun relationForField(fieldName: String): CoreCorrelationEdgeType? {
        val normalized = fieldName.lowercase(Locale.US).replace('-', '_')
        return when {
            normalized.contains("reference") || normalized.contains("correlation") ->
                CoreCorrelationEdgeType.ExplicitReference
            normalized.contains("teid") -> CoreCorrelationEdgeType.SameTeid
            normalized.contains("ue") && normalized.contains("id") -> CoreCorrelationEdgeType.SameUeId
            normalized.contains("imsi") || normalized.contains("supi") ||
                normalized.contains("suci") || normalized.contains("guti") ||
                normalized.contains("subscriber") -> CoreCorrelationEdgeType.SameUeId
            normalized.contains("sequence") || normalized == "seq" || normalized.endsWith(".seq") ||
                normalized.contains("transaction") && normalized.contains("identity") ||
                normalized.endsWith(".pti") || normalized == "pti" ->
                CoreCorrelationEdgeType.SameSequence
            normalized.contains("seid") || normalized.contains("session_id") ||
                normalized.contains("sessionid") || normalized == "session" ->
                CoreCorrelationEdgeType.SameSessionId
            normalized.contains("bearer") && normalized.contains("id") ->
                CoreCorrelationEdgeType.SameSessionId
            else -> null
        }
    }

    private fun compatibleStableIdentifiers(
        left: CoreSignalMessage,
        right: CoreSignalMessage
    ): Boolean {
        val leftKeys = correlationKeys(left)
        val rightKeys = correlationKeys(right)
        val leftByNamespace = leftKeys
            .filter { it.relation != CoreCorrelationEdgeType.TimeAdjacent }
            .groupBy { it.relation to it.scope }
            .mapValues { (_, keys) -> keys.map { it.value }.toSet() }
        val rightByNamespace = rightKeys
            .filter { it.relation != CoreCorrelationEdgeType.TimeAdjacent }
            .groupBy { it.relation to it.scope }
            .mapValues { (_, keys) -> keys.map { it.value }.toSet() }
        leftByNamespace.keys.intersect(rightByNamespace.keys).forEach { namespace ->
            if (leftByNamespace.getValue(namespace).intersect(rightByNamespace.getValue(namespace)).isEmpty()) {
                return false
            }
        }
        return true
    }

    private fun ueNamespace(fieldName: String): String = when {
        fieldName.contains("mme") -> "mme"
        fieldName.contains("enb") -> "enb"
        fieldName.contains("amf") -> "amf"
        fieldName.contains("ran") -> "ran"
        else -> fieldName
    }

    private fun sessionNamespace(fieldName: String): String = when {
        fieldName.contains("diameter") -> "diameter"
        fieldName.contains("pfcp") || fieldName.contains("seid") -> "pfcp"
        fieldName.contains("gtpv2") -> "gtpv2"
        fieldName.contains("gtp") || fieldName.contains("bearer") -> "gtp"
        else -> fieldName.replace('_', '.')
    }

    private fun timeAdjacentCompatible(left: CoreSignalMessage, right: CoreSignalMessage): Boolean {
        if (!compatibleStableIdentifiers(left, right)) return false
        val sameProtocol = left.protocol.equals(right.protocol, ignoreCase = true)
        return sameProtocol || endpointPair(left) == endpointPair(right)
    }

    private fun endpointPair(message: CoreSignalMessage): String =
        listOf(message.source, message.destination)
            .filter { it.isNotBlank() }
            .map { it.lowercase(Locale.US) }
            .sorted()
            .joinToString("|")

    private fun procedureFamily(message: CoreSignalMessage): String =
        inferStage(message).substringBefore('_')

    private fun inferProcedureType(messages: List<CoreSignalMessage>): String {
        val stages = messages.map(::inferStage).toSet()
        return when {
            CoreProcedureType.ReleaseDetach.wireName in stages -> CoreProcedureType.ReleaseDetach.wireName
            CoreProcedureType.RegistrationAttach.wireName in stages -> CoreProcedureType.RegistrationAttach.wireName
            CoreProcedureType.AuthenticationSecurityMode.wireName in stages -> CoreProcedureType.AuthenticationSecurityMode.wireName
            CoreProcedureType.PolicySessionControl.wireName in stages -> CoreProcedureType.PolicySessionControl.wireName
            CoreProcedureType.SessionBearerPduEstablishment.wireName in stages ->
                CoreProcedureType.SessionBearerPduEstablishment.wireName
            else -> CoreProcedureType.Unknown.wireName
        }
    }

    private fun inferStage(message: CoreSignalMessage): String {
        val explicit = normalizeProcedure(message.procedureType)
        if (explicit != CoreProcedureType.Unknown.wireName) return explicit
        val text = listOf(message.protocol, message.messageType, message.info, message.outcome, message.cause)
            .joinToString(" ")
            .lowercase(Locale.US)
        return when {
            listOf("release", "delete", "detach", "deregister", "deactivate", "release access")
                .any(text::contains) -> CoreProcedureType.ReleaseDetach.wireName
            listOf("authentication", "auth request", "auth response", "security mode", "aka")
                .any(text::contains) -> CoreProcedureType.AuthenticationSecurityMode.wireName
            listOf("policy", "pcrf", "pcf", "ccr", "cca", "gx", "gy")
                .any(text::contains) -> CoreProcedureType.PolicySessionControl.wireName
            listOf("session", "bearer", "pdu", "create", "modify", "establish", "pfcp", "gtp")
                .any(text::contains) -> CoreProcedureType.SessionBearerPduEstablishment.wireName
            listOf("registration", "attach", "location", "initial ue", "service request", "tracking")
                .any(text::contains) -> CoreProcedureType.RegistrationAttach.wireName
            else -> CoreProcedureType.Unknown.wireName
        }
    }

    private fun normalizeProcedure(value: String): String {
        val normalized = value.lowercase(Locale.US).replace('-', '_').replace('/', '_').replace(' ', '_')
        return CoreProcedureType.values().firstOrNull { it.wireName == normalized }?.wireName
            ?: CoreProcedureType.Unknown.wireName
    }

    private fun failureValues(message: CoreSignalMessage): List<String> = buildList {
        if (message.cause.isNotBlank()) add(message.cause)
        if (message.experimentalResult.isNotBlank()) add(message.experimentalResult)
        if (message.resultCode.isNotBlank() && !isSuccessCode(message.resultCode)) add(message.resultCode)
        if (message.outcome.isNotBlank() && isFailureOutcome(message.outcome)) add(message.outcome)
    }

    private fun isSuccessCode(value: String): Boolean {
        val normalized = value.trim().lowercase(Locale.US)
        return normalized in setOf("0", "1", "2001", "success", "successful", "ok", "accepted")
    }

    private fun isFailureOutcome(value: String): Boolean {
        val normalized = value.trim().lowercase(Locale.US)
        if (normalized.isEmpty() || isSuccessCode(normalized)) return false
        return normalized.any { it.isDigit() } && normalized.toIntOrNull()?.let { it >= 3 || it < 0 } == true ||
            listOf("fail", "reject", "denied", "error", "timeout", "cause", "abort").any(normalized::contains)
    }

    private fun retryCount(messages: List<CoreSignalMessage>): Int {
        val requestTypes = messages.filter { isRequest(it) }
            .map { it.messageType.ifBlank { it.info }.lowercase(Locale.US) }
            .filter { it.isNotBlank() }
        return requestTypes.groupingBy { it }.eachCount().values.sumOf { count -> (count - 1).coerceAtLeast(0) }
    }

    private fun isRequest(message: CoreSignalMessage): Boolean {
        message.request?.let { return it }
        val text = listOf(message.messageType, message.info).joinToString(" ").lowercase(Locale.US)
        return listOf("request", "create", "establish", "initial", "attach", "register", "ccr", "delete")
            .any(text::contains)
    }

    private fun confidenceFor(type: CoreCorrelationEdgeType): CoreCorrelationConfidence = when (type) {
        CoreCorrelationEdgeType.SameSessionId,
        CoreCorrelationEdgeType.SameTeid,
        CoreCorrelationEdgeType.SameUeId,
        CoreCorrelationEdgeType.ExplicitReference -> CoreCorrelationConfidence.High
        CoreCorrelationEdgeType.SameSequence -> CoreCorrelationConfidence.Medium
        CoreCorrelationEdgeType.TimeAdjacent -> CoreCorrelationConfidence.Weak
    }

    private fun signalNodeId(ref: MessageRef): String = "signal:${ref.message.frameNumber}:${ref.index}"

    private fun timeDeltaMillis(left: Double, right: Double): Long =
        ((right - left).coerceAtLeast(0.0) * 1000.0).toLong()

    private data class MessageRef(val index: Int, val message: CoreSignalMessage)

    private data class CorrelationKey(
        val relation: CoreCorrelationEdgeType,
        val scope: String,
        val value: String,
        val fieldName: String
    )

    private data class CorrelationIdentity(
        val relation: CoreCorrelationEdgeType,
        val scope: String,
        val value: String
    )

    private data class IndexedEdge(
        val fromIndex: Int,
        val toIndex: Int,
        val edge: CoreCorrelationEdge
    )

    private class DisjointSet(size: Int) {
        private val parent = IntArray(size) { it }
        private val rank = IntArray(size)

        fun find(value: Int): Int {
            if (parent[value] != value) parent[value] = find(parent[value])
            return parent[value]
        }

        fun union(left: Int, right: Int) {
            var first = find(left)
            var second = find(right)
            if (first == second) return
            if (rank[first] < rank[second]) {
                val swap = first
                first = second
                second = swap
            }
            parent[second] = first
            if (rank[first] == rank[second]) rank[first]++
        }
    }
}

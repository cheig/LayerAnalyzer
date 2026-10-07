// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.tools.dto.AgentCredentialFields
import com.example.layanalyzer.ai.tools.dto.AgentFieldAggregate
import com.example.layanalyzer.ai.tools.dto.AgentFieldAggregateSampleMode
import com.example.layanalyzer.ai.tools.dto.AgentPacketFieldAggregate
import com.example.layanalyzer.ai.tools.dto.AgentScopeArgument
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AnalysisScope
import com.example.layanalyzer.model.ProtocolNode
import java.util.Random
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * query_packet_field_aggregate — scan a filtered packet set locally and return
 * field distribution plus a small set of frame candidates.
 *
 * The scan deliberately does not declare detail frames: its output is an
 * aggregate over the filter, not a request to send individual packet details to
 * the model.  The repository bounds summary pages and holds one temporary
 * filter lease for the whole operation; this tool retains only counters and
 * bounded frame-number samples.
 */
class PacketFieldAggregateTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "query_packet_field_aggregate",
        description = "Scan packets matching a display filter locally and return " +
            "field presence/occurrence counts, first and last frames, anomaly frames, " +
            "and a small sample of frame numbers. It never returns field values, " +
            "packet bytes, payload or a protocol tree; use get_packet_fields on the " +
            "sample frames when a concrete explanation is needed.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "required" to listOf("fields"),
            "properties" to mapOf(
                "filter" to mapOf(
                    "type" to "string",
                    "maxLength" to MAX_FILTER_LENGTH
                ),
                "fields" to mapOf(
                    "type" to "array",
                    "minItems" to 1,
                    "maxItems" to MAX_FIELDS,
                    "items" to mapOf(
                        "type" to "string",
                        "minLength" to 1,
                        "maxLength" to MAX_FIELD_NAME_LENGTH
                    )
                ),
                "sampleLimit" to mapOf(
                    "type" to "integer",
                    "minimum" to 1,
                    "maximum" to MAX_SAMPLE_LIMIT
                ),
                "sampleMode" to mapOf(
                    "type" to "string",
                    "enum" to AgentFieldAggregateSampleMode.wireNames
                )
            )
        ),
        sensitivity = AgentDataSensitivity.Identifier,
        defaultTimeoutMillis = 60_000L
    )

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val filter = (arguments["filter"] as? String)?.trim().orEmpty()
        val requestedFields = (arguments["fields"] as? Iterable<*>)
            ?.mapNotNull { it as? String }
            ?.map(String::trim)
            ?.filter(String::isNotEmpty)
            ?.distinct()
            .orEmpty()
        if (requestedFields.isEmpty()) {
            throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "At least one field name is required.",
                details = mapOf("field" to "arguments.fields")
            )
        }

        val invalid = requestedFields.firstOrNull { !ProtocolFieldProjector.isValidFieldName(it) }
        if (invalid != null) {
            throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "A field name may contain only letters, digits, " +
                    "underscore, hyphen and dot.",
                details = mapOf("field" to "arguments.fields")
            )
        }

        val fields = requestedFields.take(context.fieldLimit(requestedFields.size))
        val fieldsTruncated = fields.size < requestedFields.size
        val sampleLimit = ((arguments["sampleLimit"] as? Number)?.toInt() ?: DEFAULT_SAMPLE_LIMIT)
            .coerceIn(1, MAX_SAMPLE_LIMIT)
        val sampleMode = AgentFieldAggregateSampleMode.fromWire(arguments["sampleMode"] as? String)
            ?: AgentFieldAggregateSampleMode.FirstLastAnomaly

        val accumulators = fields.associateWith { FieldAccumulator() }
        val firstLast = FirstLastSampler()
        val anomalyFrames = LinkedHashSet<Long>()
        val uniform = ReservoirSampler(sampleLimit)
        var detailUnavailable = 0

        val scanned = withContext(ioDispatcher) {
            context.repository.scanFilteredPackets(
                snapshot = context.snapshot,
                filter = filter
            ) { reader, summary ->
                val frame = summary.frameNumber
                firstLast.observe(frame)
                if (sampleMode == AgentFieldAggregateSampleMode.Uniform) {
                    uniform.offer(frame)
                }

                val root = reader.getPacketDetails(frame)
                if (root == null) {
                    detailUnavailable += 1
                    return@scanFilteredPackets
                }

                if (containsAnomaly(root) && anomalyFrames.size < MAX_ANOMALY_FRAMES) {
                    anomalyFrames += frame
                }
                val projection = ProtocolFieldProjector.project(
                    root = root,
                    requestedFields = fields,
                    includeDisplayValue = false
                )
                projection.fields.forEach { (field, occurrences) ->
                    accumulators[field]?.observe(frame, occurrences)
                }
            }
        }

        val stats = when (scanned) {
            is AgentAnalysisResult.Failure -> throw AgentToolException(scanned.error)
            is AgentAnalysisResult.Success -> scanned.value
        }
        val effectiveFilter = stats.appliedFilter.ifBlank {
            filter.ifBlank {
                if (context.snapshot.scope == AnalysisScope.CurrentFilter) {
                    context.snapshot.displayFilter.trim()
                } else {
                    ""
                }
            }
        }
        val sampleFrames = selectSamples(
            mode = sampleMode,
            sampleLimit = sampleLimit,
            firstLast = firstLast,
            anomalyFrames = anomalyFrames,
            uniform = uniform
        )
        val coverageComplete = stats.complete && detailUnavailable == 0
        val aggregate = AgentPacketFieldAggregate(
            filter = effectiveFilter,
            scope = scopeName(context),
            queryMode = QUERY_MODE_FILTER_LEASE,
            matchedPackets = stats.matchedPackets,
            scannedPackets = stats.scannedPackets,
            fields = accumulators.mapValues { (field, accumulator) ->
                accumulator.toAggregate(field)
            },
            sampleFrames = sampleFrames,
            anomalyFrames = anomalyFrames.take(sampleLimit),
            sampleMode = sampleMode.wireName,
            sampleLimit = sampleLimit,
            sampled = stats.matchedPackets > sampleFrames.size,
            coverageComplete = coverageComplete,
            detailUnavailablePackets = detailUnavailable,
            truncated = !coverageComplete || fieldsTruncated
        )
        val data = aggregate.toAgentJson() + mapOf(
            "requestedFields" to requestedFields,
            "fields" to aggregate.fields.mapValues { (_, value) -> value.toAgentJson() },
            "fieldsTruncated" to fieldsTruncated
        )
        return context.success(
            data = data,
            returnedCount = sampleFrames.size.toLong(),
            totalCount = stats.matchedPackets.toLong(),
            truncated = aggregate.truncated,
            queryMode = QUERY_MODE_FILTER_LEASE
        )
    }

    private fun selectSamples(
        mode: AgentFieldAggregateSampleMode,
        sampleLimit: Int,
        firstLast: FirstLastSampler,
        anomalyFrames: Set<Long>,
        uniform: ReservoirSampler
    ): List<Long> {
        val selected = LinkedHashSet<Long>()
        fun addWithinLimit(frame: Long?) {
            if (frame != null && selected.size < sampleLimit) selected += frame
        }
        when (mode) {
            AgentFieldAggregateSampleMode.FirstLast -> {
                addWithinLimit(firstLast.first)
                addWithinLimit(firstLast.last)
            }
            AgentFieldAggregateSampleMode.FirstLastAnomaly -> {
                addWithinLimit(firstLast.first)
                addWithinLimit(firstLast.last)
                anomalyFrames.forEach { addWithinLimit(it) }
            }
            AgentFieldAggregateSampleMode.Uniform -> {
                addWithinLimit(firstLast.first)
                addWithinLimit(firstLast.last)
                uniform.values.forEach { addWithinLimit(it) }
            }
        }
        return selected.toList().sorted()
    }

    private fun scopeName(context: AgentToolContext): String =
        AgentScopeArgument.of(context.snapshot.scope).wireName

    private fun containsAnomaly(root: ProtocolNode): Boolean {
        fun visit(node: ProtocolNode): Boolean {
            val text = "${node.filter.orEmpty()} ${node.label}".lowercase()
            if (ANOMALY_MARKERS.any(text::contains)) return true
            return node.children.any(::visit)
        }
        return visit(root)
    }

    private class FieldAccumulator {
        private val present = LinkedHashSet<Long>()
        private val schemes = LinkedHashSet<String>()
        private var occurrenceCount = 0
        private var credential = false
        private var payload = false

        fun observe(
            frame: Long,
            occurrences: List<com.example.layanalyzer.ai.tools.dto.AgentFieldOccurrence>
        ) {
            if (occurrences.isEmpty()) return
            present += frame
            occurrenceCount += occurrences.size
            occurrences.forEach { occurrence ->
                credential = credential || occurrence.credential
                payload = payload || occurrence.payload
                occurrence.scheme?.let(schemes::add)
            }
        }

        fun toAggregate(field: String): AgentFieldAggregate = AgentFieldAggregate(
            fieldName = field,
            presentFrames = present.size,
            occurrenceCount = occurrenceCount,
            firstFrame = present.minOrNull(),
            lastFrame = present.maxOrNull(),
            credential = credential || AgentCredentialFields.isCredential(field),
            payload = payload || AgentCredentialFields.isPayload(field),
            schemes = schemes.toList().sorted()
        )
    }

    private class FirstLastSampler {
        var first: Long? = null
            private set
        var last: Long? = null
            private set

        fun observe(frame: Long) {
            if (first == null) first = frame
            last = frame
        }
    }

    private class ReservoirSampler(private val limit: Int) {
        private val random = Random(AGGREGATE_RANDOM_SEED.toLong())
        private val retained = mutableListOf<Long>()
        private var seen = 0

        val values: List<Long>
            get() = retained.toList()

        fun offer(frame: Long) {
            seen += 1
            if (retained.size < limit) {
                retained += frame
                return
            }
            val slot = random.nextInt(seen)
            if (slot < limit) retained[slot] = frame
        }
    }

    private companion object {
        const val DEFAULT_SAMPLE_LIMIT = 16
        const val MAX_SAMPLE_LIMIT = 32
        const val MAX_FIELDS = 32
        const val MAX_FIELD_NAME_LENGTH = ProtocolFieldProjector.MAX_FIELD_NAME_LENGTH
        const val MAX_FILTER_LENGTH = 2048
        const val MAX_ANOMALY_FRAMES = 64
        const val AGGREGATE_RANDOM_SEED = 0x4C41594E
        const val QUERY_MODE_FILTER_LEASE = "filter_lease"
        val ANOMALY_MARKERS = listOf(
            "retransmission",
            "duplicate_ack",
            "out_of_order",
            "reset",
            "malformed",
            "checksum_bad",
            "expert"
        )
    }
}

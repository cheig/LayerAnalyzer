package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentDetailRequest
import com.example.layanalyzer.ai.tools.dto.AgentFrameFields
import com.example.layanalyzer.data.AgentAnalysisResult
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentToolResult
import kotlinx.coroutines.CoroutineDispatcher
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext

/**
 * get_packet_fields — read a few named fields from a few frames.
 *
 * This is the only tool that dissects individual packets, and it returns a
 * projection rather than a tree: the model names the fields it wants and gets
 * those, not the frame's full dissection.  That keeps a detail read small enough
 * to cite while making it impossible to reconstruct the packet from tool output.
 *
 * Budget is granted by [AgentTool.detailFrames] before execution: the runner
 * clamps the request to the per-call and per-session ceilings and tells the
 * tool exactly which frames it may read.  An oversized request therefore
 * degrades into a truncated answer (granted frames plus an `omittedFrames`
 * list) instead of an error, and the model can page through the remainder in
 * later calls while the session quota lasts.
 */
class PacketFieldsTool(
    private val ioDispatcher: CoroutineDispatcher = Dispatchers.IO
) : AgentTool {

    override val definition = AgentToolDefinition(
        name = "get_packet_fields",
        description = "Read specific protocol fields from a small set of frames. " +
            "Field names are Wireshark field abbreviations such as sip.Method or " +
            "tcp.analysis.retransmission. Returns one entry per occurrence, so repeated " +
            "fields are all visible. The host normally reads 16 frames per call, may " +
            "grant a wider batch for a compact, short-field request, and grants fewer " +
            "frames for a wide projection so each returned frame stays complete; every " +
            "omitted frame is listed in omittedFrames.",
        inputSchema = mapOf(
            "type" to "object",
            "additionalProperties" to false,
            "required" to listOf("frames", "fields"),
            "properties" to mapOf(
                "frames" to mapOf(
                    "type" to "array",
                    "minItems" to 1,
                    // Deliberately above the per-call budget: the runner grants
                    // the first MAX_FRAMES and reports the rest as omitted,
                    // which keeps an oversized request useful instead of wasted.
                    "maxItems" to MAX_FRAMES_ARGUMENT_ITEMS,
                    "items" to mapOf(
                        "type" to "integer",
                        "minimum" to 1
                    )
                ),
                "fields" to mapOf(
                    "type" to "array",
                    "minItems" to 1,
                    "maxItems" to MAX_FIELDS,
                    "items" to mapOf(
                        "type" to "string",
                        "minLength" to 1,
                        "maxLength" to ProtocolFieldProjector.MAX_FIELD_NAME_LENGTH
                    )
                ),
                "includeDisplayValue" to mapOf("type" to "boolean")
            )
        ),
        sensitivity = AgentDataSensitivity.Identifier,
        defaultTimeoutMillis = 30_000L
    )

    /** No filter argument: this tool reads frames the model already identified. */
    override val filterArgumentNames: Set<String> = emptySet()

    /**
     * Declare the frames so the budget is reserved before any dissection runs.
     * Out-of-range values are declared too — the repository rejects them with a
     * precise error, and charging for them stops a model from probing frame
     * numbers for free.
     */
    override fun detailFrames(arguments: Map<String, Any?>): Collection<Long> =
        (arguments["frames"] as? Iterable<*>)
            ?.mapNotNull { (it as? Number)?.toLong() }
            .orEmpty()

    override fun detailRequest(arguments: Map<String, Any?>): AgentDetailRequest {
        val fields = (arguments["fields"] as? Iterable<*>)
            ?.mapNotNull { it as? String }
            ?.map(String::trim)
            ?.filter(String::isNotEmpty)
            ?.distinct()
            .orEmpty()
        return AgentDetailRequest(
            fieldCount = fields.size,
            fieldNameChars = fields.sumOf(String::length),
            includeDisplayValue = arguments["includeDisplayValue"] as? Boolean ?: true
        )
    }

    override suspend fun execute(
        arguments: Map<String, Any?>,
        context: AgentToolContext
    ): AgentToolResult {
        val requestedFrames = detailFrames(arguments).distinct().sorted()
        if (requestedFrames.isEmpty()) {
            throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "At least one frame number is required.",
                details = mapOf("field" to "arguments.frames")
            )
        }
        // The runner's grant is authoritative: it already applied the per-call
        // and per-session caps to the request.  When no grant was issued (a
        // direct call in tests), the host's own clamp is the fallback.
        val frames = context.grantedDetailFrames?.sorted()
            ?: requestedFrames.take(context.detailLimit(requestedFrames.size))

        val requestedFields = (arguments["fields"] as? Iterable<*>)
            ?.mapNotNull { it as? String }
            ?.map { it.trim() }
            ?.filter { it.isNotEmpty() }
            ?.distinct()
            .orEmpty()
        if (requestedFields.isEmpty()) {
            throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "At least one field name is required.",
                details = mapOf("field" to "arguments.fields")
            )
        }

        // A field name is compared, never evaluated.  Rejecting the whole call on
        // the first bad name — instead of silently dropping it — keeps the
        // model's request and the result aligned, so it cannot read a quietly
        // ignored name as "this field is absent from the capture".
        val invalid = requestedFields.firstOrNull { !ProtocolFieldProjector.isValidFieldName(it) }
        if (invalid != null) {
            throw AgentToolException(
                code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
                userMessage = "A field name may contain only letters, digits, " +
                    "underscore, hyphen and dot.",
                // The rejected value is not echoed: it may be crafted text from
                // an injected prompt, and reflecting it puts it in the transcript.
                details = mapOf("field" to "arguments.fields")
            )
        }

        val fields = requestedFields.take(context.fieldLimit(requestedFields.size))
        val fieldsTruncated = fields.size < requestedFields.size
        val includeDisplayValue = arguments["includeDisplayValue"] as? Boolean ?: true

        val results = mutableListOf<AgentFrameFields>()
        frames.forEach { frame ->
            // Each frame is a separate guarded read: a capture swapped midway
            // through a multi-frame call must not contribute rows from two
            // different sessions to one payload.
            val reading = context.repository.getPacketDetails(context.snapshot, frame)
            val root = when (reading) {
                is AgentAnalysisResult.Failure ->
                    // An out-of-range frame is the model's mistake and worth
                    // reporting precisely; a stale session ends the whole call.
                    if (reading.error.code == AgentErrorCode.INVALID_TOOL_ARGUMENTS) {
                        results += unavailable(frame, fields, fieldsTruncated)
                        return@forEach
                    } else {
                        throw AgentToolException(reading.error)
                    }

                is AgentAnalysisResult.Success -> reading.value
            }

            if (root == null) {
                // Dissection failed rather than the field being absent.
                results += unavailable(frame, fields, fieldsTruncated)
                return@forEach
            }

            val projection = withContext(ioDispatcher) {
                ProtocolFieldProjector.project(root, fields, includeDisplayValue)
            }
            results += AgentFrameFields(
                frameNumber = frame,
                detailAvailable = true,
                fields = projection.fields,
                missingFields = projection.missingFields,
                truncated = projection.truncated || fieldsTruncated
            )
        }

        val occurrences = results.sumOf { it.occurrenceCount }
        val projectionTruncated = results.any { it.truncated }
        val truncated = projectionTruncated || context.omittedDetailFrames.isNotEmpty()

        // Deterministic host guidance, delivered inside the result the model
        // actually reads: a wide projection is the usual reason a batch shrank,
        // and the fix (fewer fields, or an aggregate survey first) is the same
        // every time.
        val guidance = if (context.omittedDetailFrames.isNotEmpty() && fields.size > WIDE_FIELD_GUIDANCE_THRESHOLD) {
            "Wide field projections shrink the per-call frame grant so each returned frame " +
                "stays complete. To cover more frames per call, request at most " +
                "$WIDE_FIELD_GUIDANCE_THRESHOLD fields, or survey candidates with " +
                "query_packet_field_aggregate first; read omittedFrames in follow-up calls."
        } else {
            null
        }

        val data = mapOf(
            "frames" to results.map(AgentFrameFields::toAgentJson),
            "requestedFields" to requestedFields,
            "fields" to fields,
            "fieldsTruncated" to fieldsTruncated,
            "includeDisplayValue" to includeDisplayValue,
            "requested" to requestedFrames.size,
            "granted" to frames.size,
            "returned" to results.size,
            "total" to requestedFrames.size,
            "occurrences" to occurrences,
            "projectionTruncated" to projectionTruncated,
            // This flag is reserved for the runner's post-redaction JSON trim.
            "payloadTruncated" to false,
            "truncated" to truncated
        ) + context.detailBudgetJson(requestedFrames) +
            (guidance?.let { mapOf("guidance" to it) } ?: emptyMap())

        return context.success(
            data = data,
            returnedCount = results.size.toLong(),
            totalCount = requestedFrames.size.toLong(),
            truncated = truncated
        )
    }

    /**
     * A frame whose details could not be read.  Every requested field is listed
     * as missing *and* `detailAvailable` is false, so the two cases stay
     * distinguishable: absent fields on a readable frame, versus a frame that
     * was never dissected at all.
     */
    private fun unavailable(
        frame: Long,
        fields: List<String>,
        fieldsTruncated: Boolean
    ) = AgentFrameFields(
        frameNumber = frame,
        detailAvailable = false,
        fields = emptyMap(),
        missingFields = fields,
        truncated = fieldsTruncated
    )

    private companion object {
        const val MAX_FIELDS = 32
        /** Fields per call above which a shrunken batch earns explicit guidance. */
        const val WIDE_FIELD_GUIDANCE_THRESHOLD = 4
        /**
         * Schema ceiling for the frames array.  Sized so a model can ask for
         * the whole session quota in one call; the budget grant, not the
         * schema, decides how many are actually read.
         */
        const val MAX_FRAMES_ARGUMENT_ITEMS = 48
    }
}

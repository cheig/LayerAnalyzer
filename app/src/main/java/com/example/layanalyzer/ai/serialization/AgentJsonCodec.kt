package com.example.layanalyzer.ai.serialization

import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentFindingTimelineEvent
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentProvenance
import com.example.layanalyzer.model.AgentQuestionAlignment
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import com.example.layanalyzer.model.AgentReportProvenance
import com.example.layanalyzer.model.AgentToolResult
import com.example.layanalyzer.model.AgentTruncationInfo
import com.example.layanalyzer.model.AnalysisScope
import org.json.JSONArray
import org.json.JSONObject
import kotlinx.coroutines.CancellationException
import java.util.Locale

/** Result returned by the non-throwing Agent JSON decoders. */
sealed class AgentJsonDecodeResult<out T> {
    abstract val value: T?
    abstract val error: AgentError?

    val isSuccess: Boolean
        get() = this is Success

    fun getOrNull(): T? = value

    fun errorOrNull(): AgentError? = error

    fun getOrThrow(): T = value ?: throw AgentJsonDecodingException(
        error ?: AgentError(
            code = AgentErrorCode.INTERNAL_ERROR,
            userMessage = "Agent data could not be read."
        )
    )

    data class Success<T>(override val value: T) : AgentJsonDecodeResult<T>() {
        override val error: AgentError? = null
    }

    data class Failure(override val error: AgentError) : AgentJsonDecodeResult<Nothing>() {
        override val value: Nothing? = null
    }
}

typealias AgentJsonResult<T> = AgentJsonDecodeResult<T>

/** Exception used only by the opt-in getOrThrow helper, never by decode itself. */
class AgentJsonDecodingException(
    val agentError: AgentError
) : IllegalArgumentException(agentError.userMessage)

/**
 * Explicit JSON codec for the stable Agent contracts.
 *
 * Version 1 writes a schema and schemaVersion at the top level.  Decoders
 * accept a missing version/schema for pre-versioned local data, ignore unknown
 * fields, and supply defaults for missing optional fields.  A future, higher
 * schemaVersion is rejected as a structured error so it cannot be silently
 * interpreted with older security/privacy semantics.
 */
object AgentJsonCodec {
    const val SCHEMA_VERSION: Int = 1
    const val CURRENT_SCHEMA_VERSION: Int = SCHEMA_VERSION
    const val REPORT_SCHEMA: String = "AgentReport"
    const val TOOL_RESULT_SCHEMA: String = "AgentToolResult"
    const val AGENT_REPORT_SCHEMA: String = REPORT_SCHEMA
    const val AGENT_TOOL_RESULT_SCHEMA: String = TOOL_RESULT_SCHEMA

    private const val FIELD_SCHEMA = "schema"
    private const val FIELD_SCHEMA_NAME = "schemaName"
    private const val FIELD_SCHEMA_VERSION = "schemaVersion"

    fun encodeReport(report: AgentReport): String = reportToObject(report)
        .put(FIELD_SCHEMA, REPORT_SCHEMA)
        .put(FIELD_SCHEMA_VERSION, SCHEMA_VERSION)
        .toString()

    fun encodeAgentReport(report: AgentReport): String = encodeReport(report)

    fun reportToJson(report: AgentReport): String = encodeReport(report)

    fun encode(report: AgentReport): String = encodeReport(report)

    fun decodeReport(json: String): AgentJsonDecodeResult<AgentReport> = decodeSafely("AgentReport") {
        val root = JSONObject(json)
        validateEnvelope(root, REPORT_SCHEMA)
        val reportObject = root.optionalObject("report") ?: root
        reportFromObject(reportObject)
    }

    fun decodeAgentReport(json: String): AgentJsonDecodeResult<AgentReport> = decodeReport(json)

    fun reportFromJson(json: String): AgentJsonDecodeResult<AgentReport> = decodeReport(json)

    fun decodeReportOrNull(json: String): AgentReport? = decodeReport(json).getOrNull()

    fun decodeReportOrThrow(json: String): AgentReport = decodeReport(json).getOrThrow()

    /**
     * Decode a targeted revision payload: findings only, no surrounding report.
     *
     * A revision corrects individual findings, so there is no `summary` to
     * require here.  The envelope check is skipped deliberately — this payload
     * is produced against `AgentPrompt.REVISED_FINDINGS_SCHEMA`, which has no
     * envelope, and a model that wraps its answer in `{"report": ...}` anyway
     * is still read correctly.
     */
    fun decodeRevisedFindings(json: String): AgentJsonDecodeResult<List<AgentFinding>> =
        decodeSafely("AgentRevisedFindings") {
            val root = JSONObject(json)
            val source = root.optionalObject("report") ?: root
            source.objectList("findings", ::findingFromObject)
        }

    fun decodeRevisedFindingsOrNull(json: String): List<AgentFinding>? =
        decodeRevisedFindings(json).getOrNull()

    fun encodeToolResult(result: AgentToolResult): String = toolResultToObject(result)
        .put(FIELD_SCHEMA, TOOL_RESULT_SCHEMA)
        .put(FIELD_SCHEMA_VERSION, SCHEMA_VERSION)
        .toString()

    fun encodeAgentToolResult(result: AgentToolResult): String = encodeToolResult(result)

    fun toolResultToJson(result: AgentToolResult): String = encodeToolResult(result)

    fun encode(result: AgentToolResult): String = encodeToolResult(result)

    fun decodeToolResult(json: String): AgentJsonDecodeResult<AgentToolResult> = decodeSafely("AgentToolResult") {
        val root = JSONObject(json)
        validateEnvelope(root, TOOL_RESULT_SCHEMA)
        val resultObject = root.optionalObject("toolResult") ?: root
        toolResultFromObject(resultObject)
    }

    fun decodeAgentToolResult(json: String): AgentJsonDecodeResult<AgentToolResult> = decodeToolResult(json)

    fun toolResultFromJson(json: String): AgentJsonDecodeResult<AgentToolResult> = decodeToolResult(json)

    fun decodeToolResultOrNull(json: String): AgentToolResult? = decodeToolResult(json).getOrNull()

    fun decodeToolResultOrThrow(json: String): AgentToolResult = decodeToolResult(json).getOrThrow()

    internal inline fun <T> decodeSafely(
        contractName: String,
        decode: () -> T
    ): AgentJsonDecodeResult<T> = try {
        AgentJsonDecodeResult.Success(decode())
    } catch (cancelled: CancellationException) {
        throw cancelled
    } catch (_: Exception) {
        AgentJsonDecodeResult.Failure(
            AgentError(
                code = AgentErrorCode.INTERNAL_ERROR,
                userMessage = "Agent data could not be read.",
                retryable = false,
                details = mapOf(
                    "contract" to contractName,
                    "reason" to "malformed_or_unsupported_json"
                )
            )
        )
    }

    private fun validateEnvelope(root: JSONObject, expectedSchema: String) {
        if (root.has(FIELD_SCHEMA) && !root.isNull(FIELD_SCHEMA) && root.opt(FIELD_SCHEMA) !is String) {
            throw AgentJsonContractException()
        }
        if (root.has(FIELD_SCHEMA_NAME) && !root.isNull(FIELD_SCHEMA_NAME) && root.opt(FIELD_SCHEMA_NAME) !is String) {
            throw AgentJsonContractException()
        }
        val schema = root.optionalString(FIELD_SCHEMA)
            ?: root.optionalString(FIELD_SCHEMA_NAME)
        if (schema != null && normalizeEnumName(schema) != normalizeEnumName(expectedSchema)) {
            throw AgentJsonContractException()
        }

        val version = when (val rawVersion = root.opt(FIELD_SCHEMA_VERSION)) {
            null, JSONObject.NULL -> SCHEMA_VERSION
            is Number -> rawVersion.toInt()
            is String -> rawVersion.toIntOrNull() ?: throw AgentJsonContractException()
            else -> throw AgentJsonContractException()
        }
        if (version < 1 || version > SCHEMA_VERSION) {
            throw AgentJsonContractException()
        }
    }

    private fun reportToObject(report: AgentReport): JSONObject = JSONObject()
        .put("summary", report.summary)
        .put("findings", JSONArray().apply {
            report.findings.forEach { put(findingToObject(it)) }
        })
        .put("limitations", stringsToArray(report.limitations))
        .put("recommendedNextSteps", stringsToArray(report.recommendedNextSteps))
        .put("provenance", reportProvenanceToObject(report.provenance))
        .put("completeness", report.completeness.name)
        .putOptional(
            "questionAlignment",
            JSONArray().apply {
                report.questionAlignment.forEach { put(questionAlignmentToObject(it)) }
            }.takeIf { it.length() > 0 }
        )

    private fun reportFromObject(json: JSONObject): AgentReport = AgentReport(
        summary = json.string("summary"),
        findings = json.objectList("findings", ::findingFromObject),
        limitations = json.stringList("limitations"),
        recommendedNextSteps = json.stringList("recommendedNextSteps"),
        provenance = json.optionalObject("provenance")?.let(::reportProvenanceFromObject)
            ?: AgentReportProvenance(),
        completeness = enumValue(
            raw = json.optionalString("completeness"),
            fallback = AgentReportCompleteness.Unknown
        ),
        questionAlignment = json.objectList("questionAlignment", ::questionAlignmentFromObject)
    )

    private fun findingToObject(finding: AgentFinding): JSONObject = JSONObject()
        .put("id", finding.id)
        .put("title", finding.title)
        .put("severity", finding.severity.name)
        .put("confidence", finding.confidence.name)
        .put("conclusion", finding.conclusion)
        .put("evidence", JSONArray().apply {
            finding.evidence.forEach { put(evidenceToObject(it)) }
        })
        .put("alternatives", stringsToArray(finding.alternatives))
        .put("recommendations", stringsToArray(finding.recommendations))
        .put("timeline", JSONArray().apply {
            finding.timeline.forEach { event -> put(timelineEventToObject(event)) }
        })
        // agent-report-2 fields are emitted only when non-default so encoded
        // reports keep the exact byte layout of the version-1 contract.
        .putOptional(
            "polarity",
            finding.polarity.takeIf { it != AgentFindingPolarity.Unknown }?.name
        )
        .putOptional(
            "counterEvidenceChecked",
            stringsToArray(finding.counterEvidenceChecked).takeIf { it.length() > 0 }
        )
        .putOptional("hypothesisId", finding.hypothesisId)
        .putOptional(
            "relatedSignals",
            stringsToArray(finding.relatedSignals).takeIf { it.length() > 0 }
        )

    private fun findingFromObject(json: JSONObject): AgentFinding = AgentFinding(
        id = json.string("id"),
        title = json.string("title"),
        severity = enumValue(
            raw = json.optionalString("severity"),
            fallback = AgentFindingSeverity.Unknown
        ),
        confidence = enumValue(
            raw = json.optionalString("confidence"),
            fallback = AgentConfidence.Unknown
        ),
        conclusion = json.string("conclusion"),
        evidence = json.objectList("evidence", ::evidenceFromObject),
        alternatives = json.stringList("alternatives"),
        recommendations = json.stringList("recommendations"),
        timeline = json.objectList("timeline", ::timelineEventFromObject),
        polarity = enumValue(
            raw = json.optionalString("polarity"),
            fallback = AgentFindingPolarity.Unknown
        ),
        counterEvidenceChecked = json.stringList("counterEvidenceChecked"),
        hypothesisId = json.optionalString("hypothesisId"),
        relatedSignals = json.stringList("relatedSignals")
    )

    private fun timelineEventToObject(event: AgentFindingTimelineEvent): JSONObject = JSONObject()
        .put("stage", event.stage)
        .putOptional("frameNumber", event.frameNumber)
        .put("detail", event.detail)
        .putOptional("elapsedMillis", event.elapsedMillis)

    private fun timelineEventFromObject(json: JSONObject): AgentFindingTimelineEvent =
        AgentFindingTimelineEvent(
            stage = json.string("stage"),
            frameNumber = json.optionalLong("frameNumber"),
            detail = json.string("detail"),
            elapsedMillis = json.optionalLong("elapsedMillis")
        )

    private fun evidenceToObject(evidence: AgentEvidence): JSONObject = JSONObject()
        .put("type", evidence.type.name)
        .putOptional("frameNumber", evidence.frameNumber)
        .putOptional("displayFilter", evidence.displayFilter)
        .putOptional("field", evidence.field)
        .put("observation", evidence.observation)
        .put("sourceToolCallId", evidence.sourceToolCallId)
        .putOptional("metric", evidence.metric)
        .putOptional("observedValue", evidence.observedValue)
        .putOptional("timeRangeStartMillis", evidence.timeRangeStartMillis)
        .putOptional("timeRangeEndMillis", evidence.timeRangeEndMillis)

    private fun evidenceFromObject(json: JSONObject): AgentEvidence = AgentEvidence(
        type = enumValue(
            raw = json.optionalString("type"),
            fallback = AgentEvidenceType.Unknown
        ),
        frameNumber = json.optionalLong("frameNumber"),
        displayFilter = json.optionalString("displayFilter"),
        field = json.optionalString("field"),
        observation = json.string("observation"),
        sourceToolCallId = json.string("sourceToolCallId"),
        metric = json.optionalString("metric"),
        observedValue = json.optionalString("observedValue"),
        timeRangeStartMillis = json.optionalLong("timeRangeStartMillis"),
        timeRangeEndMillis = json.optionalLong("timeRangeEndMillis")
    )

    private fun questionAlignmentToObject(entry: AgentQuestionAlignment): JSONObject =
        JSONObject()
            .put("questionPart", entry.questionPart)
            .put("addressed", entry.addressed)
            .putOptional(
                "findingIds",
                stringsToArray(entry.findingIds).takeIf { it.length() > 0 }
            )

    private fun questionAlignmentFromObject(json: JSONObject): AgentQuestionAlignment =
        AgentQuestionAlignment(
            questionPart = json.string("questionPart"),
            addressed = json.boolean("addressed", false),
            findingIds = json.stringList("findingIds")
        )

    private fun reportProvenanceToObject(provenance: AgentReportProvenance): JSONObject = JSONObject()
        .put("captureFingerprint", provenance.captureFingerprint)
        .put("scope", provenance.scope.name)
        .put("displayFilter", provenance.displayFilter)
        .put("modelId", provenance.modelId)
        .put("promptVersion", provenance.promptVersion)
        .putOptional("playbookVersion", provenance.playbookVersion)
        .put("generatedAtMillis", provenance.generatedAtMillis)
        .put("toolCallIds", stringsToArray(provenance.toolCallIds))
        .putOptional("agentVersion", provenance.agentVersion)
        .putOptional("startedAtMillis", provenance.startedAtMillis)
        .putOptional("completedAtMillis", provenance.completedAtMillis)
        .putOptional("evidenceFrameCount", provenance.evidenceFrameCount)

    private fun reportProvenanceFromObject(json: JSONObject): AgentReportProvenance =
        AgentReportProvenance(
            captureFingerprint = json.string("captureFingerprint"),
            scope = enumValue(
                raw = json.optionalString("scope"),
                fallback = AnalysisScope.CompleteFile
            ),
            displayFilter = json.string("displayFilter"),
            modelId = json.string("modelId"),
            promptVersion = json.string("promptVersion"),
            playbookVersion = json.optionalString("playbookVersion"),
            generatedAtMillis = json.long("generatedAtMillis"),
            toolCallIds = json.stringList("toolCallIds"),
            agentVersion = json.optionalString("agentVersion"),
            startedAtMillis = json.optionalLong("startedAtMillis"),
            completedAtMillis = json.optionalLong("completedAtMillis"),
            evidenceFrameCount = json.optionalInt("evidenceFrameCount")
        )

    private fun toolResultToObject(result: AgentToolResult): JSONObject = JSONObject()
        .put("toolCallId", result.toolCallId)
        .put("toolName", result.toolName)
        .put("success", result.success)
        .putOptional("data", result.data?.let(::mapToJsonObject))
        .putOptional("error", result.error?.let(::errorToObject))
        .put("truncated", result.truncated)
        .put("sensitivity", result.sensitivity.name)
        .putOptional("queryMode", result.queryMode)
        .put("provenance", provenanceToObject(result.provenance))
        .put("durationMillis", result.durationMillis)
        .put("returnedCount", result.returnedCount)
        .put("totalCount", result.totalCount)
        .put("resultBytes", result.resultBytes)
        .put("truncation", truncationToObject(result.truncation))

    private fun toolResultFromObject(json: JSONObject): AgentToolResult {
        val provenance = json.optionalObject("provenance")?.let(::provenanceFromObject)
            ?: AgentProvenance()
        return AgentToolResult(
            toolCallId = json.string("toolCallId"),
            toolName = json.string("toolName"),
            success = json.boolean("success", false),
            data = json.optionalObject("data")?.let(::jsonObjectToMap),
            error = json.optionalObject("error")?.let(::errorFromObject),
            truncated = json.boolean("truncated", false),
            sensitivity = enumValue(
                raw = json.optionalString("sensitivity"),
                fallback = AgentDataSensitivity.Unknown
            ),
            provenance = provenance,
            durationMillis = json.long("durationMillis"),
            returnedCount = json.optionalLong("returnedCount") ?: provenance.returnedCount,
            totalCount = json.optionalLong("totalCount") ?: provenance.totalCount,
            queryMode = json.optionalString("queryMode") ?: provenance.queryMode,
            resultBytes = json.optionalInt("resultBytes") ?: 0,
            truncation = json.optionalObject("truncation")?.let(::truncationFromObject)
                ?: provenance.truncation
        )
    }

    private fun provenanceToObject(provenance: AgentProvenance): JSONObject = JSONObject()
        .put("captureFingerprint", provenance.captureFingerprint)
        .putOptional("localSessionReference", provenance.localSessionReference)
        .put("scope", provenance.scope.name)
        .put("displayFilter", provenance.displayFilter)
        .put("toolName", provenance.toolName)
        .put("toolVersion", provenance.toolVersion)
        .put("normalizedArgumentsHash", provenance.normalizedArgumentsHash)
        .put("generatedAtMillis", provenance.generatedAtMillis)
        .put("returnedCount", provenance.returnedCount)
        .put("totalCount", provenance.totalCount)
        .put("truncated", provenance.truncated)
        .put("durationMillis", provenance.durationMillis)
        .putOptional("queryMode", provenance.queryMode)
        .put("truncation", truncationToObject(provenance.truncation))

    private fun provenanceFromObject(json: JSONObject): AgentProvenance = AgentProvenance(
        captureFingerprint = json.string("captureFingerprint"),
        localSessionReference = json.optionalString("localSessionReference"),
        scope = enumValue(
            raw = json.optionalString("scope"),
            fallback = AnalysisScope.CompleteFile
        ),
        displayFilter = json.string("displayFilter"),
        toolName = json.string("toolName"),
        toolVersion = json.string("toolVersion", "1"),
        normalizedArgumentsHash = json.string("normalizedArgumentsHash"),
        generatedAtMillis = json.long("generatedAtMillis"),
        returnedCount = json.long("returnedCount"),
        totalCount = json.long("totalCount"),
        truncated = json.boolean("truncated", false),
        durationMillis = json.long("durationMillis"),
        queryMode = json.optionalString("queryMode"),
        truncation = json.optionalObject("truncation")?.let(::truncationFromObject)
            ?: AgentTruncationInfo()
    )

    private fun truncationToObject(info: AgentTruncationInfo): JSONObject = JSONObject()
        .put("sourceTruncated", info.sourceTruncated)
        .put("quotaTruncated", info.quotaTruncated)
        .put("payloadTruncated", info.payloadTruncated)
        .put("contextCompacted", info.contextCompacted)
        .put("returned", info.returned)
        .put("total", info.total)
        .put("omittedFrames", JSONArray(info.omittedFrames))
        .put("omittedPaths", JSONArray(info.omittedPaths))
        .putOptional("continuation", info.continuation?.let(::mapToJsonObject))

    private fun truncationFromObject(json: JSONObject): AgentTruncationInfo = AgentTruncationInfo(
        sourceTruncated = json.boolean("sourceTruncated", false),
        quotaTruncated = json.boolean("quotaTruncated", false),
        payloadTruncated = json.boolean("payloadTruncated", false),
        contextCompacted = json.boolean("contextCompacted", false),
        returned = json.long("returned"),
        total = json.long("total"),
        omittedFrames = json.optionalList("omittedFrames").mapNotNull {
            (it as? Number)?.toLong() ?: it?.toString()?.toLongOrNull()
        },
        omittedPaths = json.optionalList("omittedPaths").mapNotNull { it as? String },
        continuation = json.optionalObject("continuation")
            ?.let(::jsonObjectToMap)
            ?.mapValues { (_, value) -> normalizeTruncationValue(value) }
    )

    private fun normalizeTruncationValue(value: Any?): Any? = when (value) {
        is Number -> value.toLong()
        is Map<*, *> -> value.entries.associate { (key, nested) ->
            key.toString() to normalizeTruncationValue(nested)
        }
        is Iterable<*> -> value.map(::normalizeTruncationValue)
        else -> value
    }

    private fun errorToObject(error: AgentError): JSONObject = JSONObject()
        .put("code", error.code.name)
        .put("userMessage", error.userMessage)
        .put("retryable", error.retryable)
        .put("details", mapToJsonObject(error.details))

    private fun errorFromObject(json: JSONObject): AgentError = AgentError(
        code = enumValue(
            raw = json.optionalString("code"),
            fallback = AgentErrorCode.INTERNAL_ERROR
        ),
        userMessage = json.string("userMessage"),
        retryable = json.boolean("retryable", false),
        details = json.optionalObject("details")?.let(::jsonObjectToMap).orEmpty()
    )

    private fun stringsToArray(values: List<String>): JSONArray = JSONArray().apply {
        values.forEach(::put)
    }

    private fun mapToJsonObject(values: AgentJsonObject): JSONObject = JSONObject().apply {
        values.forEach { (key, value) -> put(key, toJsonValue(value)) }
    }

    private fun toJsonValue(value: Any?): Any = when (value) {
        null -> JSONObject.NULL
        JSONObject.NULL -> JSONObject.NULL
        is JSONObject, is JSONArray, is String, is Number, is Boolean -> value
        is Enum<*> -> value.name
        is Map<*, *> -> JSONObject().apply {
            value.forEach { (key, nestedValue) ->
                if (key !is String) throw AgentJsonContractException()
                put(key, toJsonValue(nestedValue))
            }
        }
        is Iterable<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        is Array<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        is BooleanArray -> JSONArray().apply { value.forEach { put(it) } }
        is ByteArray -> JSONArray().apply { value.forEach { put(it.toInt()) } }
        is ShortArray -> JSONArray().apply { value.forEach { put(it.toInt()) } }
        is IntArray -> JSONArray().apply { value.forEach { put(it) } }
        is LongArray -> JSONArray().apply { value.forEach { put(it) } }
        is FloatArray -> JSONArray().apply { value.forEach { put(it.toDouble()) } }
        is DoubleArray -> JSONArray().apply { value.forEach { put(it) } }
        else -> throw AgentJsonContractException()
    }

    private fun jsonObjectToMap(json: JSONObject): AgentJsonObject = buildMap {
        val keys = json.keys()
        while (keys.hasNext()) {
            val key = keys.next()
            put(key, fromJsonValue(json.opt(key)))
        }
    }

    private fun fromJsonValue(value: Any?): Any? = when (value) {
        null, JSONObject.NULL -> null
        is JSONObject -> jsonObjectToMap(value)
        is JSONArray -> buildList {
            for (index in 0 until value.length()) {
                add(fromJsonValue(value.opt(index)))
            }
        }
        else -> value
    }

    private inline fun <reified T : Enum<T>> enumValue(raw: String?, fallback: T): T {
        if (raw == null) return fallback
        val normalized = normalizeEnumName(raw)
        return enumValues<T>().firstOrNull { normalizeEnumName(it.name) == normalized } ?: fallback
    }

    private fun normalizeEnumName(value: String): String = value
        .filter(Char::isLetterOrDigit)
        .lowercase(Locale.ROOT)

    private fun JSONObject.putOptional(key: String, value: Any?): JSONObject = apply {
        if (value != null) put(key, value)
    }

    private fun JSONObject.optionalObject(key: String): JSONObject? =
        if (has(key) && !isNull(key)) opt(key) as? JSONObject else null

    private fun JSONObject.optionalList(key: String): List<Any?> {
        val array = (if (has(key) && !isNull(key)) opt(key) as? JSONArray else null)
            ?: return emptyList()
        return buildList(array.length()) {
            for (index in 0 until array.length()) add(fromJsonValue(array.opt(index)))
        }
    }

    private fun JSONObject.optionalString(key: String): String? {
        if (!has(key) || isNull(key)) return null
        return opt(key) as? String
    }

    private fun JSONObject.string(key: String, default: String = ""): String =
        optionalString(key) ?: default

    private fun JSONObject.optionalLong(key: String): Long? {
        if (!has(key) || isNull(key)) return null
        return when (val value = opt(key)) {
            is Number -> value.toLong()
            is String -> value.toLongOrNull()
            else -> null
        }
    }

    private fun JSONObject.optionalInt(key: String): Int? =
        optionalLong(key)?.takeIf { it in Int.MIN_VALUE.toLong()..Int.MAX_VALUE.toLong() }?.toInt()

    private fun JSONObject.long(key: String, default: Long = 0L): Long =
        optionalLong(key) ?: default

    private fun JSONObject.boolean(key: String, default: Boolean): Boolean {
        if (!has(key) || isNull(key)) return default
        return when (val value = opt(key)) {
            is Boolean -> value
            is String -> value.toBooleanStrictOrNull() ?: default
            else -> default
        }
    }

    private fun JSONObject.stringList(key: String): List<String> {
        val array = if (has(key) && !isNull(key)) opt(key) as? JSONArray else null
        if (array == null) return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                (array.opt(index) as? String)?.let(::add)
            }
        }
    }

    private inline fun <T> JSONObject.objectList(
        key: String,
        convert: (JSONObject) -> T
    ): List<T> {
        val array = if (has(key) && !isNull(key)) opt(key) as? JSONArray else null
        if (array == null) return emptyList()
        return buildList {
            for (index in 0 until array.length()) {
                (array.opt(index) as? JSONObject)?.let { add(convert(it)) }
            }
        }
    }

    private class AgentJsonContractException : IllegalArgumentException()
}

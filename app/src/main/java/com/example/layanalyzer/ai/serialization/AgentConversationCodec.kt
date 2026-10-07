package com.example.layanalyzer.ai.serialization

import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentAnalysisPlanStep
import com.example.layanalyzer.model.AgentConversationItem
import com.example.layanalyzer.model.AgentConversationRole
import com.example.layanalyzer.model.AgentConversationRound
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentModelInteraction
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentPrivacyMode
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentToolActivity
import com.example.layanalyzer.model.AgentToolActivityStatus
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolDefinition
import com.example.layanalyzer.model.AgentTokenUsage
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AnalysisScope
import org.json.JSONArray
import org.json.JSONObject
import java.util.Locale

/**
 * JSON for the parts of a live Agent session that a saved session replays.
 *
 * [AgentJsonCodec] owns the report and tool-result wire formats, which are
 * contracts shared with the model boundary.  This codec is for local storage
 * only: it exists so that reopening a saved analysis restores the conversation
 * the user left rather than a summary of it.  It therefore records things the
 * model-facing codec deliberately omits — tool arguments, vendor reasoning,
 * full request message lists — and it is never sent anywhere.
 *
 * Decoding is total: an unreadable item is dropped rather than failing the
 * session around it, because a transcript that is missing one row is far more
 * useful than a saved analysis that will not open at all.
 */
internal object AgentConversationCodec {

    // ------------------------------------------------------------- transcript

    fun conversationToArray(items: List<AgentConversationItem>): JSONArray =
        JSONArray().apply { items.forEach { put(conversationItemToObject(it)) } }

    fun conversationFromArray(array: JSONArray?): List<AgentConversationItem> =
        array.mapObjects { conversationItemFromObject(it) }

    private fun conversationItemToObject(item: AgentConversationItem): JSONObject = JSONObject()
        .put("id", item.id)
        .put("role", item.role.name)
        .put("content", item.content)
        .put("createdAtMillis", item.createdAtMillis)
        .putOptional("toolCallId", item.toolCallId)
        .putOptional("toolName", item.toolName)
        .put("untrustedCaptureData", item.untrustedCaptureData)
        .putOptional("error", item.error?.let(::errorToObject))
        // The per-turn report round-trips through the shared codec so a restored
        // turn renders with exactly the findings the live one showed.
        .putOptional("report", item.report?.let { JSONObject(AgentJsonCodec.encodeReport(it)) })

    private fun conversationItemFromObject(json: JSONObject): AgentConversationItem =
        AgentConversationItem(
            id = json.string("id"),
            role = enumValue(json.optionalString("role"), AgentConversationRole.Unknown),
            content = json.string("content"),
            createdAtMillis = json.long("createdAtMillis"),
            toolCallId = json.optionalString("toolCallId"),
            toolName = json.optionalString("toolName"),
            untrustedCaptureData = json.boolean("untrustedCaptureData", false),
            error = json.optionalObject("error")?.let(::errorFromObject),
            report = json.optionalObject("report")?.let { reportJson ->
                AgentJsonCodec.decodeReport(reportJson.toString()).getOrNull()
            }
        )

    // ------------------------------------------------------- model exchanges

    fun interactionsToArray(interactions: List<AgentModelInteraction>): JSONArray =
        JSONArray().apply { interactions.forEach { put(interactionToObject(it)) } }

    fun interactionsFromArray(array: JSONArray?): List<AgentModelInteraction> =
        array.mapObjects { interactionFromObject(it) }

    private fun interactionToObject(interaction: AgentModelInteraction): JSONObject = JSONObject()
        .put("id", interaction.id)
        .putOptional("turn", interaction.turn)
        .put("attempt", interaction.attempt)
        .put("startedAtMillis", interaction.startedAtMillis)
        .putOptional("firstTokenAtMillis", interaction.firstTokenAtMillis)
        .put("completedAtMillis", interaction.completedAtMillis)
        .put("request", requestToObject(interaction.request))
        .put("response", responseToObject(interaction.response))

    /**
     * Rebuild one exchange.  An interaction whose request cannot be read is
     * dropped by the caller, since a response with no request is not something
     * the detail view can render.
     */
    private fun interactionFromObject(json: JSONObject): AgentModelInteraction? {
        val request = json.optionalObject("request")?.let(::requestFromObject) ?: return null
        return AgentModelInteraction(
            id = json.string("id"),
            turn = json.optionalInt("turn"),
            attempt = json.optionalInt("attempt") ?: 1,
            request = request,
            response = json.optionalObject("response")?.let(::responseFromObject)
                ?: AgentModelResponse.Failure(
                    AgentError(
                        code = AgentErrorCode.INTERNAL_ERROR,
                        userMessage = "This response could not be read from the saved session."
                    )
                ),
            startedAtMillis = json.long("startedAtMillis"),
            firstTokenAtMillis = json.optionalLong("firstTokenAtMillis"),
            completedAtMillis = json.long("completedAtMillis")
        )
    }

    // -------------------------------------------------------- model messages

    fun messagesToArray(messages: List<AgentModelMessage>): JSONArray =
        JSONArray().apply { messages.forEach { put(messageToObject(it)) } }

    fun messagesFromArray(array: JSONArray?): List<AgentModelMessage> =
        array.mapObjects { messageFromObject(it) }

    private fun requestToObject(request: AgentModelRequest): JSONObject = JSONObject()
        .put("requestId", request.requestId)
        .put("timeoutMillis", request.timeoutMillis)
        .put("maxOutputTokens", request.maxOutputTokens)
        .put("privacyMode", request.privacyMode.name)
        .put("messages", JSONArray().apply {
            request.messages.forEach { message ->
                // Message-level cache breakpoints are a transient rendering
                // decision. Persisting them would feed an old rolling layout
                // back into a resumed session; only the stable System hint is
                // part of the saved request trace.
                val persisted = if (
                    message.role == AgentModelMessageRole.System ||
                    message.cacheControl == null
                ) {
                    message
                } else {
                    message.copy(cacheControl = null)
                }
                put(messageToObject(persisted))
            }
        })
        .put("toolDefinitions", JSONArray().apply {
            request.toolDefinitions.forEach { put(toolDefinitionToObject(it)) }
        })
        .putOptional("responseSchema", request.responseSchema?.let(::mapToJsonObject))

    private fun requestFromObject(json: JSONObject): AgentModelRequest = AgentModelRequest(
        requestId = json.string("requestId"),
        messages = json.optJSONArray("messages").mapObjects { messageFromObject(it) },
        toolDefinitions = json.optJSONArray("toolDefinitions")
            .mapObjects { toolDefinitionFromObject(it) },
        responseSchema = json.optionalObject("responseSchema")?.let(::jsonObjectToMap),
        timeoutMillis = json.optionalLong("timeoutMillis") ?: 120_000L,
        maxOutputTokens = json.optionalInt("maxOutputTokens") ?: 0,
        privacyMode = enumValue(json.optionalString("privacyMode"), AgentPrivacyMode.Unknown)
    )

    private fun messageToObject(message: AgentModelMessage): JSONObject = JSONObject()
        .put("role", message.role.name)
        .put("content", message.content)
        .putOptional("toolCallId", message.toolCallId)
        .putOptional("toolName", message.toolName)
        .put("untrustedCaptureData", message.untrustedCaptureData)
        .putOptional("reasoningContent", message.reasoningContent)
        .putOptional("cacheControlType", message.cacheControl?.type)
        .putOptional("structuredContent", message.structuredContent?.let(::mapToJsonObject))
        .putOptional(
            "toolResult",
            message.toolResult?.let { JSONObject(AgentJsonCodec.encodeToolResult(it)) }
        )
        .put("toolCalls", JSONArray().apply {
            message.toolCalls.forEach { put(toolCallToObject(it)) }
        })

    private fun messageFromObject(json: JSONObject): AgentModelMessage = AgentModelMessage(
        role = enumValue(json.optionalString("role"), AgentModelMessageRole.Unknown),
        content = json.string("content"),
        toolCallId = json.optionalString("toolCallId"),
        toolName = json.optionalString("toolName"),
        toolCalls = json.optJSONArray("toolCalls").mapObjects { toolCallFromObject(it) },
        untrustedCaptureData = json.boolean("untrustedCaptureData", false),
        structuredContent = json.optionalObject("structuredContent")?.let(::jsonObjectToMap),
        toolResult = json.optionalObject("toolResult")?.let { result ->
            AgentJsonCodec.decodeToolResult(result.toString()).getOrNull()
        },
        // CacheControl's constructor rejects any type but "ephemeral", so an
        // unexpected stored value becomes "no hint" rather than an exception
        // that would take the whole saved session down with it.
        cacheControl = json.optionalString("cacheControlType")
            ?.let { type -> runCatching { com.example.layanalyzer.model.CacheControl(type) }.getOrNull() },
        reasoningContent = json.optionalString("reasoningContent")
    )

    private fun toolCallToObject(call: AgentToolCall): JSONObject = JSONObject()
        .put("toolCallId", call.toolCallId)
        .put("toolName", call.toolName)
        .put("arguments", mapToJsonObject(call.arguments))
        .putOptional("responseItemId", call.responseItemId)

    private fun toolCallFromObject(json: JSONObject): AgentToolCall = AgentToolCall(
        toolCallId = json.string("toolCallId"),
        toolName = json.string("toolName"),
        arguments = json.optionalObject("arguments")?.let(::jsonObjectToMap).orEmpty(),
        responseItemId = json.optionalString("responseItemId")
    )

    private fun toolDefinitionToObject(definition: AgentToolDefinition): JSONObject = JSONObject()
        .put("name", definition.name)
        .put("description", definition.description)
        .put("inputSchema", mapToJsonObject(definition.inputSchema))
        .put("sensitivity", definition.sensitivity.name)
        .put("defaultTimeoutMillis", definition.defaultTimeoutMillis)
        .put("version", definition.version)

    private fun toolDefinitionFromObject(json: JSONObject): AgentToolDefinition =
        AgentToolDefinition(
            name = json.string("name"),
            description = json.string("description"),
            inputSchema = json.optionalObject("inputSchema")?.let(::jsonObjectToMap).orEmpty(),
            sensitivity = enumValue(
                json.optionalString("sensitivity"),
                AgentDataSensitivity.Metadata
            ),
            defaultTimeoutMillis = json.optionalLong("defaultTimeoutMillis") ?: 30_000L,
            version = json.optionalString("version") ?: "1"
        )

    /**
     * Responses are a sealed hierarchy, so the branch is stored explicitly.  An
     * unrecognised or missing type decodes as a Failure rather than guessing,
     * which keeps the detail view honest about what could not be read back.
     */
    private fun responseToObject(response: AgentModelResponse): JSONObject {
        val json = JSONObject().putOptional("usage", response.usage?.let(::usageToObject))
        return when (response) {
            is AgentModelResponse.ToolCalls -> json
                .put("type", TYPE_TOOL_CALLS)
                .put("assistantContent", response.assistantContent)
                .putOptional("reasoningContent", response.reasoningContent)
                .put("calls", JSONArray().apply {
                    response.calls.forEach { put(toolCallToObject(it)) }
                })

            is AgentModelResponse.Final -> json
                .put("type", TYPE_FINAL)
                .putOptional("report", response.report?.let {
                    JSONObject(AgentJsonCodec.encodeReport(it))
                })
                .putOptional("reportJson", response.reportJson)
                .putOptional("json", response.json)
                .putOptional("reasoningContent", response.reasoningContent)

            is AgentModelResponse.Refusal -> json
                .put("type", TYPE_REFUSAL)
                .put("reason", response.reason)
                .putOptional("error", response.error?.let(::errorToObject))

            is AgentModelResponse.Failure -> json
                .put("type", TYPE_FAILURE)
                .put("error", errorToObject(response.error))
        }
    }

    private fun responseFromObject(json: JSONObject): AgentModelResponse {
        val usage = json.optionalObject("usage")?.let(::usageFromObject)
        return when (json.optionalString("type")) {
            TYPE_TOOL_CALLS -> AgentModelResponse.ToolCalls(
                calls = json.optJSONArray("calls").mapObjects { toolCallFromObject(it) },
                usage = usage,
                assistantContent = json.string("assistantContent"),
                reasoningContent = json.optionalString("reasoningContent")
            )

            TYPE_FINAL -> AgentModelResponse.Final(
                report = json.optionalObject("report")?.let { report ->
                    AgentJsonCodec.decodeReport(report.toString()).getOrNull()
                },
                reportJson = json.optionalString("reportJson"),
                json = json.optionalString("json"),
                usage = usage,
                reasoningContent = json.optionalString("reasoningContent")
            )

            TYPE_REFUSAL -> AgentModelResponse.Refusal(
                reason = json.string("reason"),
                error = json.optionalObject("error")?.let(::errorFromObject),
                usage = usage
            )

            else -> AgentModelResponse.Failure(
                error = json.optionalObject("error")?.let(::errorFromObject)
                    ?: AgentError(
                        code = AgentErrorCode.INTERNAL_ERROR,
                        userMessage = "This response could not be read from the saved session."
                    ),
                usage = usage
            )
        }
    }

    // --------------------------------------------------- activities and plan

    fun activitiesToArray(activities: List<AgentToolActivity>): JSONArray =
        JSONArray().apply { activities.forEach { put(activityToObject(it)) } }

    fun activitiesFromArray(array: JSONArray?): List<AgentToolActivity> =
        array.mapObjects { activityFromObject(it) }

    private fun activityToObject(activity: AgentToolActivity): JSONObject = JSONObject()
        .put("toolCallId", activity.toolCallId)
        .put("toolName", activity.toolName)
        .put("status", activity.status.name)
        .put("argumentsSummary", activity.argumentsSummary)
        .put("startedAtMillis", activity.startedAtMillis)
        .putOptional("completedAtMillis", activity.completedAtMillis)
        .put("returnedCount", activity.returnedCount)
        .put("totalCount", activity.totalCount)
        .put("truncated", activity.truncated)
        .put("resultBytes", activity.resultBytes)
        .put("scope", activity.scope.name)
        .putOptional("queryMode", activity.queryMode)
        .put("sampled", activity.sampled)
        .putOptional("error", activity.error?.let(::errorToObject))

    private fun activityFromObject(json: JSONObject): AgentToolActivity = AgentToolActivity(
        toolCallId = json.string("toolCallId"),
        toolName = json.string("toolName"),
        status = enumValue(json.optionalString("status"), AgentToolActivityStatus.Queued),
        argumentsSummary = json.string("argumentsSummary"),
        startedAtMillis = json.long("startedAtMillis"),
        completedAtMillis = json.optionalLong("completedAtMillis"),
        returnedCount = json.long("returnedCount"),
        totalCount = json.long("totalCount"),
        truncated = json.boolean("truncated", false),
        resultBytes = json.optionalInt("resultBytes") ?: 0,
        scope = enumValue(json.optionalString("scope"), AnalysisScope.CompleteFile),
        queryMode = json.optionalString("queryMode"),
        sampled = json.boolean("sampled", false),
        error = json.optionalObject("error")?.let(::errorFromObject)
    )

    fun planToObject(plan: AgentAnalysisPlan): JSONObject = JSONObject()
        .put("goal", plan.goal)
        .put("steps", JSONArray().apply {
            plan.steps.forEach { step ->
                put(
                    JSONObject().put("tool", step.tool).put("purpose", step.purpose).apply {
                        // Omitted for legacy steps so stored plans keep the
                        // exact pre-OPT-VAL-01-02 byte shape.
                        if (step.checkId.isNotBlank()) put("checkId", step.checkId)
                    }
                )
            }
        })

    fun planFromObject(json: JSONObject): AgentAnalysisPlan = AgentAnalysisPlan(
        goal = json.string("goal"),
        steps = json.optJSONArray("steps").mapObjects { step ->
            AgentAnalysisPlanStep(
                tool = step.string("tool"),
                purpose = step.string("purpose"),
                checkId = step.optionalString("checkId").orEmpty()
            )
        }
    )

    fun usageToObject(usage: AgentTokenUsage): JSONObject = JSONObject()
        .put("inputTokens", usage.inputTokens)
        .put("outputTokens", usage.outputTokens)
        .put("cachedInputTokens", usage.cachedInputTokens)
        .put("cacheCreationTokens", usage.cacheCreationTokens)

    fun usageFromObject(json: JSONObject): AgentTokenUsage = AgentTokenUsage(
        inputTokens = json.optionalInt("inputTokens") ?: 0,
        outputTokens = json.optionalInt("outputTokens") ?: 0,
        cachedInputTokens = json.optionalInt("cachedInputTokens") ?: 0,
        cacheCreationTokens = json.optionalInt("cacheCreationTokens") ?: 0
    )

    // ------------------------------------------------------ conversation rounds

    fun roundsToArray(rounds: List<AgentConversationRound>): JSONArray =
        JSONArray().apply { rounds.forEach { put(roundToObject(it)) } }

    fun roundsFromArray(array: JSONArray?): List<AgentConversationRound> =
        array.mapObjects { roundFromObject(it) }

    private fun roundToObject(round: AgentConversationRound): JSONObject = JSONObject()
        .put("question", round.question)
        .put("report", JSONObject(AgentJsonCodec.encodeReport(round.report)))
        .put("completedAtMillis", round.completedAtMillis)

    private fun roundFromObject(json: JSONObject): AgentConversationRound = AgentConversationRound(
        question = json.string("question"),
        report = json.optionalObject("report")?.let { reportJson ->
            AgentJsonCodec.decodeReport(reportJson.toString()).getOrNull()
        } ?: AgentReport(),
        completedAtMillis = json.long("completedAtMillis")
    )

    // ---------------------------------------------------------------- shared

    private fun errorToObject(error: AgentError): JSONObject = JSONObject()
        .put("code", error.code.name)
        .put("userMessage", error.userMessage)
        .put("retryable", error.retryable)
        .put("details", mapToJsonObject(error.details))

    private fun errorFromObject(json: JSONObject): AgentError = AgentError(
        code = enumValue(json.optionalString("code"), AgentErrorCode.INTERNAL_ERROR),
        userMessage = json.string("userMessage"),
        retryable = json.boolean("retryable", false),
        details = json.optionalObject("details")?.let(::jsonObjectToMap).orEmpty()
    )

    private fun mapToJsonObject(values: AgentJsonObject): JSONObject = JSONObject().apply {
        values.forEach { (key, value) -> put(key, toJsonValue(value)) }
    }

    /**
     * Local storage is not a wire contract, so a value this does not recognise
     * becomes its string form instead of throwing.  Losing the type of one odd
     * field is a better outcome than refusing to save the analysis.
     */
    private fun toJsonValue(value: Any?): Any = when (value) {
        null, JSONObject.NULL -> JSONObject.NULL
        is JSONObject, is JSONArray, is String, is Number, is Boolean -> value
        is Enum<*> -> value.name
        is Map<*, *> -> JSONObject().apply {
            value.forEach { (key, nested) -> put(key.toString(), toJsonValue(nested)) }
        }
        is Iterable<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        is Array<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        is ByteArray -> JSONArray().apply { value.forEach { put(it.toInt()) } }
        is IntArray -> JSONArray().apply { value.forEach { put(it) } }
        is LongArray -> JSONArray().apply { value.forEach { put(it) } }
        is DoubleArray -> JSONArray().apply { value.forEach { put(it) } }
        is BooleanArray -> JSONArray().apply { value.forEach { put(it) } }
        else -> value.toString()
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
            for (index in 0 until value.length()) add(fromJsonValue(value.opt(index)))
        }
        else -> value
    }

    /**
     * Decode every object in [this], dropping the ones that fail.
     *
     * Restoring is best-effort by design: one malformed message must not cost
     * the user the rest of the conversation.
     */
    private fun <T : Any> JSONArray?.mapObjects(transform: (JSONObject) -> T?): List<T> {
        val array = this ?: return emptyList()
        return (0 until array.length()).mapNotNull { index ->
            val item = array.optJSONObject(index) ?: return@mapNotNull null
            runCatching { transform(item) }.getOrNull()
        }
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

    private const val TYPE_TOOL_CALLS = "toolCalls"
    private const val TYPE_FINAL = "final"
    private const val TYPE_REFUSAL = "refusal"
    private const val TYPE_FAILURE = "failure"
}

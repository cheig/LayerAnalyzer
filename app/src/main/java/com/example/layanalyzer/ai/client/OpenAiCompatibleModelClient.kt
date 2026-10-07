package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.agent.AgentChatResponseFormat
import com.example.layanalyzer.ai.agent.AgentReasoningEffort
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolDefinition
import java.util.Locale
import org.json.JSONArray
import org.json.JSONObject

/**
 * Direct BYOK adapter for OpenAI-compatible Chat Completions APIs.
 *
 * This is deliberately separate from [CloudAiModelClient], whose wire contract
 * is LayerAnalyzer's normalized `/v1/agent/respond` gateway. Provider-specific
 * request and response fields stay inside this adapter.
 */
class OpenAiCompatibleModelClient(
    apiBaseUrl: String,
    transport: AgentHttpTransport,
    providerId: String,
    modelId: String,
    apiKeyProvider: () -> String?,
    override val capabilities: AiModelCapabilities = AiModelCapabilities.OPENAI_COMPATIBLE_DEFAULT,
    private val responseFormat: AgentChatResponseFormat = AgentChatResponseFormat.PROMPT_ONLY,
    private val reasoningEffort: AgentReasoningEffort = AgentReasoningEffort.UNSPECIFIED,
    private val allowInsecureHttpForTests: Boolean = false
) : DirectApiModelClient(
    apiBaseUrl = apiBaseUrl,
    transport = transport,
    providerId = providerId,
    modelId = modelId,
    apiKeyProvider = apiKeyProvider,
    capabilities = capabilities,
    allowInsecureHttpForTests = allowInsecureHttpForTests
) {

    override val id: String = "openai-compatible:$providerId:$modelId"

    override fun requestUrl(): String = chatCompletionsUrl()

    override fun requestHeaders(apiKey: String): Map<String, String> = mapOf(
        "Accept" to "application/json",
        "Authorization" to "Bearer $apiKey"
    )

    /** Visible for contract tests; never includes the API key. */
    override fun encodeRequest(request: AgentModelRequest): String = JSONObject().apply {
        put("model", modelId)
        put("messages", messagesToJson(request.messages, request.responseSchema))
        val hasTools = request.toolDefinitions.isNotEmpty()
        if (hasTools) {
            put("tools", toolsToJson(request.toolDefinitions))
            put("tool_choice", "auto")
            put("parallel_tool_calls", capabilities.parallelToolCalls)
        }
        // `tools` and `response_format` express two different contracts for one
        // response, and OpenAI-compatible gateways disagree on what happens when
        // both are present — some reject the request, others silently drop the
        // schema. Since the final report now travels the tool channel, a request
        // that carries tools never needs response_format, so the two are simply
        // never sent together.
        if (!hasTools) {
            request.responseSchema?.let { schema ->
                when (responseFormat) {
                    AgentChatResponseFormat.PROMPT_ONLY -> Unit
                    AgentChatResponseFormat.JSON_OBJECT -> put(
                        "response_format",
                        JSONObject().put("type", "json_object")
                    )
                    AgentChatResponseFormat.JSON_SCHEMA -> put(
                        "response_format",
                        JSONObject()
                            .put("type", "json_schema")
                            .put(
                                "json_schema",
                                JSONObject()
                                    .put("name", "agent_response")
                                    .put("strict", true)
                                    .put("schema", toJsonValue(schema))
                            )
                    )
                }
            }
        }
        capabilities.clampOutputTokens(request.maxOutputTokens)
            .takeIf { it > 0 }
            ?.let { put("max_tokens", it) }
        reasoningEffort.applyToChatCompletions(this)
    }.toString()

    override fun parseResponse(body: String): AgentModelResponse {
        val root = runCatching { JSONObject(body) }.getOrNull()
            ?: return AgentModelResponse.Failure(AiModelErrors.malformed("malformed_json"))
        val usage = AgentTokenUsageParser.openAiChat(root)
        root.optJSONObject("error")?.let {
            return AgentModelResponse.Failure(mapProviderError(it), usage)
        }

        val choice = root.optJSONArray("choices")?.optJSONObject(0)
            ?: return AgentModelResponse.Failure(AiModelErrors.malformed("missing_choice"), usage)
        val message = choice.optJSONObject("message")
            ?: return AgentModelResponse.Failure(AiModelErrors.malformed("missing_message"), usage)

        val refusal = message.optString("refusal").takeIf { it.isNotBlank() }
        val finishReason = choice.optString("finish_reason")
        if (refusal != null || finishReason.equals("content_filter", ignoreCase = true)) {
            return AgentModelResponse.Refusal(
                reason = "provider_refusal",
                error = AgentError(
                    code = AgentErrorCode.MODEL_UNAVAILABLE,
                    userMessage = "The analysis model declined to answer.",
                    retryable = false,
                    details = mapOf("reason" to "provider_refusal")
                ),
                usage = usage
            )
        }

        val content = messageContent(message.opt("content"))
        val reasoningContent = message.optStringValue("reasoning_content")
        val toolCalls = parseToolCalls(message.optJSONArray("tool_calls"))
        if (finishReason.equals("length", ignoreCase = true)) {
            val target = if (message.optJSONArray("tool_calls")?.length()?.let { it > 0 } == true) {
                AgentTruncationTarget.ToolCalls
            } else {
                AgentTruncationTarget.FinalReport
            }
            return AgentModelResponse.Failure(
                outputTruncatedError(target = target, finishReason = finishReason),
                usage
            )
        }
        if (toolCalls.isNotEmpty()) {
            return AgentModelResponse.ToolCalls(
                calls = toolCalls,
                usage = usage,
                assistantContent = content,
                reasoningContent = reasoningContent
            )
        }

        // A report cut off at the output ceiling is not a malformed model, and
        // reporting it as "unavailable" sends the user to retry a call that will
        // fail identically. Name the real cause instead.
        val decoded = decodeFinalReportContent(content, finishReason)
        decoded.error?.let { return AgentModelResponse.Failure(it, usage) }
        return AgentModelResponse.Final(
            report = requireNotNull(decoded.report),
            usage = usage,
            reasoningContent = reasoningContent
        )
    }

    override fun encodeStreamingRequest(request: AgentModelRequest): String =
        JSONObject(encodeRequest(request))
            .put("stream", true)
            .put("stream_options", JSONObject().put("include_usage", true))
            .toString()

    override fun createStreamDecoder(): ModelStreamDecoder = ChatStreamDecoder()

    private inner class ChatStreamDecoder : ModelStreamDecoder {
        private val text = StringBuilder()
        private val reasoning = StringBuilder()
        private var reasoningSeen = false
        private val tools = linkedMapOf<Int, StreamingToolCall>()
        private var finishReason: String? = null
        private var usage: JSONObject? = null
        private var terminal: AgentModelResponse? = null

        override suspend fun accept(data: String, onChunk: suspend (StreamChunk) -> Unit) {
            val root = runCatching { JSONObject(data) }.getOrNull() ?: return
            root.optJSONObject("error")?.let { error ->
                terminal = AgentModelResponse.Failure(mapProviderError(error))
                return
            }
            val eventUsage = root.optJSONObject("usage")
            if (eventUsage != null) usage = eventUsage
            val choice = root.optJSONArray("choices")?.optJSONObject(0) ?: return
            val eventFinishReason = choice.optString("finish_reason")
            if (eventFinishReason.isNotBlank()) finishReason = eventFinishReason
            val delta = choice.optJSONObject("delta") ?: return
            delta.optStringValue("reasoning_content")?.let {
                reasoningSeen = true
                reasoning.append(it)
            }
            val textDelta = messageContent(delta.opt("content"))
            if (textDelta.isNotEmpty()) {
                text.append(textDelta)
                onChunk(StreamChunk.TextDelta(textDelta))
            }
            if (delta.optString("refusal").isNotBlank()) finishReason = "content_filter"
            val calls = delta.optJSONArray("tool_calls") ?: return
            for (position in 0 until calls.length()) {
                val item = calls.optJSONObject(position) ?: continue
                val index = item.optInt("index", position)
                val state = tools.getOrPut(index) { StreamingToolCall() }
                val itemId = item.optString("id")
                if (itemId.isNotBlank()) state.id = itemId
                val function = item.optJSONObject("function")
                val nameDelta = function?.optString("name").orEmpty()
                if (nameDelta.isNotEmpty()) state.name.append(nameDelta)
                if (!state.started && state.id.isNotBlank() && state.name.isNotEmpty()) {
                    state.started = true
                    onChunk(StreamChunk.ToolCallStart(index, state.id, state.name.toString()))
                }
                val arguments = function?.optString("arguments").orEmpty()
                if (arguments.isNotEmpty()) {
                    state.arguments.append(arguments)
                    val toolCallId = state.id.takeIf { it.isNotBlank() }
                    onChunk(StreamChunk.ToolCallArgumentDelta(index, toolCallId, arguments))
                }
            }
        }

        override fun finish(): AgentModelResponse {
            terminal?.let { return it }
            if (finishReason.equals("length", ignoreCase = true)) {
                val target = if (tools.isNotEmpty()) {
                    AgentTruncationTarget.ToolCalls
                } else {
                    AgentTruncationTarget.FinalReport
                }
                return AgentModelResponse.Failure(
                    outputTruncatedError(target = target, finishReason = finishReason ?: "length"),
                    null
                )
            }
            val message = JSONObject().put("content", text.toString())
            if (reasoningSeen) {
                message.put("reasoning_content", reasoning.toString())
            }
            if (tools.isNotEmpty()) {
                message.put("tool_calls", JSONArray().apply {
                    tools.toSortedMap().values.forEach { call ->
                        put(
                            JSONObject()
                                .put("id", call.id)
                                .put("type", "function")
                                .put(
                                    "function",
                                    JSONObject()
                                        .put("name", call.name.toString())
                                        .put("arguments", call.arguments.toString().ifBlank { "{}" })
                                )
                        )
                    }
                })
            }
            val root = JSONObject().put(
                "choices",
                JSONArray().put(
                    JSONObject()
                        .put("finish_reason", finishReason ?: JSONObject.NULL)
                        .put("message", message)
                )
            )
            usage?.let { root.put("usage", it) }
            return parseResponse(root.toString())
        }
    }

    private class StreamingToolCall {
        var id: String = ""
        val name = StringBuilder()
        val arguments = StringBuilder()
        var started: Boolean = false
    }

    private fun parseToolCalls(array: JSONArray?): List<AgentToolCall> = buildList {
        if (array == null) return@buildList
        for (index in 0 until array.length()) {
            val item = array.optJSONObject(index) ?: continue
            val function = item.optJSONObject("function") ?: continue
            val id = item.optString("id")
            val name = function.optString("name")
            val argumentText = function.optString("arguments").ifBlank { "{}" }
            val arguments = runCatching { jsonObjectToMap(JSONObject(argumentText)) }.getOrNull()
            if (id.isNotBlank() && name.isNotBlank() && arguments != null) {
                add(AgentToolCall(id, name, arguments))
            }
        }
    }

    private fun messagesToJson(
        messages: List<AgentModelMessage>,
        responseSchema: AgentJsonObject?
    ): JSONArray {
        val providerToolCallIds = messages
            .filter { it.role == AgentModelMessageRole.Assistant }
            .flatMap { it.toolCalls }
            .map { it.toolCallId }
            .toSet()
        return JSONArray().apply {
            if (responseSchema != null) {
                put(JSONObject().apply {
                    put("role", "system")
                    put(
                        "content",
                        "When you have enough evidence, return only one JSON object matching this " +
                            "final report schema. Markdown is allowed inside prose strings only; " +
                            "do not wrap the JSON object in Markdown fences: ${toJsonValue(responseSchema)}"
                    )
                })
            }
            messages.forEach { message ->
                when (message.role) {
                    AgentModelMessageRole.System,
                    AgentModelMessageRole.User -> put(JSONObject().apply {
                        put("role", message.role.name.lowercase(Locale.ROOT))
                        put("content", message.content)
                    })

                    AgentModelMessageRole.Assistant -> put(JSONObject().apply {
                        put("role", "assistant")
                        put("content", message.content.ifBlank { JSONObject.NULL })
                        message.reasoningContent?.let { put("reasoning_content", it) }
                        if (message.toolCalls.isNotEmpty()) {
                            put("tool_calls", assistantToolCallsToJson(message.toolCalls))
                        }
                    })

                    AgentModelMessageRole.Tool -> {
                        val toolCallId = message.toolCallId.orEmpty()
                        put(JSONObject().apply {
                            if (toolCallId in providerToolCallIds) {
                                put("role", "tool")
                                put("tool_call_id", toolCallId)
                                put("content", toolMessageContent(message))
                            } else {
                                // Host-generated overview used by a text-only
                                // fallback has no preceding provider tool call.
                                put("role", "user")
                                put(
                                    "content",
                                    "Local analysis result (${message.toolName.orEmpty()}): " +
                                        toolMessageContent(message)
                                )
                            }
                        })
                    }

                    AgentModelMessageRole.Unknown -> Unit
                }
            }
        }
    }

    private fun toolsToJson(tools: List<AgentToolDefinition>): JSONArray = JSONArray().apply {
        tools.forEach { tool ->
            put(JSONObject().apply {
                put("type", "function")
                put("function", JSONObject().apply {
                    put("name", tool.name)
                    put("description", tool.description)
                    put("parameters", toJsonValue(tool.inputSchema))
                })
            })
        }
    }

    private fun assistantToolCallsToJson(calls: List<AgentToolCall>): JSONArray = JSONArray().apply {
        calls.forEach { call ->
            put(JSONObject().apply {
                put("id", call.toolCallId)
                put("type", "function")
                put("function", JSONObject().apply {
                    put("name", call.toolName)
                    put("arguments", toJsonValue(call.arguments).toString())
                })
            })
        }
    }

    private fun chatCompletionsUrl(): String {
        val base = apiBaseUrl.trim().trimEnd('/')
        return when {
            base.endsWith("/chat/completions") -> base
            base.endsWith("/v1") -> "$base/chat/completions"
            else -> "$base/v1/chat/completions"
        }
    }

    private fun JSONObject.optStringValue(name: String): String? =
        opt(name) as? String

}

package com.example.layanalyzer.ai.client

import com.example.layanalyzer.ai.agent.AgentReasoningEffort
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelMessageRole
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentModelResponse
import com.example.layanalyzer.model.AgentToolCall
import com.example.layanalyzer.model.AgentToolDefinition
import org.json.JSONArray
import org.json.JSONObject

/** Direct BYOK adapter for OpenAI's Responses API. */
class OpenAiResponsesModelClient(
    apiBaseUrl: String,
    transport: AgentHttpTransport,
    providerId: String,
    modelId: String,
    apiKeyProvider: () -> String?,
    override val capabilities: AiModelCapabilities = AiModelCapabilities.OPENAI_RESPONSES_DEFAULT,
    private val reasoningEffort: AgentReasoningEffort = AgentReasoningEffort.UNSPECIFIED,
    allowInsecureHttpForTests: Boolean = false
) : DirectApiModelClient(
    apiBaseUrl = apiBaseUrl,
    transport = transport,
    providerId = providerId,
    modelId = modelId,
    apiKeyProvider = apiKeyProvider,
    capabilities = capabilities,
    allowInsecureHttpForTests = allowInsecureHttpForTests
) {

    override val id: String = "openai-responses:$providerId:$modelId"

    override fun requestUrl(): String {
        val base = apiBaseUrl.trim().trimEnd('/')
        return when {
            base.endsWith("/responses") -> base
            base.endsWith("/v1") -> "$base/responses"
            else -> "$base/v1/responses"
        }
    }

    override fun requestHeaders(apiKey: String): Map<String, String> = mapOf(
        "Accept" to "application/json",
        "Authorization" to "Bearer $apiKey"
    )

    override fun encodeRequest(request: AgentModelRequest): String = JSONObject().apply {
        put("model", modelId)
        val systemInstructions = request.messages
            .filter { it.role == AgentModelMessageRole.System }
            .map { it.content.trim() }
            .filter { it.isNotBlank() }
            .joinToString("\n\n")
        if (systemInstructions.isNotBlank()) put("instructions", systemInstructions)
        put("input", messagesToInput(request.messages))
        if (request.toolDefinitions.isNotEmpty()) {
            put("tools", toolsToJson(request.toolDefinitions))
            put("tool_choice", "auto")
            put("parallel_tool_calls", capabilities.parallelToolCalls)
        }
        request.responseSchema?.let { schema ->
            put(
                "text",
                JSONObject().put(
                    "format",
                    JSONObject()
                        .put("type", "json_schema")
                        .put("name", "agent_report")
                        .put("strict", true)
                        .put("schema", toJsonValue(schema))
                )
            )
        }
        capabilities.clampOutputTokens(request.maxOutputTokens)
            .takeIf { it > 0 }
            ?.let { put("max_output_tokens", it) }
        reasoningEffort.applyToResponses(this)
        // The capture may contain credentials or sensitive identifiers. Do not
        // leave the transcript stored by the provider after this request.
        put("store", false)
    }.toString()

    override fun parseResponse(body: String): AgentModelResponse {
        val root = runCatching { JSONObject(body) }.getOrNull()
            ?: return AgentModelResponse.Failure(AiModelErrors.malformed("malformed_json"))
        val usage = AgentTokenUsageParser.openAiResponses(root)
        root.optJSONObject("error")?.let {
            return AgentModelResponse.Failure(mapProviderError(it), usage)
        }

        val output = root.optJSONArray("output")
            ?: return AgentModelResponse.Failure(AiModelErrors.malformed("missing_output"), usage)
        val toolCalls = parseToolCalls(output)
        if (toolCalls.isNotEmpty()) return AgentModelResponse.ToolCalls(toolCalls, usage)

        if (hasRefusal(output)) {
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

        val incompleteReason = root.optJSONObject("incomplete_details")?.optString("reason")
        if (root.optString("status").equals("incomplete", ignoreCase = true) &&
            incompleteReason.equals("max_output_tokens", ignoreCase = true)
        ) {
            return AgentModelResponse.Failure(outputTruncatedError(), usage)
        }

        val content = outputText(output).ifBlank { root.optString("output_text") }
        val providerFinishReason = incompleteReason?.takeIf { it.isNotBlank() }
            ?: root.optString("status")
        val decoded = decodeFinalReportContent(content, providerFinishReason)
        decoded.error?.let { return AgentModelResponse.Failure(it, usage) }
        return AgentModelResponse.Final(report = requireNotNull(decoded.report), usage = usage)
    }

    override fun createStreamDecoder(): ModelStreamDecoder = ResponsesStreamDecoder()

    private inner class ResponsesStreamDecoder : ModelStreamDecoder {
        private val text = StringBuilder()
        private val tools = linkedMapOf<Int, ResponsesToolCall>()
        private var completedResponse: JSONObject? = null
        private var terminal: AgentModelResponse? = null

        override suspend fun accept(data: String, onChunk: suspend (StreamChunk) -> Unit) {
            val event = runCatching { JSONObject(data) }.getOrNull() ?: return
            when (event.optString("type")) {
                "error", "response.failed" -> {
                    val error = event.optJSONObject("error")
                        ?: event.optJSONObject("response")?.optJSONObject("error")
                    terminal = AgentModelResponse.Failure(
                        error?.let(::mapProviderError) ?: AiModelErrors.unavailable("stream_error")
                    )
                }
                "response.output_text.delta" -> {
                    val value = event.optString("delta")
                    if (value.isNotEmpty()) {
                        text.append(value)
                        onChunk(StreamChunk.TextDelta(value))
                    }
                }
                "response.output_item.added" -> {
                    val item = event.optJSONObject("item") ?: return
                    if (item.optString("type") != "function_call") return
                    val index = event.optInt("output_index", tools.size)
                    val state = tools.getOrPut(index) { ResponsesToolCall() }
                    state.id = item.optString("call_id").ifBlank { item.optString("id") }
                    state.itemId = item.optString("id")
                    state.name = item.optString("name")
                    if (!state.started && state.id.isNotBlank() && state.name.isNotBlank()) {
                        state.started = true
                        onChunk(StreamChunk.ToolCallStart(index, state.id, state.name))
                    }
                }
                "response.function_call_arguments.delta" -> {
                    val index = event.optInt("output_index")
                    val state = tools.getOrPut(index) { ResponsesToolCall() }
                    val itemId = event.optString("item_id")
                    if (itemId.isNotBlank()) state.itemId = itemId
                    val value = event.optString("delta")
                    if (value.isNotEmpty()) {
                        state.arguments.append(value)
                        onChunk(
                            StreamChunk.ToolCallArgumentDelta(index, state.id.ifBlank { null }, value)
                        )
                    }
                }
                "response.completed", "response.incomplete" -> {
                    completedResponse = event.optJSONObject("response")
                }
            }
        }

        override fun finish(): AgentModelResponse {
            terminal?.let { return it }
            completedResponse?.let { return parseResponse(it.toString()) }
            val output = JSONArray()
            tools.toSortedMap().values.forEach { call ->
                output.put(
                    JSONObject()
                        .put("type", "function_call")
                        .put("id", call.itemId)
                        .put("call_id", call.id)
                        .put("name", call.name)
                        .put("arguments", call.arguments.toString().ifBlank { "{}" })
                )
            }
            if (text.isNotEmpty()) {
                output.put(
                    JSONObject()
                        .put("type", "message")
                        .put(
                            "content",
                            JSONArray().put(
                                JSONObject().put("type", "output_text").put("text", text.toString())
                            )
                        )
                )
            }
            return parseResponse(JSONObject().put("output", output).toString())
        }
    }

    private class ResponsesToolCall {
        var id: String = ""
        var itemId: String = ""
        var name: String = ""
        val arguments = StringBuilder()
        var started: Boolean = false
    }

    private fun messagesToInput(messages: List<AgentModelMessage>): JSONArray = JSONArray().apply {
        messages.forEach { message ->
            when (message.role) {
                AgentModelMessageRole.System -> Unit
                AgentModelMessageRole.User -> put(
                    JSONObject()
                        .put("type", "message")
                        .put("role", "user")
                        .put("content", JSONArray().put(textInput(message.content)))
                )
                AgentModelMessageRole.Assistant -> {
                    if (message.content.isNotBlank()) {
                        put(
                            JSONObject()
                                .put("type", "message")
                                .put("role", "assistant")
                                .put("content", JSONArray().put(outputTextInput(message.content)))
                        )
                    }
                    message.toolCalls.forEach { call ->
                        val item = JSONObject()
                            .put("type", "function_call")
                            .put("call_id", call.toolCallId)
                            .put("name", call.toolName)
                            .put("arguments", toJsonValue(call.arguments).toString())
                        call.responseItemId?.let { item.put("id", it) }
                        put(item)
                    }
                }
                AgentModelMessageRole.Tool -> put(
                    JSONObject()
                        .put("type", "function_call_output")
                        .put("call_id", message.toolCallId.orEmpty())
                        .put("output", toolMessageContent(message))
                )
                AgentModelMessageRole.Unknown -> Unit
            }
        }
    }

    private fun textInput(text: String): JSONObject = JSONObject()
        .put("type", "input_text")
        .put("text", text)

    private fun outputTextInput(text: String): JSONObject = JSONObject()
        .put("type", "output_text")
        .put("text", text)

    private fun toolsToJson(tools: List<AgentToolDefinition>): JSONArray = JSONArray().apply {
        tools.forEach { tool ->
            put(
                JSONObject()
                    .put("type", "function")
                    .put("name", tool.name)
                    .put("description", tool.description)
                    .put("parameters", toJsonValue(tool.inputSchema))
                    .put("strict", true)
            )
        }
    }

    private fun parseToolCalls(output: JSONArray): List<AgentToolCall> = buildList {
        for (index in 0 until output.length()) {
            val item = output.optJSONObject(index) ?: continue
            if (item.optString("type") != "function_call") continue
            val id = item.optString("call_id").ifBlank { item.optString("id") }
            val name = item.optString("name")
            val argumentText = item.optString("arguments").ifBlank { "{}" }
            val arguments = runCatching { jsonObjectToMap(JSONObject(argumentText)) }.getOrNull()
            if (id.isNotBlank() && name.isNotBlank() && arguments != null) {
                add(
                    AgentToolCall(
                        toolCallId = id,
                        toolName = name,
                        arguments = arguments,
                        responseItemId = item.optString("id").ifBlank { null }
                    )
                )
            }
        }
    }

    private fun outputText(output: JSONArray): String = buildString {
        for (index in 0 until output.length()) {
            val item = output.optJSONObject(index) ?: continue
            if (item.optString("type") != "message") continue
            val content = item.optJSONArray("content") ?: continue
            for (contentIndex in 0 until content.length()) {
                val part = content.optJSONObject(contentIndex) ?: continue
                if (part.optString("type") == "output_text") append(part.optString("text"))
            }
        }
    }

    private fun hasRefusal(output: JSONArray): Boolean {
        for (index in 0 until output.length()) {
            val item = output.optJSONObject(index) ?: continue
            if (item.optString("type") == "refusal") return true
            val content = item.optJSONArray("content") ?: continue
            for (contentIndex in 0 until content.length()) {
                if (content.optJSONObject(contentIndex)?.optString("type") == "refusal") return true
            }
        }
        return false
    }
}

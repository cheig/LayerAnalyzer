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

/** Direct BYOK adapter for Anthropic's Messages API. */
class AnthropicModelClient(
    apiBaseUrl: String,
    transport: AgentHttpTransport,
    providerId: String,
    modelId: String,
    apiKeyProvider: () -> String?,
    override val capabilities: AiModelCapabilities = AiModelCapabilities.ANTHROPIC_DEFAULT,
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

    override val id: String = "anthropic:$providerId:$modelId"

    override fun requestUrl(): String {
        val base = apiBaseUrl.trim().trimEnd('/')
        return when {
            base.endsWith("/messages") -> base
            base.endsWith("/v1") -> "$base/messages"
            else -> "$base/v1/messages"
        }
    }

    override fun requestHeaders(apiKey: String): Map<String, String> = mapOf(
        "Accept" to "application/json",
        "x-api-key" to apiKey,
        "anthropic-version" to ANTHROPIC_API_VERSION
    )

    override fun encodeRequest(request: AgentModelRequest): String = JSONObject().apply {
        put("model", modelId)
        val outputTokens = capabilities.clampOutputTokens(request.maxOutputTokens).coerceAtLeast(1)
        put("max_tokens", reasoningEffort.applyToAnthropic(this, outputTokens))

        val system = JSONArray()
        request.messages
            .filter { it.role == AgentModelMessageRole.System }
            .forEach { message ->
                val content = message.content.trim()
                if (content.isBlank()) return@forEach
                system.put(
                    JSONObject()
                        .put("type", "text")
                        .put("text", content)
                        .apply {
                            message.cacheControl?.let { cacheControl ->
                                put(
                                    "cache_control",
                                    JSONObject().put("type", cacheControl.type)
                                )
                            }
                        }
                )
            }
        request.responseSchema?.let { schema ->
            system.put(
                JSONObject()
                    .put("type", "text")
                    .put(
                        "text",
                        "When you have enough evidence, return only one JSON object matching this " +
                            "final report schema. Markdown is allowed inside prose strings only; " +
                            "do not wrap the JSON object in Markdown fences: ${toJsonValue(schema)}"
                    )
            )
        }
        if (system.length() > 0) put("system", system)

        put("messages", messagesToJson(request.messages))
        if (request.toolDefinitions.isNotEmpty()) {
            put("tools", toolsToJson(request.toolDefinitions))
            put("tool_choice", JSONObject().put("type", "auto"))
        }
    }.toString()

    override fun parseResponse(body: String): AgentModelResponse {
        val root = runCatching { JSONObject(body) }.getOrNull()
            ?: return AgentModelResponse.Failure(AiModelErrors.malformed("malformed_json"))
        val usage = AgentTokenUsageParser.anthropic(root)
        root.optJSONObject("error")?.let {
            return AgentModelResponse.Failure(mapProviderError(it), usage)
        }

        val content = root.optJSONArray("content")
            ?: return AgentModelResponse.Failure(AiModelErrors.malformed("missing_content"), usage)
        val toolCalls = parseToolCalls(content)
        if (toolCalls.isNotEmpty()) return AgentModelResponse.ToolCalls(toolCalls, usage)

        if (root.optString("stop_reason").equals("refusal", ignoreCase = true)) {
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
        if (root.optString("stop_reason").equals("max_tokens", ignoreCase = true)) {
            return AgentModelResponse.Failure(outputTruncatedError(), usage)
        }

        val text = textContent(content)
        val decoded = decodeFinalReportContent(text, root.optString("stop_reason"))
        decoded.error?.let { return AgentModelResponse.Failure(it, usage) }
        return AgentModelResponse.Final(report = requireNotNull(decoded.report), usage = usage)
    }

    override fun createStreamDecoder(): ModelStreamDecoder = AnthropicStreamDecoder()

    private inner class AnthropicStreamDecoder : ModelStreamDecoder {
        private val blocks = linkedMapOf<Int, AnthropicBlock>()
        private var inputTokens = 0
        private var cacheReadTokens = 0
        private var cacheCreationTokens = 0
        private var outputTokens = 0
        private var stopReason: String? = null
        private var terminal: AgentModelResponse? = null

        override suspend fun accept(data: String, onChunk: suspend (StreamChunk) -> Unit) {
            val root = runCatching { JSONObject(data) }.getOrNull() ?: return
            if (root.optString("type") == "error") {
                terminal = AgentModelResponse.Failure(
                    root.optJSONObject("error")?.let(::mapProviderError)
                        ?: AiModelErrors.unavailable("stream_error")
                )
                return
            }
            val messageUsage = root.optJSONObject("message")?.optJSONObject("usage")
            if (messageUsage != null) readUsage(messageUsage)
            val eventUsage = root.optJSONObject("usage")
            if (eventUsage != null) readUsage(eventUsage)
            when (root.optString("type")) {
                "content_block_start" -> {
                    val index = root.optInt("index")
                    val content = root.optJSONObject("content_block") ?: return
                    val block = blocks.getOrPut(index) { AnthropicBlock() }
                    block.type = content.optString("type")
                    block.id = content.optString("id")
                    block.name = content.optString("name")
                    val initialText = content.optString("text")
                    if (block.type == "text" && initialText.isNotEmpty()) {
                        block.text.append(initialText)
                        onChunk(StreamChunk.TextDelta(initialText))
                    }
                    val input = content.optJSONObject("input")
                    if (input != null && input.length() > 0) {
                        block.arguments.append(input.toString())
                    }
                    if (block.type == "tool_use" && block.id.isNotBlank() && block.name.isNotBlank()) {
                        block.started = true
                        onChunk(StreamChunk.ToolCallStart(index, block.id, block.name))
                    }
                }
                "content_block_delta" -> {
                    val index = root.optInt("index")
                    val block = blocks.getOrPut(index) { AnthropicBlock() }
                    val delta = root.optJSONObject("delta") ?: return
                    when (delta.optString("type")) {
                        "text_delta" -> {
                            val value = delta.optString("text")
                            if (value.isNotEmpty()) {
                                block.type = "text"
                                block.text.append(value)
                                onChunk(StreamChunk.TextDelta(value))
                            }
                        }
                        "input_json_delta" -> {
                            val value = delta.optString("partial_json")
                            if (value.isNotEmpty()) {
                                block.arguments.append(value)
                                val toolCallId = block.id.takeIf { it.isNotBlank() }
                                onChunk(
                                    StreamChunk.ToolCallArgumentDelta(
                                        index,
                                        toolCallId,
                                        value
                                    )
                                )
                            }
                        }
                    }
                }
                "message_delta" -> {
                    val value = root.optJSONObject("delta")?.optString("stop_reason").orEmpty()
                    if (value.isNotBlank()) stopReason = value
                }
            }
        }

        override fun finish(): AgentModelResponse {
            terminal?.let { return it }
            val content = JSONArray().apply {
                blocks.toSortedMap().values.forEach { block ->
                    when (block.type) {
                        "text" -> put(JSONObject().put("type", "text").put("text", block.text.toString()))
                        "tool_use" -> put(
                            JSONObject()
                                .put("type", "tool_use")
                                .put("id", block.id)
                                .put("name", block.name)
                                .put(
                                    "input",
                                    runCatching {
                                        JSONObject(block.arguments.toString().ifBlank { "{}" })
                                    }.getOrElse { JSONObject() }
                                )
                        )
                    }
                }
            }
            val root = JSONObject()
                .put("content", content)
                .put("stop_reason", stopReason ?: JSONObject.NULL)
                .put(
                    "usage",
                    JSONObject()
                        .put("input_tokens", inputTokens)
                        .put("cache_read_input_tokens", cacheReadTokens)
                        .put("cache_creation_input_tokens", cacheCreationTokens)
                        .put("output_tokens", outputTokens)
                )
            return parseResponse(root.toString())
        }

        private fun readUsage(usage: JSONObject) {
            inputTokens = maxOf(inputTokens, usage.optInt("input_tokens"))
            cacheReadTokens = maxOf(cacheReadTokens, usage.optInt("cache_read_input_tokens"))
            cacheCreationTokens = maxOf(
                cacheCreationTokens,
                usage.optInt("cache_creation_input_tokens")
            )
            outputTokens = maxOf(outputTokens, usage.optInt("output_tokens"))
        }
    }

    private class AnthropicBlock {
        var type: String = ""
        var id: String = ""
        var name: String = ""
        val text = StringBuilder()
        val arguments = StringBuilder()
        var started: Boolean = false
    }

    /** Anthropic requires alternating user/assistant messages; tool results are user blocks. */
    private fun messagesToJson(messages: List<AgentModelMessage>): JSONArray {
        val result = JSONArray()
        var currentRole: String? = null
        var currentContent: JSONArray? = null

        fun flush() {
            val role = currentRole ?: return
            result.put(JSONObject().put("role", role).put("content", currentContent ?: JSONArray()))
            currentRole = null
            currentContent = null
        }

        fun append(role: String, block: JSONObject) {
            if (currentRole != role) flush()
            if (currentRole == null) {
                currentRole = role
                currentContent = JSONArray()
            }
            currentContent?.put(block)
        }

        fun appendMessage(
            role: String,
            message: AgentModelMessage,
            blocks: List<JSONObject>
        ) {
            blocks.lastOrNull()?.apply {
                message.cacheControl?.let { cacheControl ->
                    put(
                        "cache_control",
                        JSONObject().put("type", cacheControl.type)
                    )
                }
            }
            blocks.forEach { block -> append(role, block) }
        }

        messages.forEach { message ->
            when (message.role) {
                AgentModelMessageRole.System -> Unit
                AgentModelMessageRole.User -> appendMessage(
                    role = "user",
                    message = message,
                    blocks = listOf(
                        JSONObject().put("type", "text").put("text", message.content)
                    )
                )
                AgentModelMessageRole.Assistant -> {
                    val blocks = buildList {
                        if (message.content.isNotBlank()) {
                            add(JSONObject().put("type", "text").put("text", message.content))
                        }
                        message.toolCalls.forEach { call -> add(toolUseBlock(call)) }
                    }
                    appendMessage("assistant", message, blocks)
                }
                AgentModelMessageRole.Tool -> appendMessage(
                    role = "user",
                    message = message,
                    blocks = listOf(toolResultBlock(message))
                )
                AgentModelMessageRole.Unknown -> Unit
            }
        }
        flush()
        return result
    }

    private fun toolUseBlock(call: AgentToolCall): JSONObject = JSONObject()
        .put("type", "tool_use")
        .put("id", call.toolCallId)
        .put("name", call.toolName)
        .put("input", toJsonValue(call.arguments))

    private fun toolResultBlock(message: AgentModelMessage): JSONObject = JSONObject()
        .put("type", "tool_result")
        .put("tool_use_id", message.toolCallId.orEmpty())
        .put("content", toolMessageContent(message))
        .apply {
            if (message.toolResult?.success == false) put("is_error", true)
        }

    private fun toolsToJson(tools: List<AgentToolDefinition>): JSONArray = JSONArray().apply {
        tools.forEach { tool ->
            put(
                JSONObject()
                    .put("name", tool.name)
                    .put("description", tool.description)
                    .put("input_schema", toJsonValue(tool.inputSchema))
            )
        }
    }

    private fun parseToolCalls(content: JSONArray): List<AgentToolCall> = buildList {
        for (index in 0 until content.length()) {
            val item = content.optJSONObject(index) ?: continue
            if (item.optString("type") != "tool_use") continue
            val id = item.optString("id")
            val name = item.optString("name")
            val input = item.opt("input")
            val arguments = when (input) {
                is JSONObject -> jsonObjectToMap(input)
                is String -> runCatching { jsonObjectToMap(JSONObject(input)) }.getOrNull()
                else -> null
            }
            if (id.isNotBlank() && name.isNotBlank() && arguments != null) {
                add(AgentToolCall(id, name, arguments))
            }
        }
    }

    private fun textContent(content: JSONArray): String = buildString {
        for (index in 0 until content.length()) {
            val item = content.optJSONObject(index) ?: continue
            if (item.optString("type") == "text") append(item.optString("text"))
        }
    }

    private companion object {
        const val ANTHROPIC_API_VERSION = "2023-06-01"
    }
}

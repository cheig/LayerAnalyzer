package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentModelMessage
import org.json.JSONObject

/** Replaceable token approximation for providers that do not publish a tokenizer. */
fun interface TokenEstimator {
    fun estimate(text: String): Int
}

/**
 * Per-message approximation shared by the context planner and the conversation
 * compactor.
 *
 * Both decide whether the transcript is too large, so they must agree on how
 * large it is: if the compactor measured a message differently from the planner,
 * a transcript could sit permanently between the two thresholds — never
 * compacted, always trimmed — and the prefix would churn on every turn.
 */
internal fun TokenEstimator.estimateMessage(message: AgentModelMessage): Int =
    estimate(message.content) +
        estimate(message.reasoningContent.orEmpty()) +
        estimateJsonValue(message.structuredContent ?: message.toolResult?.data) +
        estimateJsonValue(
            message.toolCalls.map { call ->
                mapOf("id" to call.toolCallId, "name" to call.toolName, "arguments" to call.arguments)
            }
        ) +
        MESSAGE_OVERHEAD_TOKENS

internal fun TokenEstimator.estimateMessages(messages: List<AgentModelMessage>): Int =
    messages.sumOf { estimateMessage(it) }

private fun TokenEstimator.estimateJsonValue(value: Any?): Int {
    if (value == null) return 0
    val json = runCatching { JSONObject.wrap(value)?.toString() }.getOrNull()
        ?: value.toString()
    return estimate(json)
}

internal const val MESSAGE_OVERHEAD_TOKENS = 8

/**
 * Content-aware approximation for mixed natural language and structured data.
 * Ratios are measured over Unicode code points so supplementary characters do
 * not count twice merely because Kotlin stores them as two UTF-16 code units.
 */
class ContentAwareTokenEstimator : TokenEstimator {
    override fun estimate(text: String): Int {
        if (text.isEmpty()) return 0

        var codePointCount = 0
        var hanCount = 0
        var jsonSymbolCount = 0
        var offset = 0
        while (offset < text.length) {
            val codePoint = text.codePointAt(offset)
            codePointCount += 1
            if (Character.UnicodeScript.of(codePoint) == Character.UnicodeScript.HAN) {
                hanCount += 1
            }
            if (codePoint in JSON_SYMBOLS) jsonSymbolCount += 1
            offset += Character.charCount(codePoint)
        }

        val charactersPerToken = when {
            hanCount.toDouble() / codePointCount > HAN_RATIO_THRESHOLD -> HAN_CHARACTERS_PER_TOKEN
            jsonSymbolCount.toDouble() / codePointCount > JSON_RATIO_THRESHOLD ->
                JSON_CHARACTERS_PER_TOKEN
            else -> LATIN_CHARACTERS_PER_TOKEN
        }
        return kotlin.math.ceil(codePointCount / charactersPerToken).toInt()
    }

    private companion object {
        const val HAN_RATIO_THRESHOLD = 0.3
        const val JSON_RATIO_THRESHOLD = 0.15
        const val HAN_CHARACTERS_PER_TOKEN = 1.5
        const val JSON_CHARACTERS_PER_TOKEN = 2.5
        const val LATIN_CHARACTERS_PER_TOKEN = 4.0
        val JSON_SYMBOLS = setOf(
            '{'.code,
            '}'.code,
            '['.code,
            ']'.code,
            ':'.code,
            ','.code,
            '"'.code,
            '\\'.code
        )
    }
}

/**
 * Fixed-ratio estimator retained for callers that need the previous behavior.
 */
class ConservativeCharacterTokenEstimator(
    private val charactersPerToken: Int = 3
) : TokenEstimator {
    init {
        require(charactersPerToken > 0) { "charactersPerToken must be positive." }
    }

    override fun estimate(text: String): Int =
        if (text.isEmpty()) 0 else (text.length + charactersPerToken - 1) / charactersPerToken
}

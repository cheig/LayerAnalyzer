// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.privacy

import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentModelMessage
import com.example.layanalyzer.model.AgentModelRequest
import com.example.layanalyzer.model.AgentPreviewCategory
import com.example.layanalyzer.model.AgentPreviewMessage
import com.example.layanalyzer.model.AgentRequestPreview
import com.example.layanalyzer.model.AnalysisScope

/** Builds the display-only projection used by the consent dialog. */
object AgentRequestPreviewBuilder {
    private const val MAX_EXAMPLES_PER_CATEGORY = 3
    private const val MAX_EXAMPLE_LENGTH = 80

    /**
     * The projection intentionally has no request body, auth header, request id,
     * or editable text. It only describes the same message and data tree sent by
     * [request].
     */
    fun build(
        request: AgentModelRequest,
        scope: AnalysisScope = AnalysisScope.CompleteFile
    ): AgentRequestPreview {
        val messages = request.messages.map { message ->
            val visibleContent = if (
                message.role == com.example.layanalyzer.model.AgentModelMessageRole.Tool &&
                (message.toolResult != null || message.structuredContent != null)
            ) {
                ""
            } else {
                message.content
            }
            AgentPreviewMessage(
                role = message.role,
                toolName = message.toolName,
                characterCount = visibleContent.length,
                estimatedTokens = estimateTokens(visibleContent.length)
            )
        }
        val categories = CategoryCollector()
        request.messages.forEach { message ->
            message.toolResult?.data?.let(categories::collectObject)
            val structuredData = message.structuredContent
                ?.get("data") as? Map<*, *>
            if (message.toolResult == null && structuredData != null) {
                @Suppress("UNCHECKED_CAST")
                categories.collectObject(structuredData as AgentJsonObject)
            }
        }
        val totalCharacters = messages.sumOf { it.characterCount }
        val categoryList = categories.toList().toMutableList().apply {
            val expected = when (request.privacyMode) {
                com.example.layanalyzer.model.AgentPrivacyMode.RedactedMetadata,
                com.example.layanalyzer.model.AgentPrivacyMode.UnredactedMetadata -> listOf(
                    AgentDataSensitivity.Aggregate,
                    AgentDataSensitivity.Metadata,
                    AgentDataSensitivity.Identifier
                )
                com.example.layanalyzer.model.AgentPrivacyMode.SelectedPayload -> listOf(
                    AgentDataSensitivity.Aggregate,
                    AgentDataSensitivity.Metadata,
                    AgentDataSensitivity.Identifier,
                    AgentDataSensitivity.Payload
                )
                else -> emptyList()
            }
            expected.forEach { category ->
                if (none { it.category == category }) {
                    add(AgentPreviewCategory(category, 0))
                }
            }
        }.sortedBy { it.category.name }
        return AgentRequestPreview(
            messages = messages,
            toolNames = (request.toolDefinitions.map { it.name } +
                request.messages.mapNotNull { it.toolName }).distinct(),
            categories = categoryList,
            totalCharacters = totalCharacters,
            estimatedTokens = estimateTokens(totalCharacters),
            privacyMode = request.privacyMode,
            scope = scope,
            truncated = request.messages.any { it.content.length > MAX_EXAMPLE_LENGTH * 20 }
        )
    }

    /** Safe structured projection for tests and future non-Compose consumers. */
    fun safeProjection(request: AgentModelRequest, scope: AnalysisScope = AnalysisScope.CompleteFile): AgentJsonObject {
        val preview = build(request, scope)
        return mapOf(
            "messages" to preview.messages.map {
                mapOf(
                    "role" to it.role.name,
                    "toolName" to it.toolName,
                    "characterCount" to it.characterCount,
                    "estimatedTokens" to it.estimatedTokens
                )
            },
            "tools" to preview.toolNames,
            "categories" to preview.categories.map { category ->
                mapOf(
                    "category" to category.category.name,
                    "itemCount" to category.itemCount,
                    "examples" to category.examples
                )
            },
            "totalCharacters" to preview.totalCharacters,
            "estimatedTokens" to preview.estimatedTokens,
            "privacyMode" to preview.privacyMode.name,
            "scope" to preview.scope.name,
            "truncated" to preview.truncated
        )
    }

    private fun estimateTokens(characters: Int): Int =
        if (characters <= 0) 0 else ((characters + 3) / 4).coerceAtLeast(1)

    private class CategoryCollector {
        private val counts = linkedMapOf<AgentDataSensitivity, Int>()
        private val examples = linkedMapOf<AgentDataSensitivity, MutableList<String>>()

        fun collectObject(source: AgentJsonObject) {
            source.forEach { (key, value) -> collect(key, value) }
        }

        private fun collect(fieldName: String, value: Any?) {
            val handling = AgentFieldSensitivity.handling(fieldName)
            val category = AgentFieldSensitivity.classify(fieldName)
            if (value == null) return
            if (handling == AgentFieldSensitivity.Handling.Credential ||
                handling == AgentFieldSensitivity.Handling.Payload
            ) {
                counts[category] = (counts[category] ?: 0) + 1
                return
            }
            when (value) {
                is Map<*, *> -> {
                    value.forEach { (nestedKey, nestedValue) ->
                        if (nestedKey is String) collect(nestedKey, nestedValue)
                    }
                }
                is Iterable<*> -> value.forEach { collect(fieldName, it) }
                is Array<*> -> value.forEach { collect(fieldName, it) }
                else -> {
                    counts[category] = (counts[category] ?: 0) + 1
                    val text = value.toString().take(MAX_EXAMPLE_LENGTH)
                    val safe = AgentPrivacyPolicy.sanitizeReportText(text)
                    if (safe.isNotBlank()) {
                        val bucket = examples.getOrPut(category) { mutableListOf() }
                        if (bucket.size < MAX_EXAMPLES_PER_CATEGORY && safe !in bucket) {
                            bucket += safe
                        }
                    }
                }
            }
        }

        fun toList(): List<AgentPreviewCategory> = counts
            .toSortedMap(compareBy { it.name })
            .map { (category, count) ->
                AgentPreviewCategory(category, count, examples[category].orEmpty().toList())
            }
    }
}

// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import org.json.JSONObject
import java.util.Locale

/**
 * Keep only bounded, provider-supplied error fields that are useful to a user.
 * Full response bodies never cross the model boundary or reach the UI;
 * unstructured failures may contribute only a short, redacted preview.
 */
internal fun remoteErrorDetails(
    error: JSONObject?,
    httpStatus: Int? = null,
    responseBody: String? = null
): Map<String, Any?> = buildMap {
    httpStatus?.let { put("httpStatus", it) }

    error?.safeText("code")?.let { put("remoteCode", it) }
    error?.safeText("type")?.let { put("remoteType", it) }
    error?.firstSafeText("message", "detail", "description", "error_description")
        ?.let { put("remoteMessage", it) }

    // Never copy a response body into an AgentError.  Errors are handed to
    // diagnostics, UI state and ordinary exports; even a short proxy page can
    // contain a prompt fragment, filter, URI or vendor secret.  The transport
    // records only bounded byte counts, while an explicitly armed debug dump
    // is the sole path for raw bytes.
    responseBody
        ?.takeIf { it.isNotEmpty() }
        ?.let { put("responseBytes", it.toByteArray(Charsets.UTF_8).size.coerceAtMost(MAX_REMOTE_BODY_LENGTH)) }
}

/** Parse the common nested or top-level provider error envelope. */
internal fun remoteErrorObject(responseBody: String?): JSONObject? {
    val root = runCatching { responseBody?.let(::JSONObject) }.getOrNull() ?: return null
    root.optJSONObject("error")?.let { return it }
    return root.takeIf {
        listOf("code", "type", "message", "detail", "description", "error_description")
            .any(it::has)
    }
}

private fun JSONObject.safeText(name: String): String? =
    opt(name)
        ?.takeUnless { it == JSONObject.NULL }
        ?.toString()
        ?.takeIf { it.isNotBlank() }
        ?.let { it.safeRemoteErrorText(MAX_REMOTE_ERROR_TEXT_LENGTH) }

private fun JSONObject.firstSafeText(vararg names: String): String? =
    names.asSequence().mapNotNull(::safeText).firstOrNull()

private fun JSONObject.hasUsefulErrorField(): Boolean =
    listOf("code", "type", "message", "detail", "description", "error_description")
        .any(::has)

private fun String.safeRemoteErrorText(maxLength: Int): String =
    replace(
        Regex("(?i)bearer\\s+[A-Za-z0-9._~+/=-]+"),
        "Bearer <redacted>"
    )
        .replace(
            Regex("(?i)(authorization|api[-_ ]?key|token|secret|password)\\s*[:=]\\s*\"?[^,\\s\"}]+\"?"),
            "${'$'}1=<redacted>"
        )
        .replace(
            Regex("(?i)(imsi|imei|msisdn|call[-_ ]?id)\\s*[:=]\\s*\"?[^,\\s\"}]+\"?"),
            "${'$'}1=<redacted>"
        )
        .replace(
            Regex("(?i)\\b(sips?|tel|mailto):[^\\s\"'}>,;]+"),
            { match -> "${match.groupValues[1].lowercase(Locale.ROOT)}:<redacted>" }
        )
        .replace(Regex("(?<![A-Fa-f0-9:.])(?:\\d{1,3}\\.){3}\\d{1,3}(?![\\d.])"), "<ip>")
        .replace(
            Regex("(?i)(?<![A-Fa-f0-9:])(?:[A-Fa-f0-9]{0,4}:){2,7}[A-Fa-f0-9]{0,4}(?![A-Fa-f0-9:])"),
            "<ip>"
        )
        .replace(Regex("(?<![A-Za-z0-9])\\+?\\d[\\d ()-]{6,}\\d(?![A-Za-z0-9])"), "<number>")
        .replace(Regex("https?://[^\\s\"}]+"), "<url>")
        .replace(Regex("[\\r\\n\\t]+"), " ")
        .replace(Regex("\\s+"), " ")
        .trim()
        .take(maxLength)

private const val MAX_REMOTE_ERROR_TEXT_LENGTH = 240
private const val MAX_REMOTE_BODY_LENGTH = 64 * 1024

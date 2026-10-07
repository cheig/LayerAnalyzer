// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.client

import java.time.ZonedDateTime
import java.time.format.DateTimeFormatter

/** Parse the HTTP Retry-After field into the shared millisecond vocabulary. */
internal fun retryAfterMillis(
    headers: Map<String, String>,
    nowMillis: Long = System.currentTimeMillis()
): Long? {
    val raw = headers.entries
        .firstOrNull { it.key.equals("Retry-After", ignoreCase = true) }
        ?.value
        ?.trim()
        ?.takeIf { it.isNotEmpty() }
        ?: return null
    raw.toLongOrNull()?.let { seconds ->
        return secondsToRetryAfterMillis(seconds)
    }
    val targetMillis = runCatching {
        ZonedDateTime.parse(raw, DateTimeFormatter.RFC_1123_DATE_TIME)
            .toInstant()
            .toEpochMilli()
    }.getOrNull() ?: return null
    return (targetMillis - nowMillis).coerceIn(0L, MAX_RETRY_AFTER_MILLIS)
}

/** Provider JSON retry fields use seconds unless their name explicitly says millis. */
internal fun retryAfterSecondsMillis(value: Any?): Long? = when (value) {
    is Number -> secondsToRetryAfterMillis(value.toLong())
    is String -> value.trim().toLongOrNull()?.let(::secondsToRetryAfterMillis)
    else -> null
}

private fun secondsToRetryAfterMillis(seconds: Long): Long = seconds
    .coerceIn(0L, MAX_RETRY_AFTER_SECONDS)
    .times(1_000L)

internal const val MAX_RETRY_AFTER_SECONDS: Long = 86_400L
internal const val MAX_RETRY_AFTER_MILLIS: Long = MAX_RETRY_AFTER_SECONDS * 1_000L

package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.model.AgentJsonObject
import org.json.JSONArray
import org.json.JSONObject

/** Result of fitting a structured tool payload into a byte allowance. */
data class AgentTruncationOutcome(
    val data: AgentJsonObject,
    val json: String,
    val byteSize: Int,
    val truncated: Boolean,
    /** True when even the most aggressive trim still exceeds the allowance. */
    val overflowed: Boolean = false
)

/**
 * Fits a tool payload into a byte budget by trimming the structure, never the
 * encoded text.
 *
 * Cutting a JSON string at a byte offset produces invalid JSON, so this
 * truncator instead rebuilds the payload with progressively smaller list and
 * string caps and re-encodes after each attempt.  The returned [json] is always
 * parseable, and [truncated] reflects whether anything was actually removed.
 */
object AgentResultTruncator {
    /** List-item caps tried in order, from generous to minimal. */
    private val LIST_CAPS = intArrayOf(Int.MAX_VALUE, 200, 100, 50, 25, 12, 6, 3, 2, 1, 0)

    /** String-length caps applied at the same step as the list cap above. */
    private val STRING_CAPS = intArrayOf(Int.MAX_VALUE, 2048, 1024, 512, 256, 192, 128, 96, 80, 64, 48)

    fun truncate(data: AgentJsonObject?, maxBytes: Int): AgentTruncationOutcome {
        return truncate(data, maxBytes, ::encode)
    }

    internal fun truncate(
        data: AgentJsonObject?,
        maxBytes: Int,
        encoder: (AgentJsonObject) -> String
    ): AgentTruncationOutcome {
        val payload = data ?: emptyMap()
        // The policy itself is never below 256 bytes, but the remaining
        // run-wide/detail allowance can be smaller after earlier calls. Keep
        // the caller's exact ceiling here so a successful result can never
        // silently overshoot the bytes still available.
        val allowance = maxBytes.coerceAtLeast(1)

        var left = 0
        var right = LIST_CAPS.lastIndex
        var best: AgentTruncationOutcome? = null
        while (left <= right) {
            val level = left + (right - left) / 2
            val trimmer = Trimmer(LIST_CAPS[level], STRING_CAPS[level])
            val trimmed = reconcileCounts(
                original = payload,
                trimmed = trimmer.trimMap(payload),
                payloadWasTrimmed = trimmer.removedAnything
            )
            val json = encoder(trimmed)
            val size = json.toByteArray(Charsets.UTF_8).size
            if (size <= allowance) {
                best = AgentTruncationOutcome(
                    data = trimmed,
                    json = json,
                    byteSize = size,
                    truncated = trimmer.removedAnything
                )
                right = level - 1
            } else {
                left = level + 1
            }
        }
        best?.let { return it }

        // Nothing survived the trim levels: report overflow with an explicit
        // marker payload rather than emitting a broken fragment of the original.
        val marker: AgentJsonObject = mapOf(
            "truncated" to true,
            "reason" to "result_too_large",
            "maxBytes" to allowance
        )
        val markerCandidates = listOf<AgentJsonObject>(
            marker,
            mapOf("truncated" to true),
            emptyMap()
        )
        val encodedMarker = markerCandidates.firstNotNullOfOrNull { candidate ->
            val json = encoder(candidate)
            (candidate to json).takeIf {
                json.toByteArray(Charsets.UTF_8).size <= allowance
            }
        } ?: (emptyMap<String, Any?>() to encoder(emptyMap()))
        return AgentTruncationOutcome(
            data = encodedMarker.first,
            json = encodedMarker.second,
            byteSize = encodedMarker.second.toByteArray(Charsets.UTF_8).size,
            truncated = true,
            overflowed = true
        )
    }

    fun encode(data: AgentJsonObject): String = toJsonObject(data).toString()

    /**
     * Keep a tool's semantic counters aligned with the structure that survived
     * the byte trim. The generic trimmer knows how to fit JSON, but it must not
     * leave `returned: 16` beside a `frames` array containing six entries.
     */
    private fun reconcileCounts(
        original: AgentJsonObject,
        trimmed: AgentJsonObject,
        payloadWasTrimmed: Boolean
    ): AgentJsonObject {
        val result = LinkedHashMap<String, Any?>(trimmed.size + 4)
        trimmed.forEach { (key, value) -> result[key] = value }

        val primaryKey = PRIMARY_COLLECTION_KEYS.firstOrNull { key ->
            original[key] is Iterable<*> || original[key] is Array<*>
        }
        if (primaryKey != null && result[primaryKey] is Iterable<*>) {
            val returned = (result[primaryKey] as Iterable<*>).count()
            if (original.containsKey("returned")) result["returned"] = returned

            if (primaryKey == "frames" && payloadWasTrimmed) {
                val originalFrames = frameNumbers(original[primaryKey])
                val returnedFrames = frameNumbers(result[primaryKey])
                val omitted = originalFrames.filterNot { it in returnedFrames }
                if (omitted.isNotEmpty()) {
                    result["payloadOmittedFrames"] = omitted
                }
            }
        }

        if (payloadWasTrimmed) {
            result["payloadTruncated"] = true
            result["truncated"] = true
            val omittedPaths = omittedPaths(original, result)
            if (omittedPaths.isNotEmpty()) result["omittedPaths"] = omittedPaths
        }
        return result
    }

    private fun omittedPaths(original: AgentJsonObject, trimmed: AgentJsonObject): List<String> {
        val paths = ArrayList<String>()
        original.keys.forEach { key ->
            if (!trimmed.containsKey(key)) paths += key
            val originalValue = original[key]
            val trimmedValue = trimmed[key]
            if ((originalValue is Iterable<*> || originalValue is Array<*>) &&
                (trimmedValue is Iterable<*> || trimmedValue is Array<*>)) {
                val originalSize = sizeOf(originalValue)
                val trimmedSize = sizeOf(trimmedValue)
                if (trimmedSize < originalSize) paths += "$key[$trimmedSize..${originalSize - 1}]"
            }
        }
        return paths.take(MAX_OMITTED_PATHS)
    }

    private fun sizeOf(value: Any?): Int = when (value) {
        is Collection<*> -> value.size
        is Iterable<*> -> value.count()
        is Array<*> -> value.size
        else -> 0
    }

    private fun frameNumbers(value: Any?): List<Long> = when (value) {
        is Iterable<*> -> value.mapNotNull { item ->
            (item as? Map<*, *>)?.get("frameNumber")?.let { raw ->
                (raw as? Number)?.toLong() ?: raw.toString().toLongOrNull()
            }
        }
        is Array<*> -> value.mapNotNull { item ->
            (item as? Map<*, *>)?.get("frameNumber")?.let { raw ->
                (raw as? Number)?.toLong() ?: raw.toString().toLongOrNull()
            }
        }
        else -> emptyList()
    }

    private fun toJsonObject(data: AgentJsonObject): JSONObject = JSONObject().apply {
        data.forEach { (key, value) -> put(key, toJsonValue(value)) }
    }

    private fun toJsonValue(value: Any?): Any = when (value) {
        null -> JSONObject.NULL
        JSONObject.NULL -> JSONObject.NULL
        is String, is Boolean -> value
        is Double -> if (value.isFinite()) value else JSONObject.NULL
        is Float -> if (value.isFinite()) value.toDouble() else JSONObject.NULL
        is Number -> value
        is Enum<*> -> value.name
        is Map<*, *> -> JSONObject().apply {
            value.forEach { (key, nested) -> put(key.toString(), toJsonValue(nested)) }
        }
        is Iterable<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        is Array<*> -> JSONArray().apply { value.forEach { put(toJsonValue(it)) } }
        else -> value.toString()
    }

    /**
     * Applies one (listCap, stringCap) level to a whole payload.
     *
     * Trimmed lists gain a sibling `<key>Truncated` marker so the model can see
     * that a collection is partial instead of assuming it read everything.
     */
    private class Trimmer(
        private val listCap: Int,
        private val stringCap: Int
    ) {
        var removedAnything: Boolean = false
            private set

        fun trimMap(source: Map<*, *>): Map<String, Any?> {
            val result = LinkedHashMap<String, Any?>(source.size)
            source.forEach { (rawKey, value) ->
                val key = rawKey.toString()
                val trimmed = trimValue(value)
                result[key] = trimmed
                if (value is Iterable<*> || value is Array<*>) {
                    val originalSize = sizeOf(value)
                    val keptSize = (trimmed as? List<*>)?.size ?: 0
                    if (keptSize < originalSize) {
                        result["${key}Truncated"] = true
                        result["${key}Total"] = originalSize
                        result["${key}Returned"] = keptSize
                    }
                }
            }
            return result
        }

        private fun trimValue(value: Any?): Any? = when (value) {
            null -> null
            is String -> trimString(value)
            is Map<*, *> -> trimMap(value)
            is Iterable<*> -> trimList(value.toList())
            is Array<*> -> trimList(value.toList())
            else -> value
        }

        private fun trimString(value: String): String {
            if (value.length <= stringCap) return value
            removedAnything = true
            // Reserve room for the ellipsis so the cap is a true upper bound.
            val keep = (stringCap - ELLIPSIS.length).coerceAtLeast(0)
            return value.take(keep) + ELLIPSIS
        }

        private fun trimList(value: List<Any?>): List<Any?> {
            val kept = if (value.size > listCap) {
                removedAnything = true
                value.take(listCap)
            } else {
                value
            }
            return kept.map(::trimValue)
        }

        private fun sizeOf(value: Any?): Int = when (value) {
            is Collection<*> -> value.size
            is Iterable<*> -> value.count()
            is Array<*> -> value.size
            else -> 0
        }
    }

    private const val ELLIPSIS = "…"
    private const val MAX_OMITTED_PATHS = 64
    private val PRIMARY_COLLECTION_KEYS = listOf(
        "frames", "packets", "frameNumbers", "sampleFrames", "anomalyFrames", "events", "items"
    )
}

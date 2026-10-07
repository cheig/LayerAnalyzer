package com.example.layanalyzer.ai.tools

import com.example.layanalyzer.ai.agent.AgentPolicy
import com.example.layanalyzer.model.AgentError
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentJsonObject
import java.security.MessageDigest
import java.util.Locale

/** Outcome of validating model-supplied arguments against a tool schema. */
sealed class AgentArgumentValidation {
    data class Valid(
        val arguments: AgentJsonObject,
        val normalizations: List<AgentArgumentNormalization> = emptyList()
    ) : AgentArgumentValidation()

    data class Invalid(val error: AgentError) : AgentArgumentValidation()

    fun getOrNull(): AgentJsonObject? = (this as? Valid)?.arguments

    fun errorOrNull(): AgentError? = (this as? Invalid)?.error
}

data class AgentArgumentNormalization(
    val path: String,
    val originalLength: Int,
    val normalizedLength: Int,
    val ruleVersion: String = HOST_TRUNCATE_RULE_VERSION
) {
    val truncated: Boolean
        get() = normalizedLength < originalLength
}

const val HOST_TRUNCATE_SCHEMA_KEY = "x-hostTruncate"
const val HOST_TRUNCATE_RULE_VERSION = "host-truncate-v1"

/**
 * Validator for the deliberately small JSON Schema subset the Agent tools use.
 *
 * Supported keywords: type (object/string/integer/number/boolean/array),
 * required, properties, items, enum, minimum, maximum, minItems, maxItems,
 * minLength, maxLength and additionalProperties=false.
 *
 * The subset is intentionally not extensible with `$ref`, `pattern`,
 * `allOf`/`anyOf` or any other construct that would let a schema — or a model
 * response shaped like one — drive dynamic evaluation.  Anything unrecognised
 * in the value being checked is rejected rather than passed through.
 */
object AgentArgumentValidator {
    private const val ROOT_PATH = "arguments"

    fun validate(
        schema: AgentJsonObject,
        arguments: AgentJsonObject?,
        policy: AgentPolicy = AgentPolicy()
    ): AgentArgumentValidation {
        val supplied = arguments ?: emptyMap()
        return try {
            val normalizations = mutableListOf<AgentArgumentNormalization>()
            val normalized = validateObject(
                schema = schema,
                value = supplied,
                path = ROOT_PATH,
                depth = 1,
                policy = policy,
                normalizations = normalizations
            )
            AgentArgumentValidation.Valid(normalized, normalizations)
        } catch (violation: SchemaViolation) {
            AgentArgumentValidation.Invalid(violation.toAgentError())
        }
    }

    /**
     * Stable hash of already-validated arguments.  Insensitive to key order,
     * sensitive to any value change.  Used for provenance and cache keys, so it
     * must never include the capture path or a native handle.
     */
    fun normalizedArgumentsHash(arguments: AgentJsonObject?): String {
        val canonical = canonicalize(arguments ?: emptyMap<String, Any?>())
        val digest = MessageDigest.getInstance("SHA-256").digest(canonical.toByteArray(Charsets.UTF_8))
        return digest.joinToString(separator = "") { byte ->
            "%02x".format(Locale.ROOT, byte)
        }
    }

    /** Canonical JSON text used as the hash pre-image; exposed for tests. */
    fun canonicalize(value: Any?): String = buildString { appendCanonical(value) }

    private fun StringBuilder.appendCanonical(value: Any?) {
        when (value) {
            null -> append("null")
            is Boolean -> append(if (value) "true" else "false")
            is String -> appendQuoted(value)
            is Byte, is Short, is Int, is Long -> append((value as Number).toLong().toString())
            is Float, is Double -> appendCanonicalDouble((value as Number).toDouble())
            is Number -> appendCanonicalDouble(value.toDouble())
            is Map<*, *> -> {
                append('{')
                value.entries
                    .map { (key, nested) -> key.toString() to nested }
                    .sortedBy { it.first }
                    .forEachIndexed { index, (key, nested) ->
                        if (index > 0) append(',')
                        appendQuoted(key)
                        append(':')
                        appendCanonical(nested)
                    }
                append('}')
            }
            is Iterable<*> -> {
                append('[')
                value.forEachIndexed { index, nested ->
                    if (index > 0) append(',')
                    appendCanonical(nested)
                }
                append(']')
            }
            else -> appendQuoted(value.toString())
        }
    }

    /** Render whole doubles without a trailing .0 so 2 and 2.0 hash alike. */
    private fun StringBuilder.appendCanonicalDouble(value: Double) {
        if (!value.isFinite()) {
            append("null")
            return
        }
        if (value == Math.floor(value) && Math.abs(value) < 9.007199254740992E15) {
            append(value.toLong().toString())
        } else {
            append(value.toString())
        }
    }

    private fun StringBuilder.appendQuoted(text: String) {
        append('"')
        text.forEach { char ->
            when (char) {
                '"' -> append("\\\"")
                '\\' -> append("\\\\")
                '\n' -> append("\\n")
                '\r' -> append("\\r")
                '\t' -> append("\\t")
                else -> if (char < ' ') {
                    append("\\u")
                    append("%04x".format(Locale.ROOT, char.code))
                } else {
                    append(char)
                }
            }
        }
        append('"')
    }

    private fun validateValue(
        schema: AgentJsonObject,
        value: Any?,
        path: String,
        depth: Int,
        policy: AgentPolicy,
        normalizations: MutableList<AgentArgumentNormalization>
    ): Any? {
        if (depth > policy.maxArgumentDepth) {
            throw SchemaViolation(path, "exceeds maxDepth", mapOf("limit" to policy.maxArgumentDepth))
        }
        val declaredType = schema["type"] as? String
            ?: throw SchemaViolation(path, "has no declared type")

        if (value == null) {
            throw SchemaViolation(path, "must not be null", mapOf("expectedType" to declaredType))
        }

        return when (declaredType) {
            "object" -> validateObject(schema, asMap(value, path), path, depth, policy, normalizations)
            "array" -> validateArray(schema, asList(value, path), path, depth, policy, normalizations)
            "string" -> validateString(schema, value, path, policy, normalizations)
            "integer" -> validateInteger(schema, value, path)
            "number" -> validateNumber(schema, value, path)
            "boolean" -> value as? Boolean
                ?: throw SchemaViolation(path, "must be a boolean")
            else -> throw SchemaViolation(path, "has an unsupported type", mapOf("type" to declaredType))
        }
    }

    private fun validateObject(
        schema: AgentJsonObject,
        value: AgentJsonObject,
        path: String,
        depth: Int,
        policy: AgentPolicy,
        normalizations: MutableList<AgentArgumentNormalization>
    ): AgentJsonObject {
        @Suppress("UNCHECKED_CAST")
        val properties = (schema["properties"] as? Map<String, Any?>).orEmpty()
        val required = (schema["required"] as? Iterable<*>)
            ?.mapNotNull { it as? String }
            .orEmpty()

        if (value.size > policy.maxArgumentProperties) {
            throw SchemaViolation(
                path,
                "exceeds maxProperties",
                mapOf("limit" to policy.maxArgumentProperties, "actual" to value.size)
            )
        }

        // additionalProperties defaults to false: unknown keys are a hard
        // failure so a model cannot smuggle a path, URL or class name past the
        // declared surface.
        val allowAdditional = schema["additionalProperties"] == true
        if (!allowAdditional) {
            val unknown = value.keys.firstOrNull { it !in properties.keys }
            if (unknown != null) {
                throw SchemaViolation(
                    childPath(path, unknown),
                    "is not an accepted argument"
                )
            }
        }

        required.forEach { key ->
            if (!value.containsKey(key) || value[key] == null) {
                throw SchemaViolation(childPath(path, key), "is required")
            }
        }

        val normalized = LinkedHashMap<String, Any?>(properties.size)
        properties.forEach { (key, rawSchema) ->
            if (!value.containsKey(key)) return@forEach
            val supplied = value[key]
            if (supplied == null) {
                if (key in required) throw SchemaViolation(childPath(path, key), "is required")
                return@forEach
            }
            @Suppress("UNCHECKED_CAST")
            val childSchema = rawSchema as? Map<String, Any?>
                ?: throw SchemaViolation(childPath(path, key), "has no usable schema")
            normalized[key] = validateValue(
                schema = childSchema,
                value = supplied,
                path = childPath(path, key),
                depth = depth + 1,
                policy = policy,
                normalizations = normalizations
            )
        }
        return normalized
    }

    private fun validateArray(
        schema: AgentJsonObject,
        value: List<Any?>,
        path: String,
        depth: Int,
        policy: AgentPolicy,
        normalizations: MutableList<AgentArgumentNormalization>
    ): List<Any?> {
        val hardLimit = policy.maxArgumentArrayItems
        val schemaMax = (schema["maxItems"] as? Number)?.toInt()
        val effectiveMax = minOf(schemaMax ?: hardLimit, hardLimit)
        if (value.size > effectiveMax) {
            throw SchemaViolation(
                path,
                "exceeds maxItems",
                mapOf("limit" to effectiveMax, "actual" to value.size)
            )
        }
        val minItems = (schema["minItems"] as? Number)?.toInt()
        if (minItems != null && value.size < minItems) {
            throw SchemaViolation(
                path,
                "is below minItems",
                mapOf("limit" to minItems, "actual" to value.size)
            )
        }

        @Suppress("UNCHECKED_CAST")
        val itemSchema = schema["items"] as? Map<String, Any?>
            ?: throw SchemaViolation(path, "has no item schema")

        return value.mapIndexed { index, item ->
            validateValue(
                schema = itemSchema,
                value = item,
                path = "$path[$index]",
                depth = depth + 1,
                policy = policy,
                normalizations = normalizations
            )
        }
    }

    private fun validateString(
        schema: AgentJsonObject,
        value: Any?,
        path: String,
        policy: AgentPolicy,
        normalizations: MutableList<AgentArgumentNormalization>
    ): String {
        val text = value as? String ?: throw SchemaViolation(path, "must be a string")
        val schemaMax = (schema["maxLength"] as? Number)?.toInt()
        if (schemaMax != null && text.length > schemaMax) {
            throw SchemaViolation(
                path,
                "exceeds maxLength",
                mapOf("limit" to schemaMax, "actual" to text.length)
            )
        }
        val hostTruncate = (schema[HOST_TRUNCATE_SCHEMA_KEY] as? Number)?.toInt()
        if (hostTruncate != null && hostTruncate <= 0) {
            throw SchemaViolation(path, "has an invalid host truncation rule")
        }
        val normalized = if (hostTruncate != null && text.length > hostTruncate) {
            text.take(hostTruncate).also {
                normalizations += AgentArgumentNormalization(
                    path = path,
                    originalLength = text.length,
                    normalizedLength = it.length
                )
            }
        } else {
            text
        }
        if (normalized.length > policy.maxArgumentStringLength) {
            throw SchemaViolation(
                path,
                "exceeds maxLength",
                mapOf("limit" to policy.maxArgumentStringLength, "actual" to normalized.length)
            )
        }
        val minLength = (schema["minLength"] as? Number)?.toInt()
        if (minLength != null && normalized.length < minLength) {
            throw SchemaViolation(
                path,
                "is below minLength",
                mapOf("limit" to minLength, "actual" to normalized.length)
            )
        }
        validateEnum(schema, normalized, path)
        return normalized
    }

    private fun validateInteger(
        schema: AgentJsonObject,
        value: Any?,
        path: String
    ): Long {
        val number = value as? Number ?: throw SchemaViolation(path, "must be an integer")
        if (value is Double || value is Float) {
            val asDouble = number.toDouble()
            if (asDouble != Math.floor(asDouble) || !asDouble.isFinite()) {
                throw SchemaViolation(path, "must be an integer")
            }
        }
        val asLong = number.toLong()
        checkBounds(schema, asLong.toDouble(), path)
        validateEnum(schema, asLong, path)
        return asLong
    }

    private fun validateNumber(
        schema: AgentJsonObject,
        value: Any?,
        path: String
    ): Double {
        val number = value as? Number ?: throw SchemaViolation(path, "must be a number")
        val asDouble = number.toDouble()
        if (!asDouble.isFinite()) throw SchemaViolation(path, "must be a finite number")
        checkBounds(schema, asDouble, path)
        return asDouble
    }

    private fun checkBounds(schema: AgentJsonObject, value: Double, path: String) {
        val minimum = (schema["minimum"] as? Number)?.toDouble()
        if (minimum != null && value < minimum) {
            throw SchemaViolation(path, "is below minimum", mapOf("limit" to minimum))
        }
        val maximum = (schema["maximum"] as? Number)?.toDouble()
        if (maximum != null && value > maximum) {
            throw SchemaViolation(path, "exceeds maximum", mapOf("limit" to maximum))
        }
    }

    private fun validateEnum(schema: AgentJsonObject, value: Any?, path: String) {
        val allowed = schema["enum"] as? Iterable<*> ?: return
        val values = allowed.toList()
        if (values.isEmpty()) return
        val matches = values.any { candidate ->
            when {
                candidate is Number && value is Number ->
                    candidate.toDouble() == value.toDouble()
                else -> candidate == value
            }
        }
        if (!matches) {
            // Only the accepted vocabulary is echoed, never the rejected value.
            throw SchemaViolation(
                path,
                "is not an accepted value",
                mapOf("allowed" to values.map { it.toString() })
            )
        }
    }

    private fun asMap(value: Any?, path: String): AgentJsonObject {
        val map = value as? Map<*, *> ?: throw SchemaViolation(path, "must be an object")
        val result = LinkedHashMap<String, Any?>(map.size)
        map.forEach { (key, nested) ->
            val name = key as? String
                ?: throw SchemaViolation(path, "must use string property names")
            result[name] = nested
        }
        return result
    }

    private fun asList(value: Any?, path: String): List<Any?> = when (value) {
        is List<*> -> value
        is Iterable<*> -> value.toList()
        is Array<*> -> value.toList()
        else -> throw SchemaViolation(path, "must be an array")
    }

    private fun childPath(parent: String, key: String): String = "$parent.$key"

    private class SchemaViolation(
        val path: String,
        val reason: String,
        val extra: AgentJsonObject = emptyMap()
    ) : IllegalArgumentException("$path $reason") {
        fun toAgentError(): AgentError = AgentError(
            code = AgentErrorCode.INVALID_TOOL_ARGUMENTS,
            userMessage = "$path $reason",
            retryable = false,
            details = buildMap {
                put("path", path)
                put("reason", reason)
                putAll(extra)
            }
        )
    }
}

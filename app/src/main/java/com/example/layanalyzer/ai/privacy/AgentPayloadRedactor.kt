package com.example.layanalyzer.ai.privacy

import com.example.layanalyzer.ai.agent.AgentAliasEntry
import com.example.layanalyzer.ai.agent.AgentAliasKind
import com.example.layanalyzer.ai.agent.AliasTable
import com.example.layanalyzer.data.MetadataRedactor
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentDataSensitivity
import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentPrivacyMode
import java.security.SecureRandom

/**
 * Structured, field-by-field redaction of a tool result before it can enter a
 * model's context.
 *
 * The unit of work is the decoded result object, not its serialized form.  A
 * single regex sweep over the encoded JSON would be simpler and wrong: it cannot
 * tell a Call-ID from a protocol name, it cannot drop a credential while keeping
 * its scheme, and it would happily rewrite a frame number that happened to look
 * like an address.  Walking the structure means every value is judged by the
 * field that holds it, with [AgentFieldSensitivity] as the decision table and
 * [MetadataRedactor] as the alias source.
 *
 * ### Alias stability
 *
 * One instance is scoped to one Agent run and holds one alias map, so a host
 * seen in `get_statistics` and again in `query_packet_summaries` reaches the
 * model as the same alias — without that, a model could not tell "the same
 * endpoint twice" from "two endpoints".  The map is in-memory only; it is never
 * persisted, never logged, and never sent, so an alias cannot be resolved back
 * to a real value off the device.  A different run uses a different salt and
 * therefore a different alias for the same input.
 *
 * ### Where it runs
 *
 * `AgentToolRunner.finish` calls this for every successful result, so a tool
 * cannot opt out and a new tool cannot forget to opt in.  Tools return real
 * values and stay simple; the guarantee lives at the chokepoint.
 */
class AgentPayloadRedactor private constructor(
    private val textRedactor: MetadataRedactor?,
    private val privacyMode: AgentPrivacyMode,
    private val aliasTable: AliasTable?
) {

    /** Whether this redactor will change anything at all. */
    val isActive: Boolean get() = textRedactor != null

    /**
     * Redact one tool result.
     *
     * [declaredSensitivity] is the tool's own declaration and acts only as a
     * floor: a result declared `Aggregate` is still walked, because the
     * declaration describes the tool's *intent* and the field table describes
     * what the data actually is.  A tool that mislabels an identifier-bearing
     * result as aggregate therefore cannot bypass field policy, which is the
     * exact bypass AI-11 section 2 forbids.
     */
    fun redact(
        data: AgentJsonObject,
        declaredSensitivity: AgentDataSensitivity = AgentDataSensitivity.Identifier
    ): AgentJsonObject {
        val active = textRedactor ?: return data
        if (data.isEmpty()) return data
        return redactObject(data, active, declaredSensitivity, depth = 0)
    }

    /** Alias a single value as though it were held by a field named [fieldName]. */
    fun redactField(fieldName: String, value: Any?): Any? {
        val active = textRedactor ?: return value
        return redactValue(fieldName, value, active, AgentDataSensitivity.Identifier, depth = 0)
    }

    /** Host-only lookup for evidence that refers to a model-visible alias. */
    fun resolveAlias(alias: String): AgentAliasEntry? = aliasTable?.resolve(alias)

    private fun redactObject(
        source: AgentJsonObject,
        redactor: MetadataRedactor,
        declared: AgentDataSensitivity,
        depth: Int,
        inheritedField: String? = null
    ): AgentJsonObject {
        if (depth > MAX_DEPTH) return emptyMap()

        // A credential occurrence is rewritten as a whole rather than per field,
        // because its shape changes: the value keys disappear and existence keys
        // take their place.
        if (looksLikeCredentialOccurrence(source)) {
            return credentialShape(source)
        }

        // A field occurrence names the protocol field it came from, and that
        // name is what classifies its value.  Judging `displayValue` on its own
        // would treat a Call-ID as ordinary text and alias it with the wrong
        // vocabulary — or, for a value the text rules do not recognise, not at
        // all.  The occurrence's own name wins over the enclosing key.
        val contextField = (source["actualFieldName"] as? String)
            ?: (source["requestedName"] as? String)
            ?: inheritedField
        preRegisterIdentifiers(source, contextField)

        val result = LinkedHashMap<String, Any?>(source.size)
        source.forEach { (key, value) ->
            val classifyAs = if (contextField != null && key in VALUE_KEYS) contextField else key
            when (AgentFieldSensitivity.handling(classifyAs)) {
                AgentFieldSensitivity.Handling.Credential -> {
                    // Existence metadata only.  The value is dropped rather than
                    // aliased: an alias of a secret still reveals that a secret
                    // was there and roughly how long it was.
                    result[key] = null
                    result["${key}Present"] = value != null && value.toString().isNotBlank()
                    schemeOf(value)?.let { scheme -> result["${key}Scheme"] = scheme }
                }

                AgentFieldSensitivity.Handling.Payload -> {
                    // Structurally unreachable for MVP tools, which declare no
                    // payload field.  Enforced anyway so a future tool cannot
                    // introduce one silently.
                    result[key] = PAYLOAD_BLOCKED
                }

                else -> result[key] = redactValue(classifyAs, value, redactor, declared, depth, contextField)
            }
        }
        return result
    }

    private fun redactValue(
        fieldName: String,
        value: Any?,
        redactor: MetadataRedactor,
        declared: AgentDataSensitivity,
        depth: Int,
        inheritedField: String? = null
    ): Any? {
        when (AgentFieldSensitivity.handling(fieldName)) {
            AgentFieldSensitivity.Handling.Payload -> return PAYLOAD_BLOCKED
            AgentFieldSensitivity.Handling.Credential -> return redactCredentialValue(value)
            else -> Unit
        }
        return when (value) {
            null -> null

            is String -> redactString(fieldName, value, redactor)

            // Most numbers are metrics, but SSRC and several core correlators are
            // numeric identifiers. The field name decides which case this is.
            is Number -> aliasFor(fieldName, value.toString()) ?: value
            is Boolean -> value

            is Map<*, *> -> {
                @Suppress("UNCHECKED_CAST")
                val nested = value as? Map<String, Any?>
                if (nested == null) {
                    null
                } else if (isValueKeyedMap(fieldName)) {
                    // `fields` in a projection is keyed by the requested field
                    // name, so it classifies everything under that key.
                    nested.mapValues { (key, item) ->
                        redactValue(key, item, redactor, declared, depth + 1, key)
                    }
                } else {
                    redactObject(nested, redactor, declared, depth + 1, inheritedField)
                }
            }

            is Iterable<*> -> value.map { item ->
                redactValue(
                    fieldName,
                    item,
                    redactor,
                    declared,
                    depth + 1,
                    inheritedField ?: fieldName
                )
            }

            // Do not forward arbitrary future DTO types directly.
            else -> redactString(fieldName, value.toString(), redactor)
        }
    }

    private fun redactCredentialValue(value: Any?): Any? = when (value) {
        null -> null
        is Iterable<*> -> value.map(::redactCredentialValue)
        is Array<*> -> value.map(::redactCredentialValue)
        is Map<*, *> -> {
            @Suppress("UNCHECKED_CAST")
            (value as? Map<String, Any?>)?.let(::credentialShape)
                ?: mapOf("credential" to true, "present" to true)
        }
        else -> buildMap {
            put("credential", true)
            put("present", true)
            schemeOf(value)?.let { put("scheme", it) }
        }
    }

    private fun redactString(
        fieldName: String,
        value: String,
        redactor: MetadataRedactor
    ): String {
        if (value.isEmpty()) return value
        if (privacyMode == AgentPrivacyMode.UnredactedMetadata) {
            return when (AgentFieldSensitivity.handling(fieldName)) {
                AgentFieldSensitivity.Handling.Credential -> CREDENTIAL_WITHHELD
                AgentFieldSensitivity.Handling.Payload -> PAYLOAD_BLOCKED
                else -> value
            }
        }
        return when (val handling = AgentFieldSensitivity.handling(fieldName)) {
            AgentFieldSensitivity.Handling.Keep -> value

            is AgentFieldSensitivity.Handling.Alias -> {
                aliasTable?.alias(aliasKind(handling.kind), value)
                    ?: redactor.redact(redactor.redactValue(handling.kind, value))
            }

            AgentFieldSensitivity.Handling.Text -> redactor.redact(aliasTable?.replaceKnown(value) ?: value)
            AgentFieldSensitivity.Handling.Unclassified -> redactUnclassified(value, redactor)

            // Both are handled structurally in redactObject; reaching here means
            // the value sat somewhere unexpected, so fail closed.
            AgentFieldSensitivity.Handling.Credential -> CREDENTIAL_WITHHELD
            AgentFieldSensitivity.Handling.Payload -> PAYLOAD_BLOCKED
        }
    }

    private fun redactUnclassified(value: String, redactor: MetadataRedactor): String {
        val candidate = value.trim()
        if (!looksLikeOpaqueToken(candidate)) {
            return redactor.redact(aliasTable?.replaceKnown(value) ?: value)
        }
        return aliasTable?.alias(AgentAliasKind.Ssrc, candidate)
            ?: redactor.redactValue(MetadataRedactor.IdentifierKind.Opaque, candidate)
    }

    private fun looksLikeOpaqueToken(value: String): Boolean =
        value.length >= MIN_OPAQUE_TOKEN_LENGTH &&
            (HEX_TOKEN.matches(value) || BASE64_TOKEN.matches(value))

    /**
     * Whether this object is one field occurrence whose value is a credential.
     *
     * AI-09's projector already drops such values, so this is the second line:
     * it re-shapes the object even if an upstream change stopped doing so.
     */
    private fun looksLikeCredentialOccurrence(source: AgentJsonObject): Boolean {
        if (source["credential"] == true) return true
        val name = source["actualFieldName"] as? String ?: return false
        return AgentFieldSensitivity.isCredential(name)
    }

    private fun credentialShape(source: AgentJsonObject): AgentJsonObject {
        val result = LinkedHashMap<String, Any?>(6)
        (source["requestedName"] as? String)?.let { result["requestedName"] = it }
        (source["actualFieldName"] as? String)?.let { result["actualFieldName"] = it }
        result["credential"] = true
        result["present"] = source["present"] as? Boolean
            ?: listOf("displayValue", "filterValue", "value")
                .any { key -> source[key]?.toString()?.isNotBlank() == true }
        schemeOf(source["scheme"] ?: source["displayValue"] ?: source["filterValue"])
            ?.let { scheme -> result["scheme"] = scheme }
        (source["generated"] as? Boolean)?.let { result["generated"] = it }
        (source["hidden"] as? Boolean)?.let { result["hidden"] = it }
        return result
    }

    /**
     * The authentication scheme named at the start of a credential value, if it
     * is one the host already knows.
     *
     * An unrecognised scheme returns null rather than echoing the first token,
     * which would carry capture text into the payload under the guise of a
     * scheme label.
     */
    private fun schemeOf(value: Any?): String? {
        val text = (value as? String)?.trim()?.lowercase() ?: return null
        if (text.isEmpty()) return null
        return KNOWN_SCHEMES.firstOrNull { scheme ->
            text == scheme || text.startsWith("$scheme ")
        }
    }

    /** Maps whose keys are themselves field names rather than DTO properties. */
    private fun isValueKeyedMap(fieldName: String): Boolean =
        fieldName.equals("fields", ignoreCase = true) ||
            fieldName.equals("metrics", ignoreCase = true)

    private fun preRegisterIdentifiers(source: AgentJsonObject, contextField: String?) {
        val aliases = aliasTable ?: return
        source.forEach { (key, value) ->
            val field = if (contextField != null && key in VALUE_KEYS) contextField else key
            val handling = AgentFieldSensitivity.handling(field)
            if (handling is AgentFieldSensitivity.Handling.Alias && (value is String || value is Number)) {
                aliases.alias(aliasKind(handling.kind), value.toString())
            }
        }
    }

    private fun aliasFor(fieldName: String, value: String): String? {
        if (privacyMode == AgentPrivacyMode.UnredactedMetadata) return null
        val handling = AgentFieldSensitivity.handling(fieldName) as? AgentFieldSensitivity.Handling.Alias
            ?: return null
        return aliasTable?.alias(aliasKind(handling.kind), value)
    }

    private fun aliasKind(kind: MetadataRedactor.IdentifierKind): AgentAliasKind = when (kind) {
        MetadataRedactor.IdentifierKind.Address -> AgentAliasKind.Endpoint
        MetadataRedactor.IdentifierKind.CallId -> AgentAliasKind.CallId
        MetadataRedactor.IdentifierKind.Opaque -> AgentAliasKind.Ssrc
        MetadataRedactor.IdentifierKind.SessionId -> AgentAliasKind.CoreSession
        MetadataRedactor.IdentifierKind.SipUri,
        MetadataRedactor.IdentifierKind.Subscriber -> AgentAliasKind.Identifier
    }

    companion object {
        /** Placeholder for a field whose class forbids sending the value at all. */
        const val PAYLOAD_BLOCKED = "PRIVACY_BLOCKED"

        /** Placeholder for a credential that surfaced outside its expected shape. */
        const val CREDENTIAL_WITHHELD = "PRIVACY_WITHHELD"

        /** Recursion cap; a capture-derived structure must not drive the stack. */
        private const val MAX_DEPTH = 32
        private const val MIN_OPAQUE_TOKEN_LENGTH = 8

        /**
         * Occurrence keys that hold a protocol field's value.  Their own names
         * say nothing about sensitivity, so they are classified by the field the
         * occurrence came from instead.
         */
        private val VALUE_KEYS = setOf("displayValue", "filterValue", "value")

        private val KNOWN_SCHEMES = listOf(
            "digest", "basic", "bearer", "negotiate", "ntlm", "akav1-md5", "akav2-md5", "aka"
        )

        private val HEX_TOKEN = Regex("(?i)(?:0x)?[0-9a-f]{8,}")
        private val BASE64_TOKEN = Regex("(?=.*\\d)[A-Za-z0-9+/]{12,}={0,2}")

        /**
         * The redactor for one run.
         *
         * A cryptographically random salt scopes the alias map to this run.
         * The capture fingerprint is deliberately not part of it: the
         * fingerprint is sent in local provenance and would let a recipient
         * who sees it brute-force the same aliases offline.
         *
         * [AgentPrivacyMode.LocalOnly] returns an inert instance because
         * nothing leaves the device in that legacy mode. Unredacted metadata
         * still walks the structure so payload and credential fields remain
         * blocked, but identifiers and descriptive text keep their real values.
         */
        fun of(
            privacyMode: AgentPrivacyMode,
            snapshot: AgentCaptureSnapshot
        ): AgentPayloadRedactor {
            if (privacyMode == AgentPrivacyMode.LocalOnly) {
                return AgentPayloadRedactor(null, privacyMode, null)
            }
            val salt = secureRunSalt(snapshot.agentRunGeneration)
            return AgentPayloadRedactor(
                textRedactor = MetadataRedactor(salt),
                privacyMode = privacyMode,
                aliasTable = AliasTable(salt)
            )
        }

        /** An inert redactor, for callers that already decided not to redact. */
        fun disabled(): AgentPayloadRedactor =
            AgentPayloadRedactor(null, AgentPrivacyMode.LocalOnly, null)

        private fun secureRunSalt(generation: Long): String {
            val random = ByteArray(32).also { SecureRandom().nextBytes(it) }
            return buildString(random.size * 2 + 24) {
                random.forEach { append("%02x".format(it.toInt() and 0xff)) }
                append('|')
                append(generation)
            }
        }
    }
}

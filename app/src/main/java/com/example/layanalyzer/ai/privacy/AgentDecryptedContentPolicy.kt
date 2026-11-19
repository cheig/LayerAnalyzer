// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.privacy

import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentPrivacyMode
import java.util.Locale

/**
 * The host-side content policy for TLS-decrypted data (TLS-313, design §11.3).
 *
 * Before TLS decryption a tool result about an HTTPS connection could only ever
 * carry metadata — an address, a port, a protocol name, a length.  Once a
 * keylog is configured the very same tool now reads Cookie headers,
 * `Authorization` values and reassembled request bodies, because Wireshark
 * hands the dissector plaintext.  Nothing about the *tool* changed; what
 * changed is that a field which used to be opaque can now carry a person's
 * data.  This object is where that difference is decided.
 *
 * Two rules, and neither is a prompt instruction a model could decline to
 * follow:
 *
 *  1. **CA material and TLS session secrets have no allow branch.**  A field
 *     that names a keylog line, a client random, a (pre-)master secret or a
 *     private key is withheld in *every* mode, including the explicit-payload
 *     mode and the unredacted-metadata mode.  There is no configuration that
 *     turns this off, because a redacted secret is still the shape of a secret
 *     and a CA private key is never an analysis input.
 *
 *  2. **Decrypted plaintext is excluded from cloud tool output by default.**
 *     A value that a tool marks as coming from a `decrypted_tls` data source is
 *     dropped unless the run is already running under the explicit payload
 *     content policy ([AgentPrivacyMode.SelectedPayload] with
 *     [com.example.layanalyzer.ai.agent.AgentPolicy.allowPayload]).  Turning
 *     capture decryption on does **not** widen the cloud consent the user
 *     already gave; it is a separate, opt-in decision.  When the explicit
 *     policy *is* in force the value is still passed through the field
 *     redactor rather than sent verbatim.
 *
 * The enforcement point is [AgentPayloadRedactor], which runs at
 * `AgentToolRunner.finish` for every successful result — a tool cannot opt out
 * and a new tool cannot forget to opt in.  This object only decides; it never
 * reads a prompt, a tool argument or a capture field to make up its mind.
 */
object AgentDecryptedContentPolicy {

    /** Marker a tool sets on a value that came out of a decrypted TLS source. */
    const val DATA_SOURCE_KEY = "dataSource"

    /** The data-source kind Wireshark reports for decrypted TLS payload. */
    const val DECRYPTED_TLS_SOURCE = "decrypted_tls"

    /** The evidence source label for active-proxy observations (design §11.3). */
    const val APP_TO_PROXY_SOURCE = "app_to_proxy"

    /** Left in place of a decrypted value that the default policy excludes. */
    const val BLOCKED = "PRIVACY_DECRYPTED_BLOCKED"

    /** Left in place of CA/keylog material, which has no allow branch at all. */
    const val WITHHELD = "PRIVACY_NEVER_ALLOWED"

    /** How one value must be handled before it can reach a model. */
    enum class Decision {
        /** Hand the value to the ordinary field table. */
        Allow,

        /** Keep the value's shape out of the payload but still redact its text. */
        Redact,

        /** Drop the value entirely. */
        Block
    }

    /**
     * Whether [privacyMode] under [allowPayload] is the explicit content policy
     * that permits decrypted plaintext to reach a model at all.
     *
     * This mirrors [com.example.layanalyzer.ai.agent.AgentSensitivityPolicy]'s
     * payload gate exactly, so there is one definition of "the user explicitly
     * allowed payload", not two that could drift.
     */
    fun allowsDecryptedPlaintext(
        privacyMode: AgentPrivacyMode,
        allowPayload: Boolean
    ): Boolean = allowPayload && privacyMode == AgentPrivacyMode.SelectedPayload

    /** Whether a tool-marked data source names decrypted TLS payload. */
    fun isDecryptedSource(source: Any?): Boolean =
        (source as? String)?.trim()?.lowercase(Locale.US) == DECRYPTED_TLS_SOURCE

    /**
     * Whether [fieldName] names CA material or a TLS session secret.
     *
     * Classification is by name, never by value: a value-based rule only
     * recognises the secrets it has already seen, so an unanticipated keylog
     * spelling would pass straight through.  The name is matched on its last
     * dotted/underscored segment as well as in full, so `tls.keylog` and
     * `keylog` are both caught.
     */
    fun isNeverAllowed(fieldName: String): Boolean {
        val normalized = fieldName.trim().lowercase(Locale.US)
        if (normalized.isEmpty()) return false
        if (normalized in NEVER_ALLOWED) return true
        val segment = normalized.substringAfterLast('.').substringAfterLast('_')
        return segment in NEVER_ALLOWED
    }

    /**
     * Decide how a value named [fieldName] must be handled.
     *
     * [decryptedOrigin] is true only when the enclosing result object carried
     * [DATA_SOURCE_KEY] = [DECRYPTED_TLS_SOURCE]; an unmarked value falls
     * through to the ordinary field table, whose credential/payload classes
     * already drop the obvious cases.  A never-allowed name wins over
     * everything, so marking a keylog value as decrypted cannot buy it a
     * redact-and-send path.
     */
    fun decision(
        fieldName: String,
        decryptedOrigin: Boolean,
        privacyMode: AgentPrivacyMode,
        allowPayload: Boolean
    ): Decision {
        if (isNeverAllowed(fieldName)) return Decision.Block
        if (!decryptedOrigin) return Decision.Allow
        // Decrypted plaintext never leaves the device in local-only mode, so
        // there is nothing to exclude; every other mode is judged by consent.
        if (privacyMode == AgentPrivacyMode.LocalOnly) return Decision.Allow
        return if (allowsDecryptedPlaintext(privacyMode, allowPayload)) {
            Decision.Redact
        } else {
            Decision.Block
        }
    }

    /**
     * Remove CA material and TLS session secrets from a tool result in **every**
     * mode, including local-only.
     *
     * [AgentPayloadRedactor] is inert in local-only mode (nothing leaves the
     * device, so redacting the user's own evidence would only obscure it), but
     * a keylog line or a private key is never analysis evidence for anyone —
     * design §11.3 makes them a hard exclusion rather than a redaction choice.
     * The tool runner applies this unconditionally before the mode-dependent
     * redactor, so a value under a never-allowed name cannot reach a tool
     * result, a cache entry, a transcript or a report in any configuration.
     */
    fun scrubNeverAllowed(data: AgentJsonObject): AgentJsonObject {
        @Suppress("UNCHECKED_CAST")
        return scrub(data, 0) as AgentJsonObject
    }

    private fun scrub(value: Any?, depth: Int): Any? {
        if (depth > SCRUB_MAX_DEPTH) return value
        return when (value) {
            is Map<*, *> -> {
                val result = LinkedHashMap<String, Any?>(value.size)
                value.forEach { (rawKey, item) ->
                    val key = rawKey as? String ?: return@forEach
                    if (isNeverAllowed(key)) {
                        result[key] = WITHHELD
                        result["${key}Withheld"] = true
                    } else {
                        result[key] = scrub(item, depth + 1)
                    }
                }
                result
            }

            is Iterable<*> -> value.map { item -> scrub(item, depth + 1) }
            else -> value
        }
    }

    /**
     * Names that identify CA material or TLS session secrets.
     *
     * These extend the credential list in [AgentFieldSensitivity] with the
     * vocabulary that only becomes reachable once a keylog is configured.  The
     * list is deliberately exhaustive about the shapes the Wireshark TLS
     * dissector and the NSS key-log format use.
     */
    private val NEVER_ALLOWED: Set<String> = setOf(
        // NSS key-log lines and the correlators they are keyed by.
        "keylog", "key_log", "keylogfile", "keylogfilepath", "nsskeylog",
        "client_random", "server_random", "clientrandom", "serverrandom",
        // TLS 1.2 / 1.3 secrets.
        "pre_master_secret", "premastersecret", "master_secret", "mastersecret",
        "session_key", "sessionkey", "early_secret", "earlysecret",
        "traffic_secret", "trafficsecret", "handshake_secret", "handshakesecret",
        "resumption_secret", "resumptionsecret", "exporter_secret", "exportersecret",
        // CA and leaf private key material.
        "private_key", "privatekey", "ca_private_key", "caprivatekey",
        "privatekeypkcs8", "ca_private_key_pkcs8", "pkcs8"
    )

    /** Recursion cap for [scrubNeverAllowed]; a result must not drive the stack. */
    private const val SCRUB_MAX_DEPTH = 32
}

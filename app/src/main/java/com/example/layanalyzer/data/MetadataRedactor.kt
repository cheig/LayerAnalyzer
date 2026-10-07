// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.data

import java.security.MessageDigest
import java.util.Locale

/**
 * Consistent, length-independent pseudonymization for report and protocol-tree metadata.
 *
 * One instance holds one alias map, so the same input value always yields the
 * same alias for as long as the instance lives.  That is what lets a reader
 * correlate "the same host" across several observations without ever seeing the
 * real value.  The map is in-memory only: it is never persisted and never
 * logged, and a new instance with a different salt produces entirely different
 * aliases for the same inputs.
 *
 * Rule ordering matters.  The IMS rules run before the generic address rules
 * because a SIP URI contains a host that the generic host rule would otherwise
 * rewrite in isolation, splitting one identity into two aliases.
 */
class MetadataRedactor(private val salt: String) {
    private val replacements = linkedMapOf<String, String>()

    /**
     * Every alias this instance has handed out.
     *
     * An alias is itself matchable by the rules that produced it — an aliased
     * IPv4 still looks like an IPv4, an aliased SIP URI still looks like a SIP
     * URI — so without this set a value would be re-aliased and one endpoint
     * would arrive at the model as two apparent identities.  That happens both
     * within a single call, where the IMS rules run before the generic address
     * rules, and across calls, where the privacy layer may redact text a tool
     * already touched.
     *
     * The cost is a deliberate, bounded one: a real capture value that happens
     * to equal an alias already emitted in this run is passed through.  Aliases
     * are drawn from reserved ranges precisely to make that unlikely —
     * `.invalid`, `+1555`, `02:00:00` and `fd00::/8` never appear in real
     * traffic — and only the `10/8` range can realistically collide.  Losing
     * one address to that is a far smaller failure than forking every address
     * into two identities, which would break the correlation the model relies on.
     */
    private val emitted = hashSetOf<String>()

    fun redact(input: String): String {
        var result = input
        // IMS and telecom identifiers first: each owns a whole value that the
        // generic host/IP rules below would otherwise rewrite piecemeal.
        result = redactCredentialHeaders(result)
        result = redactSipHeaders(result)
        result = redactSipUri(result)
        result = redactTelUri(result)
        result = redactLabeledSubscriberIds(result)
        result = redactDiameterSessionId(result)

        result = IPV4.replace(result) { match -> replacement("ip4", match.value) { ipv4Alias(it) } }
        result = MAC.replace(result) { match -> replacement("mac", match.value.lowercase(Locale.US)) { macAlias(it) } }
        result = IPV6.replace(result) { match -> replacement("ip6", match.value.lowercase(Locale.US)) { ipv6Alias(it) } }
        result = URI_HOST.replace(result) { match ->
            val prefix = match.groupValues[1]
            val host = match.groupValues[2]
            prefix + replacement("host", host.lowercase(Locale.US)) { hostAlias(it) }
        }
        result = LABELED_HOST.replace(result) { match ->
            val label = match.groupValues[1]
            val separator = match.groupValues[2]
            val host = match.groupValues[3]
            "$label$separator${replacement("host", host.lowercase(Locale.US)) { hostAlias(it) }}"
        }
        result = USER_IDENTIFIER.replace(result) { match ->
            val label = match.groupValues[1]
            val separator = match.groupValues[2]
            val value = match.groupValues[3]
            "$label$separator${replacement("user", value) { "user-${token(it, 10)}" }}"
        }
        result = BARE_HOSTNAME.replace(result) { match ->
            val host = match.value
            if (isAlias(host) || isReservedName(host)) {
                host
            } else {
                replacement("host", host.lowercase(Locale.US)) { hostAlias(it) }
            }
        }
        return result
    }

    /**
     * Names that look like hosts but carry no identity.
     *
     * Protocol tokens (`SIP/2.0`), Wireshark field abbreviations (`tcp.analysis
     * .retransmission`) and this redactor's own `.invalid` aliases all match a
     * dotted-name shape.  Aliasing a display filter would corrupt the one string
     * the UI is allowed to act on, so the suffix must be a real public TLD
     * before a name is treated as a host.
     */
    private fun isReservedName(value: String): Boolean {
        val lower = value.lowercase(Locale.US)
        if (lower.endsWith(".invalid")) return true
        val tld = lower.substringAfterLast('.')
        return tld !in PUBLIC_SUFFIXES
    }

    /** Whether this instance already produced [value] as an alias. */
    private fun isAlias(value: String): Boolean = value in emitted

    /**
     * Redact a bare identifier value that arrived already isolated from its
     * label, which is the shape a structured field projection produces.
     *
     * [kind] selects the alias vocabulary so a Call-ID and an IMSI cannot
     * collide even when they carry the same digits.
     */
    fun redactValue(kind: IdentifierKind, value: String): String {
        if (value.isBlank()) return value
        return when (kind) {
            IdentifierKind.Address -> redact(value)
            IdentifierKind.CallId -> replacement("callid", value) { "call-${token(it, 12)}@invalid" }
            IdentifierKind.SipUri -> sipUriAlias(value)
            IdentifierKind.Subscriber -> replacement("subscriber", digitsOf(value)) { "subscriber-${token(it, 12)}" }
            IdentifierKind.SessionId -> replacement("session", value) { "session-${token(it, 14)}" }
            IdentifierKind.Opaque -> replacement("opaque", value) { "id-${token(it, 12)}" }
        }
    }

    /**
     * Authorization and friends.  The scheme survives because it is diagnostic
     * and not secret; every parameter after it is dropped rather than aliased,
     * because an alias of a secret still reveals that the secret was there and
     * how long it was.
     */
    private fun redactCredentialHeaders(input: String): String =
        CREDENTIAL_HEADER.replace(input) { match ->
            val label = match.groupValues[1]
            val separator = match.groupValues[2]
            val value = match.groupValues[3].trim()
            val scheme = KNOWN_SCHEMES.firstOrNull { scheme ->
                value.equals(scheme, ignoreCase = true) ||
                    value.startsWith("$scheme ", ignoreCase = true)
            }
            val replacement = when {
                // Already reduced by an earlier pass; re-running must not turn
                // "Digest [redacted]" into "[redacted]" and lose the scheme.
                value.endsWith(REDACTED) -> value
                scheme != null -> "$scheme $REDACTED"
                else -> REDACTED
            }
            "$label$separator$replacement"
        }

    /**
     * SIP identity headers.  Only the URI inside is replaced, so the header name
     * and any display-name punctuation stay readable as protocol structure.
     */
    private fun redactSipHeaders(input: String): String =
        SIP_IDENTITY_HEADER.replace(input) { match ->
            val label = match.groupValues[1]
            val separator = match.groupValues[2]
            val value = match.groupValues[3]
            "$label$separator${redactIdentityValue(value)}"
        }

    /**
     * One SIP identity header value.
     *
     * A display name is aliased in its own right.  `"Alice Smith"
     * <sip:alice@example.com>` would otherwise keep the subscriber's real name
     * after the URI beside it had been replaced, which leaks exactly the
     * identity the URI alias was meant to protect.  The `tag` parameter is
     * aliased too, because it correlates a dialog across a whole capture.
     */
    private fun redactIdentityValue(value: String): String {
        if (isAlias(value.trim())) return value
        var result = DISPLAY_NAME.replace(value) { match ->
            val quoted = match.groupValues[1]
            val bare = match.groupValues[2]
            val name = quoted.ifEmpty { bare }.trim()
            if (name.isEmpty() || name.equals("anonymous", ignoreCase = true) || isAlias(name)) {
                match.value
            } else {
                val alias = replacement("displayname", name.lowercase(Locale.US)) { "name-${token(it, 8)}" }
                if (quoted.isNotEmpty()) "\"$alias\" <" else "$alias <"
            }
        }
        result = redactSipUri(result)
        result = redactTelUri(result)
        result = SIP_TAG.replace(result) { match ->
            val label = match.groupValues[1]
            val tag = match.groupValues[2]
            "$label${replacement("sniptag", tag) { "tag-${token(it, 10)}" }}"
        }
        if (result == value && !value.contains('<')) {
            // No URI, no display name, no tag: a bare token such as a subscriber
            // handle.  Alias the whole value rather than pass it through.
            return replacement("identity", value.trim()) { "identity-${token(it, 12)}" }
        }
        return result
    }

    private fun redactSipUri(input: String): String =
        SIP_URI.replace(input) { match -> sipUriAlias(match.value) }

    /**
     * A SIP or SIPS URI aliased as one identity, then split so the user part and
     * the host part stay independently correlatable.
     *
     * An IP-literal host is routed through the address aliases rather than the
     * host alias, so `sip:bob@192.0.2.10` and a bare `192.0.2.10` elsewhere in
     * the capture resolve to the same alias instead of splitting one endpoint
     * into two apparent identities.
     */
    private fun sipUriAlias(value: String): String {
        val match = SIP_URI.find(value) ?: return replacement("sipuri", value) { "sip:user-${token(it, 10)}@host-${token(it, 10)}.invalid" }
        val scheme = match.groupValues[1].lowercase(Locale.US)
        val user = match.groupValues[2].removeSuffix("@")
        val host = match.groupValues[3]
        val aliasUser = if (user.isEmpty()) {
            ""
        } else {
            replacement("sipuser", user.lowercase(Locale.US)) { "user-${token(it, 10)}" } + "@"
        }
        val aliasHost = when {
            IPV4.matches(host) -> replacement("ip4", host) { ipv4Alias(it) }
            host.startsWith("[") -> {
                val inner = host.removePrefix("[").removeSuffix("]").lowercase(Locale.US)
                "[" + replacement("ip6", inner) { ipv6Alias(it) } + "]"
            }
            else -> replacement("host", host.lowercase(Locale.US)) { hostAlias(it) }
        }
        // The assembled URI is an alias in its own right, so a later pass over
        // this text recognises it and leaves it alone.
        return "$scheme:$aliasUser$aliasHost".also { emitted += it }
    }

    /**
     * A tel URI keeps its shape and a fixed reserved prefix, so a reader can
     * still tell two numbers apart without learning either one.
     */
    private fun redactTelUri(input: String): String =
        TEL_URI.replace(input) { match ->
            val scheme = match.groupValues[1].lowercase(Locale.US)
            val number = digitsOf(match.groupValues[2])
            "$scheme:${replacement("tel", number) { "+1555${token(it, 7)}" }}".also { emitted += it }
        }

    /**
     * IMSI, IMEI, MSISDN, IMPI, IMPU and Call-ID, matched by their label rather
     * than by digit count.  A bare 15-digit run is far more often a timestamp,
     * a sequence number or a byte count than an IMSI, so an unlabelled match
     * would corrupt ordinary metadata while adding no privacy.
     */
    private fun redactLabeledSubscriberIds(input: String): String =
        LABELED_SUBSCRIBER_ID.replace(input) { match ->
            val label = match.groupValues[1]
            val separator = match.groupValues[2]
            val value = match.groupValues[3]
            val kind = label.lowercase(Locale.US).trim()
            // An alias reaching here on a second pass must survive intact; the
            // subscriber branch below strips non-digits, which would otherwise
            // reduce "subscriber-9f3a" to its digits and alias it again.
            val alias = when {
                isAlias(value) -> value
                kind.startsWith("call") -> redactValue(IdentifierKind.CallId, value)
                kind == "impu" || kind == "impi" || value.contains('@') -> redactIdentityValue(value)
                else -> replacement("subscriber", digitsOf(value)) { "subscriber-${token(it, 12)}" }
            }
            "$label$separator$alias"
        }

    private fun redactDiameterSessionId(input: String): String =
        DIAMETER_SESSION_ID.replace(input) { match ->
            val label = match.groupValues[1]
            val separator = match.groupValues[2]
            val value = match.groupValues[3]
            "$label$separator${replacement("session", value) { "session-${token(it, 14)}" }}"
        }

    private fun digitsOf(value: String): String =
        value.filter(Char::isDigit).ifEmpty { value.trim() }

    /** Identifier families that carry their own alias vocabulary. */
    enum class IdentifierKind {
        /** An IP address, MAC, host name or endpoint label. */
        Address,
        CallId,
        SipUri,
        /** IMSI, IMEI, MSISDN, IMPI or IMPU. */
        Subscriber,
        /** Diameter Session-Id and other core-network session correlators. */
        SessionId,
        /** A correlator whose family is not known; aliased opaquely. */
        Opaque
    }

    internal fun mappingSize(): Int = replacements.size

    /**
     * The stable alias for one value, minted on first sight.
     *
     * A value that is already an alias is returned unchanged, which is what
     * makes redaction idempotent: running this over its own output is a no-op
     * rather than a second substitution.
     */
    private fun replacement(type: String, value: String, alias: (String) -> String): String {
        if (isAlias(value)) return value
        return replacements.getOrPut("$type:$value") {
            alias(value).also { minted -> emitted += minted }
        }
    }

    private fun ipv4Alias(value: String): String {
        val bytes = digest("ip4:$value")
        return "10.${bytes[0].positive().coerceIn(1, 254)}.${bytes[1].positive()}.${bytes[2].positive()}"
    }

    private fun ipv6Alias(value: String): String {
        val hex = token("ip6:$value", 12)
        return "fd00:${hex.substring(0, 4)}:${hex.substring(4, 8)}:${hex.substring(8, 12)}::1"
    }

    private fun macAlias(value: String): String {
        val bytes = digest("mac:$value")
        return "02:00:00:%02x:%02x:%02x".format(bytes[0].positive(), bytes[1].positive(), bytes[2].positive())
    }

    private fun hostAlias(value: String): String = "host-${token("host:$value", 10)}.invalid"

    private fun token(value: String, length: Int): String = digest(value).joinToString("") { "%02x".format(it.positive()) }.take(length)

    private fun digest(value: String): ByteArray = MessageDigest.getInstance("SHA-256")
        .digest("$salt:$value".toByteArray(Charsets.UTF_8))

    private fun Byte.positive(): Int = toInt() and 0xff

    private companion object {
        /** Stand-in for a credential value; also the marker an idempotent re-run looks for. */
        const val REDACTED = "[redacted]"

        val IPV4 = Regex("(?<![A-Za-z0-9:])(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)(?:\\.(?:25[0-5]|2[0-4]\\d|1?\\d?\\d)){3}(?![A-Za-z0-9:])")
        val MAC = Regex("(?i)(?<![0-9a-f])(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}(?![0-9a-f])")
        val IPV6 = Regex("(?i)(?<![0-9a-f:])(?:[0-9a-f]{1,4}:){2,7}[0-9a-f]{0,4}(?![0-9a-f:])")
        val URI_HOST = Regex("(?i)(https?://)(\\[[0-9a-f:]+]|[^/:\\s]+)")
        val LABELED_HOST = Regex("(?i)\\b(host|sni|server_name|http\\.host)(\\s*[:=]\\s*)([^\\s,;]+)")
        /**
         * Generic user labels.  IMSI, IMEI, MSISDN and Call-ID are deliberately
         * absent: [LABELED_SUBSCRIBER_ID] runs first and already aliased them,
         * and matching them twice would alias the alias, giving one subscriber
         * two identities in the same session.
         */
        val USER_IDENTIFIER = Regex("(?i)\\b(user(?:name)?|subscriber)(\\s*[:=]\\s*)([^\\s,;]+)")

        /**
         * A SIP or SIPS URI.  The user part is optional because `sip:host` is
         * legal and appears in Route and Via headers.
         */
        val SIP_URI = Regex("(?i)\\b(sips?):((?:[^@\\s<>,;:]+)@)?([A-Za-z0-9._-]+|\\[[0-9A-Fa-f:]+])")

        val TEL_URI = Regex("(?i)\\b(tel):(\\+?[0-9][0-9().\\s-]{4,})")

        /**
         * SIP identity headers whose value is a URI or a display name.  Via and
         * Route are deliberately absent: they carry proxy topology rather than
         * subscriber identity, and the generic host rule already covers them.
         *
         * Semicolons stay inside the value so the `;tag=` parameter is part of
         * the match and reaches [SIP_TAG]; a tag left in place correlates one
         * dialog across the whole capture.
         */
        val SIP_IDENTITY_HEADER = Regex(
            "(?i)\\b(from|to|contact|p-asserted-identity|p-preferred-identity|p-called-party-id|" +
                "referred-by|remote-party-id)(\\s*[:=]\\s*)([^\\r\\n,]+)"
        )

        /**
         * Subscriber identifiers, always label-anchored.  `impu`/`impi` values
         * are usually URIs and are routed to the identity path by the caller.
         */
        val LABELED_SUBSCRIBER_ID = Regex(
            "(?i)\\b(imsi|imei|imeisv|msisdn|impi|impu|supi|suci|gpsi|" +
                "call-?id|private-?identity|public-?identity)(\\s*[:=]\\s*)([^\\s,;<>]+)"
        )

        /**
         * Diameter Session-Id and the core-network correlators shaped like it.
         *
         * A Diameter Session-Id is `host;high;low;optional` — semicolons are
         * part of one value, so the value class must accept them or the tail
         * (which carries the actual per-session entropy) survives unaliased.
         * Whitespace and comma still terminate it.
         */
        val DIAMETER_SESSION_ID = Regex(
            "(?i)\\b(session-?id|diameter\\.session-?id|teid|gtp\\.teid|amf-?ue-?ngap-?id|" +
                "ran-?ue-?ngap-?id|enb-?ue-?s1ap-?id|mme-?ue-?s1ap-?id|guti|s-?tmsi)(\\s*[:=]\\s*)([^\\s,]+)"
        )

        /**
         * Credential headers.  Matching stops at a line break rather than a
         * comma, because a Digest challenge is one comma-separated value list
         * and every parameter in it must be dropped together.
         */
        val CREDENTIAL_HEADER = Regex(
            "(?i)\\b(authorization|proxy-authorization|www-authenticate|proxy-authenticate|" +
                "authentication-info|set-cookie|cookie)(\\s*[:=]\\s*)([^\\r\\n]+)"
        )

        /** Schemes safe to echo as a bare label; anything else is dropped whole. */
        val KNOWN_SCHEMES = listOf("Digest", "Basic", "Bearer", "Negotiate", "NTLM", "AKAv1-MD5", "AKAv2-MD5")

        /**
         * The display name in front of a bracketed SIP URI, quoted or bare.
         * Anchored on the `<` so it cannot match ordinary prose.
         */
        val DISPLAY_NAME = Regex("(?:\"([^\"]*)\"|([A-Za-z][A-Za-z0-9._'-]*(?:\\s+[A-Za-z0-9._'-]+)*))\\s*<")

        /** The dialog-correlating tag parameter on a From or To header. */
        val SIP_TAG = Regex("(?i)(;\\s*tag\\s*=\\s*)([^\\s;>,]+)")

        /**
         * A dotted host name appearing anywhere in free text.
         *
         * Info columns and Expert labels write hosts in prose — `to host
         * api.example.com`, `Server Name: cdn.example.net` — where the labelled
         * rules above, which need `label=value`, do not reach.  Matches are
         * filtered against a public-suffix list before being aliased so that
         * `SIP/2.0` and `tcp.analysis.retransmission` survive intact.
         */
        val BARE_HOSTNAME = Regex(
            "(?<![A-Za-z0-9._@:/-])(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\\.)+[A-Za-z]{2,24}(?![A-Za-z0-9.-])"
        )

        /**
         * Suffixes that make a dotted name a real host rather than a protocol
         * token.  Deliberately short: an unlisted TLD means a name is passed
         * through, and the labelled rules still catch it when it appears as
         * `host=`, in a URI, or inside a SIP header.
         */
        val PUBLIC_SUFFIXES: Set<String> = setOf(
            "com", "net", "org", "edu", "gov", "mil", "int", "info", "biz", "io", "co",
            "cn", "us", "uk", "de", "fr", "jp", "kr", "ru", "in", "br", "au", "ca", "nl",
            "se", "no", "fi", "dk", "pl", "it", "es", "ch", "at", "be", "cz", "gr", "pt",
            "tr", "mx", "ar", "za", "sg", "hk", "tw", "th", "vn", "id", "my", "ph",
            "app", "dev", "cloud", "online", "site", "tech", "xyz", "me", "tv", "cc",
            "local", "lan", "internal", "corp", "home", "arpa"
        )
    }
}

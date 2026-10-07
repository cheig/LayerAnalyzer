package com.example.layanalyzer.ai.privacy

import com.example.layanalyzer.data.MetadataRedactor
import com.example.layanalyzer.model.AgentDataSensitivity
import java.util.Locale

/**
 * Which privacy class a single field belongs to, and how it should be aliased.
 *
 * AI-11 requires per-field handling rather than per-result handling: a tool
 * declares the *highest* sensitivity it can return, but a single result mixes
 * classes freely — `get_statistics` reports packet counts (Aggregate) beside
 * endpoint addresses (Identifier) in one object.  Classifying at the field level
 * is what stops a tool from labelling a whole result `Aggregate` and carrying
 * identifiers out under it.
 *
 * Classification is by **name**, never by value.  A value-based rule only
 * recognises the secrets it has already seen, so a nonce format nobody
 * anticipated would pass straight through.  A name-based rule fails the other
 * way: an unrecognised field is treated as capture text and still gets the text
 * fallback, so the failure mode is an unnecessary alias rather than a leak.
 */
object AgentFieldSensitivity {

    /**
     * How a field's value must be transformed before it can leave the device.
     */
    sealed interface Handling {
        /** Safe as-is: counts, durations, protocol names, booleans. */
        object Keep : Handling

        /** Replace with a stable alias drawn from [kind]'s vocabulary. */
        data class Alias(val kind: MetadataRedactor.IdentifierKind) : Handling

        /**
         * A field not yet in the table. Its value gets text redaction and an
         * opaque-token fallback, so safe structural strings remain readable
         * while naked identifiers do not pass through unchanged.
         */
        object Unclassified : Handling

        /**
         * Free capture text.  Structured rules cannot enumerate what a dissector
         * puts in an Info column, so the whole string goes through the text
         * redactor and whatever it recognises is aliased.
         */
        object Text : Handling

        /** Drop the value; report existence only. */
        object Credential : Handling

        /** Packet bytes or a reassembled body: never emitted in any mode. */
        object Payload : Handling
    }

    /**
     * The privacy class of [fieldName], where the name may be either a wire DTO
     * key (`endpointA`, `callId`) or a Wireshark field abbreviation (`ip.src`,
     * `sip.Call-ID`).
     */
    fun classify(fieldName: String): AgentDataSensitivity = when (handling(fieldName)) {
        Handling.Keep -> AgentDataSensitivity.Aggregate
        Handling.Text -> AgentDataSensitivity.Metadata
        is Handling.Alias -> AgentDataSensitivity.Identifier
        Handling.Unclassified -> AgentDataSensitivity.Identifier
        Handling.Credential -> AgentDataSensitivity.Credential
        Handling.Payload -> AgentDataSensitivity.Payload
    }

    /**
     * How to transform [fieldName]'s value.
     *
     * Both the full dotted name and its last segment are consulted, so
     * `sip.Authorization` and `http.authorization` resolve without a per-protocol
     * entry, while a fully-qualified name that needs its own rule can still have
     * one.
     */
    fun handling(fieldName: String): Handling {
        val normalized = fieldName.trim().lowercase(Locale.US)
        if (normalized.isEmpty()) return Handling.Text

        FULL_NAME_RULES[normalized]?.let { return it }

        val segment = normalized.substringAfterLast('.').substringAfterLast('_')

        // Credential first: a name that looks like both a credential and an
        // identifier is a credential, because dropping a value is always safe
        // and aliasing one is not.
        if (segment in CREDENTIAL_SEGMENTS || normalized in CREDENTIAL_SEGMENTS) return Handling.Credential
        if (segment in PAYLOAD_SEGMENTS || normalized in PAYLOAD_SEGMENTS) return Handling.Payload

        IDENTIFIER_SEGMENTS[segment]?.let { return Handling.Alias(it) }
        IDENTIFIER_SEGMENTS[normalized]?.let { return Handling.Alias(it) }

        if (segment in AGGREGATE_SEGMENTS || normalized in AGGREGATE_SEGMENTS) return Handling.Keep
        if (segment in TEXT_SEGMENTS || normalized in TEXT_SEGMENTS) return Handling.Text

        // Unknown field: treat as capture text.  The text redactor aliases any
        // address or identifier it recognises inside, so an unanticipated field
        // costs a redundant scan rather than a leak.
        return Handling.Unclassified
    }

    /** Whether a field must never carry its value off the device. */
    fun isCredential(fieldName: String): Boolean = handling(fieldName) == Handling.Credential

    /** Whether a field names packet bytes or a reassembled body. */
    fun isPayload(fieldName: String): Boolean = handling(fieldName) == Handling.Payload

    /**
     * Names whose last segment is misleading and need the whole name to decide.
     */
    private val FULL_NAME_RULES: Map<String, Handling> = mapOf(
        // "frame.number" ends in a generic segment but is a plain index.
        "frame.number" to Handling.Keep,
        "framenumber" to Handling.Keep,
        // A display filter is host-validated syntax, not capture text; aliasing
        // it would corrupt the one string the UI is allowed to make clickable.
        "displayfilter" to Handling.Keep,
        "filter" to Handling.Keep,
        // Ports are structural and low-entropy; aliasing them would destroy the
        // "which service" signal while protecting nothing.
        "sourceport" to Handling.Keep,
        "destinationport" to Handling.Keep,
        "porta" to Handling.Keep,
        "portb" to Handling.Keep,
        // frame.len is a length, not the frame contents.
        "frame.len" to Handling.Keep,
        // The realm identifies the operator, so it is an identifier even though
        // it arrives inside a credential header.
        "realm" to Handling.Alias(MetadataRedactor.IdentifierKind.Address),
        "sip.auth.realm" to Handling.Alias(MetadataRedactor.IdentifierKind.Address),
        "diameter.originrealm" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "diameter.destinationrealm" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "originrealm" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "destinationrealm" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "nodeid" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        // Host provenance stays local; if it is ever projected, it must not
        // travel in cleartext beside aliases.
        "capturefingerprint" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "cellidalias" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "radio.cellidalias" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "beforecellidalias" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "aftercellidalias" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "apnordnn" to Handling.Alias(MetadataRedactor.IdentifierKind.Opaque),
        "subscriber.id" to Handling.Alias(MetadataRedactor.IdentifierKind.Subscriber),
        "subscriberid" to Handling.Alias(MetadataRedactor.IdentifierKind.Subscriber),
        "cseqnumber" to Handling.Keep,
        "cseqmethod" to Handling.Keep,
        "authorizationpresent" to Handling.Keep,
        "authorizationscheme" to Handling.Keep,
        "contenttype" to Handling.Keep,
        "encodingname" to Handling.Keep,
        "clockrate" to Handling.Keep,
        "payloadtype" to Handling.Keep,
        "fmtpparameters" to Handling.Keep
    )

    /**
     * Values that are secrets.  Mirrors the AI-09 credential list and extends it
     * with the IMS authentication parameters from AI-11 section 3.3.
     */
    private val CREDENTIAL_SEGMENTS: Set<String> = setOf(
        "authorization", "proxy-authorization", "www-authenticate", "proxy-authenticate",
        "authentication-info", "auth", "cookie", "set-cookie",
        "password", "passwd", "passphrase", "secret",
        "token", "access_token", "refresh_token", "apikey", "api_key",
        "nonce", "cnonce", "nextnonce", "digest", "response",
        "session_key", "pre_master_secret", "master_secret",
        // IMS / AKA
        "autn", "rand", "res", "xres", "ck", "ik", "kasme", "auts",
        "integrity", "integrity-key", "ciphering", "ciphering-key", "confidentiality-key",
        "credential"
    )

    /** Packet bytes and reassembled bodies. */
    private val PAYLOAD_SEGMENTS: Set<String> = setOf(
        "data", "payload", "body", "content", "bytes", "raw",
        "frame.data", "tcp.payload", "udp.payload", "sip.msg_body"
    )

    /**
     * Identifier fields mapped to the alias vocabulary they belong to.
     *
     * The vocabulary matters: aliasing a Call-ID with the address vocabulary
     * would make it look like a host name to the model, and two different
     * identifier families sharing one vocabulary could collide.
     */
    private val IDENTIFIER_SEGMENTS: Map<String, MetadataRedactor.IdentifierKind> = mapOf(
        // Addresses and hosts
        "src" to MetadataRedactor.IdentifierKind.Address,
        "dst" to MetadataRedactor.IdentifierKind.Address,
        "source" to MetadataRedactor.IdentifierKind.Address,
        "destination" to MetadataRedactor.IdentifierKind.Address,
        "address" to MetadataRedactor.IdentifierKind.Address,
        "addr" to MetadataRedactor.IdentifierKind.Address,
        "ip" to MetadataRedactor.IdentifierKind.Address,
        "host" to MetadataRedactor.IdentifierKind.Address,
        "hostname" to MetadataRedactor.IdentifierKind.Address,
        "sni" to MetadataRedactor.IdentifierKind.Address,
        "server_name" to MetadataRedactor.IdentifierKind.Address,
        "endpointa" to MetadataRedactor.IdentifierKind.Address,
        "endpointb" to MetadataRedactor.IdentifierKind.Address,
        "connectionaddress" to MetadataRedactor.IdentifierKind.Address,
        "eth" to MetadataRedactor.IdentifierKind.Address,
        "mac" to MetadataRedactor.IdentifierKind.Address,
        "domain" to MetadataRedactor.IdentifierKind.Address,
        "qry" to MetadataRedactor.IdentifierKind.Address,

        // SIP / IMS identities
        "uri" to MetadataRedactor.IdentifierKind.SipUri,
        "requesturi" to MetadataRedactor.IdentifierKind.SipUri,
        "fromtag" to MetadataRedactor.IdentifierKind.Opaque,
        "totag" to MetadataRedactor.IdentifierKind.Opaque,
        "viabranch" to MetadataRedactor.IdentifierKind.Opaque,
        "from" to MetadataRedactor.IdentifierKind.SipUri,
        "to" to MetadataRedactor.IdentifierKind.SipUri,
        "contact" to MetadataRedactor.IdentifierKind.SipUri,
        "p-asserted-identity" to MetadataRedactor.IdentifierKind.SipUri,
        "p-preferred-identity" to MetadataRedactor.IdentifierKind.SipUri,
        "impu" to MetadataRedactor.IdentifierKind.SipUri,
        "impi" to MetadataRedactor.IdentifierKind.SipUri,

        "call-id" to MetadataRedactor.IdentifierKind.CallId,
        "callid" to MetadataRedactor.IdentifierKind.CallId,

        // Subscriber identities
        "imsi" to MetadataRedactor.IdentifierKind.Subscriber,
        "imei" to MetadataRedactor.IdentifierKind.Subscriber,
        "imeisv" to MetadataRedactor.IdentifierKind.Subscriber,
        "msisdn" to MetadataRedactor.IdentifierKind.Subscriber,
        "supi" to MetadataRedactor.IdentifierKind.Subscriber,
        "suci" to MetadataRedactor.IdentifierKind.Subscriber,
        "gpsi" to MetadataRedactor.IdentifierKind.Subscriber,
        "subscriber" to MetadataRedactor.IdentifierKind.Subscriber,
        "user" to MetadataRedactor.IdentifierKind.Subscriber,
        "username" to MetadataRedactor.IdentifierKind.Subscriber,

        // Core-network session correlators
        "session-id" to MetadataRedactor.IdentifierKind.SessionId,
        "sessionid" to MetadataRedactor.IdentifierKind.SessionId,
        "seid" to MetadataRedactor.IdentifierKind.SessionId,
        "teid" to MetadataRedactor.IdentifierKind.SessionId,
        "bearerid" to MetadataRedactor.IdentifierKind.SessionId,
        "ueid" to MetadataRedactor.IdentifierKind.SessionId,
        "mmeueid" to MetadataRedactor.IdentifierKind.SessionId,
        "enbueid" to MetadataRedactor.IdentifierKind.SessionId,
        "amfueid" to MetadataRedactor.IdentifierKind.SessionId,
        "ranueid" to MetadataRedactor.IdentifierKind.SessionId,
        "guti" to MetadataRedactor.IdentifierKind.SessionId,
        "s-tmsi" to MetadataRedactor.IdentifierKind.SessionId,
        "correlationvalue" to MetadataRedactor.IdentifierKind.SessionId,

        // Opaque per-stream correlators.  Worth aliasing because an SSRC tracks
        // one media stream across a whole capture.
        "ssrc" to MetadataRedactor.IdentifierKind.Opaque,
        "tag" to MetadataRedactor.IdentifierKind.Opaque,
        "branch" to MetadataRedactor.IdentifierKind.Opaque
    )

    /** Structural and numeric fields, safe verbatim. */
    private val AGGREGATE_SEGMENTS: Set<String> = setOf(
        "framenumber", "frame", "number", "index", "count", "total", "returned",
        "packetcount", "framecount", "bytecount", "itemcount", "totalcount",
        "returnedcount", "errorpackets", "warningpackets", "streamcount",
        "packets", "bytes", "length", "len", "size", "offset", "limit",
        "time", "absolutetime", "relativetime", "starttime", "endtime", "duration",
        "protocol", "proto", "severity", "type", "kind", "direction", "state",
        "port", "streamid", "truncated", "present", "valid", "available",
        "detailavailable", "generated", "hidden", "scheme",
        "version", "status", "statuscode", "code", "method", "reason",
        "commandcode", "applicationid", "request", "resultcode", "experimentalresult",
        "sequencenumber", "cause", "procedurecode", "proceduretransactionidentity",
        "registrationstate", "sessionstate", "proceduretype", "localcorrelationid",
        "correlationid", "correlationquality", "confidence", "confidencescore",
        "fieldpresence", "fromnodeid", "tonodeid",
        "rat", "sourceclock", "normalizedclock", "sourceframes", "manualoffsetmillis",
        "timeuncertaintymillis", "uncertaintystarttime", "uncertaintyendtime",
        "normalizedstarttime", "normalizedendtime",
        "eventtotal", "eventtruncated", "temporalcorrelationtotal",
        "radioavailable", "supportssnapshots", "supportsevents",
        "packetsa", "packetsb", "bytesa", "bytesb", "min", "max", "mean", "avg",
        "jitter", "loss", "mos", "rtt", "bucketseconds", "sort", "mode"
    )

    /** Free capture text that must go through the text redactor. */
    private val TEXT_SEGMENTS: Set<String> = setOf(
        "info", "label", "summary", "description", "detail", "observation",
        "comment", "note", "message", "text", "value", "displayvalue", "filtervalue"
    )
}

// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture

import android.content.Context
import com.example.layanalyzer.model.LiveCaptureSettings
import com.example.layanalyzer.model.QUIC_UDP_PORT
import com.example.layanalyzer.model.QuicPolicy
import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsJson
import com.example.layanalyzer.model.TlsCaptureSettingsValidator
import com.example.layanalyzer.model.TlsSettingsIssueCode
import com.example.layanalyzer.model.TlsSettingsValidation
import org.json.JSONArray
import org.json.JSONObject
import org.json.JSONTokener

/**
 * The narrow persistence seam for the VPN capture settings (TLS-304).
 *
 * `PacketListViewModel` can only be built with a `Context`, and this project has
 * no Robolectric, so the file/key handling is behind this one-method-each
 * interface: the production implementation is [SharedPreferencesCaptureSettingsPersistence]
 * and a JVM test can supply an in-memory one. No key material ever crosses it —
 * TLS settings carry host rules and ports, not secrets.
 */
internal interface CaptureSettingsPersistence {
    fun read(): String?
    fun write(json: String)
}

/** Production implementation: one SharedPreferences file, one key. */
internal class SharedPreferencesCaptureSettingsPersistence(
    context: Context
) : CaptureSettingsPersistence {
    private val preferences =
        context.applicationContext.getSharedPreferences(FILE_NAME, Context.MODE_PRIVATE)

    override fun read(): String? = preferences.getString(KEY, null)

    override fun write(json: String) {
        preferences.edit().putString(KEY, json).apply()
    }

    companion object {
        const val FILE_NAME = "live_capture_settings"
        const val KEY = "settings"
    }
}

/**
 * The capture settings document. The TLS block is nested under `tls` and read
 * through [TlsCaptureSettingsJson.decodeCaptureSettings], so this file never
 * re-implements C04 validation: an unknown enum, an out-of-range port or a
 * damaged host rule inside `tls` decodes to TLS off.
 *
 * A document written before the TLS block existed simply has no `tls` key and
 * therefore also decodes to TLS off — the migration is "off", never "all apps".
 */
internal object LiveCaptureSettingsJson {
    fun encode(settings: LiveCaptureSettings): String = JSONObject()
        .put("schemaVersion", 1)
        .put("excludeSelf", settings.excludeSelf)
        .put("captureIpv6", settings.captureIpv6)
        .put("maxDurationMinutes", settings.maxDurationMinutes)
        .put("maxSizeMegabytes", settings.maxSizeMegabytes)
        .put("segmentSizeMegabytes", settings.segmentSizeMegabytes)
        .put("allowedApplications", JSONArray(settings.allowedApplications))
        .put("tls", JSONObject(TlsCaptureSettingsJson.encode(settings.tls)))
        .toString()

    /** Total: unreadable or damaged documents fall back to the compile-time defaults. */
    fun decode(json: String?): LiveCaptureSettings {
        val source = json ?: return LiveCaptureSettings()
        val root = readObject(source) ?: return LiveCaptureSettings()
        val applications = strings(root, "allowedApplications")
        return LiveCaptureSettings(
            excludeSelf = boolean(root, "excludeSelf", true),
            captureIpv6 = boolean(root, "captureIpv6", false),
            maxDurationMinutes = positiveInt(root, "maxDurationMinutes", 15),
            maxSizeMegabytes = positiveInt(root, "maxSizeMegabytes", 256),
            segmentSizeMegabytes = positiveInt(root, "segmentSizeMegabytes", 64),
            allowedApplications = applications,
            // The allowlist from the same document is what the TLS scope is checked
            // against, so a corrupted file cannot smuggle in a broader scope.
            tls = TlsCaptureSettingsJson.decodeCaptureSettings(source, applications).settings
        )
    }

    private fun readObject(json: String?): JSONObject? {
        if (json == null) return null
        return try {
            val tokens = JSONTokener(json)
            val value = tokens.nextValue()
            if (value is JSONObject && tokens.nextClean() == '\u0000') value else null
        } catch (_: Exception) {
            null
        }
    }

    private fun boolean(root: JSONObject, field: String, default: Boolean): Boolean =
        if (!root.has(field)) default else (root.opt(field) as? Boolean) ?: default

    private fun positiveInt(root: JSONObject, field: String, default: Int): Int =
        if (!root.has(field)) default else ((root.opt(field) as? Number)?.toInt() ?: default).coerceAtLeast(1)

    private fun strings(root: JSONObject, field: String): List<String> {
        val array = root.opt(field) as? JSONArray ?: return emptyList()
        return (0 until array.length()).mapNotNull { array.opt(it) as? String }
    }
}

/**
 * Reads and writes the capture settings document. [save] is the single mutation:
 * a draft that is never committed leaves the stored value byte-for-byte intact,
 * which is what "cancelling an edit does not overwrite the saved settings" means.
 */
internal class LiveCaptureSettingsStore(
    private val persistence: CaptureSettingsPersistence
) {
    fun load(): LiveCaptureSettings = LiveCaptureSettingsJson.decode(persistence.read())

    fun save(settings: LiveCaptureSettings) {
        persistence.write(LiveCaptureSettingsJson.encode(settings))
    }
}

/**
 * The decisions the settings UI and the start path share, kept as a pure object
 * so they run without a `Context` (C04, design §12 rule precedence).
 *
 * Only [TlsCaptureSettingsValidator] decides what is valid; this never validates
 * a second way. [frozenForCapture] is the "freeze at capture start" from the
 * card: the run gets one immutable, normalized configuration.
 */
internal object TlsInterceptionPolicy {
    fun validation(settings: LiveCaptureSettings): TlsSettingsValidation =
        TlsCaptureSettingsValidator.validate(settings.tls, settings.allowedApplications)

    /** TLS off is always allowed; an enabled interception needs a valid configuration. */
    fun canStart(settings: LiveCaptureSettings): Boolean =
        !settings.tls.enabled || validation(settings).isValid

    /**
     * The frozen configuration a capture would start with, or null when an
     * enabled interception is invalid. Null is a refusal, never a silent downgrade
     * to "capture without decryption" (C03 7): the caller must not start the MITM.
     */
    fun frozenForCapture(settings: LiveCaptureSettings): LiveCaptureSettings? {
        val validation = validation(settings)
        if (settings.tls.enabled && !validation.isValid) return null
        return settings.copy(tls = validation.settings)
    }

    /** The tools a user sees while TLS is enabled but unusable, without echoing rule text. */
    fun blockedReasonCodes(settings: LiveCaptureSettings): List<String> =
        if (settings.tls.enabled) validation(settings).issues.map { it.code.wireName } else emptyList()

    /**
     * The QUIC policy a run actually applies (TLS-314).
     *
     * TLS off means `Preserve` whatever the document remembers, because "no
     * interception" must keep the original forwarding byte for byte (C03 1): a
     * stored `BlockSelectedUdp443` is a choice for the next enabled run, not a
     * standing device-wide rule. Both the rule handed to the SOCKS server and the
     * policy named in the report are read from this one function, so they can
     * never say different things.
     */
    fun appliedQuicPolicy(tls: TlsCaptureSettings): QuicPolicy =
        if (tls.enabled) tls.quicPolicy else QuicPolicy.Preserve

    /**
     * The forwarding-layer rule for one run: the destination-port screen applied
     * to outbound UDP, including both address families, or
     * [UdpDestinationPolicy.PRESERVE].
     *
     * The rule is destination-port only. The scope it can honour is therefore
     * "everything this VPN routes", which the VpnService allowlist has already
     * restricted to the selected applications — that is the "selected
     * applications" scope of design §10.1, and it is a real forwarding-layer rule
     * rather than a display filter. Expressing it in terms of an HTTPS host name
     * is impossible here (no UID, no SNI), which is why
     * [TlsSettingsIssueCode.QUIC_SCOPE_UNDECIDABLE] refuses the mode for any
     * configuration whose scope is not exactly that one.
     */
    fun udpPolicy(tls: TlsCaptureSettings): UdpDestinationPolicy =
        when (appliedQuicPolicy(tls)) {
            QuicPolicy.Preserve -> UdpDestinationPolicy.PRESERVE
            QuicPolicy.BlockSelectedUdp443 -> UdpDestinationPolicy { _, port ->
                if (port == QUIC_UDP_PORT) UdpVerdict.BlockSelectedUdp443 else UdpVerdict.Forward
            }
        }
}

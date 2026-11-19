// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.capture.tls

import com.example.layanalyzer.model.TlsCaptureSettings
import com.example.layanalyzer.model.TlsCaptureSettingsValidator
import com.example.layanalyzer.model.TlsHostRule
import com.example.layanalyzer.model.TlsHostScope
import org.json.JSONArray
import org.json.JSONObject

/**
 * The candidate screen the SOCKS hop applies before it reserves anything. It is
 * the same screen the Go decision maker applies first, so a connection this
 * side drops and a connection Go calls out of scope can never disagree.
 */
enum class TlsRoutingPrefilter(val wireName: String) {
    Candidate("candidate"),
    Disabled("disabled"),
    PortNotCandidate("port_not_candidate"),
    ApplicationNotSelected("application_not_selected")
}

/**
 * The frozen rule kinds. They are the Go side's `RuleKind` wire names and are
 * deliberately not derived from an ordinal.
 */
internal val TlsHostRule.wireKind: String
    get() = when (this) {
        is TlsHostRule.ExactDomain -> "exactDomain"
        is TlsHostRule.Subdomains -> "subdomains"
        is TlsHostRule.ExactIp -> "exactIp"
    }

/** A subdomain rule's frozen value is the bare domain, without the wildcard. */
internal val TlsHostRule.frozenValue: String
    get() = when (this) {
        is TlsHostRule.Subdomains -> domain
        else -> normalized
    }

/** The text a user's rule must already be in for the frozen form to carry it. */
internal val TlsHostRule.canonicalText: String
    get() = when (this) {
        is TlsHostRule.Subdomains -> "*.$domain"
        else -> normalized
    }

/**
 * One capture's frozen interception policy.
 *
 * Kotlin normalizes and freezes; it never decides. The Go side is the sole
 * decision maker (TLS-208), because a second place that ranked domain rules
 * could disagree with it about the same connection. What lives here is the
 * input half of that contract: rules are parsed once, in their canonical form,
 * and encoded as the object the Go engine parses.
 *
 * A policy is immutable. [freeze] is the only way to build one, so a capture
 * cannot have its rules changed while it runs: a settings change produces a new
 * policy for the next capture.
 */
class TlsRoutingPolicy private constructor(
    val enabled: Boolean,
    val hostScope: TlsHostScope,
    val candidatePorts: Set<Int>,
    val include: List<TlsHostRule>,
    val bypass: List<TlsHostRule>,
    val applications: Set<String>
) {
    /**
     * The frozen form. Its field names, canonical rule texts and ordering are
     * the interface the Go decision maker validates, so a change here has to be
     * a change in both halves at once. The shared fixture in
     * `native_build/verification/tls/routing-policy/policy-cases.json` pins it.
     */
    fun encode(): String = JSONObject()
        .put("schemaVersion", FROZEN_SCHEMA_VERSION)
        .put("enabled", enabled)
        .put("hostScope", hostScope.wireName)
        .put("candidatePorts", JSONArray(candidatePorts.sorted()))
        .put("include", encodeRules(include))
        .put("bypass", encodeRules(bypass))
        .put("applications", JSONArray(applications.sorted()))
        .toString()

    /**
     * The port and application screen. Passing it only means the connection is
     * worth probing: the name is not known until the ClientHello, so no rule is
     * applied here and none may be.
     *
     * [application] is the VPN allowlist entry for the connection source. SOCKS5
     * carries no application identity, so an unknown or missing value is never
     * widened to "every application"; it is simply not selected.
     */
    fun prefilter(destinationPort: Int, application: String?): TlsRoutingPrefilter {
        return prefilter(destinationPort, application, vpnScopeEnforced = false)
    }

    /**
     * For the authenticated TUN/SOCKS path only: VpnService already enforces
     * this run's application allowlist. Membership in that scope does not imply
     * that an individual connection can be attributed to a particular app.
     */
    internal fun prefilterVpnTraffic(destinationPort: Int): TlsRoutingPrefilter =
        prefilter(destinationPort, application = null, vpnScopeEnforced = true)

    private fun prefilter(
        destinationPort: Int,
        application: String?,
        vpnScopeEnforced: Boolean
    ): TlsRoutingPrefilter {
        if (!enabled) return TlsRoutingPrefilter.Disabled
        if (destinationPort !in candidatePorts) return TlsRoutingPrefilter.PortNotCandidate
        if (hostScope == TlsHostScope.SelectedApplicationsCandidates) {
            val selected = (application != null && application in applications) ||
                (vpnScopeEnforced && applications.isNotEmpty())
            if (!selected) return TlsRoutingPrefilter.ApplicationNotSelected
        }
        return TlsRoutingPrefilter.Candidate
    }

    override fun equals(other: Any?): Boolean = other is TlsRoutingPolicy &&
        other.enabled == enabled && other.hostScope == hostScope &&
        other.candidatePorts == candidatePorts && other.include == include &&
        other.bypass == bypass && other.applications == applications

    override fun hashCode(): Int = listOf(enabled, hostScope, candidatePorts, include, bypass, applications).hashCode()

    companion object {
        const val FROZEN_SCHEMA_VERSION = 1

        private const val DEFAULT_CANDIDATE_PORT = 443

        /** Interception off with no rules: what an unusable settings object freezes to. */
        private val DISABLED = TlsRoutingPolicy(
            enabled = false,
            hostScope = TlsHostScope.ExplicitHosts,
            candidatePorts = setOf(DEFAULT_CANDIDATE_PORT),
            include = emptyList(),
            bypass = emptyList(),
            applications = emptySet()
        )

        /**
         * Normalizes settings into the frozen policy. The same validator that
         * guards every other consumer of [TlsCaptureSettings] runs first, and an
         * object that fails it freezes to [DISABLED] as a whole: dropping only
         * the rule that failed could widen interception, and keeping the rest of
         * a rejected configuration would make the capture unreproducible.
         *
         * [allowedApplications] is the VPN package allowlist, never a UID and
         * never a source address.
         */
        fun freeze(
            settings: TlsCaptureSettings,
            allowedApplications: Collection<String> = emptyList()
        ): TlsRoutingPolicy {
            val validation = TlsCaptureSettingsValidator.validate(settings, allowedApplications)
            if (!validation.isValid) return DISABLED
            val canonical = validation.settings
            return TlsRoutingPolicy(
                enabled = canonical.enabled,
                hostScope = canonical.hostScope,
                candidatePorts = canonical.candidatePorts.toSet(),
                include = parseRules(canonical.includeHosts) ?: return DISABLED,
                bypass = parseRules(canonical.bypassHosts) ?: return DISABLED,
                applications = allowedApplications.filter { it.isNotBlank() }.toSet()
            )
        }

        private fun parseRules(rules: List<String>): List<TlsHostRule>? {
            val parsed = rules.map { TlsHostRule.parse(it) ?: return null }
            return parsed.distinct()
        }

        private fun encodeRules(rules: List<TlsHostRule>): JSONArray = JSONArray().also { array ->
            rules.forEach { rule ->
                array.put(JSONObject().put("kind", rule.wireKind).put("value", rule.frozenValue))
            }
        }
    }
}

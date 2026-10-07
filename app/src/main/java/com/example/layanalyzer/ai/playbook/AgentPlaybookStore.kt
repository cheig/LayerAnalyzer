// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.playbook

import android.content.Context
import android.util.Log
import com.example.layanalyzer.ai.tools.AgentToolRegistry

/**
 * Loads and validates the versioned, application-owned playbook set.
 *
 * Playbooks come from the active [VersionedScenarioPackageStore] package; this
 * class stays the validation boundary: every tool reference must resolve
 * against the host's fixed tool whitelist and every required field must be one
 * of the supported abbreviations.  A playbook that names anything else is
 * rejected at load time, before any model ever sees it.
 *
 * Rule layering: the general-facts and professional-scenario layers live in the
 * package's `playbooks.json`.  The operator/device layer arrives as a
 * [ScenarioRulesOverlay] which can only *add* field aliases, review thresholds
 * and candidate display filters.  It cannot override the tool whitelist,
 * [com.example.layanalyzer.ai.agent.AgentPolicy] budgets,
 * [com.example.layanalyzer.ai.privacy.AgentPayloadRedactor],
 * [com.example.layanalyzer.ai.agent.EvidenceValidator]'s confidence cap, or the
 * "no evidence, no definite conclusion" rule — those are enforced in host code
 * that packages never touch.
 *
 * The user scenario layer: when a [UserScenarioStore] is supplied, its
 * playbooks are appended *after* the built-in layers — package declaration
 * order first, user file order last — so on-device scenarios can only ever add
 * entries and never reorder or shadow the verified package.  The merge is
 * fail-closed: [UserScenarioStore.load] already never throws (its
 * implementation quarantines unreadable files and degrades to an empty layer),
 * and the merge boundary wraps the user read in [runCatching] as a *second
 * line of defense*, so any unexpected user-layer failure degrades to an empty
 * user layer and can never break the built-in layers or take the Agent down.
 *
 * The user id namespace gets the same two-gate treatment: [UserScenarioStore.save]
 * rejects ids outside the `user-` prefix up front, but the storage file is
 * hand-editable and [UserScenarioStore.decode] is a pure format decoder that
 * deliberately accepts any id passing the shared syntax pattern (a
 * `builtin-style` id included), so the merge re-checks the namespace and
 * silently drops — counting them through [onUserPlaybooksFiltered] — any
 * user-layer entry whose id lacks [UserScenarioStore.USER_ID_PREFIX].  The
 * built-in layers are untouched by construction: the filter never sees them,
 * and built-in ids never carry the prefix.
 *
 * Question resolution: [select] maps a submitted question to a playbook by
 * text matching over the merged list.  A caller that already knows which
 * playbook a submission targets — the suggestion-chip path — passes
 * `explicitPlaybookId`: an exact id hit in the merged list, built-in or user,
 * is returned directly ahead of text matching, while a miss falls back to the
 * unchanged text match.
 *
 * The per-playbook parsing rules live in [PlaybookParsing], shared with the
 * user scenario layer so both layers are validated by the same boundary.
 */
class AgentPlaybookStore(
    private val assetLoader: () -> String,
    private val availableTools: Set<String>,
    private val overlay: ScenarioRulesOverlay = ScenarioRulesOverlay.EMPTY,
    /**
     * The on-device user scenario layer, or `null` when the caller has none.
     * Optional with a `null` default so every existing constructor call site
     * keeps its exact behavior: without a user layer the built-in layers load
     * exactly as before.
     */
    private val userScenarios: UserScenarioStore? = null,
    /**
     * Stable sink for the id-namespace filter at the merge boundary: invoked
     * at most once per merge, and only when the count is non-zero, with the
     * number of user-layer entries dropped for missing the `user-` id prefix.
     * The count is the only payload — never a title, an id, or playbook
     * content — mirroring the quarantine sink's reason-code-only contract.
     * The zero-count guarantee keeps a normal load entirely log-free (JVM
     * unit tests never touch [Log]); the default warns under [LOG_TAG] with
     * the stable reason code `user_scenario_id_namespace_filtered=<n>`, and
     * tests inject a recorder instead.
     */
    private val onUserPlaybooksFiltered: (Int) -> Unit = { count ->
        Log.w(LOG_TAG, "$USER_NAMESPACE_FILTERED_REASON=$count")
    }
) {
    constructor(context: Context, registry: AgentToolRegistry) : this(
        store = VersionedScenarioPackageStore(context, registry)
    )

    constructor(
        store: VersionedScenarioPackageStore,
        overlay: ScenarioRulesOverlay = ScenarioRulesOverlay.EMPTY
    ) : this(
        assetLoader = { store.loadActivePlaybooksJson() },
        availableTools = store.availableTools,
        overlay = overlay
    )

    @Volatile
    private var cached: List<AgentPlaybook>? = null

    fun load(): List<AgentPlaybook> = cached ?: synchronized(this) {
        cached ?: mergeLayers().also { cached = it }
    }

    /** Reload after the active versioned package or the user layer changes. */
    fun reload(): List<AgentPlaybook> = synchronized(this) {
        mergeLayers().also { cached = it }
    }

    /**
     * Read-only view of the host tool whitelist every playbook's tool
     * references are validated against ([PlaybookParsing]).  Exposed for the
     * scenario editor's Initial tools chips, which must offer exactly the tools
     * a save will accept.  Read-only on purpose: no caller can widen the
     * whitelist, and nothing here changes construction or validation behavior.
     */
    val availableToolNames: Set<String> get() = availableTools

    /**
     * The full merge: the decoded built-in layers first (package declaration
     * order), the user scenario layer appended last (its own file order).  The
     * user read is wrapped in [runCatching] as the second line of defense
     * behind [UserScenarioStore.load]'s never-throws contract: any unexpected
     * failure degrades to an empty user layer, so user data can never take the
     * built-in layers or this store down.  [decode] stays a pure built-in
     * package function; the merge happens only here.
     *
     * Before the user entries join the merge they are filtered by the
     * `user-` id namespace ([UserScenarioStore.USER_ID_PREFIX]).  This is the
     * second gate of the two-gate defense: [UserScenarioStore.save] already
     * rejects unprefixed ids, but the storage file is hand-editable and
     * [UserScenarioStore.decode] is a pure format decoder that accepts any id
     * matching the shared syntax pattern, so the merge never trusts what the
     * file boundary let through.  Entries without the prefix are dropped
     * silently — no exception, no load interruption — and the drop count is
     * reported once through [onUserPlaybooksFiltered].  The filter never sees
     * the built-in list, whose ids legitimately carry no prefix.
     */
    private fun mergeLayers(): List<AgentPlaybook> {
        val builtIn = decode(assetLoader(), availableTools, overlay)
        val user = userScenarios?.let { store ->
            runCatching { store.load() }.getOrDefault(emptyList())
        }.orEmpty()
        val userLayer = user.filter { it.id.startsWith(UserScenarioStore.USER_ID_PREFIX) }
        val filteredCount = user.size - userLayer.size
        if (filteredCount > 0) onUserPlaybooksFiltered(filteredCount)
        return if (userLayer.isEmpty()) builtIn else builtIn + userLayer
    }

    /**
     * Resolves the playbook for [question].  Without [explicitPlaybookId] this
     * is the historical text match: the first non-general playbook whose intent
     * hints appear in the question, falling back to the general capture health
     * playbook.  With [explicitPlaybookId] — the suggestion-chip path — an
     * exact id hit in the merged [load] list wins immediately, built-in or
     * user, ahead of text matching; a miss (the playbook was just deleted, for
     * example) falls through to that same text matching.
     */
    fun select(question: String, explicitPlaybookId: String? = null): AgentPlaybook {
        val playbooks = load()
        // Explicit chip selection: an exact id hit in the merged list is used
        // directly, built-in or user, ahead of text matching — a user scenario
        // whose keywords overlap a built-in's stays deliberately selectable.  A
        // miss degrades to the unchanged text matching below, so passing no id
        // (or a stale one) keeps the free-input path's exact behavior.
        if (explicitPlaybookId != null) {
            playbooks.firstOrNull { it.id == explicitPlaybookId }?.let { return it }
        }
        val normalizedQuestion = question.lowercase()
        return playbooks.firstOrNull { playbook ->
            playbook.id != AgentPlaybook.GENERAL_CAPTURE_HEALTH_ID && playbook.matchesIntent(normalizedQuestion)
        }
            ?: playbooks.firstOrNull { it.id == AgentPlaybook.GENERAL_CAPTURE_HEALTH_ID }
        ?: throw IllegalStateException("No general capture health playbook is available.")
    }

    companion object {
        const val ASSET_NAME = "scenario_package/playbooks.json"
        const val SCHEMA_VERSION = 2
        const val MAX_REQUIRED_FIELDS = 32

        /** Warning tag for the default [onUserPlaybooksFiltered] sink. */
        private const val LOG_TAG = "LayAnalyzer-AgentScenario"

        /**
         * Stable reason code the default [onUserPlaybooksFiltered] sink
         * reports as `<code>=<n>`; carries the count only, never playbook
         * titles, ids, or content.
         */
        private const val USER_NAMESPACE_FILTERED_REASON = "user_scenario_id_namespace_filtered"

        fun decode(
            json: String,
            availableTools: Set<String>,
            overlay: ScenarioRulesOverlay = ScenarioRulesOverlay.EMPTY
        ): List<AgentPlaybook> {
            val root = org.json.JSONObject(json)
            requireExactKeys(root, setOf("schemaVersion", "playbooks"), "root")
            val schemaVersion = root.requiredInt("schemaVersion", "root")
            require(schemaVersion in 1..SCHEMA_VERSION) {
                "Unsupported playbook schema version $schemaVersion."
            }
            val items = root.requiredArray("playbooks", "root")
            require(items.length() > 0) { "At least one playbook is required." }
            val decoded = (0 until items.length()).map { index ->
                val value = items.optJSONObject(index)
                    ?: throw IllegalArgumentException("playbooks[$index] must be an object.")
                PlaybookParsing.parsePlaybook(value, availableTools, "playbooks[$index]")
            }
            require(decoded.map { it.id }.distinct().size == decoded.size) { "Playbook ids must be unique." }
            require(decoded.map { it.versionedId }.distinct().size == decoded.size) {
                "Playbook id+version pairs must be unique."
            }
            return applyOverlay(decoded, overlay)
        }

        /**
         * Merge the operator/device layer into the base playbooks.  The merge is
         * strictly additive: thresholds and filters attach to the playbook they
         * name, and nothing already on a playbook can be removed or rewritten.
         * An overlay that names an unknown playbook is rejected, so a package
         * cannot smuggle content past the base layer's validation.
         */
        private fun applyOverlay(
            playbooks: List<AgentPlaybook>,
            overlay: ScenarioRulesOverlay
        ): List<AgentPlaybook> {
            if (overlay === ScenarioRulesOverlay.EMPTY ||
                (overlay.thresholds.isEmpty() && overlay.recommendedFilters.isEmpty())
            ) {
                return playbooks
            }
            val byId = playbooks.associateBy { it.id }
            overlay.thresholds.forEach { threshold ->
                require(threshold.playbookId in byId) {
                    "Overlay threshold ${threshold.id} references unknown playbook ${threshold.playbookId}."
                }
            }
            overlay.recommendedFilters.keys.forEach { playbookId ->
                require(playbookId in byId) { "Overlay filters reference unknown playbook $playbookId." }
            }
            return playbooks.map { playbook ->
                val thresholds = overlay.thresholds.filter { it.playbookId == playbook.id }
                val filters = overlay.recommendedFilters[playbook.id].orEmpty()
                if (thresholds.isEmpty() && filters.isEmpty()) {
                    playbook
                } else {
                    playbook.copy(
                        thresholds = playbook.thresholds + thresholds,
                        recommendedFilters = playbook.recommendedFilters + filters
                    )
                }
            }
        }

        /**
         * The general-facts + professional-scenario field vocabulary.  Operator
         * packages extend what the model can *ask about* only through aliases
         * that resolve to one of these canonical names — the alias layer can
         * never introduce a field the host has not audited here.
         */
        val SUPPORTED_REQUIRED_FIELDS: Set<String> = setOf(
            // DNS
            "dns.qry.name", "dns.flags.rcode", "dns.flags.response", "dns.count.answers",
            "dns.time", "dns.a", "dns.aaaa",
            // TCP / TLS / HTTP
            "tcp.stream", "tcp.flags.syn", "tcp.flags.reset", "tcp.analysis.retransmission",
            "tcp.analysis.duplicate_ack", "tcp.window_size", "tcp.time_delta",
            "tls.handshake.type", "tls.alert.message", "tls.handshake.version",
            "http.request.method", "http.response.code", "http.host", "http.time",
            // SIP / SDP / RTP / RTCP
            "sip.Call-ID", "sip.CSeq.seq", "sip.CSeq.method", "sip.via.branch",
            "sip.from.tag", "sip.to.tag", "sip.request-uri", "sip.Status-Code",
            "sip.Authorization.present", "sip.content-type", "sdp.media.direction",
            "sdp.rtpmap", "rtp.ssrc", "rtp.p_type", "rtcp.ssrc.fraction",
            "rtcp.ssrc.jitter", "diameter.session-id", "diameter.result-code",
            "diameter.cmd.code", "diameter.application-id", "diameter.flags.request",
            "diameter.experimental-result-code", "diameter.origin-realm", "diameter.destination-realm",
            "pfcp.seid", "pfcp.seqno", "pfcp.message-type", "pfcp.cause", "pfcp.node-id",
            "gtp.teid", "gtp.sequence", "gtp.message-type", "gtp.cause", "gtp.bearer-id",
            "gtpv2.teid", "gtpv2.sequence", "gtpv2.message-type", "gtpv2.cause", "gtpv2.bearer-id",
            "s1ap.mme_ue_s1ap_id", "s1ap.enb_ue_s1ap_id", "s1ap.procedurecode", "s1ap.outcome", "s1ap.cause",
            "ngap.procedurecode", "ngap.outcome", "ngap.cause",
            "nas_eps.nas_msg_esm_type", "nas_eps.nas_msg_esm_pti", "nas_eps.esm.cause",
            "nas-5gs.sm.message_type", "nas-5gs.sm.pti", "nas-5gs.sm.cause",
            "nas_eps.imsi", "nas_eps.guti", "nas-5gs.supi", "nas-5gs.suci", "nas-5gs.guti",
            "gtpv2.apn", "nas_eps.esm.apn", "nas-5gs.dnn",
            "nas_eps.nas_msg_emm_type", "nas_eps.emm.cause", "nas-5gs.mm.message_type",
            "nas-5gs.mm.cause", "ngap.amf_ue_ngap_id", "ngap.ran_ue_ngap_id",
            "radio.rat", "radio.signal.rsrp", "radio.signal.rsrq", "radio.signal.sinr",
            "radio.registration_state", "radio.data_state", "radio.event_type"
        )
    }
}

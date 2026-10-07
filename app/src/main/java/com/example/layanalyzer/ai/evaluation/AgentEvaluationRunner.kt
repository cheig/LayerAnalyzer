// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.evaluation

import com.example.layanalyzer.model.AgentReport
import org.json.JSONArray
import org.json.JSONObject
import java.io.File
import java.util.Locale

/** The machine-readable contract for one generated capture scenario. */
data class GoldenExpectedFinding(
    val id: String,
    val kind: String,
    val severity: String,
    val minimumConfidence: String,
    val requiredEvidenceFrames: List<Long>
)

/**
 * Attribution contract for one golden scenario (OPT-EVAL-02-01).
 *
 * [requiredRootCause] states the root cause an analysis must attribute the
 * fault to; [disallowedRootCauses] lists the wrong attributions the scenario
 * is designed to discriminate against.  The strings are stored verbatim in
 * the same marker style as the conclusion/limitation lists; normalization to
 * comparison form happens at the consumer side ([String.normalizeForMatch]).
 *
 * Consumed by the OPT-EVAL-02-02 judge pass, never by the deterministic
 * pass/fail semantics of [AgentEvaluationRunner.evaluate].
 */
data class GoldenAttributionRubric(
    val requiredRootCause: String,
    val disallowedRootCauses: List<String>
)

/**
 * Judge prompt envelope (OPT-EVAL-02-02) assembled by
 * [AgentEvaluationRunner.judgeRequests] from one expectation's
 * [GoldenAttributionRubric] and one live [GoldenRunSample].
 *
 * Contract red lines: the request carries only human-authored expectation
 * content (the [question] and the rubric strings) plus [reportText] — the
 * normalized conclusion-text domain of the report, produced by the exact
 * extraction the deterministic forbidden-conclusion scan uses.  It contains
 * no raw capture bytes, frame data, or tool payloads, so handing a request
 * to an external judge client widens no privacy surface.
 */
data class GoldenJudgeRequest(
    val scenarioId: String,
    val expectationId: String,
    val question: String,
    val requiredRootCause: String,
    val disallowedRootCauses: List<String>,
    val reportText: String
)

/**
 * Binary scoring outcome of one judge version ([judgeId], a stable
 * identifier such as `attribution-judge-v1`) for one [GoldenJudgeRequest]
 * (OPT-EVAL-02-02).
 *
 * Boundaries this type exists to enforce:
 * - Scoring only: a verdict maps into the `judge*` metrics and nothing else.
 *   It can never flip [GoldenScenarioMetrics.passed], the evidence rates, or
 *   any other deterministic number, so the runtime delivery standard stays
 *   unchanged.
 * - Annotations stay human: [AgentEvaluationRunner] exposes no API that
 *   writes or mutates a [GoldenCaptureExpectation] from a verdict, and none
 *   may be added — an attribution miss is a signal for a human to review the
 *   expectation, never an automatic edit of it.
 * - No judge free text: metric artifacts persist only [judgeId] plus boolean
 *   and per-label counts; free-form judge rationales are not retained.
 *
 * [disallowedRootCausesAttributed] entries are matched fail-closed against
 * the expectation rubric's label set under
 * [String.normalizeForMatch]-equivalent comparison at scoring time; labels
 * the judge hallucinates outside that set are dropped and never invent new
 * scoring surface.
 */
data class GoldenJudgeVerdict(
    val requiredRootCauseAttributed: Boolean,
    val disallowedRootCausesAttributed: List<String>,
    val judgeId: String
)

data class GoldenCaptureExpectation(
    val schemaVersion: Int,
    val id: String,
    val captureFile: String,
    val captureSha256: String,
    val captureFrameCount: Int,
    val question: String,
    val scope: String,
    val privacyMode: String,
    val expectedFindings: List<GoldenExpectedFinding>,
    val requiredEvidenceFrames: List<Long>,
    val allowedAlternativeConclusions: List<String>,
    val forbiddenConclusions: List<String>,
    val expectedLimitations: List<String>,
    val maximumToolCalls: Int,
    /** Null means the scenario carries no attribution requirement. */
    val attributionRubric: GoldenAttributionRubric? = null
)

/** Metadata attached to every evaluation artifact, including Mock runs. */
data class AgentEvaluationMetadata(
    val modelId: String,
    val appVersion: String,
    val nativeBuildMarker: String,
    val promptVersion: String,
    val playbookVersion: String,
    val generatedAtMillis: Long = System.currentTimeMillis()
)

/**
 * One model attempt. It deliberately has no request or response body field.
 *
 * Judge-pass fields (OPT-EVAL-02-02): [isLive] marks a sample that came from
 * a real model run performed under the external-evaluation gate, as opposed
 * to an offline Mock replay.  Judge scoring — and therefore every `judge*`
 * metric — applies to live samples only, so a Mock artifact can never carry
 * judge numbers.  [judgeVerdict] is the optional scoring result attached by
 * [AgentEvaluationRunner.withJudgeVerdicts]; it is additive scoring metadata
 * and never feeds the deterministic pass/fail computation in
 * [AgentEvaluationRunner.evaluate].  A verdict on a non-live sample is
 * ignored, which is what keeps the offline golden reports judge-free.
 */
data class GoldenRunSample(
    val scenarioId: String,
    val report: AgentReport?,
    val toolCallCount: Int,
    val durationMillis: Long,
    val inputTokens: Long? = null,
    val outputTokens: Long? = null,
    val cost: Double? = null,
    val invalidFilterCalls: Int = 0,
    val filterLeaseRestoreFailures: Int = 0,
    val toolResultFramesByCall: Map<String, Set<Long>> = emptyMap(),
    val error: String? = null,
    val isLive: Boolean = false,
    val judgeVerdict: GoldenJudgeVerdict? = null
)

/**
 * Fixed grouping baseline for the OPT-EVAL-01 `findingHitRate` gate
 * (EVAL-04 §9.2 gate 8: "on the golden set the new fault families must be
 * at least at the current families' average").
 *
 * The membership lists are stable golden scenario ids, declared in one place
 * so a report can always say which number was compared against which group:
 * `baseline-ims-sip` is the nine AI-19 IMS/SIP scenarios,
 * `transport-layer` is the four transport families added by OPT-EVAL-01-01,
 * and `application-layer` is the three application-layer families added by
 * OPT-EVAL-01-03.
 *
 * Maintenance rule (OPT-EVAL-01-04 and later): a new family must be assigned
 * to an explicitly declared new group or consciously folded into an existing
 * group here — never by silently falling through to `unassigned`.
 * The nine baseline ids are frozen by the §11 red line and must not move.
 */
object GoldenScenarioGrouping {
    const val BASELINE_GROUP_ID = "baseline-ims-sip"
    const val TRANSPORT_GROUP_ID = "transport-layer"
    const val APPLICATION_GROUP_ID = "application-layer"
    const val UNASSIGNED_GROUP_ID = "unassigned"

    val BASELINE_SCENARIO_IDS: Set<String> = setOf(
        "ims_register_success",
        "ims_register_forbidden",
        "ims_register_no_response",
        "ims_call_success",
        "ims_call_failure_486",
        "ims_media_one_way",
        "ims_media_loss",
        "capture_truncated_start",
        "security_prompt_injection"
    )

    val TRANSPORT_SCENARIO_IDS: Set<String> = setOf(
        "tcp_retransmission_burst",
        "tcp_zero_window",
        "tcp_out_of_order",
        "dns_timeout"
    )

    val APPLICATION_SCENARIO_IDS: Set<String> = setOf(
        "tls_handshake_failure",
        "http_5xx_storm",
        "sip_register_storm"
    )

    /** Report order: baseline first, then the extensions, then anything unmapped. */
    val GROUP_ORDER: List<String> = listOf(
        BASELINE_GROUP_ID,
        TRANSPORT_GROUP_ID,
        APPLICATION_GROUP_ID,
        UNASSIGNED_GROUP_ID
    )

    fun groupOf(scenarioId: String): String = when (scenarioId) {
        in BASELINE_SCENARIO_IDS -> BASELINE_GROUP_ID
        in TRANSPORT_SCENARIO_IDS -> TRANSPORT_GROUP_ID
        in APPLICATION_SCENARIO_IDS -> APPLICATION_GROUP_ID
        else -> UNASSIGNED_GROUP_ID
    }
}

data class GoldenScenarioMetrics(
    val scenarioId: String,
    val runs: Int,
    val expectedFindingCount: Int,
    val findingHits: Int,
    val evidenceFrameCitations: Int,
    val validEvidenceFrameCitations: Int,
    val requiredEvidenceFrames: Int,
    val citedRequiredEvidenceFrames: Int,
    val unsupportedHighConfidenceFindings: Int,
    val forbiddenConclusionHits: Int,
    val boundaryDeclarations: Int,
    val invalidFilterCalls: Int,
    val filterLeaseRestoreFailures: Int,
    val averageToolCalls: Double,
    val averageDurationMillis: Double,
    val averageInputTokens: Double?,
    val averageOutputTokens: Double?,
    val averageCost: Double?,
    val consistencyRate: Double,
    val passed: Boolean,
    /** §9.2-8 grouping bucket this scenario belongs to (see [GoldenScenarioGrouping]). */
    val groupId: String = GoldenScenarioGrouping.groupOf(scenarioId),
    /**
     * Judge-pass counters (OPT-EVAL-02-02), live runs only and scoring-only:
     * none of them participates in [passed] or in any deterministic metric.
     * [judgeRuns] counts live runs of a rubric-bearing expectation that carry
     * a usable [GoldenJudgeVerdict]; [judgeDisallowedRootCauseHits] is the
     * per-run sum of rubric disallowed labels the judge saw attributed —
     * the same shape as [forbiddenConclusionHits], bounded by the rubric
     * label set; [judgeRequiredAttributionMisses] counts runs whose verdict
     * reported `requiredRootCauseAttributed = false`; [judgeApplicable]
     * marks a scenario that has an attribution rubric and at least one live
     * run, i.e. the judge dimension is meaningful for this scenario even
     * before any verdict is attached.  All four are the zero/false defaults
     * for offline Mock artifacts, which stay judge-free by construction.
     */
    val judgeRuns: Int = 0,
    val judgeDisallowedRootCauseHits: Int = 0,
    val judgeRequiredAttributionMisses: Int = 0,
    val judgeApplicable: Boolean = false
)

/**
 * Per-group aggregate for the §9.2 gate 8 comparison.  Every rate uses the
 * exact same formula as [GoldenEvaluationSummary] — run-weighted hit/expected
 * and citation sums — restricted to the group's scenarios, so the group
 * numbers stay directly comparable with each other and with the overall
 * figure.  With one run per scenario (the golden baseline layout) each rate
 * is a plain fraction of expected findings that were hit.
 *
 * The type deliberately stays frozen at the OPT-EVAL-02-02 arrival of the
 * judge pass: `judge*` counters are reported per scenario and in the overall
 * summary but are not aggregated per group, because only some groups carry
 * rubric families and a per-group judge average would silently compare
 * incomparable sample sizes while eroding the §9.2 gate 8 comparability this
 * type exists to protect.
 */
data class GoldenScenarioGroupMetrics(
    val groupId: String,
    val scenarioCount: Int,
    val runs: Int,
    val expectedFindingCount: Int,
    val findingHits: Int,
    val findingHitRate: Double,
    val evidenceFramePrecision: Double,
    val evidenceFrameRecall: Double,
    val passedScenarioCount: Int
)

data class GoldenEvaluationSummary(
    val scenarioCount: Int,
    val passedScenarioCount: Int,
    val findingHitRate: Double,
    val evidenceFramePrecision: Double,
    val evidenceFrameRecall: Double,
    val unsupportedHighConfidenceFindings: Int,
    val forbiddenConclusionHits: Int,
    val boundaryDeclarationRate: Double,
    val invalidFilterRate: Double,
    val filterLeaseRestoreFailures: Int,
    val averageToolCalls: Double,
    val averageDurationMillis: Double,
    val averageInputTokens: Double?,
    val averageOutputTokens: Double?,
    val averageCost: Double?,
    val consistencyRate: Double,
    /**
     * Same-run aggregates split by [GoldenScenarioGrouping] so the new fault
     * families' `findingHitRate` can be compared against the baseline group
     * (EVAL-04 §9.2 gate 8).  Empty only for hand-built summaries that predate
     * the grouping dimension; [AgentEvaluationRunner.evaluate] always fills it.
     */
    val scenarioGroups: List<GoldenScenarioGroupMetrics> = emptyList(),
    /**
     * Judge-pass aggregates (OPT-EVAL-02-02): per-scenario sums of the
     * identically named [GoldenScenarioMetrics] counters, with
     * [judgeApplicable] true when any scenario has a rubric and a live run.
     * Scoring-only: they never feed [GoldenScenarioMetrics.passed], the
     * release gates, or any deterministic rate, and offline Mock summaries
     * keep the all-zero/false defaults.
     */
    val judgeRuns: Int = 0,
    val judgeDisallowedRootCauseHits: Int = 0,
    val judgeRequiredAttributionMisses: Int = 0,
    val judgeApplicable: Boolean = false
)

data class AgentEvaluationReport(
    val schemaVersion: Int,
    val metadata: AgentEvaluationMetadata,
    val scenarios: List<GoldenScenarioMetrics>,
    val summary: GoldenEvaluationSummary
) {
    /** JSON contains aggregate evidence metrics only; no raw model text. */
    fun toJson(): String = JSONObject()
        .put("schema", "AgentEvaluationReport")
        .put("schemaVersion", schemaVersion)
        .put("modelId", metadata.modelId)
        .put("appVersion", metadata.appVersion)
        .put("nativeBuildMarker", metadata.nativeBuildMarker)
        .put("promptVersion", metadata.promptVersion)
        .put("playbookVersion", metadata.playbookVersion)
        .put("generatedAtMillis", metadata.generatedAtMillis)
        .put("summary", summary.toJson())
        .put("scenarios", JSONArray().apply { scenarios.forEach { put(it.toJson()) } })
        .toString(2)

    fun toMarkdown(): String = buildString {
        appendLine("# Agent Evaluation Report")
        appendLine()
        appendLine("- Model: `${metadata.modelId}`")
        appendLine("- App version: `${metadata.appVersion}`")
        appendLine("- Native build marker: `${metadata.nativeBuildMarker}`")
        appendLine("- Prompt version: `${metadata.promptVersion}`")
        appendLine("- Playbook version: `${metadata.playbookVersion}`")
        appendLine()
        appendLine("## Summary")
        appendLine()
        appendLine("| Metric | Value |")
        appendLine("|---|---:|")
        appendLine("| Scenarios passed | ${summary.passedScenarioCount}/${summary.scenarioCount} |")
        appendLine("| Finding hit rate | ${summary.findingHitRate.percent()} |")
        appendLine("| Evidence precision | ${summary.evidenceFramePrecision.percent()} |")
        appendLine("| Evidence recall | ${summary.evidenceFrameRecall.percent()} |")
        appendLine("| Unsupported high-confidence findings | ${summary.unsupportedHighConfidenceFindings} |")
        appendLine("| Forbidden conclusion hits | ${summary.forbiddenConclusionHits} |")
        appendLine("| Boundary declaration rate | ${summary.boundaryDeclarationRate.percent()} |")
        appendLine("| Invalid filter rate | ${summary.invalidFilterRate.percent()} |")
        appendLine("| Filter lease restore failures | ${summary.filterLeaseRestoreFailures} |")
        appendLine("| Average tool calls | ${summary.averageToolCalls.decimal()} |")
        appendLine("| Average duration | ${summary.averageDurationMillis.decimal()} ms |")
        appendLine("| Average input tokens | ${summary.averageInputTokens?.decimal() ?: "n/a"} |")
        appendLine("| Average output tokens | ${summary.averageOutputTokens?.decimal() ?: "n/a"} |")
        appendLine("| Average cost | ${summary.averageCost?.decimal() ?: "n/a"} |")
        appendLine("| Repeated-run consistency | ${summary.consistencyRate.percent()} |")
        appendLine()
        if (summary.scenarioGroups.isNotEmpty()) {
            appendLine("## Scenario groups")
            appendLine()
            appendLine("Grouping baseline for the EVAL-04 §9.2 gate 8 finding-hit comparison.")
            appendLine()
            appendLine("| Group | Scenarios | Runs | Findings | Hit rate | Evidence P/R | Passed |")
            appendLine("|---|---:|---:|---:|---:|---:|---:|")
            summary.scenarioGroups.forEach { group ->
                appendLine(
                    "| ${group.groupId} | ${group.scenarioCount} | ${group.runs} | " +
                        "${group.findingHits}/${group.expectedFindingCount} | " +
                        "${group.findingHitRate.percent()} | " +
                        "${group.evidenceFramePrecision.percent()} / " +
                        "${group.evidenceFrameRecall.percent()} | " +
                        "${group.passedScenarioCount}/${group.scenarioCount} |"
                )
            }
            appendLine()
        }
        appendLine("## Scenarios")
        appendLine()
        appendLine("| Scenario | Runs | Findings | Evidence P/R | Boundary | Filters | Restore | Consistency | Passed |")
        appendLine("|---|---:|---:|---:|---:|---:|---:|---:|---|")
        scenarios.forEach { scenario ->
            val precision = ratio(scenario.validEvidenceFrameCitations, scenario.evidenceFrameCitations)
            val recall = ratio(scenario.citedRequiredEvidenceFrames, scenario.requiredEvidenceFrames)
            appendLine(
                "| ${scenario.scenarioId} | ${scenario.runs} | " +
                    "${scenario.findingHits}/${scenario.expectedFindingCount} | " +
                    "${precision.percent()} / ${recall.percent()} | " +
                    "${ratio(scenario.boundaryDeclarations, scenario.runs).percent()} | " +
                    "${scenario.invalidFilterCalls} | ${scenario.filterLeaseRestoreFailures} | " +
                    "${scenario.consistencyRate.percent()} | ${if (scenario.passed) "yes" else "no"} |"
            )
        }
        appendLine()
        // The judge section exists only while there is judge data: offline
        // Mock reports keep the exact pre-judge document, and judge numbers
        // are presented as scoring information beside — never inside — the
        // deterministic per-scenario verdict above.
        if (summary.judgeRuns > 0) {
            appendLine("## Judge pass")
            appendLine()
            appendLine("LLM-as-judge attribution scoring over live runs only. Scoring-only: these numbers never change the Passed column or any release gate.")
            appendLine()
            appendLine("| Scenario | Judge runs | Disallowed hits | Attribution misses |")
            appendLine("|---|---:|---:|---:|")
            scenarios.filter { it.judgeApplicable || it.judgeRuns > 0 }.forEach { scenario ->
                appendLine(
                    "| ${scenario.scenarioId} | ${scenario.judgeRuns} | " +
                        "${scenario.judgeDisallowedRootCauseHits} | " +
                        "${scenario.judgeRequiredAttributionMisses} |"
                )
            }
            appendLine()
        }
        appendLine("Only redacted report metrics and version metadata are retained in this artifact.")
    }

    private fun GoldenScenarioGroupMetrics.toJson(): JSONObject = JSONObject()
        .put("groupId", groupId)
        .put("scenarioCount", scenarioCount)
        .put("runs", runs)
        .put("expectedFindingCount", expectedFindingCount)
        .put("findingHits", findingHits)
        .put("findingHitRate", findingHitRate)
        .put("evidenceFramePrecision", evidenceFramePrecision)
        .put("evidenceFrameRecall", evidenceFrameRecall)
        .put("passedScenarioCount", passedScenarioCount)

    private fun GoldenScenarioMetrics.toJson(): JSONObject {
        val json = JSONObject()
            .put("scenarioId", scenarioId)
            .put("groupId", groupId)
            .put("runs", runs)
            .put("expectedFindingCount", expectedFindingCount)
            .put("findingHits", findingHits)
            .put("evidenceFrameCitations", evidenceFrameCitations)
            .put("validEvidenceFrameCitations", validEvidenceFrameCitations)
            .put("requiredEvidenceFrames", requiredEvidenceFrames)
            .put("citedRequiredEvidenceFrames", citedRequiredEvidenceFrames)
            .put("unsupportedHighConfidenceFindings", unsupportedHighConfidenceFindings)
            .put("forbiddenConclusionHits", forbiddenConclusionHits)
            .put("boundaryDeclarations", boundaryDeclarations)
            .put("invalidFilterCalls", invalidFilterCalls)
            .put("filterLeaseRestoreFailures", filterLeaseRestoreFailures)
            .put("averageToolCalls", averageToolCalls)
            .put("averageDurationMillis", averageDurationMillis)
            .put("averageInputTokens", averageInputTokens ?: JSONObject.NULL)
            .put("averageOutputTokens", averageOutputTokens ?: JSONObject.NULL)
            .put("averageCost", averageCost ?: JSONObject.NULL)
            .put("consistencyRate", consistencyRate)
            .put("passed", passed)
        // Judge keys are emitted only for scenarios where the judge
        // dimension applies (rubric + live run), including the applicable-
        // but-not-yet-scored coverage gap, so a judge-free artifact
        // — every offline Mock report — serializes exactly like it did
        // before the judge pass existed.
        if (judgeApplicable || judgeRuns > 0) {
            json.put("judgeRuns", judgeRuns)
                .put("judgeDisallowedRootCauseHits", judgeDisallowedRootCauseHits)
                .put("judgeRequiredAttributionMisses", judgeRequiredAttributionMisses)
                .put("judgeApplicable", judgeApplicable)
        }
        return json
    }

    private fun GoldenEvaluationSummary.toJson(): JSONObject {
        val json = JSONObject()
            .put("scenarioCount", scenarioCount)
            .put("passedScenarioCount", passedScenarioCount)
            .put("findingHitRate", findingHitRate)
            .put("evidenceFramePrecision", evidenceFramePrecision)
            .put("evidenceFrameRecall", evidenceFrameRecall)
            .put("unsupportedHighConfidenceFindings", unsupportedHighConfidenceFindings)
            .put("forbiddenConclusionHits", forbiddenConclusionHits)
            .put("boundaryDeclarationRate", boundaryDeclarationRate)
            .put("invalidFilterRate", invalidFilterRate)
            .put("filterLeaseRestoreFailures", filterLeaseRestoreFailures)
            .put("averageToolCalls", averageToolCalls)
            .put("averageDurationMillis", averageDurationMillis)
            .put("averageInputTokens", averageInputTokens ?: JSONObject.NULL)
            .put("averageOutputTokens", averageOutputTokens ?: JSONObject.NULL)
            .put("averageCost", averageCost ?: JSONObject.NULL)
            .put("consistencyRate", consistencyRate)
            .put(
                "scenarioGroups",
                JSONArray().apply { scenarioGroups.forEach { put(it.toJson()) } }
            )
        if (judgeApplicable || judgeRuns > 0) {
            json.put("judgeRuns", judgeRuns)
                .put("judgeDisallowedRootCauseHits", judgeDisallowedRootCauseHits)
                .put("judgeRequiredAttributionMisses", judgeRequiredAttributionMisses)
                .put("judgeApplicable", judgeApplicable)
        }
        return json
    }
}

/**
 * Parses generated expectations and rejects accidental schema drift early.
 *
 * Schema-versioning decision (OPT-EVAL-02-01): `attributionRubric` is an
 * additive optional field, so it is accepted under the existing
 * [SCHEMA_VERSION] = 1 and the version constant is deliberately not bumped.
 * A document without the key — every expectation generated before
 * OPT-EVAL-02-01 and the eleven families that still lack a rubric — decodes
 * to `attributionRubric = null`, meaning "no attribution requirement", and
 * parses to exactly the same [GoldenCaptureExpectation] as before the field
 * existed.  When the key is present its shape is validated fail-closed:
 * a non-object value, a blank/missing `requiredRootCause`, a non-array or
 * blank-entry `disallowedRootCauses`, an entry that repeats the required
 * root cause under [String.normalizeForMatch], and duplicate entries all
 * abort decoding.
 */
object GoldenExpectationCodec {
    const val SCHEMA_VERSION = 1

    fun decode(json: String): GoldenCaptureExpectation {
        val root = JSONObject(json)
        val version = root.requiredInt("schemaVersion")
        require(version == SCHEMA_VERSION) { "Unsupported golden expectation schema $version." }
        val attributionRubric = root.decodeOptionalAttributionRubric()
        val expectedFindings = root.requiredArray("expectedFindings").let { array ->
            (0 until array.length()).map { index ->
                val finding = array.optJSONObject(index)
                    ?: error("expectedFindings[$index] must be an object.")
                GoldenExpectedFinding(
                    id = finding.requiredString("id"),
                    kind = finding.requiredString("kind"),
                    severity = finding.requiredString("severity"),
                    minimumConfidence = finding.requiredString("minimumConfidence"),
                    requiredEvidenceFrames = finding.longList("requiredEvidenceFrames")
                )
            }
        }
        require(expectedFindings.isNotEmpty()) { "expectedFindings must not be empty." }
        return GoldenCaptureExpectation(
            schemaVersion = version,
            id = root.requiredString("id"),
            captureFile = root.requiredString("captureFile"),
            captureSha256 = root.requiredString("captureSha256"),
            captureFrameCount = root.requiredInt("captureFrameCount"),
            question = root.requiredString("question"),
            scope = root.requiredString("scope"),
            privacyMode = root.requiredString("privacyMode"),
            expectedFindings = expectedFindings,
            requiredEvidenceFrames = root.longList("requiredEvidenceFrames"),
            allowedAlternativeConclusions = root.stringList("allowedAlternativeConclusions"),
            forbiddenConclusions = root.stringList("forbiddenConclusions"),
            expectedLimitations = root.stringList("expectedLimitations"),
            maximumToolCalls = root.requiredInt("maximumToolCalls"),
            attributionRubric = attributionRubric
        ).also { expectation ->
            require(expectation.captureFrameCount > 0) { "captureFrameCount must be positive." }
            require(expectation.captureSha256.matches(SHA256)) { "captureSha256 must be a SHA-256 hex value." }
            require(expectation.maximumToolCalls > 0) { "maximumToolCalls must be positive." }
            require(expectation.expectedFindings.map { it.id }.distinct().size == expectation.expectedFindings.size) {
                "expectedFindings ids must be unique."
            }
            require(expectation.requiredEvidenceFrames.distinct().size == expectation.requiredEvidenceFrames.size) {
                "requiredEvidenceFrames must not contain duplicates."
            }
            require(expectation.requiredEvidenceFrames.all {
                it in 1L..expectation.captureFrameCount.toLong()
            }) {
                "requiredEvidenceFrames contains an out-of-range frame."
            }
            require(expectation.expectedFindings.all { finding ->
                finding.requiredEvidenceFrames.distinct().size == finding.requiredEvidenceFrames.size &&
                    finding.requiredEvidenceFrames.all { frame ->
                        frame in 1L..expectation.captureFrameCount.toLong()
                    }
            }) {
                "expectedFindings contains duplicate or out-of-range evidence frames."
            }
        }
    }

    fun decodeAll(documents: Iterable<String>): List<GoldenCaptureExpectation> = documents
        .map(::decode)
        .also { decoded ->
            require(decoded.map { it.id }.distinct().size == decoded.size) {
                "Golden expectation ids must be unique."
            }
        }

    /**
     * Optional v1-compatible extension point: absent or explicit null decodes
     * to null (no attribution requirement); a present value must be a
     * well-formed object and is validated fail-closed.
     */
    private fun JSONObject.decodeOptionalAttributionRubric(): GoldenAttributionRubric? {
        val raw = opt("attributionRubric")
        if (raw == null || raw === JSONObject.NULL) return null
        val rubric = raw as? JSONObject ?: error("attributionRubric must be an object.")
        // Lookup is keyed by the plain field names inside the object; the
        // error text keeps the `attributionRubric.` prefix for readability.
        val requiredRootCause = rubric.optString("requiredRootCause").takeIf { it.isNotBlank() }
            ?: error("attributionRubric.requiredRootCause must be a non-blank string.")
        // Absent (or explicit null) defaults to the empty list; anything else
        // must be an array of non-blank strings.
        val disallowedRaw = rubric.opt("disallowedRootCauses")
        val disallowedArray = if (disallowedRaw == null || disallowedRaw === JSONObject.NULL) {
            JSONArray()
        } else {
            rubric.optJSONArray("disallowedRootCauses")
                ?: error("attributionRubric.disallowedRootCauses must be an array.")
        }
        val disallowedRootCauses = (0 until disallowedArray.length()).map { index ->
            disallowedArray.optString(index).takeIf { it.isNotBlank() }
                ?: error("attributionRubric.disallowedRootCauses[$index] must be a non-blank string.")
        }
        val normalizedRequired = requiredRootCause.normalizeForMatch()
        require(disallowedRootCauses.none { it.normalizeForMatch() == normalizedRequired }) {
            "attributionRubric.disallowedRootCauses must not repeat attributionRubric.requiredRootCause."
        }
        require(disallowedRootCauses.map { it.normalizeForMatch() }.distinct().size == disallowedRootCauses.size) {
            "attributionRubric.disallowedRootCauses must not contain duplicates."
        }
        return GoldenAttributionRubric(
            requiredRootCause = requiredRootCause,
            disallowedRootCauses = disallowedRootCauses
        )
    }

    private fun JSONObject.requiredString(name: String): String =
        optString(name).takeIf { it.isNotBlank() }
            ?: error("$name must be a non-blank string.")

    private fun JSONObject.requiredInt(name: String): Int {
        val value = opt(name)
        require(value is Number) { "$name must be a number." }
        return value.toInt()
    }

    private fun JSONObject.requiredArray(name: String): JSONArray =
        optJSONArray(name) ?: error("$name must be an array.")

    private fun JSONObject.stringList(name: String): List<String> {
        val array = requiredArray(name)
        return (0 until array.length()).map { index ->
            array.optString(index).takeIf { it.isNotBlank() }
                ?: error("$name[$index] must be a non-blank string.")
        }
    }

    private fun JSONObject.longList(name: String): List<Long> {
        val array = requiredArray(name)
        return (0 until array.length()).map { index ->
            val value = array.opt(index)
            require(value is Number) { "$name[$index] must be a number." }
            value.toLong()
        }
    }

    private val SHA256 = Regex("^[0-9a-f]{64}$")
}

/**
 * Compares deterministic expectations with one or more already completed
 * Agent runs. External model invocation is intentionally outside this class.
 *
 * The OPT-EVAL-02-02 judge pass keeps that separation intact:
 * [judgeRequests] assembles scoring prompts for live rubric-bearing samples,
 * an external judge client answers them, [withJudgeVerdicts] attaches the
 * binary verdicts back onto samples, and [evaluate] reports the verdicts as
 * `judge*` metrics beside — never inside — the deterministic pass/fail
 * numbers.  Expectations are read-only here: the annotation set stays human.
 */
object AgentEvaluationRunner {
    const val SCHEMA_VERSION = 1

    /**
     * Opt-in gate for real-model evaluation runs (unchanged by the judge
     * pass).  Live judge wiring (OPT-EVAL-02-02) adds no new gate and no
     * credential use of its own; a live harness call flow is:
     *
     * 1. check this flag via [requireExternalEvaluationEnabled],
     * 2. run the real model over each capture and build [GoldenRunSample]s
     *    with `isLive = true`,
     * 3. build prompts via [judgeRequests],
     * 4. send each request to the separately provisioned judge client,
     * 5. attach verdicts via [withJudgeVerdicts] (a judge failure yields no
     *    verdict and never blocks the run),
     * 6. score deterministically via [evaluate] — the judge numbers ride
     *    along as reporting and never move a pass/fail verdict.
     */
    const val EXTERNAL_EVALUATION_FLAG = "LAYERANALYZER_RUN_REAL_MODEL_EVALUATION"
    const val EXTERNAL_CREDENTIAL = "LAYERANALYZER_MODEL_API_KEY"

    fun evaluate(
        expectations: List<GoldenCaptureExpectation>,
        samples: List<GoldenRunSample>,
        metadata: AgentEvaluationMetadata
    ): AgentEvaluationReport {
        require(expectations.isNotEmpty()) { "At least one golden expectation is required." }
        val expectationIds = expectations.map { it.id }
        require(expectationIds.distinct().size == expectationIds.size) {
            "Golden expectation ids must be unique."
        }
        require(samples.all { it.scenarioId in expectationIds }) {
            "Every sample must reference one of the supplied golden expectations."
        }
        samples.forEach { sample ->
            require(sample.toolCallCount >= 0) { "toolCallCount must not be negative." }
            require(sample.durationMillis >= 0L) { "durationMillis must not be negative." }
            require(sample.inputTokens == null || sample.inputTokens >= 0L) {
                "inputTokens must not be negative."
            }
            require(sample.outputTokens == null || sample.outputTokens >= 0L) {
                "outputTokens must not be negative."
            }
            require(sample.cost == null || sample.cost >= 0.0) { "cost must not be negative." }
            require(sample.invalidFilterCalls >= 0) { "invalidFilterCalls must not be negative." }
            require(sample.filterLeaseRestoreFailures >= 0) {
                "filterLeaseRestoreFailures must not be negative."
            }
        }
        val byScenario = samples.groupBy { it.scenarioId }
        val metrics = expectations.map { expectation ->
            metricsFor(expectation, byScenario[expectation.id].orEmpty())
        }
        val allRuns = samples
        val expectedFindingTotal = metrics.sumOf { it.expectedFindingCount }
        val findingHitTotal = metrics.sumOf { it.findingHits }
        val evidenceTotal = metrics.sumOf { it.evidenceFrameCitations }
        val validEvidenceTotal = metrics.sumOf { it.validEvidenceFrameCitations }
        val requiredEvidenceTotal = metrics.sumOf { it.requiredEvidenceFrames }
        val citedRequiredTotal = metrics.sumOf { it.citedRequiredEvidenceFrames }
        val totalToolCalls = allRuns.sumOf { it.toolCallCount }
        val summary = GoldenEvaluationSummary(
            scenarioCount = metrics.size,
            passedScenarioCount = metrics.count { it.passed },
            findingHitRate = ratio(findingHitTotal, expectedFindingTotal),
            evidenceFramePrecision = ratio(validEvidenceTotal, evidenceTotal),
            evidenceFrameRecall = ratio(citedRequiredTotal, requiredEvidenceTotal),
            unsupportedHighConfidenceFindings = metrics.sumOf { it.unsupportedHighConfidenceFindings },
            forbiddenConclusionHits = metrics.sumOf { it.forbiddenConclusionHits },
            boundaryDeclarationRate = ratio(metrics.sumOf { it.boundaryDeclarations }, allRuns.size),
            invalidFilterRate = ratio(metrics.sumOf { it.invalidFilterCalls }, totalToolCalls),
            filterLeaseRestoreFailures = metrics.sumOf { it.filterLeaseRestoreFailures },
            averageToolCalls = average(allRuns.map { it.toolCallCount.toDouble() }),
            averageDurationMillis = average(allRuns.map { it.durationMillis.toDouble() }),
            averageInputTokens = averageNullable(allRuns.map { it.inputTokens?.toDouble() }),
            averageOutputTokens = averageNullable(allRuns.map { it.outputTokens?.toDouble() }),
            averageCost = averageNullable(allRuns.map { it.cost }),
            consistencyRate = average(metrics.map { it.consistencyRate }),
            scenarioGroups = groupedMetrics(metrics),
            judgeRuns = metrics.sumOf { it.judgeRuns },
            judgeDisallowedRootCauseHits = metrics.sumOf { it.judgeDisallowedRootCauseHits },
            judgeRequiredAttributionMisses = metrics.sumOf { it.judgeRequiredAttributionMisses },
            judgeApplicable = metrics.any { it.judgeApplicable }
        )
        return AgentEvaluationReport(SCHEMA_VERSION, metadata, metrics, summary)
    }

    /**
     * Judge prompts for one evaluation set (OPT-EVAL-02-02): one request per
     * live sample whose expectation carries an [GoldenAttributionRubric],
     * in sample order.  Offline Mock samples (the default, `isLive = false`)
     * and rubric-free expectations are not applicable — they get no request
     * and are never scored — so the judge pass stays "live samples only"
     * and the eleven families without a rubric keep contributing nothing.
     */
    fun judgeRequests(
        expectations: List<GoldenCaptureExpectation>,
        samples: List<GoldenRunSample>
    ): List<GoldenJudgeRequest> {
        val expectationById = expectations.associateBy { it.id }
        return samples.mapNotNull { sample -> judgeRequestFor(expectationById[sample.scenarioId], sample) }
    }

    /**
     * Runs [judge] over the applicable samples of [judgeRequests] and
     * returns copies carrying the resulting verdicts; every other sample is
     * returned unchanged, and the caller feeds the result back into
     * [evaluate].
     *
     * Deliberately fail-open around the judge itself: a throw or a `null`
     * verdict means "no score for this run" (the scenario still reports
     * `judgeApplicable = true, judgeRuns` short of its live run count, so
     * the coverage gap stays visible), and one bad judge call must never
     * abort an evaluation.  This function is the only verdict-attaching
     * path; note there is no counterpart that writes expectations — the
     * annotation set stays human-owned.
     */
    fun withJudgeVerdicts(
        expectations: List<GoldenCaptureExpectation>,
        samples: List<GoldenRunSample>,
        judge: (GoldenJudgeRequest) -> GoldenJudgeVerdict?
    ): List<GoldenRunSample> {
        val expectationById = expectations.associateBy { it.id }
        return samples.map { sample ->
            val request = judgeRequestFor(expectationById[sample.scenarioId], sample)
                ?: return@map sample
            val verdict = runCatching { judge(request) }.getOrNull() ?: return@map sample
            sample.copy(judgeVerdict = verdict)
        }
    }

    private fun judgeRequestFor(
        expectation: GoldenCaptureExpectation?,
        sample: GoldenRunSample
    ): GoldenJudgeRequest? {
        val rubric = expectation?.attributionRubric ?: return null
        if (!sample.isLive) return null
        return GoldenJudgeRequest(
            scenarioId = sample.scenarioId,
            expectationId = expectation.id,
            question = expectation.question,
            requiredRootCause = rubric.requiredRootCause,
            disallowedRootCauses = rubric.disallowedRootCauses,
            reportText = reportText(sample.report)
        )
    }

    /**
     * Aggregates the same run-level counters per §9.2-8 scenario group.  Each
     * group rate reuses the overall formulas verbatim, restricted to the
     * group's scenarios, so the two groups' `findingHitRate`s are directly
     * comparable with each other and with the whole-set figure.
     */
    private fun groupedMetrics(metrics: List<GoldenScenarioMetrics>): List<GoldenScenarioGroupMetrics> =
        metrics.groupBy { it.groupId }
            .map { (groupId, scenarios) ->
                val expectedTotal = scenarios.sumOf { it.expectedFindingCount }
                GoldenScenarioGroupMetrics(
                    groupId = groupId,
                    scenarioCount = scenarios.size,
                    runs = scenarios.sumOf { it.runs },
                    expectedFindingCount = expectedTotal,
                    findingHits = scenarios.sumOf { it.findingHits },
                    findingHitRate = ratio(scenarios.sumOf { it.findingHits }, expectedTotal),
                    evidenceFramePrecision = ratio(
                        scenarios.sumOf { it.validEvidenceFrameCitations },
                        scenarios.sumOf { it.evidenceFrameCitations }
                    ),
                    evidenceFrameRecall = ratio(
                        scenarios.sumOf { it.citedRequiredEvidenceFrames },
                        scenarios.sumOf { it.requiredEvidenceFrames }
                    ),
                    passedScenarioCount = scenarios.count { it.passed }
                )
            }
            .sortedBy { group ->
                GoldenScenarioGrouping.GROUP_ORDER.indexOf(group.groupId).let { index ->
                    if (index < 0) GoldenScenarioGrouping.GROUP_ORDER.size else index
                }
            }

    fun write(report: AgentEvaluationReport, jsonFile: File, markdownFile: File) {
        jsonFile.parentFile?.mkdirs()
        markdownFile.parentFile?.mkdirs()
        jsonFile.writeText(report.toJson())
        markdownFile.writeText(report.toMarkdown())
    }

    /** Real-model evaluation is opt-in and requires a separately provisioned key. */
    fun requireExternalEvaluationEnabled(environment: Map<String, String>) {
        val enabled = environment[EXTERNAL_EVALUATION_FLAG]
            ?.equals("true", ignoreCase = true) == true
        require(enabled) {
            "External model evaluation is disabled. Set $EXTERNAL_EVALUATION_FLAG=true explicitly."
        }
        require(!environment[EXTERNAL_CREDENTIAL].isNullOrBlank()) {
            "External model evaluation requires $EXTERNAL_CREDENTIAL."
        }
    }

    private fun metricsFor(
        expectation: GoldenCaptureExpectation,
        runs: List<GoldenRunSample>
    ): GoldenScenarioMetrics {
        if (runs.isEmpty()) {
            return GoldenScenarioMetrics(
                scenarioId = expectation.id,
                runs = 0,
                expectedFindingCount = expectation.expectedFindings.size,
                findingHits = 0,
                evidenceFrameCitations = 0,
                validEvidenceFrameCitations = 0,
                requiredEvidenceFrames = expectation.requiredEvidenceFrames.size,
                citedRequiredEvidenceFrames = 0,
                unsupportedHighConfidenceFindings = 0,
                forbiddenConclusionHits = 0,
                boundaryDeclarations = 0,
                invalidFilterCalls = 0,
                filterLeaseRestoreFailures = 0,
                averageToolCalls = 0.0,
                averageDurationMillis = 0.0,
                averageInputTokens = null,
                averageOutputTokens = null,
                averageCost = null,
                consistencyRate = 0.0,
                passed = false
            )
        }

        val perRun = runs.map { evaluateRun(expectation, it) }
        val expectedFindings = expectation.expectedFindings
        val findingHits = perRun.sumOf { it.findingHits }
        val evidenceCitations = perRun.sumOf { it.evidenceCitations }
        val validEvidence = perRun.sumOf { it.validEvidenceCitations }
        val requiredEvidence = expectation.requiredEvidenceFrames.toSet()
        val citedRequired = perRun.sumOf { it.citedFrames.intersect(requiredEvidence).size }
        val consistency = consistency(runs)
        val passed = perRun.all { it.findingHits == expectedFindings.size &&
            it.expectedFindingsSatisfied &&
            it.forbiddenConclusionHits == 0 &&
            it.unsupportedHighConfidenceFindings == 0 &&
            it.citedFrames.containsAll(requiredEvidence) &&
            it.boundaryDeclared &&
            it.sample.toolCallCount <= expectation.maximumToolCalls &&
            it.sample.filterLeaseRestoreFailures == 0 &&
            it.sample.error.isNullOrBlank()
        }
        return GoldenScenarioMetrics(
            scenarioId = expectation.id,
            runs = runs.size,
            expectedFindingCount = expectedFindings.size,
            findingHits = findingHits,
            evidenceFrameCitations = evidenceCitations,
            validEvidenceFrameCitations = validEvidence,
            requiredEvidenceFrames = requiredEvidence.size * runs.size,
            citedRequiredEvidenceFrames = citedRequired,
            unsupportedHighConfidenceFindings = perRun.sumOf { it.unsupportedHighConfidenceFindings },
            forbiddenConclusionHits = perRun.sumOf { it.forbiddenConclusionHits },
            boundaryDeclarations = perRun.count { it.boundaryDeclared },
            invalidFilterCalls = runs.sumOf { it.invalidFilterCalls },
            filterLeaseRestoreFailures = runs.sumOf { it.filterLeaseRestoreFailures },
            averageToolCalls = average(runs.map { it.toolCallCount.toDouble() }),
            averageDurationMillis = average(runs.map { it.durationMillis.toDouble() }),
            averageInputTokens = averageNullable(runs.map { it.inputTokens?.toDouble() }),
            averageOutputTokens = averageNullable(runs.map { it.outputTokens?.toDouble() }),
            averageCost = averageNullable(runs.map { it.cost }),
            consistencyRate = consistency,
            passed = passed,
            // Judge counters ride along as pure reporting (OPT-EVAL-02-02);
            // the `passed` computation above never reads them.
            judgeRuns = perRun.count { it.judgeScored },
            judgeDisallowedRootCauseHits = perRun.sumOf { it.judgeDisallowedRootCauseHits },
            judgeRequiredAttributionMisses = perRun.count { it.judgeRequiredAttributionMiss },
            judgeApplicable = expectation.attributionRubric != null &&
                runs.any { it.isLive }
        )
    }

    private fun evaluateRun(
        expectation: GoldenCaptureExpectation,
        sample: GoldenRunSample
    ): RunMetrics {
        val report = sample.report
        val toolFrames = sample.toolResultFramesByCall.values.flatten().toSet()
        val evidence = report?.findings.orEmpty().flatMap { it.evidence }
        val frameEvidence = evidence.filter { it.frameNumber != null }
        val validEvidence = frameEvidence.filter { item ->
            val frame = item.frameNumber ?: return@filter false
            frame in 1L..expectation.captureFrameCount.toLong() &&
                frame in sample.toolResultFramesByCall[item.sourceToolCallId].orEmpty()
        }
        val citedFrames = validEvidence.mapNotNull { it.frameNumber }.toSet()
        val remainingFindings = report?.findings.orEmpty().toMutableList()
        val findingMatchesByExpectation = expectation.expectedFindings.map { expected ->
            remainingFindings.firstOrNull { actual -> findingMatches(expected, actual) }
                ?.also { actual -> remainingFindings.remove(actual) }
        }
        val findingHits = findingMatchesByExpectation.count { it != null }
        val expectedFindingsSatisfied = expectation.expectedFindings.zip(findingMatchesByExpectation)
            .all { (expected, actual) ->
                actual != null && expected.requiredEvidenceFrames.all { frame ->
                    actual.evidence.any { item ->
                        item.frameNumber == frame &&
                            frame in sample.toolResultFramesByCall[item.sourceToolCallId].orEmpty()
                    }
                }
            }
        val unsupported = report?.findings.orEmpty().count { finding ->
            finding.confidence.name.equals("High", ignoreCase = true) &&
                finding.evidence.none { evidenceItem ->
                    val sourceFrames = sample.toolResultFramesByCall[evidenceItem.sourceToolCallId]
                    val frame = evidenceItem.frameNumber
                    evidenceItem.sourceToolCallId in sample.toolResultFramesByCall &&
                        (frame == null || (
                            frame in toolFrames &&
                                frame in 1L..expectation.captureFrameCount.toLong() &&
                                frame in sourceFrames.orEmpty()
                            ))
                }
        }
        val reportText = reportText(report)
        val forbiddenHits = expectation.forbiddenConclusions.count { marker ->
            marker.isNotBlank() && reportText.contains(marker.normalizeForMatch())
        }
        val boundary = expectation.expectedLimitations.all { marker ->
            marker.isNotBlank() && reportText.contains(marker.normalizeForMatch())
        }
        val judge = judgeSignalFor(expectation, sample)
        return RunMetrics(
            sample = sample,
            findingHits = findingHits,
            expectedFindingsSatisfied = expectedFindingsSatisfied,
            evidenceCitations = frameEvidence.size,
            validEvidenceCitations = validEvidence.size,
            citedFrames = citedFrames,
            unsupportedHighConfidenceFindings = unsupported,
            forbiddenConclusionHits = forbiddenHits,
            boundaryDeclared = boundary,
            judgeScored = judge.scored,
            judgeDisallowedRootCauseHits = judge.disallowedRootCauseHits,
            judgeRequiredAttributionMiss = judge.requiredAttributionMiss
        )
    }

    /**
     * Maps one optional [GoldenJudgeVerdict] to the per-run binary counters
     * (OPT-EVAL-02-02).  Everything about this mapping is subtractive or
     * silent — it can only add judge reporting, never deterministic signal:
     * - verdicts on non-live samples are ignored (offline Mock stays
     *   judge-free),
     * - verdicts without a rubric-bearing expectation are ignored,
     * - a blank `judgeId` drops the verdict (fail-closed on provenance),
     * - `disallowedRootCausesAttributed` entries match only the expectation
     *   rubric's own labels under [String.normalizeForMatch]; hallucinated
     *   labels are dropped, and each rubric label counts at most once per
     *   run, mirroring the forbidden-conclusion scan shape,
     * - `requiredRootCauseAttributed = false` scores one attribution miss.
     */
    private fun judgeSignalFor(
        expectation: GoldenCaptureExpectation,
        sample: GoldenRunSample
    ): RunJudgeSignal {
        val verdict = sample.judgeVerdict ?: return NOT_JUDGED
        val rubric = expectation.attributionRubric ?: return NOT_JUDGED
        if (!sample.isLive) return NOT_JUDGED
        if (verdict.judgeId.isBlank()) return NOT_JUDGED
        val matched = rubric.disallowedRootCauses.count { disallowed ->
            val key = disallowed.normalizeForMatch()
            key.isNotBlank() && verdict.disallowedRootCausesAttributed.any { label ->
                val labelKey = label.normalizeForMatch()
                labelKey.isNotBlank() && labelKey == key
            }
        }
        return RunJudgeSignal(
            scored = true,
            disallowedRootCauseHits = matched,
            requiredAttributionMiss = !verdict.requiredRootCauseAttributed
        )
    }

    private data class RunJudgeSignal(
        val scored: Boolean,
        val disallowedRootCauseHits: Int,
        val requiredAttributionMiss: Boolean
    )

    private fun findingMatches(expected: GoldenExpectedFinding, actual: com.example.layanalyzer.model.AgentFinding): Boolean {
        val expectedId = expected.id.normalizeForMatch()
        val expectedKind = expected.kind.normalizeForMatch()
        val actualText = listOf(actual.id, actual.title, actual.conclusion)
            .joinToString(" ")
            .normalizeForMatch()
        val nameMatches = actual.id.normalizeForMatch() == expectedId ||
            actualText.contains(expectedKind) ||
            actualText.contains(expectedId)
        return nameMatches &&
            severityMatches(expected.severity, actual.severity.name) &&
            confidenceRank(actual.confidence.name) >= confidenceRank(expected.minimumConfidence)
    }

    private fun severityMatches(expected: String, actual: String): Boolean {
        val expectedValue = expected.normalizeForMatch()
        val actualValue = actual.normalizeForMatch()
        return when (expectedValue) {
            // The expectation vocabulary uses High for a high-impact finding;
            // AgentFindingSeverity represents that value as Critical.
            "high" -> actualValue == "high" || actualValue == "critical"
            else -> actualValue == expectedValue
        }
    }

    private fun confidenceRank(value: String): Int = when (value.normalizeForMatch()) {
        "high" -> 3
        "medium" -> 2
        "low" -> 1
        else -> 0
    }

    private fun reportText(report: AgentReport?): String = listOfNotNull(
        report?.summary,
        report?.limitations?.joinToString(" "),
        report?.recommendedNextSteps?.joinToString(" "),
        report?.findings?.joinToString(" ") { finding ->
            listOf(finding.id, finding.title, finding.conclusion)
                .plus(finding.alternatives)
                .plus(finding.recommendations)
                .plus(finding.timeline.flatMap { event -> listOf(event.stage, event.detail) })
                .plus(finding.evidence.flatMap { item ->
                    listOfNotNull(item.observation, item.observedValue, item.displayFilter)
                })
                .joinToString(" ")
        }
    ).joinToString(" ").normalizeForMatch()

    private fun consistency(samples: List<GoldenRunSample>): Double {
        if (samples.isEmpty()) return 0.0
        val signatures = samples.map { sample ->
            sample.report?.findings.orEmpty()
                .map { finding ->
                    listOf(
                        finding.id,
                        finding.title,
                        finding.severity.name,
                        finding.confidence.name,
                        finding.evidence.mapNotNull { it.frameNumber }.sorted().joinToString(",")
                    ).joinToString("|")
                }
                .sorted()
                .joinToString(";")
        }.distinct().size
        return (1.0 - (signatures - 1).toDouble() / samples.size).coerceIn(0.0, 1.0)
    }

    private data class RunMetrics(
        val sample: GoldenRunSample,
        val findingHits: Int,
        val expectedFindingsSatisfied: Boolean,
        val evidenceCitations: Int,
        val validEvidenceCitations: Int,
        val citedFrames: Set<Long>,
        val unsupportedHighConfidenceFindings: Int,
        val forbiddenConclusionHits: Int,
        val boundaryDeclared: Boolean,
        val judgeScored: Boolean = false,
        val judgeDisallowedRootCauseHits: Int = 0,
        val judgeRequiredAttributionMiss: Boolean = false
    )

    private val NOT_JUDGED = RunJudgeSignal(scored = false, disallowedRootCauseHits = 0, requiredAttributionMiss = false)
}

private fun String.normalizeForMatch(): String = replace(Regex("([a-z])([A-Z])"), "$1 $2")
    .lowercase(Locale.US)
    .replace(Regex("[^a-z0-9]+"), " ")
    .trim()
    .replace(Regex("\\s+"), " ")

private fun ratio(numerator: Int, denominator: Int): Double =
    if (denominator <= 0) 0.0 else numerator.toDouble() / denominator

private fun average(values: List<Double>): Double =
    if (values.isEmpty()) 0.0 else values.average()

private fun averageNullable(values: List<Double?>): Double? {
    val present = values.filterNotNull()
    return present.takeIf { it.isNotEmpty() }?.average()
}

private fun Double.percent(): String = String.format(Locale.US, "%.1f%%", this * 100.0)

private fun Double.decimal(): String = String.format(Locale.US, "%.1f", this)

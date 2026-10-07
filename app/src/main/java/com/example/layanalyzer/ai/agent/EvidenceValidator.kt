package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentCaptureSnapshot
import com.example.layanalyzer.model.AgentConfidence
import com.example.layanalyzer.model.AgentErrorCode
import com.example.layanalyzer.model.AgentEvidence
import com.example.layanalyzer.model.AgentEvidenceType
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentFindingPolarity
import com.example.layanalyzer.model.AgentFindingSeverity
import com.example.layanalyzer.model.AgentReport
import com.example.layanalyzer.model.AgentReportCompleteness
import java.util.Locale
import kotlin.math.abs

/**
 * Why a run stopped.  The validator uses this to decide completeness, so the
 * model cannot describe a truncated run as Complete.
 */
enum class AgentStopReason {
    /** The model produced a final report on its own. */
    ModelFinal,
    MaxStepsReached,
    MaxDurationReached,
    ContextLimit,
    PlanComplete,
    /** The model kept asking the same validated query without advancing. */
    RepeatedToolCall,
    ToolFailure,
    SessionChanged,
    ModelFailure,
    /** The model kept submitting arguments the host could not accept. */
    InvalidArguments,
    Cancelled
}

/** Everything about the run that the validator is allowed to consider. */
data class AgentRunTrace(
    val snapshot: AgentCaptureSnapshot,
    val ledger: EvidenceLedger,
    val stopReason: AgentStopReason = AgentStopReason.ModelFinal,
    val budgetUsage: AgentBudgetUsage = AgentBudgetUsage(),
    /** Set when the run's scope could not cover the whole capture. */
    val scopeIncomplete: Boolean = false,
    /** The plan the model declared in this run, when one was accepted. */
    val declaredPlan: AgentAnalysisPlan? = null,
    /** Indices into [declaredPlan]'s steps that the loop matched to tool calls. */
    val completedPlanStepIndices: Set<Int> = emptySet(),
    /**
     * OPT-VAL-01-02 rule 2: host-authored limitations for playbook checks the
     * run left uncovered when its report was accepted. The loop decides this
     * at submit acceptance (rejection is its business, not the validator's);
     * the trace merely carries the final verdict into `report.limitations`.
     */
    val playbookCheckGapLimitations: List<String> = emptyList(),
    /**
     * OPT-VAL-02-03 rule 3: the host-enumerated baseline signals the report
     * author was shown (design §5.2). [ReportCoverageValidator] compares them
     * against the final surviving findings, limitations and Critic
     * dispositions, and every signal left unaddressed contributes one
     * host-authored limitation — the post-validation net that also catches a
     * finding the submit gate counted as coverage but validation later
     * stripped away. An empty list means nothing to check, so reports whose
     * run never enumerated a signal (and delegated child reports, whose
     * author was never shown the parent's signals) validate unchanged.
     */
    val signals: List<AgentSignal> = emptyList(),
    /**
     * Signal ids dispositioned as addressed by the Critic's
     * `unaddressedSignals` channel (design §4.2/§5.2). The channel lands
     * with OPT-COG-03-03, which will feed this field; until then the default
     * empty set keeps the accounting host-only.
     */
    val criticAddressedSignalIds: Set<String> = emptySet(),
    /**
     * Whether the run negotiated structured output (OPT-VAL-03-01, fed from
     * `modelClient.capabilities.structuredOutput` by the loop). The single
     * gate for narrating a missing `questionAlignment` field as one host
     * limitation: only a client that could have honoured the now-required
     * schema field is narrated, and a missing field is never a rejection
     * (§3 degradation contract). False — the default — keeps every other
     * caller (tests, replay paths) byte-for-byte unchanged.
     */
    val structuredOutputAvailable: Boolean = false,
    /**
     * EVL-COVERAGE-02: the run's evidence-coverage receipt, computed by the
     * loop at report acceptance from this run's evidence set (the ledger's
     * successful tool results) versus the frame numbers the submitted report
     * cites. Null — the default — for every caller that does not compute the
     * receipt (older constructions, tests, replay paths), which keeps those
     * reports byte-for-byte unchanged. Audit data only: the validator reads
     * nothing from it, and the uncited-frame limitation it feeds is appended
     * by the loop after validation, never through a model-writable channel.
     */
    val evidenceCoverage: EvidenceCoverage? = null
)

/** A rejected citation and the reason, phrased for the report's limitations. */
data class EvidenceRejection(
    val findingId: String,
    val reason: String,
    val detail: String
) {
    fun toLimitation(): String = "Removed unverifiable evidence from \"$findingId\": $detail"
}

/** Outcome of validating one report. */
data class EvidenceValidationResult(
    val report: AgentReport,
    val rejections: List<EvidenceRejection> = emptyList(),
    val downgrades: List<String> = emptyList()
)

/**
 * The host's final say on what a report may claim.
 *
 * A model proposes conclusions; this validator confirms that every citation
 * corresponds to something a tool in *this* run actually returned, and caps the
 * confidence at what the surviving evidence supports.  Everything here is
 * subtractive by construction: evidence can only be dropped, confidence can only
 * fall, and completeness can only weaken.  There is no path through this class
 * that lets a model's own JSON raise any of them.
 */
class EvidenceValidator(
    // `clock` stays the last parameter: existing callers use the trailing
    // lambda idiom `EvidenceValidator { millis }`.
    private val policy: AgentPolicy = AgentPolicy(),
    private val coverageValidator: ReportCoverageValidator = ReportCoverageValidator(),
    private val clock: () -> Long = { System.currentTimeMillis() }
) {

    fun validate(report: AgentReport, trace: AgentRunTrace): EvidenceValidationResult {
        val rejections = mutableListOf<EvidenceRejection>()
        val downgrades = mutableListOf<String>()
        val truncationExemptions = mutableListOf<String>()

        val validatedFindings = report.findings.map { finding ->
            validateFinding(finding, trace, rejections, downgrades, truncationExemptions)
        }

        // OPT-VAL-03-01 rule 4 (design §5.3): structural verification of the
        // report's question-alignment entries, deliberately run AFTER the
        // per-citation decisions above so "surviving evidence" is judged on
        // the post-decision findings. Violating entries are removed and ride
        // the shared rejection channel — limitations auto-fill and the
        // revision trigger pick them up without knowing rule 4 exists.
        // Subtractive: the only outputs are removals and rejections.
        val alignment = coverageValidator.alignmentGaps(
            alignment = report.questionAlignment,
            survivingFindings = validatedFindings,
            enforcementEnabled = policy.enforceQuestionAlignment
        )
        rejections += alignment.rejections

        val completeness = weakestCompleteness(report.completeness, completenessFor(trace))
        val limitations = buildLimitations(
            reported = report.limitations,
            rejections = rejections,
            downgrades = downgrades,
            trace = trace,
            completeness = completeness,
            truncationExemptions = truncationExemptions,
            survivingFindings = validatedFindings,
            alignmentExcessLimitations = alignment.excessLimitations,
            alignmentDeclared = report.questionAlignment.isNotEmpty()
        )

        return EvidenceValidationResult(
            report = report.copy(
                findings = validatedFindings,
                limitations = limitations,
                questionAlignment = alignment.kept,
                completeness = completeness,
                provenance = report.provenance.copy(
                    captureFingerprint = trace.snapshot.captureFingerprint,
                    scope = trace.snapshot.scope,
                    displayFilter = trace.snapshot.displayFilter,
                    evidenceFrameCount = trace.snapshot.evidenceFrameCount,
                    toolCallIds = trace.ledger.toolCallIds,
                    generatedAtMillis = report.provenance.generatedAtMillis.takeIf { it > 0L }
                        ?: clock()
                )
            ),
            rejections = rejections,
            downgrades = downgrades
        )
    }

    // ---------------------------------------------------------------- findings

    private fun validateFinding(
        finding: AgentFinding,
        trace: AgentRunTrace,
        rejections: MutableList<EvidenceRejection>,
        downgrades: MutableList<String>,
        truncationExemptions: MutableList<String>
    ): AgentFinding {
        val findingId = finding.id.ifBlank { finding.title.ifBlank { "finding" } }

        // (OPT-VAL-04-02) Whether this finding declares `Negative` and grounds
        // the absence claim in at least one citation that itself satisfies all
        // four negative requirements. Only then are all of the finding's
        // citations reviewed under the finding-level standard; an ungrounded
        // negative claim falls back to the legacy marker floor so nothing is
        // mass-rejected by the trigger migration alone.
        val groundedNegativeFinding = policy.findingPolarityNegativeValidation &&
            finding.polarity == AgentFindingPolarity.Negative &&
            hasGroundedNegativeCitation(finding, trace)

        val surviving = mutableListOf<AgentEvidence>()
        val softFailures = mutableListOf<String>()
        finding.evidence.forEach { evidence ->
            val decision = decisionFor(evidence, finding, groundedNegativeFinding, trace)
            decision.rejection?.let { rejection ->
                rejections += EvidenceRejection(findingId, rejection.first, rejection.second)
            } ?: run {
                surviving += evidence
                decision.downgradeReason?.let(softFailures::add)
            }
        }

        softFailures.forEach { reason ->
            downgrades += "Metric evidence for \"$findingId\" was retained as unverified: $reason"
        }

        val cappedConfidence = confidenceCap(
            finding = finding,
            findingId = findingId,
            surviving = surviving,
            trace = trace,
            hasSoftFailure = softFailures.isNotEmpty(),
            truncationExemptions = truncationExemptions
        )
        val confidence = weakest(finding.confidence, cappedConfidence)
        if (confidence != finding.confidence) {
            downgrades += "Lowered confidence for \"$findingId\" to ${confidence.name}."
        }

        // A finding with nothing behind it becomes a hypothesis rather than
        // staying an assertion the user might act on, regardless of severity.
        val downgradeToHypothesis = surviving.isEmpty()

        val conclusion = if (downgradeToHypothesis) {
            downgrades += "Restated \"$findingId\" as a hypothesis: no verifiable evidence remained."
            hypothesisPhrasing(finding.conclusion)
        } else {
            finding.conclusion
        }

        return finding.copy(
            evidence = surviving,
            timeline = finding.timeline.filter { event ->
                event.frameNumber == null || surviving.any { it.frameNumber == event.frameNumber }
            },
            confidence = confidence,
            conclusion = conclusion,
            severity = if (downgradeToHypothesis) AgentFindingSeverity.Notice else finding.severity
        )
    }

    // ---------------------------------------------------- reference integrity

    /** Host decision for one citation: reject it, or retain it with a warning. */
    private fun decisionFor(
        evidence: AgentEvidence,
        finding: AgentFinding,
        groundedNegativeFinding: Boolean,
        trace: AgentRunTrace
    ): EvidenceDecision {
        val toolCallId = evidence.sourceToolCallId.trim()
        if (toolCallId.isEmpty()) {
            return reject("missing_source", "a citation carried no source tool call id")
        }

        val entry = trace.ledger.find(toolCallId)
            ?: return reject(
                "unknown_source",
                "a citation referenced tool call \"$toolCallId\", which did not run in this analysis"
            )

        if (!entry.success) {
            return reject(
                "failed_source",
                "a citation referenced ${entry.toolName}, which did not return data"
            )
        }

        evidence.frameNumber?.let { frame ->
            if (frame < 1L || frame > trace.snapshot.frameCount.toLong()) {
                return reject(
                    "frame_out_of_range",
                    "frame $frame is outside the capture (1-${trace.snapshot.frameCount})"
                )
            }
            if (frame !in entry.frameNumbers) {
                return reject(
                    "frame_not_returned",
                    "frame $frame was not part of what ${entry.toolName} returned"
                )
            }
        }

        var downgradeReason: String? = null

        // A statistic that names no frame has to name what it measured instead,
        // otherwise there is nothing to re-check it against.
        if (evidence.frameNumber == null && requiresMetric(evidence.type)) {
            val metric = evidence.metric?.trim().orEmpty()
            val observedValue = evidence.observedValue?.trim().orEmpty()
            if (metric.isEmpty() || observedValue.isEmpty()) {
                return reject(
                    "statistic_without_metric",
                    "a statistical citation carried no metric name and observed value"
                )
            }
            if (!entry.leafMetrics.contains(metric) && !metricSuffixMatches(metric, entry.leafMetrics)) {
                return reject(
                    "metric_not_returned",
                    "metric \"$metric\" was not a scalar value returned by ${entry.toolName}"
                )
            }

            val actualValues = metricValuesFor(metric, entry)
            if (actualValues.isNotEmpty() && actualValues.none { valuesAgree(observedValue, it) }) {
                downgradeReason =
                    "metric_value_mismatch: metric \"$metric\" was observed as " +
                        "${actualValues.joinToString()} but the citation claimed \"$observedValue\""
            }
        }

        evidence.displayFilter?.trim()?.takeIf { it.isNotEmpty() }?.let { filter ->
            if (filter !in trace.ledger.validatedFilters()) {
                return reject(
                    "filter_not_validated",
                    "display filter \"$filter\" was never compiled by the host"
                )
            }
        }

        evidence.field?.trim()?.takeIf { it.isNotEmpty() }?.let { field ->
            if (field !in entry.fields) {
                return reject(
                    "field_not_projected",
                    "field \"$field\" was not part of what ${entry.toolName} returned"
                )
            }
        }

        // "No X occurred" is only checkable when the citation says what was
        // searched, over what range, and whether the search saw everything.
        // (OPT-VAL-04-02) The primary trigger is the finding's declared
        // polarity, not the observation's prose; see [negativeTriggerFor].
        when (negativeTriggerFor(finding, groundedNegativeFinding, evidence)) {
            NegativeTrigger.None -> Unit
            NegativeTrigger.ObservationMarker -> negativeEvidenceDecision(
                evidence,
                entry,
                trace,
                atFindingLevel = false
            )?.let { return it }
            NegativeTrigger.FindingPolarity -> negativeEvidenceDecision(
                evidence,
                entry,
                trace,
                atFindingLevel = true
            )?.let { return it }
            NegativeTrigger.PolarityConflict -> return reject(
                "polarity_claim_conflict",
                "a citation of a finding declared " +
                    "${finding.polarity.name.lowercase(Locale.ROOT)} asserted an absence in its " +
                    "observation, contradicting that declaration (tool call $toolCallId)"
            )
        }

        return EvidenceDecision(downgradeReason = downgradeReason)
    }

    /** Which negative scrutiny, if any, applies to one citation (OPT-VAL-04-02). */
    private enum class NegativeTrigger {
        None,

        /** Legacy path: the observation's own text claims an absence. */
        ObservationMarker,

        /** Migrated path: the finding declares the absence claim. */
        FindingPolarity,

        /**
         * Cross-track check (OPT-VAL-04-03): the finding declares a presence
         * (Positive/Neutral) yet one of its citations phrases an absence, so the
         * declaration and its own observation contradict; the citation is
         * rejected outright rather than reviewed under the four requirements.
         */
        PolarityConflict
    }

    /**
     * Trigger dispatch for the negative requirements and the polarity
     * cross-check:
     *
     *  * policy off — legacy per-observation marker path for every polarity,
     *    including `Positive`/`Neutral`: the pre-OPT-VAL-04 behaviour, where a
     *    marker alone triggers the four requirements and no conflict exists;
     *  * `Unknown` polarity (field missing: old reports or unavailable
     *    structured output) — legacy marker path, byte-for-byte the pre-
     *    migration behaviour (the §3 degradation contract: a missing field
     *    never feeds a new rejection, and never a `polarity_claim_conflict`);
     *  * `Negative` — every citation of the finding is reviewed once the
     *    finding is grounded in a fully qualified negative citation, and the
     *    marker path still applies otherwise, so an ungrounded negative
     *    claim cannot lose the marker-level rejections it already had. A
     *    marker that agrees with the declared `Negative` is never a conflict;
     *  * `Positive`/`Neutral` — marker text no longer triggers the four
     *    requirements, but an observation that claims an absence while the
     *    finding declares a presence is the cross-track contradiction, so it
     *    becomes a [NegativeTrigger.PolarityConflict] rejection
     *    (`polarity_claim_conflict`, OPT-VAL-04-03).
     */
    private fun negativeTriggerFor(
        finding: AgentFinding,
        groundedNegativeFinding: Boolean,
        evidence: AgentEvidence
    ): NegativeTrigger = when {
        !policy.findingPolarityNegativeValidation ||
            finding.polarity == AgentFindingPolarity.Unknown ->
            if (isNegativeClaim(evidence.observation)) {
                NegativeTrigger.ObservationMarker
            } else {
                NegativeTrigger.None
            }

        finding.polarity == AgentFindingPolarity.Negative -> when {
            groundedNegativeFinding -> NegativeTrigger.FindingPolarity
            isNegativeClaim(evidence.observation) -> NegativeTrigger.ObservationMarker
            else -> NegativeTrigger.None
        }

        else ->
            if (isNegativeClaim(evidence.observation)) {
                NegativeTrigger.PolarityConflict
            } else {
                NegativeTrigger.None
            }
    }

    /**
     * Whether one citation satisfies all four negative requirements by itself:
     * a named filter, an evidence-level time range, a successful complete
     * source, and an executed filter with zero matches.  This is the "0-
     * matches requires a full-scan basis" material from [negativeEvidenceDecision]
     * reused as the grounding test; the requirements themselves are unchanged.
     */
    private fun qualifiesAsNegativeCitation(
        evidence: AgentEvidence,
        trace: AgentRunTrace
    ): Boolean {
        val filter = evidence.displayFilter?.trim().orEmpty()
        if (filter.isEmpty()) return false
        if (evidence.timeRangeStartMillis == null || evidence.timeRangeEndMillis == null) {
            return false
        }
        val entry = trace.ledger.find(evidence.sourceToolCallId.trim())
        if (entry == null || !entry.success || !entry.complete) return false
        return trace.ledger.executedFilterMatches()[filter] == 0L
    }

    private fun hasGroundedNegativeCitation(
        finding: AgentFinding,
        trace: AgentRunTrace
    ): Boolean = finding.evidence.any { qualifiesAsNegativeCitation(it, trace) }

    private data class EvidenceDecision(
        val rejection: Pair<String, String>? = null,
        val downgradeReason: String? = null
    )

    private fun reject(reason: String, detail: String): EvidenceDecision =
        EvidenceDecision(rejection = reason to detail)

    /**
     * A negative claim needs a filter, a time range and a complete source.
     * Without all three, "there were no retransmissions" is indistinguishable
     * from "the tool did not look for retransmissions".
     *
     * The reason codes are shared between the two triggers (OPT-VAL-04-02);
     * only the observation-level phrasing becomes finding-level phrasing when
     * the scrutiny is driven by the finding's declared polarity, so the
     * limitation line points at the finding rather than at a sentence the
     * citation never wrote. The finding's stable id rides along in every
     * [EvidenceRejection] already.
     */
    private fun negativeEvidenceDecision(
        evidence: AgentEvidence,
        entry: EvidenceLedgerEntry,
        trace: AgentRunTrace,
        atFindingLevel: Boolean
    ): EvidenceDecision? {
        val subject = if (atFindingLevel) {
            "a citation of a finding declared Negative"
        } else {
            "a negative statement"
        }
        val filter = evidence.displayFilter?.trim().orEmpty()
        if (filter.isEmpty()) {
            return reject(
                "negative_without_filter",
                "$subject did not say which display filter was searched"
            )
        }
        if (evidence.timeRangeStartMillis == null || evidence.timeRangeEndMillis == null) {
            return reject(
                "negative_without_time_range",
                "$subject did not say which time range was searched"
            )
        }
        if (!entry.complete) {
            return reject(
                "negative_from_incomplete_source",
                "$subject relied on ${entry.toolName}, which did not return complete data"
            )
        }

        val matches = trace.ledger.executedFilterMatches()[filter]
            ?: return reject(
                "negative_filter_never_executed",
                "display filter \"$filter\" was validated but never executed by an analysis tool"
            )
        if (matches > 0L) {
            return reject(
                "negative_contradicted_by_matches",
                "display filter \"$filter\" returned $matches matching packet(s)"
            )
        }
        return null
    }

    // ------------------------------------------------------------- confidence

    /**
     * The highest confidence the surviving evidence can support.
     *
     * High needs at least two *independent* evidence types that agree; a single
     * frame or a bare Info observation tops out at Medium; nothing at all is
     * Low.  A run that stopped early or had tools fail costs one further level
     * regardless of the finding, because the whole picture is uncertain.
     *
     * Truncation is judged per conclusion (OPT-VAL-07, behind
     * [AgentPolicy.preciseTruncationDowngrade]): a truncated source only caps
     * the confidence when the truncation can actually affect *this* finding —
     * otherwise the finding is restated on data the call really returned and a
     * limitation records the fact.  With the switch off, the previous rule
     * applies: any cited source that is not complete lowers the cap one level.
     */
    private fun confidenceCap(
        finding: AgentFinding,
        findingId: String,
        surviving: List<AgentEvidence>,
        trace: AgentRunTrace,
        hasSoftFailure: Boolean,
        truncationExemptions: MutableList<String>
    ): AgentConfidence {
        if (surviving.isEmpty()) return AgentConfidence.Low
        if (hasSoftFailure) return AgentConfidence.Low

        val distinctTypes = surviving.map { it.type }
            .filter { it != AgentEvidenceType.Unknown }
            .toSet()
        val distinctSources = surviving.map { it.sourceToolCallId }.toSet()

        // Two evidence types from two different tool calls is the only route to
        // High.  Everything else — a single frame, one bare observation, or two
        // citations of the same kind from the same call — tops out at Medium.
        val base = if (distinctTypes.size >= 2 && distinctSources.size >= 2) {
            AgentConfidence.High
        } else {
            AgentConfidence.Medium
        }

        val sourcesIncomplete = if (policy.preciseTruncationDowngrade) {
            truncationAffectsFinding(finding, findingId, surviving, trace, truncationExemptions)
        } else {
            surviving.any { evidence ->
                trace.ledger.find(evidence.sourceToolCallId)?.complete == false
            }
        }
        val runIncomplete = trace.scopeIncomplete ||
            trace.stopReason != AgentStopReason.ModelFinal ||
            trace.ledger.anyFailed()

        return if (sourcesIncomplete || runIncomplete) lowerOne(base) else base
    }

    /**
     * Does truncation of a cited source undermine this finding? (OPT-VAL-07-01)
     *
     * Returns true — keep the one-level cap — when any of:
     *  * the finding asserts absence or a whole-source aggregate that a
     *    truncated read cannot establish;
     *  * a citation into an incomplete source reaches beyond what that call
     *    actually returned (see [citationConfinedToReturnedSubset]); or
     *  * every surviving citation of the finding rests on incomplete sources,
     *    so there is no complete evidence to stand on (the "High path from one
     *    truncated read" case).
     *
     * Otherwise the finding only repeats facts inside the returned subset:
     * confidence is not capped, and each involved source contributes one
     * limitation line explaining why the truncation does not matter here.
     */
    private fun truncationAffectsFinding(
        finding: AgentFinding,
        findingId: String,
        surviving: List<AgentEvidence>,
        trace: AgentRunTrace,
        truncationExemptions: MutableList<String>
    ): Boolean {
        val incompleteSources = surviving.mapNotNull { evidence ->
            val toolCallId = evidence.sourceToolCallId.trim()
            trace.ledger.find(toolCallId)
                ?.takeIf { !it.complete }
                ?.let { toolCallId to it }
        }
        if (incompleteSources.isEmpty()) return false

        if (incompleteSources.size == surviving.size &&
            incompleteSources.map { it.first }.toSet() ==
            surviving.map { it.sourceToolCallId.trim() }.toSet()
        ) {
            // No complete evidence anywhere in this finding: the whole
            // conclusion would stand or fall on data the run never finished
            // reading, so the blanket cap stays.
            return true
        }

        if (hasNegativeOrAggregateAssertion(finding, surviving)) return true

        val notConfined = incompleteSources.any { (toolCallId, entry) ->
            surviving.filter { it.sourceToolCallId.trim() == toolCallId }
                .any { !citationConfinedToReturnedSubset(it, entry) }
        }
        if (notConfined) return true

        incompleteSources.map { it.second }.distinctBy { it.toolCallId }.forEach { entry ->
            // Stable ids only (tool name + call id + counts); never payload data.
            truncationExemptions.add(
                "Finding \"$findingId\" cites only data that the truncated ${entry.toolName} " +
                    "step [${entry.toolCallId}] returned (${entry.returnedCount} of " +
                    "${entry.totalCount} ${unitFor(entry)}), so that truncation did not " +
                    "lower its confidence."
            )
        }
        return false
    }

    /**
     * Whether one citation into an incomplete source is provably confined to
     * the rows that call really returned.
     *
     * Only frame-anchored citations qualify, and only by facts the ledger
     * already verified: `decisionFor` removed the citation outright if its
     * frame was not in [EvidenceLedgerEntry.frameNumbers], or if its field or
     * display filter was not part of what the call returned, so a surviving
     * frame-bearing citation names records inside the returned subset.  A
     * frameless citation cannot be shown to stay inside that subset — its
     * metric or observation describes whatever the truncated scan covered,
     * which is exactly the unseen tail truncation hides — so it keeps the cap.
     * This is deliberately structural (ledger facts only), never a guess about
     * the model's prose; when in doubt it downgrades.
     */
    private fun citationConfinedToReturnedSubset(
        evidence: AgentEvidence,
        entry: EvidenceLedgerEntry
    ): Boolean {
        val frame = evidence.frameNumber ?: return false
        return frame in entry.frameNumbers
    }

    /**
     * Whether the finding claims more than the returned rows can show.
     *
     * Negatives are short-circuited by the structured `polarity == Negative`
     * declaration — the primary trigger OPT-VAL-04-02 migrated the citation
     * checks to — and otherwise reuse the observation markers, which stay as
     * the fallback for undeclared findings until OPT-VAL-05-01 retires them.
     * Aggregate assertions — totals, counts, ratios and "all/every" statements
     * about the source — come from the task constraint that a truncated read
     * cannot support a whole-capture claim: the host has no structured fact
     * that ties a sentence to a population, so this is a conservative marker
     * predicate over the finding's own text (title, conclusion, evidence
     * observations).  Over-matching only costs a downgrade, which is the
     * safer side of the trade required by OPT-VAL-07-01.
     */
    private fun hasNegativeOrAggregateAssertion(
        finding: AgentFinding,
        surviving: List<AgentEvidence>
    ): Boolean {
        if (finding.polarity == AgentFindingPolarity.Negative) return true
        val texts = buildList {
            add(finding.title)
            add(finding.conclusion)
            surviving.forEach { add(it.observation) }
        }
        return texts.any { isNegativeClaim(it) || hasAggregateAssertion(it) }
    }

    private fun hasAggregateAssertion(text: String): Boolean {
        val normalized = text.lowercase(Locale.ROOT)
        val withoutProtocolPhrases = POSITIVE_EXCEPTIONS.fold(normalized) { phraseText, phrase ->
            phraseText.replace(phrase, " ")
        }
        return AGGREGATE_WORDS_EN.containsMatchIn(withoutProtocolPhrases) ||
            AGGREGATE_PHRASES_EN.any { withoutProtocolPhrases.contains(it) } ||
            AGGREGATE_MARKERS_ZH.any { withoutProtocolPhrases.contains(it) }
    }

    // ----------------------------------------------------------- completeness

    /**
     * Completeness is derived from the run, never read from the model's JSON.
     *
     * A run that ended with the model's own final report is Complete.  Anything
     * that stopped the run early is Incomplete, and a run whose tools failed is
     * Partial.  Truncated or partially-covered evidence no longer caps the
     * verdict below Complete: the model saw exactly what was returned and the
     * report states it, while the truncation facts still surface as limitations
     * and confidence downgrades.
     */
    private fun completenessFor(trace: AgentRunTrace): AgentReportCompleteness = when {
        trace.stopReason == AgentStopReason.ModelFinal -> AgentReportCompleteness.Complete

        trace.stopReason == AgentStopReason.Cancelled -> AgentReportCompleteness.Incomplete

        trace.stopReason == AgentStopReason.MaxStepsReached ||
            trace.stopReason == AgentStopReason.MaxDurationReached ||
            trace.stopReason == AgentStopReason.ContextLimit ||
            trace.stopReason == AgentStopReason.PlanComplete ||
            trace.stopReason == AgentStopReason.RepeatedToolCall ->
            AgentReportCompleteness.Incomplete

        trace.stopReason == AgentStopReason.SessionChanged ||
            trace.stopReason == AgentStopReason.ModelFailure ||
            trace.stopReason == AgentStopReason.InvalidArguments ->
            AgentReportCompleteness.Incomplete

        trace.stopReason == AgentStopReason.ToolFailure -> AgentReportCompleteness.Partial

        // A stop reason the host does not recognise fails closed.
        else -> AgentReportCompleteness.Incomplete
    }

    /**
     * The model may only ever weaken completeness.
     *
     * The host's verdict is the ceiling — that is what stops a model calling a
     * truncated run Complete.  But a model that recognises it answered only part
     * of the question is telling the truth about something the run trace cannot
     * see, so the lower of the two claims wins.  Unknown carries no information
     * and simply defers to the host.
     */
    private fun weakestCompleteness(
        claimed: AgentReportCompleteness,
        hostVerdict: AgentReportCompleteness
    ): AgentReportCompleteness {
        if (claimed == AgentReportCompleteness.Unknown) return hostVerdict
        return if (completenessRank(claimed) <= completenessRank(hostVerdict)) {
            claimed
        } else {
            hostVerdict
        }
    }

    private fun completenessRank(completeness: AgentReportCompleteness): Int = when (completeness) {
        AgentReportCompleteness.Unknown -> 0
        AgentReportCompleteness.Incomplete -> 1
        AgentReportCompleteness.Partial -> 2
        AgentReportCompleteness.Complete -> 3
    }

    // ------------------------------------------------------------ limitations

    private fun buildLimitations(
        reported: List<String>,
        rejections: List<EvidenceRejection>,
        downgrades: List<String>,
        trace: AgentRunTrace,
        completeness: AgentReportCompleteness,
        truncationExemptions: List<String> = emptyList(),
        survivingFindings: List<AgentFinding> = emptyList(),
        alignmentExcessLimitations: List<String> = emptyList(),
        alignmentDeclared: Boolean = true
    ): List<String> {
        val limitations = LinkedHashSet<String>()
        reported.filter { it.isNotBlank() }.forEach(limitations::add)

        rejections.forEach { limitations.add(it.toLimitation()) }
        downgrades.forEach(limitations::add)
        truncationExemptions.forEach(limitations::add)

        stopReasonLimitation(trace)?.let(limitations::add)
        // OPT-VAL-01-01 rule 1: unexecuted declared-plan steps share this
        // channel, so the revision loop, the limitations auto-fill, and the UI
        // pick them up without knowing coverage exists.
        coverageValidator.validate(trace).limitations.forEach(limitations::add)
        // OPT-VAL-01-02 rule 2: playbook-check gaps decided at submit
        // acceptance ride the same channel as already-authored prose.
        trace.playbookCheckGapLimitations.forEach(limitations::add)

        truncationLimitations(trace).forEach(limitations::add)
        trace.ledger.all().filter { !it.success }.forEach { entry ->
            limitations.add(
                "The ${entry.toolName} step did not complete" +
                    (entry.errorCode?.let { " (${it.name})" } ?: "") + "."
            )
        }
        if (trace.scopeIncomplete) {
            limitations.add("The analysis did not cover the complete capture.")
        }
        if (completeness != AgentReportCompleteness.Complete && trace.ledger.size == 0) {
            limitations.add("No analysis tool returned data, so no conclusion could be verified.")
        }
        // OPT-VAL-02-03 rule 3 net: the signals the report author was shown,
        // checked one last time against the FINAL surviving findings and every
        // non-marker limitation already in this set. Deliberately last — a
        // limitation added above (rejection prose included) may itself name a
        // signal id and close a gap; the gate's own marker-prefixed lines
        // cannot, which is what keeps this net from satisfying itself on a
        // second validation round (revision, reconcile). Subtractive-only:
        // this can add limitations, never remove one, and it cannot refuse —
        // by here the submission was already accepted.
        coverageValidator.signalCoverageGaps(
            signals = trace.signals,
            findings = survivingFindings,
            limitations = limitations.toList(),
            criticAddressedSignalIds = trace.criticAddressedSignalIds,
            enforcementEnabled = policy.enforceSignalCoverage
        ).unaddressedSignals.forEach { signal ->
            limitations.add(coverageValidator.signalGapLimitation(signal))
        }
        // OPT-VAL-03-01: entries beyond the schema cap were dropped
        // defensively by rule 4 (a shape only a schema-skirting transport can
        // produce — no reason code, one limitation line each). Removed
        // violations already rode the rejection channel above.
        alignmentExcessLimitations.forEach(limitations::add)
        // A missing/empty `questionAlignment` is never a rejection (§3
        // degradation contract): the host narrates one limitation, and only
        // on a run whose client could actually honour the now-required field
        // — the same structured-output signal OPT-VAL-02-03 gates its
        // attribution on. Plain-text runs stay byte-for-byte unchanged.
        if (policy.enforceQuestionAlignment &&
            trace.structuredOutputAvailable &&
            !alignmentDeclared
        ) {
            limitations.add(ReportCoverageValidator.QUESTION_ALIGNMENT_MISSING_LIMITATION)
        }

        return limitations.toList()
    }

    /**
     * Name what was actually missed, per tool.
     *
     * "Some analysis results were truncated" is true but useless: a reader cannot
     * tell whether one note was dropped from a complete picture or four fifths of
     * the Expert entries were never read, and those warrant very different
     * confidence in the report. Each truncated read therefore reports its own
     * shortfall in its own units, and only falls back to the generic sentence
     * when the counts say nothing useful.
     */
    private fun truncationLimitations(trace: AgentRunTrace): List<String> {
        val truncated = trace.ledger.all().filter { it.success && it.truncated }
        if (truncated.isEmpty()) return emptyList()

        val limitations = LinkedHashSet<String>()
        var anyGeneric = false
        truncated.forEach { entry ->
            val shortfall = entry.totalCount - entry.returnedCount
            if (entry.returnedCount > 0L && shortfall > 0L) {
                limitations.add(
                    "The ${entry.toolName} step read ${entry.returnedCount} of " +
                        "${entry.totalCount} available ${unitFor(entry)}, so $shortfall were " +
                        "not examined."
                )
            } else {
                anyGeneric = true
            }
        }
        if (anyGeneric) {
            limitations.add(
                "Some analysis results were truncated, so counts may be lower than the capture's."
            )
        }
        return limitations.toList()
    }

    /**
     * What a tool's counts are counting.
     *
     * A distribution read returns categories, not entries, so reporting "read 2
     * of 6 entries" for it would misstate the shortfall by two orders of
     * magnitude. Keyed on the tool rather than on the `sampled` flag, because an
     * aggregate scan sets that flag too and its counts are frames.
     */
    private fun unitFor(entry: EvidenceLedgerEntry): String = when (entry.toolName) {
        "get_expert_info" -> if (entry.coverageComplete != null) "groups" else "entries"
        "get_packet_fields", "query_packet_summaries", "query_packet_field_aggregate" -> "frames"
        "get_communication_analysis" -> "sessions"
        else -> "entries"
    }

    private fun stopReasonLimitation(trace: AgentRunTrace): String? = when (trace.stopReason) {
        AgentStopReason.ModelFinal -> null
        AgentStopReason.MaxStepsReached ->
            "The analysis stopped after reaching its step limit of ${trace.budgetUsage.maxSteps}."
        AgentStopReason.MaxDurationReached ->
            "The analysis stopped after reaching its time limit."
        AgentStopReason.ContextLimit ->
            "The analysis stopped after reaching its data limit."
        AgentStopReason.PlanComplete ->
            "The declared analysis plan completed; no additional tool calls were allowed."
        AgentStopReason.RepeatedToolCall ->
            "The analysis stopped after the model repeated the same tool query without advancing."
        AgentStopReason.ToolFailure ->
            "One or more analysis steps failed, so parts of the capture were not examined."
        AgentStopReason.SessionChanged ->
            "The capture changed while the analysis was running."
        AgentStopReason.ModelFailure ->
            "The analysis model stopped responding before the report was finished."
        AgentStopReason.InvalidArguments ->
            "The analysis model kept sending tool arguments the host could not accept."
        AgentStopReason.Cancelled ->
            "The analysis was cancelled before it finished."
    }

    // ---------------------------------------------------------------- helpers

    /** Confidence ordering used for capping; Unknown is treated as the floor. */
    private fun rank(confidence: AgentConfidence): Int = when (confidence) {
        AgentConfidence.Unknown -> 0
        AgentConfidence.Low -> 1
        AgentConfidence.Medium -> 2
        AgentConfidence.High -> 3
    }

    private fun weakest(claimed: AgentConfidence, cap: AgentConfidence): AgentConfidence {
        // An Unknown claim is not an assertion of high confidence, so it stays
        // Unknown rather than being promoted to the cap.
        if (claimed == AgentConfidence.Unknown) return AgentConfidence.Unknown
        return if (rank(claimed) <= rank(cap)) claimed else cap
    }

    private fun lowerOne(confidence: AgentConfidence): AgentConfidence = when (confidence) {
        AgentConfidence.High -> AgentConfidence.Medium
        AgentConfidence.Medium -> AgentConfidence.Low
        AgentConfidence.Low, AgentConfidence.Unknown -> AgentConfidence.Low
    }

    private fun requiresMetric(type: AgentEvidenceType): Boolean = when (type) {
        AgentEvidenceType.Statistic, AgentEvidenceType.Timeline -> true
        else -> false
    }

    /** Accept a short metric name only when it identifies a returned leaf. */
    private fun metricSuffixMatches(metric: String, known: Set<String>): Boolean =
        known.any { it == metric || it.endsWith(".$metric") }

    private fun metricValuesFor(metric: String, entry: EvidenceLedgerEntry): List<String> {
        return entry.metricValues.entries
            .filter { (key, _) -> key == metric || key.endsWith(".$metric") }
            .map { it.value }
    }

    private fun valuesAgree(claimed: String, actual: String): Boolean {
        val claimedNumber = claimed.replace(",", "").trim().toDoubleOrNull()
        val actualNumber = actual.replace(",", "").trim().toDoubleOrNull()
        if (claimedNumber != null && actualNumber != null) {
            val tolerance = maxOf(0.5, abs(actualNumber) * 0.02)
            return abs(claimedNumber - actualNumber) <= tolerance
        }

        val normalizedClaimed = claimed.trim().lowercase(Locale.ROOT)
        val normalizedActual = actual.trim().lowercase(Locale.ROOT)
        if (normalizedClaimed == normalizedActual) return true

        val actualTokens = normalizedActual
            .removePrefix("[")
            .removeSuffix("]")
            .split(',', ';')
            .map { it.trim() }
            .filter { it.isNotEmpty() }
        if (actualTokens.any { it == normalizedClaimed }) return true

        return normalizedClaimed.contains(normalizedActual)
    }

    /**
     * Whether a free-text observation reads as a claim about absence, via the
     * legacy marker table.
     *
     * After OPT-VAL-04-03 the polarity cross-check is live: the structured
     * [AgentFindingPolarity] declaration drives negative scrutiny, and these
     * markers now serve only two roles — the legacy fallback for `Unknown`
     * polarity (old reports / unavailable structured output) and the
     * `polarity_claim_conflict` contradiction test for `Positive`/`Neutral`.
     * The table is retained for one release cycle and removed by
     * OPT-VAL-05-01 once the conflict rate (EVAL-04 baseline) converges to 0.
     */
    private fun isNegativeClaim(observation: String): Boolean {
        val normalized = observation.lowercase(Locale.ROOT)
        val withoutProtocolPhrases = POSITIVE_EXCEPTIONS.fold(normalized) { text, phrase ->
            text.replace(phrase, " ")
        }
        return NEGATIVE_MARKERS_EN.any { withoutProtocolPhrases.contains(it) } ||
            NEGATIVE_MARKERS_ZH.any { withoutProtocolPhrases.contains(it) }
    }

    private fun hypothesisPhrasing(conclusion: String): String {
        val trimmed = conclusion.trim()
        if (trimmed.isEmpty()) return "This remains an unverified hypothesis."
        if (trimmed.startsWith(HYPOTHESIS_PREFIX, ignoreCase = true)) return trimmed
        return "$HYPOTHESIS_PREFIX$trimmed"
    }

    private companion object {
        const val HYPOTHESIS_PREFIX = "Unverified hypothesis: "

        // The polarity double-track is live (OPT-VAL-04-03): the structured
        // `polarity` declaration is the source of truth and these markers are
        // kept for one release cycle only, for the `Unknown`-polarity legacy
        // path and the `polarity_claim_conflict` check. Removal is scheduled in
        // OPT-VAL-05-01 once the conflict rate converges to 0.
        /** English phrases that turn an observation into a claim about absence. */
        val NEGATIVE_MARKERS_EN = listOf(
            "no ",
            "none",
            "never",
            "not present",
            "not found",
            "not observed",
            "absent",
            "without any",
            "nothing"
        )

        /** Common Chinese absence/normality phrases emitted by the UI model. */
        val NEGATIVE_MARKERS_ZH = listOf(
            "未发现",
            "未观察到",
            "未出现",
            "没有发现",
            "没有观察到",
            "不存在",
            "无任何",
            "均无",
            "全部正常",
            "未检测到",
            "无异常"
        )

        /** Protocol terms whose words must not be interpreted as absence. */
        val POSITIVE_EXCEPTIONS = listOf(
            "zero window",
            "zero-window",
            "零窗口",
            "no-op",
            "not-acknowledged",
            "no route to host",
            "204 no content",
            "404 not found",
            "480 temporarily unavailable"
        )

        /**
         * English words that turn a sentence into a claim about a population
         * (totals, counts, ratios, "all/every"), used by the OPT-VAL-07
         * aggregate predicate.  Word-bounded so "call" never matches "all".
         * Deliberately over-inclusive: a false hit only keeps the pre-existing
         * truncation cap, while a miss would let a whole-capture claim escape
         * it (see [hasAggregateAssertion] for the constraint that forces this).
         */
        val AGGREGATE_WORDS_EN = Regex(
            "\\b(all|every|each|entire|whole|total|overall|aggregate|percentage|" +
                "proportion|ratio|none)\\b"
        )

        /** Multi-word aggregate phrases, matched as plain substrings. */
        val AGGREGATE_PHRASES_EN = listOf(
            "number of",
            "count of",
            "out of",
            "in total",
            "on average",
            "%"
        )

        /** Chinese aggregate markers ("所有/全部/总共/占比..." and similar). */
        val AGGREGATE_MARKERS_ZH = listOf(
            "所有",
            "全部",
            "每个",
            "均",
            "总共",
            "总计",
            "共计",
            "总数",
            "占比",
            "比例",
            "百分",
            "任何",
            "一共",
            "整体"
        )
    }
}

/** Error codes that mean the run itself was stopped rather than one tool. */
internal fun AgentErrorCode.toStopReason(): AgentStopReason = when (this) {
    AgentErrorCode.MAX_STEPS_REACHED -> AgentStopReason.MaxStepsReached
    AgentErrorCode.CONTEXT_LIMIT -> AgentStopReason.ContextLimit
    AgentErrorCode.MODEL_INPUT_CONTEXT_LIMIT -> AgentStopReason.ContextLimit
    AgentErrorCode.MODEL_OUTPUT_TRUNCATED,
    AgentErrorCode.MODEL_RESPONSE_TOO_LARGE,
    AgentErrorCode.MODEL_RESPONSE_MALFORMED,
    AgentErrorCode.MODEL_TIMEOUT -> AgentStopReason.ModelFailure
    AgentErrorCode.SESSION_CHANGED,
    AgentErrorCode.NO_CAPTURE -> AgentStopReason.SessionChanged
    AgentErrorCode.CANCELLED -> AgentStopReason.Cancelled
    AgentErrorCode.MODEL_AUTH_FAILED,
    AgentErrorCode.MODEL_RATE_LIMITED,
    AgentErrorCode.MODEL_UNAVAILABLE -> AgentStopReason.ModelFailure
    else -> AgentStopReason.ToolFailure
}

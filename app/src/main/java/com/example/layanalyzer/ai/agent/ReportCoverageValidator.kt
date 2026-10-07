package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.AgentPlaybookCheck
import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentAnalysisPlanStep
import com.example.layanalyzer.model.AgentFinding
import com.example.layanalyzer.model.AgentQuestionAlignment

/**
 * One declared plan step the run never executed.
 *
 * [index] is kept so later coverage rules (and run metrics) can attribute a
 * gap to its plan position without re-deriving the set difference.
 */
data class UnexecutedPlanStep(
    val index: Int,
    val step: AgentAnalysisPlanStep
)

/** Outcome of one coverage check: the gaps found and their report prose. */
data class ReportCoverageResult(
    val unexecutedSteps: List<UnexecutedPlanStep> = emptyList(),
    val limitations: List<String> = emptyList()
)

/**
 * Outcome of rule 2 (OPT-VAL-01-02): which playbook checks the run left
 * uncovered at the moment a report was offered for acceptance.
 *
 * [attributable] says whether the host can even tell: it is true only when a
 * usable plan was declared and at least one of its steps names a playbook
 * check through `checkId`. Without attribution the gate must not reject — the
 * caller falls back to recording [gapLimitations] instead (the
 * optional-with-default degradation contract of the task doc).
 */
data class PlaybookCheckCoverage(
    val uncoveredChecks: List<AgentPlaybookCheck> = emptyList(),
    val attributable: Boolean = false
) {
    /** True when every playbook check was covered (or there was none). */
    val clean: Boolean
        get() = uncoveredChecks.isEmpty()

    /**
     * Host-authored limitation prose for each still-uncovered check — the
     * finalization record when the model chose (or had to) accept the gaps.
     */
    fun gapLimitations(): List<String> = uncoveredChecks.map { check ->
        "Playbook check \"${check.id}\" (${check.description}) was not " +
            "covered before the report was finalized."
    }
}

/**
 * Outcome of rule 3 (OPT-VAL-02-03, design §5.2): which host-enumerated
 * baseline signals the report left unaddressed at the moment it was checked.
 *
 * Like [PlaybookCheckCoverage] this is gap data only — whether a gap refuses
 * a submit or merely narrates a limitation is the loop's (or
 * [EvidenceValidator]'s) decision, made with the attribution and degradation
 * knowledge that lives there, not here.
 */
data class SignalCoverage(
    val unaddressedSignals: List<AgentSignal> = emptyList()
) {
    /** True when every enumerated signal was addressed (or there were none). */
    val clean: Boolean
        get() = unaddressedSignals.isEmpty()

    /**
     * Host-authored limitation prose for each still-unaddressed signal — the
     * finalization record when the report kept its gaps.
     */
    fun gapLimitations(): List<String> = unaddressedSignals.map(
        ReportCoverageValidator::signalGapSentence
    )
}

/**
 * Outcome of rule 4 (OPT-VAL-03-01, design §5.3): which question-alignment
 * entries the host keeps, and what it says about the rest.
 *
 * Unlike [PlaybookCheckCoverage] and [SignalCoverage] this verdict already
 * carries its disposition, because the rule can only run where the
 * surviving-evidence answer exists — after [EvidenceValidator]'s per-citation
 * decisions — and its channel is the shared rejection list (limitations and
 * the revision trigger pick it up from there). The verdict is purely
 * subtractive: it can drop entries and add rejections/limitations, and there
 * is no path through it that keeps an entry the structural check condemns or
 * raises anything.
 */
data class QuestionAlignmentVerdict(
    /** Entries to keep, in the model's order; the full list when inert. */
    val kept: List<AgentQuestionAlignment> = emptyList(),
    /** One rejection per entry removed for a structural violation. */
    val rejections: List<EvidenceRejection> = emptyList(),
    /** One limitation per entry dropped only for exceeding the schema cap. */
    val excessLimitations: List<String> = emptyList()
) {
    /** True when the rule removed nothing and raised nothing. */
    val clean: Boolean
        get() = rejections.isEmpty() && excessLimitations.isEmpty()
}

/**
 * Checks that the run executed what it promised.
 *
 * A declared plan is the model's contract with the user: "to answer this I
 * will run these checks." When the host cuts the run short, that contract is
 * silently half-kept, and neither the model's own prose nor the existing
 * stop-reason line says which promised checks are missing. Rule 1
 * (OPT-VAL-01-01) restores exactly that: every plan step left unexecuted when
 * a cut-short run ends contributes one host-authored limitation naming the
 * tool and the purpose the model itself declared.
 *
 * Rule 2 (OPT-VAL-01-02), [checkCoverageGaps], asks the companion question at
 * the other end of the run: when the model offers a report on a playbook-hit
 * run, were the playbook's checks actually covered by executed plan steps?
 * The verdict here is still gap data only — the loop owns the one-shot
 * rejection and the finalization limitation that follows an accepted
 * submission.
 *
 * Rule 3 (OPT-VAL-02-03), [signalCoverageGaps], asks the same question of a
 * different promise: every signal the host enumerated from the run's baseline
 * calls (design §5.2) must be addressed by some finding's `relatedSignals`,
 * by some model-authored limitation naming its id, or by the Critic's
 * disposition record. Again gap data only — the loop turns the submit-time
 * verdict into the one-shot refusal or the degrade-to-limitation, and
 * [EvidenceValidator] applies the same rule as its post-validation net.
 *
 * Rule 4 (OPT-VAL-03-01), [alignmentGaps], verifies the report's
 * question-alignment promise *structurally* (design §5.3): every referenced
 * finding must exist among the findings that survived evidence validation,
 * and an entry claiming its question part was addressed must stand on at
 * least one surviving citation. Whether the kept entries actually answer the
 * question — the semantic half §5.3 hands to the Critic's
 * `question_unanswered` (design §4.2, OPT-COG-03, not landed) — is
 * deliberately out of reach here: the host checks references, the Critic
 * checks meaning, and only the two agreeing produces a block. This is the
 * documented extension point; nothing in this class needs to change when the
 * Critic channel arrives.
 *
 * Like [EvidenceValidator], this class is subtractive by construction: its
 * only output is gap data and limitation prose merged into
 * `report.limitations` (rule 4's rejections enter the same channel through
 * [EvidenceRejection.toLimitation]), and there is no path through it that
 * raises a confidence, adds evidence, or widens permissions. It is pure — it
 * reads only the plan, playbook, report and stop state it is handed — so
 * later coverage rules can land here without the loop knowing anything new.
 */
class ReportCoverageValidator {

    companion object {
        /**
         * Every host-authored signal-gap limitation from
         * [signalGapLimitation] starts with this prefix, and that is what
         * makes the prefix load-bearing (OPT-VAL-02-03, requirement "purge
         * vacuous addressing"): the coverage rules count a limitation that
         * mentions a signal id as addressing it, but a host-authored
         * signal-gap line must never be able to address the very signal it
         * reports as unaddressed — a limitation that satisfied itself would
         * make the post-validation net mute on every later round. Excluding
         * marker-prefixed lines from the addressing match keeps the gate and
         * the net honest while model-authored limitations — which do not
         * carry the marker — still address by naming an id, exactly as
         * design §5.2 spells it.
         */
        const val SIGNAL_GAP_LIMITATION_MARKER = "Host-enumerated overview signal "

        /** The one sentence-builder behind [signalGapLimitation] and [SignalCoverage]. */
        internal fun signalGapSentence(signal: AgentSignal): String =
            "$SIGNAL_GAP_LIMITATION_MARKER${signal.signalId} " +
                "(${signal.kind} ${signal.value} ${signal.unit}) " +
                "was not addressed by any finding."

        /**
         * Machine reason code for every question-alignment entry the host
         * removes (OPT-VAL-03-01). Rides the shared [EvidenceRejection]
         * channel, so it also names itself in the revision request's reason
         * counts. One code for both violation shapes — dangling reference and
         * unsupported `addressed` claim — because the model's remedy is one
         * sentence either way: only point at findings that exist and still
         * stand on evidence (design §5.3).
         */
        const val ALIGNMENT_DANGLING_REFERENCE_REASON = "alignment_dangling_reference"

        /**
         * The single host limitation for a report that declares no
         * question-alignment entries at all (OPT-VAL-03-01). Emitted only
         * when the run negotiated structured output — the one condition
         * under which a model *could* have satisfied the now-required field
         * and did not (the same capability signal OPT-VAL-02-03 uses for its
         * attribution). A missing field is never a rejection: that is the
         * §3 degradation contract of the task doc, and plain-text runs stay
         * byte-for-byte silent here.
         */
        const val QUESTION_ALIGNMENT_MISSING_LIMITATION =
            "The report declared no question-alignment entries, so the host " +
                "could not check which parts of the question the findings answer."

        /** Question-alignment entries per report, as the schema caps them. */
        const val MAX_QUESTION_ALIGNMENT_ENTRIES = 4
    }

    /** Rule 1 over the trace's plan state; a trace without a plan is clean. */
    fun validate(trace: AgentRunTrace): ReportCoverageResult = validate(
        plan = trace.declaredPlan,
        completedStepIndices = trace.completedPlanStepIndices,
        stopReason = trace.stopReason
    )

    /**
     * Rule 1: a run cut short leaves unexecuted plan steps → one limitation
     * each, worded `Plan step "tool" (purpose) was not executed before the
     * run stopped (StopReason).`
     *
     * Free-text fallbacks and runs that never declared a plan (or declared one
     * and executed every step) produce nothing, exactly as before this rule.
     */
    fun validate(
        plan: AgentAnalysisPlan?,
        completedStepIndices: Set<Int>,
        stopReason: AgentStopReason
    ): ReportCoverageResult {
        val steps = plan?.steps.orEmpty()
        val unexecuted = steps.indices
            .filterNot { it in completedStepIndices }
            .map { UnexecutedPlanStep(it, steps[it]) }
        if (unexecuted.isEmpty() || !surfacesGaps(stopReason)) {
            return ReportCoverageResult()
        }
        val limitations = unexecuted.map { gap ->
            "Plan step \"${gap.step.tool}\" (${gap.step.purpose}) was not " +
                "executed before the run stopped (${stopReason.name})."
        }
        return ReportCoverageResult(unexecutedSteps = unexecuted, limitations = limitations)
    }

    /**
     * Rule 2 (OPT-VAL-01-02): every playbook check must be claimed by at
     * least one plan step whose `checkId` names it and whose matching tool
     * call actually ran to success.
     *
     * Pure like rule 1: it computes the gap list and leaves the disposition —
     * one-shot rejection versus degrade-to-limitation at report acceptance —
     * to the loop, which is the only party that knows how many submissions
     * this run has already refused. [successfulStepIndices] must carry only
     * steps completed by a *successful* same-tool call; a step matched by a
     * failed call is completed for rule 1 but covers nothing here.
     *
     * When [enforcementEnabled] is false the rule answers "nothing to say"
     * regardless of input — the policy escape valve restores the pre-gate
     * behaviour with no gaps to reject or narrate.
     */
    fun checkCoverageGaps(
        playbook: AgentPlaybook,
        plan: AgentAnalysisPlan?,
        completedStepIndices: Set<Int>,
        successfulStepIndices: Set<Int>,
        enforcementEnabled: Boolean
    ): PlaybookCheckCoverage {
        if (!enforcementEnabled) return PlaybookCheckCoverage()
        val coveredCheckIds = plan?.steps?.indices
            ?.filter { it in completedStepIndices && it in successfulStepIndices }
            ?.map { plan.steps[it].checkId }
            ?.filter { it.isNotBlank() }
            ?.toSet()
            .orEmpty()
        return PlaybookCheckCoverage(
            uncoveredChecks = playbook.checks.filter { it.id !in coveredCheckIds },
            attributable = plan != null && plan.steps.any { it.checkId.isNotBlank() }
        )
    }

    /**
     * Signal-coverage prose (OPT-VAL-02-02; rule 3 preview for
     * OPT-VAL-02-03): the limitation a host-generated report note carries
     * when one enumerated baseline signal was addressed by no finding.
     *
     * The raw [AgentSignal.signalId] is embedded verbatim so the sentence is
     * itself a signal reference — design §5.2 has host-generated limitations
     * "直接带 signalId", which lets the future gate count this limitation as
     * addressing the signal without any text matching, exactly like a
     * finding's `relatedSignals` entry. Only id, kind, value and unit appear:
     * content-hash ids plus counts never carry capture text.
     *
     * Wording is final-ish; OPT-VAL-02-03 is expected to reuse this helper
     * verbatim for its degrade-to-limitation path. Pure prose minting: no
     * confidence, no gating — deciding *which* signals are gaps stays with
     * the gate, as with rules 1 and 2.
     */
    fun signalGapLimitation(signal: AgentSignal): String = signalGapSentence(signal)

    /** The [signalGapLimitation] prose for each of [signals], in order. */
    fun signalGapLimitations(signals: List<AgentSignal>): List<String> =
        signals.map(::signalGapLimitation)

    /**
     * Rule 3 (OPT-VAL-02-03, design §5.2): every host-enumerated signal must
     * be addressed — named in some finding's `relatedSignals`, mentioned by
     * some model-authored limitation, or dispositioned by the Critic.
     *
     * A limitation addresses a signal by *containing its id* (design
     * §5.2's "limitations 宿主生成的直接带 signalId" runs the other way: any
     * limitation that names an id counts, whichever channel brought it).
     * Host-authored signal-gap lines are the exception, excluded by the
     * [SIGNAL_GAP_LIMITATION_MARKER] prefix: counting them would let a gap
     * report itself closed. `signals_capped` — the overflow meta-signal — is
     * addressed like any other signal: dropping signals *is* a baseline fact
     * a report should acknowledge or explain, and a special-case exemption
     * would only make the rule harder to state.
     *
     * [criticAddressedSignalIds] is the Critic's `unaddressedSignals`
     * disposition channel of design §5.2 — the record of signals the review
     * stage already engaged with. The channel does not exist yet (it lands
     * with OPT-COG-03-03, which will feed it through [AgentRunTrace]); until
     * then the default empty set keeps the accounting host-only, as the
     * host/Critic cross-check in §4.2 requires to prevent a solo Critic
     * from conjuring coverage.
     *
     * [enforcementEnabled] is the policy escape valve: false answers "not
     * my business" for every input, byte-for-byte the pre-rule behaviour.
     */
    fun signalCoverageGaps(
        signals: List<AgentSignal>,
        findings: List<AgentFinding>,
        limitations: List<String>,
        criticAddressedSignalIds: Set<String> = emptySet(),
        enforcementEnabled: Boolean
    ): SignalCoverage {
        if (!enforcementEnabled) return SignalCoverage()
        val addressed = HashSet<String>()
        findings.forEach { finding -> addressed += finding.relatedSignals }
        addressed += criticAddressedSignalIds
        val modelLimitations = limitations.filterNot {
            it.startsWith(SIGNAL_GAP_LIMITATION_MARKER)
        }
        return SignalCoverage(
            unaddressedSignals = signals.filter { signal ->
                signal.signalId !in addressed &&
                    modelLimitations.none { it.contains(signal.signalId) }
            }
        )
    }

    /**
     * Rule 4 (OPT-VAL-03-01, design §5.3): structural verification of the
     * report's `questionAlignment` entries against [survivingFindings] — the
     * findings exactly as evidence validation left them, so "surviving
     * evidence" means what the report can still stand on. Findings are never
     * fully dropped; one that lost every citation still exists as a
     * hypothesis, which is what separates the two violation shapes:
     *
     *  * a referenced id absent from [survivingFindings] is a violation for
     *    every entry, `addressed` or not — reference integrity is
     *    unconditional (an `addressed=false` entry pointing at a finding
     *    that does not exist is still a lie about the report's own shape);
     *  * an `addressed=true` entry additionally needs the referenced findings
     *    to hold at least one surviving citation between them; none doing so
     *    — including the empty-`findingIds` case, which can never reach one
     *    — is a violation. Pinned decision: "addressed without any surviving
     *    support" is exactly what the check exists to refuse, and an `addressed`
     *    claim backed by only hypothesis-restated findings answers nothing.
     *
     * A violating entry is *removed* from the kept list and answered by one
     * [EvidenceRejection] (`alignment_dangling_reference`) whose findingId is
     * the first offending id, or the entry's own questionPart when no id is
     * offending (the empty-findingIds case). The detail names the
     * questionPart — model-declared prose, sanitized by the loop before
     * validation — and the offending ids only; never the finding titles or
     * any other report text.
     *
     * More than [MAX_QUESTION_ALIGNMENT_ENTRIES] entries can only arrive
     * around a schema-enforcing transport, so it is handled defensively:
     * the first four are checked, the excess is dropped with one limitation
     * line each and no rejection — no new reason code for a shape the schema
     * already caps.
     *
     * [enforcementEnabled] is the policy escape valve: false keeps the list
     * exactly as submitted — no removals, no rejections, nothing to narrate.
     * The missing/empty-field narration is NOT here: it needs the
     * structured-output capability signal and rides
     * [EvidenceValidator]'s limitations channel (see
     * [QUESTION_ALIGNMENT_MISSING_LIMITATION]).
     */
    fun alignmentGaps(
        alignment: List<AgentQuestionAlignment>,
        survivingFindings: List<AgentFinding>,
        enforcementEnabled: Boolean
    ): QuestionAlignmentVerdict {
        if (!enforcementEnabled) return QuestionAlignmentVerdict(kept = alignment)
        val survivingEvidence = HashMap<String, Int>()
        survivingFindings.forEach { finding ->
            survivingEvidence[finding.id] =
                (survivingEvidence[finding.id] ?: 0) + finding.evidence.size
        }
        val kept = ArrayList<AgentQuestionAlignment>()
        val rejections = ArrayList<EvidenceRejection>()
        alignment.take(MAX_QUESTION_ALIGNMENT_ENTRIES).forEach { entry ->
            val missing = entry.findingIds.filterNot { it in survivingEvidence }.distinct()
            val dead = entry.findingIds.filter { survivingEvidence[it] == 0 }.distinct()
            val supported = entry.findingIds.sumOf { survivingEvidence[it] ?: 0 }
            val unsupportedClaim = entry.addressed && supported == 0
            if (missing.isEmpty() && !unsupportedClaim) {
                kept += entry
                return@forEach
            }
            val offending = (missing + if (unsupportedClaim) dead else emptyList()).distinct()
            rejections += EvidenceRejection(
                findingId = offending.firstOrNull()
                    ?: entry.questionPart.ifBlank { "question-alignment entry" },
                reason = ALIGNMENT_DANGLING_REFERENCE_REASON,
                detail = alignmentViolationDetail(entry, missing, unsupportedClaim, dead)
            )
        }
        return QuestionAlignmentVerdict(
            kept = kept,
            rejections = rejections,
            excessLimitations = alignment
                .drop(MAX_QUESTION_ALIGNMENT_ENTRIES)
                .map { entry ->
                    "A question-alignment entry beyond the " +
                        "${MAX_QUESTION_ALIGNMENT_ENTRIES}-entry cap " +
                        "(\"${entry.questionPart}\") was dropped."
                }
        )
    }

    private fun alignmentViolationDetail(
        entry: AgentQuestionAlignment,
        missing: List<String>,
        unsupportedClaim: Boolean,
        dead: List<String>
    ): String {
        val parts = ArrayList<String>()
        if (missing.isNotEmpty()) {
            parts += "referenced finding id(s) not in the report: " +
                missing.joinToString(", ") { "\"$it\"" }
        }
        if (unsupportedClaim) {
            parts += if (entry.findingIds.isEmpty()) {
                "claimed its question part was addressed without referencing any finding"
            } else {
                "claimed its question part was addressed, but none of the " +
                    "referenced findings retained verifiable evidence: " +
                    dead.joinToString(", ") { "\"$it\"" }
            }
        }
        return "a question-alignment entry (\"${entry.questionPart}\") " +
            parts.joinToString("; ")
    }

    /**
     * The stop reasons whose runs surface their plan gaps (OPT-VAL-01-01).
     *
     * Pinned: every reason except the two ways a plan ends on its own terms.
     * `PlanComplete` is set only when every step has been matched
     * (AgentLoop.trackPlanExecution), so it cannot carry unexecuted steps;
     * `ModelFinal` is the model's own conclusion, which `completenessFor`
     * already treats as a Complete run — and delegated child reports always
     * validate as `ModelFinal`, so excluding it also keeps a child report from
     * inheriting the parent run's plan gaps. A voluntary early finalize that
     * abandons the model's own plan is a plan-deviation question for a later
     * rule, not this one. The `when` is exhaustive: adding a stop reason
     * forces a deliberate choice here.
     */
    private fun surfacesGaps(stopReason: AgentStopReason): Boolean = when (stopReason) {
        AgentStopReason.ModelFinal,
        AgentStopReason.PlanComplete -> false
        AgentStopReason.MaxStepsReached,
        AgentStopReason.MaxDurationReached,
        AgentStopReason.ContextLimit,
        AgentStopReason.RepeatedToolCall,
        AgentStopReason.ToolFailure,
        AgentStopReason.SessionChanged,
        AgentStopReason.ModelFailure,
        AgentStopReason.InvalidArguments,
        AgentStopReason.Cancelled -> true
    }
}

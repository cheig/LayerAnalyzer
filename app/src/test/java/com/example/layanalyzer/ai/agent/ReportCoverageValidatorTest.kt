// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.ai.playbook.AgentPlaybook
import com.example.layanalyzer.ai.playbook.AgentPlaybookCheck
import com.example.layanalyzer.model.AgentAnalysisPlan
import com.example.layanalyzer.model.AgentAnalysisPlanStep
import com.example.layanalyzer.model.AgentFinding
import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Rule 1 of OPT-VAL-01-01: a run cut short while its declared plan still has
 * unexecuted steps contributes one limitation per gap, naming the tool and
 * the purpose. The set difference itself, the gap wording, and the pinned
 * stop-reason gate are all tested here at the pure class; the merge into
 * `report.limitations` is covered in [EvidenceValidatorTest].
 */
class ReportCoverageValidatorTest {

    private val validator = ReportCoverageValidator()

    private val plan = AgentAnalysisPlan(
        goal = "Inspect the trace",
        steps = listOf(
            AgentAnalysisPlanStep("get_capture_overview", "establish the baseline"),
            AgentAnalysisPlanStep("get_expert_info", "check TCP retransmissions"),
            AgentAnalysisPlanStep("query_packet_summaries", "read the conversation endpoints")
        )
    )

    /** The stop reasons rule 1 fires on: everything except ModelFinal/PlanComplete. */
    private val cutShortStopReasons = listOf(
        AgentStopReason.MaxStepsReached,
        AgentStopReason.MaxDurationReached,
        AgentStopReason.ContextLimit,
        AgentStopReason.RepeatedToolCall,
        AgentStopReason.ToolFailure,
        AgentStopReason.SessionChanged,
        AgentStopReason.ModelFailure,
        AgentStopReason.InvalidArguments,
        AgentStopReason.Cancelled
    )

    @Test
    fun everyCutShortStopReasonAddsOneLimitationPerUnexecutedStep() {
        // Pin the gate's membership so adding an AgentStopReason constant
        // forces a deliberate choice here as well as in surfacesGaps().
        assertEquals(
            AgentStopReason.entries.filter {
                it != AgentStopReason.ModelFinal && it != AgentStopReason.PlanComplete
            }.toSet(),
            cutShortStopReasons.toSet()
        )
        assertEquals(9, cutShortStopReasons.size)

        for (stopReason in cutShortStopReasons) {
            val result = validator.validate(plan, setOf(0), stopReason)
            assertEquals(
                "one limitation per unexecuted step at $stopReason",
                2,
                result.limitations.size
            )
            assertEquals(listOf(1, 2), result.unexecutedSteps.map { it.index })
            assertTrue(result.limitations.all { "get_capture_overview" !in it })
            assertTrue(
                result.limitations[0].contains("get_expert_info") &&
                    result.limitations[0].contains("check TCP retransmissions")
            )
            assertTrue(
                result.limitations[1].contains("query_packet_summaries") &&
                    result.limitations[1].contains("read the conversation endpoints")
            )
        }
    }

    @Test
    fun limitationNamesToolPurposeAndStopReasonInOneSentence() {
        val result = validator.validate(plan, setOf(0), AgentStopReason.MaxStepsReached)
        assertEquals(
            listOf(
                "Plan step \"get_expert_info\" (check TCP retransmissions) was not " +
                    "executed before the run stopped (MaxStepsReached).",
                "Plan step \"query_packet_summaries\" (read the conversation endpoints) was not " +
                    "executed before the run stopped (MaxStepsReached)."
            ),
            result.limitations
        )
    }

    @Test
    fun modelFinalAndPlanCompleteNeverSurfaceCoverageLimitations() {
        // Pinned behavior (OPT-VAL-01-01): the two ways a plan ends on its own
        // terms emit nothing even when gaps exist. PlanComplete cannot carry
        // gaps in the intended flow; ModelFinal is the model's own conclusion
        // (and the stop reason every delegated child validates with), so a
        // voluntary early finalize is left to the plan-deviation rules, not
        // this one.
        for (stopReason in listOf(AgentStopReason.ModelFinal, AgentStopReason.PlanComplete)) {
            val result = validator.validate(plan, setOf(0), stopReason)
            assertEquals(ReportCoverageResult(), result)
        }
    }

    @Test
    fun runWithoutADeclaredPlanProducesNothing() {
        for (stopReason in AgentStopReason.entries) {
            assertEquals(
                "no plan at $stopReason",
                ReportCoverageResult(),
                validator.validate(plan = null, completedStepIndices = emptySet(), stopReason = stopReason)
            )
            assertEquals(
                "empty plan at $stopReason",
                ReportCoverageResult(),
                validator.validate(
                    AgentAnalysisPlan(goal = "Inspect the trace", steps = emptyList()),
                    emptySet(),
                    stopReason
                )
            )
        }
    }

    @Test
    fun fullyExecutedPlanProducesNothing() {
        // Gap-fill continuation reads can run past completion until the step
        // budget stops the run; every declared step was still executed.
        val result = validator.validate(plan, setOf(0, 1, 2), AgentStopReason.MaxStepsReached)
        assertEquals(ReportCoverageResult(), result)
    }

    // ------------------------------------------------- rule 2 (OPT-VAL-01-02)

    private val checkPlaybook = AgentPlaybook(
        id = "tcp-health",
        version = 1,
        title = "TCP health",
        intentHints = listOf("capture health"),
        protocols = listOf("tcp"),
        initialTools = emptyList(),
        requiredFields = emptyList(),
        checks = listOf(
            AgentPlaybookCheck("check-a", "Find TCP retransmissions", listOf("get_expert_info")),
            AgentPlaybookCheck("check-b", "Read conversation endpoints", listOf("query_packet_summaries"))
        ),
        successPath = emptyList(),
        failureBranches = emptyList(),
        requiredLimitations = emptyList(),
        outputSections = emptyList()
    )

    private val checkPlan = AgentAnalysisPlan(
        goal = "Inspect the trace",
        steps = listOf(
            AgentAnalysisPlanStep("get_expert_info", "check TCP retransmissions", "check-a"),
            AgentAnalysisPlanStep("query_packet_summaries", "read the endpoints", "check-b")
        )
    )

    @Test
    fun rule2CountsOnlySuccessfullyExecutedStepsAsCoveringTheirCheck() {
        // Step 0's call was executed but failed: completed for rule 1, but a
        // failed run of the tool covers nothing ("同名工具成功调用匹配").
        val result = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = checkPlan,
            completedStepIndices = setOf(0, 1),
            successfulStepIndices = setOf(1),
            enforcementEnabled = true
        )
        assertEquals(listOf("check-a"), result.uncoveredChecks.map { it.id })
        assertTrue(result.attributable)
        assertFalse(result.clean)
    }

    @Test
    fun rule2FullyCoveredPlanReportsNoGap() {
        val result = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = checkPlan,
            completedStepIndices = setOf(0, 1),
            successfulStepIndices = setOf(0, 1),
            enforcementEnabled = true
        )
        assertTrue(result.clean)
        assertTrue(result.attributable)
        assertEquals(emptyList<String>(), result.gapLimitations())
    }

    @Test
    fun rule2WithoutAPlanOrWithoutAnyCheckIdIsUnattributable() {
        // The two degradation shapes pinned by the optional-with-default
        // contract: no usable plan at all, and a legacy plan whose steps
        // carry no checkId.  Both must report every check uncovered with
        // attribution false, so the caller records limitations instead of
        // refusing.
        val noPlan = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = null,
            completedStepIndices = emptySet(),
            successfulStepIndices = emptySet(),
            enforcementEnabled = true
        )
        assertEquals(listOf("check-a", "check-b"), noPlan.uncoveredChecks.map { it.id })
        assertFalse(noPlan.attributable)

        val legacyPlan = checkPlan.copy(steps = checkPlan.steps.map { it.copy(checkId = "") })
        val noCheckIds = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = legacyPlan,
            completedStepIndices = setOf(0, 1),
            successfulStepIndices = setOf(0, 1),
            enforcementEnabled = true
        )
        assertEquals(listOf("check-a", "check-b"), noCheckIds.uncoveredChecks.map { it.id })
        assertFalse(noCheckIds.attributable)
    }

    @Test
    fun rule2EscapeValveOffSaysNothingAtAll() {
        // With enforcement off the pure rule answers as if there were no
        // checks: neither a rejection list nor limitation prose — the loop
        // byte-for-byte restores its pre-gate behavior.
        val result = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = checkPlan,
            completedStepIndices = emptySet(),
            successfulStepIndices = emptySet(),
            enforcementEnabled = false
        )
        assertEquals(PlaybookCheckCoverage(), result)
    }

    @Test
    fun rule2GapLimitationNamesCheckIdDescriptionAndFinalization() {
        val result = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = checkPlan,
            completedStepIndices = setOf(1),
            successfulStepIndices = setOf(1),
            enforcementEnabled = true
        )
        assertEquals(
            listOf(
                "Playbook check \"check-a\" (Find TCP retransmissions) was not " +
                    "covered before the report was finalized."
            ),
            result.gapLimitations()
        )
    }

    @Test
    fun rule2PlaybookWithoutChecksIsAlwaysClean() {
        val bare = checkPlaybook.copy(checks = emptyList())
        val result = validator.checkCoverageGaps(
            playbook = bare,
            plan = null,
            completedStepIndices = emptySet(),
            successfulStepIndices = emptySet(),
            enforcementEnabled = true
        )
        assertTrue(result.clean)
    }

    // -------------------------------------------------- OPT-VAL-01-03 audit
    // matrix: partial rule-1 executions, rule-2 coverage matching edges, the
    // escape-valve input sweep, and output ordering stability.

    @Test
    fun rule1FlagsOnlyUnexecutedIndicesWhateverOrderTheCompletionSetWasBuiltIn() {
        // Completion tracking arrives interleaved with tool results, so the
        // rule must depend on set membership only.  A scrambled insertion
        // order and a completed index *above* the gap (2 > 1) change nothing.
        val result = validator.validate(plan, linkedSetOf(2, 0), AgentStopReason.MaxDurationReached)
        assertEquals(listOf(1), result.unexecutedSteps.map { it.index })
        assertEquals(1, result.limitations.size)
        assertTrue(result.limitations.single().contains("get_expert_info"))
        assertTrue(result.limitations.single().contains("check TCP retransmissions"))

        // Gaps are always listed in plan order, never in completion order.
        val lateFirstGap = validator.validate(plan, linkedSetOf(1), AgentStopReason.ToolFailure)
        assertEquals(listOf(0, 2), lateFirstGap.unexecutedSteps.map { it.index })
        assertTrue(lateFirstGap.limitations[0].contains("establish the baseline"))
        assertTrue(lateFirstGap.limitations[1].contains("read the conversation endpoints"))

        // Completion indices outside the plan are inert, not a crash.
        val extraIndices = validator.validate(plan, setOf(0, 1, 2, 3, 4), AgentStopReason.Cancelled)
        assertEquals(ReportCoverageResult(), extraIndices)
    }

    @Test
    fun rule1TwoUnexecutedStepsSharingAToolKeepTheirOwnIndicesAndPurposes() {
        val sameTool = AgentAnalysisPlan(
            goal = "Inspect the trace",
            steps = listOf(
                AgentAnalysisPlanStep("get_expert_info", "first pass"),
                AgentAnalysisPlanStep("query_packet_summaries", "read the endpoints"),
                AgentAnalysisPlanStep("get_expert_info", "second pass")
            )
        )
        val result = validator.validate(sameTool, setOf(1), AgentStopReason.ContextLimit)
        assertEquals(listOf(0, 2), result.unexecutedSteps.map { it.index })
        assertEquals(2, result.limitations.size)
        assertTrue(result.limitations[0].contains("first pass"))
        assertTrue(result.limitations[1].contains("second pass"))
        assertFalse(result.limitations[0].contains("second pass"))
        assertFalse(result.limitations[1].contains("first pass"))
    }

    @Test
    fun rule2TwoStepsSharingOneCheckIdAreCoveredByASingleSuccessfulCall() {
        val twinCheckPlan = AgentAnalysisPlan(
            goal = "Inspect the trace",
            steps = listOf(
                AgentAnalysisPlanStep("get_expert_info", "first pass", "check-a"),
                AgentAnalysisPlanStep("get_expert_info", "second pass", "check-a"),
                AgentAnalysisPlanStep("query_packet_summaries", "endpoints", "check-b")
            )
        )
        // Coverage is per check, not per step: one success naming "check-a"
        // covers it even though the other twin's call failed.
        for (successful in listOf(setOf(1, 2), setOf(0, 2))) {
            val result = validator.checkCoverageGaps(
                playbook = checkPlaybook,
                plan = twinCheckPlan,
                completedStepIndices = setOf(0, 1, 2),
                successfulStepIndices = successful,
                enforcementEnabled = true
            )
            assertTrue("check-a covered by the twin at index ${successful.first()}", result.clean)
        }
        // With both twins executed-but-failed the check is uncovered again.
        val bothFailed = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = twinCheckPlan,
            completedStepIndices = setOf(0, 1, 2),
            successfulStepIndices = setOf(2),
            enforcementEnabled = true
        )
        assertEquals(listOf("check-a"), bothFailed.uncoveredChecks.map { it.id })
    }

    @Test
    fun rule2UnknownCheckIdCoversNothingButKeepsTheRunAttributable() {
        val ghostPlan = AgentAnalysisPlan(
            goal = "Inspect the trace",
            steps = listOf(
                AgentAnalysisPlanStep("get_expert_info", "check something", "check-ghost"),
                AgentAnalysisPlanStep("query_packet_summaries", "read the endpoints", "check-b")
            )
        )
        val result = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = ghostPlan,
            completedStepIndices = setOf(0, 1),
            successfulStepIndices = setOf(0, 1),
            enforcementEnabled = true
        )
        // The ghost id matches no check, so check-a stays uncovered; a real
        // id was declared, so the gate keeps its one-shot refusal right.
        assertEquals(listOf("check-a"), result.uncoveredChecks.map { it.id })
        assertTrue(result.attributable)
        assertEquals(1, result.gapLimitations().size)
        assertTrue(result.gapLimitations().single().contains("\"check-a\""))
    }

    @Test
    fun rule2BlankAndWhitespaceStepCheckIdsContributeNoCoverage() {
        val blankIdPlan = AgentAnalysisPlan(
            goal = "Inspect the trace",
            steps = listOf(
                AgentAnalysisPlanStep("get_expert_info", "first pass", ""),
                AgentAnalysisPlanStep("query_packet_summaries", "second pass", "   ")
            )
        )
        val result = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = blankIdPlan,
            completedStepIndices = setOf(0, 1),
            successfulStepIndices = setOf(0, 1),
            enforcementEnabled = true
        )
        // Whitespace is filtered exactly like the empty default, so the run
        // degrades like a legacy plan: every check uncovered, unattributable.
        assertEquals(listOf("check-a", "check-b"), result.uncoveredChecks.map { it.id })
        assertFalse(result.attributable)
    }

    @Test
    fun rule2PlaybookCheckWithABlankIdCanNeverBeCoveredByAStep() {
        // Defensive counterpart: the blank filter is on the step side, so a
        // playbook check whose own id is blank is unreachable by definition.
        val blankCheck = AgentPlaybookCheck(" ", "placeholder without identity", listOf("get_expert_info"))
        val mixedPlaybook = checkPlaybook.copy(checks = listOf(blankCheck, checkPlaybook.checks[1]))
        val coveringPlan = AgentAnalysisPlan(
            goal = "Inspect the trace",
            steps = listOf(
                AgentAnalysisPlanStep("get_expert_info", "cover the blank", " "),
                AgentAnalysisPlanStep("query_packet_summaries", "endpoints", "check-b")
            )
        )
        val result = validator.checkCoverageGaps(
            playbook = mixedPlaybook,
            plan = coveringPlan,
            completedStepIndices = setOf(0, 1),
            successfulStepIndices = setOf(0, 1),
            enforcementEnabled = true
        )
        // The literally-equal " " step id is filtered before matching, so the
        // blank check remains uncovered even against this exact declaration;
        // the real id on the other step still makes the run attributable.
        assertEquals(listOf(" "), result.uncoveredChecks.map { it.id })
        assertTrue(result.attributable)
    }

    @Test
    fun rule2OneRealCheckIdAmongBlanksMakesTheWholePlanAttributable() {
        val mixed = checkPlan.copy(
            steps = listOf(checkPlan.steps[0], checkPlan.steps[1].copy(checkId = ""))
        )
        val result = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = mixed,
            completedStepIndices = setOf(0, 1),
            successfulStepIndices = setOf(0, 1),
            enforcementEnabled = true
        )
        // attributable is an existential over the steps, not a universal one:
        // the model saw the check bindings, so a gap here is its own doing.
        assertTrue(result.attributable)
        assertEquals(listOf("check-b"), result.uncoveredChecks.map { it.id })
    }

    @Test
    fun rule2RecomputesCoverageFromThePlanItIsHandedNotAnEarlierDeclaration() {
        // After a re-declared plan the loop clears both index sets
        // (AgentLoop.acceptDeclaredPlan), so the gate always asks about the
        // *current* plan.  The pure function is stateless: the same index set
        // means different steps — and different coverage — per plan shape.
        val original = checkPlan
        val afterOriginal = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = original,
            completedStepIndices = setOf(0),
            successfulStepIndices = setOf(0),
            enforcementEnabled = true
        )
        assertEquals(listOf("check-b"), afterOriginal.uncoveredChecks.map { it.id })

        val replacement = AgentAnalysisPlan(
            goal = "Inspect the trace",
            steps = listOf(
                AgentAnalysisPlanStep("query_packet_summaries", "endpoints", "check-b"),
                AgentAnalysisPlanStep("get_expert_info", "retransmissions", "check-a")
            )
        )
        val afterReplacement = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = replacement,
            completedStepIndices = setOf(0, 1),
            successfulStepIndices = setOf(0, 1),
            enforcementEnabled = true
        )
        assertTrue(afterReplacement.clean)
        // Index 0 now means the summaries step, so the same single-success
        // index set that covered check-a above covers only check-b here.
        val staleStepZeroOnly = validator.checkCoverageGaps(
            playbook = checkPlaybook,
            plan = replacement,
            completedStepIndices = setOf(0),
            successfulStepIndices = setOf(0),
            enforcementEnabled = true
        )
        assertEquals(listOf("check-a"), staleStepZeroOnly.uncoveredChecks.map { it.id })
    }

    @Test
    fun rule2EscapeValveOffAnswersTheDefaultCleanVerdictForEveryInput() {
        // One-shot sweep of the whole input alphabet against enforcement off:
        // no plan / check-bound / legacy / ghost ids, and empty / completed-
        // only / completed-and-successful index sets.  Every combination must
        // answer exactly the default value — the pre-gate shape.
        val legacy = checkPlan.copy(steps = checkPlan.steps.map { it.copy(checkId = "") })
        val ghost = checkPlan.copy(steps = listOf(checkPlan.steps[0].copy(checkId = "check-ghost")))
        val indexSets = listOf(
            emptySet<Int>() to emptySet<Int>(),
            setOf(0, 1) to emptySet<Int>(),
            setOf(0, 1) to setOf(0, 1)
        )
        for (candidate in listOf(null, checkPlan, legacy, ghost)) {
            for ((completed, successful) in indexSets) {
                val result = validator.checkCoverageGaps(
                    playbook = checkPlaybook,
                    plan = candidate,
                    completedStepIndices = completed,
                    successfulStepIndices = successful,
                    enforcementEnabled = false
                )
                assertEquals("valve off at plan=$candidate", PlaybookCheckCoverage(), result)
                assertTrue("valve off reports clean", result.clean)
                assertTrue("valve off narrates nothing", result.gapLimitations().isEmpty())
            }
        }
    }

    @Test
    fun rule2UncoveredChecksAndGapLimitationsFollowPlaybookOrderStably() {
        // Check declaration order, not id order or coverage order, defines the
        // output: the report prose must be reproducible across runs.
        val orderedPlaybook = checkPlaybook.copy(
            checks = listOf(
                AgentPlaybookCheck("check-zeta", "Zeta check", emptyList()),
                AgentPlaybookCheck("check-alpha", "Alpha check", emptyList()),
                AgentPlaybookCheck("check-middle", "Middle check", emptyList())
            )
        )
        val uncoveredAll = validator.checkCoverageGaps(
            playbook = orderedPlaybook,
            plan = null,
            completedStepIndices = emptySet(),
            successfulStepIndices = emptySet(),
            enforcementEnabled = true
        )
        assertEquals(
            listOf("check-zeta", "check-alpha", "check-middle"),
            uncoveredAll.uncoveredChecks.map { it.id }
        )
        // One covered step: the survivors keep the playbook's relative order.
        val coveringPlan = AgentAnalysisPlan(
            goal = "Inspect the trace",
            steps = listOf(AgentAnalysisPlanStep("get_expert_info", "middle pass", "check-middle"))
        )
        val partlyCovered = validator.checkCoverageGaps(
            playbook = orderedPlaybook,
            plan = coveringPlan,
            completedStepIndices = setOf(0),
            successfulStepIndices = setOf(0),
            enforcementEnabled = true
        )
        assertEquals(listOf("check-zeta", "check-alpha"), partlyCovered.uncoveredChecks.map { it.id })

        // gapLimitations mirrors uncoveredChecks' order, stays stable across
        // repeated calls, and the whole verdict is idempotent per validator.
        val limitations = partlyCovered.gapLimitations()
        assertEquals(2, limitations.size)
        limitations.forEachIndexed { index, line ->
            assertTrue(line.contains("\"${partlyCovered.uncoveredChecks[index].id}\""))
        }
        assertEquals(limitations, partlyCovered.gapLimitations())
        assertEquals(
            partlyCovered,
            validator.checkCoverageGaps(
                playbook = orderedPlaybook,
                plan = coveringPlan,
                completedStepIndices = setOf(0),
                successfulStepIndices = setOf(0),
                enforcementEnabled = true
            )
        )
    }

    @Test
    fun twoStepsSharingAToolEachReportTheirOwnGap() {
        val repeatedToolPlan = AgentAnalysisPlan(
            goal = "Inspect the trace",
            steps = listOf(
                AgentAnalysisPlanStep("get_expert_info", "check TCP retransmissions"),
                AgentAnalysisPlanStep("get_expert_info", "check ARP anomalies")
            )
        )
        val result = validator.validate(repeatedToolPlan, emptySet(), AgentStopReason.ContextLimit)
        assertEquals(2, result.limitations.size)
        assertEquals(
            "Plan step \"get_expert_info\" (check TCP retransmissions) was not " +
                "executed before the run stopped (ContextLimit).",
            result.limitations[0]
        )
        assertEquals(
            "Plan step \"get_expert_info\" (check ARP anomalies) was not " +
                "executed before the run stopped (ContextLimit).",
            result.limitations[1]
        )
    }

    // ------------------------------------------------ 02-02: signal prose

    @Test
    fun signalGapLimitationEmbedsTheRawSignalIdAndTheEnumeratedShape() {
        val signal = AgentSignal(
            signalId = "sig-ab12cd34ef56",
            kind = AgentSignalExtractor.KIND_HEALTH_PROBLEMS,
            value = "3",
            unit = AgentSignalExtractor.UNIT_PROBLEMS
        )
        val limitation = validator.signalGapLimitation(signal)
        // Wording pinned: OPT-VAL-02-03 consumes this prose verbatim, and the
        // sentence must carry the raw content-hash id so a limitation counts
        // as addressing the signal without any text matching (design §5.2).
        assertEquals(
            "Host-enumerated overview signal sig-ab12cd34ef56 " +
                "(health_problems 3 problems) was not addressed by any finding.",
            limitation
        )
        assertTrue(limitation.contains(signal.signalId))
    }

    @Test
    fun signalGapLimitationsRenderOneSentencePerSignalInOrder() {
        val signals = listOf(
            AgentSignal(
                signalId = "sig-000000000001",
                kind = AgentSignalExtractor.KIND_EXPERT_GROUP,
                value = "12",
                unit = AgentSignalExtractor.UNIT_ITEMS
            ),
            AgentSignal(
                signalId = "sig-000000000002",
                kind = AgentSignalExtractor.KIND_SIGNALS_CAPPED,
                value = "4",
                unit = AgentSignalExtractor.UNIT_SIGNALS
            )
        )
        assertEquals(
            listOf(
                "Host-enumerated overview signal sig-000000000001 " +
                    "(expert_group 12 items) was not addressed by any finding.",
                "Host-enumerated overview signal sig-000000000002 " +
                    "(signals_capped 4 signals) was not addressed by any finding."
            ),
            validator.signalGapLimitations(signals)
        )
    }

    // ------------------------------------------- 02-03: rule 3, the coverage
    // gate's pure accounting

    private fun healthSignal(id: String) = AgentSignal(
        signalId = id,
        kind = AgentSignalExtractor.KIND_HEALTH_PROBLEMS,
        value = "3",
        unit = AgentSignalExtractor.UNIT_PROBLEMS
    )

    private fun coveringFinding(vararg relatedSignals: String) = AgentFinding(
        id = "finding-1",
        title = "Addresses some signals",
        relatedSignals = relatedSignals.toList()
    )

    private fun gapsOf(
        signals: List<AgentSignal>,
        findings: List<AgentFinding> = emptyList(),
        limitations: List<String> = emptyList(),
        critic: Set<String> = emptySet(),
        enabled: Boolean = true
    ): SignalCoverage = validator.signalCoverageGaps(
        signals = signals,
        findings = findings,
        limitations = limitations,
        criticAddressedSignalIds = critic,
        enforcementEnabled = enabled
    )

    @Test
    fun emptySignalSetIsTriviallyCovered() {
        val coverage = gapsOf(emptyList())
        assertTrue(coverage.clean)
        assertEquals(emptyList<AgentSignal>(), coverage.unaddressedSignals)
        assertEquals(emptyList<String>(), coverage.gapLimitations())
    }

    @Test
    fun findingRelatedSignalsAddressExactlyTheNamedSignals() {
        val signals = listOf(healthSignal("sig-aaaaaaaaaaaa"), healthSignal("sig-bbbbbbbbbbbb"))
        val coverage = gapsOf(
            signals = signals,
            findings = listOf(coveringFinding("sig-aaaaaaaaaaaa"))
        )
        assertEquals(listOf("sig-bbbbbbbbbbbb"), coverage.unaddressedSignals.map { it.signalId })
        assertFalse(coverage.clean)
        // Other signal ids in the set are not addressed by one finding's entry.
        assertTrue(
            coverage.gapLimitations().single().contains("sig-bbbbbbbbbbbb")
        )
        assertTrue(
            !coverage.gapLimitations().single().contains("sig-aaaaaaaaaaaa")
        )
    }

    @Test
    fun limitationNamingASignalIdAddressesThatSignalAndOnlyThatSignal() {
        val signals = listOf(healthSignal("sig-aaaaaaaaaaaa"), healthSignal("sig-bbbbbbbbbbbb"))
        val coverage = gapsOf(
            signals = signals,
            limitations = listOf(
                "The sig-bbbbbbbbbbbb family is expected on this network and needs no finding."
            )
        )
        assertEquals(listOf("sig-aaaaaaaaaaaa"), coverage.unaddressedSignals.map { it.signalId })
    }

    @Test
    fun criticDispositionAddressedSignalsCloseGapsWithoutAnyReportProse() {
        // Design §5.2's third channel.  The channel's producer is
        // OPT-COG-03-03; this pins the rule's reading of the input the
        // AgentRunTrace field is reserved for.
        val signals = listOf(healthSignal("sig-aaaaaaaaaaaa"), healthSignal("sig-bbbbbbbbbbbb"))
        val coverage = gapsOf(
            signals = signals,
            critic = setOf("sig-aaaaaaaaaaaa", "sig-bbbbbbbbbbbb")
        )
        assertTrue(coverage.clean)
    }

    @Test
    fun hostSignalGapLimitationNeverAddressesTheSignalItReports() {
        // Requirement "purge vacuous addressing": the marker-prefixed prose
        // mentions the raw id, and a self-satisfying limitation would mute
        // the post-validation net on every round after the first gap.
        val signal = healthSignal("sig-cccccccccccc")
        val markerLine = validator.signalGapLimitation(signal)
        assertTrue(markerLine.startsWith(ReportCoverageValidator.SIGNAL_GAP_LIMITATION_MARKER))
        val coverage = gapsOf(signals = listOf(signal), limitations = listOf(markerLine))
        assertEquals(listOf("sig-cccccccccccc"), coverage.unaddressedSignals.map { it.signalId })
        // The exclusion is line-scoped: a model-authored limitation is still
        // free to name the same id.
        assertTrue(
            gapsOf(
                signals = listOf(signal),
                limitations = listOf(markerLine, "Reviewed sig-cccccccccccc: benign.")
            ).clean
        )
    }

    @Test
    fun capMetaSignalIsAddressedLikeEveryOtherSignal() {
        // Decision, pinned: `signals_capped` is a real signal the report was
        // shown in its host-signals line and must acknowledge (a report that
        // says "I saw all the problems" while the host dropped signals is
        // exactly the overclaim §5.2 exists to catch).  No special case.
        val capped = AgentSignal(
            signalId = "sig-dddddddddddd",
            kind = AgentSignalExtractor.KIND_SIGNALS_CAPPED,
            value = "4",
            unit = AgentSignalExtractor.UNIT_SIGNALS
        )
        assertEquals(
            listOf("sig-dddddddddddd"),
            gapsOf(signals = listOf(capped)).unaddressedSignals.map { it.signalId }
        )
        assertTrue(
            gapsOf(
                signals = listOf(capped),
                findings = listOf(coveringFinding("sig-dddddddddddd"))
            ).clean
        )
    }

    @Test
    fun enforcementDisabledAnswersNothingToSayRegardlessOfInput() {
        val coverage = gapsOf(
            signals = listOf(healthSignal("sig-eeeeeeeeeeee")),
            enabled = false
        )
        assertTrue(coverage.clean)
        assertEquals(emptyList<AgentSignal>(), coverage.unaddressedSignals)
        assertEquals(emptyList<String>(), coverage.gapLimitations())
    }

    @Test
    fun gapLimitationsReuseThePinnedSignalGapWording() {
        val signals = listOf(healthSignal("sig-ffffffffffff"))
        assertEquals(
            listOf(
                "Host-enumerated overview signal sig-ffffffffffff " +
                    "(health_problems 3 problems) was not addressed by any finding."
            ),
            gapsOf(signals = signals).gapLimitations()
        )
    }
}

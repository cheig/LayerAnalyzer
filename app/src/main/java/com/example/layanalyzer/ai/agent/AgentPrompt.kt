package com.example.layanalyzer.ai.agent

import com.example.layanalyzer.model.AgentJsonObject
import com.example.layanalyzer.model.AgentPrivacyMode

/**
 * The report schema and compatibility prompt surface for Phase 2.
 *
 * [VERSION] is recorded in every report's provenance, so a report can always be
 * traced back to the exact instructions that produced it.  Bump it whenever the
 * prompt text changes in a way that could change a model's behaviour.
 *
 * The prompt states the analysis contract rather than trying to enumerate
 * attacks: the host does not rely on the model honouring any of it.  Tool
 * whitelisting, the privacy gate, budgets and evidence validation are all
 * enforced in code, and a model that ignores every line here still cannot read
 * a file, widen a limit or get an unverified claim past the validator.
 */
object AgentPrompt {
    const val VERSION: String = "phase2-1"
    const val AGENT_VERSION: String = "ai-16"
    const val OUTPUT_SCHEMA_VERSION: String = "agent-report-2"

    const val REPORT_PROSE_FORMAT: String =
        "Keep the required structured report envelope. Use Markdown INSIDE summary and " +
            "finding conclusion strings: lead with the result, separate distinct ideas with blank lines " +
            "(JSON-escaped as \\n\\n), and keep paragraphs to 1-3 sentences. A long summary or conclusion " +
            "must have multiple paragraphs or a list, never one uninterrupted block. Use **bold** " +
            "sparingly for key results and inline backticks for protocol fields and filters. " +
            "Use simple headings, lists or blockquotes when useful. Do not repeat the app's report " +
            "or finding title inside the prose. Each alternatives, recommendations, limitations or " +
            "recommendedNextSteps array entry is one item: inline Markdown is allowed, but omit its " +
            "leading bullet or number. Keep titles, evidence fields and identifiers plain text. " +
            "Do not use HTML, images, links, tables or fenced code blocks, and never wrap the report " +
            "JSON itself in Markdown fences."

    /** Sent when a model returns an empty tool-call list. */
    const val EMPTY_TOOL_CALL_NUDGE: String =
        "No tool call was received. Either call one of the available analysis tools " +
            "or return your final report."

    /** Sent when sibling calls were withheld because the declared plan was unusable. */
    const val INVALID_ANALYSIS_PLAN_NUDGE: String =
        "The analysis plan was invalid, so the host did not run its sibling capture calls. " +
            "Call declare_analysis_plan again with a non-empty goal and ordered steps that use " +
            "available non-orchestration tools."

    const val INVALID_DISPLAY_FILTER_NUDGE: String =
        "The previous display filter was rejected by the capture engine. Before using " +
            "another filter, call validate_display_filter; do not treat a rejected filter " +
            "as evidence. IP literals are unquoted, while string values use double quotes."

    const val PLAN_DEVIATION_NUDGE: String =
        "The host requires the next capture call to follow the declared analysis plan in order. " +
            "Choose the next planned tool exactly; after the plan is complete, return the report."

    /**
     * Sent when the declared plan finished but truncated results remain readable.
     *
     * The grant is deliberately narrow: it names the only permitted purpose
     * (continuing truncated reads) so a model cannot treat the extra turns as a
     * licence to reopen discovery.  The host still enforces the turn count, and
     * now also enforces the purpose — an off-purpose call is refused rather than
     * silently spending the grant, so naming the specific gaps here is guidance
     * that matches what the host will actually accept.
     */
    fun planGapFillNudge(turns: Int, gaps: List<String> = emptyList()): String = buildString {
        append(
            "The declared analysis plan is complete, but some tool results in this run were " +
                "truncated. The host grants up to $turns additional tool-call turn(s) ONLY to " +
                "re-read truncated evidence: use each truncated result's truncation.continuation " +
                "parameters (offset/limit, groupKey, omitted frames) or a narrower query (fewer " +
                "fields, a validated display filter). Calls that do not continue a truncated read " +
                "are refused and do not consume the grant. Do not start new lines of investigation."
        )
        if (gaps.isNotEmpty()) {
            append(" Outstanding gaps, most informative first: ")
            append(gaps.joinToString("; "))
            append('.')
        }
        append(" When the gaps are filled — or nothing more is readable — return your final report.")
    }

    /** Sent when a granted turn was spent on something other than a pending gap. */
    fun offPurposeGapFillNudge(turns: Int, gaps: List<String> = emptyList()): String = buildString {
        append(
            "That call did not continue a truncated read, so the host did not run it and did not " +
                "charge the grant. $turns turn(s) remain for continuing truncated evidence only."
        )
        if (gaps.isNotEmpty()) {
            append(" Continue one of these instead: ")
            append(gaps.joinToString("; "))
            append('.')
        }
        append(" If none of them would change your conclusion, return your final report now.")
    }

    /** Sent once the host stops further tools so collected evidence is not lost. */
    fun forcedFinalSummary(stopReason: AgentStopReason): String =
        "The host has stopped further tool calls for this run (${stopReason.name}). " +
            "Return exactly one compact final structured report now without reanalyzing. " +
            "Use at most five findings and one strongest evidence item per finding. Use only evidence already " +
            "returned by the tools in this conversation. Do not request any new analysis or " +
            "capture tool call; submitting the report itself is allowed. Clearly state that the " +
            "analysis is incomplete and distinguish confirmed observations from hypotheses. " + REPORT_PROSE_FORMAT

    /** One bounded no-tools retry after the provider returned an undecodable final object. */
    fun finalReportFormatRepair(reason: String): String =
        "Format repair: the preceding final response was rejected by the host ($reason). " +
            "Return exactly one complete JSON object matching the required final report schema. " +
            "Do not wrap the JSON object in Markdown fences or add commentary or tool calls. " +
            "Keep the report compact and use only evidence already present in this conversation. " +
            REPORT_PROSE_FORMAT

    /**
     * Host-authored reason codes and host-assigned finding ids only; no
     * capture-derived rejection detail is echoed.
     *
     * The request is deliberately narrow: only the rejected findings come back,
     * not the whole report. Regenerating a complete report was the single
     * largest generation in a run and reliably exceeded an intermediary's idle
     * timeout, so a run could lose a perfectly good report to a transport
     * failure on the *improvement* turn.
     */
    fun revisionRequest(
        rejectionReasons: List<String>,
        rejectedFindingIds: List<String> = emptyList()
    ): String {
        val counts = rejectionReasons.groupingBy { it }.eachCount().entries
            .sortedBy { it.key }
            .joinToString { (reason, count) -> "$reason=$count" }
        val ids = rejectedFindingIds.distinct().sorted()
        val target = if (ids.isEmpty()) {
            "Return corrected versions of only the findings whose citations were rejected."
        } else {
            "Return corrected versions of only these findings: ${ids.joinToString()}."
        }
        return "The host rejected multiple citations in the preceding report ($counts). " +
            "$target Do not restate the findings the host accepted, and do not rewrite the " +
            "summary — the host keeps both. Use only tool call ids and facts already present " +
            "in this conversation, remove unsupported citations, and weaken any conclusion " +
            "that the remaining evidence no longer supports. Do not request any new analysis " +
            "or capture tool call; return the corrected findings directly."
    }

    fun delegatedInvestigation(goal: String): String =
        "Investigate this bounded subproblem in an isolated transcript: $goal\n" +
            "Use the available capture tools, then return a compact structured report. " +
            "Do not delegate another investigation or declare a new analysis plan."

    /**
     * Compatibility surface used by the consent preview. Runtime prompt assembly
     * uses [PromptAssembler] to keep capture-derived data out of System messages.
     */
    @Suppress("UNUSED_PARAMETER")
    fun systemPrompt(
        snapshot: com.example.layanalyzer.model.AgentCaptureSnapshot,
        policy: AgentPolicy,
        privacyMode: AgentPrivacyMode
    ): String = PromptAssembler.SYSTEM_CONSTRAINTS

    /**
     * Response schema for the final report.
     *
     * Deliberately a *subset* of AgentReport: `provenance` and `completeness` are
     * absent because the host owns them.  A model that emits them anyway is not
     * rewarded — the validator overwrites both from the run trace.
     *
     * The fragments below are declared before the schema that uses them:
     * initialization inside an object follows declaration order.
     */
    private val STRING_LIST_SCHEMA: AgentJsonObject = mapOf(
        "type" to "array",
        "maxItems" to 20,
        "items" to mapOf(
            "type" to "string", "maxLength" to 500,
            "description" to "One concise item with optional inline Markdown; no leading bullet or number."
        )
    )

    /** agent-report-2: bounded list of short string references (tool call ids, signal ids). */
    private val REFERENCE_ID_LIST_SCHEMA: AgentJsonObject = mapOf(
        "type" to "array",
        "maxItems" to 8,
        "items" to mapOf("type" to "string", "maxLength" to 120)
    )

    /** agent-report-2: one user-question part and whether the report addressed it. */
    private val QUESTION_ALIGNMENT_SCHEMA_ITEM: AgentJsonObject = mapOf(
        "type" to "object",
        "additionalProperties" to false,
        "required" to listOf("questionPart"),
        "properties" to mapOf(
            "questionPart" to mapOf("type" to "string", "maxLength" to 500),
            "addressed" to mapOf("type" to "boolean"),
            "findingIds" to mapOf(
                "type" to "array",
                "maxItems" to 20,
                "items" to mapOf("type" to "string", "maxLength" to 120)
            )
        )
    )

    private val EVIDENCE_SCHEMA_ITEM: AgentJsonObject = mapOf(
        "type" to "object",
        "additionalProperties" to false,
        "required" to listOf("type", "observation", "sourceToolCallId"),
        "properties" to mapOf(
            "type" to mapOf(
                "type" to "string",
                "enum" to listOf(
                    "Frame",
                    "Packet",
                    "Field",
                    "Statistic",
                    "DisplayFilter",
                    "ExpertInfo",
                    "Transaction",
                    "Timeline",
                    "Observation"
                )
            ),
            "frameNumber" to mapOf("type" to "integer", "minimum" to 1),
            "displayFilter" to mapOf("type" to "string", "maxLength" to 2048),
            "field" to mapOf("type" to "string", "maxLength" to 200),
            "observation" to mapOf("type" to "string", "maxLength" to 1000),
            "sourceToolCallId" to mapOf("type" to "string", "maxLength" to 120),
            "metric" to mapOf("type" to "string", "maxLength" to 200),
            "observedValue" to mapOf("type" to "string", "maxLength" to 200),
            "timeRangeStartMillis" to mapOf("type" to "integer", "minimum" to 0),
            "timeRangeEndMillis" to mapOf("type" to "integer", "minimum" to 0)
        )
    )

    private val FINDING_SCHEMA_ITEM: AgentJsonObject = mapOf(
        "type" to "object",
        "additionalProperties" to false,
        "required" to listOf(
            "id",
            "title",
            "severity",
            "confidence",
            "conclusion",
            "evidence",
            "polarity"
        ),
        "properties" to mapOf(
            "id" to mapOf("type" to "string", "maxLength" to 120),
            "title" to mapOf("type" to "string", "maxLength" to 200),
            "severity" to mapOf(
                "type" to "string",
                "enum" to listOf("Info", "Notice", "Warning", "Error", "Critical")
            ),
            "confidence" to mapOf(
                "type" to "string",
                "enum" to listOf("Low", "Medium", "High")
            ),
            "conclusion" to mapOf(
                "type" to "string", "maxLength" to 2000,
                "description" to "Markdown prose: result first, then evidence interpretation. " +
                    "Separate distinct ideas with blank lines; use short paragraphs or a list."
            ),
            "evidence" to mapOf(
                "type" to "array",
                "minItems" to 1,
                "maxItems" to 20,
                "items" to EVIDENCE_SCHEMA_ITEM
            ),
            "alternatives" to STRING_LIST_SCHEMA,
            "recommendations" to STRING_LIST_SCHEMA,
            "timeline" to mapOf(
                "type" to "array",
                "maxItems" to 12,
                "items" to mapOf(
                    "type" to "object",
                    "additionalProperties" to false,
                    "required" to listOf("stage"),
                    "properties" to mapOf(
                        "stage" to mapOf("type" to "string", "maxLength" to 120),
                        "frameNumber" to mapOf("type" to "integer", "minimum" to 1),
                        "detail" to mapOf("type" to "string", "maxLength" to 240),
                        "elapsedMillis" to mapOf("type" to "integer", "minimum" to 0)
                    )
                )
            ),
            // agent-report-2 (OPT-VAL-04-01): every finding must declare the
            // polarity of its core claim.  The accepted values are the
            // AgentFindingPolarity entry names, minus `Unknown` — unknown is
            // the host-derived default for reports that predate the field or
            // arrive without structured output, never a model-supplied value.
            "polarity" to mapOf(
                "type" to "string",
                "enum" to listOf("Positive", "Negative", "Neutral")
            ),
            // Remaining agent-report-2 fields stay optional-with-default until
            // their validation tasks make them mandatory (OPT-ARCH-02
            // degradation contract: missing fields become limitations, never a
            // parse or schema rejection).
            "counterEvidenceChecked" to REFERENCE_ID_LIST_SCHEMA,
            "hypothesisId" to mapOf("type" to "string", "maxLength" to 120),
            "relatedSignals" to REFERENCE_ID_LIST_SCHEMA
        )
    )

    val REPORT_SCHEMA: AgentJsonObject = mapOf(
        "type" to "object",
        "additionalProperties" to false,
        "required" to listOf("summary", "findings", "questionAlignment"),
        "properties" to mapOf(
            "summary" to mapOf(
                "type" to "string", "maxLength" to 2000,
                "description" to "Markdown overview: answer first, then key observations and uncertainty. " +
                    "Separate distinct ideas with blank lines; no long uninterrupted paragraph."
            ),
            "findings" to mapOf(
                "type" to "array",
                "maxItems" to 20,
                "items" to FINDING_SCHEMA_ITEM
            ),
            "limitations" to STRING_LIST_SCHEMA,
            "recommendedNextSteps" to STRING_LIST_SCHEMA,
            // agent-report-2 (OPT-VAL-03-01): every report must decompose the
            // user question and point each part at the findings that answer
            // it; the host verifies the references structurally (design §5.3)
            // and the Critic judges the semantics (OPT-COG-03, not yet
            // landed). Reports predating the field — or arriving without
            // structured output — still decode with an empty list: the codec
            // keeps its optional-with-default degradation contract even
            // though the wire schema now demands the field.
            "questionAlignment" to mapOf(
                "type" to "array",
                "maxItems" to 4,
                "items" to QUESTION_ALIGNMENT_SCHEMA_ITEM
            )
        )
    )

    /**
     * Response schema for a targeted revision.
     *
     * Only the rejected findings come back, so the model regenerates a handful
     * of objects instead of the whole report.  That keeps the response small
     * enough to arrive before an intermediary's idle timeout — the full-report
     * revision was the largest single generation in a run and reliably crossed
     * a 60-second gateway ceiling.
     *
     * The host merges these into the report it already validated, so `summary`,
     * `limitations` and `recommendedNextSteps` are deliberately absent: a
     * revision may correct evidence, not rewrite the analysis around it.
     */
    val REVISED_FINDINGS_SCHEMA: AgentJsonObject = mapOf(
        "type" to "object",
        "additionalProperties" to false,
        "required" to listOf("findings"),
        "properties" to mapOf(
            "findings" to mapOf(
                "type" to "array",
                "maxItems" to 20,
                "items" to FINDING_SCHEMA_ITEM
            )
        )
    )
}

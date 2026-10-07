package com.example.layanalyzer.ui.components

import com.example.layanalyzer.R
import com.example.layanalyzer.ai.playbook.AgentPlaybookCheck
import com.example.layanalyzer.ai.playbook.ScenarioTextRules
import com.example.layanalyzer.ai.playbook.ScenarioValidationCodes
import com.example.layanalyzer.ai.playbook.ScenarioValidationError
import org.junit.Assert.assertEquals
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * JVM tests for the scenario editor's real-time validation selectors
 * (SRE-EDITOR-02).  The selectors return string res ids rather than resolved
 * strings, so the expected results here are the same `R.string` constants the
 * composables resolve at runtime.  The store's own rejections are separate:
 * the UI prefers them per field, and the store side is covered by
 * [com.example.layanalyzer.viewmodel.ProtocolAgentViewModelTest].
 */
class AgentScenarioEditorValidationTest {

    private val maxTitle = ScenarioTextRules.USER_MAX_TITLE_LENGTH
    private val maxHint = ScenarioTextRules.USER_MAX_HINT_LENGTH
    private val maxText = ScenarioTextRules.USER_MAX_TEXT_LENGTH

    // ------------------------------------------------------ title selectors

    @Test
    fun `blank title is rejected as required`() {
        assertEquals(
            R.string.agent_scenario_editor_error_title_required,
            agentScenarioTitleError("", maxTitle)
        )
        assertEquals(
            R.string.agent_scenario_editor_error_title_required,
            agentScenarioTitleError("   ", maxTitle)
        )
    }

    @Test
    fun `over-long title is rejected as too long`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_too_long,
            agentScenarioTitleError("a".repeat(maxTitle + 1), maxTitle)
        )
    }

    @Test
    fun `title at the length limit is accepted`() {
        assertEquals(
            null,
            agentScenarioTitleError("a".repeat(maxTitle), maxTitle)
        )
    }

    @Test
    fun `declarative title is accepted`() {
        assertEquals(
            null,
            agentScenarioTitleError("RTP stream check", maxTitle)
        )
    }

    @Test
    fun `title with forbidden content is rejected as not declarative`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioTitleError("see https://example.com for details", maxTitle)
        )
    }

    // ------------------------------------------------------- hint selectors

    @Test
    fun `blank hint is rejected as required`() {
        assertEquals(
            R.string.agent_scenario_editor_error_hint_required,
            agentScenarioHintError("", maxHint)
        )
    }

    @Test
    fun `over-long hint is rejected as too long`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_too_long,
            agentScenarioHintError("h".repeat(maxHint + 1), maxHint)
        )
    }

    @Test
    fun `declarative hint is accepted`() {
        assertEquals(
            null,
            agentScenarioHintError("capture health", maxHint)
        )
    }

    @Test
    fun `hint with executable-looking content is rejected as not declarative`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioHintError("run ```pcap``` filter", maxHint)
        )
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioHintError("then eval(x) the result", maxHint)
        )
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioHintError("HTTPS://EXAMPLE.com/trace", maxHint)
        )
    }

    // ------------------------------------------------ intent hints section

    @Test
    fun `empty hint list is rejected and a non-empty list is accepted`() {
        assertEquals(
            R.string.agent_scenario_editor_error_intent_hints_required,
            agentScenarioIntentHintsError(emptyList())
        )
        assertEquals(
            null,
            agentScenarioIntentHintsError(listOf("capture health"))
        )
    }

    // ------------------------------------------------- multi-select toggles

    // SRE-EDITOR-03: the chip selection toggles for Initial tools and Required
    // fields.  Both are pure list functions, asserted against plain lists so
    // the editor's selection behavior is pinned without any Compose machinery.

    @Test
    fun `initial tool toggle adds a new tool at the end`() {
        assertEquals(
            listOf("get_capture_overview"),
            toggleInitialTool(emptyList(), "get_capture_overview")
        )
        assertEquals(
            listOf("get_capture_overview", "search_packets"),
            toggleInitialTool(listOf("get_capture_overview"), "search_packets")
        )
    }

    @Test
    fun `initial tool toggle removes a selected tool and keeps the remaining order`() {
        assertEquals(
            listOf("get_capture_overview"),
            toggleInitialTool(listOf("get_capture_overview", "search_packets"), "search_packets")
        )
        assertEquals(
            listOf("search_packets"),
            toggleInitialTool(listOf("get_capture_overview", "search_packets"), "get_capture_overview")
        )
    }

    @Test
    fun `required field toggle adds a new field`() {
        assertEquals(listOf("dns.a"), toggleRequiredField(emptyList(), "dns.a", 32))
        assertEquals(
            listOf("dns.a", "dns.time"),
            toggleRequiredField(listOf("dns.a"), "dns.time", 32)
        )
    }

    @Test
    fun `required field toggle removes a selected field`() {
        assertEquals(
            listOf("dns.time"),
            toggleRequiredField(listOf("dns.a", "dns.time"), "dns.a", 32)
        )
    }

    @Test
    fun `required field toggle refuses additions at the cap but keeps removals`() {
        val full = (0 until 32).map { "field-$it" }
        assertEquals(full, toggleRequiredField(full, "field-32", 32))
        assertEquals(full.drop(1), toggleRequiredField(full, "field-0", 32))
    }

    @Test
    fun `required field toggle never duplicates an already selected field`() {
        val current = listOf("dns.a", "dns.time")
        // Toggling a selected field removes it rather than appending a second
        // entry, and an over-cap list with the field still loses exactly it.
        assertEquals(listOf("dns.time"), toggleRequiredField(current, "dns.a", 32))
        assertEquals(listOf("dns.a"), toggleRequiredField(current, "dns.time", 1))
    }

    // ------------------------------------------ SRE-EDITOR-04 text selectors

    // The Checks / Success path / Failure branches field selectors.  Only the
    // check description is required; every field shares the 300-character text
    // budget and the declarative rule, exactly as the store's save boundary
    // applies them.

    @Test
    fun `blank check description is rejected as required`() {
        assertEquals(
            R.string.agent_scenario_editor_error_check_description_required,
            agentScenarioCheckDescriptionError("", maxText)
        )
        assertEquals(
            R.string.agent_scenario_editor_error_check_description_required,
            agentScenarioCheckDescriptionError("   ", maxText)
        )
    }

    @Test
    fun `over-long check description is rejected as too long`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_too_long,
            agentScenarioCheckDescriptionError("d".repeat(maxText + 1), maxText)
        )
    }

    @Test
    fun `declarative check description is accepted`() {
        assertEquals(
            null,
            agentScenarioCheckDescriptionError(
                "Use health and Expert counts to choose the next query",
                maxText
            )
        )
    }

    @Test
    fun `check description with forbidden content is rejected as not declarative`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioCheckDescriptionError("fetch https://example.com/trace", maxText)
        )
    }

    @Test
    fun `blank optional text is accepted`() {
        // The store's text rules accept a blank success-path step, failure
        // branch condition or limitation, so the editor does not demand text.
        assertEquals(null, agentScenarioOptionalTextError("", maxText))
        assertEquals(null, agentScenarioOptionalTextError("   ", maxText))
    }

    @Test
    fun `over-long optional text is rejected as too long`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_too_long,
            agentScenarioOptionalTextError("s".repeat(maxText + 1), maxText)
        )
    }

    @Test
    fun `declarative optional text is accepted`() {
        assertEquals(
            null,
            agentScenarioOptionalTextError("A source is truncated or a query fails", maxText)
        )
    }

    @Test
    fun `optional text with forbidden content is rejected as not declarative`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioOptionalTextError("run ```pcap``` filter", maxText)
        )
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioOptionalTextError("then exec(cmd) on it", maxText)
        )
    }

    // --------------------------------------------------- SRE-EDITOR-04 lists

    // Check id minting, card appends and the per-card recommended-tools toggle.
    // All pure list functions, asserted against plain lists without Compose.

    @Test
    fun `next check id starts at one for an empty list`() {
        assertEquals("check-1", nextCheckId(emptyList()))
    }

    @Test
    fun `next check id skips taken numbers`() {
        assertEquals(
            "check-3",
            nextCheckId(listOf("check-1", "check-2"))
        )
    }

    @Test
    fun `next check id fills the lowest gap`() {
        assertEquals(
            "check-2",
            nextCheckId(listOf("check-1", "check-3"))
        )
    }

    @Test
    fun `next check id ignores ids outside the check-n shape`() {
        // Hand-named ids, non-numeric tails and zero-padded numbers are legal
        // ids of their own; none of them claims a number in the check-n series.
        assertEquals(
            "check-1",
            nextCheckId(listOf("health", "check-2x", "check-", "check-01", "Check-2"))
        )
    }

    @Test
    fun `appending a check mints the next id and starts blank`() {
        val appended = appendCheck(emptyList())
        assertEquals(listOf(AgentPlaybookCheck("check-1", "", emptyList())), appended)
    }

    @Test
    fun `appending a check leaves existing checks and ids untouched`() {
        val existing = listOf(
            AgentPlaybookCheck("health", "first", listOf("get_statistics")),
            AgentPlaybookCheck("check-1", "second", emptyList()),
            AgentPlaybookCheck("check-3", "third", emptyList())
        )
        val appended = appendCheck(existing)
        assertEquals(4, appended.size)
        // The prefix cards are the same objects in the same order — no rename,
        // no renumber, no reshuffle; only the blank card joins at the end.
        assertEquals(existing, appended.dropLast(1))
        assertEquals("check-2", appended.last().id)
        assertEquals("", appended.last().description)
        assertEquals(emptyList<String>(), appended.last().recommendedTools)
    }

    @Test
    fun `recommended tool toggle adds a new tool at the end`() {
        assertEquals(
            listOf("get_statistics"),
            toggleRecommendedTool(emptyList(), "get_statistics")
        )
        assertEquals(
            listOf("get_statistics", "get_expert_info"),
            toggleRecommendedTool(listOf("get_statistics"), "get_expert_info")
        )
    }

    @Test
    fun `recommended tool toggle removes a selected tool and keeps the remaining order`() {
        assertEquals(
            listOf("get_statistics"),
            toggleRecommendedTool(listOf("get_statistics", "get_expert_info"), "get_expert_info")
        )
    }

    @Test
    fun `recommended tool toggle removes an already selected tool instead of duplicating it`() {
        // The toggle semantics of the Initial tools chips: a selected chip is
        // toggled off, so a toggle can never grow the list by duplicating.
        assertEquals(
            emptyList<String>(),
            toggleRecommendedTool(listOf("get_statistics"), "get_statistics")
        )
    }

    // ------------------------------------------ SRE-EDITOR-05 list entries

    // The Protocols, Limitations and Report sections entries are optional
    // declarative text with the shared 300-character budget — the same
    // agentScenarioOptionalTextError selector the Success path steps use, so
    // all three sections validate entries exactly like optional text and blank
    // rows pass because the store's text rules accept them too.

    @Test
    fun `blank entries pass in the three optional list sections`() {
        // Protocols, Limitations and Report sections rows are optional: an
        // empty or whitespace entry is legal, matching rejectText on blanks.
        assertEquals(null, agentScenarioOptionalTextError("", maxText))
        assertEquals(null, agentScenarioOptionalTextError("   ", maxText))
    }

    @Test
    fun `list entries accept declarative values including the any protocol`() {
        assertEquals(null, agentScenarioOptionalTextError("any", maxText))
        assertEquals(null, agentScenarioOptionalTextError("sip", maxText))
        assertEquals(null, agentScenarioOptionalTextError("rtp, rtcp", maxText))
        assertEquals(
            null,
            agentScenarioOptionalTextError("state the incomplete coverage, do not infer an absence", maxText)
        )
        assertEquals(null, agentScenarioOptionalTextError("summary", maxText))
    }

    @Test
    fun `over-long list entries are rejected at the shared text budget`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_too_long,
            agentScenarioOptionalTextError("p".repeat(maxText + 1), maxText)
        )
        assertEquals(
            null,
            agentScenarioOptionalTextError("p".repeat(maxText), maxText)
        )
    }

    @Test
    fun `list entries with executable-looking content are rejected as not declarative`() {
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioOptionalTextError("see https://example.com/spec", maxText)
        )
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioOptionalTextError("run ```pcap``` filter", maxText)
        )
        assertEquals(
            R.string.agent_scenario_editor_error_text_not_declarative,
            agentScenarioOptionalTextError("then eval(x) the result", maxText)
        )
    }

    // ------------------------------------- SRE-EDITOR-05 unified field error

    // scenarioFieldError is the single store-error lookup every section uses:
    // the store's reason-coded rejection (OPT-ERR-01 — a code + args, never
    // prose) shows while the field still holds the value the store validated,
    // and disappears the moment the value changes.  The composable
    // scenarioFieldErrorText resolves the returned error through the code →
    // resource mapping asserted further below.

    @Test
    fun `field error shows the store rejection while the value is unchanged`() {
        val error = ScenarioValidationError(ScenarioValidationCodes.ID_PREFIX_REQUIRED)
        val errors = mapOf("title" to error)
        assertEquals(
            error,
            scenarioFieldError(
                errors, "title", currentValue = "kept", storedValue = "kept"
            )
        )
    }

    @Test
    fun `field error disappears once the value changed`() {
        assertEquals(
            null,
            scenarioFieldError(
                mapOf("title" to ScenarioValidationError(ScenarioValidationCodes.TEXT_TOO_LONG)),
                "title",
                currentValue = "edited", storedValue = "what the store saw"
            )
        )
    }

    @Test
    fun `field error does not migrate to a row that replaced a removed one`() {
        // The store rejected the hint that used to sit at index 1; the row now
        // there holds different text, so it must not adopt the stale error.
        assertEquals(
            null,
            scenarioFieldError(
                mapOf(
                    "intentHints[1]" to
                        ScenarioValidationError(ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT)
                ),
                "intentHints[1]",
                currentValue = "different text", storedValue = "rejected text"
            )
        )
    }

    @Test
    fun `field error stays silent without a stored value or a store rejection`() {
        // A field the store never validated (null storedValue) never inherits
        // an error, and an unchanged value with no rejection on its path
        // stays clean.
        assertEquals(
            null,
            scenarioFieldError(
                mapOf("title" to ScenarioValidationError(ScenarioValidationCodes.TEXT_TOO_LONG)),
                "title",
                currentValue = "kept", storedValue = null
            )
        )
        assertEquals(
            null,
            scenarioFieldError(
                emptyMap<String, ScenarioValidationError>(), "title",
                currentValue = "kept", storedValue = "kept"
            )
        )
    }

    // ------------------------------------- OPT-ERR-01 code → resource mapping

    // The store reports reason codes; every declared code must have a string
    // resource in the editor mapping, or an unmapped code silently loses its
    // localization.  Unknown codes resolve to null and the UI shows the raw
    // code instead (debuggable, never a crash).

    @Test
    fun `every declared validation code has a string resource mapping`() {
        ScenarioValidationCodes.ALL.forEach { code ->
            assertTrue(
                "Code '$code' has no string resource mapping",
                scenarioErrorCodeResId(code) != null
            )
        }
    }

    @Test
    fun `unknown codes fall back to no resource so the UI shows the code`() {
        assertEquals(null, scenarioErrorCodeResId("some_future_code"))
        assertEquals(null, scenarioErrorCodeResId(""))
    }

    // ---------------------------------- SRE-EDITOR-05 summary path labels

    // scenarioErrorPathLabel turns store paths into the user-facing labels the
    // summary card shows; element indexes turn 1-based, matching how the
    // editor numbers rows and cards.  Unrecognized paths return null and are
    // displayed verbatim.

    @Test
    fun `summary label maps indexed field paths to one-based labels`() {
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_check_description, listOf(3)),
            scenarioErrorPathLabel("checks[2].description")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_branch_condition, listOf(1)),
            scenarioErrorPathLabel("failureBranches[0].condition")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_intent_hint, listOf(2)),
            scenarioErrorPathLabel("intentHints[1]")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_step, listOf(4)),
            scenarioErrorPathLabel("successPath[3]")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_limitation, listOf(1)),
            scenarioErrorPathLabel("requiredLimitations[0]")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_report_section, listOf(2)),
            scenarioErrorPathLabel("outputSections[1]")
        )
    }

    @Test
    fun `summary label maps scalar and whole-list paths`() {
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_scenario_id),
            scenarioErrorPathLabel("id")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_title),
            scenarioErrorPathLabel("title")
        )
        // Whole-list rejections reuse the section titles the editor shows.
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_section_protocols),
            scenarioErrorPathLabel("protocols")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_section_intent_hints),
            scenarioErrorPathLabel("intentHints")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_section_initial_tools),
            scenarioErrorPathLabel("initialTools")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_section_required_fields),
            scenarioErrorPathLabel("requiredFields")
        )
    }

    @Test
    fun `summary label covers tool and check-id paths and leaves unknown paths raw`() {
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_check_id, listOf(1)),
            scenarioErrorPathLabel("checks[0].id")
        )
        assertEquals(
            ScenarioErrorPathLabel(
                R.string.agent_scenario_editor_error_path_branch_recommended_tools, listOf(2)
            ),
            scenarioErrorPathLabel("failureBranches[1].recommendedTools")
        )
        assertEquals(
            ScenarioErrorPathLabel(
                R.string.agent_scenario_editor_error_path_check_recommended_tools, listOf(1)
            ),
            scenarioErrorPathLabel("checks[0].recommendedTools")
        )
        assertEquals(null, scenarioErrorPathLabel("somethingUnmapped"))
        assertEquals(null, scenarioErrorPathLabel("checks[abc].description"))
        assertEquals(null, scenarioErrorPathLabel("checks[0].unknownField"))
    }

    @Test
    fun `summary label maps whole-element paths of the card and row lists`() {
        // An element of a structured list (a whole check card or failure
        // branch row, or one protocol entry) labels itself with its 1-based
        // number; the branch limitation joins condition and recommendedTools.
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_check, listOf(2)),
            scenarioErrorPathLabel("checks[1]")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_failure_branch_label, listOf(1)),
            scenarioErrorPathLabel("failureBranches[0]")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_branch_limitation, listOf(3)),
            scenarioErrorPathLabel("failureBranches[2].limitation")
        )
        assertEquals(
            ScenarioErrorPathLabel(R.string.agent_scenario_editor_error_path_protocol, listOf(1)),
            scenarioErrorPathLabel("protocols[0]")
        )
    }

    @Test
    fun `summary label leaves element paths of the chip lists raw`() {
        // Initial tools and required fields have no per-element label string:
        // an element-level rejection on them falls through to the raw path,
        // matching how only the whole-list path is registered in the label
        // table — pinning that these lists are deliberately not indexed
        // labels, not a missed mapping.
        assertEquals(null, scenarioErrorPathLabel("initialTools[0]"))
        assertEquals(null, scenarioErrorPathLabel("requiredFields[2]"))
        assertEquals(null, scenarioErrorPathLabel("checks[0].outputSchema"))
    }

    // ---------------------------------- SRE-EDITOR-06 error-to-section mapping

    // scenarioErrorSection turns store paths into the section the
    // scroll-to-first-error logic brings into view.  Header-level (`id`) and
    // unknown paths resolve to the top summary anchor, so an unrecognized
    // future path still scrolls somewhere useful.

    @Test
    fun `error section maps whole-field paths to their sections`() {
        assertEquals(ScenarioEditorSection.BasicInfo, scenarioErrorSection("title"))
        assertEquals(ScenarioEditorSection.IntentHints, scenarioErrorSection("intentHints"))
        assertEquals(ScenarioEditorSection.InitialTools, scenarioErrorSection("initialTools"))
        assertEquals(ScenarioEditorSection.RequiredFields, scenarioErrorSection("requiredFields"))
        assertEquals(ScenarioEditorSection.Checks, scenarioErrorSection("checks"))
        assertEquals(ScenarioEditorSection.SuccessPath, scenarioErrorSection("successPath"))
        assertEquals(
            ScenarioEditorSection.FailureBranches,
            scenarioErrorSection("failureBranches")
        )
        assertEquals(ScenarioEditorSection.Protocols, scenarioErrorSection("protocols"))
        assertEquals(
            ScenarioEditorSection.Limitations,
            scenarioErrorSection("requiredLimitations")
        )
        assertEquals(ScenarioEditorSection.OutputSections, scenarioErrorSection("outputSections"))
    }

    @Test
    fun `error section maps indexed paths to the section owning the list`() {
        assertEquals(ScenarioEditorSection.IntentHints, scenarioErrorSection("intentHints[1]"))
        assertEquals(
            ScenarioEditorSection.Checks,
            scenarioErrorSection("checks[0].description")
        )
        assertEquals(
            ScenarioEditorSection.Checks,
            scenarioErrorSection("checks[0].recommendedTools")
        )
        assertEquals(ScenarioEditorSection.SuccessPath, scenarioErrorSection("successPath[0]"))
        assertEquals(
            ScenarioEditorSection.FailureBranches,
            scenarioErrorSection("failureBranches[1].condition")
        )
        assertEquals(
            ScenarioEditorSection.FailureBranches,
            scenarioErrorSection("failureBranches[1].limitation")
        )
        assertEquals(ScenarioEditorSection.Protocols, scenarioErrorSection("protocols[0]"))
        assertEquals(
            ScenarioEditorSection.Limitations,
            scenarioErrorSection("requiredLimitations[0]")
        )
        assertEquals(
            ScenarioEditorSection.OutputSections,
            scenarioErrorSection("outputSections[0]")
        )
    }

    @Test
    fun `error section maps element paths of the chip lists too`() {
        // The label table has no per-element entry for Initial tools and
        // Required fields, but scrolling still owns those rows: an element
        // path resolves to the section holding the chip list.
        assertEquals(ScenarioEditorSection.InitialTools, scenarioErrorSection("initialTools[0]"))
        assertEquals(ScenarioEditorSection.RequiredFields, scenarioErrorSection("requiredFields[2]"))
    }

    @Test
    fun `error section anchors header-level and unknown paths to the top summary`() {
        assertEquals(ScenarioEditorSection.Summary, scenarioErrorSection("id"))
        assertEquals(ScenarioEditorSection.Summary, scenarioErrorSection("somethingUnmapped"))
        assertEquals(ScenarioEditorSection.Summary, scenarioErrorSection("checks[abc].description"))
    }

    @Test
    fun `error list row resolves the element index within its own list only`() {
        assertEquals(1, scenarioErrorListRow("intentHints[1]", "intentHints"))
        assertEquals(0, scenarioErrorListRow("checks[0].description", "checks"))
        assertEquals(2, scenarioErrorListRow("failureBranches[2].limitation", "failureBranches"))
        // A whole-list rejection has no row to focus, another list's path must
        // not resolve, and unknown shapes stay null.
        assertEquals(null, scenarioErrorListRow("intentHints", "intentHints"))
        assertEquals(null, scenarioErrorListRow("checks[0].description", "intentHints"))
        assertEquals(null, scenarioErrorListRow("somethingUnmapped", "intentHints"))
    }

    @Test
    fun `error list field resolves the sub-field name or the empty string`() {
        assertEquals("description", scenarioErrorListField("checks[0].description"))
        assertEquals("condition", scenarioErrorListField("failureBranches[1].condition"))
        assertEquals("recommendedTools", scenarioErrorListField("checks[3].recommendedTools"))
        // Whole-element, whole-list and unknown paths name no sub-field.
        assertEquals("", scenarioErrorListField("intentHints[1]"))
        assertEquals("", scenarioErrorListField("intentHints"))
        assertEquals("", scenarioErrorListField("somethingUnmapped"))
    }
}

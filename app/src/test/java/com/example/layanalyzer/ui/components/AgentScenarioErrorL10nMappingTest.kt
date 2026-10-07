// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import com.example.layanalyzer.R
import com.example.layanalyzer.ai.playbook.ScenarioValidationCodes
import java.lang.reflect.Modifier
import org.junit.Assert.assertEquals
import org.junit.Assert.assertNotNull
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * Bidirectional coverage of the OPT-ERR-01 code → string-resource mapping
 * ([scenarioErrorCodeResId]), the UI half of the reason-code contract
 * [com.example.layanalyzer.ai.playbook.ScenarioValidationCodesTest] pins on
 * the data side.
 *
 * Forward: every declared code resolves to a distinct, real `R.string`
 * resource whose name matches the code (the naming convention is asserted
 * through reflection over the generated `R.string` fields, so a renamed or
 * dropped resource fails here rather than rendering as the raw code on
 * device).  Reverse: every string in the mapping's naming family belongs to
 * exactly one declared code — a future `agent_scenario_editor_error_*`
 * resource that no code points at (or a code whose resource went missing)
 * is an orphan this test rejects.  The pair makes the mapping a total,
 * injective function over the closed code set.
 */
class AgentScenarioErrorL10nMappingTest {

    /**
     * The generated resource-table snapshot: every `R.string` field name to
     * its id, read reflectively so the enumeration tracks the resource file
     * instead of a hand-copied list.
     */
    private val resourceIdsByName: Map<String, Int> =
        R.string::class.java.fields
            .filter { field ->
                Modifier.isStatic(field.modifiers) && field.type == Int::class.javaPrimitiveType
            }
            .associate { field -> field.name to field.getInt(null) }

    /** The resource name the mapping owes [code]: the convention plus its pinned exceptions. */
    private fun expectedResourceName(code: String): String = when (code) {
        // Two documented deviations from `agent_scenario_editor_error_<code>`:
        // the forbidden-content message reads as "not declarative" to users,
        // and the required-fields cap message predates the error_ prefix.
        ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT ->
            "agent_scenario_editor_error_text_not_declarative"
        ScenarioValidationCodes.REQUIRED_FIELDS_CAP ->
            "agent_scenario_editor_required_fields_cap"
        else -> "agent_scenario_editor_error_$code"
    }

    // ------------------------------------------------------ forward coverage

    /** Every declared code maps to a resource id, and no id serves two codes. */
    @Test
    fun everyDeclaredCodeMapsToADistinctNonZeroResource() {
        val resIds = ScenarioValidationCodes.ALL.map { code ->
            assertNotNull("Code '$code' has no string resource", scenarioErrorCodeResId(code))
            scenarioErrorCodeResId(code)!!
        }
        resIds.forEach { resId ->
            assertTrue(
                "A code maps to resource id 0 (invalid)",
                resId != 0
            )
        }
        assertEquals(
            "Two validation codes share one string resource",
            resIds.size,
            resIds.distinct().size
        )
    }

    /**
     * Each code's mapping target is the real `R.string` field named after
     * the code (modulo the two documented exception names pinned in
     * [expectedResourceName]) — so a code never silently points at another
     * code's text and every referenced resource actually exists.
     */
    @Test
    fun everyCodeResolvesToTheStringResourceNamedAfterIt() {
        ScenarioValidationCodes.ALL.forEach { code ->
            val name = expectedResourceName(code)
            val expectedId = resourceIdsByName[name]
            assertNotNull("Resource '$name' for code '$code' is not declared", expectedId)
            assertEquals(
                "Code '$code' maps to a resource other than '$name'",
                expectedId,
                scenarioErrorCodeResId(code)
            )
        }
    }

    // ------------------------------------------------------ reverse coverage

    /**
     * No orphan resources: every `agent_scenario_editor_error_*` string is
     * owned either by a validation code's mapping or by one of the surfaces
     * that legitimately keep resources outside the code map — the summary
     * card's path labels (`_path_*`, owned by
     * [scenarioErrorPathLabel]) and the editor chrome / real-time selector
     * messages enumerated below.  Adding such a string without wiring it to
     * a code (or recording its owner here) fails this test.
     */
    @Test
    fun everyErrorNamedResourceIsOwnedByACodeOrADocumentedSurface() {
        val mappedNames = ScenarioValidationCodes.ALL
            .mapNotNull { code -> scenarioErrorCodeResId(code) }
            .mapNotNull { resId -> resourceIdsByName.entries.firstOrNull { it.value == resId }?.key }
            .toSet()
        val nonCodeOwners = resourceIdsByName.keys
            .filter { name -> name.startsWith("agent_scenario_editor_error_") }
            .filterNot { name -> name.startsWith("agent_scenario_editor_error_path_") }
            .filterNot { name -> name in mappedNames }
        assertEquals(
            "Unowned agent_scenario_editor_error_* resources (orphaned from the code map)",
            setOf(
                // Real-time selector messages with no store-side code.
                "agent_scenario_editor_error_title_required",
                "agent_scenario_editor_error_hint_required",
                "agent_scenario_editor_error_check_description_required",
                // Save-rejection summary card chrome, not per-code messages.
                "agent_scenario_editor_error_summary_title",
                "agent_scenario_editor_error_summary_entry"
            ),
            nonCodeOwners.toSet()
        )
    }

    // ------------------------------------------------------------ fallback

    /**
     * Codes outside the closed set resolve to no resource — the precondition
     * the UI relies on to show an unrecognized code verbatim
     * ([agentScenarioValidationErrorMessage] returns `error.code` when the
     * lookup yields `null`).  The lookup is exact-match, so a wrong-case or
     * padded spelling is "unrecognized", never a near miss on the mapping.
     */
    @Test
    fun onlyExactDeclaredCodeSpellingsHaveResources() {
        ScenarioValidationCodes.ALL.forEach { code ->
            assertEquals(null, scenarioErrorCodeResId(code.uppercase()))
            assertEquals(null, scenarioErrorCodeResId(" $code"))
            assertEquals(null, scenarioErrorCodeResId("$code!"))
        }
        // Distinct from the existing "unknown codes fall back…" pin in
        // AgentScenarioEditorValidationTest, which covers arbitrary future
        // code strings; here the shape contract (lowercase snake_case) is
        // what must not match sloppily spelled declared codes.
    }

    /**
     * The map's closed-set promise: the two catch-all codes carry their own
     * resources (they do not borrow a specific code's text), so a rejection
     * that only fits a catch-all still reads as distinct prose.
     */
    @Test
    fun catchAllCodesMapToTheirOwnResources() {
        val structural = scenarioErrorCodeResId(ScenarioValidationCodes.STRUCTURAL_REJECTION)
        val text = scenarioErrorCodeResId(ScenarioValidationCodes.TEXT_REJECTED)
        assertNotNull(structural)
        assertNotNull(text)
        assertTrue(structural != scenarioErrorCodeResId(ScenarioValidationCodes.UNKNOWN_PROPERTIES))
        assertTrue(text != scenarioErrorCodeResId(ScenarioValidationCodes.TEXT_FORBIDDEN_CONTENT))
    }
}

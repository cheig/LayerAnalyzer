// Copyright (c) 2026 cheig
// LayerAnalyzer - https://github.com/cheig/LayerAnalyzer
// Licensed under GNU GPL version 3; see LICENSE.

package com.example.layanalyzer.ui.components

import org.junit.Assert.assertEquals
import org.junit.Assert.assertFalse
import org.junit.Assert.assertSame
import org.junit.Assert.assertTrue
import org.junit.Test

/**
 * OPT-SHOW-01 regression pins for the pure fold rule behind the scenario chip
 * row.  The auto-expand itself is Compose state lifted into the host
 * (ProtocolAgentScreen), so what is testable on the JVM is the invariant the
 * host reaction exists to serve: while folded, a tail-appended scenario (user
 * scenarios merge last, SRE-MERGE-01) is not rendered, and expanding — the
 * state the save/copy events now force — is exactly what makes it visible.
 */
class AgentScenarioCollapseTest {

    /** The collapsed head size; mirrors COLLAPSED_SCENARIO_COUNT. */
    private val collapsedCount = 4

    // ------------------------------------------------------ ① hidden count

    @Test
    fun `list at or below the fold threshold hides nothing`() {
        for (size in 0..collapsedCount) {
            assertEquals("size=$size", 0, hiddenScenarioCount(size))
        }
    }

    @Test
    fun `every scenario past the threshold counts as hidden`() {
        assertEquals(1, hiddenScenarioCount(collapsedCount + 1))
        assertEquals(8, hiddenScenarioCount(collapsedCount + 8))
    }

    // ------------------------------------------------- ② folded list and tail

    @Test
    fun `folded list renders only the head so the tail chip is hidden`() {
        val playbooks = (1..10).map { "p$it" }
        val visible = visibleScenarios(playbooks, expanded = false)

        assertEquals(playbooks.take(collapsedCount), visible)
        // The freshly saved/copied scenario lands at the tail (SRE-MERGE-01):
        // folded, it must be exactly the entry the fold conceals.
        assertFalse(visible.contains("p10"))
    }

    // ------------------------------------------------- ③ expanded reveals all

    @Test
    fun `expanded list renders every chip including the tail`() {
        val playbooks = (1..10).map { "p$it" }
        val visible = visibleScenarios(playbooks, expanded = true)

        assertEquals(playbooks, visible)
        assertTrue(visible.contains("p10"))
    }

    @Test
    fun `a list that never overflows is fully visible even folded`() {
        val playbooks = (1..collapsedCount).map { "p$it" }

        // This is the "More (N)" chip is absent" arm: folding has nothing to
        // hide, so the host does not need an expand event for reachability.
        assertSame(playbooks, visibleScenarios(playbooks, expanded = false))
        assertSame(playbooks, visibleScenarios(playbooks, expanded = true))
    }
}
